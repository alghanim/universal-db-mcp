"""Functional fail-closed regression tests for scripts/upgrade_offline.sh.

Why this file exists (completeness-critic round 2): the offline UPGRADE path
is a trust-bearing verifier consumer -- it runs the admin-installed
verify_bundle.py --pubkey against the new bundle, stages a private copy,
re-verifies the staging copy, and only then installs os-packages and rebuilds
the venv -- yet before this file its ENTIRE test coverage was:

- ``bash -n`` (tests/unit/test_hardening_gates.py,
  tests/unit/test_rollback_integrity_manifest.py),
- content greps (post-switch doctor ``--config``, os_packages.sh sourcing,
  manifest recording before the demotion rename).

No test ever EXECUTED the script, so none of its fail-closed refusals were
regression-locked: missing release pubkey, running from inside the bundle,
missing trusted verifier, verifier inside the bundle, a verifier that fails
the new bundle, and a verifier that fails the STAGED copy. Each test below
runs the real script and pins one refusal: nonzero exit, the canonical FAIL
diagnostic, and -- where the target/staging state is reachable -- proof that
nothing was mutated (verify-then-execute, invariant 1, on the upgrade path).

Honest scope: the happy path (a genuinely signed bundle, real venv rebuild,
os-package install, atomic switch) still has no unit test here -- it needs a
full wheelhouse build and is exercised (if at all) by out-of-band gates. The
source-level ordering test below pins the verify-then-use shape that any
future happy-path gate must preserve.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="bash-based POSIX test")

REPO = Path(__file__).resolve().parents[2]
UPGRADE = REPO / "scripts" / "upgrade_offline.sh"


# --------------------------------------------------------------------- helpers


def _run_upgrade(
    tmp_path: Path,
    bundle: Path,
    target: Path,
    *,
    env_extra: dict[str, str] | None = None,
    env_pop: tuple[str, ...] = (),
    script: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run upgrade_offline.sh in a hermetic sandbox.

    A ``sudo`` shim that simply execs its arguments is prepended to PATH so
    the script's privilege adoption (it uses ``sudo`` whenever euid != 0) is
    deterministic and never hits host sudoers policy; every path it touches is
    inside tmp_path, so running unprivileged is exactly equivalent.
    """
    shim_bin = tmp_path / "shim-bin"
    shim_bin.mkdir(exist_ok=True)
    shim = shim_bin / "sudo"
    shim.write_text("#!/bin/sh\nexec \"$@\"\n", encoding="utf-8")
    shim.chmod(0o755)

    env = dict(os.environ)
    env["PATH"] = f"{shim_bin}:{env.get('PATH', '')}"
    env["UDBMCP_STAGING_DIR"] = str(tmp_path / "staging")
    env["UDBMCP_TRUST_DIR"] = str(tmp_path / "trust")
    for key in ("UDBMCP_RELEASE_PUBKEY", "UDBMCP_VERIFIER", "UDBMCP_CONFIG", *env_pop):
        env.pop(key, None)
    if env_extra:
        env.update(env_extra)
    return subprocess.run(  # noqa: S603 - fixed args, repo script under test
        ["/bin/bash", str(script or UPGRADE), str(bundle), str(target),
         str(tmp_path / "backups")],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )


def _dummy_bundle(tmp_path: Path) -> Path:
    """A minimal existing bundle dir (the script cd's into it before any
    refusal check, so it must exist even for the early-refusal cases)."""
    bundle = tmp_path / "bundle"
    bundle.mkdir(exist_ok=True)
    (bundle / "manifest.json").write_text("{}\n", encoding="utf-8")
    return bundle


def _installed_target(target: Path) -> None:
    """A pre-existing installation whose venv must survive every refusal."""
    (target / "venv" / "bin").mkdir(parents=True, exist_ok=True)
    (target / "venv" / "bin" / "python").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    (target / "venv" / "MARKER").write_text("pre-upgrade state\n", encoding="utf-8")


def _assert_target_untouched(target: Path) -> None:
    assert (target / "venv" / "MARKER").read_text(encoding="utf-8") == "pre-upgrade state\n", (
        "a failed upgrade must not touch the installed venv"
    )
    assert not (target / "venv.previous").exists(), "no demotion may happen on a failed upgrade"
    assert not (target / "venv.failed").exists(), "no displacement may happen on a failed upgrade"


# ------------------------------------------------------------------ refusals


def test_upgrade_fails_closed_without_release_pubkey(tmp_path: Path) -> None:
    """No UDBMCP_RELEASE_PUBKEY -> refusal BEFORE the verifier is consulted
    and before anything is staged or installed."""
    bundle = _dummy_bundle(tmp_path)
    target = tmp_path / "target"
    _installed_target(target)

    proc = _run_upgrade(tmp_path, bundle, target, env_pop=("UDBMCP_RELEASE_PUBKEY",))

    assert proc.returncode != 0, proc.stdout + proc.stderr
    out = proc.stdout + proc.stderr
    assert "FAIL" in out, f"refusal must carry the canonical FAIL diagnostic:\n{out}"
    assert "UDBMCP_RELEASE_PUBKEY" in out, f"refusal must name the missing prerequisite:\n{out}"
    _assert_target_untouched(target)
    staging = tmp_path / "staging"
    assert not any(staging.iterdir()) if staging.exists() else True, (
        "nothing may be staged before the pubkey prerequisite is met"
    )


def test_upgrade_fails_closed_without_trusted_verifier(tmp_path: Path) -> None:
    """A set pubkey but no verifier at UDBMCP_VERIFIER -> refusal naming the
    verifier path, with the target installation untouched."""
    bundle = _dummy_bundle(tmp_path)
    target = tmp_path / "target"
    _installed_target(target)
    missing = tmp_path / "trust" / "verify_bundle.py"  # never created

    proc = _run_upgrade(
        tmp_path, bundle, target,
        env_extra={"UDBMCP_RELEASE_PUBKEY": str(tmp_path / "release.pub.pem"),
                   "UDBMCP_VERIFIER": str(missing)},
    )

    assert proc.returncode != 0, proc.stdout + proc.stderr
    out = proc.stdout + proc.stderr
    assert "FAIL" in out and str(missing) in out, (
        f"refusal must name the missing trusted verifier:\n{out}"
    )
    _assert_target_untouched(target)


def test_upgrade_refuses_verifier_inside_the_bundle(tmp_path: Path) -> None:
    """A verifier shipped inside the bundle it would verify is attacker
    controlled (a tampered bundle's verifier prints PASSED): the script must
    refuse it even though the file exists."""
    bundle = _dummy_bundle(tmp_path)
    inside = bundle / "trusted-tools" / "verify_bundle.py"
    inside.parent.mkdir(parents=True, exist_ok=True)
    inside.write_text("#!/usr/bin/env python3\nimport sys; sys.exit(0)\n", encoding="utf-8")
    target = tmp_path / "target"
    _installed_target(target)

    proc = _run_upgrade(
        tmp_path, bundle, target,
        env_extra={"UDBMCP_RELEASE_PUBKEY": str(tmp_path / "release.pub.pem"),
                   "UDBMCP_VERIFIER": str(inside)},
    )

    assert proc.returncode != 0, proc.stdout + proc.stderr
    out = proc.stdout + proc.stderr
    assert "inside the bundle" in out, f"refusal must name the inside-the-bundle violation:\n{out}"
    _assert_target_untouched(target)


def test_upgrade_refuses_to_run_from_inside_the_bundle(tmp_path: Path) -> None:
    """The script executed from a copy inside the bundle IS bundle supply
    chain code: it must refuse before verifying anything (mirrors the
    install_offline.sh P0 gate, which had no upgrade-path counterpart)."""
    bundle = _dummy_bundle(tmp_path)
    embedded = bundle / "upgrade_offline.sh"
    shutil.copy2(UPGRADE, embedded)
    target = tmp_path / "target"
    _installed_target(target)

    proc = _run_upgrade(
        tmp_path, bundle, target, script=embedded,
        env_extra={"UDBMCP_RELEASE_PUBKEY": str(tmp_path / "release.pub.pem")},
    )

    assert proc.returncode != 0, proc.stdout + proc.stderr
    out = proc.stdout + proc.stderr
    assert "refusing to run from inside the bundle" in out, (
        f"self-location refusal diagnostic missing:\n{out}"
    )
    _assert_target_untouched(target)


def test_upgrade_fails_closed_when_verifier_rejects_the_new_bundle(tmp_path: Path) -> None:
    """The verifier runs and exits nonzero (untrusted/unsigned/tampered
    bundle): the upgrade must abort with the target installation untouched,
    and the verifier must actually have been consulted (the stub writes a
    canary) -- a refusal that never ran the verifier would prove nothing."""
    bundle = _dummy_bundle(tmp_path)
    target = tmp_path / "target"
    _installed_target(target)
    canary = tmp_path / "verifier-consulted"
    stub = tmp_path / "stub_verifier.py"
    stub.write_text(
        "import pathlib, sys\n"
        f"pathlib.Path({str(canary)!r}).write_text('consulted')\n"
        "sys.exit(1)\n",
        encoding="utf-8",
    )

    proc = _run_upgrade(
        tmp_path, bundle, target,
        env_extra={"UDBMCP_RELEASE_PUBKEY": str(tmp_path / "release.pub.pem"),
                   "UDBMCP_VERIFIER": str(stub)},
    )

    assert canary.exists(), "the trusted verifier must actually run against the new bundle"
    assert proc.returncode != 0, "a failed bundle verification must fail the upgrade closed"
    out = proc.stdout + proc.stderr
    assert "==> preflight" in out, "the abort must happen in the preflight verify phase"
    _assert_target_untouched(target)
    staging = tmp_path / "staging"
    assert not staging.exists() or not any(staging.iterdir()), (
        "nothing may remain staged when the preflight verification fails"
    )


def test_upgrade_fails_closed_when_verifier_rejects_the_staged_copy(tmp_path: Path) -> None:
    """The second verifier call (against the private staging copy that closes
    the verify-then-use race) failing must also abort: no os-packages install,
    no venv rebuild, no switch, and the staging area cleaned by the exit trap."""
    bundle = _dummy_bundle(tmp_path)
    target = tmp_path / "target"
    _installed_target(target)
    calls = tmp_path / "verifier-calls"
    stub = tmp_path / "stub_verifier.py"
    stub.write_text(
        "import pathlib, sys\n"
        f"calls = pathlib.Path({str(calls)!r})\n"
        "calls.mkdir(parents=True, exist_ok=True)\n"
        "seen = list(calls.glob('call-*'))\n"
        "(calls / ('call-%d' % len(seen))).write_text(' '.join(sys.argv))\n"
        "sys.exit(0 if len(seen) == 0 else 1)\n",
        encoding="utf-8",
    )

    proc = _run_upgrade(
        tmp_path, bundle, target,
        env_extra={"UDBMCP_RELEASE_PUBKEY": str(tmp_path / "release.pub.pem"),
                   "UDBMCP_VERIFIER": str(stub)},
    )

    seen = sorted(p.name for p in calls.iterdir())
    assert len(seen) == 2, (
        f"expected exactly two verifier invocations (bundle, then staged copy); got {seen}"
    )
    assert proc.returncode != 0, "a failed staged-copy verification must fail the upgrade closed"
    _assert_target_untouched(target)
    staging = tmp_path / "staging"
    assert not staging.exists() or not any(staging.iterdir()), (
        "the exit trap must clean the staging copy when the staged re-verify fails"
    )


# ----------------------------------------------------- source-level ordering


def test_verification_precedes_every_state_mutating_step() -> None:
    """Source-level: both verifier invocations must precede the os-package
    install and the venv demotion/switch, so ANY verification failure aborts
    before the running installation is touched."""
    text = UPGRADE.read_text(encoding="utf-8")
    verify_new = text.index('$sudo_ok $VEXEC "$VERIFIER" --bundle "$NEW_BUNDLE" --pubkey "$PUBKEY"')
    stage_copy = text.index('cp -a "$NEW_BUNDLE"/. "$STAGING/"')
    verify_staging = text.index('$sudo_ok $VEXEC "$VERIFIER" --bundle "$STAGING" --pubkey "$PUBKEY"')
    os_packages = text.index("udbmcp_install_os_packages ")
    demote = text.index('mv "$TARGET/venv" "$TARGET/venv.previous"')
    assert verify_new < stage_copy < verify_staging < os_packages < demote, (
        "verify-then-use order broken: verify(bundle) -> stage -> verify(staging) "
        "-> os-packages -> venv switch"
    )
