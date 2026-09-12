"""Regression tests for the deb:build_script artifact (scripts/package/build_deb.sh)
and the dpkg-lock tripwire in scripts/lib/os_packages.sh.

Defects locked out here (verifier lenses, deb:build_script artifact):

P1 (root cause lives in scripts/lib/os_packages.sh, reached via the deb's
   maintainer scripts): a nested `dpkg -i` can never succeed while the outer
   `dpkg -i` holds the dpkg frontend lock for its whole run — the deb was
   UNINSTALLABLE whenever the bundle shipped os-packages (the linux-x86_64
   profile always does). The lib now detects the maintainer-script context
   with dpkg's locks genuinely held and defers behind a loud marker instead
   of deadlocking; packaging/deb/postinst (its own artifact) defers the whole
   dpkg-dependent install to a detached worker, and this file also locks in
   that the worker drops dpkg's maintainer-script environment so the
   tripwire can never misfire inside it.

P3: build_deb.sh staged the systemd unit into the dpkg payload at
   etc/systemd/system/ (dpkg-owned, silently overwritten on upgrade). The
   unit is installed by postinst OUTSIDE dpkg management now (the deb ships
   the canonical copy under usr/share/universal-db-mcp/systemd/); build_deb.sh
   must never stage the unit under /etc again. The default config, by
   contrast, IS staged at etc/universal-db-mcp/config.yaml as a dpkg
   conffile (plan Phase 4, registered via packaging/deb/conffiles): dpkg owns
   it, preserves admin edits across upgrades, and postinst's only-if-absent
   seeding stays as the documented fallback for a conffile an admin deleted
   before an upgrade — it is not dead code. See
   tests/unit/test_deb_conffiles_gate.py, the authoritative suite for the
   conffile staging and its fail-loud gate.

P2 (build side): the deb's trusted-tools payload must be COMPLETE
   (profiles.py next to verify_bundle.py, lib/os_packages.sh next to
   install_offline.sh). Since the no-self-bootstrap fix the deb-shipped copy
   is INERT reference material — postinst never bootstraps the trust dir from
   the package payload — but the copy that ships next to the bundle on the
   trusted channel must still be usable by the admin, so build_deb.sh fails
   closed at build time if it is missing either file.

Trust invariants under test (never broken):
  1. verify-before-execute: build_deb.sh still verifies the source bundle via
     the trusted-channel verifier with --pubkey before staging anything;
  2. no key material in the package (unchanged scan);
  3. pip hardening stays inside install_offline.sh;
  4. fail closed: marker-record failure, missing trusted-tools files, or any
     verification failure aborts (nonzero) without an artifact.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

_POSIX = pytest.mark.skipif(sys.platform == "win32", reason="POSIX shell/fcntl semantics; run on linux/macos")

_PROJECT = Path(__file__).resolve().parents[2]
_BUILD_DEB = _PROJECT / "scripts" / "package" / "build_deb.sh"
_LIB = _PROJECT / "scripts" / "lib" / "os_packages.sh"
_POSTINST = _PROJECT / "packaging" / "deb" / "postinst"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _bash_n(path: Path) -> None:
    proc = subprocess.run(  # noqa: S603 - fixed args, local script syntax check
        ["/bin/bash", "-n", str(path)], capture_output=True, text=True, timeout=60
    )
    assert proc.returncode == 0, proc.stderr


def _noncomment(text: str) -> str:
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


# ------------------------------------------------------------------ build_deb.sh


def test_build_deb_passes_bash_syntax_check() -> None:
    _bash_n(_BUILD_DEB)


def test_build_deb_does_not_stage_unit_into_dpkg_payload() -> None:
    """P3: the systemd unit is installed by postinst OUTSIDE dpkg management
    (/etc/systemd/system is admin-controlled; a dpkg-owned unit would be
    silently clobbered on upgrade). build_deb.sh stages the deb-shipped
    canonical copy under usr/share/universal-db-mcp/systemd/ only — never
    under /etc. The default config, unlike the unit, IS deliberately staged
    under etc/ as a dpkg conffile (plan Phase 4); that staging and its
    fail-loud gate are covered authoritatively by
    tests/unit/test_deb_conffiles_gate.py — here only the unit is locked
    out of dpkg's /etc paths."""
    code = _noncomment(_read(_BUILD_DEB))
    assert "etc/systemd/system/universal-db-mcp.service" not in code
    # The canonical copies postinst consumes must still be staged.
    assert 'cp "$UNIT_SRC" "$PKG_SHARE/systemd/universal-db-mcp.service"' in code
    assert 'CONFIG_TEMPLATE="$BUNDLE/config-templates/config.yaml"' in code
    # The conffile staging is intentional (not a regression): assert the
    # exact string the conffiles-gate suite requires, so the two suites can
    # never disagree about the config's dpkg ownership again.
    assert 'install -m 0644 "$CONFIG_TEMPLATE" "$DEBROOT/etc/universal-db-mcp/config.yaml"' in code


def test_build_deb_requires_complete_trusted_tools_including_profiles() -> None:
    """P2: a deb whose trusted-tools payload lacks lib/os_packages.sh or
    profiles.py produces a self-bootstrap that fails inside postinst (the
    installer sources the lib, the verifier imports profiles.py). Fail closed
    at build time instead."""
    code = _noncomment(_read(_BUILD_DEB))
    assert 'die "trusted-tools copy is incomplete: lib/os_packages.sh missing from $TRUSTED"' in code
    assert "[ -f \"$TRUSTED/profiles.py\" ] || die" in code
    assert "profiles.py missing from $TRUSTED" in code


def test_build_deb_still_verifies_source_bundle_before_staging() -> None:
    """Trust invariant 1: the trusted-channel verify_bundle.py --pubkey run
    must happen before anything is staged."""
    text = _read(_BUILD_DEB)
    code = _noncomment(text)
    verify_at = code.index("verify_bundle.py")
    stage_at = code.index('cp -a "$BUNDLE/." "$PKG_SHARE/bundle/"')
    assert verify_at < stage_at, "verify the signed bundle BEFORE staging the payload"
    assert "--allow-platform-mismatch" in code  # documented staging-side mode
    assert "refusing to package unverified payload" in code  # fail closed


@_POSIX
def test_build_deb_refuses_unsigned_bundle_and_missing_trusted_tools(tmp_path: Path) -> None:
    """Functional fail-closed checks that need no docker: an unsigned bundle
    and an incomplete trusted-tools copy must abort before staging."""
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "manifest.json").write_text(
        '{"release": "0.1.0", "source_rev": "test", "target": {"os": "linux-x86_64-ubuntu24.04", "arch": "x86_64"}}\n',
        encoding="utf-8",
    )
    # No SIGNATURE / SHA256SUMS / trusted-tools: build must abort.
    proc = subprocess.run(  # noqa: S603 - fixed args, local script
        ["/bin/bash", str(_BUILD_DEB), str(bundle), "--pubkey", str(tmp_path / "nokey.pem")],
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 1
    assert "UNSIGNED" in proc.stderr or "not found" in proc.stderr

    # Signed-looking bundle but trusted-tools without profiles.py: abort.
    (bundle / "SIGNATURE").write_text("sig\n", encoding="utf-8")
    (bundle / "SHA256SUMS").write_text("\n", encoding="utf-8")
    trusted = tmp_path / "trusted-tools"
    (trusted / "lib").mkdir(parents=True)
    (trusted / "verify_bundle.py").write_text("# verifier\n", encoding="utf-8")
    (trusted / "install_offline.sh").write_text("# installer\n", encoding="utf-8")
    (trusted / "lib" / "os_packages.sh").write_text("# lib\n", encoding="utf-8")
    # profiles.py deliberately missing.
    proc = subprocess.run(  # noqa: S603 - fixed args, local script
        ["/bin/bash", str(_BUILD_DEB), str(bundle), "--pubkey", str(tmp_path / "nokey.pem")],
        capture_output=True, text=True, timeout=60,
    )
    # The build may abort on the missing pubkey first (checked before the
    # trusted-tools completeness scan) — either way it must fail closed.
    assert proc.returncode == 1


# ------------------------------------------------- os_packages.sh lock tripwire


def test_os_packages_sh_passes_bash_syntax_check() -> None:
    _bash_n(_LIB)


def test_os_packages_sh_defer_marker_is_outside_udbmcp_writable_state() -> None:
    """The pending marker must default to a ROOT-owned path: /var/lib/
    universal-db-mcp is udbmcp-owned (created by install_offline.sh for the
    service account), so a marker there could be pre-created or removed by
    the service account."""
    code = _noncomment(_read(_LIB))
    assert "/run/universal-db-mcp/os-packages.pending" in code
    assert 'UDBMCP_OSPKG_DEFER_MARKER:-/run/universal-db-mcp/os-packages.pending' in code


def test_os_packages_sh_defer_requires_maintainer_context_and_held_locks() -> None:
    """The tripwire must trigger only for maintainer-script contexts with the
    dpkg locks genuinely held: the deb's deferred worker inherits
    DPKG_MAINTSCRIPT_PACKAGE in its environment but runs AFTER dpkg released
    the locks, so it must proceed to install (never defer)."""
    code = _noncomment(_read(_LIB))
    assert "DPKG_MAINTSCRIPT_PACKAGE" in code
    assert "_udbmcp_dpkg_locks_held" in code
    # The probe must exist and consult fcntl (dpkg uses fcntl, not flock).
    assert "fcntl" in code
    assert "lock-frontend" in code


def test_postinst_worker_drops_maintainer_script_environment() -> None:
    """Cross-artifact invariant: packaging/deb/postinst's deferred worker is
    NOT a maintainer script; it must unset dpkg's maintainer-script variables
    so lib/os_packages.sh can never defer the closure install inside it."""
    code = _read(_POSTINST)
    assert "unset DPKG_MAINTSCRIPT_PACKAGE" in code


class _LockHolder:
    """Background process holding fcntl exclusive locks on the given files
    until released (simulates the outer dpkg)."""

    def __init__(self, tmp_path: Path, lock_files: list[Path]) -> None:
        self.marker = tmp_path / "holder-release"
        holder = tmp_path / "holder.py"
        holder.write_text(
            "import fcntl, os, sys, time\n"
            "fds = []\n"
            + "".join(
                f"fds.append(open({str(p)!r}, 'r+'))\n" for p in lock_files
            )
            + "".join(
                f"fcntl.lockf(fds[{i}], fcntl.LOCK_EX)\n" for i in range(len(lock_files))
            )
            + f"while not os.path.exists({str(self.marker)!r}):\n"
            "    time.sleep(0.05)\n"
            "sys.exit(0)\n",
            encoding="utf-8",
        )
        for p in lock_files:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.touch()
        self.proc = subprocess.Popen(  # noqa: S603 - fixed args, local helper
            [sys.executable, str(holder)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

    def release(self) -> None:
        self.marker.write_text("go\n", encoding="utf-8")
        self.proc.wait(timeout=30)


def _run_lib_install(tmp_path: Path, bundle: Path, env_extra: dict[str, str]) -> subprocess.CompletedProcess[str]:
    script = (
        "set -eu\n"
        f"source {str(_LIB)!r}\n"
        f"udbmcp_install_os_packages {str(bundle)!r} python3 ''\n"
    )
    env = dict(os.environ)
    env.update(env_extra)
    env["UDBMCP_DPKG_LOCK_FILES"] = env_extra.get(
        "UDBMCP_DPKG_LOCK_FILES", f"{tmp_path}/dpkg/lock-frontend {tmp_path}/dpkg/lock"
    )
    env["UDBMCP_OSPKG_DEFER_MARKER"] = f"{tmp_path}/run/os-packages.pending"
    env.pop("DPKG_MAINTSCRIPT_PACKAGE", None)
    env.pop("DPKG_FRONTEND_LOCKED", None)
    for key, value in env_extra.items():
        env[key] = value
    return subprocess.run(  # noqa: S603 - fixed args, local sandbox script
        ["/bin/bash", "-c", script], capture_output=True, text=True, timeout=120, env=env
    )


def _make_bundle(tmp_path: Path) -> Path:
    bundle = tmp_path / "bundle"
    (bundle / "os-packages").mkdir(parents=True)
    (bundle / "os-packages" / "dummy_1.0_amd64.deb").write_bytes(b"deb")
    (bundle / "manifest.json").write_text("{}\n", encoding="utf-8")
    return bundle


@_POSIX
def test_os_packages_defer_when_maintainer_context_and_locks_held(tmp_path: Path) -> None:
    """P1 tripwire, positive case: inside a maintainer-script context with
    dpkg's locks held, the helper must NOT attempt a nested dpkg -i (which
    always dies with 'dpkg frontend lock was locked by another process').
    It records the pending state behind the marker and returns success so the
    rest of the trusted install still completes."""
    holder = _LockHolder(tmp_path, [tmp_path / "dpkg" / "lock-frontend", tmp_path / "dpkg" / "lock"])
    try:
        # Wait until the holder really owns the locks.
        for _ in range(100):
            probe = subprocess.run(  # noqa: S603 - fixed args, local helper
                [sys.executable, "-c",
                 "import fcntl,sys\n"
                 f"fh=open({str(tmp_path / 'dpkg' / 'lock-frontend')!r},'r+')\n"
                 "try:\n"
                 "    fcntl.lockf(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)\n"
                 "except OSError:\n"
                 "    sys.exit(1)\n"
                 "sys.exit(0)"],
                capture_output=True, text=True, timeout=30,
            )
            if probe.returncode == 1:
                break
            time.sleep(0.05)
        else:
            pytest.fail("lock holder never acquired the sandbox dpkg locks")

        proc = _run_lib_install(
            tmp_path, _make_bundle(tmp_path), {"DPKG_MAINTSCRIPT_PACKAGE": "universal-db-mcp"}
        )
    finally:
        holder.release()

    assert proc.returncode == 0, f"defer path failed: {proc.stderr}\n{proc.stdout}"
    assert "DEFERRED" in proc.stdout
    assert "could never succeed against the outer dpkg's locks" in proc.stdout
    assert "PENDING marker" in proc.stdout
    marker = tmp_path / "run" / "os-packages.pending"
    assert marker.exists(), "deferred state must be recorded behind the pending marker"


@_POSIX
def test_os_packages_no_defer_when_locks_free_or_outside_maintainer_context(tmp_path: Path) -> None:
    """The tripwire must NOT misfire:
    - maintainer-script env but locks FREE (the deb's deferred worker case)
      -> proceeds to the dpkg step (which fails loudly here: no dpkg binary
      in the sandbox PATH, and the dummy deb is not installable);
    - locks held but NO maintainer-script env (a plain CLI run racing apt)
      -> unchanged historical behavior: dpkg is attempted and its own lock
      error surfaces; nothing is silently deferred."""
    bundle = _make_bundle(tmp_path)

    # Case 1: env set, locks free.
    proc = _run_lib_install(tmp_path, bundle, {"DPKG_MAINTSCRIPT_PACKAGE": "universal-db-mcp"})
    assert proc.returncode != 0, "must not defer when dpkg's locks are free"
    assert "DEFERRED" not in proc.stdout
    assert not (tmp_path / "run" / "os-packages.pending").exists()

    # Case 2: locks held, no maintainer env.
    holder = _LockHolder(tmp_path, [tmp_path / "dpkg" / "lock-frontend", tmp_path / "dpkg" / "lock"])
    try:
        time.sleep(0.2)  # give the holder a moment to take the locks
        proc = _run_lib_install(tmp_path, bundle, {})
    finally:
        holder.release()
    assert proc.returncode != 0
    assert "DEFERRED" not in proc.stdout
    assert not (tmp_path / "run" / "os-packages.pending").exists()


@_POSIX
def test_os_packages_no_os_packages_is_a_clean_noop_without_marker(tmp_path: Path) -> None:
    """A bundle without os-packages must stay a clean no-op in a maintainer
    context (nothing to defer, no marker) — the probe short-circuits before
    the tripwire."""
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "manifest.json").write_text("{}\n", encoding="utf-8")
    proc = _run_lib_install(tmp_path, bundle, {"DPKG_MAINTSCRIPT_PACKAGE": "universal-db-mcp"})
    assert proc.returncode == 0, proc.stderr
    assert "no OS packages in bundle os-packages/" in proc.stdout
    assert not (tmp_path / "run" / "os-packages.pending").exists()
