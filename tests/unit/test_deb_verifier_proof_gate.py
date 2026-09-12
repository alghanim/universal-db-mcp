"""Regression tests: a zero-length (or silently non-proving) trusted verifier
must fail closed on every deb trust path.

Defect (final-critic round): python3 on a ZERO-LENGTH verify_bundle.py exits 0
vacuously (argparse never runs), and the deb decided trust from exit codes
alone — the preinst checked only readability (-r), the postinst trust-dir loop
only existence (-f), and both install modes deferred to install_offline.sh,
which trusted the verifier's exit code with no output proof. A truncated
trusted-channel copy of the verifier therefore made the deb install the
unverified wheelhouse and enable universal-db-mcp.service with ZERO signature
checking. Both sibling platforms already guard this exact case:
packaging/pkg/preinstall uses [ ! -s ] and packaging/msi/custom/verify.ps1
requires exit 0 AND the literal 'bundle verification PASSED' AND no FAIL line.

Fix locked in here (platform-consistent fail closed):
  1. packaging/deb/preinst refuses an EMPTY verifier ([ ! -s ], alongside -r);
  2. packaging/deb/postinst's trust-dir completeness gate treats zero-length
     like missing for ALL four trusted tools;
  3. packaging/deb/postinst verifies the unpacked payload through a PROOF gate
     on BOTH install modes (deferred synchronous verify + sync-path pre-verify
     before install_offline.sh): exit 0 alone aborts unless the verifier
     printed 'bundle verification PASSED' and no 'FAIL:' line;
  4. scripts/install_offline.sh refuses an empty verifier and requires the
     same output proof for BOTH verifier invocations (original + staging copy).

Trust invariants exercised (never weakened):
  - verify-before-execute: nothing unverified is staged, installed or enabled;
  - fail closed: every non-proving outcome aborts with a diagnostic;
  - no in-package pubkey / no self-bootstrap: untouched (see
    test_deb_postinst_no_self_bootstrap.py).
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

_POSIX = pytest.mark.skipif(sys.platform == "win32", reason="POSIX shell semantics; run on linux/macos")

_PROJECT = Path(__file__).resolve().parents[2]
_PREINST = _PROJECT / "packaging" / "deb" / "preinst"
_POSTINST = _PROJECT / "packaging" / "deb" / "postinst"
_INSTALLER = _PROJECT / "scripts" / "install_offline.sh"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _bash_n(path: Path) -> None:
    proc = subprocess.run(  # noqa: S603 - fixed args, local script syntax check
        ["/bin/bash", "-n", str(path)], capture_output=True, text=True, timeout=60
    )
    assert proc.returncode == 0, proc.stderr


# ------------------------------------------------------------------ structure


@_POSIX
def test_preinst_passes_bash_syntax_check() -> None:
    _bash_n(_PREINST)


@_POSIX
def test_postinst_passes_bash_syntax_check() -> None:
    _bash_n(_POSTINST)


@_POSIX
def test_installer_passes_bash_syntax_check() -> None:
    _bash_n(_INSTALLER)


@_POSIX
def test_preinst_requires_a_nonempty_verifier() -> None:
    """The preinst must check -s (non-empty) in addition to -r: python3 on an
    empty script exits 0 without running argparse, so readability alone lets a
    truncated trusted-channel copy 'pass' vacuously."""
    code = "\n".join(
        line for line in _read(_PREINST).splitlines() if not line.lstrip().startswith("#")
    )
    assert 'if [ ! -r "$VERIFIER" ]; then' in code
    assert 'if [ ! -s "$VERIFIER" ]; then' in code, (
        "preinst must refuse a zero-length verifier (vacuous-pass guard)"
    )
    # Both verifier gates must fail closed with their own exit 1.
    assert code.count("exit 1") >= 3


@_POSIX
def test_postinst_trust_dir_loop_requires_nonempty_tools() -> None:
    code = "\n".join(
        line for line in _read(_POSTINST).splitlines() if not line.lstrip().startswith("#")
    )
    assert '[ ! -f "$f" ] || [ ! -s "$f" ]' in code, (
        "the trust-dir completeness gate must treat zero-length like missing"
    )


@_POSIX
def test_postinst_proof_gate_covers_both_install_modes() -> None:
    """The proof gate must run on the deferred branch (synchronous verify) AND
    on the synchronous path BEFORE the trusted installer is invoked — an older
    admin-installed installer revision that still trusts exit codes alone must
    not become the weakest link."""
    code = "\n".join(
        line for line in _read(_POSTINST).splitlines() if not line.lstrip().startswith("#")
    )
    assert 'grep -q \'bundle verification PASSED\'' in code, (
        "postinst must require the verifier's explicit PASSED proof"
    )
    # Standalone call sites only (not the function definition line).
    calls = [
        m.start() for m in re.finditer(r"(?m)^\s*verify_payload_with_proof\s*$", code)
    ]
    assert len(calls) == 2, "the proof gate must be invoked on both install modes"
    compgen_at = code.index('if compgen -G "$BUNDLE/os-packages/*.deb"')
    installer_calls = [
        m.start() for m in re.finditer(re.escape('bash "$TRUST_DIR/install_offline.sh" "$BUNDLE" "$TARGET"'), code)
    ]
    assert len(installer_calls) == 2
    # First call: deferred branch, after the compgen decision, before the spawn.
    # Second call: synchronous path, before its installer invocation.
    assert compgen_at < calls[0] < code.index("setsid --fork")
    assert installer_calls[1] > calls[1] > code.index("exit 0", code.index("setsid --fork"))


@_POSIX
def test_installer_requires_proof_for_both_verifier_invocations() -> None:
    code = "\n".join(
        line for line in _read(_INSTALLER).splitlines() if not line.lstrip().startswith("#")
    )
    assert 'if [ ! -s "$VERIFIER" ]; then' in code, (
        "install_offline.sh must refuse a zero-length verifier"
    )
    assert 'grep -q \'bundle verification PASSED\'' in code, (
        "install_offline.sh must require the verifier's explicit PASSED proof"
    )
    gate_calls = [m.start() for m in re.finditer(r"verify_with_proof \"\$", code)]
    assert len(gate_calls) == 2, (
        "both verifier invocations (original bundle + private staging copy) must go through the proof gate"
    )
    # The direct exit-code-only invocations are gone (the only remaining
    # $VEXEC call is INSIDE the proof gate, against its "$1" parameter).
    assert '"$VERIFIER" --bundle "$BUNDLE"' not in code
    assert '"$VERIFIER" --bundle "$STAGING"' not in code


# ------------------------------------------------------------------ functional


def _preinst_sandbox(tmp_path: Path) -> tuple[Path, Path, Path]:
    """preinst with its hardcoded trust paths rewritten into the sandbox."""
    trust_dir = tmp_path / "udbmcp-trust"
    pubkey = tmp_path / "udbmcp-keys" / "release.pub.pem"
    text = _read(_PREINST)
    text = text.replace("/usr/local/lib/udbmcp-trust", str(trust_dir))
    text = text.replace("/etc/universal-db-mcp/keys/release.pub.pem", str(pubkey))
    assert f'TRUST_DIR="{trust_dir}"' in text
    script = tmp_path / "preinst_sbx.sh"
    script.write_text(text, encoding="utf-8")
    return script, trust_dir / "verify_bundle.py", pubkey


@_POSIX
def test_preinst_functional_refuses_empty_verifier(tmp_path: Path) -> None:
    script, verifier, pubkey = _preinst_sandbox(tmp_path)
    verifier.parent.mkdir(parents=True)
    verifier.write_text("", encoding="utf-8")  # the truncated trusted-channel copy
    pubkey.parent.mkdir(parents=True)
    pubkey.write_text("-----BEGIN PUBLIC KEY-----\nsbx\n-----END PUBLIC KEY-----\n", encoding="utf-8")

    proc = subprocess.run(["/bin/bash", str(script)], capture_output=True, text=True, timeout=60)  # noqa: S603
    assert proc.returncode == 1, proc.stdout
    assert "exists but is EMPTY" in proc.stderr
    assert "exits 0 on an empty script" in proc.stderr
    assert "ABORTED" in proc.stderr


def _postinst_sandbox(tmp_path: Path) -> Path:
    """The whole postinst with every absolute path constant rewritten into the
    sandbox (ordering and fail-closed logic untouched)."""
    text = _read(_POSTINST)
    lines = text.splitlines()
    rewritten = []
    for line in lines:
        match = re.match(r"^([A-Z_]+)=/.+$", line)
        if match:
            line = f"{match.group(1)}={tmp_path / match.group(1).lower()}"
        line = line.replace("/var/lib/dpkg/lock-frontend", str(tmp_path / "dpkg" / "lock-frontend"))
        line = line.replace("/var/lib/dpkg/lock", str(tmp_path / "dpkg" / "lock"))
        line = line.replace("/run/udbmcp-deferred-install.lock", str(tmp_path / "run" / "udbmcp-deferred-install.lock"))
        line = line.replace(
            "/var/tmp/udbmcp-postinst-worker.XXXXXX",  # noqa: S108
            str(tmp_path / "tmp" / "udbmcp-postinst-worker.XXXXXX"),
        )
        line = re.sub(r"-o root -g root ", "", line)
        line = re.sub(r"-o udbmcp -g udbmcp ", "", line)
        rewritten.append(line)
    script = tmp_path / "postinst_sbx.sh"
    script.write_text("#!/bin/bash\n" + "\n".join(rewritten) + "\n", encoding="utf-8")
    return script


def _deferred_bundle(tmp_path: Path) -> Path:
    bundle = tmp_path / "bundle"
    (bundle / "os-packages").mkdir(parents=True)
    (bundle / "os-packages" / "dummy_1.0_amd64.deb").write_bytes(b"deb")
    (bundle / "config-templates").mkdir()
    (bundle / "config-templates" / "config.yaml").write_text("# template\n", encoding="utf-8")
    (bundle / "operations").mkdir()
    (bundle / "operations" / "universal-db-mcp.service").write_text("[Unit]\n", encoding="utf-8")
    return bundle


def _complete_admin_trust_dir(tmp_path: Path, verifier_body: str) -> Path:
    trust = tmp_path / "trust_dir"
    (trust / "lib").mkdir(parents=True)
    (trust / "verify_bundle.py").write_text(verifier_body, encoding="utf-8")
    (trust / "profiles.py").write_text("# admin profiles\n", encoding="utf-8")
    (trust / "install_offline.sh").write_text("#!/bin/bash\nexit 1\n", encoding="utf-8")
    (trust / "lib" / "os_packages.sh").write_text("# admin lib\n", encoding="utf-8")
    return trust


@_POSIX
def test_postinst_functional_refuses_zero_length_trust_verifier(tmp_path: Path) -> None:
    """The dpkg --configure path (postinst run directly, no preinst) must abort
    at the trust-dir completeness gate when the admin verifier is empty."""
    _deferred_bundle(tmp_path)
    _complete_admin_trust_dir(tmp_path, verifier_body="")
    (tmp_path / "pubkey").write_text("-----BEGIN PUBLIC KEY-----\nsbx\n-----END PUBLIC KEY-----\n", encoding="utf-8")

    proc = subprocess.run(  # noqa: S603
        ["/bin/bash", str(_postinst_sandbox(tmp_path))], capture_output=True, text=True, timeout=60
    )
    assert proc.returncode != 0, proc.stdout
    assert "trusted tool missing from the admin trust dir" in proc.stderr
    assert "zero-length" in proc.stderr
    assert "bundle verification PASSED" not in proc.stdout


@_POSIX
def test_postinst_functional_refuses_silent_verifier_without_proof(tmp_path: Path) -> None:
    """A NON-empty verifier that exits 0 without certifying is just as vacuous:
    the deferred branch's synchronous verification must abort the configure
    step for lack of the 'bundle verification PASSED' proof."""
    _deferred_bundle(tmp_path)
    _complete_admin_trust_dir(
        tmp_path, verifier_body="import sys\nsys.exit(0)\n"  # silent vacuous pass
    )
    (tmp_path / "pubkey").write_text("-----BEGIN PUBLIC KEY-----\nsbx\n-----END PUBLIC KEY-----\n", encoding="utf-8")

    proc = subprocess.run(  # noqa: S603
        ["/bin/bash", str(_postinst_sandbox(tmp_path))], capture_output=True, text=True, timeout=60
    )
    assert proc.returncode != 0, proc.stdout
    assert "did not certify the payload" in proc.stderr
    # Fail closed BEFORE anything is touched: no guard drop-in, no worker spawn.
    assert "deferred-install guard installed" not in proc.stdout
    assert not (tmp_path / "unit_dropin_dir" / "deferred-install-guard.conf").exists()


def _installer_sandbox(tmp_path: Path, verifier_body: str, *, executable: bool) -> subprocess.CompletedProcess[str]:
    """Run the REAL install_offline.sh against a stub verifier at the given
    trust path (sudo pass-through stub, python3 delegating to the real
    interpreter). The run is expected to stop at/before the service account."""
    stubs = tmp_path / "stubs"
    stubs.mkdir(exist_ok=True)
    sudo = stubs / "sudo"
    sudo.write_text('#!/bin/sh\nexec "$@"\n', encoding="utf-8")
    sudo.chmod(0o755)
    py = stubs / "python3"
    py.write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n', encoding="utf-8")
    py.chmod(0o755)

    verifier = tmp_path / "trust" / "verify_bundle.py"
    verifier.parent.mkdir(parents=True, exist_ok=True)
    verifier.write_text(verifier_body, encoding="utf-8")
    verifier.chmod(0o755 if executable else 0o644)

    bundle = tmp_path / "bundle"
    (bundle / "requirements").mkdir(parents=True)
    (bundle / "requirements" / "runtime.lock").write_text("", encoding="utf-8")

    env = dict(os.environ)
    env["PATH"] = f"{stubs}:{os.environ.get('PATH', '')}"
    env["UDBMCP_RELEASE_PUBKEY"] = str(tmp_path / "pub.pem")
    env["UDBMCP_VERIFIER"] = str(verifier)
    env["UDBMCP_STAGING_DIR"] = str(tmp_path / "staging")

    return subprocess.run(  # noqa: S603 - fixed args, repo script under test
        ["/bin/bash", str(_INSTALLER), str(bundle), str(tmp_path / "target")],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )


@_POSIX
def test_installer_functional_refuses_empty_verifier(tmp_path: Path) -> None:
    proc = _installer_sandbox(tmp_path, verifier_body="", executable=False)
    assert proc.returncode != 0
    assert "is empty; refusing to proceed" in proc.stderr
    assert "bundle verification PASSED" not in proc.stdout
    # Fail closed BEFORE anything is staged or consumed.
    assert not list((tmp_path / "staging").glob("udbmcp-install.*")) if (tmp_path / "staging").exists() else True
    assert not (tmp_path / "target").exists()


@_POSIX
def test_installer_functional_refuses_silent_verifier_without_proof(tmp_path: Path) -> None:
    """An executable verifier that exits 0 silently must not satisfy the
    installer: exit code alone is not proof (mirrors verify.ps1)."""
    proc = _installer_sandbox(tmp_path, verifier_body="#!/bin/sh\nexit 0\n", executable=True)
    assert proc.returncode != 0
    assert "did not print 'bundle verification PASSED'" in proc.stderr
    assert not (tmp_path / "target").exists()


@_POSIX
def test_installer_functional_accepts_proving_verifier(tmp_path: Path) -> None:
    """Positive control: a verifier that exits 0 AND prints the canonical PASSED
    line gets past BOTH proof-gated invocations (original + staging copy); the
    run then continues to the later (unrelated, environment) failure."""
    proc = _installer_sandbox(
        tmp_path, verifier_body='#!/bin/sh\necho "bundle verification PASSED"\nexit 0\n', executable=True
    )
    assert "bundle verification PASSED" in proc.stdout
    assert "did not print 'bundle verification PASSED'" not in proc.stderr
    assert "is empty; refusing to proceed" not in proc.stderr
