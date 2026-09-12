"""Regression tests: the deb postinst must NEVER self-bootstrap the trust dir.

Gap (completeness critic, round 2): packaging/deb/postinst used to bootstrap
/usr/local/lib/udbmcp-trust from the deb's own trusted-tools/ payload when
the dir was absent, and to "complete" a partial admin install from it (only
missing files, never overwriting admin copies). Both directions are a trust
hole: the deb's trusted-tools copy travels on the SAME channel as the payload
it would verify, so a tampered package could ship a verifier that prints
"bundle verification PASSED" (or an installer that skips verification) and
have it installed to the root-owned trust path and executed there — exactly
the path an admin who skips the manual bootstrap hits. The hole was also
unexercised: the deb gate's tamper negative performed the admin trust
bootstrap first, so the self-bootstrap path was never tested.

Fix locked in here: the trust dir is an ADMIN prerequisite exactly like the
release pubkey. The postinst only CHECKS completeness (all four trusted
files) and fails closed with bootstrap instructions when the dir is absent or
incomplete — reachable without a preinst run via `dpkg --configure`, so the
postinst must enforce this on its own. The deb-shipped copy is inert
reference material: nothing in the package reads, copies or executes it.

Trust invariants exercised (never broken):
  1. no payload execution before a trusted verify_bundle.py --pubkey run
     (the deb's own verifier is never a trust anchor);
  2. the release pubkey is out-of-band (checked AFTER the trust-dir gate);
  4. fail closed on every verification failure.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

_POSIX = pytest.mark.skipif(sys.platform == "win32", reason="POSIX shell semantics; run on linux/macos")

_PROJECT = Path(__file__).resolve().parents[2]
_POSTINST = _PROJECT / "packaging" / "deb" / "postinst"
_BUILD_DEB = _PROJECT / "scripts" / "package" / "build_deb.sh"
_DEB_GATE = _PROJECT / "scripts" / "package" / "test_package_deb.sh"

_TRUST_FILES = ("verify_bundle.py", "profiles.py", "install_offline.sh", "lib/os_packages.sh")


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _executable_lines(text: str) -> str:
    """Strip full-line comments so assertions apply to code, not documentation."""
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def _bash_n(path: Path) -> None:
    proc = subprocess.run(  # noqa: S603 - fixed args, local script syntax check
        ["/bin/bash", "-n", str(path)], capture_output=True, text=True, timeout=60
    )
    assert proc.returncode == 0, proc.stderr


# ------------------------------------------------------------------- structure


@_POSIX
def test_postinst_passes_bash_syntax_check() -> None:
    _bash_n(_POSTINST)


@_POSIX
def test_step1_is_a_pure_completeness_gate() -> None:
    """Step 1 must CHECK the admin trust dir and fail closed; it must never
    write to it, and must never reference the deb-shipped trusted-tools copy
    in executable code at all."""
    code = _executable_lines(_read(_POSTINST))
    # Split the RAW text on the step-marker comments (they are comments, so
    # they are gone from `code`), then strip comments from the block.
    raw = _read(_POSTINST)
    step1 = _executable_lines(raw.split("# --- step 1", 1)[1].split("# --- step 2", 1)[0])
    # Every trusted file is required, one diagnostic, one exit.
    for rel in _TRUST_FILES:
        assert f'"{rel}"' in step1 or f"$TRUST_DIR/{rel}" in step1, f"step 1 must require {rel}"
    assert "trusted tool missing from the admin trust dir" in step1
    assert "exit 1" in step1
    assert "admin trust dir complete" in step1
    # No writes of any kind in step 1 (echo instructions in the diagnostic are
    # arguments to echo, never executed).
    assert not re.search(r"(?m)^\s*(install|cp|mkdir|cat|tee)\b", step1), (
        "step 1 must be a pure check: no install/cp/mkdir/cat writes"
    )
    # The deb-shipped copy is not even named in executable code.
    assert "TRUSTED_TOOLS" not in code, (
        "postinst must never reference the deb-shipped trusted-tools copy"
    )


@_POSIX
def test_build_deb_gates_against_self_bootstrap_regression() -> None:
    """build_deb.sh must fail the build if the postinst ever regrows a
    self-bootstrap (any TRUSTED_TOOLS reference) or loses the fail-closed
    completeness check."""
    code = _executable_lines(_read(_BUILD_DEB))
    assert 'grep -q \'TRUSTED_TOOLS\' "$DEBROOT/DEBIAN/postinst"' in code
    assert "must NEVER bootstrap or complete /usr/local/lib/udbmcp-trust from the package payload" in code
    assert "trusted tool missing from the admin trust dir" in code


@_POSIX
def test_deb_gate_has_negative_case_without_admin_bootstrap() -> None:
    """The deb gate must exercise the no-bootstrap path: a stubbed deb-shipped
    verifier ('bundle verification PASSED') with NO admin trust dir and NO
    pubkey must fail closed — postinst refusal + dpkg -i abort."""
    gate = _read(_DEB_GATE)
    assert "bundle verification PASSED" in gate, "the gate must stub the deb verifier with the canonical PASSED lie"
    assert "NEGATIVE2_EOF" in gate
    assert "postinst_refuses_self_bootstrap" in gate
    assert "no_admin_bootstrap" in gate
    # The negative-2 runner deliberately mounts NO /trust and NO /pubkey
    # (split on the runner's echo marker — the header comment mentions the
    # case earlier, before negative 1's /trust mounts).
    neg2_runner = gate.split('echo "==> NEGATIVE case 2:', 1)[1]
    assert "/trust/" not in neg2_runner.split("NEG2_RC", 1)[0]
    assert "/pubkey.pem" not in neg2_runner.split("NEG2_RC", 1)[0]


# ------------------------------------------------- functional (full sandbox run)


def _sandbox_postinst(tmp_path: Path) -> Path:
    """Rewrite the WHOLE postinst into a sandbox: every path constant points
    into tmp_path, dpkg's lock files and the worker temp dir become sandbox
    paths, and root/udbmcp ownership flags are dropped so the flow could run
    as a non-root test user. Ordering and all fail-closed logic untouched.
    (These tests expect the postinst to abort in step 1; the full rewrite
    guarantees that even a regression cannot touch the real host tree.)"""
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


def _make_deb_payload(tmp_path: Path, verifier_body: str) -> Path:
    """The deb-shipped trusted-tools copy (inert reference material, exactly
    as a real deb stages it). `verifier_body` lets a test poison the shipped
    verifier so that EXECUTING it leaves a marker."""
    tools = tmp_path / "trusted_tools"
    (tools / "lib").mkdir(parents=True, exist_ok=True)
    (tools / "verify_bundle.py").write_text(verifier_body, encoding="utf-8")
    (tools / "profiles.py").write_text("# deb-shipped profiles\n", encoding="utf-8")
    (tools / "install_offline.sh").write_text("# deb-shipped installer\n", encoding="utf-8")
    (tools / "lib" / "os_packages.sh").write_text("# deb-shipped lib\n", encoding="utf-8")
    return tools


@_POSIX
def test_missing_trust_dir_fails_closed_and_never_copies_or_runs_payload(tmp_path: Path) -> None:
    """The critic's concrete check, in a sandbox: a deb whose shipped verifier
    is a PASSED-printing stub, installed with NO admin trust dir. The postinst
    (the dpkg --configure path, no preinst) must abort, create NOTHING at the
    trust-dir path, and never execute the shipped verifier."""
    poison = tmp_path / "poison-ran"
    verifier_body = (
        "import pathlib, sys\n"
        f'pathlib.Path("{poison}").write_text("ran\\n")\n'
        "print('bundle verification PASSED')\n"
        "sys.exit(0)\n"
    )
    _make_deb_payload(tmp_path, verifier_body)

    script = _sandbox_postinst(tmp_path)
    proc = subprocess.run(["/bin/bash", str(script)], capture_output=True, text=True, timeout=60)  # noqa: S603
    assert proc.returncode != 0, f"postinst must fail closed without the admin trust dir: {proc.stdout}"
    assert "trusted tool missing from the admin trust dir" in proc.stderr
    assert "NEVER bootstraps" in proc.stderr
    # Fail closed, three ways: no trust dir, no copy of the payload into one,
    # and the shipped (stub) verifier never executed.
    assert not (tmp_path / "trust_dir").exists()
    assert not poison.exists(), "the deb-shipped verifier was EXECUTED by the postinst"
    assert "bundle verification PASSED" not in proc.stdout


@_POSIX
def test_incomplete_admin_trust_dir_is_never_completed_from_the_deb(tmp_path: Path) -> None:
    """An admin trust dir missing files must abort even though the deb payload
    COULD supply them: completion from the package would let a tampered
    package install its own verifier/installer/lib as root."""
    verifier_body = "# admin-context: deb-shipped verifier (must never run)\nimport sys\nsys.exit(1)\n"
    tools = _make_deb_payload(tmp_path, verifier_body)

    trust = tmp_path / "trust_dir"
    (trust / "lib").mkdir(parents=True)
    (trust / "verify_bundle.py").write_text("# admin verifier\n", encoding="utf-8")
    (trust / "install_offline.sh").write_text("# admin installer\n", encoding="utf-8")
    # profiles.py and lib/os_packages.sh deliberately missing from the ADMIN dir.

    script = _sandbox_postinst(tmp_path)
    proc = subprocess.run(["/bin/bash", str(script)], capture_output=True, text=True, timeout=60)  # noqa: S603
    assert proc.returncode != 0
    assert "trusted tool missing from the admin trust dir" in proc.stderr
    # The missing files were NOT completed from the (present!) deb payload...
    assert not (trust / "profiles.py").exists()
    assert not (trust / "lib" / "os_packages.sh").exists()
    # ...the deb-shipped copy is untouched...
    assert (tools / "profiles.py").read_text() == "# deb-shipped profiles\n"
    # ...and the admin-provided files are byte-identical.
    assert (trust / "verify_bundle.py").read_text() == "# admin verifier\n"
    assert (trust / "install_offline.sh").read_text() == "# admin installer\n"


def _step1_and_step2_script(tmp_path: Path) -> Path:
    """Extract postinst's variable definitions + the step-1 completeness gate
    + the step-2 pubkey gate (nothing after it) into a sandbox script, so a
    test can prove a COMPLETE admin trust dir passes step 1 and reaches the
    pubkey prerequisite."""
    text = _read(_POSTINST)
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith("# --- step 1"))
    end = next(i for i, line in enumerate(lines) if line.startswith("# --- step 3"))
    defs = [line for line in lines[:start] if re.match(r"^[A-Z_]+=/", line)]
    rewritten = []
    for line in defs + lines[start:end]:
        match = re.match(r"^([A-Z_]+)=/.+$", line)
        if match:
            line = f"{match.group(1)}={tmp_path / match.group(1).lower()}"
        rewritten.append(line)
    script = tmp_path / "postinst_step12.sh"
    script.write_text("#!/bin/bash\nset -e\n" + "\n".join(rewritten) + "\n", encoding="utf-8")
    return script


@_POSIX
def test_complete_admin_trust_dir_reaches_the_pubkey_gate(tmp_path: Path) -> None:
    """A complete admin trust dir must PASS step 1 and the flow must proceed
    to the out-of-band pubkey prerequisite (step 2): without the pubkey it
    fails with the pubkey diagnostic — proving the trust-dir gate did not
    block a legitimate, admin-bootstrapped install."""
    trust = tmp_path / "trust_dir"
    (trust / "lib").mkdir(parents=True)
    (trust / "verify_bundle.py").write_text("# admin verifier\n", encoding="utf-8")
    for rel in ("profiles.py", "install_offline.sh"):
        (trust / rel).write_text("# admin copy\n", encoding="utf-8")
    (trust / "lib" / "os_packages.sh").write_text("# admin lib\n", encoding="utf-8")

    script = _step1_and_step2_script(tmp_path)
    # No pubkey yet: step 1 must PASS (rc comes from step 2's pubkey gate).
    proc = subprocess.run(["/bin/bash", str(script)], capture_output=True, text=True, timeout=60)  # noqa: S603
    assert proc.returncode != 0
    assert "release public key not found" in proc.stderr
    assert "trusted tool missing from the admin trust dir" not in proc.stderr

    # With the pubkey in place both gates pass.
    (tmp_path / "pubkey").write_text("-----BEGIN PUBLIC KEY-----\nsbx\n-----END PUBLIC KEY-----\n", encoding="utf-8")
    proc = subprocess.run(["/bin/bash", str(script)], capture_output=True, text=True, timeout=60)  # noqa: S603
    assert proc.returncode == 0, proc.stderr
    assert "admin trust dir complete" in proc.stdout
