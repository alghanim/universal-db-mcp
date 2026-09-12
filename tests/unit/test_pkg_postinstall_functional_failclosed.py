"""FUNCTIONAL fail-closed regression tests for ``packaging/pkg/postinstall``.

Gap this file closes (completeness critic, round 1): every other trust-bearing
maintainer script in this repo has an EXECUTED fail-closed regression test —
deb preinst/postinst/postrm run in path-rewritten sandboxes
(test_deb_packaging.py, test_deb_postrm_purge.py), deb prerm is executed for
its no-action refusal (test_deb_packaging.py), and pkg preinstall has a real
execution gate (test_pkg_packaging.py). ``pkg postinstall`` — the macOS
verify-before-execute gate — was guarded ONLY by regex content gates
(test_pkg_packaging.py, test_pkg_postinstall_hardening.py, both explicitly
"pure text-content gates"). Demonstrated blind spot: a mutant that rewrote the
verifier's fatal ``|| { fail ... }`` branch into ``|| echo`` passed all 33
existing pkg tests while proceeding PAST verification into service-account
provisioning — exactly the failure class postinstall exists to prevent.

These tests therefore EXECUTE postinstall in a sandbox, the same
extract-and-rewrite technique the deb tests use:

- hardcoded path constants (PREFIX, CONFIG_DIR, STATE_DIR, LOG_DIR, PLIST and
  the two CPython 3.12 candidate paths) are sed-rewritten into ``tmp_path``
  (PREFIX has no env override — the trust inputs do:
  ``UDBMCP_TRUST_DIR``/``UDBMCP_VERIFIER``/``UDBMCP_RELEASE_PUBKEY``);
- the trusted verifier is a stub under tmp_path (outside the bundle);
- ``dscl``/``launchctl`` are PATH shims that only log, so the real system
  directory services and launchd are never touched. postinstall re-prepends
  the system dirs to PATH internally (its launchd-PATH workaround), which
  would shadow the inherited shims — that re-assignment is rewritten to
  ``PATH="$PATH"`` too, so the shim dir inherited at the front of PATH
  genuinely intercepts dscl/launchctl;
- the CPython 3.12 candidates point at a ``python312-sandbox`` shim: postinstall
  selects the interpreter BEFORE running the verifier (never a PATH search), so
  the sandbox must supply the preinstall-validated candidate; it passes the
  `-c` prerequisite probes and executes the verifier stub via the host python3.

Invariant 1 (nothing executes payload before the trusted-channel verifier
passes) and invariant 2 (pubkey never sourced from the bundle) are asserted
functionally: a tampered payload (verifier exit 3), a missing verifier, a
missing pubkey, and a verifier placed inside the bundle must each abort with
the canonical FAIL diagnostic BEFORE any provisioning step runs.

Pure stdlib + pytest; needs /bin/bash (POSIX). Skipped on Windows like the
sibling pkg tests.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess  # noqa: S404 - executes the sandboxed producer script only
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="macOS .pkg packaging is POSIX-only"
)

PROJECT = Path(__file__).resolve().parents[2]
POSTINSTALL = PROJECT / "packaging" / "pkg" / "postinstall"

# The exact fatal branch on the verifier invocation. Functional tests below
# fail closed when this disappears; this tight text gate names the regression
# directly (a swallowed `|| { fail ... }` is the mutant that passed all
# content-gate suites).
_FATAL_VERIFY_BRANCH = re.compile(
    r'\$VEXEC "\$VERIFIER" --bundle "\$BUNDLE" --pubkey "\$PUBKEY"\s*\|\|\s*\{\s*\n'
    r'\s*fail "bundle verification FAILED'
)

_PATH_REWRITES = [
    (r'^PREFIX="/usr/local/universal-db-mcp"$', 'PREFIX="{prefix}"'),
    (r'^CONFIG_DIR="/etc/universal-db-mcp"$', 'CONFIG_DIR="{etc}"'),
    (r'^STATE_DIR="/var/lib/universal-db-mcp"$', 'STATE_DIR="{state}"'),
    (r'^LOG_DIR="/var/log/universal-db-mcp"$', 'LOG_DIR="{log}"'),
    (r'^PLIST="/Library/LaunchDaemons/com\.udbmcp\.server\.plist"$', 'PLIST="{plist}"'),
    # The interpreter candidates are absolute paths with no env override: point
    # both at the sandbox py shim — postinstall selects the interpreter (the
    # preinstall-approved candidate) BEFORE executing the verifier, so the
    # sandbox must supply one regardless of what the host has installed.
    (
        r'^FRAMEWORK_PY="/Library/Frameworks/Python\.framework/Versions/3\.12/bin/python3"$',
        'FRAMEWORK_PY="{pyshim}"',
    ),
    (r'^USR_LOCAL_PY="/usr/local/bin/python3"$', 'USR_LOCAL_PY="{pyshim}"'),
    # postinstall re-prepends the system dirs to PATH (its launchd-minimal-PATH
    # workaround), which would put the REAL /usr/bin/dscl and /bin/launchctl
    # ahead of the sandbox shim dir inherited via env["PATH"] — leaving the
    # `_shim_invocations(...) == []` guards vacuous and the real directory
    # service reachable by a verify-branch mutant. Drop the prepend so the
    # inherited PATH (shim dir first) stays in effect inside the sandbox copy.
    (
        r'^PATH="/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin:\$PATH"$',
        'PATH="$PATH"',
    ),
]


def _require_script() -> str:
    assert POSTINSTALL.is_file(), f"missing producer file: {POSTINSTALL}"
    return POSTINSTALL.read_text(encoding="utf-8")


def _sandbox_postinstall(tmp_path: Path, *, verifier: str | None = None, pubkey: str | None = None) -> Path:
    """Copy postinstall with its hardcoded paths rewritten into tmp_path.

    Trust inputs (verifier/pubkey) keep their env overrides; the caller points
    them at the sandbox (or at an in-bundle location for the refusal test).
    """
    text = _require_script()
    dirs = {
        "prefix": str(tmp_path / "prefix"),
        "etc": str(tmp_path / "etc"),
        "state": str(tmp_path / "state"),
        "log": str(tmp_path / "log"),
        "plist": str(tmp_path / "com.udbmcp.server.plist"),
        "pyshim": str(tmp_path / "shim-bin" / "python312-sandbox"),
    }
    for pattern, replacement in _PATH_REWRITES:
        new_text, n = re.subn(pattern, replacement.format(**dirs), text, flags=re.MULTILINE)
        assert n == 1, f"path-rewrite pattern matched {n} times (expected 1): {pattern}"
        text = new_text
    # comments still document the real paths; only EXECUTABLE lines must be sandboxed
    code = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    assert "/usr/local/universal-db-mcp" not in code, "sandbox rewrite missed a hardcoded prefix"
    script = tmp_path / "postinstall_sbx.sh"
    script.write_text(text, encoding="utf-8")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return script


def _build_bundle(tmp_path: Path) -> Path:
    """Minimal unpacked payload: manifest + config template at <prefix>/bundle."""
    bundle = tmp_path / "prefix" / "bundle"
    (bundle / "config-templates").mkdir(parents=True)
    (bundle / "manifest.json").write_text("{}\n", encoding="utf-8")
    (bundle / "config-templates" / "config.yaml").write_text("# sandbox template\n", encoding="utf-8")
    return bundle


def _verifier_stub(tmp_path: Path, name: str, *, exit_code: int) -> Path:
    stub = tmp_path / "trust" / name
    stub.parent.mkdir(parents=True, exist_ok=True)
    stub.write_text(
        "import sys\n"
        'print("SIGNATURE MISMATCH: sandbox tampered payload", file=sys.stderr)\n'
        f"sys.exit({exit_code})\n",
        encoding="utf-8",
    )
    return stub


def _pubkey_stub(tmp_path: Path, *, name: str = "release.pub.pem") -> Path:
    key = tmp_path / "keys" / name
    key.parent.mkdir(parents=True, exist_ok=True)
    key.write_text(
        "-----BEGIN PUBLIC KEY-----\nSANDBOX-NOT-A-REAL-KEY\n-----END PUBLIC KEY-----\n",
        encoding="utf-8",
    )
    return key


def _shim_bin(tmp_path: Path) -> Path:
    """PATH shims for dscl/launchctl (log invocations, never touch the system)
    and for the preinstall-validated CPython 3.12 candidate: the py shim passes
    the `-c` prerequisite probes and executes the trusted verifier stub by
    delegating to the host python3 (resolved beyond the shim dir — the shim is
    named python312-sandbox, so `python3` cannot re-enter it). It does NOT log
    into shims.log, which the tests below pin to dscl/launchctl only."""
    log = tmp_path / "shims.log"
    bin_dir = tmp_path / "shim-bin"
    bin_dir.mkdir(exist_ok=True)
    for tool in ("dscl", "launchctl"):
        shim = bin_dir / tool
        shim.write_text(
            "#!/bin/sh\n"
            f'printf \'{tool} "$*"\\n\' >> "{log}"\n'
            "# fail loudly so a script that wrongly reaches provisioning aborts\n"
            "exit 1\n",
            encoding="utf-8",
        )
        shim.chmod(shim.stat().st_mode | stat.S_IXUSR)
    pyshim = bin_dir / "python312-sandbox"
    pyshim.write_text(
        "#!/bin/sh\n"
        "# rewritten preinstall-approved candidate: `-c` probes pass; anything\n"
        "# else is the trusted verifier stub executing under this interpreter.\n"
        'if [ "$1" = "-c" ]; then exit 0; fi\n'
        'exec python3 "$@"\n',
        encoding="utf-8",
    )
    pyshim.chmod(pyshim.stat().st_mode | stat.S_IXUSR)
    return bin_dir


def _shim_invocations(tmp_path: Path) -> list[str]:
    log = tmp_path / "shims.log"
    return log.read_text(encoding="utf-8").splitlines() if log.exists() else []


# --------------------------------------------------------------------------
# content gate: the fatal verifier branch must exist (names the mutant class)
# --------------------------------------------------------------------------


def test_verifier_failure_branch_is_fatal() -> None:
    m = _FATAL_VERIFY_BRANCH.search(_require_script())
    assert m, (
        "postinstall's verifier invocation must keep its fatal `|| { fail \"bundle verification "
        "FAILED ...\" }` branch; swallowing it lets an unverified payload proceed to provisioning"
    )


# --------------------------------------------------------------------------
# functional: executed sandbox, one test per fail-closed prerequisite
# --------------------------------------------------------------------------


def test_functional_tampered_payload_aborts_before_provisioning(tmp_path: Path) -> None:
    """Trust invariant 1, executed: verifier exit 3 (tampered/corrupt payload)
    must abort with the canonical diagnostic BEFORE the service-account,
    venv, or launchctl steps run — i.e. nothing touches the payload or the
    system once verification fails."""
    script = _sandbox_postinstall(tmp_path)
    _build_bundle(tmp_path)
    env = dict(os.environ)
    env["UDBMCP_VERIFIER"] = str(_verifier_stub(tmp_path, "verify_bundle.py", exit_code=3))
    env["UDBMCP_RELEASE_PUBKEY"] = str(_pubkey_stub(tmp_path))
    bin_dir = _shim_bin(tmp_path)
    env["PATH"] = f"{bin_dir}:{env.get('PATH', '')}"

    proc = subprocess.run(  # noqa: S603 - fixed args, sandboxed copy
        ["/bin/bash", str(script)], capture_output=True, text=True, timeout=120, env=env
    )
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0, f"tampered payload must fail closed:\n{out}"
    assert "FAIL: bundle verification FAILED" in out, f"canonical diagnostic required:\n{out}"
    assert "SIGNATURE MISMATCH" in out, "the sandbox verifier's complaint must be surfaced"
    # aborted BEFORE provisioning: no dscl/launchctl, no venv
    shims = _shim_invocations(tmp_path)
    assert shims == [], f"provisioning ran despite failed verification:\n{shims}"
    assert not (tmp_path / "prefix" / "venv").exists(), "venv must not be built from an unverified payload"


def test_functional_missing_verifier_fails_closed(tmp_path: Path) -> None:
    script = _sandbox_postinstall(tmp_path)
    _build_bundle(tmp_path)
    env = dict(os.environ)
    env["UDBMCP_VERIFIER"] = str(tmp_path / "trust" / "absent-verify_bundle.py")
    env["UDBMCP_RELEASE_PUBKEY"] = str(_pubkey_stub(tmp_path))
    env["PATH"] = f"{_shim_bin(tmp_path)}:{env.get('PATH', '')}"

    proc = subprocess.run(  # noqa: S603 - fixed args, sandboxed copy
        ["/bin/bash", str(script)], capture_output=True, text=True, timeout=120, env=env
    )
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0, f"missing verifier must fail closed:\n{out}"
    assert "trusted verifier not found" in out, f"canonical diagnostic required:\n{out}"
    assert _shim_invocations(tmp_path) == []


def test_functional_missing_pubkey_fails_closed(tmp_path: Path) -> None:
    """Trust invariant 2, executed: with the admin pubkey absent (admin
    skipped the out-of-band trust bootstrap), postinstall must abort — never
    fall back to a key shipped inside the bundle or the package."""
    script = _sandbox_postinstall(tmp_path)
    bundle = _build_bundle(tmp_path)
    # a pubkey sitting inside the bundle must NOT be picked up as a fallback
    in_bundle_key = "-----BEGIN PUBLIC KEY-----\nIN-BUNDLE\n-----END PUBLIC KEY-----\n"
    (bundle / "release.pub.pem").write_text(in_bundle_key, encoding="utf-8")
    env = dict(os.environ)
    env["UDBMCP_VERIFIER"] = str(_verifier_stub(tmp_path, "verify_bundle.py", exit_code=0))
    env["UDBMCP_RELEASE_PUBKEY"] = str(tmp_path / "keys" / "absent.pub.pem")
    env["PATH"] = f"{_shim_bin(tmp_path)}:{env.get('PATH', '')}"

    proc = subprocess.run(  # noqa: S603 - fixed args, sandboxed copy
        ["/bin/bash", str(script)], capture_output=True, text=True, timeout=120, env=env
    )
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0, f"missing pubkey must fail closed:\n{out}"
    assert "release pubkey not found" in out, f"canonical diagnostic required:\n{out}"
    assert _shim_invocations(tmp_path) == []


def test_functional_verifier_inside_bundle_is_refused(tmp_path: Path) -> None:
    """Executed: a verifier shipped inside the bundle it verifies would print
    PASSED unconditionally — postinstall must refuse it even when present."""
    script = _sandbox_postinstall(tmp_path)
    bundle = _build_bundle(tmp_path)
    in_bundle = _verifier_stub(bundle, "verify_bundle.py", exit_code=0)
    env = dict(os.environ)
    env["UDBMCP_VERIFIER"] = str(in_bundle)
    env["UDBMCP_RELEASE_PUBKEY"] = str(_pubkey_stub(tmp_path))
    env["PATH"] = f"{_shim_bin(tmp_path)}:{env.get('PATH', '')}"

    proc = subprocess.run(  # noqa: S603 - fixed args, sandboxed copy
        ["/bin/bash", str(script)], capture_output=True, text=True, timeout=120, env=env
    )
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0, f"in-bundle verifier must be refused:\n{out}"
    assert "refusing to verify with a verifier inside the bundle" in out, f"canonical diagnostic required:\n{out}"
    assert _shim_invocations(tmp_path) == []
