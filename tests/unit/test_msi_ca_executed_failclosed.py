"""EXECUTED fail-closed regression tests for ``packaging/msi/custom/verify.ps1``.

Gap 30 (completeness critic, /tmp/gaps_final.json, round 2): verify.ps1 is the
Windows verify-before-execute gate (nothing in the installed bundle may run
before the ADMIN-installed trusted verifier passes), yet every test of it was
a pure content gate: test_msi_custom_actions.py and
test_msi_ca_verify_wiring.py assert strings/regexes over the .ps1 sources and
never execute anything.

Execution strategy, honestly stated:

- pwsh is NOT installed on the staging host this suite was written on
  (``command -v pwsh``: not found), and the Windows runtime is ledgered
  ``not_run`` in IMPLEMENTATION_STATUS.md. The ps1-driven tests below are
  therefore written against the real script and SKIP when pwsh is absent;
  they run verbatim wherever pwsh exists (they deliberately avoid the
  containment cases, whose ``Test-InsideDir`` backslash prefix semantics are
  Windows-path specific).
- Because the fail-closed DECISIONS must be regression-locked on THIS host
  too, the module carries an executed PYTHON TWIN of verify.ps1
  (``_TWIN_SOURCE``): a branch-for-branch translation of the script's actual
  decision flow (CustomActionData parsing, BUNDLE_DIR requirement, the four
  inside-the-bundle containment refusals, verifier/profiles/pubkey/interpreter
  prerequisites, and the exit-0-only-with-proof rule). Each twin branch cites
  the verify.ps1 region it mirrors, and the ``test_twin_matches_*`` content
  gates pin the corresponding source lines in verify.ps1 itself, so the twin
  and the producer cannot silently drift apart: if verify.ps1 changes a
  decision, its pin fails and the twin must be re-derived.

Every ``test_twin_*`` test EXECUTES the twin as a subprocess (the same
out-of-process discipline as the ps1 itself) against a sandbox bundle, a stub
trusted verifier OUTSIDE the bundle, and no network, no root, no msiexec.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess  # noqa: S404 - executes the twin/ps1 under test only
import sys
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parents[2]
VERIFY_PS1 = PROJECT / "packaging" / "msi" / "custom" / "verify.ps1"
PWSH = shutil.which("pwsh")

pytestmark = pytest.mark.skipif(
    sys.platform == "win32" and PWSH is None,
    reason="pwsh is required to execute verify.ps1 on Windows",
)

# ---------------------------------------------------------------------------
# The executed python twin. Branch-for-branch mirror of verify.ps1; DO NOT
# "improve" the diagnostics here — they are the MSI's operator-facing contract
# and must stay identical to the producer's.
# ---------------------------------------------------------------------------

_TWIN_SOURCE = r'''
#!/usr/bin/env python3
"""Executed python twin of packaging/msi/custom/verify.ps1 (see
tests/unit/test_msi_ca_executed_failclosed.py for the tie and the drift pins).
Mirrors the script's decision ORDER and diagnostics exactly."""
import os
import re
import subprocess
import sys


def fail(msg):  # verify.ps1 function 'Fail': FAIL line + aborted line + exit 1
    print(f"FAIL: {msg}")
    print("universal-db-mcp: installation ABORTED (fail closed); msiexec will roll back.")
    sys.exit(1)


def real_path(path):  # verify.ps1 function 'Real-Path': GetFullPath, trim trailing sep
    ap = os.path.abspath(path)
    return ap.rstrip(os.sep) if ap != os.sep else ap


def inside_dir(candidate, directory):  # verify.ps1 'Test-InsideDir': sep-bounded prefix
    c = real_path(candidate) + os.sep
    d = real_path(directory) + os.sep
    return c.lower().startswith(d.lower())


try:  # verify.ps1 top-level try -> catch { Fail "unexpected error ..." }
    custom = sys.argv[1] if len(sys.argv) > 1 else ""

    # --- parse CustomActionData (verify.ps1: malformed pair -> Fail) --------
    data = {}
    for pair in custom.split(";"):
        t = pair.strip()
        if not t:
            continue
        idx = t.find("=")
        if idx < 1:
            fail("malformed CustomActionData pair '" + t + "' (expected KEY=VALUE); "
                 "this is a packaging bug in udbmcp.wxs, not an admin problem.")
        # ALLOW_DOWNGRADE carries a public msiexec property and the wxs passes
        # it last: a key after it (or one named twice) came from a ';' in it.
        # verify.ps1's @{} hashtable ignores the case of its keys: so does
        # this one (stored upper-case, named as given).
        key = t[:idx]
        if "ALLOW_DOWNGRADE" in data:
            fail("CustomActionData names " + key + " after ALLOW_DOWNGRADE; a msiexec property value "
                 "may not contain ';'.")
        if key.upper() in data:
            fail("CustomActionData names " + key + " twice; a msiexec property value may not contain ';'.")
        data[key.upper()] = t[idx + 1:].strip()

    # --- BUNDLE_DIR required and must exist (verify.ps1 prerequisite block) --
    if not data.get("BUNDLE_DIR"):
        fail("BUNDLE_DIR missing from CustomActionData; the wxs must pass the "
             "installed bundle path (packaging bug), so verification cannot proceed.")
    bundle_dir = data["BUNDLE_DIR"]
    if not os.path.isdir(bundle_dir):
        fail("installed bundle directory not found at " + bundle_dir +
             " (wrong BUNDLE_DIR wiring in udbmcp.wxs?).")

    # --- this script itself must not run from inside the bundle --------------
    ps_command_path = os.environ.get("UDBMCP_SANDBOX_PS_COMMAND_PATH", "")
    if ps_command_path and inside_dir(ps_command_path, bundle_dir):
        fail("this verifier is running from inside the bundle (" + ps_command_path +
             "); the verifier MUST come from the trust directory outside the bundle, "
             "never from the payload it would verify.")

    # --- trust dir resolution + containment (a bundle trust dir proves nada) --
    trust_dir = data.get("TRUST_DIR") or os.environ.get("UDBMCP_TRUST_DIR") \
        or os.path.join(os.environ.get("ProgramFiles", os.path.join(os.sep, "Program Files")), "udbmcp-trust")
    verifier = os.path.join(trust_dir, "verify_bundle.py")
    if inside_dir(trust_dir, bundle_dir):
        fail("trust directory (" + trust_dir + ") is inside the installed bundle (" +
             bundle_dir + "); a verifier from the payload proves nothing.")

    # --- prerequisite 1: trusted verifier + its profiles registry ------------
    if not os.path.isfile(verifier):
        fail("trusted verifier not found at " + verifier + "; installation ABORTED (fail closed).")
    profiles_py = None
    for candidate in (os.path.join(trust_dir, "profiles.py"),
                      os.path.join(trust_dir, "lib", "profiles.py")):
        if os.path.isfile(candidate):
            profiles_py = candidate
            break
    if not profiles_py:
        fail("profiles.py not found in the trust directory (" + trust_dir +
             "); installation ABORTED (fail closed).")
    # a verifier that parses options but predates --installed-manifest would
    # stop on the unknown option: name the fix instead
    with open(verifier, encoding="utf-8", errors="replace") as fh:
        verifier_text = fh.read()
    if '"--pubkey"' in verifier_text and '"--installed-manifest"' not in verifier_text:
        fail("the trusted verifier at " + verifier + " is an OUTDATED copy (no --installed-manifest "
             "option): it cannot refuse a downgrade to an older release. Install verify_bundle.py and "
             "profiles.py from this release's trusted channel into " + trust_dir +
             ", then re-run the installer.")

    # --- prerequisite 2: release pubkey, NEVER shipped in the MSI ------------
    pubkey = data.get("PUBKEY") or os.environ.get("UDBMCP_RELEASE_PUBKEY")
    if not pubkey:
        fail("release public key not configured (UDBMCP_RELEASE_PUBKEY); "
             "installation ABORTED (fail closed).")
    if not os.path.isfile(pubkey):
        fail("release public key not found at " + pubkey + "; installation ABORTED (fail closed).")
    if inside_dir(pubkey, bundle_dir):
        fail("release public key (" + pubkey + ") is inside the installed bundle (" +
             bundle_dir + "); a key shipped with the payload authenticates nothing.")

    # --- prerequisite 3: an interpreter OUTSIDE the bundle -------------------
    # The producer (verify.ps1) additionally resolves a missing PYTHON from
    # the PER-MACHINE HKLM PEP 514 hive ONLY (never py.exe/PATH/HKCU: a local
    # non-admin can register a per-user interpreter, which would then run as
    # LocalSystem before the bundle is verified) and version-probes the
    # registry-resolved interpreter for 3.12. Both branches are Windows-only
    # (no HKLM on POSIX); they are locked by content drift pins in
    # _TWIN_TIE_PINS instead of mirrored here.
    py_exe = data.get("PYTHON") or os.environ.get("UDBMCP_PYTHON")
    if py_exe:
        if not os.path.isfile(py_exe):
            fail("configured python interpreter not found at " + py_exe +
                 " (PYTHON in CustomActionData or UDBMCP_PYTHON).")
    else:
        fail("no python interpreter available to run the trusted verifier; "
             "installation ABORTED (fail closed).")
    if inside_dir(py_exe, bundle_dir):
        fail("python interpreter (" + py_exe + ") is inside the installed bundle; "
             "bundle payload (including its python) may not execute before verification passes.")

    # --- anti-rollback: the installed release's manifest where the wxs says
    #     (else beside the bundle); the override is per run (CustomActionData
    #     only) -----------------------------------------------------------------
    # (verify.ps1 also refuses a record that is a reparse point, that a
    # non-admin owns or that grants anybody else write access: Windows ACL
    # APIs, locked by drift pins instead.)
    installed_manifest = data.get("INSTALLED_MANIFEST") or os.path.join(
        os.path.dirname(real_path(bundle_dir)), "manifest.json")
    rollback_args = ["--installed-manifest", installed_manifest]
    if data.get("ALLOW_DOWNGRADE") == "1":
        rollback_args.append("--allow-downgrade")
        print("WARNING: ALLOW_DOWNGRADE=1 (msiexec UDBMCP_ALLOW_DOWNGRADE=1): an OLDER release than the "
              "installed one is accepted for this install only.")
    elif data.get("ALLOW_DOWNGRADE"):
        fail("ALLOW_DOWNGRADE='" + data["ALLOW_DOWNGRADE"] + "' is not understood; pass "
             "UDBMCP_ALLOW_DOWNGRADE=1 to msiexec to accept an older release, or leave it unset.")

    # --- run the ONE trusted verifier (verify.ps1: exit code + output are the
    #     ONLY decision inputs), isolated (-I) ---------------------------------
    proc = subprocess.run(
        [py_exe, "-I", verifier, "--bundle", bundle_dir, "--pubkey", pubkey, *rollback_args],
        capture_output=True, text=True,
    )
    out = (proc.stdout or "") + (proc.stderr or "")
    for line in out.splitlines():
        if line.strip():
            print("  verify: " + line)

    # --- fail closed on EVERY non-passing outcome ----------------------------
    if proc.returncode != 0 and re.search(r"(?m)^FAIL: rollback refused", out):
        fail("this MSI carries an OLDER release than the one installed (see 'verify:' lines above); "
             "installation ABORTED. To downgrade on purpose, run msiexec with "
             "UDBMCP_ALLOW_DOWNGRADE=1 for that one install.")
    if proc.returncode != 0:
        fail("trusted verifier exited " + str(proc.returncode) +
             " (see 'verify:' lines above). The bundle is untrusted: installation ABORTED.")
    if re.search(r"(?m)^FAIL:", out):
        fail("trusted verifier reported FAIL (see above); the bundle is untrusted: "
             "installation ABORTED.")
    if "bundle verification PASSED" not in out:
        fail("trusted verifier exited 0 but did not print 'bundle verification PASSED'; "
             "without explicit proof of verification the bundle is treated as untrusted: "
             "installation ABORTED.")

    print("==> universal-db-mcp: installed bundle verified (twin); payload may now be used.")
    sys.exit(0)  # the ONLY exit-0 path: verification passed with proof
except SystemExit:
    raise
except Exception as exc:  # verify.ps1 catch-all -> Fail
    fail("unexpected error during bundle verification: " + str(exc))
'''

# Drift pins: each regex must keep matching verify.ps1, tying the twin branch
# (left comment) to the producer line it mirrors. If one of these fails,
# verify.ps1's decision flow changed and the twin must be re-derived.
_TWIN_TIE_PINS: tuple[tuple[str, str], ...] = (
    ("twin: fail-closed preference on any cmdlet error", r"\$ErrorActionPreference\s*=\s*'Stop'"),
    ("twin: exit-code != 0 decision", r"if \(\$verifierExit -ne 0\)"),
    ("twin: FAIL-line decision (regex literal)", r"'\(\?m\)\^FAIL:'"),
    ("twin: proof-of-verification decision", r"-notmatch 'bundle verification PASSED'"),
    ("twin: PSCommandPath containment", r"Test-InsideDir \$PSCommandPath \$BundleDir"),
    ("twin: trust-dir containment", r"Test-InsideDir \$TrustDir \$BundleDir"),
    ("twin: pubkey containment", r"Test-InsideDir \$PubKey \$BundleDir"),
    ("twin: interpreter containment", r"Test-InsideDir \$pyExe \$BundleDir"),
    ("twin: interpreter pinned to the per-machine HKLM PEP 514 hive "
     "(never py.exe/PATH/HKCU -- a non-admin can register a per-user "
     "interpreter that would otherwise run as LocalSystem)",
     r"HKLM:\\SOFTWARE\\Python\\PythonCore\\3\.12\\InstallPath"),
    ("twin: registry-resolved interpreter version probe (cp312 before the "
     "trusted verifier is executed with it)",
     r"sys\.version_info\[:2\] == \(3, 12\)"),
    ("twin: exit 0 only after proof", r"The ONLY exit-0 path: verification passed with proof"),
    ("twin: outdated-verifier refusal (no --installed-manifest option)",
     r"""\$verifierText\.Contains\('"--pubkey"'\) -and -not \$verifierText\.Contains\('"--installed-manifest"'\)"""),
    ("twin: the installed release's manifest beside the bundle",
     r"\$InstalledManifest = Join-Path \(Split-Path -Parent \(Real-Path \$BundleDir\)\) 'manifest\.json'"),
    ("twin: the downgrade override comes from CustomActionData only",
     r"if \(\$data\['ALLOW_DOWNGRADE'\] -eq '1'\) \{"),
    ("twin: the older-release diagnostic", r"'\(\?m\)\^FAIL: rollback refused'"),
    ("twin: the verifier runs isolated", r"\$pyArgs = @\('-I'\)"),
    ("twin: a CustomActionData key given twice is refused", r"if \(\$data\.ContainsKey\(\$key\)\) \{"),
    ("twin: CustomActionData keys ignore case (a PowerShell @{} hashtable)", r"\$data = @\{\}\n"),
    ("twin: no CustomActionData key after ALLOW_DOWNGRADE",
     r"if \(\$data\.ContainsKey\('ALLOW_DOWNGRADE'\)\) \{\s*\n"
     r"\s*Fail \"CustomActionData names \$key after ALLOW_DOWNGRADE"),
    ("twin: the record the wxs names comes first",
     r"\$InstalledManifest = \$data\['INSTALLED_MANIFEST'\]\s*\n"
     r"\s*if \(-not \$InstalledManifest\) \{ \$InstalledManifest = Join-Path"),
    ("twin: only '1' asks for a downgrade", r"\} elseif \(\$data\['ALLOW_DOWNGRADE'\]\) \{"),
    ("twin: the rollback arguments reach the verifier",
     r"& \$pyExe @pyArgs \$Verifier --bundle \$BundleDir --pubkey \$PubKey @rollbackArgs "),
)


def _require_ps1() -> str:
    assert VERIFY_PS1.is_file(), f"missing producer file: {VERIFY_PS1}"
    return VERIFY_PS1.read_text(encoding="utf-8")


def _write_twin(tmp_path: Path) -> Path:
    twin = tmp_path / "verify_twin.py"
    twin.write_text(_TWIN_SOURCE, encoding="utf-8")
    twin.chmod(twin.stat().st_mode | stat.S_IXUSR)
    return twin


# ----------------------------------------------------------------- sandbox --
def _make_exec(path: Path) -> None:
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def _trust_dir(tmp_path: Path, *, verifier_exit: int, verifier_output: str = "") -> Path:
    """Admin trust bootstrap OUTSIDE the bundle: verifier stub + profiles.py."""
    trust = tmp_path / "trust"
    (trust / "lib").mkdir(parents=True, exist_ok=True)
    (trust / "profiles.py").write_text("# sandbox profile registry\n", encoding="utf-8")
    body = "import sys\n"
    if verifier_output:
        body += f"print({verifier_output!r})\n"
    body += f"sys.exit({verifier_exit})\n"
    (trust / "verify_bundle.py").write_text(body, encoding="utf-8")
    return trust


def _sandbox_bundle(tmp_path: Path) -> Path:
    bundle = tmp_path / "prefix" / "bundle"
    (bundle / "wheelhouse").mkdir(parents=True, exist_ok=True)
    (bundle / "manifest.json").write_text("{}\n", encoding="utf-8")
    return bundle


def _custom_action_data(
    bundle: Path, trust: Path, pubkey: Path, *, extra: str = "", python: str = sys.executable
) -> str:
    return f"BUNDLE_DIR={bundle};TRUST_DIR={trust};PUBKEY={pubkey};PYTHON={python}{extra}"


def _run_twin(
    tmp_path: Path, data: str, *, env_extra: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    for key in ("UDBMCP_TRUST_DIR", "UDBMCP_RELEASE_PUBKEY", "UDBMCP_PYTHON", "UDBMCP_SANDBOX_PS_COMMAND_PATH"):
        env.pop(key, None)
    env.update(env_extra or {})
    return subprocess.run(  # noqa: S603 - fixed args, sandboxed twin under test
        [sys.executable, str(_write_twin(tmp_path)), data],
        capture_output=True, text=True, timeout=120, env=env,
    )


# --------------------------------------------------------------- drift pins --


@pytest.mark.parametrize(("tie", "pattern"), _TWIN_TIE_PINS, ids=[t[0] for t in _TWIN_TIE_PINS])
def test_twin_matches_verify_ps1_decision_line(tie: str, pattern: str) -> None:
    assert re.search(pattern, _require_ps1()), (
        f"verify.ps1 no longer contains the pinned decision line ({pattern!r}); the executed "
        f"python twin mirrors it and MUST be re-derived before these tests can pass: {tie}"
    )


# ------------------------------------------------- executed twin: fail-closed


def test_twin_happy_path_exits_zero_with_proof(tmp_path: Path) -> None:
    bundle = _sandbox_bundle(tmp_path)
    trust = _trust_dir(tmp_path, verifier_exit=0, verifier_output="bundle verification PASSED")
    pubkey = tmp_path / "keys" / "udbmcp-release.pub.pem"
    pubkey.parent.mkdir(parents=True, exist_ok=True)
    pubkey.write_text("-----BEGIN PUBLIC KEY-----\nSANDBOX\n-----END PUBLIC KEY-----\n", encoding="utf-8")

    proc = _run_twin(tmp_path, _custom_action_data(bundle, trust, pubkey))

    assert proc.returncode == 0, f"verified bundle must exit 0:\n{proc.stdout}{proc.stderr}"
    assert "FAIL" not in proc.stdout


def test_twin_verifier_nonzero_exit_rolls_back(tmp_path: Path) -> None:
    """The core fail-closed contract, executed: verifier exit 1 -> the action
    exits nonzero (Return=check makes msiexec roll the install back)."""
    bundle = _sandbox_bundle(tmp_path)
    trust = _trust_dir(tmp_path, verifier_exit=1, verifier_output="SIGNATURE MISMATCH: tampered")
    pubkey = tmp_path / "k.pem"
    pubkey.write_text("x\n", encoding="utf-8")

    proc = _run_twin(tmp_path, _custom_action_data(bundle, trust, pubkey))

    out = proc.stdout + proc.stderr
    assert proc.returncode != 0, "nonzero verifier exit must fail the action closed"
    assert "FAIL: trusted verifier exited 1" in out, f"canonical diagnostic required:\n{out}"
    assert "installation ABORTED (fail closed)" in out


def test_twin_exit_zero_without_proof_is_refused(tmp_path: Path) -> None:
    """A verifier that exits 0 without printing 'bundle verification PASSED'
    is treated as failed (exit code alone is not trusted)."""
    bundle = _sandbox_bundle(tmp_path)
    trust = _trust_dir(tmp_path, verifier_exit=0, verifier_output="all good, trust me")
    pubkey = tmp_path / "k.pem"
    pubkey.write_text("x\n", encoding="utf-8")

    proc = _run_twin(tmp_path, _custom_action_data(bundle, trust, pubkey))

    out = proc.stdout + proc.stderr
    assert proc.returncode != 0
    assert "did not print 'bundle verification PASSED'" in out, f"canonical diagnostic:\n{out}"


def test_twin_exit_zero_with_fail_line_is_refused(tmp_path: Path) -> None:
    bundle = _sandbox_bundle(tmp_path)
    trust = _trust_dir(
        tmp_path, verifier_exit=0,
        verifier_output="FAIL: wheel hash mismatch\nbundle verification PASSED",
    )
    pubkey = tmp_path / "k.pem"
    pubkey.write_text("x\n", encoding="utf-8")

    proc = _run_twin(tmp_path, _custom_action_data(bundle, trust, pubkey))

    out = proc.stdout + proc.stderr
    assert proc.returncode != 0
    assert "trusted verifier reported FAIL" in out, f"canonical diagnostic:\n{out}"


def test_twin_missing_verifier_refuses(tmp_path: Path) -> None:
    bundle = _sandbox_bundle(tmp_path)
    trust = tmp_path / "trust"  # exists but WITHOUT verify_bundle.py
    (trust / "lib").mkdir(parents=True, exist_ok=True)
    (trust / "profiles.py").write_text("# registry\n", encoding="utf-8")
    pubkey = tmp_path / "k.pem"
    pubkey.write_text("x\n", encoding="utf-8")

    proc = _run_twin(tmp_path, _custom_action_data(bundle, trust, pubkey))

    out = proc.stdout + proc.stderr
    assert proc.returncode != 0
    assert "trusted verifier not found" in out, f"canonical diagnostic:\n{out}"


def test_twin_missing_profiles_registry_refuses(tmp_path: Path) -> None:
    bundle = _sandbox_bundle(tmp_path)
    trust = _trust_dir(tmp_path, verifier_exit=0)
    (trust / "profiles.py").unlink()  # the only profiles.py location
    pubkey = tmp_path / "k.pem"
    pubkey.write_text("x\n", encoding="utf-8")

    proc = _run_twin(tmp_path, _custom_action_data(bundle, trust, pubkey))

    out = proc.stdout + proc.stderr
    assert proc.returncode != 0
    assert "profiles.py not found in the trust directory" in out, f"canonical diagnostic:\n{out}"


def test_twin_missing_pubkey_config_refuses(tmp_path: Path) -> None:
    """Trust invariant 2, executed: no UDBMCP_RELEASE_PUBKEY anywhere (it is
    NEVER shipped inside the MSI) -> refusal, not a fall back to bundle keys."""
    bundle = _sandbox_bundle(tmp_path)
    (bundle / "udbmcp-release.pub.pem").write_text("IN-BUNDLE-DECOY\n", encoding="utf-8")
    trust = _trust_dir(tmp_path, verifier_exit=0, verifier_output="bundle verification PASSED")

    data = f"BUNDLE_DIR={bundle};TRUST_DIR={trust};PYTHON={sys.executable}"
    proc = _run_twin(tmp_path, data)

    out = proc.stdout + proc.stderr
    assert proc.returncode != 0
    assert "release public key not configured" in out, f"canonical diagnostic:\n{out}"
    assert "IN-BUNDLE-DECOY" not in out, "an in-bundle key must never be picked up"


def test_twin_pubkey_inside_bundle_is_refused(tmp_path: Path) -> None:
    bundle = _sandbox_bundle(tmp_path)
    trust = _trust_dir(tmp_path, verifier_exit=0, verifier_output="bundle verification PASSED")
    in_bundle_key = bundle / "keys" / "udbmcp-release.pub.pem"
    in_bundle_key.parent.mkdir(parents=True, exist_ok=True)
    in_bundle_key.write_text("-----BEGIN PUBLIC KEY-----\nIN-BUNDLE\n-----END PUBLIC KEY-----\n", encoding="utf-8")

    proc = _run_twin(tmp_path, _custom_action_data(bundle, trust, in_bundle_key))

    out = proc.stdout + proc.stderr
    assert proc.returncode != 0
    assert "is inside the installed bundle" in out, f"canonical diagnostic:\n{out}"
    assert "authenticates nothing" in out


def test_twin_trust_dir_inside_bundle_is_refused(tmp_path: Path) -> None:
    """A verifier shipped inside the payload would print PASSED unconditionally:
    a trust dir inside the bundle is refused even before the file checks."""
    bundle = _sandbox_bundle(tmp_path)
    trust = _trust_dir(bundle / "attacker-trust", verifier_exit=0, verifier_output="bundle verification PASSED")
    pubkey = tmp_path / "k.pem"
    pubkey.write_text("x\n", encoding="utf-8")

    proc = _run_twin(tmp_path, _custom_action_data(bundle, trust, pubkey))

    out = proc.stdout + proc.stderr
    assert proc.returncode != 0
    assert "trust directory" in out and "is inside the installed bundle" in out, (
        f"canonical diagnostic:\n{out}"
    )


def test_twin_interpreter_inside_bundle_is_refused(tmp_path: Path) -> None:
    """No bundle payload (including its python) may execute before verification
    passes: PYTHON pointing into the bundle is refused."""
    bundle = _sandbox_bundle(tmp_path)
    trust = _trust_dir(tmp_path, verifier_exit=0, verifier_output="bundle verification PASSED")
    pubkey = tmp_path / "k.pem"
    pubkey.write_text("x\n", encoding="utf-8")
    in_bundle_py = bundle / "venv" / "bin" / "python"
    in_bundle_py.parent.mkdir(parents=True, exist_ok=True)
    in_bundle_py.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    _make_exec(in_bundle_py)

    data = f"BUNDLE_DIR={bundle};TRUST_DIR={trust};PUBKEY={pubkey};PYTHON={in_bundle_py}"
    proc = _run_twin(tmp_path, data)

    out = proc.stdout + proc.stderr
    assert proc.returncode != 0
    assert "python interpreter" in out and "is inside the installed bundle" in out, (
        f"canonical diagnostic:\n{out}"
    )


def test_twin_missing_bundle_dir_refuses(tmp_path: Path) -> None:
    trust = _trust_dir(tmp_path, verifier_exit=0)
    pubkey = tmp_path / "k.pem"
    pubkey.write_text("x\n", encoding="utf-8")

    proc = _run_twin(tmp_path, f"TRUST_DIR={trust};PUBKEY={pubkey}")

    out = proc.stdout + proc.stderr
    assert proc.returncode != 0
    assert "BUNDLE_DIR missing from CustomActionData" in out, f"canonical diagnostic:\n{out}"


def test_twin_malformed_custom_action_data_refuses(tmp_path: Path) -> None:
    proc = _run_twin(tmp_path, "BUNDLE_DIR-not-a-pair")

    out = proc.stdout + proc.stderr
    assert proc.returncode != 0
    assert "malformed CustomActionData pair" in out, f"canonical diagnostic:\n{out}"


# ------------------------------------------ executed twin: anti-rollback --

# A stub trusted verifier that runs the REAL release-order check of
# scripts/verify_bundle.py (no signatures): the twin's wiring is exercised
# against the verifier's own decision.
_RELEASE_VERIFIER = f'''
import argparse
import importlib.util
import json
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location("verify_bundle", {str(PROJECT / "scripts" / "verify_bundle.py")!r})
vb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vb)
ap = argparse.ArgumentParser()
ap.add_argument("--bundle")
ap.add_argument("--pubkey")
ap.add_argument("--installed-manifest")
ap.add_argument("--allow-downgrade", action="store_true")
args = ap.parse_args()
print("isolated=%d" % sys.flags.isolated)
if args.installed_manifest:
    manifest = json.loads((Path(args.bundle) / "manifest.json").read_text())
    vb.check_release_order(manifest, Path(args.installed_manifest), args.allow_downgrade)
if vb.failed:
    sys.exit(1)
print("bundle verification PASSED")
'''


def _release_sandbox(tmp_path: Path, *, bundle_seq: int, installed_seq: int | None) -> str:
    bundle = _sandbox_bundle(tmp_path)
    (bundle / "manifest.json").write_text(f'{{"release_seq": {bundle_seq}}}\n', encoding="utf-8")
    if installed_seq is not None:
        # the installed release's manifest, beside the bundle directory
        (bundle.parent / "manifest.json").write_text(f'{{"release_seq": {installed_seq}}}\n', encoding="utf-8")
    trust = _trust_dir(tmp_path, verifier_exit=0)
    (trust / "verify_bundle.py").write_text(_RELEASE_VERIFIER, encoding="utf-8")
    pubkey = tmp_path / "k.pem"
    pubkey.write_text("x\n", encoding="utf-8")
    return _custom_action_data(bundle, trust, pubkey)


def test_twin_refuses_an_older_release_than_the_installed_one(tmp_path: Path) -> None:
    proc = _run_twin(tmp_path, _release_sandbox(tmp_path, bundle_seq=5, installed_seq=6))
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0
    assert "FAIL: rollback refused" in out, out
    assert "carries an OLDER release than the one installed" in out and "UDBMCP_ALLOW_DOWNGRADE=1" in out, out


def test_twin_downgrade_override_applies_to_one_run_only(tmp_path: Path) -> None:
    data = _release_sandbox(tmp_path, bundle_seq=5, installed_seq=6)
    proc = _run_twin(tmp_path, data + ";ALLOW_DOWNGRADE=1")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "DOWNGRADE allowed by --allow-downgrade" in proc.stdout
    # nothing about the override persists: the next run refuses again
    proc = _run_twin(tmp_path, data)
    assert proc.returncode != 0 and "FAIL: rollback refused" in proc.stdout


@pytest.mark.parametrize(
    ("installed_seq", "expected"),
    [(None, "nothing installed yet"), (5, "(not a downgrade)"), (4, "(not a downgrade)")],
    ids=["first-install", "reinstall", "upgrade"],
)
def test_twin_accepts_a_first_install_a_reinstall_and_an_upgrade(
    tmp_path: Path, installed_seq: int | None, expected: str
) -> None:
    proc = _run_twin(tmp_path, _release_sandbox(tmp_path, bundle_seq=5, installed_seq=installed_seq))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert expected in proc.stdout
    assert "isolated=1" in proc.stdout, "the trusted verifier runs under -I"


def test_twin_refuses_an_outdated_verifier(tmp_path: Path) -> None:
    """A verifier that parses options but has no --installed-manifest would
    stop on the unknown option; it is refused by name, never run."""
    bundle = _sandbox_bundle(tmp_path)
    trust = _trust_dir(tmp_path, verifier_exit=0)
    canary = tmp_path / "outdated-verifier-ran"
    (trust / "verify_bundle.py").write_text(
        "import argparse, pathlib\nap = argparse.ArgumentParser()\n"
        'ap.add_argument("--bundle")\nap.add_argument("--pubkey")\nap.parse_args()\n'
        f"pathlib.Path({str(canary)!r}).write_text('ran')\nprint('bundle verification PASSED')\n",
        encoding="utf-8",
    )
    pubkey = tmp_path / "k.pem"
    pubkey.write_text("x\n", encoding="utf-8")
    proc = _run_twin(tmp_path, _custom_action_data(bundle, trust, pubkey))
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0
    assert "is an OUTDATED copy (no --installed-manifest option)" in out, out
    assert not canary.exists()


def test_twin_refuses_a_customactiondata_key_given_twice(tmp_path: Path) -> None:
    data = _release_sandbox(tmp_path, bundle_seq=5, installed_seq=None)
    elsewhere = _trust_dir(tmp_path / "elsewhere", verifier_exit=0, verifier_output="bundle verification PASSED")
    proc = _run_twin(tmp_path, f"{data};TRUST_DIR={elsewhere}")
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0
    assert "CustomActionData names TRUST_DIR twice" in out, out


@pytest.mark.parametrize("injected", ["PUBKEY", "PYTHON", "TRUST_DIR"])
def test_twin_refuses_any_key_after_the_downgrade_property(tmp_path: Path, injected: str) -> None:
    """The wxs carries one public msiexec property (UDBMCP_ALLOW_DOWNGRADE)
    into CustomActionData, last. A value such as '1;PUBKEY=<file>' added a
    key the wxs never passes (so not a duplicate), which took precedence over
    the administrator's machine-wide UDBMCP_RELEASE_PUBKEY or UDBMCP_PYTHON."""
    _release_sandbox(tmp_path, bundle_seq=5, installed_seq=None)
    bundle, trust, key = tmp_path / "prefix" / "bundle", tmp_path / "trust", tmp_path / "k.pem"
    admin = {"UDBMCP_RELEASE_PUBKEY": str(key), "UDBMCP_PYTHON": sys.executable}
    wxs_shaped = f"BUNDLE_DIR={bundle};TRUST_DIR={trust};ALLOW_DOWNGRADE=1"
    proc = _run_twin(tmp_path, wxs_shaped, env_extra=admin)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    elsewhere = _trust_dir(tmp_path / "elsewhere", verifier_exit=0, verifier_output="bundle verification PASSED")
    value = {"PUBKEY": str(key), "PYTHON": sys.executable, "TRUST_DIR": str(elsewhere)}[injected]
    proc = _run_twin(tmp_path, f"{wxs_shaped};{injected}={value}", env_extra=admin)
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0
    assert f"CustomActionData names {injected} after ALLOW_DOWNGRADE" in out, out


@pytest.mark.parametrize(
    ("extra", "refusal"),
    [
        (";trust_dir={elsewhere}", "CustomActionData names trust_dir twice"),
        (";Allow_Downgrade=1;pubkey={key}", "CustomActionData names pubkey after ALLOW_DOWNGRADE"),
    ],
    ids=["duplicate", "after-downgrade"],
)
def test_twin_compares_customactiondata_keys_ignoring_case(tmp_path: Path, extra: str, refusal: str) -> None:
    """verify.ps1 keeps the keys in a PowerShell @{} hashtable, which ignores
    case: a lower-case key is the same key, refused as a duplicate or after
    ALLOW_DOWNGRADE, and a lower-case allow_downgrade=1 is honoured."""
    data = _release_sandbox(tmp_path, bundle_seq=5, installed_seq=6)
    elsewhere = _trust_dir(tmp_path / "elsewhere", verifier_exit=0, verifier_output="bundle verification PASSED")
    proc = _run_twin(tmp_path, data + extra.format(elsewhere=elsewhere, key=tmp_path / "k.pem"))
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0
    assert refusal in out, out
    proc = _run_twin(tmp_path, data + ";allow_downgrade=1")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "DOWNGRADE allowed by --allow-downgrade" in proc.stdout


def test_twin_reads_the_release_record_the_wxs_names(tmp_path: Path) -> None:
    """The wxs passes INSTALLED_MANIFEST (a fixed path under Program Files),
    so an install to another INSTALLFOLDER still finds the record."""
    data = _release_sandbox(tmp_path, bundle_seq=5, installed_seq=None)
    record = tmp_path / "ProgramFiles" / "UniversalDB MCP" / "manifest.json"
    record.parent.mkdir(parents=True)
    record.write_text('{"release_seq": 6}\n', encoding="utf-8")
    proc = _run_twin(tmp_path, f"{data};INSTALLED_MANIFEST={record}")
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0
    assert "FAIL: rollback refused" in out and str(record) in out, out


def test_twin_refuses_an_unknown_downgrade_value(tmp_path: Path) -> None:
    data = _release_sandbox(tmp_path, bundle_seq=5, installed_seq=6)
    proc = _run_twin(tmp_path, data + ";ALLOW_DOWNGRADE=yes")
    assert proc.returncode != 0
    assert "ALLOW_DOWNGRADE='yes' is not understood" in proc.stdout, proc.stdout


# ------------------------------------------- executed real ps1 (pwsh present)


# verify.ps1 secures its ProgramData log directory and checks the folders
# above the release key and the interpreter's folder with the Windows ACL
# APIs (Get-Acl, Set-Acl, DirectorySecurity), which pwsh implements on
# Windows only; this wrapper stubs them (every entry owned by SYSTEM and
# writable by SYSTEM and Administrators only, Set-Acl a no-op) so the
# verifier decisions run on any host with pwsh, the CI ubuntu runner
# included. The ACL decisions themselves are exercised in
# tests/unit/test_hardening_2026_09_27_msi.py.
_PS1_WRAPPER = r"""
param([string]$Script, [string]$CustomActionData)
function global:Get-Acl {
    param([string]$LiteralPath)
    $acl = [pscustomobject]@{ AreAccessRulesProtected = $true }
    $acl | Add-Member -MemberType ScriptMethod -Name GetOwner -Value {
        param($type) [pscustomobject]@{ Value = 'S-1-5-18' }
    }
    $acl | Add-Member -MemberType ScriptMethod -Name GetAccessRules -Value {
        param($explicit, $inherited, $type)
        foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
            [pscustomobject]@{
                IdentityReference = [pscustomobject]@{ Value = $sid }
                AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
                FileSystemRights  = [System.Security.AccessControl.FileSystemRights]::FullControl
                PropagationFlags  = [System.Security.AccessControl.PropagationFlags]::None
            }
        }
    }
    return $acl
}
function global:Set-Acl { param([string]$LiteralPath, $AclObject) }
function global:New-Object {
    if ($args.Count -ge 1 -and $args[0] -eq 'System.Security.AccessControl.DirectorySecurity') {
        $security = [pscustomobject]@{}
        $security | Add-Member -MemberType ScriptMethod -Name SetSecurityDescriptorSddlForm -Value { param($sddl) }
        return $security
    }
    Microsoft.PowerShell.Utility\New-Object @args
}
& $Script -CustomActionData $CustomActionData
exit $LASTEXITCODE
"""


@pytest.mark.skipif(PWSH is None, reason="pwsh not installed on this host (recorded honestly; "
                                         "Windows runtime is ledgered not_run)")
class TestVerifyPs1ExecutedUnderPwsh:
    """The REAL packaging/msi/custom/verify.ps1, executed by pwsh where one
    exists, with the Windows ACL APIs stubbed (see _PS1_WRAPPER).
    Deliberately limited to the decisions that are host-independent: the
    containment cases rely on Windows path separators inside Test-InsideDir
    and are locked by the twin tests + drift pins instead."""

    def _run_ps1(self, tmp_path: Path, data: str) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ)
        env["ProgramData"] = str(tmp_path)  # Write-Log's log dir, sandboxed
        for key in ("UDBMCP_TRUST_DIR", "UDBMCP_RELEASE_PUBKEY", "UDBMCP_PYTHON"):
            env.pop(key, None)
        wrapper = tmp_path / "run-verify.ps1"
        wrapper.write_text(_PS1_WRAPPER, encoding="utf-8")
        return subprocess.run(  # noqa: S603 - fixed args, repo script under test
            [str(PWSH), "-NoProfile", "-NonInteractive", "-File", str(wrapper),
             "-Script", str(VERIFY_PS1), "-CustomActionData", data],
            capture_output=True, text=True, timeout=300, env=env,
        )

    def _pubkey(self, tmp_path: Path) -> Path:
        key = tmp_path / "k.pem"
        key.write_text("-----BEGIN PUBLIC KEY-----\nSANDBOX\n-----END PUBLIC KEY-----\n", encoding="utf-8")
        return key

    def _data(self, tmp_path: Path, bundle: Path, trust: Path) -> str:
        # verify.ps1 refuses an interpreter that is a link (sys.executable
        # often is one): a plain python.exe that runs this interpreter
        python = tmp_path / "Python312" / "python.exe"
        python.parent.mkdir()
        python.write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n', encoding="utf-8")
        _make_exec(python)
        return _custom_action_data(bundle, trust, self._pubkey(tmp_path), python=str(python))

    def test_happy_path_exits_zero(self, tmp_path: Path) -> None:
        bundle = _sandbox_bundle(tmp_path)
        trust = _trust_dir(tmp_path, verifier_exit=0, verifier_output="bundle verification PASSED")
        proc = self._run_ps1(tmp_path, self._data(tmp_path, bundle, trust))
        assert proc.returncode == 0, f"{proc.stdout}{proc.stderr}"

    def test_verifier_nonzero_exit_rolls_back(self, tmp_path: Path) -> None:
        bundle = _sandbox_bundle(tmp_path)
        trust = _trust_dir(tmp_path, verifier_exit=1)
        proc = self._run_ps1(tmp_path, self._data(tmp_path, bundle, trust))
        out = proc.stdout + proc.stderr
        assert proc.returncode != 0
        assert "FAIL: trusted verifier exited 1" in out, f"{out}"

    def test_customactiondata_keys_ignore_case_as_in_the_twin(self, tmp_path: Path) -> None:
        bundle = _sandbox_bundle(tmp_path)
        trust = _trust_dir(tmp_path, verifier_exit=0, verifier_output="bundle verification PASSED")
        elsewhere = _trust_dir(tmp_path / "elsewhere", verifier_exit=0, verifier_output="bundle verification PASSED")
        proc = self._run_ps1(tmp_path, self._data(tmp_path, bundle, trust) + f";trust_dir={elsewhere}")
        out = proc.stdout + proc.stderr
        assert proc.returncode != 0
        assert "CustomActionData names trust_dir twice" in out, out

    def test_exit_zero_without_proof_is_refused(self, tmp_path: Path) -> None:
        bundle = _sandbox_bundle(tmp_path)
        trust = _trust_dir(tmp_path, verifier_exit=0, verifier_output="silent success")
        proc = self._run_ps1(tmp_path, self._data(tmp_path, bundle, trust))
        out = proc.stdout + proc.stderr
        assert proc.returncode != 0
        assert "did not print 'bundle verification PASSED'" in out, f"{out}"
