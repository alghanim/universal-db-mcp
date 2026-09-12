"""Trust tests for the delivered Windows MSI gate (scripts/test_package_msi.ps1).

Two verified defects were fixed in the gate script; these tests pin both so
they cannot regress:

1. Evidence JSON on every failure path. ``Stop-Gate`` ends with ``exit 1``,
   and ``exit`` unwinds a PowerShell script WITHOUT running the ``catch``
   block, so a Save-Evidence call that only lives in ``catch``/the tail of
   ``try`` never runs for a real gate failure (missing pubkey, msiexec
   nonzero exit, trusted-verifier FAIL, service absent, tamper negative,
   restore re-verify). The header promises "the evidence JSON is written
   even when the gate fails"; the bash gates get the same guarantee from
   their ``trap finalize EXIT``. The fix: Stop-Gate itself saves the
   evidence before exiting, fed from script-scope install state that is
   valid from the very first prerequisite check.

2. The PS 5.1 native-stderr trap. The gate runs with
   ``$ErrorActionPreference = 'Stop'``; Windows PowerShell 5.1 turns
   native-command stderr (merged via 2>&1 or redirected to a file) into
   error records that a 'Stop' preference escalates into a spurious
   terminating NativeCommandError - e.g. ``sc.exe query`` writing its 1060
   diagnostic to stderr would abort the service check as 'unexpected_error'
   instead of surfacing the real exit code. packaging/msi/custom/verify.ps1
   neutralizes the identical construct; the gate now does too via its
   ``Invoke-Native`` helper, deciding solely on ``$LASTEXITCODE`` / output.

The MSI gate host is a real Windows machine and this repo has no PowerShell
runtime, so these are text-level gates on the script's logical lines
(backtick continuations joined, comment-only lines dropped), the same
approach as tests/unit/test_msi_custom_actions.py and
tests/unit/test_msi_venv_eap_guard.py.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parents[2]
GATE_PS1 = PROJECT / "scripts" / "test_package_msi.ps1"


def _require_script() -> str:
    if not GATE_PS1.exists():
        pytest.skip(f"{GATE_PS1} does not exist")
    # ascii read doubles as an encoding guard: Windows PowerShell 5.1 treats a
    # BOM-less non-ASCII file as ANSI, so the gate must be pure ASCII.
    return GATE_PS1.read_text(encoding="ascii")


def _code_lines(text: str) -> list[str]:
    """Logical code lines: backtick-newline continuations joined and
    comment-only lines dropped (trust-model prose must not satisfy a gate)."""
    text = re.sub(r"`\r?\n", " ", text)
    return [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]


def _function_source(text: str, name: str, next_names: tuple[str, ...]) -> str:
    """Extract ``function <name> { ... }`` up to the next top-level function."""
    start = text.index(f"function {name}")
    rest = text[start:]
    ends = [rest.index(f"function {n}") for n in next_names if f"function {n}" in rest]
    return rest[: min(ends)] if ends else rest


# --- defect 1: evidence JSON is written on EVERY failure path -----------------


def test_stop_gate_saves_evidence_before_exiting() -> None:
    """Stop-Gate ends with `exit 1`, which bypasses the catch block - so the
    evidence MUST be saved inside Stop-Gate itself, before the exit."""
    text = _require_script()
    stop_gate = _function_source(text, "Stop-Gate", ("Save-Evidence",))
    assert "exit 1" in stop_gate, "Stop-Gate must still fail closed with exit 1"
    assert "Save-Evidence" in stop_gate, (
        "Stop-Gate must write the evidence JSON itself: `exit` unwinds the "
        "script without running the catch block, so a failure here would "
        "otherwise produce no results.json at all"
    )
    assert stop_gate.index("Save-Evidence") < stop_gate.index("exit 1"), (
        "Save-Evidence must run BEFORE the exit, not after (unreachable)"
    )
    assert re.search(r"Save-Evidence\s+-Status\s+'failed'", stop_gate), (
        "Stop-Gate must save the evidence with status 'failed'"
    )


def test_install_state_is_script_scoped_and_initialized_early() -> None:
    """Stop-Gate can fire during the prerequisite checks, before the MSI has
    been touched; the install state it records must therefore be script-scope
    and pre-initialized (exit code -1, empty MSI/log) near the check ledger."""
    text = _require_script()
    for var in ("$script:InstallExitCode", "$script:MsiUsed", "$script:MsiLog"):
        assert re.search(rf"(?m)^{re.escape(var)}\s*=", text), (
            f"{var} must be initialized at script scope so Stop-Gate can "
            "record it from the first prerequisite failure onwards"
        )
    # The initialization must precede the try block (i.e. every Stop-Gate).
    init = min(text.index(f"{var} =") for var in
               ("$script:InstallExitCode", "$script:MsiUsed", "$script:MsiLog"))
    assert init < text.index("try {"), (
        "install state must be initialized before the try body starts"
    )
    # And the msi-install section must keep it in sync (no stale defaults).
    code = "\n".join(_code_lines(text))
    assert re.search(r"\$script:InstallExitCode\s*=\s*\$proc\.ExitCode", code), (
        "the real msiexec exit code must be mirrored into the script-scope state"
    )
    assert "$script:MsiUsed = $MsiPath" in code, (
        "the MSI actually used must be mirrored into the script-scope state"
    )


def test_save_evidence_survives_missing_evidence_dir() -> None:
    """Stop-Gate / catch may run before the try body created the evidence
    directories; the evidence write itself must never fail."""
    save = _function_source(_require_script(), "Save-Evidence", ())
    assert "New-Item" in save and "Force" in save, (
        "Save-Evidence must create the evidence directory before writing"
    )
    assert save.index("New-Item") < save.index("WriteAllText"), (
        "the directory must be created before the results.json write"
    )


def test_success_and_catch_paths_still_save_evidence() -> None:
    """The fix must not remove the existing evidence writes on the success
    path and in the catch block (fail-closed diagnostics stay intact)."""
    code = "\n".join(_code_lines(_require_script()))
    assert "Save-Evidence -Status 'passed'" in code
    assert re.search(r"catch \{[\s\S]*?Save-Evidence -Status 'failed'", code)


# --- defect 2: PS 5.1 native-stderr trap --------------------------------------


def test_invoke_native_helper_relaxes_and_restores() -> None:
    """The helper must relax $ErrorActionPreference to 'Continue' around the
    invocation and restore it in a finally block - the documented
    packaging/msi/custom/verify.ps1 pattern for the identical construct."""
    text = _require_script()
    helper = _function_source(text, "Invoke-Native", ("Invoke-TrustedVerifier", "Find-Cpython312", "Test-Elevated"))
    assert "$ErrorActionPreference = 'Continue'" in helper, (
        "Invoke-Native must relax $ErrorActionPreference around the native invocation"
    )
    finally_part = helper[helper.index("finally"):]
    assert "$ErrorActionPreference = $prevEap" in finally_part, (
        "Invoke-Native must restore the previous preference in finally"
    )


def test_stderr_redirected_native_invocations_are_guarded() -> None:
    """Core regression gate: every call-operator invocation that redirects
    stderr (2>&1 / 2> file / 2>$null) must run inside the Invoke-Native
    relaxation helper. Windows PowerShell 5.1 escalates redirected stderr
    into a terminating NativeCommandError under the 'Stop' baseline - the
    sc.exe 1060 diagnostic would otherwise abort the gate as
    'unexpected_error' instead of reaching its own fail-closed diagnostic."""
    text = _require_script()
    lines = _code_lines(text)
    # The helper body itself runs relaxed; identify it so `& $Block` inside
    # is not flagged. (The gate's functions are defined inside the try block
    # and are therefore indented.)
    helper_start = next(i for i, ln in enumerate(lines)
                        if ln.lstrip().startswith("function Invoke-Native"))
    helper_end = next(i for i, ln in enumerate(lines)
                      if i > helper_start and ln.lstrip().startswith("function "))
    guarded = 0
    for i, ln in enumerate(lines):
        if helper_start < i < helper_end:
            continue  # the helper's own `& $Block` dispatch runs relaxed
        if not re.search(r"(?<![>&\w])&(?=\s)", ln):
            continue
        if not re.search(r"2>&1|2>\s|2>\$null", ln):
            continue  # unredirected native stderr is not escalated (console)
        assert "Invoke-Native {" in ln, (
            f"stderr-redirected native invocation without an EAP relaxation "
            f"guard (PS 5.1 escalates it to a terminating error): {ln}"
        )
        guarded += 1
    assert guarded >= 9, (
        "expected at least: trusted verifier, three sc.exe calls, create_demo, "
        "doctor, probe, verify.ps1 tamper run, verify.ps1 per-user-interpreter "
        f"refusal run to be present and guarded; found {guarded}"
    )


def test_stop_baseline_and_fail_closed_exits_kept() -> None:
    """The relaxation must not weaken the fail-closed policy: the global
    $ErrorActionPreference = 'Stop' baseline and the nonzero failure exits
    (Stop-Gate exit 1 / success exit 0) remain."""
    code = "\n".join(_code_lines(_require_script()))
    assert re.search(r"\$ErrorActionPreference\s*=\s*'Stop'", code), (
        "the gate must keep its $ErrorActionPreference = 'Stop' baseline"
    )
    assert re.search(r"(?m)^\s*exit\s+1\b", code), "the gate must keep its failure exit"
    assert re.search(r"(?m)^\s*exit\s+0\b", code), "the gate must keep its success exit"


# --- trust invariants that must survive the fix -------------------------------


def test_verifier_still_comes_from_outside_the_bundle() -> None:
    """The verifier is invoked from the admin trust directory, never from the
    payload (the bundle's own verifier copy is never executed)."""
    code = "\n".join(_code_lines(_require_script()))
    assert "$TrustDir 'verify_bundle.py'" in code
    assert "Test-InsideDir $TrustDir $BundleDir" in code, (
        "the trust directory must still be refused when it is inside the bundle"
    )
    assert "Test-InsideDir $PubKey $BundleDir" in code, (
        "the release pubkey must still be refused when it is inside the bundle"
    )


def test_pip_policy_not_in_gate_but_no_key_material() -> None:
    """The gate never ships key material (the release pubkey is distributed
    out-of-band and only ever referenced by path)."""
    text = _require_script()
    for marker in ("-----BEGIN", "PUBLIC KEY", "PRIVATE KEY"):
        assert marker not in text, f"gate must never embed key material ({marker!r})"


def test_delimiters_balanced() -> None:
    """No PowerShell host on this platform: a balanced-delimiters check is the
    best available syntax smoke test (the gate avoids unbalanced delimiters
    inside string literals so this stays sound)."""
    text = _require_script()
    for opener, closer in (("{", "}"), ("(", ")"), ("[", "]")):
        assert text.count(opener) == text.count(closer), (
            f"test_package_msi.ps1: unbalanced {opener}{closer} "
            f"({text.count(opener)} vs {text.count(closer)})"
        )
