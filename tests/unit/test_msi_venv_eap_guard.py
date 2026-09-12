"""Trust tests for the venv-build MSI custom action's native-invocation guard.

packaging/msi/custom/venv.ps1 runs under msiexec with redirected handles,
where Windows PowerShell 5.1 turns ANY native-command stderr output into
error records that a ``$ErrorActionPreference = 'Stop'`` preference escalates
into a spurious terminating NativeCommandError. Left unguarded, that dead-
coded graceful diagnostics and made any pip warning abort an
otherwise-successful install through the catch block.

The fix (mirroring the sibling actions verify.ps1 and doctor.ps1, which
document the guard as mandatory): relax the preference around every native
invocation and decide solely on ``$LASTEXITCODE`` -- still failing closed on
every nonzero result, so the deferred Return="check" action keeps rolling the
install back on real failures.

The MSI build host has no PowerShell runtime; these are text-level gates on
the script's logical lines (backtick continuations joined, comment-only lines
dropped), the same approach as tests/unit/test_msi_custom_actions.py.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parents[2]
VENV_PS1 = PROJECT / "packaging" / "msi" / "custom" / "venv.ps1"


def _require_script() -> str:
    if not VENV_PS1.exists():
        pytest.skip(f"{VENV_PS1} does not exist yet (msi-builder artifact pending)")
    # ascii read doubles as an encoding guard: Windows PowerShell 5.1 treats a
    # BOM-less non-ASCII file as ANSI, so the script must be pure ASCII.
    return VENV_PS1.read_text(encoding="ascii")


def _code_lines(text: str) -> list[str]:
    """Logical code lines: backtick-newline continuations joined (so the
    multi-line pip command is ONE line) and comment-only lines dropped
    (trust-model prose must not satisfy or defeat a gate)."""
    text = re.sub(r"`\r?\n", " ", text)
    return [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]


def _invocation_lines(lines: list[str]) -> list[str]:
    """Lines that invoke an external command via the call operator: ``&`` at
    line start or after an assignment (``$found = & py.exe ...``). The ``&``
    inside ``2>&1`` redirections is excluded. Cmdlets are not external
    processes."""
    return [ln for ln in lines if re.search(r"(?<![>&\w])&(?=\s)", ln)]


# --- the guard itself ---------------------------------------------------------


def test_invoke_native_helper_relaxes_and_restores() -> None:
    """The helper must relax $ErrorActionPreference to 'Continue' around the
    invocation and restore it in a finally block, returning only the exit
    code -- the documented verify.ps1 / doctor.ps1 pattern."""
    text = _require_script()
    helper = text[text.index("function Invoke-Native") :]
    # the helper ends where the next top-level function begins
    end = helper.find("function Find-Cpython312")
    helper = helper[: end] if end != -1 else helper
    assert "$ErrorActionPreference = 'Continue'" in helper, (
        "Invoke-Native must relax $ErrorActionPreference around the native invocation"
    )
    finally_part = helper[helper.index("finally") :]
    assert "$ErrorActionPreference = $previousEap" in finally_part, (
        "Invoke-Native must restore the previous preference in finally"
    )
    assert "return $LASTEXITCODE" in helper, "Invoke-Native must return only the exit code"


def test_every_native_invocation_is_guarded() -> None:
    """Core regression gate: walk the logical code lines tracking the
    relaxation state and assert EVERY call-operator invocation happens while
    $ErrorActionPreference is 'Continue'. A future native invocation added
    without the guard fails here instead of aborting real installs."""
    lines = _code_lines(_require_script())
    relaxed = 0
    guarded_invocations = 0
    for ln in lines:
        if "$ErrorActionPreference = 'Continue'" in ln:
            relaxed += 1
        elif "$ErrorActionPreference = $previousEap" in ln:
            relaxed -= 1
            assert relaxed >= 0, f"preference restored without a relaxation: {ln}"
        elif re.search(r"\$ErrorActionPreference\s*=\s*'Stop'", ln):
            # the script-level baseline is a no-op here; a restore inside a
            # relaxed scope must have consumed one relaxation
            if relaxed > 0:
                relaxed -= 1
        elif re.search(r"(?<![>&\w])&(?=\s)", ln):
            assert relaxed > 0, (
                f"native invocation without an EAP relaxation guard "
                f"(PS 5.1 escalates redirected stderr to a terminating error): {ln}"
            )
            guarded_invocations += 1
    assert guarded_invocations >= 2, (
        "expected at least the Invoke-Native helper invocation (which guards "
        "the interpreter version check and the venv create) and the pip "
        "install to be present and guarded"
    )
    assert relaxed == 0, "every relaxation must be restored before the script ends"


def test_exit_decisions_use_captured_exit_codes() -> None:
    """The fail-closed decisions must test the captured exit-code variables,
    not a $LASTEXITCODE that a later native invocation could clobber."""
    code = "\n".join(_code_lines(_require_script()))
    for var in ("$verExit", "$venvExit", "$pipExit"):
        assert f"if ({var} -ne 0" in code or f"if ({var} -eq 0" in code, (
            f"{var} must be captured and checked as the sole decision input"
        )


# --- fail-closed and trust invariants preserved by the fix --------------------


def test_global_stop_preference_and_nonzero_exit_kept() -> None:
    """The fix must not weaken the fail-closed policy: the global
    $ErrorActionPreference = 'Stop' (cmdlet failures -> terminating) and the
    nonzero exit path for the deferred Return="check" action remain."""
    code = "\n".join(_code_lines(_require_script()))
    assert re.search(r"\$ErrorActionPreference\s*=\s*'Stop'", code), (
        "venv.ps1 must still set $ErrorActionPreference = 'Stop' as its baseline"
    )
    assert re.search(r"(?m)^\s*exit\s+1\b", code), "venv.ps1 must keep its nonzero failure exit"


def test_pip_install_flags_unchanged_by_the_guard() -> None:
    """The relaxation must not touch the pip policy: --no-index
    --require-hashes from the bundle wheelhouse only, --only-binary=:all:
    (no sdist/setup.py execution), --isolated, pinned by the signed lock."""
    pip_lines = [
        ln
        for ln in _code_lines(_require_script())
        if re.search(r"&\s*\$VenvPython", ln) and "-m pip" in ln and " install " in ln
    ]
    assert pip_lines, "venv.ps1 must still install from the bundle wheelhouse"
    for ln in pip_lines:
        for flag in ("--no-index", "--require-hashes", "--find-links=$Wheelhouse",
                     "--only-binary=:all:", "--isolated"):
            assert flag in ln, f"pip install lost {flag} in the guard refactor: {ln}"
        assert "$Lock" in ln, f"pip install must resolve from the signed runtime.lock: {ln}"


def test_no_key_material_in_script() -> None:
    """The release pubkey is admin-distributed out-of-band and never shipped:
    the guard refactor must not have introduced key material."""
    text = _require_script()
    for marker in ("-----BEGIN", "PUBLIC KEY", "PRIVATE KEY"):
        assert marker not in text, f"venv.ps1 must never embed key material ({marker!r})"


def test_delimiters_balanced() -> None:
    """No PowerShell host on this platform: a balanced-delimiters check is the
    best available syntax smoke test (the script avoids unbalanced delimiters
    inside string literals so this stays sound)."""
    text = _require_script()
    for opener, closer in (("{", "}"), ("(", ")"), ("[", "]")):
        assert text.count(opener) == text.count(closer), (
            f"venv.ps1: unbalanced {opener}{closer} ({text.count(opener)} vs {text.count(closer)})"
        )
