"""Structural tests for the Windows MSI PowerShell custom actions.

The MSI build host (macOS) has no PowerShell runtime and every Windows
runtime behavior is honestly recorded as ``not_run`` in the ledger; these
tests pin down the trust-critical, text-level invariants of the three
custom-action scripts instead. Actual install/service behavior on a real
Windows host belongs to scripts/test_package_msi.ps1 (delivered gate).

Trust invariants asserted here:
  * no public-key material is ever embedded in a package script;
  * the custom actions never install packages (pip is exclusively the
    venv-build action, --no-index --require-hashes);
  * doctor.ps1 documents that it executes payload and must be sequenced
    after the trusted verify_bundle.py action;
  * the service action configures auto start + failure recovery and is
    idempotent via delete-then-create;
  * the uninstall action tolerates absent/not-running services.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parents[2]
CUSTOM_DIR = PROJECT / "packaging" / "msi" / "custom"

SCRIPTS = ("doctor.ps1", "service.ps1", "uninstall.ps1")


@pytest.fixture(scope="module")
def sources() -> dict[str, str]:
    out: dict[str, str] = {}
    for name in SCRIPTS:
        path = CUSTOM_DIR / name
        # ascii read doubles as an encoding guard: Windows PowerShell 5.1
        # treats a BOM-less non-ASCII file as ANSI, so the scripts must be
        # pure ASCII.
        out[name] = path.read_text(encoding="ascii")
    return out


def code_lines(text: str) -> str:
    """The scripts' executable lines (comment-only lines stripped).

    The trust invariants are about what the scripts DO, so prose comments
    (e.g. service.ps1's "No pip, no downloads" explanation) must not trip
    text-level assertions.
    """
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def has_sc_subcommand(text: str, subcommand: str) -> bool:
    """True if sc.exe is invoked with <subcommand> in either quote style."""
    return bool(re.search(r"[\'\"]" + re.escape(subcommand) + r" [\'\"]", text))


# --- all three scripts -------------------------------------------------------


@pytest.mark.parametrize("name", SCRIPTS)
def test_script_exists_and_is_nonempty(name: str) -> None:
    path = CUSTOM_DIR / name
    assert path.is_file(), f"missing custom action script: {path}"
    assert path.stat().st_size > 0


@pytest.mark.parametrize("name", SCRIPTS)
def test_script_is_pure_ascii(name: str, sources: dict[str, str]) -> None:
    # read_text(encoding="ascii") in the fixture already raised if not; this
    # assertion makes the intent explicit in the failure output.
    assert all(ord(ch) < 128 for ch in sources[name]), f"{name} must be pure ASCII"


@pytest.mark.parametrize("name", SCRIPTS)
def test_no_public_key_material_embedded(name: str, sources: dict[str, str]) -> None:
    text = sources[name]
    for marker in ("-----BEGIN", "PUBLIC KEY", "PRIVATE KEY"):
        assert marker not in text, (
            f"{name} embeds key material ({marker!r}); the release public key "
            "is admin-distributed out-of-band and never shipped in a package"
        )


@pytest.mark.parametrize("name", SCRIPTS)
def test_no_package_installation_in_custom_actions(name: str, sources: dict[str, str]) -> None:
    text = code_lines(sources[name])
    assert not re.search(r"\bpip3?\b", text), (
        f"{name} invokes pip; wheel installation belongs exclusively to the "
        "venv-build action (--no-index --require-hashes)"
    )
    for marker in ("Invoke-WebRequest", "Start-BitsTransfer", "curl.exe", "wget.exe"):
        assert marker not in text, f"{name} must not download anything"


@pytest.mark.parametrize("name", SCRIPTS)
def test_no_finish_service_shortcut(name: str, sources: dict[str, str]) -> None:
    # The orchestrator's bar: no "FinishService"-style exit-0-always shortcut.
    # Every failure path must exit nonzero; grep for the honest failure exits.
    text = sources[name]
    assert re.search(r"\bexit\s+1\b", text), f"{name} has no nonzero failure exit"
    assert "return 3010" not in text  # "success with reboot" masking


@pytest.mark.parametrize("name", SCRIPTS)
def test_braces_and_parens_balanced(name: str, sources: dict[str, str]) -> None:
    # No PowerShell host on this platform: a balanced-delimiters check is the
    # best available syntax smoke test. The scripts deliberately avoid
    # unbalanced braces/parens inside string literals so this stays sound.
    text = sources[name]
    for opener, closer in (("{", "}"), ("(", ")"), ("[", "]")):
        assert text.count(opener) == text.count(closer), (
            f"{name}: unbalanced {opener}{closer} ({text.count(opener)} vs {text.count(closer)})"
        )


# --- doctor.ps1 ---------------------------------------------------------------


def test_doctor_runs_doctor_module_against_config(sources: dict[str, str]) -> None:
    text = sources["doctor.ps1"]
    assert "-m" in text and "'universal_db_mcp'" in text and "'doctor'" in text
    assert "--config" in text
    assert "Scripts\\python.exe" in text  # the venv interpreter, not system python
    assert "--connectivity" not in text.replace("no --connectivity", ""), (
        "doctor must run offline at install time (no connectivity probes)"
    )


def test_doctor_propagates_failure_nonzero(sources: dict[str, str]) -> None:
    text = sources["doctor.ps1"]
    assert "$code -ne 0" in text, "doctor exit code must be checked, not ignored"


def test_doctor_documents_payload_execution_sequencing(sources: dict[str, str]) -> None:
    text = sources["doctor.ps1"]
    assert "verify_bundle.py" in text, (
        "doctor.ps1 executes payload; it must document that it is scheduled "
        "strictly after the trusted verify_bundle.py custom action"
    )


def test_doctor_sets_bundle_manifest_hook(sources: dict[str, str]) -> None:
    text = sources["doctor.ps1"]
    assert "UDBMCP_BUNDLE_MANIFEST" in text, (
        "doctor should report the installed bundle profile from the manifest "
        "(same hook as the .deb postinst and macOS postinstall)"
    )


# --- service.ps1 ----------------------------------------------------------------


def test_service_create_shape(sources: dict[str, str]) -> None:
    text = code_lines(sources["service.ps1"])
    assert has_sc_subcommand(text, "create")
    assert "binPath= " in text
    assert "start= auto" in text
    assert '" -m universal_db_mcp serve' in text
    assert "obj= " in text, "service account property must be passed to obj="


def test_service_failure_recovery_config(sources: dict[str, str]) -> None:
    text = code_lines(sources["service.ps1"])
    assert has_sc_subcommand(text, "failure")
    assert "reset= 86400" in text
    assert "restart/60000" in text


def test_service_description_registered(sources: dict[str, str]) -> None:
    text = code_lines(sources["service.ps1"])
    assert has_sc_subcommand(text, "description")


def test_service_delete_then_create_idempotent(sources: dict[str, str]) -> None:
    text = code_lines(sources["service.ps1"])
    assert has_sc_subcommand(text, "query"), "must detect an existing service (upgrade)"
    assert has_sc_subcommand(text, "stop")
    assert has_sc_subcommand(text, "delete"), "delete-then-create on upgrade"
    stop = text.index("stop ")
    delete = text.index("delete ")
    create = text.index("create ")
    assert stop < delete < create, "existing service must be stopped and deleted before create"


def test_service_writes_config_environment(sources: dict[str, str]) -> None:
    text = code_lines(sources["service.ps1"])
    assert "UDBMCP_CONFIG" in text, (
        "serve refuses to start without a config; the service must receive "
        "the validated config path via the service Environment value"
    )


def test_service_cleans_up_half_created_service_on_failure(sources: dict[str, str]) -> None:
    text = sources["service.ps1"]
    assert "Remove-ServiceBestEffort" in text
    assert re.search(r"catch\s*\{[\s\S]*Remove-ServiceBestEffort", text), (
        "a failure after sc.exe create must remove the half-configured "
        "service before exiting nonzero (sc.exe is not transactional)"
    )


# --- uninstall.ps1 ----------------------------------------------------------------


def test_uninstall_stops_and_deletes(sources: dict[str, str]) -> None:
    text = code_lines(sources["uninstall.ps1"])
    assert has_sc_subcommand(text, "stop") and has_sc_subcommand(text, "delete")


def test_uninstall_tolerates_absent_and_not_running(sources: dict[str, str]) -> None:
    text = sources["uninstall.ps1"]
    assert "1060" in text, "absent service must be a success condition"
    assert "1062" in text, "not-running service must be a success condition"
    assert "1072" in text, "marked-for-delete must be tolerated on uninstall"


def test_uninstall_fails_closed_on_other_errors(sources: dict[str, str]) -> None:
    text = sources["uninstall.ps1"]
    assert re.search(r"\bexit\s+1\b", text)


def test_uninstall_states_machine_config_is_not_retained(sources: dict[str, str]) -> None:
    """The MSI uninstall transaction DOES delete ProgramData\\...\\config.yaml
    (ConfigYamlComponent has NeverOverwrite but no Permanent, so RemoveFiles
    removes it right after this action). The script must never claim the
    config is retained: an admin relying on such a log line would skip the
    documented backup (docs/offline-deployment.md: uninstall section) and
    lose hand-edited config. The .deb comparison is the opposite: postrm
    keeps the conffile on remove."""
    text = sources["uninstall.ps1"]
    assert not re.search(r"Remove-Item[^\n]*config\.yaml", text), (
        "uninstall.ps1 itself must not delete the config (the MSI RemoveFiles "
        "standard action does that; the script stays out of it)"
    )
    assert "NOT retained" in text, (
        "the script must state explicitly that the machine-wide config is NOT "
        "retained at uninstall, so admins back it up before uninstalling"
    )
    assert "retained by design" not in text, (
        "the false retention assurance must not come back"
    )


def test_uninstall_validates_service_name_before_tool_invocation(sources: dict[str, str]) -> None:
    """$ServiceName is embedded unquoted in sc.exe command lines and inside a
    quoted reg.exe key path, so both quote styles and whitespace must be
    rejected before the first tool invocation (same guard as service.ps1)."""
    code = code_lines(sources["uninstall.ps1"])
    guard_line = next(
        (line for line in code.splitlines() if "$ServiceName -match" in line), None
    )
    assert guard_line, "uninstall.ps1 does not validate the service name"
    assert "\\s" in guard_line, "whitespace in the service name must be rejected"
    assert '"' in guard_line, "double quotes in the service name must be rejected"
    assert "'" in guard_line, "single quotes in the service name must be rejected"
    # The guard must run before the first tool invocation (the
    # Test-ServiceExists call that triggers the first sc.exe query).
    assert code.index("$ServiceName -match") < code.index("Test-ServiceExists -Name"), (
        "the service name guard must run before the first sc.exe invocation"
    )
