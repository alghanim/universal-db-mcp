"""``configure-agents --json`` (machine-readable GUI mode) + the /Applications
GUI wrapper that consumes it.

The --json contract under test:
  * ``--json`` alone: read-only detection, structured output, NOTHING written,
    never prompts (the GUI's dialogs are the consent step, not the CLI's).
  * ``--json --yes``: applies exactly the writable harness(es) (--agent
    restricts further); every applied entry reports status/summary/backups.
  * Fail-closed statuses (adapter_error / fail_closed) are data, never raises.

The GUI wrapper tests pin the ask-before-write chain in
packaging/macos-app/configure_agents_app.sh: read-only --json detection first,
a checkbox dialog, a confirm dialog mentioning the .bak backup, and only then
a per-agent ``--yes`` apply - plus the bash-heredoc/apostrophe trap that once
broke the script's syntax (an AppleScript possessive inside a $( ) heredoc).
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from universal_db_mcp.__main__ import main

REPO_ROOT = Path(__file__).resolve().parents[2]
APP_SCRIPT = REPO_ROOT / "packaging" / "macos-app" / "configure_agents_app.sh"
POSTINSTALL = REPO_ROOT / "packaging" / "pkg" / "postinstall"
BUILD_PKG = REPO_ROOT / "scripts" / "package" / "build_pkg.sh"
CONCLUSION = REPO_ROOT / "packaging" / "pkg-resources" / "conclusion.rtf"


def _parse(out: str) -> dict[str, object]:
    return json.loads(out)


def test_json_detection_is_read_only_and_well_formed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    (fake_home / ".claude").mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)  # a Linux host's own would win over HOME
    monkeypatch.setenv("PATH", "")
    # Isolate from the TEST HOST: the adapter (correctly) probes absolute
    # system app paths, and this Mac may really have Claude.app installed.
    monkeypatch.setattr(
        "universal_db_mcp.agents.claude_desktop.SYSTEM_APP_PATHS",
        (tmp_path / "no-such-app",),
    )

    rc = main(["configure-agents", "--json"])
    out = capsys.readouterr().out
    data = _parse(out)

    assert rc == 0
    assert data["home"] == str(fake_home)
    harnesses = {h["agent"]: h for h in data["harnesses"]}  # type: ignore[index]
    assert harnesses["claude-code"]["status"] == "installed_unconfigured"
    assert harnesses["claude-code"]["writable"] is True
    # every other adapter reports a status (not_installed in a fake HOME) and
    # is never writable
    assert all(h["writable"] is False for a, h in harnesses.items() if a != "claude-code")  # type: ignore[union-attr]
    # read-only: no config file appeared
    assert not (fake_home / ".claude.json").exists()


def test_json_without_yes_never_writes_even_for_single_agent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    (fake_home / ".claude").mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)  # a Linux host's own would win over HOME
    monkeypatch.setenv("PATH", "")

    rc = main(["configure-agents", "--json", "--agent", "claude-code"])
    capsys.readouterr()
    assert rc == 0
    assert not (fake_home / ".claude.json").exists()


def test_json_yes_applies_only_selected_agent_and_reports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    (fake_home / ".claude").mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)  # a Linux host's own would win over HOME
    monkeypatch.setenv("PATH", "")

    rc = main(["configure-agents", "--json", "--agent", "claude-code", "--yes"])
    out = capsys.readouterr().out
    data = _parse(out)

    assert rc == 0
    applied = data["applied"]  # type: ignore[index]
    assert isinstance(applied, list) and len(applied) == 1
    entry = applied[0]
    assert entry["agent"] == "claude-code"  # type: ignore[index]
    assert entry["status"] == "configured"  # type: ignore[index]
    # the write actually happened and is a real registration
    cfg = json.loads((fake_home / ".claude.json").read_text(encoding="utf-8"))
    assert "universal-db" in cfg["mcpServers"]


def test_json_apply_skips_non_writable_harnesses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fake_home = tmp_path / "home"
    fake_home.mkdir()  # NOTHING installed
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)  # a Linux host's own would win over HOME
    monkeypatch.setenv("PATH", "")
    # Host isolation for the absolute system-app probe (see the detection test).
    monkeypatch.setattr(
        "universal_db_mcp.agents.claude_desktop.SYSTEM_APP_PATHS",
        (tmp_path / "no-such-app",),
    )

    rc = main(["configure-agents", "--json", "--yes"])
    out = capsys.readouterr().out
    data = _parse(out)
    assert rc == 0
    assert data["applied"] == []  # type: ignore[index]


# ------------------------------------------------------- GUI wrapper invariants


def test_app_script_preserves_ask_before_write_chain() -> None:
    text = APP_SCRIPT.read_text(encoding="utf-8")
    # detection is the read-only JSON mode
    assert "configure-agents --json" in text
    # consent: a checkbox list dialog, then a confirm dialog that states the
    # .bak backup promise, BEFORE any apply
    assert "choose from list" in text
    assert "with multiple selections allowed" in text
    confirm_pos = text.index(".bak backup")
    apply_pos = text.index("--json --yes")
    assert confirm_pos < apply_pos, "the confirm dialog must precede any apply"
    # --yes is passed per selected agent, never globally
    assert "configure-agents --agent \"$agent\" --json --yes" in text
    # cancelled/closed/empty-selection dialogs exit without applying
    assert text.count("|| exit 0") + text.count("&& exit 0") >= 3


def test_app_script_multi_selection_split_is_correct() -> None:
    """P1 review fix: `chosen as text` joins with the CURRENT (empty-by-
    default) delimiters, so without setting them a multi-selection arrives as
    ONE concatenated bogus name. The script must set the delimiters with the
    apostrophe-free genitive and split the result on the same separator."""
    text = APP_SCRIPT.read_text(encoding="utf-8")
    assert "set text item delimiters of AppleScript to \"|\"" in text, (
        "multi-select needs explicit delimiters (default is the EMPTY string)"
    )
    assert 'IFS=\'|\' read -r -a AGENTS' in text, "the split must match the delimiter"
    # the empty-selection case must not reach the loop (bash 3.2 set -u dies
    # on "${AGENTS[@]}" with an empty array)
    assert '[ -z "$selected" ] && exit 0' in text


def test_app_script_apply_is_honest_about_failures() -> None:
    text = APP_SCRIPT.read_text(encoding="utf-8")
    # apply stdout only (never 2>&1): a stray stderr warning must not corrupt
    # the JSON parse
    apply_line = [ln for ln in text.splitlines() if "--json --yes" in ln and "out=" in ln][0]
    assert "2>&1" not in apply_line
    # a refused/fail-closed apply is a FAILED report, not a silent success,
    # and the script exits nonzero when any agent failed
    assert "apply_rc=$?" in text and 'exit "$rc_all"' in text
    # no backslash-in-f-string Python SyntaxError in the result extractor
    assert 'a.get(\\"status' not in text
    # the result dialog sanitizer strips quotes AND backslashes
    assert 'report="${report//\\\\/}"' in text


def test_app_script_parse_failure_is_not_success() -> None:
    """A broken detection payload must fail loudly, never masquerade as
    'every harness already configured'."""
    text = APP_SCRIPT.read_text(encoding="utf-8")
    assert "PARSE_ERROR" in text
    assert "output unreadable" in text
    # and the masquerade dialog must sit strictly AFTER the parse guard
    assert text.index("output unreadable") < text.index("No configurable agent harnesses found")


def test_app_script_avoids_apostrophe_in_substitution_heredoc() -> None:
    """bash's parser mis-tokenizes an apostrophe inside a heredoc body that
    sits within $( ): 'AppleScript's text item delimiters' once swallowed the
    rest of the script (found by bash -n 2026-09-12). The heredoc must stay
    free of single quotes."""
    body = APP_SCRIPT.read_text(encoding="utf-8")
    assert "AppleScript's" not in body


def test_app_script_is_executable_and_secrets_free() -> None:
    mode = stat.S_IMODE(APP_SCRIPT.stat().st_mode)
    assert mode & stat.S_IXUSR, "the staged app script must carry the exec bit"
    text = APP_SCRIPT.read_text(encoding="utf-8")
    assert "http-token" not in text, "the GUI app has no business touching the bearer token"
    assert os.environ.get("HOME", "")  # sanity: env access works (used via Path.home in CLI)


def test_postinstall_installs_root_owned_app_wrapper() -> None:
    text = POSTINSTALL.read_text(encoding="utf-8")
    assert "'Configure UniversalDB MCP.app'" in text
    assert "$PREFIX/share/configure_agents_app.sh" in text
    assert text.index("configure_agents_app.sh") < text.index("udbmcp-configure"), (
        "the wrapper must exec the root-owned payload script"
    )
    assert "chmod 0755" in text and "chmod 0644" in text
    # the payload prerequisite is checked BEFORE the daemon starts (past that
    # point a fatal failure would misreport a live service as a failed install)
    assert text.index('APP_SRC="$PREFIX/share/configure_agents_app.sh"') < text.index(
        "bootstrapping launchd daemon"
    )
    # the /Applications assembly itself is best-effort (loud WARNING, no abort):
    # it runs after the daemon is live
    assert "BEST-EFFORT by design" in text


def test_build_pkg_stages_the_app_script_into_the_payload() -> None:
    text = BUILD_PKG.read_text(encoding="utf-8")
    assert "packaging/macos-app/configure_agents_app.sh" in text
    assert "/usr/local/universal-db-mcp/share" in text
    assert "install -m 0755" in text


def test_installer_gui_conclusion_names_the_app() -> None:
    """The Installer's own GUI surface (conclusion screen) points at the app."""
    assert CONCLUSION.exists()
    assert "Configure UniversalDB MCP" in CONCLUSION.read_text(encoding="utf-8")


# ------------------------------------------------------- review fixes: CLI JSON


def test_json_dry_run_notice_never_pollutes_stdout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    (fake_home / ".claude").mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)  # a Linux host's own would win over HOME
    monkeypatch.setenv("PATH", "")

    rc = main(["configure-agents", "--json", "--dry-run", "--yes"])
    captured = capsys.readouterr()
    assert rc == 0
    _parse(captured.out)  # stdout must be pure JSON
    assert "dry-run" in captured.err


def test_json_apply_counts_returned_fail_closed_plan_as_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Adapters may refuse a write by RETURNING a fail-closed Plan instead of
    raising (TOCTOU: the config changed between detection and apply). The CLI
    must exit nonzero so the GUI shows FAILED, not 'Done.'."""
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    (fake_home / ".claude").mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)  # a Linux host's own would win over HOME
    monkeypatch.setenv("PATH", "")

    from universal_db_mcp.agents import registry
    from universal_db_mcp.agents.core import AgentStatus, Plan

    def _refused(name: str, env: object, home: Path, confirmed: bool) -> Plan:
        return Plan(agent=name, status=AgentStatus.UNKNOWN_STATE_FAIL_CLOSED, summary="config changed under us")

    monkeypatch.setattr(registry, "apply_confirmed", _refused)
    rc = main(["configure-agents", "--json", "--agent", "claude-code", "--yes"])
    data = _parse(capsys.readouterr().out)
    assert rc == 1, "a refused write must fail the CLI exit code"
    assert data["applied"][0]["status"] == "unknown_state_fail_closed"  # type: ignore[index]
