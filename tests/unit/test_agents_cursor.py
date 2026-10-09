"""Unit tests for the Cursor agent-harness adapter.

All tests run against fake HOME trees under tmp_path; nothing touches the
real ``~/.cursor``.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from universal_db_mcp.agents import cursor
from universal_db_mcp.agents.core import AgentStatus

ENV: dict[str, str] = {
    "UDBMCP_VENV_PYTHON": "/opt/universal-db-mcp/venv/bin/python",
    "UDBMCP_CONFIG": "/etc/universal-db-mcp/config.yaml",
}

EXPECTED_ENTRY: dict[str, Any] = {
    "command": "/opt/universal-db-mcp/venv/bin/python",
    "args": ["-I", "-m", "universal_db_mcp", "serve", "--transport", "stdio"],
    "env": {"UDBMCP_CONFIG": "/etc/universal-db-mcp/config.yaml"},
}


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def make_installed(home: Path) -> Path:
    cursor_dir = home / ".cursor"
    cursor_dir.mkdir(parents=True, exist_ok=True)
    return cursor_dir


def test_not_installed_when_cursor_dir_missing(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()

    assert cursor.detect(ENV, home) is AgentStatus.NOT_INSTALLED

    planned = cursor.plan(ENV, home)
    assert planned.status is AgentStatus.NOT_INSTALLED
    assert planned.config_path == home / ".cursor" / "mcp.json"

    applied = cursor.apply(ENV, home, confirmed=True)
    assert applied.status is AgentStatus.NOT_INSTALLED
    assert not (home / ".cursor").exists()


def test_installed_unconfigured_when_dir_exists_without_mcp_json(tmp_path: Path) -> None:
    home = tmp_path / "home"
    make_installed(home)

    assert cursor.detect(ENV, home) is AgentStatus.INSTALLED_UNCONFIGURED

    planned = cursor.plan(ENV, home)
    assert planned.status is AgentStatus.INSTALLED_UNCONFIGURED
    # Exact bytes/keys that would be added are described in the plan.
    assert json.loads(planned.config_block) == {
        "mcpServers": {"universal-db": EXPECTED_ENTRY}
    }


def test_installed_unconfigured_when_mcp_json_lacks_our_entry(tmp_path: Path) -> None:
    home = tmp_path / "home"
    target = make_installed(home) / "mcp.json"
    target.write_text(
        json.dumps({"mcpServers": {"other-server": {"command": "foo"}}}),
        encoding="utf-8",
    )

    assert cursor.detect(ENV, home) is AgentStatus.INSTALLED_UNCONFIGURED


def test_configured_when_registration_already_present(tmp_path: Path) -> None:
    home = tmp_path / "home"
    target = make_installed(home) / "mcp.json"
    target.write_text(
        json.dumps({"mcpServers": {"universal-db": EXPECTED_ENTRY}}),
        encoding="utf-8",
    )

    assert cursor.detect(ENV, home) is AgentStatus.CONFIGURED

    planned = cursor.plan(ENV, home)
    assert planned.status is AgentStatus.CONFIGURED

    # Idempotent: confirmed apply is still a no-op and rewrites nothing.
    before = target.read_text(encoding="utf-8")
    applied = cursor.apply(ENV, home, confirmed=True)
    assert applied.status is AgentStatus.CONFIGURED
    assert target.read_text(encoding="utf-8") == before
    assert not list(make_installed(home).glob("mcp.json.bak.*"))


def test_apply_writes_correct_shape_and_backup(tmp_path: Path) -> None:
    home = tmp_path / "home"
    target = make_installed(home) / "mcp.json"
    target.write_text(
        json.dumps({"mcpServers": {"other-server": {"command": "foo"}}}),
        encoding="utf-8",
    )
    before = target.read_text(encoding="utf-8")

    applied = cursor.apply(ENV, home, confirmed=True)

    assert applied.status is AgentStatus.CONFIGURED
    backups = list(make_installed(home).glob("mcp.json.bak.*"))
    assert len(backups) == 1
    # The backup preserves the pre-write bytes exactly.
    assert backups[0].read_text(encoding="utf-8") == before
    # Timestamped .bak sibling (core.backup_path naming).
    assert re.fullmatch(r"mcp\.json\.bak\.\d{8}T\d{6}\d*Z", backups[0].name)

    data = read_json(target)
    assert data["mcpServers"]["universal-db"] == EXPECTED_ENTRY
    # Pre-existing unrelated registrations are preserved.
    assert data["mcpServers"]["other-server"] == {"command": "foo"}
    # No secrets beyond the launch command and UDBMCP_CONFIG path.
    assert set(data["mcpServers"]["universal-db"]["env"]) == {"UDBMCP_CONFIG"}


def test_apply_creates_file_when_mcp_json_absent(tmp_path: Path) -> None:
    home = tmp_path / "home"
    make_installed(home)

    applied = cursor.apply(ENV, home, confirmed=True)

    assert applied.status is AgentStatus.CONFIGURED
    target = home / ".cursor" / "mcp.json"
    assert read_json(target) == {"mcpServers": {"universal-db": EXPECTED_ENTRY}}
    # Nothing to back up on first creation.
    assert not list(make_installed(home).glob("mcp.json.bak.*"))


def test_apply_is_idempotent_on_second_run(tmp_path: Path) -> None:
    home = tmp_path / "home"
    make_installed(home)

    first = cursor.apply(ENV, home, confirmed=True)
    assert first.status is AgentStatus.CONFIGURED
    after_first = (home / ".cursor" / "mcp.json").read_text(encoding="utf-8")

    second = cursor.apply(ENV, home, confirmed=True)
    assert second.status is AgentStatus.CONFIGURED
    assert (home / ".cursor" / "mcp.json").read_text(encoding="utf-8") == after_first
    # No additional backups were created by the no-op run.
    assert not list(make_installed(home).glob("mcp.json.bak.*"))


@pytest.mark.parametrize("initial", [{}, {"otherTopLevel": True}])
def test_apply_creates_mcp_servers_key_when_missing(
    tmp_path: Path, initial: dict[str, Any]
) -> None:
    """A valid mcp.json lacking "mcpServers" is writable, not a silent no-op.

    detect() classifies it as INSTALLED_UNCONFIGURED, plan() reports a
    future-tense add, and a confirmed apply must actually create the key
    (preserving other top-level keys and taking a .bak first).
    """
    home = tmp_path / "home"
    target = make_installed(home) / "mcp.json"
    target.write_text(json.dumps(initial), encoding="utf-8")
    before = target.read_text(encoding="utf-8")

    assert cursor.detect(ENV, home) is AgentStatus.INSTALLED_UNCONFIGURED

    planned = cursor.plan(ENV, home)
    assert planned.status is AgentStatus.INSTALLED_UNCONFIGURED
    assert "would back up" in planned.summary

    applied = cursor.apply(ENV, home, confirmed=True)
    assert applied.status is AgentStatus.CONFIGURED
    assert "not applied" not in applied.summary
    assert "added" in applied.summary

    # The registration was written under a newly created mcpServers key.
    data = read_json(target)
    assert data["mcpServers"] == {"universal-db": EXPECTED_ENTRY}
    for key, value in initial.items():
        assert data[key] == value
    # Timestamped .bak preserves the pre-write bytes exactly.
    backups = list(make_installed(home).glob("mcp.json.bak.*"))
    assert len(backups) == 1
    assert backups[0].read_text(encoding="utf-8") == before


def test_conflicting_registration_reported_as_conflict_not_malformed(
    tmp_path: Path,
) -> None:
    """A valid file with a user-managed "universal-db" entry fails closed
    with an accurate diagnostic, not a false "malformed" report."""
    home = tmp_path / "home"
    target = make_installed(home) / "mcp.json"
    existing = {"mcpServers": {"universal-db": {"command": "/custom/python"}}}
    target.write_text(json.dumps(existing), encoding="utf-8")

    assert cursor.detect(ENV, home) is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED

    planned = cursor.plan(ENV, home)
    assert planned.status is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    assert "conflicting" in planned.summary or "differs from" in planned.summary
    # Must not claim the healthy file is unreadable/malformed, and must not
    # suggest removing the file (that would destroy user-managed state).
    assert "malformed" not in planned.summary
    assert "unreadable" not in planned.summary
    assert "remove the file" not in planned.summary
    # The offending file's contents are still shown for operator inspection.
    assert "/custom/python" in planned.config_block

    # Apply never overwrites the conflicting registration.
    applied = cursor.apply(ENV, home, confirmed=True)
    assert applied.status is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    assert read_json(target) == existing
    assert not list(make_installed(home).glob("mcp.json.bak.*"))


@pytest.mark.parametrize("bad_content", ["{not json", "[1, 2, 3]", "null"])
def test_malformed_config_fails_closed_without_write(tmp_path: Path, bad_content: str) -> None:
    home = tmp_path / "home"
    target = make_installed(home) / "mcp.json"
    target.write_text(bad_content, encoding="utf-8")

    assert cursor.detect(ENV, home) is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED

    planned = cursor.plan(ENV, home)
    assert planned.status is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    # The plan prints the offending file's contents for the operator.
    assert "mcp.json" in planned.summary

    applied = cursor.apply(ENV, home, confirmed=True)
    assert applied.status is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    # Never silently overwritten.
    assert target.read_text(encoding="utf-8") == bad_content
    assert not list(make_installed(home).glob("mcp.json.bak.*"))


def test_non_object_mcp_servers_fails_closed(tmp_path: Path) -> None:
    home = tmp_path / "home"
    target = make_installed(home) / "mcp.json"
    target.write_text(json.dumps({"mcpServers": ["not", "an", "object"]}), encoding="utf-8")

    assert cursor.detect(ENV, home) is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED

    applied = cursor.apply(ENV, home, confirmed=True)
    assert applied.status is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    assert read_json(target) == {"mcpServers": ["not", "an", "object"]}


def test_confirmed_false_refuses_to_write(tmp_path: Path) -> None:
    home = tmp_path / "home"
    make_installed(home)

    applied = cursor.apply(ENV, home, confirmed=False)
    assert applied.status is AgentStatus.INSTALLED_UNCONFIGURED
    assert "not applied" in applied.summary
    assert not (home / ".cursor" / "mcp.json").exists()

    # Also refuses when a config already exists and would be modified.
    target = home / ".cursor" / "mcp.json"
    target.write_text(
        json.dumps({"mcpServers": {"other-server": {"command": "foo"}}}),
        encoding="utf-8",
    )
    before = target.read_text(encoding="utf-8")

    applied2 = cursor.apply(ENV, home, confirmed=False)
    assert applied2.status is AgentStatus.INSTALLED_UNCONFIGURED
    assert target.read_text(encoding="utf-8") == before
    assert not list(make_installed(home).glob("mcp.json.bak.*"))


def test_registration_entry_resolves_venv_python_and_config(tmp_path: Path) -> None:
    entry = cursor.registration_entry(ENV, tmp_path)
    assert entry == EXPECTED_ENTRY

    # Without UDBMCP_CONFIG in env, falls back to the canonical system path
    # or a per-user default rather than launching without a config.
    entry_no_cfg = cursor.registration_entry({"UDBMCP_VENV_PYTHON": "/x/py"}, tmp_path)
    assert entry_no_cfg["env"]["UDBMCP_CONFIG"].endswith("config.yaml")
