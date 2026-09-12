"""Unit tests for the claude-code configure-agents adapter.

Every test runs against a fake HOME / project tree (tmp_path); nothing here
touches the real ~/.claude.json or any real config.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from universal_db_mcp.agents.claude_code import (
    AGENT_NAME,
    SERVER_KEY,
    apply,
    detect,
    plan,
    registration_entry,
    user_config_path,
)
from universal_db_mcp.agents.core import AgentStatus

ENV: dict[str, str] = {
    "UDBMCP_CONFIG": "/etc/universal-db-mcp/config.yaml",
    "UDBMCP_VENV_PYTHON": "/opt/universal-db-mcp/venv/bin/python",
}


def _fake_env(tmp_path: Path, *, installed: bool = True, project: bool = False) -> tuple[Path, Path]:
    """Create a fake HOME (and optional project dir); return (home, project_dir)."""
    home = tmp_path / "home"
    home.mkdir()
    project_dir = tmp_path / "proj"
    project_dir.mkdir()
    if installed:
        (home / ".claude").mkdir()  # marks Claude Code as installed, config absent
    if project:
        (project_dir / ".mcp.json").write_text("{}", encoding="utf-8")
    return home, project_dir


def _read(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _bak_files(directory: Path) -> list[Path]:
    return sorted(p for p in directory.iterdir() if ".bak" in p.name)


def test_not_installed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home, project_dir = _fake_env(tmp_path, installed=False)
    # Empty PATH so shutil.which("claude") can never hit a real binary.
    monkeypatch.setenv("PATH", "")
    assert detect(ENV, home, project_dir=project_dir) is AgentStatus.NOT_INSTALLED

    planned = plan(ENV, home, project_dir=project_dir)
    assert planned.agent == AGENT_NAME
    assert planned.status is AgentStatus.NOT_INSTALLED
    assert planned.config_block == ""

    result = apply(ENV, home, True, project_dir=project_dir)
    assert result.status is AgentStatus.NOT_INSTALLED
    assert not (home / ".claude.json").exists()
    assert not (project_dir / ".mcp.json").exists()


def test_installed_unconfigured_plan_and_apply(tmp_path: Path) -> None:
    home, project_dir = _fake_env(tmp_path)
    target = user_config_path(home)

    assert detect(ENV, home, project_dir=project_dir) is AgentStatus.INSTALLED_UNCONFIGURED

    planned = plan(ENV, home, project_dir=project_dir)
    assert planned.status is AgentStatus.INSTALLED_UNCONFIGURED
    assert planned.config_path == target
    assert planned.entry == registration_entry(ENV, home)
    # Plan is precise about the exact keys/bytes: server key, launch args, env path.
    assert f'"{SERVER_KEY}"' in planned.config_block
    assert '"serve"' in planned.config_block
    assert "--transport" in planned.config_block
    assert "/etc/universal-db-mcp/config.yaml" in planned.config_block
    assert "/opt/universal-db-mcp/venv/bin/python" in planned.config_block
    assert "UDBMCP_CONFIG" in planned.config_block
    assert str(target) in planned.summary
    # Planning never writes.
    assert not target.exists()

    result = apply(ENV, home, True, project_dir=project_dir)
    assert result.status is AgentStatus.CONFIGURED
    assert target.exists()

    data = _read(target)
    entry = data["mcpServers"][SERVER_KEY]
    assert entry == {
        "type": "stdio",
        "command": "/opt/universal-db-mcp/venv/bin/python",
        "args": ["-m", "universal_db_mcp", "serve", "--transport", "stdio"],
        "env": {"UDBMCP_CONFIG": "/etc/universal-db-mcp/config.yaml"},
    }
    assert result.entry == entry
    # No secrets in the written bytes.
    written = target.read_text(encoding="utf-8")
    assert "password" not in written.lower()
    assert "token" not in written.lower()
    # Brand-new file: no .bak backups were invented.
    assert _bak_files(home) == []


def test_apply_existing_config_backed_up_and_other_keys_preserved(tmp_path: Path) -> None:
    home, project_dir = _fake_env(tmp_path)
    target = user_config_path(home)
    original = {
        "mcpServers": {"other-server": {"command": "/bin/echo"}},
        "customTopLevel": {"numProjects": 3},
    }
    _write_json(target, original)

    result = apply(ENV, home, True, project_dir=project_dir)
    assert result.status is AgentStatus.CONFIGURED
    assert "backup" in result.summary

    # Timestamped .bak sibling exists and holds the exact original bytes.
    baks = _bak_files(home)
    assert len(baks) == 1
    assert _read(baks[0]) == original
    assert baks[0].name != target.name  # never clobbers the live file

    # Merge, not replace: pre-existing keys survive.
    data = _read(target)
    assert data["customTopLevel"] == {"numProjects": 3}
    assert data["mcpServers"]["other-server"] == {"command": "/bin/echo"}
    assert data["mcpServers"][SERVER_KEY]["command"] == "/opt/universal-db-mcp/venv/bin/python"


def test_apply_is_idempotent(tmp_path: Path) -> None:
    home, project_dir = _fake_env(tmp_path)
    target = user_config_path(home)
    _write_json(target, {"mcpServers": {"other": {"command": "/bin/echo"}}})

    first = apply(ENV, home, True, project_dir=project_dir)
    assert first.status is AgentStatus.CONFIGURED
    assert detect(ENV, home, project_dir=project_dir) is AgentStatus.CONFIGURED

    before = target.read_bytes()
    baks_before = _bak_files(home)

    second = apply(ENV, home, True, project_dir=project_dir)
    assert second.status is AgentStatus.CONFIGURED
    assert "no changes needed" in second.summary
    assert target.read_bytes() == before  # no rewrite, no duplicate registration
    assert _bak_files(home) == baks_before  # no new backups on re-run

    data = _read(target)
    assert list(data["mcpServers"]).count(SERVER_KEY) == 1


def test_apply_existing_config_without_mcpServers_key(tmp_path: Path) -> None:
    """A real Claude Code install: ~/.claude.json has harness keys, no mcpServers.

    detect() must report installed_unconfigured and apply() must register the
    server without crashing (regression: KeyError on the absent key) and
    without losing the harness-managed top-level keys.
    """
    home, project_dir = _fake_env(tmp_path)
    target = user_config_path(home)
    original = {"numStartups": 5, "theme": "dark"}
    _write_json(target, original)

    assert detect(ENV, home, project_dir=project_dir) is AgentStatus.INSTALLED_UNCONFIGURED

    planned = plan(ENV, home, project_dir=project_dir)
    assert planned.status is AgentStatus.INSTALLED_UNCONFIGURED

    result = apply(ENV, home, True, project_dir=project_dir)
    assert result.status is AgentStatus.CONFIGURED

    # Timestamped .bak of the original, and the original keys preserved.
    baks = _bak_files(home)
    assert len(baks) == 1
    assert _read(baks[0]) == original
    data = _read(target)
    assert data["numStartups"] == 5
    assert data["theme"] == "dark"
    assert data["mcpServers"][SERVER_KEY]["command"] == "/opt/universal-db-mcp/venv/bin/python"

    # Re-run is idempotent against the now-registered config.
    assert detect(ENV, home, project_dir=project_dir) is AgentStatus.CONFIGURED
    before = target.read_bytes()
    assert apply(ENV, home, True, project_dir=project_dir).status is AgentStatus.CONFIGURED
    assert target.read_bytes() == before


def test_null_mcpServers_fails_closed(tmp_path: Path) -> None:
    """An explicit JSON null under mcpServers is unrecognized state, not 'clean'.

    detect() must fail closed (null is not an object) and apply() must refuse
    to write rather than silently no-op or overwrite.
    """
    home, project_dir = _fake_env(tmp_path)
    target = user_config_path(home)
    raw = '{"mcpServers": null}'
    target.write_text(raw, encoding="utf-8")

    assert detect(ENV, home, project_dir=project_dir) is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED

    planned = plan(ENV, home, project_dir=project_dir)
    assert planned.status is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    assert str(target) in planned.config_block
    assert raw in planned.config_block
    assert "refusing to write" in planned.summary

    result = apply(ENV, home, True, project_dir=project_dir)
    assert result.status is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    assert "refusing to write" in result.summary
    assert raw in result.config_block
    # Never silently overwritten, never silently no-op'd into a write.
    assert target.read_text(encoding="utf-8") == raw
    assert _bak_files(home) == []
    assert not (project_dir / ".mcp.json").exists()


def test_malformed_config_fails_closed_no_write(tmp_path: Path) -> None:
    home, project_dir = _fake_env(tmp_path)
    target = user_config_path(home)
    raw = '{"mcpServers": {"oops": '
    target.write_text(raw, encoding="utf-8")

    assert detect(ENV, home, project_dir=project_dir) is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED

    planned = plan(ENV, home, project_dir=project_dir)
    assert planned.status is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    # Fail-closed output prints the offending config block verbatim.
    assert str(target) in planned.config_block
    assert raw in planned.config_block
    assert "refusing to write" in planned.summary

    result = apply(ENV, home, True, project_dir=project_dir)
    assert result.status is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    assert target.read_text(encoding="utf-8") == raw  # never silently overwritten
    assert _bak_files(home) == []
    assert not (project_dir / ".mcp.json").exists()


def test_malformed_project_config_blocks_user_scope_write(tmp_path: Path) -> None:
    home, project_dir = _fake_env(tmp_path)
    bad_project = project_dir / ".mcp.json"
    bad_project.write_text("not json at all", encoding="utf-8")

    assert detect(ENV, home, project_dir=project_dir) is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    result = apply(ENV, home, True, project_dir=project_dir)
    assert result.status is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    assert "not json at all" in result.config_block
    assert not user_config_path(home).exists()  # nothing written anywhere


def test_malformed_mcpServers_type_fails_closed(tmp_path: Path) -> None:
    home, project_dir = _fake_env(tmp_path)
    (user_config_path(home)).write_text('{"mcpServers": [1, 2]}', encoding="utf-8")
    assert detect(ENV, home, project_dir=project_dir) is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    assert apply(ENV, home, True, project_dir=project_dir).status is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED


def test_differing_existing_entry_fails_closed(tmp_path: Path) -> None:
    home, project_dir = _fake_env(tmp_path)
    target = user_config_path(home)
    # Operator-customized registration under our key: never silently rewritten.
    _write_json(target, {"mcpServers": {SERVER_KEY: {"command": "/custom/python", "env": {}}}})

    assert detect(ENV, home, project_dir=project_dir) is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    planned = plan(ENV, home, project_dir=project_dir)
    assert planned.status is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    result = apply(ENV, home, True, project_dir=project_dir)
    assert result.status is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    assert _read(target)["mcpServers"][SERVER_KEY] == {"command": "/custom/python", "env": {}}


def test_confirmed_false_refuses_and_never_writes(tmp_path: Path) -> None:
    home, project_dir = _fake_env(tmp_path)
    target = user_config_path(home)

    planned = plan(ENV, home, project_dir=project_dir)
    result = apply(ENV, home, False, project_dir=project_dir)
    assert result.status is AgentStatus.INSTALLED_UNCONFIGURED
    assert "not applied: confirmation refused" in result.summary
    assert result.config_block == planned.config_block
    assert not target.exists()  # nothing written without explicit confirmation


def test_project_scope_existing_mcp_json_is_updated_with_backup(tmp_path: Path) -> None:
    home, project_dir = _fake_env(tmp_path, installed=False, project=True)
    proj_cfg = project_dir / ".mcp.json"
    original = {"mcpServers": {"other": {"command": "/bin/echo"}}}
    _write_json(proj_cfg, original)

    # Installed only via the project config (no home artifacts).
    assert detect(ENV, home, project_dir=project_dir) is AgentStatus.INSTALLED_UNCONFIGURED

    result = apply(ENV, home, True, project_dir=project_dir)
    assert result.status is AgentStatus.CONFIGURED
    # User scope created, project scope updated in place.
    data = _read(proj_cfg)
    assert data["mcpServers"][SERVER_KEY]["args"] == [
        "-m",
        "universal_db_mcp",
        "serve",
        "--transport",
        "stdio",
    ]
    assert data["mcpServers"]["other"] == {"command": "/bin/echo"}
    assert user_config_path(home).is_file()
    baks = [p for p in _bak_files(project_dir) if p.name.startswith(".mcp.json")]
    assert len(baks) == 1
    assert _read(baks[0]) == original


def test_absent_project_mcp_json_is_not_created(tmp_path: Path) -> None:
    home, project_dir = _fake_env(tmp_path)
    result = apply(ENV, home, True, project_dir=project_dir)
    assert result.status is AgentStatus.CONFIGURED
    assert not (project_dir / ".mcp.json").exists()


def test_env_block_only_carries_non_secret_udbmcp_config(tmp_path: Path) -> None:
    home, project_dir = _fake_env(tmp_path)
    entry = registration_entry(ENV, home)
    assert set(entry) == {"type", "command", "args", "env"}
    assert set(entry["env"]) == {"UDBMCP_CONFIG"}
    assert entry["env"]["UDBMCP_CONFIG"] == "/etc/universal-db-mcp/config.yaml"


def test_server_block_defaults_to_running_venv_python(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home, project_dir = _fake_env(tmp_path)
    import sys

    entry = registration_entry({}, home)
    assert entry["command"] == sys.executable
    override = registration_entry({"UDBMCP_VENV_PYTHON": "/opt/venv/bin/python"}, home)
    assert override["command"] == "/opt/venv/bin/python"
    # And the applied file uses the override end to end.
    result = apply({"UDBMCP_VENV_PYTHON": "/opt/venv/bin/python"}, home, True, project_dir=project_dir)
    assert result.status is AgentStatus.CONFIGURED
    assert _read(user_config_path(home))["mcpServers"][SERVER_KEY]["command"] == "/opt/venv/bin/python"


def test_claude_binary_on_path_counts_as_installed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home, project_dir = _fake_env(tmp_path, installed=False)
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    (fake_bin / "claude").write_text("#!/bin/sh\n", encoding="utf-8")
    (fake_bin / "claude").chmod(0o755)
    monkeypatch.setenv("PATH", str(fake_bin))
    assert detect(ENV, home, project_dir=project_dir) is AgentStatus.INSTALLED_UNCONFIGURED
