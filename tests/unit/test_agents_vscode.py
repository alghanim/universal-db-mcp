"""Unit tests for the VS Code (Copilot MCP) agent-harness adapter.

All tests run against fake HOME trees under tmp_path; nothing touches the
real VS Code configuration. The adapter's ``platform`` parameter is passed
explicitly so every layout is exercised deterministically regardless of the
running OS.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

import pytest

from universal_db_mcp.agents import vscode
from universal_db_mcp.agents.core import AgentStatus

ENV: dict[str, str] = {
    "UDBMCP_VENV_PYTHON": "/opt/universal-db-mcp/venv/bin/python",
    "UDBMCP_CONFIG": "/etc/universal-db-mcp/config.yaml",
}

EXPECTED_ENTRY: dict[str, Any] = {
    "type": "stdio",
    "command": "/opt/universal-db-mcp/venv/bin/python",
    "args": ["-I", "-m", "universal_db_mcp", "serve", "--transport", "stdio"],
    "env": {"UDBMCP_CONFIG": "/etc/universal-db-mcp/config.yaml"},
}


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def user_dir(home: Path, platform: str = "darwin") -> Path:
    return vscode.user_config_dir(home, platform)


def make_installed(home: Path, platform: str = "darwin") -> Path:
    # Creating the User config directory implies the Code marker dir exists.
    user = user_dir(home, platform)
    user.mkdir(parents=True, exist_ok=True)
    return user


def test_not_installed_when_code_dir_missing(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()

    assert vscode.detect(ENV, home, platform="darwin") is AgentStatus.NOT_INSTALLED

    planned = vscode.plan(ENV, home, platform="darwin")
    assert planned.status is AgentStatus.NOT_INSTALLED
    assert planned.config_path == user_dir(home) / "mcp.json"
    assert planned.config_block == ""

    applied = vscode.apply(ENV, home, confirmed=True, platform="darwin")
    assert applied.status is AgentStatus.NOT_INSTALLED
    # Nothing was created anywhere.
    assert not user_dir(home).exists()
    assert not (home / ".config").exists()


def test_platform_layouts_are_independent(tmp_path: Path) -> None:
    home = tmp_path / "home"
    make_installed(home, platform="darwin")

    # The macOS layout does not make VS Code "installed" for Linux.
    assert vscode.detect(ENV, home, platform="linux") is AgentStatus.NOT_INSTALLED
    assert vscode.config_path(home, platform="linux") == home / ".config" / "Code" / "User" / "mcp.json"
    assert vscode.config_path(home, platform="win32") == home / "AppData" / "Roaming" / "Code" / "User" / "mcp.json"
    assert vscode.config_path(home, platform="darwin") == (
        home / "Library" / "Application Support" / "Code" / "User" / "mcp.json"
    )


def test_default_platform_uses_running_sys_platform(tmp_path: Path) -> None:
    home = tmp_path / "home"
    make_installed(home, platform=sys.platform)

    # Calling without an explicit platform behaves like the running OS.
    assert vscode.detect(ENV, home) is AgentStatus.INSTALLED_UNCONFIGURED


def test_installed_unconfigured_without_mcp_json(tmp_path: Path) -> None:
    home = tmp_path / "home"
    make_installed(home)

    assert vscode.detect(ENV, home, platform="darwin") is AgentStatus.INSTALLED_UNCONFIGURED

    planned = vscode.plan(ENV, home, platform="darwin")
    assert planned.status is AgentStatus.INSTALLED_UNCONFIGURED
    # Exact bytes/keys that would be added are described in the plan.
    assert json.loads(planned.config_block) == {"servers": {"universal-db": EXPECTED_ENTRY}}


def test_installed_unconfigured_when_mcp_json_lacks_our_entry(tmp_path: Path) -> None:
    home = tmp_path / "home"
    target = make_installed(home) / "mcp.json"
    target.write_text(
        json.dumps({"servers": {"other-server": {"command": "foo"}}}),
        encoding="utf-8",
    )

    assert vscode.detect(ENV, home, platform="darwin") is AgentStatus.INSTALLED_UNCONFIGURED


def test_configured_when_registration_already_present(tmp_path: Path) -> None:
    home = tmp_path / "home"
    target = make_installed(home) / "mcp.json"
    target.write_text(
        json.dumps({"servers": {"universal-db": EXPECTED_ENTRY}}),
        encoding="utf-8",
    )

    assert vscode.detect(ENV, home, platform="darwin") is AgentStatus.CONFIGURED

    planned = vscode.plan(ENV, home, platform="darwin")
    assert planned.status is AgentStatus.CONFIGURED
    assert planned.config_block == ""

    # Idempotent: confirmed apply is still a no-op and rewrites nothing.
    before = target.read_text(encoding="utf-8")
    applied = vscode.apply(ENV, home, confirmed=True, platform="darwin")
    assert applied.status is AgentStatus.CONFIGURED
    assert target.read_text(encoding="utf-8") == before
    assert not list(user_dir(home).glob("*.bak*"))


def test_apply_writes_correct_shape_and_backup(tmp_path: Path) -> None:
    home = tmp_path / "home"
    target = make_installed(home) / "mcp.json"
    target.write_text(
        json.dumps({"servers": {"other-server": {"command": "foo"}}}),
        encoding="utf-8",
    )
    before = target.read_text(encoding="utf-8")

    applied = vscode.apply(ENV, home, confirmed=True, platform="darwin")

    assert applied.status is AgentStatus.CONFIGURED
    backups = list(user_dir(home).glob("*.bak*"))
    assert len(backups) == 1
    # The backup preserves the pre-write bytes exactly.
    assert backups[0].read_text(encoding="utf-8") == before
    # Timestamped .bak name as produced by core.backup_path
    # (e.g. mcp.json.bak.20260912T101500123456Z).
    assert re.search(r"\.bak\.\d{8}T\d{6}\d*Z$", backups[0].name)

    data = read_json(target)
    assert data["servers"]["universal-db"] == EXPECTED_ENTRY
    # VS Code entry declares its transport type.
    assert data["servers"]["universal-db"]["type"] == "stdio"
    # Pre-existing unrelated registrations are preserved.
    assert data["servers"]["other-server"] == {"command": "foo"}
    # No secrets beyond the launch command and the UDBMCP_CONFIG path.
    entry = data["servers"]["universal-db"]
    assert set(entry) == {"type", "command", "args", "env"}
    assert set(entry["env"]) == {"UDBMCP_CONFIG"}
    assert "password" not in json.dumps(entry).lower()


def test_apply_creates_file_when_mcp_json_absent(tmp_path: Path) -> None:
    home = tmp_path / "home"
    make_installed(home)

    applied = vscode.apply(ENV, home, confirmed=True, platform="darwin")

    assert applied.status is AgentStatus.CONFIGURED
    target = user_dir(home) / "mcp.json"
    assert read_json(target) == {"servers": {"universal-db": EXPECTED_ENTRY}}
    # Nothing to back up on first creation.
    assert not list(user_dir(home).glob("*.bak*"))


def test_apply_is_idempotent_on_second_run(tmp_path: Path) -> None:
    home = tmp_path / "home"
    make_installed(home)

    first = vscode.apply(ENV, home, confirmed=True, platform="darwin")
    assert first.status is AgentStatus.CONFIGURED
    target = user_dir(home) / "mcp.json"
    after_first = target.read_text(encoding="utf-8")

    second = vscode.apply(ENV, home, confirmed=True, platform="darwin")
    assert second.status is AgentStatus.CONFIGURED
    assert target.read_text(encoding="utf-8") == after_first
    # No additional backups were created by the no-op run.
    assert not list(user_dir(home).glob("*.bak*"))


def test_apply_over_existing_config_is_idempotent_and_backed_up_once(tmp_path: Path) -> None:
    home = tmp_path / "home"
    target = make_installed(home) / "mcp.json"
    target.write_text(
        json.dumps({"servers": {"other-server": {"command": "foo"}}}),
        encoding="utf-8",
    )

    vscode.apply(ENV, home, confirmed=True, platform="darwin")
    after_first = target.read_text(encoding="utf-8")
    second = vscode.apply(ENV, home, confirmed=True, platform="darwin")

    assert second.status is AgentStatus.CONFIGURED
    assert target.read_text(encoding="utf-8") == after_first
    # Still exactly one backup: the second run rewrote nothing.
    assert len(list(user_dir(home).glob("*.bak*"))) == 1


@pytest.mark.parametrize("bad_content", ["{not json", "[1, 2, 3]", "null"])
def test_malformed_config_fails_closed_without_write(tmp_path: Path, bad_content: str) -> None:
    home = tmp_path / "home"
    target = make_installed(home) / "mcp.json"
    target.write_text(bad_content, encoding="utf-8")

    assert vscode.detect(ENV, home, platform="darwin") is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED

    planned = vscode.plan(ENV, home, platform="darwin")
    assert planned.status is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    # The plan describes the offending file, never prints it (other servers' secrets).
    assert "mcp.json" in planned.summary
    assert "its contents are not shown" in planned.config_block

    applied = vscode.apply(ENV, home, confirmed=True, platform="darwin")
    assert applied.status is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    # Never silently overwritten.
    assert target.read_text(encoding="utf-8") == bad_content
    assert not list(user_dir(home).glob("*.bak*"))


def test_non_object_servers_fails_closed(tmp_path: Path) -> None:
    home = tmp_path / "home"
    target = make_installed(home) / "mcp.json"
    target.write_text(json.dumps({"servers": ["not", "an", "object"]}), encoding="utf-8")

    assert vscode.detect(ENV, home, platform="darwin") is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED

    applied = vscode.apply(ENV, home, confirmed=True, platform="darwin")
    assert applied.status is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    assert read_json(target) == {"servers": ["not", "an", "object"]}


def test_servers_null_fails_closed_at_every_stage(tmp_path: Path) -> None:
    """``{"servers": null}`` is a non-object servers value, not "absent".

    detect/plan/apply must all agree on UNKNOWN_STATE_FAIL_CLOSED so the
    interactive confirm flow never shows a plan promising a write that apply
    then refuses with a misleading "changed state" message.
    """
    home = tmp_path / "home"
    target = make_installed(home) / "mcp.json"
    bad_content = json.dumps({"servers": None})
    target.write_text(bad_content, encoding="utf-8")

    assert vscode.detect(ENV, home, platform="darwin") is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED

    planned = vscode.plan(ENV, home, platform="darwin")
    assert planned.status is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    assert '"servers" in' in planned.config_block and "is not an object" in planned.config_block

    applied = vscode.apply(ENV, home, confirmed=True, platform="darwin")
    assert applied.status is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    assert target.read_text(encoding="utf-8") == bad_content
    assert not list(user_dir(home).glob("*.bak*"))


def test_differing_existing_entry_fails_closed(tmp_path: Path) -> None:
    """A user-modified registration under our key is never overwritten."""
    home = tmp_path / "home"
    target = make_installed(home) / "mcp.json"
    mutated = {**EXPECTED_ENTRY, "command": "/usr/local/bin/python3"}
    target.write_text(
        json.dumps({"servers": {"universal-db": mutated, "other": {"command": "x"}}}),
        encoding="utf-8",
    )
    before = target.read_text(encoding="utf-8")

    assert vscode.detect(ENV, home, platform="darwin") is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED

    applied = vscode.apply(ENV, home, confirmed=True, platform="darwin")
    assert applied.status is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    assert target.read_text(encoding="utf-8") == before


@pytest.mark.parametrize("raced_shape", ["user_managed", "identical"])
def test_registration_landing_between_status_check_and_write_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, raced_shape: str
) -> None:
    """A concurrent writer landing a registration under our server key in
    the window between the apply-time status check and the write-time
    re-read must fail closed instead of being silently overwritten — even
    when the earlier reads still saw an unconfigured file.
    """
    home = tmp_path / "home"
    target = make_installed(home) / "mcp.json"
    safe = {"servers": {"other-server": {"command": "foo"}}}
    target.write_text(json.dumps(safe), encoding="utf-8")

    raced_entry: dict[str, Any] = dict(EXPECTED_ENTRY)
    if raced_shape == "user_managed":
        raced_entry["command"] = "/usr/local/bin/python3"
    raced = {"servers": {"other-server": {"command": "foo"}, "universal-db": raced_entry}}

    real_load = vscode.load_json_or_fail_closed
    calls = {"n": 0}

    def racing_load(path: Path) -> tuple[dict[str, Any] | None, str | None]:
        calls["n"] += 1
        if calls["n"] <= 2:
            # The apply() pre-check and the _apply_target status check see
            # the still-unconfigured file.
            return real_load(path)
        # The write-time re-read observes the concurrent writer's change.
        return dict(raced), None

    monkeypatch.setattr(vscode, "load_json_or_fail_closed", racing_load)

    applied = vscode.apply(ENV, home, confirmed=True, platform="darwin")

    assert calls["n"] >= 3
    assert applied.status is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    assert "changed state" in applied.summary
    # The raced content was never merged into the file on disk.
    assert read_json(target) == safe
    assert not list(user_dir(home).glob("*.bak*"))


def test_confirmed_false_refuses_to_write(tmp_path: Path) -> None:
    home = tmp_path / "home"
    make_installed(home)

    applied = vscode.apply(ENV, home, confirmed=False, platform="darwin")
    assert applied.status is AgentStatus.INSTALLED_UNCONFIGURED
    assert "not applied" in applied.summary
    assert not (user_dir(home) / "mcp.json").exists()

    # Also refuses when a config already exists and would be modified.
    target = user_dir(home) / "mcp.json"
    target.write_text(
        json.dumps({"servers": {"other-server": {"command": "foo"}}}),
        encoding="utf-8",
    )
    before = target.read_text(encoding="utf-8")

    applied2 = vscode.apply(ENV, home, confirmed=False, platform="darwin")
    assert applied2.status is AgentStatus.INSTALLED_UNCONFIGURED
    assert "not applied" in applied2.summary
    assert target.read_text(encoding="utf-8") == before
    assert not list(user_dir(home).glob("*.bak*"))


def test_workspace_target_written_alongside_user_profile(tmp_path: Path) -> None:
    home = tmp_path / "home"
    make_installed(home)
    workspace = tmp_path / "project"
    (workspace / ".vscode").mkdir(parents=True)
    ws_target = workspace / ".vscode" / "mcp.json"
    ws_target.write_text(
        json.dumps({"servers": {"other-server": {"command": "foo"}}}),
        encoding="utf-8",
    )
    planned = vscode.plan(ENV, home, platform="darwin", workspace=workspace)
    assert planned.status is AgentStatus.INSTALLED_UNCONFIGURED
    # Both targets are described in the plan: the summary names each file and
    # the config block shows the exact JSON per target.
    assert str(ws_target) in planned.summary
    assert str(planned.config_path) in planned.summary
    assert planned.config_block.count('"universal-db"') == 2
    assert vscode.workspace_config_path(workspace) in planned.config_paths

    applied = vscode.apply(ENV, home, confirmed=True, platform="darwin", workspace=workspace)
    assert applied.status is AgentStatus.CONFIGURED

    assert read_json(user_dir(home) / "mcp.json") == {"servers": {"universal-db": EXPECTED_ENTRY}}
    ws_data = read_json(ws_target)
    assert ws_data["servers"]["universal-db"] == EXPECTED_ENTRY
    assert ws_data["servers"]["other-server"] == {"command": "foo"}
    # Both writes were preceded by a timestamped backup of the existing file.
    assert len(list((workspace / ".vscode").glob("*.bak*"))) == 1


def test_workspace_without_vscode_dir_is_skipped(tmp_path: Path) -> None:
    home = tmp_path / "home"
    make_installed(home)
    workspace = tmp_path / "project"
    workspace.mkdir()

    planned = vscode.plan(ENV, home, platform="darwin", workspace=workspace)
    assert planned.status is AgentStatus.INSTALLED_UNCONFIGURED
    assert "skipped" in planned.summary

    applied = vscode.apply(ENV, home, confirmed=True, platform="darwin", workspace=workspace)
    assert applied.status is AgentStatus.CONFIGURED
    # The user profile was written; no .vscode directory was created.
    assert read_json(user_dir(home) / "mcp.json") == {"servers": {"universal-db": EXPECTED_ENTRY}}
    assert not (workspace / ".vscode").exists()


def test_workspace_malformed_fails_closed_and_writes_nothing(tmp_path: Path) -> None:
    home = tmp_path / "home"
    make_installed(home)
    workspace = tmp_path / "project"
    (workspace / ".vscode").mkdir(parents=True)
    ws_target = workspace / ".vscode" / "mcp.json"
    bad_content = "{not json"
    ws_target.write_text(bad_content, encoding="utf-8")

    planned = vscode.plan(ENV, home, platform="darwin", workspace=workspace)
    assert planned.status is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED

    applied = vscode.apply(ENV, home, confirmed=True, platform="darwin", workspace=workspace)
    assert applied.status is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    # The malformed workspace file is reported, never overwritten...
    assert ws_target.read_text(encoding="utf-8") == bad_content
    # ...and because one target failed closed, nothing was written anywhere.
    assert not (user_dir(home) / "mcp.json").exists()
    assert not list(user_dir(home).glob("*.bak*"))
    assert not list((workspace / ".vscode").glob("*.bak*"))


def test_workspace_confirmed_false_writes_nothing(tmp_path: Path) -> None:
    home = tmp_path / "home"
    make_installed(home)
    workspace = tmp_path / "project"
    (workspace / ".vscode").mkdir(parents=True)

    applied = vscode.apply(ENV, home, confirmed=False, platform="darwin", workspace=workspace)
    assert applied.status is AgentStatus.INSTALLED_UNCONFIGURED
    assert "not applied" in applied.summary
    assert not (user_dir(home) / "mcp.json").exists()
    assert not (workspace / ".vscode" / "mcp.json").exists()


def test_registration_entry_resolves_venv_python_and_config(tmp_path: Path) -> None:
    entry = vscode.registration_entry(ENV, tmp_path)
    assert entry == EXPECTED_ENTRY

    # Without UDBMCP_CONFIG in env, falls back to the canonical system path
    # or a per-user default rather than launching without a config.
    entry_no_cfg = vscode.registration_entry({"UDBMCP_VENV_PYTHON": "/x/py"}, tmp_path)
    assert entry_no_cfg["env"]["UDBMCP_CONFIG"].endswith("config.yaml")
    # Without either override the interpreter is the one running this process.
    entry_no_env = vscode.registration_entry({}, tmp_path)
    assert entry_no_env["command"] == sys.executable
