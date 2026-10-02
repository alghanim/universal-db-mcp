"""Unit tests for the Claude Desktop agent-harness adapter.

All tests run against fake HOME trees under tmp_path; nothing touches the
real Claude Desktop config. SYSTEM_APP_PATHS is neutralized via an autouse
fixture so detection never depends on the machine running the tests.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Any

import pytest

from universal_db_mcp.agents import claude_desktop
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

MAC_DIR = "Library/Application Support/Claude"
LINUX_DIR = ".config/Claude"


@pytest.fixture(autouse=True)
def _hermetic_app_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    """Never let a real /Applications/Claude.app influence these tests."""
    monkeypatch.setattr(claude_desktop, "SYSTEM_APP_PATHS", ())


@pytest.fixture
def darwin(monkeypatch: pytest.MonkeyPatch) -> None:
    """Run as on macOS, whatever OS runs the suite: the adapter picks the
    canonical config directory (and the ~/Applications probe) from
    ``sys.platform``, and CI runs on Linux."""
    monkeypatch.setattr(sys, "platform", "darwin")


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def make_config_dir(home: Path, rel: str = MAC_DIR) -> Path:
    d = home / rel
    d.mkdir(parents=True, exist_ok=True)
    return d


def config_file(home: Path, rel: str = MAC_DIR) -> Path:
    return home / rel / "claude_desktop_config.json"


# ---------------------------------------------------------------------------
# Platform path selection
# ---------------------------------------------------------------------------


def test_macos_path_is_canonical_default_on_darwin(tmp_path: Path, darwin: None) -> None:
    home = tmp_path / "home"
    home.mkdir()
    assert claude_desktop.config_path(ENV, home) == home / MAC_DIR / "claude_desktop_config.json"


def test_windows_appdata_env_selects_config_dir(tmp_path: Path) -> None:
    home = tmp_path / "home"
    appdata = tmp_path / "AppData" / "Roaming"
    target = appdata / "Claude" / "claude_desktop_config.json"
    target.parent.mkdir(parents=True)
    target.write_text("{}", encoding="utf-8")

    env = dict(ENV, APPDATA=str(appdata))
    assert claude_desktop.config_path(env, home) == target


def test_linux_dir_is_detected_when_present(tmp_path: Path) -> None:
    home = tmp_path / "home"
    target = config_file(home, LINUX_DIR)
    target.parent.mkdir(parents=True)
    target.write_text("{}", encoding="utf-8")

    assert claude_desktop.config_path(ENV, home) == target


def test_existing_config_file_wins_over_canonical_dir(tmp_path: Path) -> None:
    home = tmp_path / "home"
    make_config_dir(home, MAC_DIR)
    target = config_file(home, LINUX_DIR)
    target.parent.mkdir(parents=True)
    target.write_text("{}", encoding="utf-8")

    assert claude_desktop.config_path(ENV, home) == target


# ---------------------------------------------------------------------------
# Detection states
# ---------------------------------------------------------------------------


def test_not_installed_when_no_config_dir_and_no_app(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()

    assert claude_desktop.detect(ENV, home) is AgentStatus.NOT_INSTALLED

    planned = claude_desktop.plan(ENV, home)
    assert planned.status is AgentStatus.NOT_INSTALLED
    assert "nothing would be written" in planned.summary

    applied = claude_desktop.apply(ENV, home, confirmed=True)
    assert applied.status is AgentStatus.NOT_INSTALLED
    assert not (home / "Library").exists()


def test_installed_via_app_bundle_without_config_dir(tmp_path: Path, darwin: None) -> None:
    home = tmp_path / "home"
    (home / "Applications" / "Claude.app").mkdir(parents=True)

    assert claude_desktop.detect(ENV, home) is AgentStatus.INSTALLED_UNCONFIGURED


def test_installed_unconfigured_when_dir_exists_without_config(tmp_path: Path) -> None:
    home = tmp_path / "home"
    make_config_dir(home)

    assert claude_desktop.detect(ENV, home) is AgentStatus.INSTALLED_UNCONFIGURED


def test_installed_unconfigured_when_config_lacks_our_entry(tmp_path: Path) -> None:
    home = tmp_path / "home"
    target = config_file(home)
    target.parent.mkdir(parents=True)
    target.write_text(
        json.dumps({"mcpServers": {"other-server": {"command": "foo"}}, "globalShortcut": "Ctrl+Space"}),
        encoding="utf-8",
    )

    assert claude_desktop.detect(ENV, home) is AgentStatus.INSTALLED_UNCONFIGURED

    planned = claude_desktop.plan(ENV, home)
    assert planned.status is AgentStatus.INSTALLED_UNCONFIGURED
    # Exact bytes/keys that would be added are described in the plan.
    assert json.loads(planned.config_block) == {"mcpServers": {"universal-db": EXPECTED_ENTRY}}
    assert planned.entry == EXPECTED_ENTRY


def test_configured_when_equivalent_registration_present(tmp_path: Path) -> None:
    home = tmp_path / "home"
    target = config_file(home)
    target.parent.mkdir(parents=True)
    target.write_text(json.dumps({"mcpServers": {"universal-db": EXPECTED_ENTRY}}), encoding="utf-8")

    assert claude_desktop.detect(ENV, home) is AgentStatus.CONFIGURED

    planned = claude_desktop.plan(ENV, home)
    assert planned.status is AgentStatus.CONFIGURED


def test_differing_existing_registration_fails_closed(tmp_path: Path) -> None:
    home = tmp_path / "home"
    target = config_file(home)
    target.parent.mkdir(parents=True)
    target.write_text(
        json.dumps({"mcpServers": {"universal-db": {"command": "/usr/local/bin/python", "args": []}}}),
        encoding="utf-8",
    )

    assert claude_desktop.detect(ENV, home) is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED

    planned = claude_desktop.plan(ENV, home)
    assert planned.status is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    # The plan prints the offending file's contents for the operator.
    assert "universal-db" in planned.config_block

    applied = claude_desktop.apply(ENV, home, confirmed=True)
    assert applied.status is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    # Never silently rewritten.
    assert read_json(target) == {"mcpServers": {"universal-db": {"command": "/usr/local/bin/python", "args": []}}}
    assert not list(target.parent.glob("*.bak.*"))


# ---------------------------------------------------------------------------
# Apply: writes, backups, idempotency
# ---------------------------------------------------------------------------


def test_apply_writes_correct_shape_and_backup(tmp_path: Path) -> None:
    home = tmp_path / "home"
    target = config_file(home)
    target.parent.mkdir(parents=True)
    target.write_text(
        json.dumps({"mcpServers": {"other-server": {"command": "foo"}}, "globalShortcut": "Ctrl+Space"}),
        encoding="utf-8",
    )
    before = target.read_text(encoding="utf-8")

    applied = claude_desktop.apply(ENV, home, confirmed=True)

    assert applied.status is AgentStatus.CONFIGURED
    backups = list(target.parent.glob("*.bak.*"))
    assert len(backups) == 1
    # The backup preserves the pre-write bytes exactly.
    assert backups[0].read_text(encoding="utf-8") == before
    # Timestamped .bak sibling (core.backup_path format: <name>.bak.<UTC stamp>Z).
    assert re.search(r"\.bak\.\d{8}T\d{12}Z$", backups[0].name)

    data = read_json(target)
    assert data["mcpServers"]["universal-db"] == EXPECTED_ENTRY
    # Pre-existing unrelated registrations and settings are preserved.
    assert data["mcpServers"]["other-server"] == {"command": "foo"}
    assert data["globalShortcut"] == "Ctrl+Space"
    # No secrets: only the launch command and the UDBMCP_CONFIG path.
    assert set(data["mcpServers"]["universal-db"]["env"]) == {"UDBMCP_CONFIG"}
    assert data["mcpServers"]["universal-db"]["args"] == [
        "-I",
        "-m",
        "universal_db_mcp",
        "serve",
        "--transport",
        "stdio",
    ]


def test_apply_creates_file_when_config_absent(tmp_path: Path, darwin: None) -> None:
    home = tmp_path / "home"
    make_config_dir(home)

    applied = claude_desktop.apply(ENV, home, confirmed=True)

    assert applied.status is AgentStatus.CONFIGURED
    target = config_file(home)
    assert read_json(target) == {"mcpServers": {"universal-db": EXPECTED_ENTRY}}
    # Nothing to back up on first creation.
    assert not list(target.parent.glob("*.bak.*"))


def test_apply_adds_mcp_servers_key_when_missing(tmp_path: Path) -> None:
    home = tmp_path / "home"
    target = config_file(home)
    target.parent.mkdir(parents=True)
    target.write_text(json.dumps({"globalShortcut": "Ctrl+Space"}), encoding="utf-8")
    before = target.read_text(encoding="utf-8")

    applied = claude_desktop.apply(ENV, home, confirmed=True)

    assert applied.status is AgentStatus.CONFIGURED
    data = read_json(target)
    assert data["mcpServers"]["universal-db"] == EXPECTED_ENTRY
    assert data["globalShortcut"] == "Ctrl+Space"
    # The original settings were backed up before the first write.
    backups = list(target.parent.glob("*.bak.*"))
    assert len(backups) == 1
    assert backups[0].read_text(encoding="utf-8") == before


def test_apply_is_idempotent_on_second_run(tmp_path: Path, darwin: None) -> None:
    home = tmp_path / "home"
    make_config_dir(home)

    first = claude_desktop.apply(ENV, home, confirmed=True)
    assert first.status is AgentStatus.CONFIGURED
    after_first = config_file(home).read_text(encoding="utf-8")
    assert len(list(config_file(home).parent.glob("*.bak.*"))) == 0  # fresh file: no backup

    second = claude_desktop.apply(ENV, home, confirmed=True)
    assert second.status is AgentStatus.CONFIGURED
    assert config_file(home).read_text(encoding="utf-8") == after_first
    # No additional backups were created by the no-op run.
    assert not list(config_file(home).parent.glob("*.bak.*"))


def test_apply_is_idempotent_when_registration_preexists(tmp_path: Path) -> None:
    home = tmp_path / "home"
    target = config_file(home)
    target.parent.mkdir(parents=True)
    original = json.dumps({"mcpServers": {"universal-db": EXPECTED_ENTRY}}, indent=2)
    target.write_text(original, encoding="utf-8")

    applied = claude_desktop.apply(ENV, home, confirmed=True)

    assert applied.status is AgentStatus.CONFIGURED
    assert target.read_text(encoding="utf-8") == original
    assert not list(target.parent.glob("*.bak.*"))


# ---------------------------------------------------------------------------
# Fail-closed: malformed configs are reported, never overwritten
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad_content", ['{"mcpServers": {', "[1, 2, 3]", "null", '"just a string"'])
def test_malformed_config_fails_closed_without_write(tmp_path: Path, bad_content: str) -> None:
    home = tmp_path / "home"
    target = config_file(home)
    target.parent.mkdir(parents=True)
    target.write_text(bad_content, encoding="utf-8")

    assert claude_desktop.detect(ENV, home) is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED

    planned = claude_desktop.plan(ENV, home)
    assert planned.status is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    # The plan describes the offending file, never prints it (other servers' secrets).
    assert "its contents are not shown" in planned.config_block
    assert "refusing to write" in planned.summary

    applied = claude_desktop.apply(ENV, home, confirmed=True)
    assert applied.status is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    # Never silently overwritten.
    assert target.read_text(encoding="utf-8") == bad_content
    assert not list(target.parent.glob("*.bak.*"))


def test_non_object_mcp_servers_fails_closed(tmp_path: Path) -> None:
    home = tmp_path / "home"
    target = config_file(home)
    target.parent.mkdir(parents=True)
    bad = json.dumps({"mcpServers": ["not", "an", "object"]})
    target.write_text(bad, encoding="utf-8")

    assert claude_desktop.detect(ENV, home) is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED

    applied = claude_desktop.apply(ENV, home, confirmed=True)
    assert applied.status is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    assert target.read_text(encoding="utf-8") == bad


def test_null_mcp_servers_fails_closed(tmp_path: Path) -> None:
    """An explicit JSON null is a non-object mcpServers: fail closed, never rewrite."""
    home = tmp_path / "home"
    target = config_file(home)
    target.parent.mkdir(parents=True)
    bad = json.dumps({"mcpServers": None, "globalShortcut": "Ctrl+Space"})
    target.write_text(bad, encoding="utf-8")

    assert claude_desktop.detect(ENV, home) is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED

    planned = claude_desktop.plan(ENV, home)
    assert planned.status is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    assert "is not an object" in planned.config_block and "Ctrl+Space" not in planned.config_block
    assert "refusing to write" in planned.summary

    applied = claude_desktop.apply(ENV, home, confirmed=True)
    assert applied.status is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    # Never silently overwritten.
    assert target.read_text(encoding="utf-8") == bad
    assert not list(target.parent.glob("*.bak.*"))


@pytest.mark.skipif(sys.platform != "win32" and os.geteuid() == 0, reason="root may read any file")
def test_unreadable_config_fails_closed(tmp_path: Path) -> None:
    home = tmp_path / "home"
    target = config_file(home)
    target.parent.mkdir(parents=True)
    target.write_text("{}", encoding="utf-8")
    target.chmod(0o000)
    try:
        assert claude_desktop.detect(ENV, home) is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    finally:
        target.chmod(0o644)


# ---------------------------------------------------------------------------
# Confirmation gate
# ---------------------------------------------------------------------------


def test_confirmed_false_refuses_to_write(tmp_path: Path) -> None:
    home = tmp_path / "home"
    make_config_dir(home)

    applied = claude_desktop.apply(ENV, home, confirmed=False)
    assert applied.status is AgentStatus.INSTALLED_UNCONFIGURED
    assert "not applied" in applied.summary
    assert not config_file(home).exists()

    # Also refuses when a config already exists and would be modified.
    target = config_file(home)
    target.write_text(json.dumps({"mcpServers": {"other-server": {"command": "foo"}}}), encoding="utf-8")
    before = target.read_text(encoding="utf-8")

    applied2 = claude_desktop.apply(ENV, home, confirmed=False)
    assert applied2.status is AgentStatus.INSTALLED_UNCONFIGURED
    assert target.read_text(encoding="utf-8") == before
    assert not list(target.parent.glob("*.bak.*"))


# ---------------------------------------------------------------------------
# Entry construction (no secrets, venv python resolution)
# ---------------------------------------------------------------------------


def test_registration_entry_resolves_venv_python_and_config(tmp_path: Path) -> None:
    assert claude_desktop.registration_entry(ENV, tmp_path) == EXPECTED_ENTRY

    # Without UDBMCP_CONFIG in env, falls back to the canonical system path
    # or a per-user default rather than launching without a config.
    entry_no_cfg = claude_desktop.registration_entry({"UDBMCP_VENV_PYTHON": "/x/py"}, tmp_path)
    assert entry_no_cfg["env"]["UDBMCP_CONFIG"].endswith("config.yaml")
