"""Unit tests for the Cline agent-harness registration adapter.

All tests run against fake HOME trees under ``tmp_path``; nothing touches the
real user profile. Detection for the Cline adapter is defined as the
``cline_mcp_settings.json`` path existing, so fixtures build that path via
the adapter's own ``settings_path`` helper.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from universal_db_mcp.agents import cline
from universal_db_mcp.agents.core import AgentStatus

CONFIG_PATH_NAME = "config.yaml"


def _env(tmp_path: Path) -> dict[str, str]:
    # Explicit UDBMCP_CONFIG keeps config resolution deterministic regardless
    # of whether the canonical system path exists on the test machine.
    return {
        "UDBMCP_CONFIG": str(tmp_path / "udb" / CONFIG_PATH_NAME),
        "UDBMCP_VENV_PYTHON": "/opt/universal-db-mcp/venv/bin/python",
    }


def _write_settings(home: Path, payload: dict[str, Any] | str) -> Path:
    target = cline.settings_path(home)
    target.parent.mkdir(parents=True, exist_ok=True)
    raw = payload if isinstance(payload, str) else json.dumps(payload, indent=2)
    target.write_text(raw, encoding="utf-8")
    return target


def _read_settings(home: Path) -> dict[str, Any]:
    return json.loads(cline.settings_path(home).read_text(encoding="utf-8"))


def _backups(home: Path) -> list[Path]:
    target = cline.settings_path(home)
    return sorted(target.parent.glob(target.name + ".bak.*"))


def _expected_entry(env: dict[str, str], home: Path) -> dict[str, Any]:
    return {
        "command": env["UDBMCP_VENV_PYTHON"],
        "args": ["-I", "-m", "universal_db_mcp", "serve", "--transport", "stdio"],
        "env": {"UDBMCP_CONFIG": env["UDBMCP_CONFIG"]},
        "disabled": False,
        "autoApprove": [],
    }


def test_not_installed(tmp_path: Path) -> None:
    env = _env(tmp_path)
    home = tmp_path / "home"
    home.mkdir()

    assert cline.detect(env, home) is AgentStatus.NOT_INSTALLED

    planned = cline.plan(env, home)
    assert planned.status is AgentStatus.NOT_INSTALLED
    assert planned.summary
    assert planned.config_block == ""

    applied = cline.apply(env, home, confirmed=True)
    assert applied.status is AgentStatus.NOT_INSTALLED
    assert not cline.settings_path(home).exists()
    assert _backups(home) == []


def test_installed_unconfigured_plan_describes_exact_addition(tmp_path: Path) -> None:
    env = _env(tmp_path)
    home = tmp_path / "home"
    existing = {"mcpServers": {"other-server": {"command": "/bin/echo", "args": ["hi"]}}}
    _write_settings(home, existing)

    assert cline.detect(env, home) is AgentStatus.INSTALLED_UNCONFIGURED

    planned = cline.plan(env, home)
    assert planned.status is AgentStatus.INSTALLED_UNCONFIGURED
    assert planned.config_path == cline.settings_path(home)
    # The plan prints the exact JSON that would land under mcpServers.
    printed = json.loads(planned.config_block)
    assert printed == {"mcpServers": {"universal-db": _expected_entry(env, home)}}
    assert planned.entry == _expected_entry(env, home)
    assert ".bak" in planned.summary
    # Plans never write.
    assert _read_settings(home) == existing
    assert _backups(home) == []


def test_apply_refuses_without_confirmation(tmp_path: Path) -> None:
    env = _env(tmp_path)
    home = tmp_path / "home"
    existing = {"mcpServers": {}}
    target = _write_settings(home, existing)

    applied = cline.apply(env, home, confirmed=False)
    assert applied.status is AgentStatus.INSTALLED_UNCONFIGURED
    assert "confirmation refused" in applied.summary
    # File bytes untouched, no backup created.
    assert _read_settings(home) == existing
    assert _backups(home) == []
    assert json.loads(target.read_text(encoding="utf-8")) == existing


def test_apply_writes_shape_and_backup(tmp_path: Path) -> None:
    env = _env(tmp_path)
    home = tmp_path / "home"
    existing = {"mcpServers": {"other-server": {"command": "/bin/echo", "args": ["hi"]}}}
    target = _write_settings(home, existing)
    original_bytes = target.read_bytes()

    applied = cline.apply(env, home, confirmed=True)
    assert applied.status is AgentStatus.CONFIGURED

    # A timestamped .bak of the original file exists and holds the original bytes.
    backups = _backups(home)
    assert len(backups) == 1
    assert backups[0].name.startswith(cline.SETTINGS_FILENAME + ".bak.")
    assert backups[0].read_bytes() == original_bytes

    # The written file parses and has the exact expected shape.
    written = _read_settings(home)
    assert written["mcpServers"]["universal-db"] == _expected_entry(env, home)
    # Other registrations are preserved.
    assert written["mcpServers"]["other-server"] == existing["mcpServers"]["other-server"]
    # Nothing was added beyond the one server key.
    assert set(written["mcpServers"]) == {"other-server", "universal-db"}


def test_apply_is_idempotent(tmp_path: Path) -> None:
    env = _env(tmp_path)
    home = tmp_path / "home"
    _write_settings(home, {"mcpServers": {}})

    first = cline.apply(env, home, confirmed=True)
    assert first.status is AgentStatus.CONFIGURED
    after_first = cline.settings_path(home).read_bytes()

    second = cline.apply(env, home, confirmed=True)
    assert second.status is AgentStatus.CONFIGURED
    # No duplicate registration, no extra backup, no rewrite.
    assert "already configured" in second.summary
    assert cline.settings_path(home).read_bytes() == after_first
    assert len(_backups(home)) == 1
    assert _read_settings(home)["mcpServers"]["universal-db"] == _expected_entry(env, home)


def test_detect_configured_after_apply(tmp_path: Path) -> None:
    env = _env(tmp_path)
    home = tmp_path / "home"
    _write_settings(home, {"mcpServers": {}})
    assert cline.detect(env, home) is AgentStatus.INSTALLED_UNCONFIGURED
    cline.apply(env, home, confirmed=True)
    assert cline.detect(env, home) is AgentStatus.CONFIGURED


def test_malformed_config_fails_closed(tmp_path: Path) -> None:
    env = _env(tmp_path)
    home = tmp_path / "home"
    target = _write_settings(home, "{ this is not json }}}")

    assert cline.detect(env, home) is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED

    planned = cline.plan(env, home)
    assert planned.status is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    # The intended config block is printed for the operator (never written).
    assert "universal-db" in planned.config_block
    assert "{ this is not json }}}" in planned.config_block

    applied = cline.apply(env, home, confirmed=True)
    assert applied.status is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    # No write, no backup: the malformed file is left exactly as it was.
    assert target.read_text(encoding="utf-8") == "{ this is not json }}}"
    assert _backups(home) == []


def test_differing_existing_entry_fails_closed(tmp_path: Path) -> None:
    env = _env(tmp_path)
    home = tmp_path / "home"
    conflicting = {
        "mcpServers": {
            "universal-db": {"command": "/usr/bin/something-else", "args": ["serve"]},
        }
    }
    target = _write_settings(home, conflicting)

    assert cline.detect(env, home) is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    applied = cline.apply(env, home, confirmed=True)
    assert applied.status is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    assert _read_settings(home) == conflicting
    assert _backups(home) == []
    assert target.is_file()


def test_mcp_servers_not_an_object_fails_closed(tmp_path: Path) -> None:
    env = _env(tmp_path)
    home = tmp_path / "home"
    target = _write_settings(home, {"mcpServers": ["not", "an", "object"]})

    assert cline.detect(env, home) is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    cline.apply(env, home, confirmed=True)
    assert json.loads(target.read_text(encoding="utf-8")) == {"mcpServers": ["not", "an", "object"]}
    assert _backups(home) == []


def test_written_registration_contains_no_secrets(tmp_path: Path) -> None:
    env = _env(tmp_path)
    home = tmp_path / "home"
    _write_settings(home, {"mcpServers": {}})
    cline.apply(env, home, confirmed=True)

    entry = _read_settings(home)["mcpServers"]["universal-db"]
    assert set(entry) <= {"command", "args", "env", "disabled", "autoApprove"}
    assert set(entry["env"]) == {"UDBMCP_CONFIG"}
    serialized = json.dumps(entry)
    for secretish in ("token", "password", "secret", "credential", "api_key", "apikey"):
        assert secretish not in serialized.lower()


def test_null_mcp_servers_plan_and_apply_agree(tmp_path: Path) -> None:
    # A JSON-null mcpServers is classified as "absent" by detect(); apply must
    # agree with plan() and actually create the key (no plan/apply divergence).
    env = _env(tmp_path)
    home = tmp_path / "home"
    target = _write_settings(home, {"mcpServers": None})

    assert cline.detect(env, home) is AgentStatus.INSTALLED_UNCONFIGURED

    planned = cline.plan(env, home)
    assert planned.status is AgentStatus.INSTALLED_UNCONFIGURED

    applied = cline.apply(env, home, confirmed=True)
    assert applied.status is AgentStatus.CONFIGURED
    written = _read_settings(home)
    assert written["mcpServers"]["universal-db"] == _expected_entry(env, home)
    assert len(_backups(home)) == 1
    assert target.is_file()


def test_concurrent_differing_entry_at_write_time_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A differing universal-db entry landing on disk between detect() and
    # apply()'s write-time re-read is operator state: apply must fail closed,
    # never overwrite it (a .bak existing would not make the clobber safe).
    env = _env(tmp_path)
    home = tmp_path / "home"
    conflicting = {
        "mcpServers": {
            "universal-db": {"command": "/usr/bin/operator-controlled", "args": ["serve"]},
        }
    }
    target = _write_settings(home, conflicting)
    original_bytes = target.read_bytes()

    # Simulate the race: detect() saw INSTALLED_UNCONFIGURED on its first call,
    # then the operator's differing entry landed before apply()'s write-time
    # re-read (so every later detect() sees the conflicting state).
    real_detect = cline.detect
    calls = {"n": 0}

    def _racy_detect(env: dict[str, str], home: Path) -> AgentStatus:
        calls["n"] += 1
        if calls["n"] == 1:
            return AgentStatus.INSTALLED_UNCONFIGURED
        return real_detect(env, home)

    monkeypatch.setattr(cline, "detect", _racy_detect)

    applied = cline.apply(env, home, confirmed=True)
    assert applied.status is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    assert target.read_bytes() == original_bytes
    assert _backups(home) == []


def test_concurrent_equal_entry_at_write_time_is_idempotent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Same race, but the entry that landed is equivalent: apply is a no-op.
    env = _env(tmp_path)
    home = tmp_path / "home"
    _write_settings(home, {"mcpServers": {"universal-db": _expected_entry(env, home)}})

    real_detect = cline.detect
    calls = {"n": 0}

    def _racy_detect(env: dict[str, str], home: Path) -> AgentStatus:
        calls["n"] += 1
        if calls["n"] == 1:
            return AgentStatus.INSTALLED_UNCONFIGURED
        return real_detect(env, home)

    monkeypatch.setattr(cline, "detect", _racy_detect)

    applied = cline.apply(env, home, confirmed=True)
    assert applied.status is AgentStatus.CONFIGURED
    assert "already configured" in applied.summary
    assert _backups(home) == []
    assert _read_settings(home)["mcpServers"]["universal-db"] == _expected_entry(env, home)


def test_config_path_resolution_prefers_env(tmp_path: Path) -> None:
    home = tmp_path / "home"
    explicit = tmp_path / "explicit" / CONFIG_PATH_NAME
    with_env = cline.registration_entry({"UDBMCP_CONFIG": str(explicit)}, home)
    assert with_env["env"]["UDBMCP_CONFIG"] == str(explicit)

    # Without UDBMCP_CONFIG (and with the canonical system path absent in the
    # test environment), the per-user default is used.
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(cline, "SYSTEM_CONFIG_PATH", tmp_path / "nonexistent" / CONFIG_PATH_NAME)
        fallback = cline.registration_entry({}, home)
    assert fallback["env"]["UDBMCP_CONFIG"] == str(home / ".universal-db-mcp" / CONFIG_PATH_NAME)
