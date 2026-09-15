"""Per-user harness config resolution + seeding (agents.core).

The bug this locks in (seen live 2026-09-14): harness (stdio) spawns run as
the logged-in USER, but the adapters advertised the root-owned system config
(/etc/universal-db-mcp/config.yaml, 0640 root:_udbmcp) whenever it merely
EXISTED - so every harness server died right after connecting with
"Permission denied". The shared resolver must check READABILITY, not mere
existence, and the CLI must seed the per-user config (only-if-absent) when it
falls back to it.
"""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from universal_db_mcp.__main__ import main
from universal_db_mcp.agents import core as agents_core
from universal_db_mcp.agents.claude_desktop import registration_entry
from universal_db_mcp.config import load_config


@pytest.fixture(autouse=True)
def _isolate_system_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the resolver's system path at a sandbox path: the tests must not
    depend on whether THIS host happens to have (or can read) /etc's config."""
    system = tmp_path / "etc" / "universal-db-mcp" / "config.yaml"
    monkeypatch.setattr(agents_core, "SYSTEM_CONFIG_PATH", system)
    return system


def _fake_home(tmp_path: Path) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    return home


def test_env_override_wins_over_everything(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("UDBMCP_CONFIG", raising=False)
    env = {"UDBMCP_CONFIG": "/operator/chosen/config.yaml"}
    assert (
        agents_core.resolve_harness_config_path(env, _fake_home(tmp_path))
        == "/operator/chosen/config.yaml"
    )


def test_readable_system_config_is_advertised(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    system = tmp_path / "etc" / "universal-db-mcp" / "config.yaml"
    system.parent.mkdir(parents=True)
    system.write_text("application:\n  transport: stdio\n", encoding="utf-8")
    monkeypatch.delenv("UDBMCP_CONFIG", raising=False)
    assert agents_core.resolve_harness_config_path({}, _fake_home(tmp_path)) == str(system)


def test_unreadable_system_config_falls_back_to_per_user(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    system = tmp_path / "etc" / "universal-db-mcp" / "config.yaml"
    system.parent.mkdir(parents=True)
    system.write_text("application:\n  transport: stdio\n", encoding="utf-8")
    system.chmod(0o000)  # exists but NOT readable by this user (non-root)
    monkeypatch.delenv("UDBMCP_CONFIG", raising=False)
    home = _fake_home(tmp_path)
    assert (
        agents_core.resolve_harness_config_path({}, home)
        == str(home / ".universal-db-mcp" / "config.yaml")
    )


def test_nonexistent_system_config_falls_back_to_per_user(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("UDBMCP_CONFIG", raising=False)
    home = _fake_home(tmp_path)
    assert (
        agents_core.resolve_harness_config_path({}, home)
        == str(home / ".universal-db-mcp" / "config.yaml")
    )


def test_seeding_creates_private_valid_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("UDBMCP_CONFIG", raising=False)
    home = _fake_home(tmp_path)

    seeded, note = agents_core.ensure_per_user_harness_config({}, home)

    assert seeded is not None and seeded.is_file()
    assert "seeded" in note
    assert stat.S_IMODE(seeded.stat().st_mode) == 0o600
    assert stat.S_IMODE(seeded.parent.stat().st_mode) & 0o077 == 0, (
        "the per-user state dir must be private (no group/other bits)"
    )
    cfg = load_config(seeded)  # schema-valid: unknown fields would raise
    assert cfg.application.transport == "stdio"
    assert cfg.application.metadata_cache_path == str(home / ".universal-db-mcp" / "metadata.sqlite")
    assert cfg.application.audit_path == str(home / ".universal-db-mcp" / "audit.jsonl")


def test_seeding_is_only_if_absent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("UDBMCP_CONFIG", raising=False)
    home = _fake_home(tmp_path)
    agents_core.ensure_per_user_harness_config({}, home)
    config = home / ".universal-db-mcp" / "config.yaml"
    config.write_text("# admin's own per-user config\n", encoding="utf-8")

    seeded, note = agents_core.ensure_per_user_harness_config({}, home)

    assert seeded is None
    assert "already present" in note
    assert config.read_text(encoding="utf-8") == "# admin's own per-user config\n"


def test_seeding_skipped_when_system_config_readable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    system = tmp_path / "etc" / "universal-db-mcp" / "config.yaml"
    system.parent.mkdir(parents=True)
    system.write_text("application:\n  transport: stdio\n", encoding="utf-8")
    monkeypatch.delenv("UDBMCP_CONFIG", raising=False)

    seeded, note = agents_core.ensure_per_user_harness_config({}, _fake_home(tmp_path))

    assert seeded is None
    assert "no seeding" in note


def test_adapter_entry_advertises_per_user_config_when_system_unreadable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("UDBMCP_CONFIG", raising=False)
    home = _fake_home(tmp_path)

    entry = registration_entry({}, home)

    advertised = entry["env"]["UDBMCP_CONFIG"]
    assert advertised == str(home / ".universal-db-mcp" / "config.yaml")
    assert "etc/universal-db-mcp" not in advertised


def test_json_apply_reports_seeded_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    (fake_home / ".claude").mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("PATH", "")
    monkeypatch.setattr(
        agents_core, "SYSTEM_CONFIG_PATH", tmp_path / "no-such-etc" / "config.yaml"
    )

    rc = main(["configure-agents", "--json", "--agent", "claude-code", "--yes"])
    data = json.loads(capsys.readouterr().out)

    assert rc == 0
    applied = data["applied"][0]  # type: ignore[index]
    seeded = applied["config_seeded"]  # type: ignore[index]
    assert seeded is not None and seeded == str(fake_home / ".universal-db-mcp" / "config.yaml")
    assert Path(seeded).is_file()
    # the harness entry must advertise the SEEDED (readable) config
    harness_cfg = json.loads((fake_home / ".claude.json").read_text(encoding="utf-8"))
    assert (
        harness_cfg["mcpServers"]["universal-db"]["env"]["UDBMCP_CONFIG"]
        == str(fake_home / ".universal-db-mcp" / "config.yaml")
    )


def test_bare_doctor_resolves_the_per_user_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """`udbmcp doctor` with NO --config and NO UDBMCP_CONFIG must resolve the
    same per-user default as the wizard/configure-agents - failing with
    'no config path' while a valid per-user config exists made the doctor
    useless exactly when the user needed it (seen live 2026-09-15)."""
    fake_home = tmp_path / "home"
    (fake_home / ".universal-db-mcp").mkdir(parents=True)
    (fake_home / ".universal-db-mcp" / "config.yaml").write_text(
        "application:\n  transport: stdio\n", encoding="utf-8"
    )
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.delenv("UDBMCP_CONFIG", raising=False)
    monkeypatch.setattr(
        agents_core, "SYSTEM_CONFIG_PATH", tmp_path / "no-such-etc" / "config.yaml"
    )

    rc = main(["doctor"])
    out = capsys.readouterr().out

    assert rc == 0, out
    assert "no config path" not in out
    report = json.loads(out)
    assert report["fatal_count"] == 0, report
