"""Unit tests for the dsh adapter (universal_db_mcp.agents.dsh).

All tests run against fake HOME trees under tmp_path; nothing touches the
real ~/.dsh. Environment-dependent values (venv python path, UDBMCP_CONFIG)
are monkeypatched to deterministic strings.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from universal_db_mcp.agents import dsh
from universal_db_mcp.agents.core import AgentStatus
from universal_db_mcp.agents.dsh import (
    REGISTRATION_ID,
    apply,
    detect,
    plan,
)

NOT_INSTALLED = AgentStatus.NOT_INSTALLED
INSTALLED_UNCONFIGURED = AgentStatus.INSTALLED_UNCONFIGURED
CONFIGURED = AgentStatus.CONFIGURED
UNKNOWN = AgentStatus.UNKNOWN_STATE_FAIL_CLOSED

FAKE_PYTHON = "/opt/universal-db-mcp/venv/bin/python"
FAKE_CONFIG = "/etc/universal-db-mcp/config.yaml"

ROW_SHAPE = {
    "insert": [
        {
            "id": REGISTRATION_ID,
            "name": "@deepseek-ai/dsh-mcp-client",
            "config": {
                "serverName": "udb",
                "transport": "stdio",
                "command": FAKE_PYTHON,
                "args": ["-m", "universal_db_mcp", "serve", "--transport", "stdio"],
                "env": {"UDBMCP_CONFIG": FAKE_CONFIG},
                "failOnStartupError": True,
            },
        }
    ]
}


def make_dsh_home(tmp_path: Path, *, with_patch: str | None = None) -> Path:
    """Build a minimal recognizable dsh home under tmp_path."""
    home = tmp_path / ".dsh"
    home.mkdir(parents=True, exist_ok=True)
    (home / "settings.yaml").write_text("ui-onboarding:\n  welcomeNoticeVersion: 1\n", encoding="utf-8")
    (home / "profiles").mkdir(exist_ok=True)
    if with_patch is not None:
        (home / "cordis.patch.yml").write_text(with_patch, encoding="utf-8")
    return home


def patch_resolvers(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(dsh, "_resolve_python", lambda: FAKE_PYTHON)
    monkeypatch.setattr(dsh, "_resolve_config_path", lambda: FAKE_CONFIG)
    monkeypatch.setattr(dsh, "_dsh_cli_on_path", lambda: False)


# ---------------------------------------------------------------------------
# detect()
# ---------------------------------------------------------------------------


def test_detect_not_installed_when_home_missing(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    patch_resolvers(monkeypatch)
    assert detect(tmp_path / ".dsh") == NOT_INSTALLED


def test_detect_installed_unconfigured_without_patch_file(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    patch_resolvers(monkeypatch)
    home = make_dsh_home(tmp_path)
    assert detect(home) == INSTALLED_UNCONFIGURED


def test_detect_recognizes_live_style_registration_as_configured(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    patch_resolvers(monkeypatch)
    existing = """\
# User patch layer: applies to every dsh profile on this machine.
- insert:
    - id: mcp-universal-db
      name: '@deepseek-ai/dsh-mcp-client'
      config:
        serverName: udb
        transport: stdio
        command: /old/venv/bin/python
        args: ['-m', 'universal_db_mcp', 'serve', '--transport', 'stdio']
        env:
          UDBMCP_CONFIG: /old/config.mockdbs.yaml
          UDBMCP_DEMO_PG_USER: udbmcp_ro
        failOnStartupError: true

# Disable the old dsh-plugin-database (superseded by the udb MCP server).
- id: database
  disabled: true
"""
    home = make_dsh_home(tmp_path, with_patch=existing)
    assert detect(home) == CONFIGURED


def test_detect_installed_unconfigured_when_patch_lacks_registration(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    patch_resolvers(monkeypatch)
    existing = "- insert:\n    - id: something-else\n      name: other\n"
    home = make_dsh_home(tmp_path, with_patch=existing)
    assert detect(home) == INSTALLED_UNCONFIGURED


def test_detect_malformed_patch_fails_closed(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    patch_resolvers(monkeypatch)
    home = make_dsh_home(tmp_path, with_patch="insert: [unclosed\n  {{{\n\t: : :\n")
    assert detect(home) == UNKNOWN


def test_detect_override_form_row_fails_closed(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    patch_resolvers(monkeypatch)
    # Plain "- id:" is an override (entry-not-found); must not be treated as
    # configured and must not receive a duplicate insert row.
    home = make_dsh_home(tmp_path, with_patch=f"- id: {REGISTRATION_ID}\n  disabled: true\n")
    assert detect(home) == UNKNOWN


def test_detect_unrecognized_nonempty_home_fails_closed(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    patch_resolvers(monkeypatch)
    home = tmp_path / ".dsh"
    home.mkdir()
    (home / "mystery-file.txt").write_text("???\n", encoding="utf-8")
    assert detect(home) == UNKNOWN


def test_detect_empty_home_without_dsh_cli_is_not_installed(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    patch_resolvers(monkeypatch)
    home = tmp_path / ".dsh"
    home.mkdir()
    assert detect(home) == NOT_INSTALLED


def test_detect_non_sequence_patch_fails_closed(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    patch_resolvers(monkeypatch)
    home = make_dsh_home(tmp_path, with_patch="just: a mapping\n")
    assert detect(home) == UNKNOWN


def test_detect_non_utf8_patch_fails_closed(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Invalid UTF-8 bytes must fail closed, not raise UnicodeDecodeError."""
    patch_resolvers(monkeypatch)
    home = make_dsh_home(tmp_path)
    broken = b"- insert:\n    - id: x\n\xff\xfe garbage \x00\n"
    (home / "cordis.patch.yml").write_bytes(broken)
    assert detect(home) == UNKNOWN


# ---------------------------------------------------------------------------
# plan()
# ---------------------------------------------------------------------------


def test_plan_describes_exact_bytes_for_fresh_file(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    patch_resolvers(monkeypatch)
    home = make_dsh_home(tmp_path)
    p = plan(home)
    assert p.status == INSTALLED_UNCONFIGURED
    assert "action=create-registration" in p.summary
    assert p.config_path == home / "cordis.patch.yml"
    assert "- insert:" in p.config_block
    assert f"    - id: {REGISTRATION_ID}" in p.config_block
    assert f"        command: {FAKE_PYTHON}" in p.config_block
    assert f"          UDBMCP_CONFIG: {FAKE_CONFIG}" in p.config_block
    assert "args: ['-m', 'universal_db_mcp', 'serve', '--transport', 'stdio']" in p.config_block
    assert p.config_block == dsh._registration_block()
    # logical entry matches the block and carries no secrets
    assert p.entry["id"] == REGISTRATION_ID
    assert p.entry["config"]["command"] == FAKE_PYTHON
    assert p.entry["config"]["env"] == {"UDBMCP_CONFIG": FAKE_CONFIG}


def test_plan_append_action_for_existing_file(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    patch_resolvers(monkeypatch)
    home = make_dsh_home(tmp_path, with_patch="- insert:\n    - id: other\n      name: x\n")
    p = plan(home)
    assert p.status == INSTALLED_UNCONFIGURED
    assert "action=append-registration" in p.summary
    assert ".bak." in p.summary  # backup announced before any write


def test_plan_for_configured_has_no_block(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    patch_resolvers(monkeypatch)
    existing = "- insert:\n    - id: mcp-universal-db\n      name: x\n"
    home = make_dsh_home(tmp_path, with_patch=existing)
    p = plan(home)
    assert p.status == CONFIGURED
    assert "action=none" in p.summary
    assert p.config_block == ""


def test_plan_for_malformed_includes_existing_block_and_no_write(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    patch_resolvers(monkeypatch)
    home = make_dsh_home(tmp_path, with_patch="{{{ not yaml\n")
    p = plan(home)
    assert p.status == UNKNOWN
    assert "action=none" in p.summary
    assert p.config_block == ""
    assert "FAIL CLOSED" in p.summary
    assert "{{{ not yaml" in p.summary  # existing config block surfaced for the operator


def test_plan_for_non_utf8_patch_reports_fail_closed_without_raising(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """The fail-closed report path itself must not raise on undecodable bytes."""
    patch_resolvers(monkeypatch)
    home = make_dsh_home(tmp_path)
    broken = b"- insert:\n    - id: x\n\xff\xfe garbage \x00\n"
    (home / "cordis.patch.yml").write_bytes(broken)
    p = plan(home)  # must not raise UnicodeDecodeError
    assert p.status == UNKNOWN
    assert "action=none" in p.summary
    assert "FAIL CLOSED" in p.summary
    assert p.config_block == ""
    assert (home / "cordis.patch.yml").read_bytes() == broken  # untouched


def test_plan_for_unreadable_patch_path_reports_fail_closed_without_raising(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """A cordis.patch.yml that is a directory fails closed in plan() too."""
    patch_resolvers(monkeypatch)
    home = make_dsh_home(tmp_path)
    (home / "cordis.patch.yml").mkdir()
    p = plan(home)  # must not raise IsADirectoryError
    assert p.status == UNKNOWN
    assert "action=none" in p.summary
    assert "FAIL CLOSED" in p.summary
    assert p.config_block == ""


# ---------------------------------------------------------------------------
# apply()
# ---------------------------------------------------------------------------


def test_apply_refuses_without_confirmation(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    patch_resolvers(monkeypatch)
    home = make_dsh_home(tmp_path)
    result = apply(home, confirmed=False)
    assert result.wrote is False
    assert not (home / "cordis.patch.yml").exists()
    assert not list(home.glob("*.bak.*"))


def test_apply_creates_file_with_correct_shape(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    patch_resolvers(monkeypatch)
    home = make_dsh_home(tmp_path)
    result = apply(home, confirmed=True)
    assert result.wrote is True
    assert result.backup_path is None  # nothing pre-existed to back up
    data = yaml.safe_load((home / "cordis.patch.yml").read_text(encoding="utf-8"))
    assert isinstance(data, list)
    assert ROW_SHAPE in data
    assert detect(home) == CONFIGURED


def test_apply_appends_preserves_rows_and_creates_bak(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    patch_resolvers(monkeypatch)
    existing = "# manual row\n- insert:\n    - id: other-server\n      name: x\n"
    home = make_dsh_home(tmp_path, with_patch=existing)
    result = apply(home, confirmed=True)
    assert result.wrote is True
    backup = result.backup_path
    assert backup is not None and backup.exists()
    assert backup.name.startswith("cordis.patch.yml.bak.")
    assert backup.read_text(encoding="utf-8") == existing  # exact pre-write bytes

    text = (home / "cordis.patch.yml").read_text(encoding="utf-8")
    assert text.startswith("# manual row")  # pre-existing rows/comments preserved
    data = yaml.safe_load(text)
    assert {"insert": [{"id": "other-server", "name": "x"}]} in data
    assert ROW_SHAPE in data
    assert text.count("- insert:") == 2  # no duplicate registration


def test_apply_is_idempotent(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    patch_resolvers(monkeypatch)
    home = make_dsh_home(tmp_path)
    first = apply(home, confirmed=True)
    after_first = (home / "cordis.patch.yml").read_text(encoding="utf-8")
    second = apply(home, confirmed=True)
    assert first.wrote is True
    assert second.wrote is False
    assert second.status_before == CONFIGURED
    assert second.backup_path is None  # no new backup on the no-op run
    assert (home / "cordis.patch.yml").read_text(encoding="utf-8") == after_first
    assert len(list(home.glob("cordis.patch.yml.bak.*"))) == 0  # fresh file: never had a backup


def test_apply_idempotent_with_existing_backup_only_one_bak(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    patch_resolvers(monkeypatch)
    home = make_dsh_home(tmp_path, with_patch="- insert:\n    - id: x\n      name: x\n")
    first = apply(home, confirmed=True)
    assert first.backup_path is not None
    after_first = (home / "cordis.patch.yml").read_text(encoding="utf-8")
    second = apply(home, confirmed=True)
    assert second.wrote is False
    baks = list(home.glob("cordis.patch.yml.bak.*"))
    assert len(baks) == 1
    assert (home / "cordis.patch.yml").read_text(encoding="utf-8") == after_first


def test_apply_malformed_patch_fails_closed_never_writes(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    patch_resolvers(monkeypatch)
    broken = "{{{ not yaml\n  - [\n"
    home = make_dsh_home(tmp_path, with_patch=broken)
    result = apply(home, confirmed=True)
    assert result.wrote is False
    assert result.status_before == UNKNOWN
    assert (home / "cordis.patch.yml").read_text(encoding="utf-8") == broken  # byte-for-byte untouched
    assert not list(home.glob("*.bak.*"))


def test_apply_non_utf8_patch_fails_closed_never_writes(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Undecodable patch bytes must fail closed, not raise UnicodeDecodeError."""
    patch_resolvers(monkeypatch)
    home = make_dsh_home(tmp_path)
    broken = b"- insert:\n    - id: x\n\xff\xfe garbage \x00\n"
    (home / "cordis.patch.yml").write_bytes(broken)
    result = apply(home, confirmed=True)  # must not raise
    assert result.wrote is False
    assert result.status_before == UNKNOWN
    assert "FAIL CLOSED" in result.message
    assert (home / "cordis.patch.yml").read_bytes() == broken  # byte-for-byte untouched
    assert not list(home.glob("*.bak.*"))


def test_apply_not_installed_writes_nothing(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    patch_resolvers(monkeypatch)
    home = tmp_path / ".dsh"
    result = apply(home, confirmed=True)
    assert result.wrote is False
    assert not home.exists()


def test_apply_written_config_contains_no_secret_like_keys(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    patch_resolvers(monkeypatch)
    home = make_dsh_home(tmp_path)
    apply(home, confirmed=True)
    text = (home / "cordis.patch.yml").read_text(encoding="utf-8")
    for forbidden in ("password", "secret", "token", "api_key", "apiKey", "Bearer"):
        assert forbidden not in text
