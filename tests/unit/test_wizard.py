"""``add-connection`` wizard: config merge, credential files, live test.

Invariants under test:
  * Secrets are referenced, never inlined: username/password become 0600
    files under <config dir>/secrets (0700); the config carries only the
    username_file/password_file pointers.
  * Merge preserves the comment header and every other key; a timestamped
    .bak precedes the write; a malformed config is refused UNTOUCHED.
  * The merged result passes load_config (schema fail-closed).
  * username_file resolution in ResolvedConnection (mutual-exclusion with
    username_env; empty file refused; unsafe perms refused).
  * The optional live test uses the server's connector machinery.
"""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from universal_db_mcp.__main__ import main
from universal_db_mcp.config import ResolvedConnection, load_config
from universal_db_mcp.errors import ConfigError
from universal_db_mcp.wizard import (
    WizardError,
    apply_connection,
    build_connection,
    ensure_config_exists,
    merge_connection,
    store_credentials,
)
from universal_db_mcp.wizard import test_connection as run_live_test

SEEDED = """\
# per-user config header comment (must survive the merge)
application:
  transport: stdio
  metadata_cache_path: {home}/.universal-db-mcp/metadata.sqlite
  audit_path: {home}/.universal-db-mcp/audit.jsonl

security:
  read_only: true
"""


@pytest.fixture
def user_config(tmp_path: Path) -> Path:
    home = tmp_path / "home"
    (home / ".universal-db-mcp").mkdir(parents=True)
    cfg = home / ".universal-db-mcp" / "config.yaml"
    cfg.write_text(SEEDED.format(home=home), encoding="utf-8")
    return cfg


def test_merge_adds_connection_and_preserves_header(user_config: Path, tmp_path: Path) -> None:
    conn = build_connection(
        name="demo_sqlite", engine="sqlite", database=str(tmp_path / "demo.db")
    )
    backup = merge_connection(user_config, "demo_sqlite", conn)

    text = user_config.read_text(encoding="utf-8")
    assert text.startswith("# per-user config header comment"), "header must survive"
    assert "demo_postgres" not in text
    merged = load_config(user_config)
    assert merged.connections["demo_sqlite"].type == "sqlite"
    assert merged.connections["demo_sqlite"].read_only is True
    assert backup.is_file() and "demo_sqlite" not in backup.read_text(encoding="utf-8")


def test_merge_replaces_one_connection_and_keeps_others(user_config: Path, tmp_path: Path) -> None:
    build = build_connection(name="a", engine="sqlite", database=str(tmp_path / "a.db"))
    merge_connection(user_config, "a", build)
    backup = merge_connection(
        user_config, "b", build_connection(name="b", engine="sqlite", database=str(tmp_path / "b.db"))
    )

    merged = load_config(user_config)
    assert set(merged.connections) == {"a", "b"}
    # replacing 'a' with different settings works and keeps 'b'
    merge_connection(user_config, "a", build_connection(name="a", engine="sqlite", database=str(tmp_path / "a2.db")))
    merged = load_config(user_config)
    assert merged.connections["a"].database == str(tmp_path / "a2.db")
    assert set(merged.connections) == {"a", "b"}
    assert backup.is_file()


def test_merge_refuses_malformed_config_untouched(tmp_path: Path) -> None:
    cfg = tmp_path / "broken.yaml"
    cfg.write_text("connections: [oops\n  bad yaml:::", encoding="utf-8")
    before = cfg.read_text(encoding="utf-8")

    with pytest.raises(WizardError, match="refusing to edit"):
        merge_connection(cfg, "x", build_connection(name="x", engine="sqlite", database=str(tmp_path / "x.db")))

    assert cfg.read_text(encoding="utf-8") == before, "a refused merge must not touch the file"
    assert not list(tmp_path.glob("*.bak.*"))


def test_merge_refuses_missing_config(tmp_path: Path) -> None:
    with pytest.raises(WizardError, match="not found"):
        merge_connection(
            tmp_path / "nope.yaml",
            "x",
            build_connection(name="x", engine="sqlite", database=str(tmp_path / "x.db")),
        )


def test_store_credentials_are_private(user_config: Path) -> None:
    u, p = store_credentials(user_config, "finlink", "app_ro", "s3cret")
    assert stat.S_IMODE(u.stat().st_mode) == 0o600
    assert stat.S_IMODE(p.stat().st_mode) == 0o600
    assert stat.S_IMODE(u.parent.stat().st_mode) & 0o077 == 0
    assert u.read_text(encoding="utf-8").strip() == "app_ro"
    assert u.parent == user_config.parent / "secrets"


def test_wizard_output_is_schema_valid_and_resolves(user_config: Path) -> None:
    store_credentials(user_config, "finlink", "app_ro", "s3cret")
    conn = build_connection(
        name="finlink",
        engine="postgres",
        database="finlink",
        host="127.0.0.1",
        port=5433,
        username_file=str(user_config.parent / "secrets" / "finlink.username"),
        password_file=str(user_config.parent / "secrets" / "finlink.password"),
    )
    merge_connection(user_config, "finlink", conn)
    cfg = load_config(user_config)
    # full secret resolution (the server's own path) succeeds from the files
    resolved = ResolvedConnection("finlink", cfg.connections["finlink"])
    assert resolved.username is not None and resolved.username.value == "app_ro"
    assert resolved.password is not None and resolved.password.value == "s3cret"
    # the config text itself never contains the credentials
    assert "app_ro" not in user_config.read_text(encoding="utf-8")
    assert "s3cret" not in user_config.read_text(encoding="utf-8")


def test_username_env_and_username_file_are_mutually_exclusive(tmp_path: Path) -> None:
    from universal_db_mcp.config import ConnectionConfig

    conn = ConnectionConfig(
        type="postgres",
        host="h",
        database="d",
        username_env="U",
        username_file=str(tmp_path / "u"),
    )
    with pytest.raises(ConfigError, match="mutually exclusive"):
        ResolvedConnection("x", conn)


def test_username_file_empty_or_unsafe_refused(tmp_path: Path) -> None:
    from universal_db_mcp.config import ConnectionConfig

    empty = tmp_path / "empty.username"
    empty.write_text("", encoding="utf-8")
    empty.chmod(0o600)
    conn = ConnectionConfig(type="postgres", host="h", database="d", username_file=str(empty))
    with pytest.raises(ConfigError, match="empty"):
        ResolvedConnection("x", conn)

    unsafe = tmp_path / "unsafe.username"
    unsafe.write_text("u\n", encoding="utf-8")
    unsafe.chmod(0o644)
    conn = ConnectionConfig(type="postgres", host="h", database="d", username_file=str(unsafe))
    with pytest.raises(ConfigError, match="unsafe permissions"):
        ResolvedConnection("x", conn)


def test_ensure_config_exists_creates_minimal_valid(tmp_path: Path) -> None:
    cfg = tmp_path / "new" / "config.yaml"
    assert ensure_config_exists(cfg) is True
    assert load_config(cfg).application.transport == "stdio"
    assert stat.S_IMODE(cfg.stat().st_mode) == 0o600
    assert ensure_config_exists(cfg) is False  # never clobber


def test_live_test_uses_server_connector_machinery(tmp_path: Path) -> None:
    import yaml

    db = tmp_path / "t.db"
    db.touch()  # the sqlite connector requires an existing regular file
    conn = build_connection(name="t", engine="sqlite", database=str(db))
    merged = tmp_path / "m.yaml"
    merged.write_text(
        yaml.safe_dump(
            {
                "application": {"transport": "stdio"},
                "connections": {"t": conn.model_dump(mode="json", exclude_none=True)},
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    cfg = load_config(merged)
    result = run_live_test(cfg, "t")
    assert result["healthy"] is True, result


def test_invalid_connection_name_refused() -> None:
    with pytest.raises(WizardError, match="invalid connection name"):
        build_connection(name="bad name!", engine="sqlite", database="/tmp/x.db")  # noqa: S108


def test_add_connection_cli_non_interactive_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)  # a Linux host's own would win over HOME
    monkeypatch.delenv("UDBMCP_CONFIG", raising=False)

    rc = main(
        [
            "add-connection",
            "--json", "--no-test",
            "--name", "demo_sqlite",
            "--engine", "sqlite",
            "--database", str(tmp_path / "demo.db"),
        ]
    )
    out = capsys.readouterr().out
    data = json.loads(out)

    assert rc == 0
    assert data["connection"] == "demo_sqlite"
    assert data["tested"] is False
    cfg = load_config(home / ".universal-db-mcp" / "config.yaml")
    assert cfg.connections["demo_sqlite"].type == "sqlite"


def test_add_connection_cli_requires_tty_or_flags(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)  # a Linux host's own would win over HOME
    monkeypatch.delenv("UDBMCP_CONFIG", raising=False)

    rc = main(["add-connection"])  # no TTY, no flags: must refuse, write nothing
    err = capsys.readouterr().err
    assert rc != 0
    assert "TTY" in err or "interactive" in err.lower()
    assert not (home / ".universal-db-mcp" / "config.yaml").exists()


# ------------------------------------------------- adversarial-review fixes
# (3-lens review verified: a path-like --name truncated files OUTSIDE the
# secrets dir BEFORE validation ran; secret files had a 0644 window between
# write_text and chmod; a half-filled credential pair produced an empty
# secret file that kills the whole server at startup; merge_connection
# stripped 0640 group-read from service-owned configs and silently dropped
# in-body comments; CLI crashes escaped as raw tracebacks.)


def test_store_credentials_refuses_path_like_names(user_config: Path, tmp_path: Path) -> None:
    victim = tmp_path / "authorized_keys"
    victim.write_text("original\n", encoding="utf-8")

    for bad in ("../evil", str(victim), "a/b"):
        with pytest.raises(WizardError, match="invalid connection name"):
            store_credentials(user_config, bad, "u", "p")

    assert victim.read_text(encoding="utf-8") == "original\n", (
        "a path-like name must never truncate anything outside the secrets dir"
    )
    assert not (user_config.parent / "secrets").exists()


def test_store_credentials_refuses_empty_username(user_config: Path) -> None:
    with pytest.raises(WizardError, match="username must not be empty"):
        store_credentials(user_config, "c1", "  ", "p")


def test_store_credentials_optional_password_writes_no_password_file(user_config: Path) -> None:
    u, p = store_credentials(user_config, "c1", "app_ro", None)
    assert u.is_file() and p is None
    assert not (user_config.parent / "secrets" / "c1.password").exists()


def test_secret_files_are_born_0600(user_config: Path) -> None:
    u, p = store_credentials(user_config, "c1", "app_ro", "s3cret")
    assert stat.S_IMODE(u.stat().st_mode) == 0o600
    assert stat.S_IMODE(p.stat().st_mode) == 0o600


def test_merge_preserves_existing_file_mode(user_config: Path) -> None:
    user_config.chmod(0o640)  # a packaged service-owned config is 0640
    merge_connection(
        user_config, "a", build_connection(name="a", engine="sqlite", database=str(user_config.parent / "a.db"))
    )
    assert stat.S_IMODE(user_config.stat().st_mode) == 0o640, (
        "the wizard must not strip group-read from a service-owned config"
    )


def test_apply_reports_kept_and_comments_dropped(user_config: Path) -> None:
    text = user_config.read_text(encoding="utf-8")
    text += "\n# a mid-body admin comment about connections\n"
    user_config.write_text(text, encoding="utf-8")

    conn = build_connection(name="a", engine="sqlite", database=str(user_config.parent / "a.db"))
    result = apply_connection(user_config, "a", conn, run_test=False)

    assert result["kept"] is True
    assert result["comments_dropped"] is True
    merged = load_config(user_config)
    assert merged.connections["a"].type == "sqlite"


def test_add_connection_cli_port_zero_is_config_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)  # a Linux host's own would win over HOME
    monkeypatch.delenv("UDBMCP_CONFIG", raising=False)
    pw = tmp_path / "pw"
    pw.write_text("s3cret\n", encoding="utf-8")

    rc = main([
        "add-connection", "--json", "--no-test",
        "--name", "pg1", "--engine", "postgres",
        "--host", "h", "--database", "d", "--username", "u",
        "--password-file", str(pw), "--port", "0",
    ])
    err = capsys.readouterr().err

    assert rc != 0
    assert "CONFIG_ERROR" in err, "a raw pydantic traceback is not a fail-closed diagnostic"
    assert "Traceback" not in err
    # the connection is validated before any credential is written
    assert not (home / ".universal-db-mcp" / "secrets").exists()


def test_add_connection_cli_missing_password_file_is_config_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)  # a Linux host's own would win over HOME
    monkeypatch.delenv("UDBMCP_CONFIG", raising=False)

    rc = main([
        "add-connection", "--json", "--no-test",
        "--name", "pg1", "--engine", "postgres",
        "--host", "h", "--database", "d", "--username", "u",
        "--password-file", str(tmp_path / "nope.txt"),
    ])
    err = capsys.readouterr().err

    assert rc != 0
    assert "CONFIG_ERROR" in err
    assert "Traceback" not in err


def test_add_connection_cli_traversal_name_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)  # a Linux host's own would win over HOME
    monkeypatch.delenv("UDBMCP_CONFIG", raising=False)
    victim = tmp_path / "authorized_keys"
    victim.write_text("original\n", encoding="utf-8")

    rc = main([
        "add-connection", "--json", "--no-test",
        "--name", str(victim), "--engine", "postgres",
        "--host", "h", "--database", "d", "--username", "u",
        "--password-file", str(tmp_path / "pw"),
    ])
    err = capsys.readouterr().err

    assert rc != 0
    assert "CONFIG_ERROR" in err
    assert victim.read_text(encoding="utf-8") == "original\n"
    assert not (home / ".universal-db-mcp" / "secrets").exists()


def test_apply_refuses_unwritable_config_with_guidance(tmp_path: Path) -> None:
    """Seen live (2026-09-15): a sudo-created root-owned secrets dir in /etc
    made a later non-sudo wizard run die with errno 1 EPERM on os.chmod. The
    wizard must refuse a config it cannot WRITE up front, with the --config
    guidance, instead of failing halfway through credential creation."""
    from universal_db_mcp.wizard import apply_connection as _apply

    cfg = tmp_path / "system-config.yaml"
    cfg.write_text("application:\n  transport: stdio\n", encoding="utf-8")
    cfg.chmod(0o444)  # readable, NOT writable by this user

    conn = build_connection(name="a", engine="sqlite", database=str(tmp_path / "a.db"))
    with pytest.raises(WizardError, match="not writable by this user"):
        _apply(cfg, "a", conn, run_test=False)


def test_cli_default_falls_back_to_per_user_when_system_not_writable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from universal_db_mcp.agents import core as agents_core

    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)  # a Linux host's own would win over HOME
    monkeypatch.delenv("UDBMCP_CONFIG", raising=False)
    # a READABLE but NOT writable system config (0444, owned by this user)
    system = tmp_path / "etc-config.yaml"
    system.write_text("application:\n  transport: stdio\n", encoding="utf-8")
    system.chmod(0o444)
    monkeypatch.setattr(agents_core, "SYSTEM_CONFIG_PATH", system)

    rc = main([
        "add-connection", "--json", "--no-test",
        "--name", "demo_sqlite",
        "--engine", "sqlite",
        "--database", str(tmp_path / "demo.db"),
    ])
    err = capsys.readouterr().err

    assert rc == 0, err
    # the connection landed in the PER-USER config, never in the system file
    cfg = load_config(fake_home / ".universal-db-mcp" / "config.yaml")
    assert cfg.connections["demo_sqlite"].type == "sqlite"
    assert "demo_sqlite" not in system.read_text(encoding="utf-8")
