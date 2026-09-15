"""Config validation and secret handling."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from universal_db_mcp.config import load_config, load_resolved
from universal_db_mcp.errors import ConfigError

# POSIX mode-bit security regression: NTFS has no 0600 semantics, so this must
# be skipped on win32 ONLY (macOS/Linux run it for real).
_WIN32_ONLY = pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX mode-bit semantics; run on linux/macos"
)


def test_loads_minimal_config(tmp_path: Path) -> None:
    p = tmp_path / "c.yaml"
    p.write_text("application:\n  transport: stdio\n")
    cfg = load_config(p)
    assert cfg.application.transport == "stdio"
    assert cfg.security.read_only is True


def test_rejects_unknown_fields(tmp_path: Path) -> None:
    p = tmp_path / "c.yaml"
    p.write_text("application:\n  transport: stdio\n  sneaky_option: 1\n")
    with pytest.raises(ConfigError, match="sneaky_option"):
        load_config(p)


def test_rejects_telemetry(tmp_path: Path) -> None:
    p = tmp_path / "c.yaml"
    p.write_text("application:\n  telemetry_enabled: true\n")
    with pytest.raises(ConfigError, match="telemetry"):
        load_config(p)


def test_rejects_writes(tmp_path: Path) -> None:
    p = tmp_path / "c.yaml"
    p.write_text("security:\n  allow_write_operations: true\n")
    with pytest.raises(ConfigError, match="write"):
        load_config(p)


def test_rejects_tls_without_ca(tmp_path: Path) -> None:
    p = tmp_path / "c.yaml"
    p.write_text(
        "connections:\n  x:\n    type: postgres\n    host: h\n    database: d\n"
        "    tls:\n      enabled: true\n      verify_server: true\n"
    )
    with pytest.raises(ConfigError, match="ca_file"):
        load_config(p)


@_WIN32_ONLY
def test_secret_file_permissions_enforced(tmp_path: Path) -> None:
    secret = tmp_path / "pw"
    secret.write_text("hunter2\n")
    secret.chmod(0o644)  # world readable -> must be rejected
    p = tmp_path / "c.yaml"
    p.write_text(
        f"connections:\n  pg:\n    type: postgres\n    host: h\n    database: d\n    password_file: {secret}\n"
        "    options:\n      os_authentication: true\n"
    )
    with pytest.raises(ConfigError, match="unsafe permissions"):
        load_resolved(p)


def test_password_file_resolves(tmp_path: Path) -> None:
    secret = tmp_path / "pw"
    secret.write_text("hunter2\n")
    secret.chmod(0o600)
    p = tmp_path / "c.yaml"
    p.write_text(
        f"connections:\n  pg:\n    type: postgres\n    host: h\n    database: d\n    password_file: {secret}\n"
        "    options:\n      os_authentication: true\n"
    )
    cfg, resolved = load_resolved(p)
    pw = resolved["pg"].password
    assert pw is not None
    assert str(pw) == "<redacted>"
    assert repr(pw) == "'<redacted>'"
    # the SecretMark must not leak through serialization
    import json

    assert "hunter2" not in json.dumps({"v": str(pw)})


def test_missing_password_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("X_USER", "udbmcp_ro")
    monkeypatch.delenv("X_PW_MISSING", raising=False)
    p = tmp_path / "c.yaml"
    p.write_text(
        "connections:\n  pg:\n    type: postgres\n    host: h\n    database: d\n"
        "    username_env: X_USER\n    password_env: X_PW_MISSING\n"
    )
    with pytest.raises(ConfigError, match="X_PW_MISSING"):
        load_resolved(p)


def test_reserved_connection_names(tmp_path: Path) -> None:
    p = tmp_path / "c.yaml"
    p.write_text("connections:\n  'bad name!':\n    type: sqlite\n    database: /x.db\n")
    with pytest.raises(ConfigError, match="connection id"):
        load_config(p)


def test_db2_family_restriction(tmp_path: Path) -> None:
    p = tmp_path / "c.yaml"
    p.write_text("connections:\n  d:\n    type: db2\n    family: zos\n    host: h\n    database: x\n")
    with pytest.raises(ConfigError, match="luw"):
        load_config(p)


# ------------------------------------------------------------- service env override
# The systemd unit / launchd plist run `serve --transport http` (a daemon has
# no stdin client) while sharing the config with per-harness stdio spawns, so
# the bearer-token PATH must be able to arrive from the service environment
# (UDBMCP_HTTP_BEARER_TOKEN_FILE) instead of the shared config file. The token
# VALUE itself is never carried in an environment variable.


def test_bearer_token_path_from_service_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    p = tmp_path / "c.yaml"
    p.write_text("application:\n  transport: stdio\n")
    monkeypatch.setenv("UDBMCP_HTTP_BEARER_TOKEN_FILE", "/etc/universal-db-mcp/http-token")
    cfg = load_config(p)
    assert cfg.application.http_bearer_token_file == "/etc/universal-db-mcp/http-token"


def test_bearer_token_env_satisfies_http_transport_requirement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    p = tmp_path / "c.yaml"
    p.write_text("application:\n  transport: http\n")
    monkeypatch.setenv("UDBMCP_HTTP_BEARER_TOKEN_FILE", "/etc/universal-db-mcp/http-token")
    cfg = load_config(p)  # must NOT raise: the env fallback provides the path
    assert cfg.application.transport == "http"


def test_explicit_config_token_path_wins_over_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    p = tmp_path / "c.yaml"
    p.write_text(
        "application:\n  transport: http\n"
        "  http_bearer_token_file: /admin/chosen/token\n"
    )
    monkeypatch.setenv("UDBMCP_HTTP_BEARER_TOKEN_FILE", "/etc/universal-db-mcp/http-token")
    cfg = load_config(p)
    assert cfg.application.http_bearer_token_file == "/admin/chosen/token"


def test_bearer_token_env_injected_when_application_section_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    p = tmp_path / "c.yaml"
    p.write_text("security:\n  read_only: true\n")
    monkeypatch.setenv("UDBMCP_HTTP_BEARER_TOKEN_FILE", "/run/tok")
    cfg = load_config(p)
    assert cfg.application.http_bearer_token_file == "/run/tok"


def test_no_env_no_change(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    p = tmp_path / "c.yaml"
    p.write_text("application:\n  transport: stdio\n")
    monkeypatch.delenv("UDBMCP_HTTP_BEARER_TOKEN_FILE", raising=False)
    cfg = load_config(p)
    assert cfg.application.http_bearer_token_file is None


def test_http_transport_without_any_token_path_still_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    p = tmp_path / "c.yaml"
    p.write_text("application:\n  transport: http\n")
    monkeypatch.delenv("UDBMCP_HTTP_BEARER_TOKEN_FILE", raising=False)
    with pytest.raises(ConfigError, match="http_bearer_token_file"):
        load_config(p)
