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
