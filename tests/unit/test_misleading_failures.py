"""Failures that point at the wrong component.

Audit 2026-09-15. Each of these works today only on the newest servers our
fixtures happen to run, and each fails in a way that sends the operator to the
wrong place: an internal-looking AttributeError for a legacy auth plugin, a
protocol error for a wrong port, 'file is not a database' for an encrypted
file, a claim that a CA is missing when it is installed, and one tool dying on
a column that older servers do not have.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path
from typing import Any

import pytest

from universal_db_mcp.config import ConnectionConfig, ResolvedConnection, SecurityConfig
from universal_db_mcp.connectors.base import ConnectorError
from universal_db_mcp.security.policy import EffectivePolicy


def _secret(tmp_path: Path, name: str, value: str) -> str:
    p = tmp_path / name
    p.write_text(value + "\n", encoding="utf-8")
    p.chmod(0o600)
    return str(p)


def test_clickhouse_native_port_is_refused_with_the_reason() -> None:
    """clickhouse-connect speaks HTTP only; pointing it at 9000/9440 produces
    an opaque protocol error instead of 'wrong port'."""
    for port in (9000, 9440):
        with pytest.raises(Exception, match="HTTP|8123|8443"):
            ConnectionConfig.model_validate(
                {"type": "clickhouse", "host": "ch.corp", "database": "default",
                 "port": port, "username_env": "U"}
            )


def test_mysql_legacy_auth_plugin_gets_a_real_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """PyMySQL dispatches mysql_old_password to a helper that no longer exists,
    so the driver raises AttributeError and the operator sees what looks like
    an internal defect."""
    from universal_db_mcp.connectors import mysql as mysql_module

    class _Fake:
        cursors = types.SimpleNamespace(SSCursor=object)

        def connect(self, **_kwargs: Any) -> Any:
            raise AttributeError("module 'pymysql._auth' has no attribute 'scramble_old_password'")

    monkeypatch.setattr(mysql_module, "open_module", lambda *_a, **_k: _Fake())
    monkeypatch.setitem(sys.modules, "pymysql", types.ModuleType("pymysql"))
    cfg = ConnectionConfig.model_validate(
        {"type": "mysql", "host": "h", "database": "d",
         "username_file": _secret(tmp_path, "u", "ro"),
         "password_file": _secret(tmp_path, "p", "pw")}
    )
    resolved = ResolvedConnection("m", cfg)
    conn = mysql_module.MySQLConnector(resolved, EffectivePolicy.build(SecurityConfig(), resolved))

    with pytest.raises(ConnectorError) as exc:
        conn._connect()
    text = str(exc.value)
    assert "mysql_old_password" in text or "authentication plugin" in text
    assert "caching_sha2_password" in text or "mysql_native_password" in text


def test_sqlite_encrypted_file_is_named_as_such(tmp_path: Path) -> None:
    """An SQLCipher/SEE database reports 'file is not a database', which reads
    as corruption. Name encryption as the likely cause."""
    from universal_db_mcp.connectors import sqlite as sqlite_module

    db = tmp_path / "encrypted.db"
    db.write_bytes(b"\x00\x01\x02not-a-sqlite-header" + b"\x00" * 200)
    cfg = ConnectionConfig.model_validate({"type": "sqlite", "database": str(db)})
    resolved = ResolvedConnection("s", cfg)
    conn = sqlite_module.SQLiteConnector(resolved, EffectivePolicy.build(SecurityConfig(), resolved))

    health = conn.health_check()
    assert health.healthy is False
    assert "encrypt" in (health.detail or "").lower(), health.detail


def test_mssql_ca_check_accepts_a_hashed_capath_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """On distros whose trust store is a hashed CApath directory rather than a
    single bundle, get_ca_certs() enumerates nothing and the connector claimed
    the CA was not installed. Search the CApath too."""
    import ssl

    from universal_db_mcp.connectors import mssql as mssql_module

    pem = (
        "-----BEGIN CERTIFICATE-----\n"
        "MIIBhTCCASugAwIBAgIUYm9ndXNjZXJ0Zm9ydGVzdGluZzEwCgYIKoZIzj0EAwIw\n"
        "-----END CERTIFICATE-----\n"
    )
    ca_file = tmp_path / "internal-ca.pem"
    ca_file.write_text(pem, encoding="utf-8")
    capath = tmp_path / "certs"
    capath.mkdir()
    (capath / "abcd1234.0").write_text(pem, encoding="utf-8")

    monkeypatch.setattr(
        mssql_module.ssl, "get_default_verify_paths",
        lambda: ssl.DefaultVerifyPaths(None, str(capath), "", "", "", str(capath)),
    )

    class _EmptyContext:
        def get_ca_certs(self, binary_form: bool = False) -> list[Any]:
            return []

        def load_verify_locations(self, *a: Any, **k: Any) -> None:
            return None

    monkeypatch.setattr(mssql_module.ssl, "create_default_context", lambda *a, **k: _EmptyContext())

    mssql_module.MssqlConnector._require_ca_in_os_trust_store(str(ca_file))


def test_postgres_routines_work_on_servers_without_prokind(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """pg_proc.prokind is PostgreSQL 11+; psycopg 3 supports servers from 10,
    so db_list_routines must not be the one tool that dies there."""
    from universal_db_mcp.connectors import postgres as pg_module

    executed: list[str] = []

    class _Result:
        def fetchall(self) -> list[tuple[Any, ...]]:
            return [("public", "fn_x", "function")]

    class _Conn:
        def __enter__(self) -> _Conn:
            return self

        def __exit__(self, *a: object) -> None:
            return None

        def execute(self, sql: str, params: Any = None) -> _Result:
            executed.append(sql)
            if "prokind" in sql:
                raise RuntimeError("column p.prokind does not exist")
            return _Result()

        def close(self) -> None:
            return None

    cfg = ConnectionConfig.model_validate(
        {"type": "postgres", "host": "h", "database": "d", "username_env": "PGU"}
    )
    monkeypatch.setenv("PGU", "ro")
    resolved = ResolvedConnection("p", cfg)
    conn = pg_module.PostgresConnector(resolved, EffectivePolicy.build(SecurityConfig(), resolved))
    monkeypatch.setattr(conn, "_shared_meta_conn", lambda: _Conn(), raising=False)
    monkeypatch.setattr(conn, "_connect", lambda: _Conn(), raising=False)

    routines = conn.list_routines("public")

    assert [r.name for r in routines] == ["fn_x"]
    assert any("prokind" in s for s in executed), "the modern query is still tried first"
    assert any("proisagg" in s or "prorettype" in s for s in executed), executed
