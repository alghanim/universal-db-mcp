"""Authentication and endpoint forms that enterprise deployments require.

Audit 2026-09-15: each of these is the NORMAL arrangement somewhere, and each
was unreachable - the options allowlists were empty, so no config could express
them:

* SQL Server with Windows/Kerberos logins only (the corporate default):
  omitting credentials sent an empty SQL login, so such a site could not be
  onboarded at all.
* SQL Server named instances: the port was always appended, so a dynamic-port
  named instance was unreachable and looked like a firewall problem.
* Db2 servers that demand a specific mechanism (Kerberos, TOKEN, AES): the
  driver supports the Authentication keyword, we never emitted it, and the
  failure is SQL30082N reason 17 - the exact string our own docs now attribute
  to a client bug.
* PostgreSQL behind GSSAPI/Kerberos, or reached through a service file.
* MySQL over a Unix socket (a co-located server with no TCP listener).
"""

from __future__ import annotations

import sys
import types
from pathlib import Path
from typing import Any

import pytest
from helpers_session import SessionHandle

from universal_db_mcp.config import ConnectionConfig, ResolvedConnection, SecurityConfig
from universal_db_mcp.security.policy import EffectivePolicy


def _secret(tmp_path: Path, name: str, value: str) -> str:
    p = tmp_path / name
    p.write_text(value + "\n", encoding="utf-8")
    p.chmod(0o600)
    return str(p)


def _connector(engine: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, fake: Any,
               module_name: str, body: dict[str, Any]) -> Any:
    from universal_db_mcp.connectors import db2, mssql, mysql, postgres
    mod = {"postgres": postgres, "mysql": mysql, "mssql": mssql, "db2": db2}[engine]
    monkeypatch.setattr(mod, "open_module", lambda *_a, **_k: fake)
    for extra in {"pyodbc": [], "ibm_db": ["ibm_db_dbi"]}.get(module_name, []):
        monkeypatch.setitem(sys.modules, extra, types.ModuleType(extra))
    monkeypatch.setitem(sys.modules, module_name, types.ModuleType(module_name))
    cfg = ConnectionConfig.model_validate({"type": engine, **body})
    resolved = ResolvedConnection("c", cfg)
    cls = {"postgres": postgres.PostgresConnector, "mysql": mysql.MySQLConnector,
           "mssql": mssql.MssqlConnector, "db2": db2.Db2Connector}[engine]
    return cls(resolved, EffectivePolicy.build(SecurityConfig(), resolved))


class _FakePyodbc:
    def __init__(self) -> None:
        self.conn_strings: list[str] = []

    def drivers(self) -> list[str]:
        return ["ODBC Driver 18 for SQL Server"]

    def connect(self, cs: str, **kwargs: Any) -> SessionHandle:
        self.conn_strings.append(cs)
        return SessionHandle()


def test_mssql_trusted_connection_omits_sql_login(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = _FakePyodbc()
    conn = _connector("mssql", tmp_path, monkeypatch, fake=fake, module_name="pyodbc",
                      body={"host": "sql.corp", "database": "appdb",
                            "options": {"trusted_connection": True}})
    conn._connect()
    cs = fake.conn_strings[0]
    assert "Trusted_Connection=yes" in cs
    assert "Uid=" not in cs and "Pwd=" not in cs


def test_mssql_trusted_connection_refuses_a_sql_login_too(tmp_path: Path) -> None:
    with pytest.raises(Exception, match="trusted_connection"):
        ConnectionConfig.model_validate(
            {"type": "mssql", "host": "h", "database": "d",
             "username_env": "U", "options": {"trusted_connection": True}}
        )


def test_mssql_named_instance_keeps_the_instance_and_drops_the_port(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A named instance resolves its dynamic port through SQL Server Browser;
    appending ,1433 sends the client to the default instance instead."""
    fake = _FakePyodbc()
    conn = _connector("mssql", tmp_path, monkeypatch, fake=fake, module_name="pyodbc",
                      body={"host": "sql.corp\\SQLEXPRESS", "database": "appdb",
                            "username_file": _secret(tmp_path, "u", "sa"),
                            "password_file": _secret(tmp_path, "p", "pw")})
    conn._connect()
    cs = fake.conn_strings[0]
    assert "Server={sql.corp\\SQLEXPRESS}" in cs, cs
    assert ",1433" not in cs, "a named instance must not carry the default port"


def test_mssql_named_instance_with_explicit_port_keeps_the_port(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = _FakePyodbc()
    conn = _connector("mssql", tmp_path, monkeypatch, fake=fake, module_name="pyodbc",
                      body={"host": "sql.corp\\SQLEXPRESS", "port": 1444, "database": "appdb",
                            "username_file": _secret(tmp_path, "u2", "sa"),
                            "password_file": _secret(tmp_path, "p2", "pw")})
    conn._connect()
    assert "Server={sql.corp\\SQLEXPRESS,1444}" in fake.conn_strings[0]


class _FakeIbmDb:
    def __init__(self) -> None:
        self.dsns: list[str] = []

    def connect(self, dsn: str, user: str, password: str, *a: Any, **k: Any) -> str:
        self.dsns.append(dsn)
        return "handle"

    def exec_immediate(self, conn: str, sql: str) -> str:
        return "stmt"


def test_db2_authentication_mechanism_is_selectable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = _FakeIbmDb()
    conn = _connector("db2", tmp_path, monkeypatch, fake=fake, module_name="ibm_db",
                      body={"host": "db2.corp", "database": "SAMPLE",
                            "username_file": _secret(tmp_path, "du", "u"),
                            "password_file": _secret(tmp_path, "dp", "p"),
                            "options": {"authentication": "SERVER_ENCRYPT_AES"}})
    conn._connect()
    assert "AUTHENTICATION=SERVER_ENCRYPT_AES;" in fake.dsns[0]


def test_db2_authentication_value_is_validated() -> None:
    with pytest.raises(Exception, match="authentication"):
        ConnectionConfig.model_validate(
            {"type": "db2", "host": "h", "database": "d", "options": {"authentication": "MAGIC"}}
        )


class _FakePsycopg:
    def __init__(self) -> None:
        self.kwargs: list[dict[str, Any]] = []

    def connect(self, **kwargs: Any) -> SessionHandle:
        self.kwargs.append(kwargs)
        return SessionHandle()


def test_postgres_gssapi_options_reach_the_driver(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = _FakePsycopg()
    conn = _connector("postgres", tmp_path, monkeypatch, fake=fake, module_name="psycopg",
                      body={"host": "pg.corp", "database": "appdb",
                            "options": {"os_authentication": True, "gssencmode": "require",
                                        "krbsrvname": "postgres"}})
    conn._connect()
    kw = fake.kwargs[0]
    assert kw["gssencmode"] == "require"
    assert kw["krbsrvname"] == "postgres"


def test_postgres_sslmode_cannot_weaken_an_enabled_tls_config(tmp_path: Path) -> None:
    ca = tmp_path / "ca.pem"
    ca.write_text("x", encoding="utf-8")
    with pytest.raises(Exception, match="sslmode"):
        ConnectionConfig.model_validate(
            {"type": "postgres", "host": "h", "database": "d", "username_env": "U",
             "tls": {"enabled": True, "verify_server": True, "ca_file": str(ca)},
             "options": {"sslmode": "require"}}
        )


class _FakePyMySQL:
    def __init__(self) -> None:
        self.kwargs: list[dict[str, Any]] = []
        self.cursors = types.SimpleNamespace(SSCursor=object)

    def connect(self, **kwargs: Any) -> SessionHandle:
        self.kwargs.append(kwargs)
        return SessionHandle()


def test_mysql_unix_socket_replaces_the_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = _FakePyMySQL()
    conn = _connector("mysql", tmp_path, monkeypatch, fake=fake, module_name="pymysql",
                      body={"database": "appdb", "username_file": _secret(tmp_path, "mu", "ro"),
                            "password_file": _secret(tmp_path, "mp", "pw"),
                            "options": {"unix_socket": "/var/run/mysqld/mysqld.sock"}})
    conn._connect()
    kw = fake.kwargs[0]
    assert kw["unix_socket"] == "/var/run/mysqld/mysqld.sock"
    assert not kw.get("host"), "a socket connection has no host"
