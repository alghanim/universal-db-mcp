"""Connection-string safety: values must not become grammar.

Audit 2026-09-15, verified against the installed drivers themselves:

* mssql — `_odbc_escape` doubled '}' as if ODBC had an escape for it. It has
  none: Microsoft's grammar says the FIRST closing brace terminates a braced
  value, so a '}' truncated the credential and the remainder was parsed as
  further attributes. Because `Database=` is emitted before `Encrypt=`, and
  ODBC uses the FIRST occurrence of a repeated keyword, an injected
  `Encrypt=no` beat the connector's own `Encrypt=yes`: a TLS downgrade from a
  config value.
* oracle — host/database/sid are interpolated into a connect descriptor or
  easy-connect string. Live probes of oracledb 4.0.2's own parser confirmed
  `?ssl_server_dn_match=false` (defeating config.py's refusal to disable
  certificate verification), `?https_proxy=...`, and a second
  `(ADDRESS=(PROTOCOL=TCP)...)` plaintext fallback, all from ordinary config
  values.
* postgres — libpq treats a comma in `host` as a multi-host failover list, so
  the credentials are offered to every host in turn.
* clickhouse — with a client certificate the driver takes its mutual-TLS
  branch and NEVER sends the Basic credentials; and a password with no
  username silently authenticates as `default`.
* postgres/mysql/clickhouse — omitting the username does not send "no user":
  psycopg and PyMySQL substitute the OS account of the server process, and
  clickhouse-connect substitutes `default`.
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


def _build(engine: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, fake: Any,
           module_name: str, extra: dict[str, Any] | None = None,
           username: str | None = "app_ro",
           password: str | None = "s3cret") -> Any:  # noqa: S107 - fake credentials
    from universal_db_mcp.connectors import clickhouse, mssql, mysql, postgres
    mod = {"postgres": postgres, "mysql": mysql, "clickhouse": clickhouse, "mssql": mssql}[engine]
    monkeypatch.setattr(mod, "open_module", lambda *_a, **_k: fake)
    monkeypatch.setitem(sys.modules, module_name, types.ModuleType(module_name))
    body: dict[str, Any] = {"type": engine, "host": "db.internal", "database": "appdb"}
    if username is not None:
        body["username_file"] = _secret(tmp_path, f"{engine}.u", username)
    if password is not None:
        body["password_file"] = _secret(tmp_path, f"{engine}.p", password)
    body.update(extra or {})
    cfg = ConnectionConfig.model_validate(body)
    resolved = ResolvedConnection("c", cfg)
    cls = {
        "postgres": postgres.PostgresConnector, "mysql": mysql.MySQLConnector,
        "clickhouse": clickhouse.ClickHouseConnector, "mssql": mssql.MssqlConnector,
    }[engine]
    return cls(resolved, EffectivePolicy.build(SecurityConfig(), resolved))


# --------------------------------------------------------------- mssql
class _FakePyodbc:
    def __init__(self) -> None:
        self.conn_strings: list[str] = []

    def drivers(self) -> list[str]:
        return ["ODBC Driver 18 for SQL Server"]

    def connect(self, conn_string: str, **kwargs: Any) -> str:
        self.conn_strings.append(conn_string)
        return "handle"


def test_mssql_refuses_closing_brace_in_values(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakePyodbc()
    conn = _build(
        "mssql", tmp_path, monkeypatch, fake=fake, module_name="pyodbc",
        password="s3cr3t}",  # noqa: S106 - fake credential
    )

    with pytest.raises(ConnectorError) as exc:
        conn._connect()
    assert fake.conn_strings == [], "a value that cannot be quoted must never reach the driver"
    text = str(exc.value)
    assert "}" in text and "Pwd" in text
    assert "s3cr3t" not in text, "the secret must not appear in the diagnostic"


def test_mssql_refuses_brace_injection_from_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = _FakePyodbc()
    conn = _build(
        "mssql", tmp_path, monkeypatch, fake=fake, module_name="pyodbc",
        extra={"database": "appdb};Encrypt=no;x={"},
    )
    with pytest.raises(ConnectorError):
        conn._connect()
    assert fake.conn_strings == []


def test_mssql_encryption_keywords_precede_injectable_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Defense in depth: ODBC honors the FIRST occurrence of a repeated
    keyword, so Encrypt/TrustServerCertificate are emitted before any
    config-derived value."""
    fake = _FakePyodbc()
    ca = tmp_path / "ca.pem"
    ca.write_text("x", encoding="utf-8")
    conn = _build("mssql", tmp_path, monkeypatch, fake=fake, module_name="pyodbc",
                  extra={"tls": {"enabled": True, "verify_server": True, "ca_file": str(ca)}})
    monkeypatch.setattr(type(conn), "_require_ca_in_os_trust_store", staticmethod(lambda _ca: None))
    conn._connect()
    cs = fake.conn_strings[0]
    assert cs.index("Encrypt=") < cs.index("Database="), cs
    assert cs.index("TrustServerCertificate=") < cs.index("Database="), cs


# --------------------------------------------------------------- oracle
@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("database", "ORCL?ssl_server_dn_match=false"),
        ("database", "ORCL?https_proxy=proxy.evil&https_proxy_port=8080"),
        ("host", "dbhost)(PORT=1521))(ADDRESS=(PROTOCOL=TCP)(HOST=evil.example.com"),
        ("database", "ORCL,other"),
    ],
)
def test_oracle_refuses_connect_string_grammar_in_values(field: str, value: str) -> None:
    with pytest.raises(Exception, match="connect string|grammar|not allowed"):
        ConnectionConfig.model_validate(
            {"type": "oracle", "host": "h", "database": "d", **{field: value}}
        )


def test_oracle_refuses_grammar_in_sid_and_alias() -> None:
    with pytest.raises(Exception, match="connect string|grammar|not allowed"):
        ConnectionConfig.model_validate(
            {"type": "oracle", "host": "h", "database": "d", "options": {"sid": "ORCL)(x=y"}}
        )
    with pytest.raises(Exception, match="connect string|grammar|not allowed"):
        ConnectionConfig.model_validate(
            {"type": "oracle", "host": "h", "database": "d",
             "options": {"tns_alias": "PROD?x=1", "tns_admin": "/etc/tns"}}
        )


def test_oracle_accepts_ordinary_values() -> None:
    ConnectionConfig.model_validate({"type": "oracle", "host": "db-1.corp.internal", "database": "ORCLPDB1"})


# --------------------------------------------------------------- postgres
def test_postgres_refuses_comma_in_host() -> None:
    with pytest.raises(Exception, match="comma|multi-host"):
        ConnectionConfig.model_validate(
            {"type": "postgres", "host": "db.internal,evil.example.com", "database": "d",
             "username_env": "PGUSER_X"}
        )


# --------------------------------------------------------------- clickhouse
class _FakeClickhouse:
    def __init__(self) -> None:
        self.kwargs: list[dict[str, Any]] = []

    def get_client(self, **kwargs: Any) -> Any:
        self.kwargs.append(kwargs)
        return types.SimpleNamespace(command=lambda *_a, **_k: "ok", close=lambda: None)


def test_clickhouse_password_with_client_cert_forces_basic_auth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """clickhouse-connect skips Basic auth entirely when a client cert is set
    and tls_mode is unset, so a configured password is never sent. Ask for the
    mode explicitly whenever a password is configured."""
    ca = tmp_path / "ca.pem"
    ca.write_text("x", encoding="utf-8")
    cert = tmp_path / "client.pem"
    cert.write_text("x", encoding="utf-8")
    fake = _FakeClickhouse()
    conn = _build(
        "clickhouse", tmp_path, monkeypatch, fake=fake, module_name="clickhouse_connect",
        extra={"tls": {"enabled": True, "verify_server": True, "ca_file": str(ca),
                       "client_cert_file": str(cert)}},
    )
    conn._connect()
    assert fake.kwargs[0].get("tls_mode") == "strict", (
        "with a password configured the driver must be told to send it"
    )


def test_clickhouse_mutual_tls_without_password_keeps_cert_auth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ca = tmp_path / "ca.pem"
    ca.write_text("x", encoding="utf-8")
    cert = tmp_path / "client.pem"
    cert.write_text("x", encoding="utf-8")
    fake = _FakeClickhouse()
    conn = _build(
        "clickhouse", tmp_path, monkeypatch, fake=fake, module_name="clickhouse_connect",
        password=None,
        extra={"tls": {"enabled": True, "verify_server": True, "ca_file": str(ca),
                       "client_cert_file": str(cert)}},
    )
    conn._connect()
    assert fake.kwargs[0].get("tls_mode") in (None, "mutual"), "cert auth stays available"


# --------------------------------------------------------------- implicit OS user
@pytest.mark.parametrize("engine", ["postgres", "mysql", "clickhouse"])
def test_missing_username_is_refused_for_server_backed_engines(engine: str, tmp_path: Path) -> None:
    """Omitting the username is not 'no credential': psycopg and PyMySQL send
    the OS account of the server process and clickhouse-connect sends
    'default'. Refuse unless the operator opts in explicitly."""
    with pytest.raises(Exception, match="username"):
        ConnectionConfig.model_validate(
            {"type": engine, "host": "h", "database": "d",
             "password_file": _secret(tmp_path, f"{engine}.pw", "s3cret")}
        )


@pytest.mark.parametrize("engine", ["postgres", "mysql"])
def test_os_authentication_opt_in_allows_missing_username(engine: str) -> None:
    ConnectionConfig.model_validate(
        {"type": engine, "host": "h", "database": "d", "options": {"os_authentication": True}}
    )
