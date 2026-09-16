"""Session safety profile: what every connection does to the SERVER session
so an agent's reads cannot hurt production.

Motivation (2026-09-16): a Db2 site needs every query to run WITH UR so the
agent never holds share locks on production tables. Allowing the clause when
the agent writes it is not enough; the agent may forget. The isolation is
therefore enforced at the session level, and the same idea is applied to
every engine that supports it: server-side read-only, lock-wait ceilings,
statement timeouts and an identifiable session name for the DBAs.

Verified live before writing these tests (PostgreSQL 17, MySQL 9.7,
ClickHouse 26, Oracle 23ai, Db2 11.5.9): the statements below are accepted
and read back as expected; PostgreSQL, MySQL and ClickHouse refuse a
CREATE TABLE server-side afterwards. Oracle and Db2 have no session-wide
read-only, which the report states rather than hides.
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
from universal_db_mcp.security.session import SessionProfile, resolve_session


def _resolved(engine: str, tmp_path: Path, *, session: dict[str, Any] | None = None,
              read_only: bool = True, options: dict[str, Any] | None = None) -> ResolvedConnection:
    body: dict[str, Any] = {"type": engine, "database": "d", "read_only": read_only}
    if engine != "sqlite":
        body["host"] = "h"
        u = tmp_path / f"{engine}.u"
        u.write_text("app_ro\n", encoding="utf-8")
        u.chmod(0o600)
        p = tmp_path / f"{engine}.p"
        p.write_text("s3cret\n", encoding="utf-8")
        p.chmod(0o600)
        body["username_file"] = str(u)
        body["password_file"] = str(p)
    if session is not None:
        body["session"] = session
    if options:
        body["options"] = options
    return ResolvedConnection("prod_" + engine, ConnectionConfig.model_validate(body))


# ------------------------------------------------------------- config rules
def test_db2_read_only_defaults_to_ur(tmp_path: Path) -> None:
    conn = _resolved("db2", tmp_path)
    profile = resolve_session(conn, EffectivePolicy.build(SecurityConfig(), conn))
    assert profile.isolation == "ur"


def test_mssql_read_only_defaults_to_read_uncommitted(tmp_path: Path) -> None:
    conn = _resolved("mssql", tmp_path)
    profile = resolve_session(conn, EffectivePolicy.build(SecurityConfig(), conn))
    assert profile.isolation == "read_uncommitted"


@pytest.mark.parametrize("engine", ["postgres", "mysql", "oracle"])
def test_mvcc_engines_keep_the_server_default_isolation(engine: str, tmp_path: Path) -> None:
    conn = _resolved(engine, tmp_path)
    profile = resolve_session(conn, EffectivePolicy.build(SecurityConfig(), conn))
    assert profile.isolation is None, "readers do not block writers there; no reason to change it"


def test_explicit_isolation_overrides_the_default(tmp_path: Path) -> None:
    conn = _resolved("db2", tmp_path, session={"isolation": "cs"})
    assert resolve_session(conn, EffectivePolicy.build(SecurityConfig(), conn)).isolation == "cs"


@pytest.mark.parametrize(
    ("engine", "bad"),
    [("db2", "read_uncommitted"), ("postgres", "ur"), ("mysql", "snapshot"),
     ("oracle", "ur"), ("clickhouse", "cs"), ("sqlite", "cs")],
)
def test_isolation_values_are_engine_checked(engine: str, bad: str, tmp_path: Path) -> None:
    with pytest.raises(Exception, match="isolation"):
        _resolved(engine, tmp_path, session={"isolation": bad})


def test_application_name_defaults_and_is_dsn_safe(tmp_path: Path) -> None:
    conn = _resolved("db2", tmp_path)
    assert resolve_session(conn, EffectivePolicy.build(SecurityConfig(), conn)).application_name == "udbmcp:prod_db2"
    with pytest.raises(Exception, match="application_name"):
        _resolved("db2", tmp_path, session={"application_name": "x;y=z"})


def test_statement_timeout_comes_from_the_policy(tmp_path: Path) -> None:
    conn = _resolved("postgres", tmp_path)
    policy = EffectivePolicy.build(SecurityConfig(hard_query_timeout_seconds=42), conn)
    assert resolve_session(conn, policy).statement_timeout_seconds == 42


def test_lock_timeout_default_and_disable(tmp_path: Path) -> None:
    conn = _resolved("postgres", tmp_path)
    assert resolve_session(conn, EffectivePolicy.build(SecurityConfig(), conn)).lock_timeout_seconds == 5
    conn2 = _resolved("postgres", tmp_path, session={"lock_timeout_seconds": None})
    assert resolve_session(conn2, EffectivePolicy.build(SecurityConfig(), conn2)).lock_timeout_seconds is None


# ------------------------------------------------------------- what reaches the server
class _Recorder:
    """A connection/cursor double that records every statement."""

    def __init__(self, readback: dict[str, Any] | None = None) -> None:
        self.statements: list[str] = []
        self.readback = readback or {}
        self.attrs: dict[str, Any] = {}

    # psycopg / sqlite style
    def execute(self, sql: str, *_a: Any, **_k: Any) -> _Recorder:
        self.statements.append(sql)
        return self

    def fetchone(self) -> Any:
        return self.readback.get("row")

    def fetchall(self) -> Any:
        return self.readback.get("rows", [])

    # pymysql / pyodbc style
    def cursor(self) -> _Recorder:
        return self

    def __enter__(self) -> _Recorder:
        return self

    def __exit__(self, *_a: Any) -> None:
        return None

    def close(self) -> None:
        return None

    def __setattr__(self, key: str, value: Any) -> None:
        if key in ("statements", "readback", "attrs"):
            object.__setattr__(self, key, value)
        else:
            self.attrs[key] = value


def _connector(engine: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, fake_module: Any,
               module_name: str, session: dict[str, Any] | None = None) -> Any:
    from universal_db_mcp.connectors import db2, mssql, mysql, postgres
    mod = {"postgres": postgres, "mysql": mysql, "mssql": mssql, "db2": db2}[engine]
    monkeypatch.setattr(mod, "open_module", lambda *_a, **_k: fake_module)
    monkeypatch.setitem(sys.modules, module_name, types.ModuleType(module_name))
    if engine == "db2":
        monkeypatch.setitem(sys.modules, "ibm_db_dbi", types.ModuleType("ibm_db_dbi"))
    resolved = _resolved(engine, tmp_path, session=session)
    cls = {"postgres": postgres.PostgresConnector, "mysql": mysql.MySQLConnector,
           "mssql": mssql.MssqlConnector, "db2": db2.Db2Connector}[engine]
    return cls(resolved, EffectivePolicy.build(SecurityConfig(hard_query_timeout_seconds=60), resolved))


def test_postgres_session_is_read_only_with_timeouts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rec = _Recorder()
    fake = types.SimpleNamespace(connect=lambda **kw: (rec.attrs.update(connect_kwargs=kw), rec)[1])
    conn = _connector("postgres", tmp_path, monkeypatch, fake_module=fake, module_name="psycopg")

    conn._connect()

    assert rec.attrs["connect_kwargs"]["application_name"] == "udbmcp:prod_postgres"
    joined = "\n".join(rec.statements)
    assert "default_transaction_read_only = on" in joined
    assert "statement_timeout = '60000ms'" in joined
    assert "lock_timeout = '5000ms'" in joined


def test_mysql_session_is_read_only_with_timeouts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rec = _Recorder()
    fake = types.SimpleNamespace(
        connect=lambda **kw: (rec.attrs.update(connect_kwargs=kw), rec)[1],
        cursors=types.SimpleNamespace(SSCursor=object),
    )
    conn = _connector("mysql", tmp_path, monkeypatch, fake_module=fake, module_name="pymysql")

    conn._connect()

    assert rec.attrs["connect_kwargs"]["program_name"] == "udbmcp:prod_mysql"
    joined = "\n".join(rec.statements)
    assert "SET SESSION TRANSACTION READ ONLY" in joined
    assert "max_execution_time = 60000" in joined
    assert "innodb_lock_wait_timeout = 5" in joined


def test_mssql_session_isolation_lock_timeout_and_app_name(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rec = _Recorder()
    captured: dict[str, Any] = {}

    def connect(cs: str, **kw: Any) -> _Recorder:
        captured["cs"] = cs
        return rec

    fake = types.SimpleNamespace(connect=connect, drivers=lambda: ["ODBC Driver 18 for SQL Server"])
    conn = _connector("mssql", tmp_path, monkeypatch, fake_module=fake, module_name="pyodbc")

    conn._connect()

    assert "APP={udbmcp:prod_mssql}" in captured["cs"]
    joined = "\n".join(rec.statements)
    assert "SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED" in joined
    assert "SET LOCK_TIMEOUT 5000" in joined
    assert rec.attrs.get("timeout") == 60, "pyodbc query timeout carries the policy ceiling"


def test_db2_session_isolation_is_enforced_not_optional(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    executed: list[str] = []

    class _FakeIbmDb:
        def connect(self, dsn: str, u: str, p: str, *a: Any, **k: Any) -> str:
            executed.append("DSN:" + dsn)
            return "handle"

        def exec_immediate(self, conn: str, sql: str) -> str:
            executed.append(sql)
            return "stmt"

        def fetch_tuple(self, stmt: str) -> tuple[Any, ...]:
            return ("UR", 5, "udbmcp:prod_db2")

        def close(self, conn: str) -> bool:
            return True

    conn = _connector("db2", tmp_path, monkeypatch, fake_module=_FakeIbmDb(), module_name="ibm_db")
    conn._connect()

    dsn = executed[0]
    assert "CLIENTAPPLNAME=udbmcp:prod_db2;" in dsn
    assert "QUERYTIMEOUT=60;" in dsn
    assert "SET CURRENT ISOLATION = UR" in executed
    assert "SET CURRENT LOCK TIMEOUT = 5" in executed


def test_db2_failure_to_set_isolation_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The isolation IS the production-safety promise; if the server refuses
    it, the connection must not silently proceed at the default level."""

    class _FakeIbmDb:
        def connect(self, *a: Any, **k: Any) -> str:
            return "handle"

        def exec_immediate(self, conn: str, sql: str) -> str:
            if "ISOLATION" in sql:
                raise RuntimeError("SQL0104N unexpected token")
            return "stmt"

        def close(self, conn: str) -> bool:
            return True

    conn = _connector("db2", tmp_path, monkeypatch, fake_module=_FakeIbmDb(), module_name="ibm_db")
    with pytest.raises(ConnectorError, match="isolation"):
        conn._connect()


def test_timeouts_are_best_effort_but_reported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A lock-timeout statement an old server does not know must not take the
    connection down; it is recorded as skipped so test_connection shows it."""

    class _Rec(_Recorder):
        def execute(self, sql: str, *_a: Any, **_k: Any) -> _Rec:
            if "lock_timeout" in sql:
                raise RuntimeError("unrecognized configuration parameter")
            return super().execute(sql)

    rec = _Rec()
    fake = types.SimpleNamespace(connect=lambda **kw: rec)
    conn = _connector("postgres", tmp_path, monkeypatch, fake_module=fake, module_name="psycopg")

    conn._connect()

    assert any("lock_timeout" in s for s in conn.session_status["skipped"])
    assert any("read_only" in s for s in conn.session_status["applied"])


def test_health_report_carries_the_session(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rec = _Recorder(readback={"row": ("on", "1min", "5s", "udbmcp:prod_postgres", "PostgreSQL 17")})
    fake = types.SimpleNamespace(connect=lambda **kw: rec)
    conn = _connector("postgres", tmp_path, monkeypatch, fake_module=fake, module_name="psycopg")

    health = conn.health_check()

    assert health.healthy is True
    assert health.session is not None
    assert health.session["engine"] == "postgres"
    assert health.session["read_only_enforced"] is True
    assert health.session["applied"], health.session


def test_oracle_and_db2_report_no_server_side_read_only(tmp_path: Path) -> None:
    for engine in ("oracle", "db2"):
        conn = _resolved(engine, tmp_path)
        profile = resolve_session(conn, EffectivePolicy.build(SecurityConfig(), conn))
        assert profile.server_read_only_available is False, engine
    pg = _resolved("postgres", tmp_path)
    assert resolve_session(pg, EffectivePolicy.build(SecurityConfig(), pg)).server_read_only_available is True


def test_profile_is_a_plain_report(tmp_path: Path) -> None:
    conn = _resolved("db2", tmp_path)
    profile = resolve_session(conn, EffectivePolicy.build(SecurityConfig(), conn))
    assert isinstance(profile, SessionProfile)
    report = profile.as_dict()
    assert report["isolation"] == "ur"
    assert "application_name" in report


# ------------------------------------------------- fail-closed on the other enforced engines
@pytest.mark.parametrize("engine,module_name", [("postgres", "psycopg"), ("mysql", "pymysql")])
def test_read_only_refusal_fails_closed(
    engine: str, module_name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Rec(_Recorder):
        def execute(self, sql: str, *_a: Any, **_k: Any) -> _Rec:
            if "READ ONLY" in sql.upper() or "READ_ONLY" in sql.upper():
                raise RuntimeError("permission denied")
            return super().execute(sql)  # type: ignore[return-value]

    rec = _Rec()
    fake = types.SimpleNamespace(connect=lambda **kw: rec, cursors=types.SimpleNamespace(SSCursor=object))
    conn = _connector(engine, tmp_path, monkeypatch, fake_module=fake, module_name=module_name)
    with pytest.raises(ConnectorError, match="read-only"):
        conn._connect()


def test_mssql_isolation_refusal_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class _Rec(_Recorder):
        def execute(self, sql: str, *_a: Any, **_k: Any) -> _Rec:
            if "ISOLATION" in sql.upper():
                raise RuntimeError("cannot set")
            return super().execute(sql)  # type: ignore[return-value]

    rec = _Rec()
    fake = types.SimpleNamespace(connect=lambda cs, **kw: rec, drivers=lambda: ["ODBC Driver 18 for SQL Server"])
    conn = _connector("mssql", tmp_path, monkeypatch, fake_module=fake, module_name="pyodbc")
    with pytest.raises(ConnectorError, match="isolation"):
        conn._connect()


def test_read_only_verified_reflects_the_server_readback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rec = _Recorder(readback={"row": ("off", "1min", "5s", "udbmcp:prod_postgres", "read committed")})
    fake = types.SimpleNamespace(connect=lambda **kw: rec)
    conn = _connector("postgres", tmp_path, monkeypatch, fake_module=fake, module_name="psycopg")
    health = conn.health_check()
    assert health.session is not None
    assert health.session["read_only_enforced"] is True, "the SET was accepted"
    assert health.session["read_only_verified"] is False, "but the server says off: reported, not hidden"


def test_engines_without_a_lock_ceiling_report_none(tmp_path: Path) -> None:
    for engine in ("oracle", "clickhouse"):
        conn = _resolved(engine, tmp_path)
        assert resolve_session(conn, EffectivePolicy.build(SecurityConfig(), conn)).lock_timeout_seconds is None
