"""Discovery surface on the connectors: index listing, bulk columns, and
the per-engine top-values wrapper. Fakes feed the exact row shapes the
catalog queries return (verified live 2026-09-16 on PostgreSQL 17, MySQL 9.7,
ClickHouse 26, Oracle 23ai, Db2 11.5.9)."""

from __future__ import annotations

import sys
import types
from pathlib import Path
from typing import Any

import pytest
from helpers_session import SessionHandle

from universal_db_mcp.config import ConnectionConfig, ResolvedConnection, SecurityConfig
from universal_db_mcp.security.policy import EffectivePolicy


def _resolved(engine: str, tmp_path: Path) -> ResolvedConnection:
    body: dict[str, Any] = {"type": engine, "database": "d"}
    if engine != "sqlite":
        body["host"] = "h"
        u = tmp_path / f"{engine}.u"
        u.write_text("u\n")
        u.chmod(0o600)
        body["username_file"] = str(u)
    return ResolvedConnection("c", ConnectionConfig.model_validate(body))


class _RowsHandle(SessionHandle):
    """A handle whose every query answers with the configured rows."""

    def __init__(self, rows: list[tuple[Any, ...]]) -> None:
        super().__init__()
        object.__setattr__(self, "rows", rows)

    def fetchall(self) -> list[Any]:
        return list(self.rows)


def test_postgres_indexes_group_columns_and_flag_primary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from universal_db_mcp.connectors import postgres
    rows = [
        ("orders", "orders_pkey", True, True, "id", 1, "btree", "CREATE UNIQUE INDEX ..."),
        ("orders", "orders_cust_idx", False, False, "customer_id", 1, "btree", "CREATE INDEX ..."),
        ("orders", "orders_cust_idx", False, False, "created_at", 2, "btree", "CREATE INDEX ..."),
    ]
    handle = _RowsHandle(rows)
    monkeypatch.setattr(postgres, "open_module", lambda *_a, **_k: types.SimpleNamespace(connect=lambda **kw: handle))
    monkeypatch.setitem(sys.modules, "psycopg", types.ModuleType("psycopg"))
    r = _resolved("postgres", tmp_path)
    conn = postgres.PostgresConnector(r, EffectivePolicy.build(SecurityConfig(), r))

    idx = conn.list_indexes("public", "orders")

    by_name = {i.name: i for i in idx}
    assert by_name["orders_pkey"].primary and by_name["orders_pkey"].unique
    assert by_name["orders_cust_idx"].columns == ["customer_id", "created_at"]
    assert by_name["orders_cust_idx"].kind == "btree"


def test_mysql_primary_index_is_named_PRIMARY(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from universal_db_mcp.connectors import mysql
    rows = [("t", "PRIMARY", 0, "id", 1, "BTREE"), ("t", "ix_a", 1, "a", 1, "BTREE")]
    handle = _RowsHandle(rows)
    fake = types.SimpleNamespace(connect=lambda **kw: handle, cursors=types.SimpleNamespace(SSCursor=object))
    monkeypatch.setattr(mysql, "open_module", lambda *_a, **_k: fake)
    monkeypatch.setitem(sys.modules, "pymysql", types.ModuleType("pymysql"))
    r = _resolved("mysql", tmp_path)
    conn = mysql.MySQLConnector(r, EffectivePolicy.build(SecurityConfig(), r))

    idx = {i.name: i for i in conn.list_indexes("d", "t")}
    assert idx["PRIMARY"].primary and idx["PRIMARY"].unique
    assert not idx["ix_a"].unique


def test_db2_uniquerule_maps_to_primary_and_unique_and_names_are_trimmed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from universal_db_mcp.connectors import db2
    rows = [
        ("CITIZENS  ", "SQL1  ", "P", "CITIZEN_ID ", 1, "REG "),
        ("CITIZENS  ", "SQL2  ", "U", "NATIONAL_ID", 1, "REG "),
    ]

    class _Fake:
        def connect(self, *a: Any, **k: Any) -> str: return "h"
        def exec_immediate(self, c: str, sql: str) -> str: return "stmt"
        def prepare(self, c: str, sql: str) -> str: return "stmt"
        def execute(self, stmt: str, params: Any) -> bool: return True
        def __init__(self) -> None: self._rows = list(rows)
        def fetch_tuple(self, stmt: str) -> Any: return self._rows.pop(0) if self._rows else False
        def close(self, c: str) -> bool: return True

    monkeypatch.setattr(db2, "open_module", lambda *_a, **_k: _Fake())
    monkeypatch.setitem(sys.modules, "ibm_db_dbi", types.ModuleType("ibm_db_dbi"))
    r = _resolved("db2", tmp_path)
    conn = db2.Db2Connector(r, EffectivePolicy.build(SecurityConfig(), r))

    idx = conn.list_indexes("MOI", None)
    assert [i.table for i in idx] == ["CITIZENS", "CITIZENS"], "SYSCAT padding must be trimmed"
    assert idx[0].primary and idx[0].unique and idx[0].columns == ["CITIZEN_ID"]
    assert idx[1].unique and not idx[1].primary


def test_sqlite_lists_primary_key_and_indexes(tmp_path: Path) -> None:
    import sqlite3

    from universal_db_mcp.connectors import sqlite as sq
    db = tmp_path / "t.db"
    c = sqlite3.connect(db)
    c.execute("CREATE TABLE customers (id INTEGER PRIMARY KEY, email TEXT, region TEXT)")
    c.execute("CREATE UNIQUE INDEX ix_email ON customers(email)")
    c.execute("CREATE INDEX ix_region ON customers(region)")
    c.commit()
    c.close()
    cfg = ConnectionConfig.model_validate({"type": "sqlite", "database": str(db)})
    r = ResolvedConnection("s", cfg)
    conn = sq.SQLiteConnector(r, EffectivePolicy.build(SecurityConfig(), r))

    idx = {i.name: i for i in conn.list_indexes(None, "customers")}
    assert idx["(primary key)"].primary and idx["(primary key)"].columns == ["id"]
    assert idx["ix_email"].unique and not idx["ix_email"].primary
    assert idx["ix_region"].columns == ["region"]


@pytest.mark.parametrize(
    ("engine", "expected"),
    [
        ("postgres", 'ORDER BY cnt DESC LIMIT 3'),
        ("mysql", 'ORDER BY cnt DESC LIMIT 3'),
        ("clickhouse", 'ORDER BY cnt DESC LIMIT 3'),
        ("db2", 'ORDER BY cnt DESC FETCH FIRST 3 ROWS ONLY'),
        ("oracle", 'WHERE ROWNUM <= 3'),
        ("mssql", 'SELECT TOP 3 '),
    ],
)
def test_top_values_query_uses_each_engines_limit_syntax(engine: str, expected: str, tmp_path: Path) -> None:
    from universal_db_mcp.connectors import registry
    r = _resolved(engine, tmp_path)
    conn = registry.build_connector(r, EffectivePolicy.build(SecurityConfig(), r))
    sql = conn.build_top_values_query("SELECT x FROM t", "x", 3)
    assert expected in sql, sql
    assert "IS NOT NULL" in sql and "GROUP BY" in sql


def test_length_substring_and_like_builders_per_engine(tmp_path: Path) -> None:
    """Character (not byte) length everywhere; LIKE wildcards in the query
    text are escaped so '100%' finds the literal string."""
    from universal_db_mcp.connectors import registry
    conns = {}
    for engine in ("postgres", "mysql", "mssql", "oracle", "db2", "clickhouse", "sqlite"):
        r = _resolved(engine, tmp_path)
        conns[engine] = registry.build_connector(r, EffectivePolicy.build(SecurityConfig(), r))
    assert conns["mssql"].length_expression("c") == "LEN(c)"
    assert conns["mysql"].length_expression("c") == "CHAR_LENGTH(c)"
    assert conns["db2"].length_expression("c") == "CHARACTER_LENGTH(c, CODEUNITS32)"
    assert conns["clickhouse"].length_expression("c") == "lengthUTF8(c)"
    assert conns["postgres"].length_expression("c") == "LENGTH(c)"
    assert conns["mssql"].substring_expression("c", 200) == "SUBSTRING(c, 1, 200)"
    assert conns["oracle"].substring_expression("c", 200) == "SUBSTR(c, 1, 200)"
    assert conns["db2"].substring_expression("c", 200) == (
        "SUBSTR(c, 1, CASE WHEN LENGTH(c) < 200 THEN LENGTH(c) ELSE 200 END)"
    )  # Db2 raises SQL0138N when the length argument exceeds the value
    assert conns["postgres"].escape_like("100%_x\\y") == "100\\%\\_x\\\\y"
    assert conns["mssql"].escape_like("a[b]%") == "a\\[b]\\%"
    assert conns["postgres"].like_predicate("LOWER(c)", "%s") == "LOWER(c) LIKE %s ESCAPE '\\'"
    assert conns["clickhouse"].like_predicate("lower(c)", "%(p1)s") == "lower(c) LIKE %(p1)s"
