"""Two catalog gaps the round-3 masking design (refuse what cannot be proven)
exposed (2026-10-03):

1. PostgreSQL materialized views: list_columns read information_schema,
   which leaves them out, so every statement over one was refused under the
   default masking patterns, and db_get_table / db_list_columns did not show
   their columns. list_columns and list_all_columns now read them from
   pg_attribute (relkind 'm', in attnum order, dropped columns left out, the
   same privilege rule as information_schema).
2. ClickHouse MATERIALIZED / ALIAS / EPHEMERAL columns: SELECT * leaves them
   out, so the star the analysis proved was wider than the result and the
   statement was refused after it ran. list_columns now reports each column's
   default_kind, and the analysis expands a star to the columns * returns
   while a column named explicitly still resolves.

The unit tests drive the connectors' catalog SQL with fake sessions and the
masking end to end with a fake connector; the live ones create (and drop) a
scratch schema / database on the loopback udbmcp-* fixtures and skip where
those are not running."""

from __future__ import annotations

import contextlib
import os
import re
import socket
import types
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from test_hardening_2026_09_27_server import (
    SECRETS,
    _call,
    _fake_app_server,
    _FakeConnector,
    _refused_or_clean,
)

from universal_db_mcp.config import SecurityConfig, load_resolved
from universal_db_mcp.connectors import clickhouse as ch_module
from universal_db_mcp.connectors import postgres as pg_module
from universal_db_mcp.connectors.base import ColumnInfo, QueryOutcome, QuerySpec, TableSummary
from universal_db_mcp.security.policy import EffectivePolicy
from universal_db_mcp.server import AppContext, build_server

REPO = Path(__file__).resolve().parents[2]


def _resolved(tmp_path: Path, engine: str, port: int) -> Any:
    os.environ.setdefault("UDBMCP_CR3G_USER", "tester")
    cfg = tmp_path / f"{engine}.yaml"
    cfg.write_text(
        "application:\n  transport: stdio\n"
        f"  audit_path: {tmp_path / 'audit.jsonl'}\n  metadata_cache_path: {tmp_path / 'cache.sqlite'}\n"
        "security:\n  require_remote_tls: false\n"
        f"connections:\n  c:\n    type: {engine}\n    host: 127.0.0.1\n    port: {port}\n    database: d\n"
        "    username_env: UDBMCP_CR3G_USER\n",
        encoding="utf-8",
    )
    _app, resolved = load_resolved(cfg)
    return resolved["c"]


# --------------------------------------------- PostgreSQL: catalog SQL (unit)


class _PgMetaConn:
    def __init__(self, rows: list[tuple[Any, ...]]) -> None:
        self.rows = rows
        self.statements: list[tuple[str, Any]] = []

    def execute(self, sql: str, params: Any = None) -> Any:
        self.statements.append((sql, params))
        return types.SimpleNamespace(fetchall=lambda: list(self.rows))


def _pg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, rows: list[tuple[Any, ...]]) -> tuple[Any, _PgMetaConn]:
    resolved = _resolved(tmp_path, "postgres", 5999)
    conn = pg_module.PostgresConnector(resolved, EffectivePolicy.build(SecurityConfig(), resolved))
    meta = _PgMetaConn(rows)

    @contextlib.contextmanager
    def shared() -> Iterator[Any]:
        yield meta

    monkeypatch.setattr(conn, "_shared_meta_conn", shared)
    return conn, meta


def _assert_matview_branch(sql: str) -> None:
    """The statement reads information_schema.columns and, for materialized
    views, pg_attribute: relkind 'm', user columns only, no dropped column,
    the privilege rule information_schema applies, every catalog object and
    function qualified with pg_catalog."""
    assert "information_schema.columns" in sql, sql
    assert "pg_catalog.pg_attribute" in sql and "relkind = 'm'" in sql, sql
    assert "attnum > 0" in sql and "NOT a.attisdropped" in sql, sql
    assert "pg_catalog.has_column_privilege(" in sql and "pg_catalog.pg_has_role(" in sql, sql
    assert "pg_catalog.format_type(" in sql, sql
    called = {m.group(1) for m in re.finditer(r"(?<![\w.])(\w+)\(", sql)}
    unqualified = {f for f in called if f.lower().startswith(("pg_", "has_", "format_"))}
    assert not unqualified, unqualified


def test_pg_list_columns_includes_materialized_views(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rows = [
        ("id", "integer", "YES", None, 1, None, 32, 0),
        ("full_name", "character varying(40)", "YES", None, 2, None, None, None),
        ("ssn", "text", "YES", None, 4, None, None, None),  # attnum 3 a dropped column
    ]
    conn, meta = _pg(tmp_path, monkeypatch, rows)
    cols = conn.list_columns("app", "mv")
    (sql, params), = meta.statements
    _assert_matview_branch(sql)
    assert list(params) == ["app", "mv", "app", "mv"]
    assert sql.rstrip().endswith("ORDER BY 5"), sql
    assert [(c.name, c.data_type, c.ordinal, c.nullable) for c in cols] == [
        ("id", "integer", 1, True), ("full_name", "character varying(40)", 2, True), ("ssn", "text", 4, True),
    ]


def test_pg_list_all_columns_includes_materialized_views(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rows = [("mv", "id", "integer", "NO", None, 1, None, 32, 0), ("t", "ssn", "text", "YES", None, 1, None, None, None)]
    conn, meta = _pg(tmp_path, monkeypatch, rows)
    cols = conn.list_all_columns("app")
    (sql, params), = meta.statements
    _assert_matview_branch(sql)
    assert list(params) == ["app", "app"]
    assert sql.rstrip().endswith("ORDER BY 1, 6"), sql
    assert [(c.table, c.name, c.nullable) for c in cols] == [("mv", "id", False), ("t", "ssn", True)]


# --------------------------------------------- ClickHouse: catalog SQL (unit)


class _ChMetaClient:
    def __init__(self, rows: list[tuple[Any, ...]]) -> None:
        self.rows = rows
        self.queries: list[tuple[str, Any]] = []

    def query(self, sql: str, parameters: Any = None) -> Any:
        self.queries.append((sql, parameters))
        return types.SimpleNamespace(result_rows=list(self.rows))


def _ch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, rows: list[tuple[Any, ...]]) -> tuple[Any, _ChMetaClient]:
    resolved = _resolved(tmp_path, "clickhouse", 5998)
    conn = ch_module.ClickHouseConnector(resolved, EffectivePolicy.build(SecurityConfig(), resolved))
    client = _ChMetaClient(rows)
    monkeypatch.setattr(conn, "_shared_meta_client", lambda: client)
    return conn, client


def test_ch_list_columns_reports_each_columns_default_kind(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rows = [
        ("id", "UInt32", 1, "", ""),
        ("name", "String", 0, "", "DEFAULT"),
        ("card_number", "String", 0, "", "MATERIALIZED"),
        ("name_len", "UInt64", 0, "", "ALIAS"),
        ("raw", "String", 0, "", "EPHEMERAL"),
    ]
    conn, client = _ch(tmp_path, monkeypatch, rows)
    cols = conn.list_columns("d", "t")
    assert "default_kind" in client.queries[0][0]
    assert [(c.name, c.default_kind) for c in cols] == [
        ("id", None), ("name", "DEFAULT"), ("card_number", "MATERIALIZED"), ("name_len", "ALIAS"),
        ("raw", "EPHEMERAL"),
    ]


def test_ch_list_all_columns_reports_each_columns_default_kind(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rows = [("t", "id", "UInt32", "", 1, ""), ("t", "card_number", "String", "", 2, "MATERIALIZED")]
    conn, client = _ch(tmp_path, monkeypatch, rows)
    cols = conn.list_all_columns("d")
    assert "default_kind" in client.queries[0][0]
    assert [(c.name, c.ordinal, c.default_kind) for c in cols] == [("id", 1, None), ("card_number", 2, "MATERIALIZED")]


def test_other_engines_columns_have_no_default_kind() -> None:
    assert ColumnInfo("s", "t", "c", "integer").default_kind is None


# ----------------------------------- masking over ClickHouse's hidden columns


_CH_T = [
    ColumnInfo("d", "t", "id", "UInt32"),
    ColumnInfo("d", "t", "ssn", "String"),
    ColumnInfo("d", "t", "name", "String", default_kind="DEFAULT"),
    ColumnInfo("d", "t", "card_number", "String", default_kind="MATERIALIZED"),
    ColumnInfo("d", "t", "name_len", "UInt64", default_kind="ALIAS"),
    ColumnInfo("d", "t", "raw", "String", default_kind="EPHEMERAL"),
]
_CH_VALUES = {"id": 1, "ssn": SECRETS[0], "name": "Jane", "card_number": SECRETS[1], "name_len": 4, "raw": ""}


class _ChStarFake(_FakeConnector):
    """d.t on a ClickHouse whose driver answers a statement with ``reply``,
    the columns ClickHouse reports for it (live: * leaves out MATERIALIZED,
    ALIAS and EPHEMERAL columns, unless asterisk_include_*_columns is set)."""

    def __init__(self, reply: list[str]) -> None:
        super().__init__([TableSummary("d", "t", "table")], columns=list(_CH_T))
        self.reply = reply

    def execute_query(self, spec: QuerySpec) -> QueryOutcome:
        names = self.reply
        return QueryOutcome(columns=[(n, "String") for n in names], rows=[[_CH_VALUES[n] for n in names]],
                            truncated=False, rows_seen=1, elapsed_ms=0)


@pytest.mark.parametrize(
    ("sql", "names", "masked"),
    [
        ("SELECT * FROM d.t", ["id", "ssn", "name"], {1}),
        ("SELECT b.* FROM d.t b", ["id", "ssn", "name"], {1}),
        ("SELECT b.*, b.card_number FROM d.t b", ["id", "ssn", "name", "card_number"], {1, 3}),
        ("SELECT card_number, id FROM d.t", ["card_number", "id"], {0}),
        ("SELECT name_len, id FROM d.t", ["name_len", "id"], set()),
        ("SELECT x.* FROM (SELECT id, card_number FROM d.t) x", ["id", "card_number"], {1}),
    ],
)
def test_a_clickhouse_star_leaves_out_materialized_alias_and_ephemeral_columns(
    tmp_path: Path, monkeypatch: Any, sql: str, names: list[str], masked: set[int]
) -> None:
    fake = _ChStarFake(names)
    server, _ = _fake_app_server(tmp_path, monkeypatch, fake, engine="clickhouse", allowed=["d"], deny=True)
    env = _call(server, "db_query", {"connection_id": "remote", "sql": sql})
    data = env["data"]
    assert [c["name"] for c in data["columns"]] == names, data
    row = data["rows"][0]
    for i, name in enumerate(names):
        if i in masked:
            assert row[i] != _CH_VALUES[name], (i, row)
        else:
            assert row[i] == _CH_VALUES[name], (i, row)
    assert SECRETS[0] not in str(env) and SECRETS[1] not in str(env)


def test_a_clickhouse_star_the_engine_widens_is_refused_after_it_ran(tmp_path: Path, monkeypatch: Any) -> None:
    """asterisk_include_materialized_columns=1 in the login's profile (a
    statement's SETTINGS clause is refused by the guard) widens *: the result
    no longer has the proven width."""
    fake = _ChStarFake([c.name for c in _CH_T if c.default_kind != "EPHEMERAL"])
    server, _ = _fake_app_server(tmp_path, monkeypatch, fake, engine="clickhouse", allowed=["d"], deny=True)
    text = _refused_or_clean(server, {"connection_id": "remote", "sql": "SELECT * FROM d.t"})
    assert text is not None and "masking cannot place them" in text, text


def test_db_list_columns_shows_every_clickhouse_column_with_its_kind(tmp_path: Path, monkeypatch: Any) -> None:
    fake = _ChStarFake([])
    server, _ = _fake_app_server(tmp_path, monkeypatch, fake, engine="clickhouse", allowed=["d"], deny=True)
    env = _call(server, "db_list_columns", {"connection_id": "remote", "object_name": "t", "schema": "d"})
    assert [(c["name"], c["default_kind"]) for c in env["data"]["columns"]] == [
        (c.name, c.default_kind) for c in _CH_T
    ]


# ------------------------- masking over a PostgreSQL materialized view (fake)


class _PgMatviewFake(_FakeConnector):
    def __init__(self) -> None:
        super().__init__([TableSummary("app", "mv", "materialized_view")], columns=[
            ColumnInfo("app", "mv", "customer_id", "integer"),
            ColumnInfo("app", "mv", "full_name", "text"),
            ColumnInfo("app", "mv", "ssn", "text"),
        ])

    def execute_query(self, spec: QuerySpec) -> QueryOutcome:
        if "*" in spec.sql:
            cols, row = ["customer_id", "full_name", "ssn"], [1, "Jane", SECRETS[2]]
        else:
            cols, row = ["customer_id", "full_name"], [1, "Jane"]
        return QueryOutcome(columns=[(c, "text") for c in cols], rows=[row], truncated=False, rows_seen=1,
                            elapsed_ms=0)


def test_a_materialized_view_whose_columns_are_listed_is_masked_not_refused(
    tmp_path: Path, monkeypatch: Any
) -> None:
    server, _ = _fake_app_server(tmp_path, monkeypatch, _PgMatviewFake(), engine="postgres", allowed=["app"],
                                 deny=True)
    env = _call(server, "db_query", {"connection_id": "remote", "sql": "SELECT * FROM app.mv"})
    row = env["data"]["rows"][0]
    assert row[:2] == [1, "Jane"] and row[2] != SECRETS[2], row
    env = _call(server, "db_query", {"connection_id": "remote", "sql": "SELECT customer_id, full_name FROM app.mv"})
    assert env["data"]["rows"] == [[1, "Jane"]]


# ------------------------------------------------- live PostgreSQL (5433)


def _reachable(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            return True
    except OSError:
        return False


def _live_server(tmp_path: Path, engine: str, port: int, database: str, user_env: str, user: str, secret: Path,
                 allowed: str) -> Any:
    os.environ.setdefault(user_env, user)
    cfg = tmp_path / "live.yaml"
    cfg.write_text(
        "application:\n  transport: stdio\n"
        f"  audit_path: {tmp_path / 'audit.jsonl'}\n  metadata_cache_path: {tmp_path / 'cache.sqlite'}\n"
        "security:\n  max_concurrent_queries: 4\n  require_remote_tls: false\n  default_deny_objects: true\n"
        f"connections:\n  live:\n    type: {engine}\n    host: 127.0.0.1\n    port: {port}\n"
        f"    database: {database}\n    username_env: {user_env}\n    password_file: {secret}\n"
        f"    read_only: true\n    allowed_schemas: [{allowed}]\n",
        encoding="utf-8",
    )
    app_cfg, resolved = load_resolved(cfg)
    return build_server(AppContext(app_cfg, resolved))


def test_live_postgres_materialized_view(tmp_path: Path) -> None:
    secret = REPO / "out" / "mockdb-secrets" / "pg.pw"
    if not _reachable(5433) or not secret.is_file():
        pytest.skip("the loopback PostgreSQL fixture (127.0.0.1:5433) is not running")
    psycopg = pytest.importorskip("psycopg")
    password = secret.read_text(encoding="utf-8").strip()
    schema = f"udbmcp_cr3_mv_{os.getpid()}"
    # the fixture's superuser (scripts/fixtures/start_mock_dbs.sh) creates the
    # scratch schema; the read-only login reads it through the server
    admin = psycopg.connect(host="127.0.0.1", port=5433, dbname="postgres", user="postgres", password=password,
                            autocommit=True, connect_timeout=5)
    try:
        admin.execute(f"SET statement_timeout = '10s'; CREATE SCHEMA {schema}")
        admin.execute(
            f"CREATE TABLE {schema}.src (id int, gone int, full_name text, ssn text);"
            f"INSERT INTO {schema}.src VALUES (1, 0, 'Jane', '{SECRETS[0]}'), (2, 0, 'Omar', '{SECRETS[1]}');"
            f"ALTER TABLE {schema}.src DROP COLUMN gone;"
            f"CREATE MATERIALIZED VIEW {schema}.mv AS SELECT id, full_name, ssn FROM {schema}.src;"
            f"CREATE MATERIALIZED VIEW {schema}.hidden_mv AS SELECT id FROM {schema}.src;"
            f"GRANT USAGE ON SCHEMA {schema} TO udbmcp_ro; GRANT SELECT ON {schema}.mv TO udbmcp_ro;"
        )
        server = _live_server(tmp_path, "postgres", 5433, "postgres", "UDBMCP_DEMO_PG_USER", "udbmcp_ro", secret,
                              schema)
        args = {"connection_id": "live", "object_name": "mv", "schema": schema}
        listed = _call(server, "db_list_columns", args)["data"]["columns"]
        assert [(c["name"], c["ordinal"]) for c in listed] == [("id", 1), ("full_name", 2), ("ssn", 3)], listed
        detail = _call(server, "db_get_table", args)["data"]
        assert [c["name"] for c in detail["columns"]] == ["id", "full_name", "ssn"], detail
        env = _call(server, "db_query", {"connection_id": "live", "sql": f"SELECT * FROM {schema}.mv ORDER BY id"})
        rows = env["data"]["rows"]
        assert [r[:2] for r in rows] == [[1, "Jane"], [2, "Omar"]], rows
        assert all(r[2] not in SECRETS for r in rows), rows
        env = _call(server, "db_query", {"connection_id": "live",
                                         "sql": f"SELECT m.id, upper(m.ssn) AS s FROM {schema}.mv m ORDER BY 1"})
        assert [r[0] for r in env["data"]["rows"]] == [1, 2], env
        assert SECRETS[0] not in str(env) and SECRETS[1] not in str(env)
        env = _call(server, "db_query", {"connection_id": "live",
                                         "sql": f"SELECT id, full_name FROM {schema}.mv ORDER BY id"})
        assert env["data"]["rows"] == [[1, "Jane"], [2, "Omar"]]
        # a materialized view the login may not read lists no columns, as
        # information_schema lists none of a table it may not read
        resolved = load_resolved(tmp_path / "live.yaml")[1]["live"]
        conn = pg_module.PostgresConnector(resolved, EffectivePolicy.build(SecurityConfig(), resolved))
        try:
            assert conn.list_columns(schema, "hidden_mv") == []
            assert [c.name for c in conn.list_columns(schema, "mv")] == ["id", "full_name", "ssn"]
            assert [c.name for c in conn.list_all_columns(schema) if c.table == "mv"] == ["id", "full_name", "ssn"]
        finally:
            conn.close()
    finally:
        admin.execute(f"DROP SCHEMA IF EXISTS {schema} CASCADE")
        admin.close()


# -------------------------------------------------- live ClickHouse (8124)


def test_live_clickhouse_hidden_columns(tmp_path: Path) -> None:
    secret = REPO / "out" / "mockdb-secrets" / "clickhouse.pw"
    if not _reachable(8124) or not secret.is_file():
        pytest.skip("the loopback ClickHouse fixture (127.0.0.1:8124) is not running")
    clickhouse_connect = pytest.importorskip("clickhouse_connect")
    password = secret.read_text(encoding="utf-8").strip()
    db = f"udbmcp_cr3_ch_{os.getpid()}"
    capped = {"max_memory_usage": 268435456, "max_execution_time": 20}
    admin = clickhouse_connect.get_client(host="127.0.0.1", port=8124, username="default", password=password,
                                          settings=capped, connect_timeout=5)
    try:
        admin.command(f"CREATE DATABASE {db}")
        admin.command(
            f"CREATE TABLE {db}.t (id UInt32, ssn String, name String DEFAULT 'x', "
            "card_number String MATERIALIZED concat('4111-', ssn), name_len UInt64 ALIAS length(name), "
            "raw String EPHEMERAL '') ENGINE = MergeTree ORDER BY id"
        )
        admin.command(f"INSERT INTO {db}.t (id, ssn, name) VALUES (1, '{SECRETS[0]}', 'Jane'), "
                      f"(2, '{SECRETS[1]}', 'Omar')")
        server = _live_server(tmp_path, "clickhouse", 8124, "default", "UDBMCP_DEMO_CH_USER", "default", secret, db)
        listed = _call(server, "db_list_columns", {"connection_id": "live", "object_name": "t", "schema": db})
        assert [(c["name"], c["default_kind"]) for c in listed["data"]["columns"]] == [
            ("id", None), ("ssn", None), ("name", "DEFAULT"), ("card_number", "MATERIALIZED"),
            ("name_len", "ALIAS"), ("raw", "EPHEMERAL"),
        ], listed
        cases = [
            (f"SELECT * FROM {db}.t ORDER BY id", ["id", "ssn", "name"], {1}),
            (f"SELECT b.*, b.card_number FROM {db}.t b ORDER BY id", ["id", "ssn", "name", "card_number"], {1, 3}),
            (f"SELECT name_len, id FROM {db}.t ORDER BY id", ["name_len", "id"], set()),
            (f"SELECT card_number FROM {db}.t ORDER BY id", ["card_number"], {0}),
        ]
        for sql, names, masked in cases:
            env = _call(server, "db_query", {"connection_id": "live", "sql": sql})
            data = env["data"]
            assert [c["name"].split(".")[-1] for c in data["columns"]] == names, (sql, data)
            assert len(data["rows"]) == 2, data
            for row in data["rows"]:
                for i in masked:
                    assert not any(s in str(row[i]) for s in SECRETS), (sql, row)
            if not masked:
                assert data["rows"] == [[4, 1], [4, 2]], data
            assert SECRETS[0] not in str(env) and SECRETS[1] not in str(env), sql
        # a statement cannot widen * itself: the guard refuses its SETTINGS
        with pytest.raises(Exception, match="SETTINGS clauses are not permitted"):
            widened = f"SELECT * FROM {db}.t ORDER BY id SETTINGS asterisk_include_materialized_columns=1"
            _call(server, "db_query", {"connection_id": "live", "sql": widened})
    finally:
        admin.command(f"DROP DATABASE IF EXISTS {db} SYNC")
        admin.close()
