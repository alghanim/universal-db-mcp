"""Connector fixes from the /code-review max pass (2026-10-02).

- X1: a SQLite deadline that fires before the statement starts (during the
  LIMIT 0 probe or the select-list rewrite) still stops it: the cancel is
  remembered by the connector and every handle checks it, so the worker
  returns and the connection is not refused until a restart.
- A5: an output SQLite groups or orders by position under any spelling
  ('(2)', '2 COLLATE x', '0x2') is never cut in the engine; a constant
  GROUP BY/ORDER BY term that is not plainly a position cuts nothing.
- A6: FTS5 reads PRAGMA data_version on every query; the authorizer allows it.
- A7: the internal (shadow) tables of FTS3/4/5 and R*Tree indexes hold the
  indexed values under generic names (c0, c1ssn): they are not listed, not
  described and not readable, so masking by name cannot be sidestepped.
- E2: the Db2 LOB-capping rewrite keeps the statement's order with ORDER BY
  ORDER OF only when the statement has an ORDER BY of its own (Db2 raises
  SQLSTATE 428FI for ORDER OF a nested table expression without one).
- E3: SQL Server's TEXTSIZE cuts a (max) value at a byte count, which can
  split a UTF-16 surrogate pair; the query no longer fails to decode it.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import threading
import time
from contextlib import closing
from pathlib import Path
from typing import Any

import anyio
import pytest
import sqlglot
from helpers_sqlite import connector_reads_fts
from test_hardening_2026_09_27_connectors_sql import _Col, _FakeMssqlConn, _mssql, _MssqlScript, _ora_exec, _Rows

from universal_db_mcp.config import ConnectionConfig, ResolvedConnection, SecurityConfig, load_resolved
from universal_db_mcp.connectors import mssql as mssql_module
from universal_db_mcp.connectors import sqlite as sqlite_module
from universal_db_mcp.connectors.base import ConnectorError, ObjectNotFound, QuerySpec
from universal_db_mcp.connectors.db2 import _db2_capped_select
from universal_db_mcp.connectors.sqlite import SQLiteConnector, _compared_outputs
from universal_db_mcp.errors import ToolFailure
from universal_db_mcp.models.responses import ErrorCategory
from universal_db_mcp.security.policy import EffectivePolicy
from universal_db_mcp.server import AppContext, build_server
from universal_db_mcp.services.executor import ExecutionService

_PREFIX = "p" * 20000  # two long values that differ only past the cell limit
# Counts to 30 million: seconds of work, so a statement nothing stops is
# still running when the test looks, and ends by itself if the fix is absent.
_LONG = "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 30000000) SELECT count(*) AS n FROM c"


def _connector(db: Path) -> SQLiteConnector:
    resolved = ResolvedConnection("t", ConnectionConfig.model_validate({"type": "sqlite", "database": str(db)}))
    return SQLiteConnector(resolved, EffectivePolicy.build(SecurityConfig(), resolved))


def _docs(tmp_path: Path) -> SQLiteConnector:
    db = tmp_path / "docs.db"
    with closing(sqlite3.connect(db)) as c:
        c.execute("CREATE TABLE docs (id INTEGER PRIMARY KEY, body TEXT)")
        c.executemany("INSERT INTO docs VALUES (?, ?)", [(1, _PREFIX + "b"), (2, _PREFIX + "a"), (3, "tiny")])
        c.commit()
    return _connector(db)


# ---- X1 ---------------------------------------------------------------------


def _slow_rewrite(monkeypatch: pytest.MonkeyPatch, entered: threading.Event, release: threading.Event) -> None:
    """The select-list rewrite (sqlglot, then the LIMIT 0 probe) waits for
    the test: the window between the handle's open and the statement's start."""
    real = SQLiteConnector._value_capped

    def slow(self: SQLiteConnector, conn: sqlite3.Connection, sql: str, parameters: Any, *rest: Any) -> str | None:
        entered.set()
        release.wait(10)
        return real(self, conn, sql, parameters, *rest)

    monkeypatch.setattr(SQLiteConnector, "_value_capped", slow)


def test_x1_a_cancel_before_the_statement_starts_still_stops_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    conn = _docs(tmp_path)
    entered, release = threading.Event(), threading.Event()
    _slow_rewrite(monkeypatch, entered, release)
    outcome: dict[str, Any] = {}

    def run() -> None:
        try:
            outcome["result"] = conn.execute_query(QuerySpec(sql=_LONG))
        except Exception as exc:  # noqa: BLE001 - the test reads it
            outcome["error"] = exc

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    assert entered.wait(5)
    assert conn.cancel_current() is True, "the cancel is taken even before the statement starts"
    release.set()
    started = time.monotonic()
    worker.join(5)
    assert not worker.is_alive(), "the statement ran on although it was cancelled"
    assert time.monotonic() - started < 2
    assert isinstance(outcome.get("error"), ConnectorError), outcome


def test_x1_a_cancel_during_the_probe_never_runs_the_statement_uncut(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The LIMIT 0 probe swallows its own error (the statement as written
    reports it); an interrupt that lands there must not let the statement
    then run in full."""
    conn = _docs(tmp_path)
    ran: list[str] = []
    real_open = SQLiteConnector._open

    def tracing(self: SQLiteConnector) -> sqlite3.Connection:
        handle = real_open(self)
        handle.set_trace_callback(ran.append)
        return handle

    monkeypatch.setattr(SQLiteConnector, "_open", tracing)
    real_probe = sqlite_module._describe_probe

    def probe(select: Any) -> str | None:
        conn.cancel_current()
        return real_probe(select)

    monkeypatch.setattr(sqlite_module, "_describe_probe", probe)
    with pytest.raises(ConnectorError):
        conn.execute_query(QuerySpec(sql="SELECT id, body FROM docs"))
    assert not any(s.startswith("SELECT id, body FROM docs") and "LIMIT 0" not in s for s in ran), ran


@pytest.mark.anyio
async def test_x1_a_deadline_in_the_rewrite_window_stops_the_worker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, anyio_backend: str
) -> None:
    """Through the executor: the deadline fires while the statement is being
    rewritten; the worker returns at once, so the connection is not left
    refused behind an abandoned worker."""
    conn = _docs(tmp_path)
    real = SQLiteConnector._value_capped

    def slow(self: SQLiteConnector, handle: sqlite3.Connection, sql: str, parameters: Any, *rest: Any) -> str | None:
        time.sleep(0.6)
        return real(self, handle, sql, parameters, *rest)

    monkeypatch.setattr(SQLiteConnector, "_value_capped", slow)
    svc = ExecutionService(max_concurrent=4)
    with pytest.raises(ToolFailure) as info:
        await svc.run_bounded(conn, lambda c: c.execute_query(QuerySpec(sql=_LONG)), 0.2, description="db_query")
    assert info.value.category == ErrorCategory.TIMEOUT
    assert "cancellation was issued" in str(info.value), str(info.value)
    deadline = time.monotonic() + 3
    while svc.has_live_worker(conn) and time.monotonic() < deadline:  # noqa: ASYNC110 - a worker thread, no event
        await anyio.sleep(0.05)
    assert not svc.has_live_worker(conn), "the worker still runs the statement"


def test_x1_a_cancelled_connector_runs_no_metadata_statement_either(tmp_path: Path) -> None:
    conn = _docs(tmp_path)
    assert conn.cancel_current() is True
    with pytest.raises(sqlite3.OperationalError, match="interrupted"):
        conn.list_tables(None, {"table"}, None)


def test_x1_sql_server_a_cancel_while_the_statement_is_described_stops_it(monkeypatch: pytest.MonkeyPatch) -> None:
    """The same class on SQL Server: Cursor.cancel() reaches only a running
    statement, and the statement is described (sp_describe_first_result_set)
    before it runs."""
    script = _MssqlScript(rows=[(1,)])
    conn = _mssql(monkeypatch, script)

    def described(cur: Any, sql: str, params: Any) -> str:
        conn.cancel_current()
        return sql

    monkeypatch.setattr(conn, "_xml_cast", described)
    with pytest.raises(ConnectorError) as info:
        conn.execute_query(QuerySpec(sql="SELECT v FROM t"))
    assert info.value.category == ErrorCategory.TIMEOUT
    assert not any(isinstance(e, tuple) and e[1] == "SELECT v FROM t" for e in script.log), script.log


def test_x1_oracle_a_cancel_before_the_statement_starts_stops_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _Rows([(1,)], [_Col("N", int)])
    conn = _ora_exec(tmp_path, monkeypatch, state)

    def checked(handle: Any, sql: str) -> None:
        conn.cancel_current()  # the deadline fires during the round trip before the statement

    monkeypatch.setattr(conn, "_refuse_shadowed_dual", checked)
    with pytest.raises(ConnectorError) as info:
        conn.execute_query(QuerySpec(sql="SELECT n FROM t"))
    assert info.value.category == ErrorCategory.TIMEOUT
    assert ("SELECT n FROM t", None) not in state.statements, state.statements


# ---- A5 ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("sql", "expected"),
    [
        ("SELECT count(*), body FROM docs WHERE id < 3 GROUP BY (2)", [1, 1]),
        ("SELECT count(*), body FROM docs WHERE id < 3 GROUP BY 2 COLLATE binary", [1, 1]),
        ("SELECT count(*), body FROM docs WHERE id < 3 GROUP BY ((2))", [1, 1]),
        ("SELECT count(*), body FROM docs WHERE id < 3 GROUP BY 0x2", [1, 1]),
        ("SELECT id, body FROM docs WHERE id < 3 ORDER BY (2)", [2, 1]),
        ("SELECT id, body FROM docs WHERE id < 3 ORDER BY 2 COLLATE nocase", [2, 1]),
        ("SELECT id, body FROM docs WHERE id < 3 ORDER BY (2) COLLATE binary, 1", [2, 1]),
        ("SELECT id, body FROM docs WHERE id < 3 ORDER BY +2", [2, 1]),
        ("SELECT id, body FROM docs WHERE id < 3 ORDER BY 0x2", [2, 1]),
    ],
)
def test_a5_a_position_under_any_spelling_is_compared_whole(tmp_path: Path, sql: str, expected: list[int]) -> None:
    conn = _docs(tmp_path)
    assert [row[0] for row in conn.execute_query(QuerySpec(sql=sql)).rows] == expected


@pytest.mark.parametrize("term", ["2", "(2)", "+2", "2 COLLATE nocase", "((2)) COLLATE binary"])
def test_a5_every_spelling_of_a_position_is_read_as_one(term: str) -> None:
    for clause in ("ORDER BY", "GROUP BY"):
        tree = sqlglot.parse_one(f"SELECT a, b FROM t {clause} {term}", read="sqlite")
        assert _compared_outputs(tree, ["a", "b"]) == {1}, clause  # type: ignore[arg-type]


@pytest.mark.parametrize("term", ["'2'", "2.0", "CAST(2 AS INT)", "NULL", "random()", "(SELECT 2)"])
def test_a5_a_constant_term_that_is_no_position_compares_no_output(term: str) -> None:
    """SQLite 3.50, live: only an integer literal is a position (0x2 and
    -(-2) included, see test_cr2_sqlite); these sort or group by a value,
    so every output may still be cut (review round 2: ORDER BY random()
    refused a large table that the cut served)."""
    for clause in ("ORDER BY", "GROUP BY"):
        tree = sqlglot.parse_one(f"SELECT a, b FROM t {clause} {term}", read="sqlite")
        assert _compared_outputs(tree, ["a", "b"]) == set(), clause  # type: ignore[arg-type]


def test_a5_column_terms_still_let_the_other_outputs_be_cut() -> None:
    tree = sqlglot.parse_one("SELECT a, b FROM t ORDER BY a COLLATE nocase, 1", read="sqlite")
    assert _compared_outputs(tree, ["a", "b"]) == {0}  # type: ignore[arg-type]


# ---- A6 / A7 ------------------------------------------------------------------


def _fts(tmp_path: Path) -> Path:
    db = tmp_path / "fts.db"
    with closing(sqlite3.connect(db)) as c:
        c.executescript(
            """
            CREATE TABLE people (id INTEGER PRIMARY KEY, name TEXT, ssn TEXT);
            INSERT INTO people VALUES (1, 'ann', '123-45-6789');
            CREATE VIRTUAL TABLE people_fts USING fts5(name, ssn);
            INSERT INTO people_fts VALUES ('ann', '123-45-6789');
            CREATE VIRTUAL TABLE people_fts4 USING fts4(name, ssn);
            INSERT INTO people_fts4 VALUES ('ann', '123-45-6789');
            CREATE VIRTUAL TABLE boxes USING rtree(id, x0, x1);
            INSERT INTO boxes VALUES (1, 0, 1);
            """
        )
        c.commit()
    return db


_SHADOWS = [
    "people_fts_content", "people_fts_data", "people_fts_idx", "people_fts_docsize", "people_fts_config",
    "people_fts4_content", "people_fts4_segments", "people_fts4_segdir", "people_fts4_docsize", "people_fts4_stat",
    "boxes_node", "boxes_rowid", "boxes_parent",
]


@pytest.mark.skipif(
    not connector_reads_fts(),
    reason="this SQLite build cannot build FTS tables under the connector's authorizer (no module, or SQLite "
    "3.40's constructor check): MATCH is refused there by design",
)
def test_a6_an_fts5_query_is_authorized(tmp_path: Path) -> None:
    conn = _connector(_fts(tmp_path))
    out = conn.execute_query(QuerySpec(sql="SELECT name FROM people_fts WHERE people_fts MATCH 'ann'"))
    assert out.rows == [["ann"]]
    out = conn.execute_query(QuerySpec(sql="SELECT name FROM people_fts4 WHERE people_fts4 MATCH 'ann'"))
    assert out.rows == [["ann"]]


def test_a7_shadow_tables_are_not_listed_or_described(tmp_path: Path) -> None:
    conn = _connector(_fts(tmp_path))
    names = {t.name for t in conn.list_tables(None, set(), None)}
    assert {"people", "people_fts", "people_fts4", "boxes"} <= names
    assert not names & set(_SHADOWS), names & set(_SHADOWS)
    for name in ("people_fts_content", "PEOPLE_FTS4_CONTENT", "boxes_node"):
        with pytest.raises(ObjectNotFound):
            conn.get_table("main", name)
        assert conn.list_columns("main", name) == []


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT c1 FROM people_fts_content",
        "SELECT * FROM 'people_fts4_content'",
        'SELECT * FROM main."PEOPLE_FTS4_CONTENT"',
        "SELECT * FROM [people_fts_data]",
        "SELECT p.id FROM people p JOIN people_fts4_content s ON s.docid = p.id",
        "SELECT (SELECT c1ssn FROM `people_fts4_content`) AS x",
        "SELECT * FROM boxes_node",
    ],
)
def test_a7_shadow_tables_cannot_be_read(tmp_path: Path, sql: str) -> None:
    conn = _connector(_fts(tmp_path))
    with pytest.raises(ConnectorError) as info:
        conn.execute_query(QuerySpec(sql=sql))
    assert info.value.category == "QUERY_ERROR"
    assert "internal table" in str(info.value), str(info.value)


def test_a7_shadow_names_without_the_engine_marking_them() -> None:
    """A SQLite build that lacks the module reports its shadow tables as
    plain tables: they are known by name (the virtual table's own name, '_',
    one of that module's suffixes; see test_cr2_sqlite for the rest)."""
    lacking: frozenset[str] = frozenset()
    assert sqlite_module._unmarked_shadow("docs_content", "fts4", lacking)
    assert sqlite_module._unmarked_shadow("docs_segdir", "fts4", lacking)
    assert not sqlite_module._unmarked_shadow("docs_archive", "fts4", lacking)
    assert not sqlite_module._unmarked_shadow("other_content", None, lacking)  # 'other' is no virtual table


def test_a7_masked_values_do_not_leak_through_shadow_tables_end_to_end(tmp_path: Path) -> None:
    db = _fts(tmp_path)
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "application:\n  transport: stdio\n"
        f"  audit_path: {tmp_path / 'audit.jsonl'}\n"
        f"  metadata_cache_path: {tmp_path / 'cache.sqlite'}\n"
        "security:\n  mask_columns: ['(?i)ssn']\n"
        f"connections:\n  fts:\n    type: sqlite\n    database: {db}\n",
        encoding="utf-8",
    )
    app_cfg, resolved = load_resolved(cfg)
    server = build_server(AppContext(app_cfg, resolved))

    def call(name: str, args: dict[str, Any]) -> str:
        """The tool's response, or the error it raised, as text."""
        try:
            result = asyncio.run(server.call_tool(name, args))
        except Exception as exc:  # noqa: BLE001 - a refusal is an answer here
            return f"refused: {exc}"
        assert result.structured_content is not None
        return json.dumps(result.structured_content)

    for sql in ("SELECT c1 FROM people_fts_content", "SELECT c1ssn FROM people_fts4_content",
                "SELECT * FROM 'people_fts_content'", "SELECT ssn FROM people_fts WHERE people_fts MATCH 'ann'"):
        text = call("db_query", {"connection_id": "fts", "sql": sql})
        assert "123-45-6789" not in text, (sql, text)
    match = "SELECT name FROM people_fts WHERE people_fts MATCH 'ann'"
    if connector_reads_fts():  # see helpers_sqlite: SQLite 3.40 refuses every MATCH
        assert '"ann"' in call("db_query", {"connection_id": "fts", "sql": match})
    for table in ("people_fts_content", "people_fts4_content"):
        text = call("db_sample_table", {"connection_id": "fts", "object_name": table})
        assert text.startswith("refused") and "123-45-6789" not in text, (table, text)
    tables = json.loads(call("db_list_tables", {"connection_id": "fts"}))["data"]["tables"]
    assert not {t["name"] for t in tables} & set(_SHADOWS)


# ---- E2 ---------------------------------------------------------------------

_LOB = [("ID", "int"), ("DOC", "clob")]


@pytest.mark.parametrize(
    ("sql", "ordered"),
    [
        ("SELECT id, doc FROM t", False),
        ("SELECT id, doc FROM t FETCH FIRST 5 ROWS ONLY", False),
        ("SELECT id, doc FROM t WITH UR", False),
        ("SELECT id, doc, ROW_NUMBER() OVER (ORDER BY id) FROM t", False),
        ("SELECT id, doc FROM t WHERE id IN (SELECT id FROM u ORDER BY id FETCH FIRST 2 ROWS ONLY)", False),
        ("WITH q AS (SELECT id, doc FROM t ORDER BY id) SELECT id, doc FROM q", False),
        ('SELECT "ORDER", doc FROM t', False),
        ("SELECT 'ORDER BY' AS o, doc FROM t", False),
        ("SELECT id, doc FROM t ORDER BY id", True),
        ("SELECT id, doc FROM t ORDER BY id FETCH FIRST 5 ROWS ONLY WITH UR", True),
        ("SELECT id, doc FROM t UNION ALL SELECT id, doc FROM u ORDER BY 1", True),
        ("WITH q AS (SELECT id, doc FROM t) SELECT id, doc FROM q ORDER BY id", True),
        ("SELECT id, doc FROM t order /* c */ by id", True),
    ],
)
def test_e2_order_of_only_for_a_statement_with_its_own_order_by(sql: str, ordered: bool) -> None:
    capped = _db2_capped_select(sql, _LOB, 100)
    assert capped is not None
    assert ("ORDER BY ORDER OF udbmcp_q" in capped) is ordered, capped
    if "WITH UR" in sql:
        assert capped.endswith(" WITH UR"), capped


# ---- E3 ---------------------------------------------------------------------


def test_e3_a_surrogate_pair_cut_by_textsize_decodes() -> None:
    cut = ("a" * 10).encode("utf-16-le") + "\U0001f600".encode("utf-16-le")[:2]
    with pytest.raises(UnicodeDecodeError):
        cut.decode("utf-16-le")  # what pyodbc did
    assert mssql_module._utf16_cut_tolerant(cut) == "a" * 10 + "�"
    assert mssql_module._utf16_cut_tolerant("x\U0001f600".encode("utf-16-le")) == "x\U0001f600"
    assert mssql_module._utf16_cut_tolerant(None) is None


def test_e3_query_connections_decode_wide_text_tolerantly(monkeypatch: pytest.MonkeyPatch) -> None:
    registered: dict[int, Any] = {}

    def add_output_converter(self: _FakeMssqlConn, sqltype: int, fn: Any) -> None:
        registered[sqltype] = fn

    monkeypatch.setattr(_FakeMssqlConn, "add_output_converter", add_output_converter, raising=False)
    script = _MssqlScript(rows=[(1,)])
    conn = _mssql(monkeypatch, script)
    conn.execute_query(QuerySpec(sql="SELECT v FROM t", max_cell_bytes=8192))
    # SQL_WCHAR, SQL_WVARCHAR (nvarchar(max), xml cast to it), SQL_WLONGVARCHAR (ntext)
    assert set(registered) == {-8, -9, -10}
    assert all(fn is mssql_module._utf16_cut_tolerant for fn in registered.values())
