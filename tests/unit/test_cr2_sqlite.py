"""SQLite connector fixes from the second /code-review max pass (2026-10-03).

- Cancel without a hot callback: the previous fix stopped a statement whose
  cancel arrived before it started with a progress handler that called into
  Python every 1000 virtual-machine steps. Each call needs the GIL, so next
  to any busy Python thread a statement ran 25-250x slower. The connector now
  interrupts its open handles, and keeps interrupting them until they close,
  so a cancel that lands before a statement starts still stops it.
- Shadow tables: only the internal tables of a virtual table that exists are
  hidden, with the suffixes of that table's own module; an ordinary table
  named like one (posts_stat next to an FTS5 'posts') is a table. A statement
  is refused only when it reads such a table (FROM, JOIN, IN table), not when
  a literal, alias or column carries the name.
- list_columns and every statement no longer list the whole catalog
  (PRAGMA table_list) per call.
- ORDER BY random(), NULL, a bound parameter: such terms compare no output,
  so the in-SQLite cut still applies; every spelling of a position still
  keeps that output whole.
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

import pytest
import sqlglot
from helpers_sqlite import connector_reads_fts

from universal_db_mcp.config import ConnectionConfig, ResolvedConnection, SecurityConfig, load_resolved
from universal_db_mcp.connectors import sqlite as sqlite_module
from universal_db_mcp.connectors.base import ConnectorError, ObjectNotFound, QuerySpec
from universal_db_mcp.connectors.sqlite import SQLiteConnector, _compared_outputs
from universal_db_mcp.security.policy import EffectivePolicy
from universal_db_mcp.server import AppContext, build_server

# Counts to 300 million: tens of seconds of work, so a statement nothing
# stops is still running when the test looks.
_LONG = (
    "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 300000000) SELECT count(*) AS n FROM c"
)


def _connector(db: Path) -> SQLiteConnector:
    resolved = ResolvedConnection("t", ConnectionConfig.model_validate({"type": "sqlite", "database": str(db)}))
    return SQLiteConnector(resolved, EffectivePolicy.build(SecurityConfig(), resolved))


def _db(path: Path, script: str) -> Path:
    with closing(sqlite3.connect(path)) as c:
        c.executescript(script)
        c.commit()
    return path


def _traced(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Every statement the connector's handles run, as SQLite traces it."""
    ran: list[str] = []
    real_open = SQLiteConnector._open

    def tracing(self: SQLiteConnector) -> sqlite3.Connection:
        handle = real_open(self)
        handle.set_trace_callback(ran.append)
        return handle

    monkeypatch.setattr(SQLiteConnector, "_open", tracing)
    return ran


# ---- cancel without a progress handler -----------------------------------------


class _Recording(sqlite3.Connection):
    progress_handlers: list[Any] = []

    def set_progress_handler(self, handler: Any, n: int) -> None:  # type: ignore[override]
        _Recording.progress_handlers.append((handler, n))
        super().set_progress_handler(handler, n)


def test_handles_carry_no_progress_handler(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A Python progress handler takes the GIL every few thousand steps."""
    conn = _connector(_db(tmp_path / "a.db", "CREATE TABLE t (a); INSERT INTO t VALUES (1);"))
    real_connect = sqlite3.connect
    _Recording.progress_handlers = []

    def connect(*args: Any, **kwargs: Any) -> sqlite3.Connection:
        return real_connect(*args, factory=_Recording, **kwargs)

    monkeypatch.setattr(sqlite_module.sqlite3, "connect", connect)
    assert conn.execute_query(QuerySpec(sql="SELECT a FROM t")).rows == [[1]]
    conn.list_tables(None, set(), None)
    assert [h for h, _n in _Recording.progress_handlers if h is not None] == []


def test_a_statement_next_to_a_busy_python_thread_runs_at_full_speed(tmp_path: Path) -> None:
    """The review's microbenchmark, scaled down: 0.06 s became 16.6 s with a
    progress handler every 1000 steps next to one busy Python thread."""
    db = tmp_path / "big.db"
    with closing(sqlite3.connect(db)) as c:
        c.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, x INTEGER, s TEXT)")
        c.executemany("INSERT INTO t VALUES (?, ?, ?)", ((i, i % 97, f"row-{i}") for i in range(300_000)))
        c.commit()
    conn = _connector(db)
    sql = "SELECT count(*) AS n, sum(x) AS sx, max(length(s)) AS ms FROM t"
    alone = time.perf_counter()
    conn.execute_query(QuerySpec(sql=sql))
    alone = time.perf_counter() - alone
    stop = threading.Event()

    def busy() -> None:
        x = 0
        while not stop.is_set():
            for i in range(10_000):
                x += i * i

    thread = threading.Thread(target=busy, daemon=True)
    thread.start()
    try:
        time.sleep(0.05)
        started = time.perf_counter()
        out = conn.execute_query(QuerySpec(sql=sql))
        contended = time.perf_counter() - started
    finally:
        stop.set()
        thread.join()
    assert out.rows[0][0] == 300_000
    # A progress handler every 1000 steps made this ~20 s; the bound is loose
    # for slow CI machines and the GIL switches of the statement's own
    # Python-side steps.
    assert contended < max(2.0, alone * 20), (alone, contended)


def test_a_cancel_just_before_the_statement_starts_still_stops_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The cancel lands after the connector's last look at its flag and
    before SQLite starts the statement: interrupt() alone is forgotten then,
    as SQLite clears it when a statement starts on an idle handle."""
    conn = _connector(_db(tmp_path / "a.db", "CREATE TABLE t (a);"))
    real_stream = SQLiteConnector._stream

    def late(self: SQLiteConnector, handle: sqlite3.Connection, sql: str, *args: Any) -> Any:
        self.cancel_current()
        return real_stream(self, handle, sql, *args)

    monkeypatch.setattr(SQLiteConnector, "_stream", late)
    started = time.monotonic()
    with pytest.raises(ConnectorError):
        conn.execute_query(QuerySpec(sql=_LONG))
    assert time.monotonic() - started < 1, "the statement ran on although it was cancelled"


class _Marker:
    """A parameter whose adaptation runs Python between the statement's
    prepare (which itself fails on a pending interrupt) and its first step
    (where SQLite clears an interrupt that found the handle idle)."""


def test_a_cancel_between_prepare_and_first_step_still_stops_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    conn = _connector(_db(tmp_path / "a.db", "CREATE TABLE t (a);"))
    armed = threading.Event()

    def adapt(_value: _Marker) -> int:
        if armed.is_set():
            conn.cancel_current()
        return 1

    monkeypatch.setitem(sqlite3.adapters, (_Marker, sqlite3.PrepareProtocol), adapt)
    real_stream = SQLiteConnector._stream

    def streaming(self: SQLiteConnector, *args: Any) -> Any:
        armed.set()  # the statement itself, not the LIMIT 0 probe before it
        return real_stream(self, *args)

    monkeypatch.setattr(SQLiteConnector, "_stream", streaming)
    sql = _LONG + " WHERE ? IS NOT NULL"
    started = time.monotonic()
    with pytest.raises(ConnectorError, match="interrupted"):
        conn.execute_query(QuerySpec(sql=sql, parameters=(_Marker(),)))
    assert time.monotonic() - started < 1, "the statement ran on although it was cancelled"


def test_a_cancel_while_the_statement_runs_stops_it(tmp_path: Path) -> None:
    conn = _connector(_db(tmp_path / "a.db", "CREATE TABLE t (a);"))
    outcome: dict[str, Any] = {}

    def run() -> None:
        try:
            outcome["result"] = conn.execute_query(QuerySpec(sql=_LONG))
        except Exception as exc:  # noqa: BLE001 - the test reads it
            outcome["error"] = exc

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    time.sleep(0.3)
    assert conn.cancel_current() is True
    worker.join(3)
    assert not worker.is_alive()
    assert isinstance(outcome.get("error"), ConnectorError), outcome


def test_the_repeat_interrupts_end_with_the_last_handle(tmp_path: Path) -> None:
    conn = _connector(_db(tmp_path / "a.db", "CREATE TABLE t (a);"))
    worker = threading.Thread(target=lambda: pytest.raises(ConnectorError, conn.execute_query, QuerySpec(sql=_LONG)))
    worker.start()
    time.sleep(0.2)
    conn.cancel_current()
    worker.join(3)
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline and any(t.name.startswith("udbmcp-sqlite-cancel") for t in threading.enumerate()):
        time.sleep(0.02)
    assert not any(t.name.startswith("udbmcp-sqlite-cancel") for t in threading.enumerate())
    assert not conn._handles


def test_handles_are_released_after_every_call(tmp_path: Path) -> None:
    conn = _connector(_db(tmp_path / "a.db", "CREATE TABLE t (a); CREATE TABLE u (b);"))
    conn.execute_query(QuerySpec(sql="SELECT a FROM t"))
    with pytest.raises(ConnectorError):
        conn.execute_query(QuerySpec(sql="SELECT nope FROM t"))
    conn.list_tables(None, set(), None)
    conn.get_table("main", "t")
    conn.list_columns("main", "u")
    conn.explain("SELECT a FROM t", analyze=False)
    assert not conn._handles


# ---- shadow tables: only real ones ---------------------------------------------

_LOOKALIKES = """
CREATE VIRTUAL TABLE posts USING fts5(title, body);
INSERT INTO posts VALUES ('hello', 'world');
CREATE TABLE posts_stat (day TEXT, views INTEGER);
INSERT INTO posts_stat VALUES ('2026-10-01', 42);
CREATE VIRTUAL TABLE geo USING rtree(id, minx, maxx);
INSERT INTO geo VALUES (1, 0, 1);
CREATE TABLE geo_data (id INTEGER PRIMARY KEY, name TEXT);
INSERT INTO geo_data VALUES (1, 'Lisbon');
CREATE VIRTUAL TABLE docs USING fts4(body);
INSERT INTO docs VALUES ('alpha');
CREATE TABLE docs_config (k TEXT, v TEXT);
INSERT INTO docs_config VALUES ('lang', 'en');
CREATE TABLE orders_content (id INTEGER, note TEXT);
INSERT INTO orders_content VALUES (1, 'n');
CREATE TABLE settings (key TEXT, value TEXT, docs_content TEXT);
INSERT INTO settings VALUES ('posts_config', 'on', 'x');
"""


def test_ordinary_tables_named_like_a_shadow_table_are_tables(tmp_path: Path) -> None:
    conn = _connector(_db(tmp_path / "a.db", _LOOKALIKES))
    names = {t.name for t in conn.list_tables(None, set(), None)}
    assert {"posts_stat", "geo_data", "docs_config", "orders_content", "settings"} <= names, names
    assert not names & {"posts_content", "posts_data", "docs_segdir", "geo_node"}, names
    for table, rows in (("posts_stat", [["2026-10-01", 42]]), ("geo_data", [[1, "Lisbon"]]),
                        ("docs_config", [["lang", "en"]]), ("orders_content", [[1, "n"]])):
        assert conn.get_table("main", table)["kind"] == "table"
        assert conn.list_columns("main", table), table
        assert conn.execute_query(QuerySpec(sql=f"SELECT * FROM {table}")).rows == rows


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT value FROM settings WHERE key = 'posts_config'",
        "SELECT key AS posts_idx FROM settings",
        "SELECT docs_content FROM settings",
        "SELECT value FROM settings -- posts_data\n",
        "SELECT value FROM settings WHERE key = 'POSTS_DOCSIZE'",
        "SELECT s.value FROM settings AS posts_content_alias, settings s LIMIT 1",
        "SELECT value FROM settings WHERE key IN ('posts_config', 'docs_segdir')",
    ],
)
def test_a_name_that_is_not_a_table_reference_is_not_refused(tmp_path: Path, sql: str) -> None:
    conn = _connector(_db(tmp_path / "a.db", _LOOKALIKES))
    conn.execute_query(QuerySpec(sql=sql))


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT * FROM posts_content",
        "SELECT * FROM settings WHERE 1 IN posts_content",
        "SELECT 1 FROM settings WHERE 'x' NOT IN main.docs_segdir",
        "SELECT * FROM geo_node",
        "WITH q AS (SELECT * FROM 'docs_content') SELECT * FROM q",
        "SELECT * FROM settings WHERE EXISTS (SELECT 1 FROM [posts_data])",
    ],
)
def test_reading_a_real_shadow_table_is_still_refused(tmp_path: Path, sql: str) -> None:
    conn = _connector(_db(tmp_path / "a.db", _LOOKALIKES))
    with pytest.raises(ConnectorError) as info:
        conn.execute_query(QuerySpec(sql=sql))
    assert "internal table" in str(info.value), str(info.value)


def test_end_to_end_profile_and_sample_of_a_table_with_shadow_named_values(tmp_path: Path) -> None:
    db = _db(tmp_path / "a.db", _LOOKALIKES)
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "application:\n  transport: stdio\n"
        f"  audit_path: {tmp_path / 'audit.jsonl'}\n"
        f"  metadata_cache_path: {tmp_path / 'cache.sqlite'}\n"
        f"connections:\n  lite:\n    type: sqlite\n    database: {db}\n",
        encoding="utf-8",
    )
    app_cfg, resolved = load_resolved(cfg)
    server = build_server(AppContext(app_cfg, resolved))

    def call(name: str, args: dict[str, Any]) -> Any:
        result = asyncio.run(server.call_tool(name, args))
        assert result.structured_content is not None
        return result.structured_content

    profile = call("db_profile_table", {"connection_id": "lite", "object_name": "settings"})["data"]
    assert "posts_config" in json.dumps(profile), profile
    sample = call("db_sample_table", {"connection_id": "lite", "object_name": "settings", "columns": ["docs_content"]})
    assert sample["data"]["rows"] == [["x"]], sample
    assert call("db_sample_table", {"connection_id": "lite", "object_name": "posts_stat"})["data"]["rows"]
    tables = {t["name"] for t in call("db_list_tables", {"connection_id": "lite"})["data"]["tables"]}
    assert {"posts_stat", "geo_data", "docs_config"} <= tables
    assert "posts_content" not in tables


def test_a_module_this_build_lacks_marks_its_shadow_tables_by_its_own_suffixes() -> None:
    """SQLite reports the shadow tables of a module it lacks as plain tables:
    they are known by the virtual table's own name and that module's
    suffixes, never by another module's."""
    unmarked = sqlite_module._unmarked_shadow
    nothing: frozenset[str] = frozenset()
    assert unmarked("docs_content", "fts4", nothing)
    assert unmarked("docs_segdir", "fts3", nothing)
    assert not unmarked("docs_config", "fts4", nothing)  # FTS5's suffix, not FTS4's
    assert unmarked("posts_config", "fts5", nothing)
    assert not unmarked("posts_stat", "fts5", nothing)  # FTS3/4's suffix, not FTS5's
    assert unmarked("geo_node", "rtree", nothing)
    assert not unmarked("geo_data", "rtree", nothing)
    assert unmarked("v_chunks", "", nothing), "a module that cannot be read: fail closed"
    assert unmarked("v_chunks", "vec0", nothing), "an unknown module this build lacks: fail closed"
    assert not unmarked("docs_content", "fts4", frozenset({"fts4"})), "SQLite marks a module's own"
    assert not unmarked("geo_data", None, nothing), "no virtual table of that name"


@pytest.mark.parametrize(
    ("sql", "module"),
    [
        ("CREATE VIRTUAL TABLE f USING fts5(x)", "fts5"),
        ("CREATE VIRTUAL TABLE f using FTS4(y)", "fts4"),
        ('CREATE VIRTUAL TABLE "my using t" USING rtree(id, a, b)', "rtree"),
        ("CREATE VIRTUAL TABLE [a b]\n  USING \"rtree_i32\"(id, a, b)", "rtree_i32"),
        ("CREATE VIRTUAL TABLE main.g USING geopoly", "geopoly"),
        ("CREATE VIRTUAL TABLE f /* c */ USING fts5(x)", "fts5"),  # comments are read past (review round 3)
        ("CREATE TABLE f (x)", None),
    ],
)
def test_the_module_of_a_virtual_table(sql: str, module: str | None) -> None:
    assert sqlite_module._module_of(sql) == module


def test_the_module_reader_is_linear_on_adversarial_text() -> None:
    for body in ('"' * 65536, "CREATE VIRTUAL TABLE " + '"' + '""' * 32768, "CREATE VIRTUAL TABLE " + "a." * 32768):
        started = time.perf_counter()
        sqlite_module._module_of(body)
        assert time.perf_counter() - started < 0.2


# ---- no catalog listing per call -------------------------------------------------


def test_list_columns_and_a_statement_list_no_catalog(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """PRAGMA table_list builds every view's and virtual table's columns: per
    table of a catalog walk, or per statement, it timed out at ~3k tables."""
    conn = _connector(_db(tmp_path / "a.db", _LOOKALIKES + "CREATE VIEW v AS SELECT * FROM settings;"))
    ran = _traced(monkeypatch)
    conn.list_columns("main", "settings")
    conn.list_columns("main", "posts_stat")
    conn.execute_query(QuerySpec(sql="SELECT * FROM settings JOIN posts_stat ON 1"))
    if connector_reads_fts():  # SQLite 3.40 refuses every MATCH under the authorizer (helpers_sqlite)
        conn.execute_query(QuerySpec(sql="SELECT * FROM posts WHERE posts MATCH 'hello'"))
    assert "PRAGMA table_list" not in [s.strip() for s in ran], ran


def test_list_columns_of_a_shadow_table_is_empty(tmp_path: Path) -> None:
    conn = _connector(_db(tmp_path / "a.db", _LOOKALIKES))
    assert conn.list_columns("main", "posts_content") == []
    assert conn.list_columns("main", "DOCS_SEGDIR") == []
    with pytest.raises(ObjectNotFound):
        conn.get_table("main", "geo_node")


def test_a_schema_change_is_seen(tmp_path: Path) -> None:
    """The virtual tables are read once per schema version, not per call."""
    db = _db(tmp_path / "a.db", "CREATE TABLE notes_content (a); INSERT INTO notes_content VALUES (1);")
    conn = _connector(db)
    assert conn.execute_query(QuerySpec(sql="SELECT a FROM notes_content")).rows == [[1]]
    with closing(sqlite3.connect(db)) as c:
        c.execute("DROP TABLE notes_content")
        c.execute("CREATE VIRTUAL TABLE notes USING fts5(a)")
        c.execute("INSERT INTO notes VALUES ('secret')")
        c.commit()
    with pytest.raises(ConnectorError, match="internal table"):
        conn.execute_query(QuerySpec(sql="SELECT * FROM notes_content"))


def test_a_refusal_check_is_bounded_on_a_64k_statement(tmp_path: Path) -> None:
    conn = _connector(_db(tmp_path / "a.db", _LOOKALIKES))
    sql = "SELECT 1 FROM settings WHERE key IN (" + ", ".join(f"'posts_x{i}'" for i in range(6000)) + ")"
    assert len(sql) > 60_000
    started = time.perf_counter()
    conn.execute_query(QuerySpec(sql=sql))
    assert time.perf_counter() - started < 3


# ---- ORDER BY terms that compare no output -----------------------------------------


@pytest.mark.parametrize("term", ["random()", "NULL", "?", ":p", "'2'", "2.0", "CAST(2 AS INT)", "(SELECT 2)", "2 + 0"])
def test_a_term_that_compares_no_output_keeps_the_cut(term: str) -> None:
    for clause in ("ORDER BY", "GROUP BY"):
        tree = sqlglot.parse_one(f"SELECT a, b FROM t {clause} {term}", read="sqlite")
        assert _compared_outputs(tree, ["a", "b"]) == set(), (clause, term)  # type: ignore[arg-type]


@pytest.mark.parametrize("term", ["2", "(2)", "+2", "0x2", "-(-2)", "2 COLLATE nocase", "((2)) COLLATE binary", "+(2)"])
def test_every_spelling_of_a_position_is_still_compared(term: str) -> None:
    for clause in ("ORDER BY", "GROUP BY"):
        tree = sqlglot.parse_one(f"SELECT a, b FROM t {clause} {term}", read="sqlite")
        assert _compared_outputs(tree, ["a", "b"]) == {1}, (clause, term)  # type: ignore[arg-type]


def test_order_by_random_cuts_long_values_in_the_engine(tmp_path: Path) -> None:
    long = "x" * 200_000
    conn = _connector(_db(tmp_path / "a.db", "CREATE TABLE big (id INTEGER PRIMARY KEY, body TEXT);"))
    with closing(sqlite3.connect(tmp_path / "a.db")) as c:
        c.executemany("INSERT INTO big VALUES (?, ?)", [(i, long) for i in range(5)])
        c.commit()
    for sql, params in (("SELECT id, body FROM big ORDER BY random()", None),
                        ("SELECT id, body FROM big ORDER BY NULL", None),
                        ("SELECT id, body FROM big ORDER BY ?", (2,))):
        with conn._handle() as handle:
            capped = conn._value_capped(handle, sql, params or (), 100)
        assert capped is not None and "CASE typeof(body)" in capped.replace('"', ""), (sql, capped)
        assert "(random() & 0) + 101)" in capped, (sql, capped)
        out = conn.execute_query(QuerySpec(sql=sql, parameters=params, max_cell_bytes=100))
        assert sorted(r[0] for r in out.rows) == [0, 1, 2, 3, 4]


def test_positional_sort_and_group_results_stay_right(tmp_path: Path) -> None:
    prefix = "p" * 20000
    conn = _connector(_db(tmp_path / "a.db", "CREATE TABLE docs (id INTEGER PRIMARY KEY, body TEXT);"))
    with closing(sqlite3.connect(tmp_path / "a.db")) as c:
        c.executemany("INSERT INTO docs VALUES (?, ?)", [(1, prefix + "b"), (2, prefix + "a"), (3, "tiny")])
        c.commit()
    for term in ("2", "(2)", "-(-2)", "0x2", "+2 COLLATE binary"):
        out = conn.execute_query(QuerySpec(sql=f"SELECT id, body FROM docs WHERE id < 3 ORDER BY {term}"))
        assert [r[0] for r in out.rows] == [2, 1], term
        out = conn.execute_query(QuerySpec(sql=f"SELECT count(*), body FROM docs WHERE id < 3 GROUP BY {term}"))
        assert [r[0] for r in out.rows] == [1, 1], term


def test_the_capability_text_no_longer_says_every_column_is_kept(tmp_path: Path) -> None:
    conn = _connector(_db(tmp_path / "a.db", "CREATE TABLE t (a);"))
    text = json.dumps([lim.detail for lim in conn.capabilities().limitations])
    assert "names no column and is not a plain position" not in text


# ---- a ~user that names no account ----------------------------------------------


def test_a_tilde_user_that_names_no_account_is_a_connection_error() -> None:
    """pathlib raises RuntimeError for it, which surfaced as INTERNAL_ERROR."""
    resolved = ResolvedConnection(
        "t", ConnectionConfig.model_validate({"type": "sqlite", "database": "~udbmcp-no-such-user-zz/app.db"})
    )
    with pytest.raises(ConnectorError) as info:
        SQLiteConnector(resolved, EffectivePolicy.build(SecurityConfig(), resolved))
    assert getattr(info.value, "category", None) == "CONNECTION_ERROR"
    assert "'~udbmcp-no-such-user-zz'" in str(info.value) and "names no account" in str(info.value)


def test_a_tilde_user_through_the_server_is_a_connection_error(tmp_path: Path) -> None:
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "application:\n  transport: stdio\n"
        f"  audit_path: {tmp_path / 'audit.jsonl'}\n"
        f"  metadata_cache_path: {tmp_path / 'cache.sqlite'}\n"
        "connections:\n  lite:\n    type: sqlite\n    database: ~udbmcp-no-such-user-zz/app.db\n",
        encoding="utf-8",
    )
    app_cfg, resolved = load_resolved(cfg)
    server = build_server(AppContext(app_cfg, resolved))
    with pytest.raises(Exception) as info:  # noqa: PT011 - the tool's error, whatever the transport wraps it in
        asyncio.run(server.call_tool("db_query", {"connection_id": "lite", "sql": "SELECT 1"}))
    text = str(info.value)
    assert "INTERNAL" not in text and "names no account" in text, text
