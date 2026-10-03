"""SQLite connector behavior: read-only, authorizer backstop, limits, metadata."""

from __future__ import annotations

import sqlite3
from contextlib import closing

import pytest
from helpers_sqlite import connector_reads_dbstat

from universal_db_mcp.connectors.base import ConnectorError, QuerySpec
from universal_db_mcp.connectors.registry import build_connector


@pytest.fixture()
def connector(app_ctx, demo_policy):
    return build_connector(app_ctx.resolved["demo_sqlite"], demo_policy)


def test_health(connector) -> None:
    h = connector.health_check()
    assert h.healthy
    assert h.server_version


def test_query_basic(connector) -> None:
    out = connector.execute_query(
        QuerySpec(sql="SELECT customer_id, full_name FROM customers ORDER BY customer_id", max_rows=5)
    )
    assert [c[0] for c in out.columns] == ["customer_id", "full_name"]
    assert len(out.rows) == 5
    assert out.rows[0][0] == 1


def test_row_limit_truncates(connector) -> None:
    out = connector.execute_query(QuerySpec(sql="SELECT customer_id FROM customers", max_rows=3))
    assert out.truncated
    assert len(out.rows) == 3


def test_named_parameters(connector) -> None:
    out = connector.execute_query(
        QuerySpec(sql="SELECT full_name FROM customers WHERE customer_id = :cid", parameters={"cid": 2})
    )
    assert out.rows == [["User 1"]]


def test_bigint_preserved(connector) -> None:
    out = connector.execute_query(QuerySpec(sql="SELECT balance_cents FROM accounts WHERE account_id = 1"))
    assert out.rows[0][0] == str(2**60)  # exact, out of JSON-safe range -> string
    assert out.columns[0][1] == "bigint"


def test_metadata(connector) -> None:
    tables = connector.list_tables(None, {"table", "view"}, None)
    names = {t.name for t in tables}
    assert {"customers", "accounts", "v_accounts"} <= names
    cols = connector.list_columns("main", "customers")
    assert [c.name for c in cols][:2] == ["customer_id", "full_name"]
    fks = connector.get_foreign_keys("main", "accounts")
    assert fks and fks[0].ref_table == "customers"
    views = connector.list_views("main")
    assert any(v.name == "v_accounts" and v.definition for v in views)


def test_capabilities_truthful(connector) -> None:
    caps = connector.capabilities()
    assert caps.get("list_synonyms").value == "unsupported"
    assert caps.get("explain_analyze").value == "unsupported"


def test_missing_file_names_artifact(app_ctx, demo_policy, tmp_path) -> None:
    from universal_db_mcp.config import ResolvedConnection

    cfg = app_ctx.resolved["demo_sqlite"].config.model_copy(update={"database": str(tmp_path / "nope.db")})
    conn = build_connector(ResolvedConnection("demo_sqlite", cfg), demo_policy)
    # health_check reports; it does not raise. The detail must name the artifact.
    h = conn.health_check()
    assert not h.healthy
    assert "nope.db" in (h.detail or "")
    # while a direct open does raise, naming the missing local file
    with pytest.raises(FileNotFoundError, match="nope.db"):
        conn._open()


def test_write_denied_by_readonly_handle(connector) -> None:
    # The guard denies INSERT earlier; this proves the engine layer refuses
    # too (authorizer + read-only handle) even if SQL reached the driver.
    # The engine's refusal reaches the server as the statement's error.
    spec = QuerySpec(sql="CREATE TABLE hack (x int)")
    with pytest.raises(ConnectorError) as exc:
        connector.execute_query(spec)
    assert isinstance(exc.value.__cause__, sqlite3.Error)
    assert exc.value.category == "QUERY_ERROR"


def test_open_reads_the_header_so_a_non_sqlite_file_fails_on_every_version(app_ctx, demo_policy, tmp_path) -> None:
    """Some SQLite builds (Ubuntu 24.04's 3.45, Debian's 3.46) run
    'SELECT sqlite_version()' without reading the database header, so a
    health check that only ran that called an encrypted file healthy. The
    open itself must read the header."""
    from universal_db_mcp.config import ResolvedConnection

    db = tmp_path / "encrypted.db"
    db.write_bytes(b"\x00\x01\x02not-a-sqlite-header" + b"\x00" * 200)
    cfg = app_ctx.resolved["demo_sqlite"].config.model_copy(update={"database": str(db)})
    conn = build_connector(ResolvedConnection("demo_sqlite", cfg), demo_policy)
    with pytest.raises(sqlite3.DatabaseError, match="not a database"):
        conn._open()
    health = conn.health_check()
    assert health.healthy is False
    assert "ENCRYPTED" in (health.detail or ""), health.detail


def test_values_are_bounded_inside_the_server_process(connector) -> None:
    """SQLite runs in-process: a string-doubling CTE would build its values in
    the server's own memory. SQLITE_LIMIT_LENGTH stops the engine instead."""
    import tracemalloc

    limit = max(connector.policy.max_response_bytes * 16, 16 * 1024 * 1024)
    handle = connector._open()
    try:
        assert handle.getlimit(sqlite3.SQLITE_LIMIT_LENGTH) == limit
    finally:
        handle.close()
    # (sorted, the same values are refused sooner, at SQLite's heap limit:
    # test_sorting_many_large_rows_is_bounded_in_the_server_process)
    sql = (
        "WITH RECURSIVE t(n, s) AS (SELECT 1, 'x' UNION ALL SELECT n + 1, s || s FROM t WHERE n < 26) "
        "SELECT n, s FROM t WHERE n = 26"
    )
    tracemalloc.start()
    try:
        with pytest.raises(ConnectorError) as exc:
            connector.execute_query(QuerySpec(sql=sql, max_rows=1))
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    # SQLITE_LIMIT_LENGTH refuses the 32 MiB value, unless SQLite's heap cap,
    # process-wide and shared with this test process's other handles, is
    # reached first: either way the value is never built.
    assert (exc.value.category, "too big" in str(exc.value)) == ("QUERY_ERROR", True) or (
        exc.value.category == "LIMIT_EXCEEDED" and "memory" in str(exc.value)
    ), (exc.value.category, str(exc.value))
    assert peak < 4 * 1024 * 1024, peak


_CHILD = """
import json, resource, sqlite3, sys
from universal_db_mcp.config import ConnectionConfig, ResolvedConnection, SecurityConfig
from universal_db_mcp.connectors.base import ConnectorError, QuerySpec
from universal_db_mcp.connectors.sqlite import SQLiteConnector
from universal_db_mcp.security.policy import EffectivePolicy

path, sql, max_rows, cap_mib = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
if cap_mib:  # SQLite's heap limit only ever goes down: this one applies
    sqlite3.connect(":memory:").execute(f"PRAGMA hard_heap_limit = {cap_mib << 20}").fetchone()
sqlite3.connect(path).executescript("CREATE TABLE IF NOT EXISTS t (x); ").close()
resolved = ResolvedConnection("lite", ConnectionConfig.model_validate({"type": "sqlite", "database": path}))
conn = SQLiteConnector(resolved, EffectivePolicy.build(SecurityConfig(), resolved))
conn.execute_query(QuerySpec(sql="SELECT 1", max_rows=1))
unit = 1 if sys.platform == "darwin" else 1024  # ru_maxrss: bytes on macOS, KiB on Linux
before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * unit
try:
    out = conn.execute_query(QuerySpec(sql=sql, max_rows=max_rows))
    result = {"rows": len(out.rows), "warnings": out.warnings, "truncated": out.truncated,
              "longest": max((len(json.dumps(v)) for row in out.rows for v in row), default=0)}
except ConnectorError as exc:
    result = {"category": exc.category, "error": str(exc)}
result["grown_mb"] = (resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * unit - before) / 2**20
print(json.dumps(result))
"""


def _in_a_child(tmp_path, sql: str, max_rows: int = 1, cap_mib: int = 0) -> dict:
    """Run one query on a fresh SQLite connector in a child process: SQLite's
    own heap is invisible to tracemalloc, and its heap limit is process-wide.
    ``cap_mib`` lowers that limit first."""
    import json
    import subprocess
    import sys

    done = subprocess.run(  # noqa: S603 - this interpreter, fixed script
        [sys.executable, "-c", _CHILD, str(tmp_path / "child.db"), sql, str(max_rows), str(cap_mib)],
        capture_output=True, text=True, timeout=120, check=False,
    )
    assert done.returncode == 0, done.stderr[-2000:]
    return json.loads(done.stdout.strip().splitlines()[-1])


_DOUBLING = "WITH RECURSIVE t(n, s) AS (SELECT 1, 'x' UNION ALL SELECT n + 1, s || s FROM t WHERE n < 24) "


def _heap_accounting() -> bool:
    with closing(sqlite3.connect(":memory:")) as probe:
        options = {row[0] for row in probe.execute("PRAGMA compile_options")}
    return "DEFAULT_MEMSTATUS=0" not in options and sqlite3.sqlite_version_info >= (3, 31)


_NEEDS_HEAP_LIMIT = pytest.mark.skipif(
    not _heap_accounting(),
    reason="this SQLite build keeps no heap statistics (SQLITE_DEFAULT_MEMSTATUS=0, or older than 3.31), "
    "so it enforces no heap limit",
)


def test_a_row_of_many_large_columns_is_bounded_in_the_server_process(tmp_path) -> None:
    """Review round 4: SQLITE_LIMIT_LENGTH bounds one value, not a row. Sixteen
    columns of one 8 MiB value grew the server by 327 MB (and it scales with
    the column count, up to SQLITE_LIMIT_COLUMN). Each output column is cut
    inside SQLite now, where the value is computed, so a row holds one long
    value at a time: 64 such columns cost what one does (about 88 MB here,
    most of it the doubling CTE itself)."""
    columns = ", ".join(f"s AS c{i}" for i in range(64))
    out = _in_a_child(tmp_path, f"{_DOUBLING}SELECT {columns} FROM t WHERE n = 24")
    assert out.get("rows") == 1, out
    assert any("cell limit" in w for w in out["warnings"]), out
    assert out["longest"] < 8192 + 16, out
    assert out["grown_mb"] < 120, out


def test_sorting_many_large_rows_is_bounded_in_the_server_process(tmp_path) -> None:
    """ORDER BY over 30 rows of one 4 MiB value grew the server by 194 MB:
    SQLite's sorter holds a record of each spilled run while it merges. The
    sorter now holds the cut values (the sort key k is not cut)."""
    sql = (
        "WITH RECURSIVE b(n, s) AS (SELECT 1, 'x' UNION ALL SELECT n + 1, s || s FROM b WHERE n < 23), "
        "t(k, s) AS (SELECT 1, (SELECT s FROM b WHERE n = 23) UNION ALL SELECT k + 1, s || '' FROM t WHERE k < 40) "
        "SELECT k, s FROM t ORDER BY k DESC"
    )
    out = _in_a_child(tmp_path, sql)
    assert out.get("rows") == 1, out
    assert out["grown_mb"] < 80, out


@_NEEDS_HEAP_LIMIT
def test_what_the_cut_cannot_reach_is_refused_at_the_heap_cap(tmp_path) -> None:
    """A long sort key is compared whole, so it cannot be cut: SQLite's sorter
    then holds one record per spilled run (40 rows of 4 MiB here). The heap
    limit, process-wide, refuses it as LIMIT_EXCEEDED naming its size (a
    lowered limit applies, as the smallest one asked for always does)."""
    sql = (
        "WITH RECURSIVE g(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM g WHERE i < 40) "
        "SELECT i FROM g ORDER BY randomblob(4000000)"
    )
    out = _in_a_child(tmp_path, sql, cap_mib=64)
    assert out.get("category") == "LIMIT_EXCEEDED", out
    assert "64 MiB" in out["error"] and "memory" in out["error"], out["error"]
    assert out["grown_mb"] < 150, out


_CACHE_CHILD = """
import asyncio, json, sqlite3, sys, threading
from universal_db_mcp.config import load_resolved
from universal_db_mcp.connectors.base import QuerySpec, TableSummary
from universal_db_mcp.security.cursors import policy_fingerprint
from universal_db_mcp.server import AppContext

cfg, resolved = load_resolved(sys.argv[1])
ctx = AppContext(cfg, resolved)
lite, _ = ctx.connection("lite")
assert lite.health_check().healthy
cap = sqlite3.connect(":memory:").execute("PRAGMA hard_heap_limit").fetchone()[0]
other, policy = ctx.connection("other")
# a catalog just under the cache's 64 MiB entry cap (a 44 MB one failed)
listing = [
    TableSummary(schema="SAPSR3", name=f"/BIC/AZSD_O{i:07d}00", kind="table", row_estimate=i,
                 row_estimate_source="catalog_estimate")
    for i in range(int(sys.argv[2]))
]
other.list_tables = lambda *_a: listing
listed = asyncio.run(ctx.tables_for(policy, other))
cached = asyncio.run(ctx.tables_for(policy, other))
fp = policy_fingerprint(policy)
# while a SQLite statement sorts long rows, the cache keeps writing
sorts = ("WITH RECURSIVE b(n, s) AS (SELECT 1, 'x' UNION ALL SELECT n + 1, s || s FROM b WHERE n < 22), "
         "t(k, s) AS (SELECT 1, (SELECT s FROM b WHERE n = 22) UNION ALL SELECT k + 1, s || '' FROM t WHERE k < 12) "
         "SELECT k, length(s) FROM t ORDER BY k DESC")
done = threading.Event()
def query() -> None:
    while not done.is_set():
        lite.execute_query(QuerySpec(sql=sorts, max_rows=1))
worker = threading.Thread(target=query)
worker.start()
failures = 0
try:
    for _ in range(40):
        try:
            ctx.cache.put_tables("small", fp, listing[:10000])
        except MemoryError:
            failures += 1
finally:
    done.set()
    worker.join()
print(json.dumps({"cap": cap, "listed": len(listed), "cached": len(cached), "failures": failures,
                  "hit": ctx.cache.get_tables("other", fp, target=ctx._target("other")) is not None}))
"""


def test_the_heap_cap_leaves_the_metadata_cache_its_room(tmp_path) -> None:
    """Review round 5 (HIGH): SQLite's heap limit is process-wide, and the
    server's metadata cache is SQLite too. At 64 MiB it failed every other
    connection's catalog listing of about 44 MB (MemoryError, which the cache
    does not treat as a miss: db_list_tables and db_query on PostgreSQL
    failed), and nearly every cache write while a SQLite statement sorted a
    few MiB-sized rows. The cap now leaves room for the cache's largest
    entry beside SQLite's own statements."""
    import json
    import subprocess
    import sys

    for name in ("lite.db", "other.db"):
        sqlite3.connect(tmp_path / name).executescript("CREATE TABLE IF NOT EXISTS t (x);").close()
    config = tmp_path / "config.yaml"
    config.write_text(
        f"""
application:
  metadata_cache_path: {tmp_path}/cache.sqlite
  audit_path: {tmp_path}/audit.jsonl
connections:
  lite:
    type: sqlite
    database: {tmp_path}/lite.db
  other:
    type: sqlite
    database: {tmp_path}/other.db
""",
        encoding="utf-8",
    )
    done = subprocess.run(  # noqa: S603 - this interpreter, fixed script
        [sys.executable, "-c", _CACHE_CHILD, str(config), "430000"],
        capture_output=True, text=True, timeout=300, check=False,
    )
    assert done.returncode == 0, done.stderr[-3000:]
    out = json.loads(done.stdout.strip().splitlines()[-1])
    assert out["cap"] in (0, 512 * 1024 * 1024), out  # 0: this SQLite has no heap accounting
    assert (out["listed"], out["cached"], out["hit"]) == (430000, 430000, True), out
    assert out["failures"] == 0, out


def test_rows_reach_python_one_at_a_time(tmp_path) -> None:
    """A fetch batch held up to 200 whole rows in Python before their cells
    were cut: 40 rows of a 4 MB blob grew the server by 160 MB at
    max_rows=1000, though each row alone is well inside SQLite's limits."""
    sql = (
        "WITH RECURSIVE t(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM t WHERE n < 40) "
        "SELECT n, randomblob(4000000) AS b FROM t"
    )
    out = _in_a_child(tmp_path, sql, max_rows=1000)
    assert out.get("rows") == 40, out
    assert out["grown_mb"] < 60, out


def test_every_handle_is_closed_when_its_call_returns(connector, monkeypatch) -> None:
    """'with sqlite3.connect(...) as conn' commits or rolls back; it never
    closes, and a Connection sits in a reference cycle (its statement cache),
    so each metadata call left a handle, with the parsed schema of the whole
    database, until the cyclic GC ran. Under SQLite's heap cap (a process-wide
    64 MiB then) 14 such handles on a 200-table, 120-column database refused the
    next open: db_get_catalog failed with MemoryError."""
    opened: list[sqlite3.Connection] = []
    real_open = type(connector)._open

    def recording(self):  # type: ignore[no-untyped-def]
        handle = real_open(self)
        opened.append(handle)
        return handle

    monkeypatch.setattr(type(connector), "_open", recording)
    connector.health_check()
    connector.list_schemas(None, None)
    connector.list_tables(None, {"table", "view"}, None)
    connector.get_table("main", "customers")
    connector.list_indexes("main", "customers")
    connector.list_columns("main", "customers")
    connector.list_views("main")
    connector.get_foreign_keys("main", None)
    connector.get_statistics("main", "customers")
    connector.explain("SELECT 1", analyze=False)
    connector.execute_query(QuerySpec(sql="SELECT 1"))
    assert len(opened) >= 11
    for handle in opened:
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            handle.execute("SELECT 1")


def test_list_tables_omits_the_sqlite_catalog(connector) -> None:
    """PRAGMA table_list reports sqlite_schema (and sqlite_sequence,
    sqlite_stat1 when they exist); they are the engine's catalog, not data."""
    tables = connector.list_tables(None, {"table", "view"}, None)
    assert tables
    assert not [t.name for t in tables if t.name.lower().startswith("sqlite_")]
    assert not [fk for fk in connector.get_foreign_keys("main", None) if fk.source_table.lower().startswith("sqlite_")]


@pytest.mark.skipif(
    not connector_reads_dbstat(),
    reason="this SQLite build cannot read dbstat under the connector's authorizer (no SQLITE_ENABLE_DBSTAT_VTAB, "
    "or SQLite 3.40's constructor check): row estimates are None by design",
)
def test_row_estimates_survive_list_tables(connector) -> None:
    """list_tables read its row estimates after its handle was closed: the
    dbstat probe failed on the closed handle, was cached as 'no dbstat', and
    every later estimate (get_statistics, db_get_table, db_review_schema) was
    None for the connector's lifetime."""
    tables = {t.name: t for t in connector.list_tables(None, {"table", "view"}, None)}
    assert tables["customers"].row_estimate, tables["customers"]
    assert tables["customers"].row_estimate_source == "catalog_estimate"
    assert tables["v_accounts"].row_estimate is None
    stats = connector.get_statistics("main", "customers")
    assert stats["row_estimate"] == tables["customers"].row_estimate
    assert connector.get_table("main", "customers")["row_estimate"] == tables["customers"].row_estimate


def test_a_failed_dbstat_probe_is_remembered_only_when_dbstat_is_missing(connector) -> None:
    """Only 'no such table: dbstat' says the build lacks it; any other failure
    (a closed or interrupted handle) must not switch estimates off for good."""
    closed = connector._open()
    closed.close()
    assert connector._dbstat_ok(closed) is False
    assert connector._dbstat_available is None
    if connector_reads_dbstat():
        with closing(connector._open()) as conn:
            assert connector._dbstat_ok(conn) is True
        assert connector._dbstat_available is True

    class _NoDbstat:
        def execute(self, sql: str) -> None:
            raise sqlite3.OperationalError("no such table: dbstat")

    connector._dbstat_available = None
    assert connector._dbstat_ok(_NoDbstat()) is False  # type: ignore[arg-type]
    assert connector._dbstat_available is False


_PREFIX = "p" * 20000  # two long values that differ only past the cell limit


def _long_values(tmp_path, bad_text: bool = False):  # type: ignore[no-untyped-def]
    from universal_db_mcp.config import ConnectionConfig, ResolvedConnection, SecurityConfig
    from universal_db_mcp.connectors.sqlite import SQLiteConnector
    from universal_db_mcp.security.policy import EffectivePolicy

    db = tmp_path / "long.db"
    with closing(sqlite3.connect(db)) as c:
        c.execute("CREATE TABLE docs (id INTEGER PRIMARY KEY, body TEXT, raw BLOB, n INTEGER, r REAL, note TEXT)")
        c.executemany(
            "INSERT INTO docs VALUES (?, ?, ?, ?, ?, ?)",
            [
                (1, _PREFIX + "b", b"\x01" * 20000, 2**62, 1.5, None),
                (2, _PREFIX + "a", b"\x02" * 10, 7, -0.25, "short"),
            ],
        )
        # text that is not UTF-8 (stored by some other client); Python cannot read it
        note = "CAST(X'66ff6f' AS TEXT)" if bad_text else "'fine'"
        c.execute(f"INSERT INTO docs VALUES (3, 'tiny', NULL, NULL, NULL, {note})")  # noqa: S608 - test data
        c.commit()
    resolved = ResolvedConnection("long", ConnectionConfig.model_validate({"type": "sqlite", "database": str(db)}))
    return SQLiteConnector(resolved, EffectivePolicy.build(SecurityConfig(), resolved))


def _traced(connector, monkeypatch) -> list[str]:  # type: ignore[no-untyped-def]
    """The statements the connector's handles run."""
    ran: list[str] = []
    real_open = type(connector)._open

    def tracing(self):  # type: ignore[no-untyped-def]
        handle = real_open(self)
        handle.set_trace_callback(ran.append)
        return handle

    monkeypatch.setattr(type(connector), "_open", tracing)
    return ran


def test_long_values_are_cut_inside_sqlite_and_keep_their_types(tmp_path, monkeypatch) -> None:
    """Every output column is cut where SQLite computes it (to the cell limit
    plus one, so the cut is still seen), and a value that needs no cut keeps
    its type: integers, reals, NULL, short text and blobs."""
    conn = _long_values(tmp_path)
    ran = _traced(conn, monkeypatch)
    sql = "SELECT id, body, raw, n, r, note FROM docs ORDER BY id"
    out = conn.execute_query(QuerySpec(sql=sql, max_cell_bytes=100))
    assert [c[0] for c in out.columns] == ["id", "body", "raw", "n", "r", "note"]
    assert any("CASE typeof(body)" in s and "(random() & 0) + 101)" in s for s in ran), ran
    first, second, third = out.rows
    assert first[0] == 1 and first[1] == "p" * 100 and first[2]["$truncated"] is True
    assert (first[3], first[4], first[5]) == (str(2**62), 1.5, None)
    assert second[2] == {"$binary_b64": "AgICAgICAgICAg=="} and (second[3], second[4], second[5]) == (7, -0.25, "short")
    assert third == [3, "tiny", None, None, None, "fine"]
    assert any("cell limit" in w for w in out.warnings), out.warnings


def test_a_cut_cell_is_warned_and_truncated_stays_for_the_row_and_byte_limits(tmp_path) -> None:
    """A cut cell is reported by its warning; truncated is set only by the
    row or byte limit. Wave-3 set it for a cut cell too, as PostgreSQL,
    MySQL, Oracle, Db2 and ClickHouse do, and db_profile_table then refused
    any SQLite table whose MIN/MAX exceeded the cell limit (see the next
    test), until the server tells a cut cell from a cut result."""
    conn = _long_values(tmp_path)
    cut = conn.execute_query(QuerySpec(sql="SELECT id, body FROM docs WHERE id = 1", max_cell_bytes=100))
    assert cut.truncated is False and cut.rows == [[1, "p" * 100]]
    assert any("cell limit" in w for w in cut.warnings) and not any("result truncated by" in w for w in cut.warnings)
    whole = conn.execute_query(QuerySpec(sql="SELECT id, body FROM docs WHERE id = 3", max_cell_bytes=100))
    assert whole.truncated is False and whole.warnings == []
    rows = conn.execute_query(QuerySpec(sql="SELECT id, body FROM docs ORDER BY id", max_rows=1, max_cell_bytes=100))
    assert rows.truncated is True and any("result truncated by row limit" in w for w in rows.warnings)


def test_a_profile_of_long_text_in_a_column_declared_otherwise_is_returned(tmp_path) -> None:
    """Wave-3 review: SQLite keeps any text in a column declared DATE or
    NUMERIC, and the profile cuts MIN/MAX server-side only for string
    columns. A MIN/MAX past the cell limit was cut, the result flagged
    truncated, and db_profile_table refused the whole table as LIMIT_EXCEEDED
    ('the profile's aggregate row exceeds security.max_response_bytes'),
    which no ceiling raise cured. It is profiled, as before wave 3."""
    import asyncio

    from universal_db_mcp.config import load_resolved
    from universal_db_mcp.server import AppContext, build_server

    db = tmp_path / "readings.db"
    with closing(sqlite3.connect(db)) as c:
        c.execute("CREATE TABLE readings (id INTEGER PRIMARY KEY, taken DATE, amount NUMERIC, note TEXT)")
        c.executemany(
            "INSERT INTO readings VALUES (?, ?, ?, ?)",
            [(1, "2026-01-01", 5, "ok"), (2, "x" * 20000, 7, "fine"), (3, "2026-01-03", "y" * 20000, "n")],
        )
        c.commit()
    config = tmp_path / "config.yaml"
    config.write_text(
        "application:\n"
        f"  audit_path: {tmp_path / 'audit.jsonl'}\n  metadata_cache_path: {tmp_path / 'cache.sqlite'}\n"
        f"connections:\n  lite:\n    type: sqlite\n    database: {db}\n",
        encoding="utf-8",
    )
    server = build_server(AppContext(*load_resolved(config)))
    result = asyncio.run(server.call_tool("db_profile_table", {"connection_id": "lite", "object_name": "readings"}))
    columns = {c["name"]: c for c in result.structured_content["data"]["columns"]}
    assert columns["taken"]["max"] == "x" * 200 and columns["amount"]["max"] == "y" * 200, columns
    assert columns["note"]["distinct"] == 3


def test_a_value_past_the_length_limit_is_refused_with_the_limit_named(tmp_path) -> None:
    """Wave-3 review (I18): a stored value longer than SQLITE_LIMIT_LENGTH
    fails every read of it, length() and substr() included, and the caller
    got only the engine's 'string or blob too big'. The refusal now names the
    server's limit and what raises it; the category stays QUERY_ERROR."""
    from universal_db_mcp.config import ConnectionConfig, ResolvedConnection, SecurityConfig
    from universal_db_mcp.connectors.sqlite import SQLiteConnector
    from universal_db_mcp.security.policy import EffectivePolicy

    db = tmp_path / "big.db"
    with closing(sqlite3.connect(db)) as c:
        c.execute("CREATE TABLE big (id INTEGER PRIMARY KEY, v TEXT)")
        c.execute("INSERT INTO big VALUES (1, ?)", ("x" * (17 << 20),))
        c.commit()
    resolved = ResolvedConnection("big", ConnectionConfig.model_validate({"type": "sqlite", "database": str(db)}))
    conn = SQLiteConnector(resolved, EffectivePolicy.build(SecurityConfig(max_response_bytes=1 << 20), resolved))
    assert conn.execute_query(QuerySpec(sql="SELECT id FROM big")).rows == [[1]]
    for sql in ("SELECT id, length(v) FROM big", "SELECT id, substr(v, 1, 10) FROM big"):
        with pytest.raises(ConnectorError) as info:
            conn.execute_query(QuerySpec(sql=sql))
        assert info.value.category == "QUERY_ERROR"
        assert "16 MiB" in str(info.value) and "security.max_response_bytes" in str(info.value), str(info.value)
        assert info.value.__cause__ is None and info.value.__suppress_context__, "own text: the server keeps it"


def test_the_length_refusal_names_the_limit_sqlite_applies(tmp_path) -> None:
    """Wave-3 review: SQLite never sets SQLITE_LIMIT_LENGTH above its
    compile-time SQLITE_MAX_LENGTH (1,000,000,000 bytes by default), so with
    max_response_bytes past about 59.6 MiB the refusal named a limit SQLite
    does not apply (100 MiB: '1600 MiB', in force 953 MiB) and advised raising
    max_response_bytes, which then changes nothing. The heap cap and the
    capability text derive from the same clamped length."""
    from universal_db_mcp.config import ConnectionConfig, ResolvedConnection, SecurityConfig
    from universal_db_mcp.connectors.sqlite import SQLiteConnector
    from universal_db_mcp.security.policy import EffectivePolicy

    db = tmp_path / "t.db"
    sqlite3.connect(db).close()
    with closing(sqlite3.connect(":memory:")) as probe:  # 953 MiB, less on a library built lower
        probe.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 1_000_000_000)
        in_force = probe.getlimit(sqlite3.SQLITE_LIMIT_LENGTH)
    resolved = ResolvedConnection("big", ConnectionConfig.model_validate({"type": "sqlite", "database": str(db)}))
    conn = SQLiteConnector(resolved, EffectivePolicy.build(SecurityConfig(max_response_bytes=100 << 20), resolved))
    with pytest.raises(ConnectorError) as info:
        conn.execute_query(QuerySpec(sql=f"SELECT zeroblob({in_force + 1})"))  # refused before it is allocated
    text = str(info.value)
    assert info.value.category == "QUERY_ERROR" and f"({in_force >> 20} MiB: SQLite's own ceiling" in text, text
    assert "1600 MiB" not in text and "raising security.max_response_bytes" not in text, text
    query = next(x.detail for x in conn.capabilities().limitations if x.scope == "query")
    assert f"({(32 * 1_000_000_000) >> 20} MiB here)" in query, query


def test_what_the_statement_compares_is_compared_whole(tmp_path) -> None:
    """Cutting in the select list must not change the result: an output the
    statement orders, groups or filters by (SQLite resolves a result alias
    in WHERE, GROUP BY and ORDER BY), or a DISTINCT, keeps its whole value
    there. The two bodies differ only past the cell limit."""
    conn = _long_values(tmp_path)

    def ids(sql: str, parameters=None) -> list[int]:  # type: ignore[no-untyped-def]
        return [row[0] for row in conn.execute_query(QuerySpec(sql=sql, parameters=parameters)).rows]

    assert ids("SELECT id, body AS b FROM docs WHERE id < 3 ORDER BY b") == [2, 1]
    assert ids("SELECT id, body FROM docs WHERE id < 3 ORDER BY 2") == [2, 1]
    assert ids("SELECT id, body AS b FROM docs WHERE b = ?", [_PREFIX + "a"]) == [2]
    assert ids("SELECT count(*), body AS b FROM docs WHERE id < 3 GROUP BY b") == [1, 1]
    distinct = conn.execute_query(QuerySpec(sql="SELECT DISTINCT body FROM docs WHERE id < 3"))
    assert len(distinct.rows) == 2


def test_a_value_the_cut_cannot_read_leaves_the_statement_as_written(tmp_path) -> None:
    """The cut is a Python function, so SQLite hands it each value as Python
    text: a stored value that is not UTF-8 fails it, even in a row the
    statement sorts and the caller never reads. The statement then runs as
    written, and a result that never shows that value is returned."""
    conn = _long_values(tmp_path, bad_text=True)
    out = conn.execute_query(QuerySpec(sql="SELECT id, note FROM docs ORDER BY coalesce(r, 99)", max_rows=1))
    assert out.rows == [[2, "short"]] and out.truncated
    with pytest.raises(ConnectorError) as exc:
        conn.execute_query(QuerySpec(sql="SELECT id, note FROM docs WHERE id = 3"))
    assert exc.value.category == "QUERY_ERROR"
    assert "user-defined function" not in str(exc.value), "the engine's own error, not the cut's"


@pytest.mark.parametrize(
    ("sql", "parameters", "expected"),
    [
        ("SELECT id FROM docs ORDER BY id LIMIT ?", [2], [[1], [2]]),
        ("SELECT id FROM docs ORDER BY id LIMIT -1 OFFSET 1", None, [[2], [3]]),
        ("SELECT id FROM docs ORDER BY id LIMIT 1, 1", None, [[2]]),
        ("SELECT id FROM docs WHERE id = 1 UNION ALL SELECT id FROM docs WHERE id = 3", None, [[1], [3]]),
        ("VALUES (1, 'a'), (2, 'b')", None, [[1, "a"], [2, "b"]]),
        ("SELECT * FROM docs d JOIN docs e ON e.id = d.id WHERE d.id = 3", None, [[3, "tiny", None, None, None,
                                                                                    "fine"] * 2]),
    ],
)
def test_every_statement_shape_returns_what_it_returned_before(tmp_path, sql, parameters, expected) -> None:
    conn = _long_values(tmp_path)
    assert conn.execute_query(QuerySpec(sql=sql, parameters=parameters)).rows == expected


def test_metadata_calls_at_the_heap_cap_fail_as_limit_errors(connector, monkeypatch) -> None:
    """Review round 5: only queries mapped SQLite's MemoryError at the heap
    cap. list_tables and the other metadata calls raised it raw (reported as
    INTERNAL_ERROR 'MemoryError'), and health_check was unhealthy with an
    empty detail."""
    real_open = type(connector)._open

    class _Full:
        def __init__(self, handle: sqlite3.Connection) -> None:
            self.handle = handle

        def execute(self, *_a: object) -> None:
            raise MemoryError

        def close(self) -> None:
            self.handle.close()

    monkeypatch.setattr(type(connector), "_open", lambda self: _Full(real_open(self)))
    connector._heap_cap = 512 * 1024 * 1024
    for call in (
        lambda: connector.list_tables(None, {"table"}, None),
        lambda: connector.list_columns("main", "customers"),
        lambda: connector.get_table("main", "customers"),
        lambda: connector.explain("SELECT 1", analyze=False),
    ):
        with pytest.raises(ConnectorError) as exc:
            call()
        assert exc.value.category == "LIMIT_EXCEEDED" and "512 MiB" in str(exc.value), str(exc.value)
        assert exc.value.__cause__ is None and exc.value.__suppress_context__, "own text: the size is not redacted"
    health = connector.health_check()
    assert health.healthy is False and "512 MiB" in (health.detail or ""), health.detail


_TOOL_CHILD = """
import asyncio, json, sqlite3, sys
sqlite3.connect(":memory:").execute("PRAGMA hard_heap_limit = 67108864").fetchone()
from universal_db_mcp.config import load_resolved
from universal_db_mcp.server import AppContext, build_server
cfg, resolved = load_resolved(sys.argv[1])
server = build_server(AppContext(cfg, resolved))
try:
    res = asyncio.run(server.call_tool("db_query", {"connection_id": "lite", "sql": sys.argv[2], "max_rows": 1}))
    print(json.dumps(res[1] if isinstance(res, tuple) else str(res), default=str))
except Exception as exc:  # the MCP layer raises a tool's error
    print(json.dumps(str(exc)))
"""


@_NEEDS_HEAP_LIMIT
def test_the_heap_refusal_keeps_its_size_at_the_tool(tmp_path) -> None:
    """Review round 5: the refusal was raised from the MemoryError, so the
    server took it for driver text and redacted its number: callers read
    '(<redacted> MiB, shared by ...)'."""
    import json
    import subprocess
    import sys

    sqlite3.connect(tmp_path / "lite.db").executescript("CREATE TABLE IF NOT EXISTS t (x);").close()
    config = tmp_path / "config.yaml"
    config.write_text(
        f"""
application:
  metadata_cache_path: {tmp_path}/cache.sqlite
  audit_path: {tmp_path}/audit.jsonl
connections:
  lite:
    type: sqlite
    database: {tmp_path}/lite.db
""",
        encoding="utf-8",
    )
    sql = (
        "WITH RECURSIVE b(n, s) AS (SELECT 1, 'x' UNION ALL SELECT n + 1, s || s FROM b WHERE n < 22), "
        "t(k, s) AS (SELECT 1, (SELECT s FROM b WHERE n = 22) UNION ALL SELECT k + 1, s || '' FROM t WHERE k < 40) "
        "SELECT k FROM t ORDER BY s || k"
    )
    done = subprocess.run(  # noqa: S603 - this interpreter, fixed script
        [sys.executable, "-c", _TOOL_CHILD, str(config), sql],
        capture_output=True, text=True, timeout=120, check=False,
    )
    assert done.returncode == 0, done.stderr[-3000:]
    text = json.dumps(json.loads(done.stdout.strip().splitlines()[-1]))
    assert "LIMIT_EXCEEDED" in text and "64 MiB" in text, text
    assert "<redacted> MiB" not in text, text
