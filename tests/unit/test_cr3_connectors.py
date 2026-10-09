"""Connector fixes from the third /code-review max pass (2026-10-03).

- CH-MEM (owner decision 3): the ClickHouse connector sends max_memory_usage
  (options.max_memory_usage, 2 GiB by default) with every request where the
  account's profile accepts settings; a readonly=1 profile is detected at
  connect and nothing is sent; doctor --connectivity reports such an account
  without a limit of its own as FATAL unless options.memory_limit_from_profile
  acknowledges it. MEMORY_LIMIT_EXCEEDED is LIMIT_EXCEEDED.
- #11: MySQL/MariaDB GROUP BY/ORDER BY terms that name no column (RAND(),
  NULL, COUNT(*), '2', -2, a subquery) compare no output: the in-place cut
  stays (MariaDB no longer refuses, MySQL no longer materializes). Only a bound
  parameter, which PyMySQL may write as an integer, can be a position.
- SQLite notes: the shadow-table prefilter reads quote-doubled spellings
  ('customer''s notes_content'); 'x IN <string>' (and main.'t', 'main'.'t')
  names a table; a comment in a virtual table's definition no longer hides its
  module; the per-row Python cut function is replaced by a pure-SQL cut; the
  statement is parsed once when the shadow check parses it.
"""

from __future__ import annotations

import os
import sqlite3
import time
import types
from contextlib import closing
from pathlib import Path
from typing import Any

import pytest
import sqlglot
from test_hardening_2026_09_27_clickhouse import _make, _ServerError, _Setting
from test_hardening_2026_09_27_connectors_sql import _Col, _my_prepared, _Rows

from universal_db_mcp.config import (
    ConfigError,
    ConnectionConfig,
    ResolvedConnection,
    SecurityConfig,
    load_resolved,
)
from universal_db_mcp.connectors import clickhouse as ch_module
from universal_db_mcp.connectors import sqlite as sqlite_module
from universal_db_mcp.connectors.base import ConnectorError, QuerySpec
from universal_db_mcp.connectors.clickhouse import DEFAULT_MAX_MEMORY_USAGE, memory_limit_status
from universal_db_mcp.connectors.driver_helpers import SelectList
from universal_db_mcp.connectors.mysql import _mysql_capped_select, _mysql_compared_outputs, _mysql_select
from universal_db_mcp.connectors.sqlite import SQLiteConnector
from universal_db_mcp.diagnostics import doctor
from universal_db_mcp.models.responses import ErrorCategory
from universal_db_mcp.security.policy import EffectivePolicy
from universal_db_mcp.security.sql_guard import mask_pyformat_placeholders

# ---------------------------------------------------------------------------
# CH-MEM: ClickHouse per-query memory limit
# ---------------------------------------------------------------------------


class _Client:
    def __init__(self, server: dict[str, _Setting]) -> None:
        self.server_settings = server


@pytest.mark.parametrize(
    ("server", "cap", "sent", "profile_limit"),
    [
        ({}, DEFAULT_MAX_MEMORY_USAGE, DEFAULT_MAX_MEMORY_USAGE, 0),  # a server listing nothing
        ({"readonly": _Setting("0"), "max_memory_usage": _Setting("0")}, 5 << 20, 5 << 20, 0),
        ({"readonly": _Setting("2"), "max_memory_usage": _Setting("0")}, 5 << 20, 5 << 20, 0),
        # a lower profile limit is kept, a higher one is tightened
        ({"readonly": _Setting("0"), "max_memory_usage": _Setting("1000000")}, 5 << 20, 0, 1000000),
        ({"readonly": _Setting("0"), "max_memory_usage": _Setting("99999999999")}, 5 << 20, 5 << 20, 99999999999),
        # readonly=1 refuses every setting: nothing is sent
        ({"readonly": _Setting("1"), "max_memory_usage": _Setting("0", 1)}, 5 << 20, 0, 0),
        ({"readonly": _Setting("1"), "max_memory_usage": _Setting("1000000", 1)}, 5 << 20, 0, 1000000),
        # pinned by a constraint: not sent
        ({"readonly": _Setting("0"), "max_memory_usage": _Setting("0", 1)}, 5 << 20, 0, 0),
    ],
)
def test_ch_memory_limit_status(server: dict[str, _Setting], cap: int, sent: int, profile_limit: int) -> None:
    status = memory_limit_status(_Client(server), cap)
    assert (status["sent"], status["profile_limit"]) == (sent, profile_limit), status
    assert bool(status["why"]) == (not sent)


def _ch_connect(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, server: dict[str, _Setting], **options: Any) -> Any:
    conn, state = _make(monkeypatch, tmp_path, server=server)
    conn.connection.config.options.update(options)
    return conn, state, conn._connect()


def test_ch_every_request_carries_the_default_memory_limit(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    conn, _state, client = _ch_connect(monkeypatch, tmp_path, {"readonly": _Setting("0")})
    assert client.params["max_memory_usage"] == DEFAULT_MAX_MEMORY_USAGE == 2 * 1024**3
    assert f"max_memory_usage={DEFAULT_MAX_MEMORY_USAGE}" in conn.session_report()["applied"]


def test_ch_options_set_the_memory_limit(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _conn, _state, client = _ch_connect(
        monkeypatch, tmp_path, {"readonly": _Setting("2")}, max_memory_usage=200 * 1024 * 1024
    )
    assert client.params["max_memory_usage"] == 200 * 1024 * 1024


def test_ch_a_readonly_1_profile_gets_no_memory_setting(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """readonly=1 rejects every SET: sending the limit would fail every query."""
    conn, _state, client = _ch_connect(monkeypatch, tmp_path, {"readonly": _Setting("1")})
    assert "max_memory_usage" not in client.params
    report = conn.session_report()
    assert any(s.startswith("max_memory_usage:") and "readonly=1" in s for s in report["skipped"]), report
    assert not any(a.startswith("max_execution_time") for a in report["applied"]), "skipped, not applied"


def test_ch_the_memory_limit_rides_on_the_query_stream(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    conn, state = _make(monkeypatch, tmp_path, server={"readonly": _Setting("0")})
    seen: list[Any] = []
    real = ch_module.ClickHouseConnector._open_stream

    def spy(self: Any, client: Any, spec: QuerySpec, settings: dict[str, Any]) -> Any:
        seen.append(dict(client.params))
        return real(self, client, spec, settings)

    monkeypatch.setattr(ch_module.ClickHouseConnector, "_open_stream", spy)
    conn._execute(QuerySpec(sql="SELECT v FROM t", max_rows=10))
    assert seen and seen[0]["max_memory_usage"] == DEFAULT_MAX_MEMORY_USAGE


@pytest.mark.parametrize(
    ("error", "category", "words"),
    [
        (_ServerError("Code: 241. DB::Exception: Query memory limit exceeded: would use 225 MiB", 241),
         ErrorCategory.LIMIT, "options.max_memory_usage"),
        (_ServerError("Code: 452. DB::Exception: Setting max_memory_usage shouldn't be greater than 1000", 452),
         ErrorCategory.CONFIG, "within the profile's constraint"),
    ],
)
def test_ch_memory_errors_say_what_to_change(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, error: Exception, category: str, words: str
) -> None:
    def failing(*_a: Any, **_k: Any) -> Any:
        raise error

    conn, _state = _make(monkeypatch, tmp_path, server={"readonly": _Setting("0")})
    monkeypatch.setattr(ch_module.ClickHouseConnector, "_open_stream", lambda self, client, spec, settings: failing())
    with pytest.raises(ConnectorError) as info:
        conn._execute(QuerySpec(sql="SELECT v FROM t", max_rows=10))
    assert info.value.category == category and words in str(info.value)


def _ch_config(tmp_path: Path, options: str = "") -> Path:
    os.environ["UDBMCP_CR3_CH_USER"] = "default"
    path = tmp_path / "config.yaml"
    path.write_text(
        "application:\n  transport: stdio\n"
        f"  audit_path: {tmp_path / 'audit.jsonl'}\n  metadata_cache_path: {tmp_path / 'cache.sqlite'}\n"
        "security:\n  read_only: true\n  allow_write_operations: false\n  require_remote_tls: false\n"
        "connections:\n  ch:\n    type: clickhouse\n    host: 127.0.0.1\n    port: 8124\n    database: default\n"
        "    username_env: UDBMCP_CR3_CH_USER\n    read_only: true\n" + options,
        encoding="utf-8",
    )
    return path


def test_ch_memory_options_load_through_the_config_file(tmp_path: Path) -> None:
    options = "    options:\n      max_memory_usage: 209715200\n      memory_limit_from_profile: true\n"
    path = _ch_config(tmp_path, options)
    _app, resolved = load_resolved(path)
    conn = ch_module.ClickHouseConnector(resolved["ch"], EffectivePolicy.build(SecurityConfig(), resolved["ch"]))
    assert conn.memory_cap() == 209715200
    assert resolved["ch"].config.options["memory_limit_from_profile"] is True
    for bad in ("0", "true", "'2G'", "1.5"):
        with pytest.raises((ConfigError, ValueError), match="max_memory_usage"):
            load_resolved(_ch_config(tmp_path, f"    options:\n      max_memory_usage: {bad}\n"))


def _memory_check(report: dict[str, Any]) -> dict[str, Any]:
    return next(c for c in report["checks"] if c["check"] == "connection-ch-memory-limit")


def _status(readonly: str, profile_limit: int = 0) -> dict[str, Any]:
    status = memory_limit_status(
        _Client({"readonly": _Setting(readonly), "max_memory_usage": _Setting(str(profile_limit))}),
        DEFAULT_MAX_MEMORY_USAGE,
    )
    assert status["readonly"] == readonly
    return status


def test_doctor_offline_says_what_is_sent_without_logging_in(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def no_login(self: Any) -> Any:
        raise AssertionError("offline doctor must not log in")

    monkeypatch.setattr(ch_module.ClickHouseConnector, "memory_limit", no_login)
    check = _memory_check(doctor.run_doctor(str(_ch_config(tmp_path))))
    assert check["status"] == "ok" and "max_memory_usage=2147483648" in check["detail"]


@pytest.mark.parametrize(
    ("status", "options", "expected"),
    [
        (lambda: _status("1"), "", "fatal"),
        (lambda: _status("1"), "    options:\n      memory_limit_from_profile: true\n", "ok"),
        (lambda: _status("1", 1_000_000_000), "", "ok"),  # the account has its own limit
        (lambda: _status("0"), "", "ok"),  # the connector's own limit is accepted
        (lambda: _status("2"), "", "ok"),
    ],
)
def test_doctor_connectivity_reports_a_readonly_1_account_without_a_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, status: Any, options: str, expected: str
) -> None:
    import socket

    monkeypatch.setattr(ch_module.ClickHouseConnector, "memory_limit", lambda self: status())
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: closing(types.SimpleNamespace(close=lambda: None)))
    report = doctor.run_doctor(str(_ch_config(tmp_path, options)), connectivity=True)
    check = _memory_check(report)
    assert check["status"] == expected, check
    if expected == "fatal":
        assert "ALTER USER" in check["detail"] and "memory_limit_from_profile: true" in check["detail"]
        assert not report["healthy"]


def test_doctor_connectivity_reports_a_login_failure_as_a_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refused(self: Any) -> Any:
        raise ConnectorError("Authentication failed")

    monkeypatch.setattr(ch_module.ClickHouseConnector, "memory_limit", refused)
    check = _memory_check(doctor.run_doctor(str(_ch_config(tmp_path)), connectivity=True))
    assert check["status"] == "warning" and "could not read" in check["detail"]


# ---------------------------------------------------------------------------
# #11: MySQL/MariaDB terms that name no column keep the in-place cut
# ---------------------------------------------------------------------------

# (a subquery is never the in-place form: _mysql_select)
_VALUE_TERMS = ["RAND()", "NULL", "'2'", "-2", "2.0", "0x2", "CAST(2 AS SIGNED)", "2 + 0"]


@pytest.mark.parametrize(
    ("clause", "term"),
    [("ORDER BY", t) for t in _VALUE_TERMS] + [("GROUP BY id ORDER BY", t) for t in [*_VALUE_TERMS, "COUNT(*)"]],
)
def test_mysql_a_value_term_is_cut_in_place(term: str, clause: str) -> None:
    sql = f"SELECT id, body FROM docs {clause} {term} LIMIT 3"
    select = _mysql_select(sql)
    assert select is not None
    description = [_Col("id", 3, 11), _Col("body", 252, 65535)]
    assert _mysql_capped_select(select, description, {1}, 100) == (
        f"SELECT id, LEFT(body, 101) AS `body` FROM docs {clause} {term} LIMIT 3"
    )


@pytest.mark.parametrize("term", ["%s", "(%s)", "%(p)s", "%s COLLATE utf8mb4_bin"])
def test_mysql_a_bound_term_may_be_a_position(term: str) -> None:
    """PyMySQL writes an int as 2, True as 1, Decimal('2') as 2 (live, 9.7:
    ORDER BY %s with 2 sorted by the second column)."""
    sql = f"SELECT id, body FROM docs ORDER BY {term}"
    tree = sqlglot.parse_one(mask_pyformat_placeholders(sql), read="mysql")
    assert _mysql_compared_outputs(tree, ["id", "body"]) == {0, 1}  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT id, notes FROM t ORDER BY RAND() LIMIT 3",
        "SELECT cat, COUNT(*) AS n, MIN(notes) AS notes FROM t GROUP BY cat ORDER BY COUNT(*) DESC",
        "SELECT id, notes FROM t ORDER BY NULL",
    ],
)
@pytest.mark.parametrize("server", ["9.7.2", "5.5.5-10.11.6-MariaDB-1"])
def test_mysql_and_mariadb_serve_value_terms_with_the_in_place_cut(
    monkeypatch: pytest.MonkeyPatch, sql: str, server: str
) -> None:
    """The finding's repro: MariaDB refused these ('does not keep the ORDER BY
    of the derived table'), MySQL ran them as a materialized derived table."""
    width = 3 if "cat" in sql else 2
    description = [_Col("cat", 3, 11), _Col("n", 8, 21), _Col("notes", 252, 65535)][-width:]
    state = _Rows([(1, 2, "x")[-width:]], description)
    conn, _asked = _my_prepared(monkeypatch, state, server_version=server)
    conn._execute(QuerySpec(sql=sql, max_cell_bytes=100))
    ran = state.statements[-1][0]
    assert "LEFT(" in ran and "101) AS `notes`" in ran and "udbmcp_q" not in ran, ran


def test_mariadb_still_refuses_a_bound_position_it_cannot_cut_in_place(monkeypatch: pytest.MonkeyPatch) -> None:
    state = _Rows([(1, "x")], [_Col("id", 3, 11), _Col("notes", 252, 65535)])
    conn, _asked = _my_prepared(monkeypatch, state, server_version="5.5.5-10.11.6-MariaDB-1")
    with pytest.raises(ConnectorError, match="MariaDB"):
        conn._execute(QuerySpec(sql="SELECT id, notes FROM t ORDER BY %s", parameters=[2], max_cell_bytes=100))


# ---------------------------------------------------------------------------
# SQLite
# ---------------------------------------------------------------------------


def _connector(db: Path) -> SQLiteConnector:
    resolved = ResolvedConnection("t", ConnectionConfig.model_validate({"type": "sqlite", "database": str(db)}))
    return SQLiteConnector(resolved, EffectivePolicy.build(SecurityConfig(), resolved))


def _db(path: Path, script: str) -> Path:
    with closing(sqlite3.connect(path)) as c:
        c.executescript(script)
        c.commit()
    return path


def _fts5(tmp_path: Path, name: str = "customer's notes") -> SQLiteConnector:
    quoted = '"' + name.replace('"', '""') + '"'
    try:
        db = _db(
            tmp_path / "f.db",
            f"CREATE VIRTUAL TABLE {quoted} USING fts5(ssn, note);"
            f"INSERT INTO {quoted} VALUES ('123-45-6789', 'vip');"
            "CREATE TABLE plain (id INTEGER, note TEXT); INSERT INTO plain VALUES (1, 'n');",
        )
    except sqlite3.OperationalError:
        pytest.skip("this SQLite build has no FTS5")
    return _connector(db)


@pytest.mark.parametrize(
    ("name", "sql"),
    [
        ("customer's notes", "SELECT * FROM 'customer''s notes_content'"),
        ("customer's notes", "SELECT * FROM 'Customer''S Notes_data'"),
        ('x"y', 'SELECT * FROM "x""y_content"'),
        ("a`b", "SELECT * FROM `a``b_content`"),
    ],
)
def test_sqlite_a_quote_doubled_shadow_table_is_refused(tmp_path: Path, name: str, sql: str) -> None:
    conn = _fts5(tmp_path, name)
    with pytest.raises(ConnectorError, match="internal table"):
        conn.execute_query(QuerySpec(sql=sql))
    assert conn.execute_query(QuerySpec(sql="SELECT id FROM plain")).rows == [[1]]


@pytest.mark.parametrize(
    "where",
    [
        "(1, '123-45-6789', 'vip') IN 'customer''s notes_content'",
        "(1, '123-45-6789', 'vip') NOT IN main.'customer''s notes_content'",
        "(1, '123-45-6789', 'vip') IN 'main'.'customer''s notes_content'",
        "(1, '123-45-6789', 'vip') IN \"customer's notes_content\"",
    ],
)
def test_sqlite_in_a_string_names_a_table(tmp_path: Path, where: str) -> None:
    conn = _fts5(tmp_path)
    with pytest.raises(ConnectorError, match="internal table"):
        conn.execute_query(QuerySpec(sql=f"SELECT 'hit' AS r WHERE {where}"))


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT id FROM plain WHERE note IN ('customer''s notes_content') OR id = 1",
        "SELECT id FROM plain WHERE note IN (SELECT note FROM plain)",
        "SELECT id FROM plain WHERE 'customer''s notes_content' = note OR id IN (1)",
    ],
)
def test_sqlite_lists_strings_and_functions_after_in_are_no_tables(tmp_path: Path, sql: str) -> None:
    assert _fts5(tmp_path).execute_query(QuerySpec(sql=sql)).rows == [[1]]


@pytest.mark.parametrize(
    "ddl",
    [
        "CREATE VIRTUAL TABLE posts -- note\n USING fts5(title, body);",
        "CREATE VIRTUAL TABLE posts /* x */ USING fts5(title, body);",
        "CREATE VIRTUAL TABLE posts USING /* m */ fts5(title, body);",
        'CREATE VIRTUAL TABLE "posts"USING fts5(title, body);',
        "CREATE VIRTUAL TABLE [posts]USING fts5(title, body);",
        'CREATE VIRTUAL TABLE posts USING"fts5"(title, body);',
        "CREATE VIRTUAL TABLE posts /* USING rtree */ USING fts5(title, body);",
    ],
)
def test_sqlite_a_comment_in_a_virtual_table_definition_hides_no_plain_table(tmp_path: Path, ddl: str) -> None:
    try:
        db = _db(
            tmp_path / "c.db",
            ddl + "INSERT INTO posts VALUES ('hello', 'world');"
            "CREATE TABLE posts_archive (id INTEGER, title TEXT); INSERT INTO posts_archive VALUES (1, 'old');"
            "CREATE TABLE posts_stat (day TEXT, views INTEGER); INSERT INTO posts_stat VALUES ('d', 42);",
        )
    except sqlite3.OperationalError:
        pytest.skip("this SQLite build has no FTS5 or does not take this spelling")
    with closing(sqlite3.connect(db)) as c:
        stored = c.execute("SELECT sql FROM sqlite_master WHERE name = 'posts'").fetchone()[0]
    assert sqlite_module._module_of(stored) == "fts5", stored
    conn = _connector(db)
    names = {t.name for t in conn.list_tables(None, set(), None)}
    assert {"posts_archive", "posts_stat"} <= names
    assert conn.execute_query(QuerySpec(sql="SELECT * FROM posts_archive")).rows == [[1, "old"]]
    assert conn.execute_query(QuerySpec(sql="SELECT views FROM posts_stat")).rows == [[42]]
    with pytest.raises(ConnectorError, match="internal table"):
        conn.execute_query(QuerySpec(sql="SELECT * FROM posts_content"))


@pytest.mark.parametrize(
    "text",
    ["/*" * 500_000, "--\n" * 350_000, "'" * 1_000_000, "-/" * 500_000, '"' + "x" * 1_000_000],
)
def test_sqlite_comment_blanking_is_linear(text: str) -> None:
    start = time.perf_counter()
    sqlite_module._without_comments(text)
    assert time.perf_counter() - start < 2.0
    start = time.perf_counter()
    sqlite_module._module_of("CREATE VIRTUAL TABLE " + text)
    assert time.perf_counter() - start < 2.0


def _long(tmp_path: Path) -> SQLiteConnector:
    db = _db(tmp_path / "l.db", "CREATE TABLE docs (id INTEGER PRIMARY KEY, body TEXT, raw BLOB, n INTEGER, r REAL);")
    with closing(sqlite3.connect(db)) as c:
        c.executemany(
            "INSERT INTO docs VALUES (?, ?, ?, ?, ?)",
            [(1, "p" * 5000, b"\x01" * 5000, 2**62, 1.5), (2, "short", b"\x02", 7, None), (3, None, None, None, None)],
        )
        c.commit()
    return _connector(db)


def _traced(conn: SQLiteConnector, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    ran: list[str] = []
    real_open = SQLiteConnector._open

    def tracing(self: SQLiteConnector) -> sqlite3.Connection:
        handle = real_open(self)
        handle.set_trace_callback(ran.append)
        return handle

    monkeypatch.setattr(SQLiteConnector, "_open", tracing)
    return ran


def test_sqlite_values_are_cut_in_sql_and_keep_their_types(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    conn = _long(tmp_path)
    ran = _traced(conn, monkeypatch)
    for sql in ("SELECT id, body, raw, n, r FROM docs ORDER BY random()", "SELECT id, body, raw, n, r FROM docs"):
        out = conn.execute_query(QuerySpec(sql=sql, max_cell_bytes=100))
        rows = sorted(out.rows, key=lambda r: r[0])
        assert rows[0][1] == "p" * 100 and rows[0][2]["$truncated"] is True
        assert (rows[0][3], rows[0][4]) == (str(2**62), 1.5)
        assert rows[1][1:] == ["short", {"$binary_b64": "Ag=="}, 7, None] and rows[2][1:] == [None] * 4
    assert any("CASE typeof(body) WHEN 'text'" in s for s in ran), ran
    assert not any("udbmcp_cut" in s for s in ran), "no Python function is called per row"


def test_sqlite_the_cut_holds_no_whole_value_per_column() -> None:
    """The cut keeps types; its memory over 64 wide columns is pinned by
    test_a_row_of_many_large_columns_is_bounded_in_the_server_process
    (substr() with constant bounds kept every column's whole value)."""
    doubling = "WITH RECURSIVE t(n, s) AS (SELECT 1, 'x' UNION ALL SELECT n + 1, s || s FROM t WHERE n < 22) "
    with closing(sqlite3.connect(":memory:")) as c:
        cut = sqlite_module._sql_cut("s", 101)
        row = c.execute(f"{doubling}SELECT {cut} AS a, {cut} AS b, typeof({sqlite_module._sql_cut('n', 101)}) "
                        "FROM t WHERE n = 22").fetchone()
        assert row == ("x" * 101, "x" * 101, "integer")


def test_sqlite_a_select_list_parameter_is_not_repeated(tmp_path: Path) -> None:
    """The cut names its expression twice; a '?' in it would renumber the
    parameters after it, so such a select list is not cut in SQL."""
    conn = _long(tmp_path)
    out = conn.execute_query(
        QuerySpec(sql="SELECT substr(body, ?) AS b, n FROM docs WHERE id = ?", parameters=(4990, 1), max_cell_bytes=100)
    )
    assert out.rows == [["p" * 11, str(2**62)]]


def test_sqlite_the_statement_is_parsed_once_when_the_shadow_check_parses_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    conn = _fts5(tmp_path, "notes")
    trees: list[Any] = []
    real = SelectList.locate.__func__  # type: ignore[attr-defined]

    def spy(cls: Any, sql: str, dialect: str, **kw: Any) -> Any:
        trees.append(kw.get("tree"))
        return real(cls, sql, dialect, **kw)

    monkeypatch.setattr(SelectList, "locate", classmethod(spy))
    out = conn.execute_query(QuerySpec(sql="SELECT note AS notes_x FROM plain -- notes_", max_cell_bytes=100))
    assert out.rows == [["n"]]
    assert trees and trees[0] is not None, "the shadow check's parse is reused"
    trees.clear()
    conn.execute_query(QuerySpec(sql="SELECT note FROM plain", max_cell_bytes=100))
    assert trees == [None], "no vtab name in the text: no shadow parse, one parse for the cut"
