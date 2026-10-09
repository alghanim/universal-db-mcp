"""Regression tests for the /code-review max findings on the guard, the
parameter binding of the %-formatting drivers (PyMySQL, clickhouse-connect,
psycopg), the redaction helpers and the system-schema lists.

Ids are the review's (verdicts.md): S1 with p03L-1/p03S-1/p03L-7, A3, A4,
p03L-2, X8, E1, E4, E5, E7, H1, H2, M4, S2, R2, T1, T2.
"""

from __future__ import annotations

import os
import types
from typing import Any

import pytest

from universal_db_mcp.config import ConnectionConfig, ResolvedConnection, SecurityConfig
from universal_db_mcp.connectors.base import QuerySpec
from universal_db_mcp.errors import ToolFailure
from universal_db_mcp.models.responses import ErrorCategory
from universal_db_mcp.security.policy import EffectivePolicy
from universal_db_mcp.security.sql_guard import bind_text

# --------------------------------------------------------------------------
# S1 / p03L-1 / p03S-1: a placeholder inside a literal or a comment
# --------------------------------------------------------------------------


def _pymysql_sent(text: str, args: Any) -> str:
    """What PyMySQL sends: ``query % escaped_args`` (its own escaping)."""
    pytest.importorskip("pymysql")
    from pymysql.converters import escape_item

    if args is None:
        return text
    if isinstance(args, dict):
        return text % {k: escape_item(v, "utf8mb4") for k, v in args.items()}
    return text % tuple(escape_item(v, "utf8mb4") for v in args)


def _clickhouse_sent(text: str, params: Any) -> str:
    """What clickhouse-connect sends (its real client-side binding)."""
    from clickhouse_connect.driver.binding import bind_query

    final, server = bind_query(text, params)
    assert server == {}
    return str(final)


def test_s1_mysql_placeholder_in_a_literal_is_text_not_a_parameter() -> None:
    """The verdict's repro: "SELECT '%s' AS c" ["MARKER"] was sent as
    "SELECT ''MARKER'' AS c" — the value's quotes closed the literal."""
    with pytest.raises(ToolFailure) as info:
        bind_text("SELECT '%s' AS c", ["MARKER"], engine="mysql")
    assert info.value.category == ErrorCategory.VALIDATION
    assert "0 placeholder(s)" in str(info.value)
    # with a real placeholder too, the literal's %s stays text
    text = bind_text("SELECT '%s' AS c, %s AS d", ["MARKER"], engine="mysql")
    assert _pymysql_sent(text, ["MARKER"]) == "SELECT '%s' AS c, 'MARKER' AS d"


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT a FROM d.t WHERE name = '%(x)s'",
        "SELECT a FROM d.t /* %(x)s */ WHERE name = 'n'",
        "SELECT a FROM d.t WHERE name = \"%(x)s\"",
        "SELECT a FROM d.t WHERE name = $h$%(x)s$h$",
        "SELECT a FROM d.t -- %(x)s\nWHERE 1",
        "SELECT a FROM d.t #! %(x)s\nWHERE 1",
        "SELECT a FROM d.t /* /* */ %(x)s */ WHERE 1",
    ],
)
def test_s1_clickhouse_placeholder_in_a_literal_or_comment_is_never_filled(sql: str) -> None:
    """p03L-1: '%(x)s' inside a literal/comment took a value whose quotes
    closed the literal: '' UNION ALL SELECT secret FROM d.denied ..."""
    value = {"x": " UNION ALL SELECT secret FROM d.denied WHERE name = "}
    with pytest.raises(ToolFailure) as info:  # the value has no placeholder to go to: refused
        bind_text(sql, value, engine="clickhouse")
    assert info.value.category == ErrorCategory.VALIDATION and "['x']" in str(info.value)
    # with a real placeholder beside it, the literal's/comment's %(x)s stays text
    both = sql + " AND z = %(x)s"
    sent = _clickhouse_sent(bind_text(both, value, engine="clickhouse"), value)
    assert sent == sql + " AND z = '" + value["x"] + "'"


def test_s1_clickhouse_positional_inside_a_literal_is_refused() -> None:
    with pytest.raises(ToolFailure) as info:
        bind_text("SELECT a FROM d.t WHERE name = '%s'", ["x' OR 1=1 --"], engine="clickhouse")
    assert info.value.category == ErrorCategory.VALIDATION


def test_p03l7_bare_percent_with_parameters_is_text() -> None:
    """A LIKE pattern or a modulo next to a bound value failed client-side
    ('unsupported format character') and was reported as CONNECTION_ERROR."""
    sql = "SELECT a FROM t WHERE s LIKE 'x%' AND b % 2 = 0 AND c = %(y)s"
    sent = _clickhouse_sent(bind_text(sql, {"y": 1}, engine="clickhouse"), {"y": 1})
    assert sent == "SELECT a FROM t WHERE s LIKE 'x%' AND b % 2 = 0 AND c = 1"


def test_s1_sent_text_is_the_validated_one_byte_for_byte() -> None:
    """Everything but the real placeholders arrives as written: a
    '%(name)s' in a quoted name, an odd '%d'; the DBAPI escape '%%' in a
    string literal is one '%', as the driver always sent it (cr2 SW-1)."""
    sql = "SELECT '100%%' AS `p%(q)s`, 'x%d' AS y, %s AS z FROM t WHERE s LIKE '%s%'"
    expected = sql.replace("%s AS z", "7 AS z").replace("'100%%'", "'100%'")
    assert _pymysql_sent(bind_text(sql, [7], engine="mysql"), [7]) == expected


def test_s1_mysql_backtick_takes_no_backslash_escape() -> None:
    """MySQL ends `a\\` at its second backtick (live): reading a backslash
    escape there would make the %s after it look like a literal's text, and
    one inside the server's identifier look like code."""
    assert bind_text("SELECT `a\\` , %s", [1], engine="mysql") == "SELECT `a\\` , %s"
    # the server's identifier `a\`` , %s, ` holds the %s: text, not a parameter
    with pytest.raises(ToolFailure):
        bind_text("SELECT `a\\`` , %s, ` FROM t", [1], engine="mysql")


def test_s1_mysql_hash_and_dash_comments() -> None:
    assert bind_text("SELECT %s # %s\n", [1], engine="mysql") == "SELECT %s # %%s\n"
    # '--' without a following space is two minus signs on MySQL: code
    assert bind_text("SELECT 1--%s\n", [1], engine="mysql") == "SELECT 1--%s\n"
    assert bind_text("SELECT 1 -- %s\n, %s", [1], engine="mysql") == "SELECT 1 -- %%s\n, %s"


def test_s1_postgres_dollar_quotes_nested_comments_and_e_strings() -> None:
    assert bind_text("SELECT $doc$ %s $doc$, %s", [1], engine="postgres") == "SELECT $doc$ %%s $doc$, %s"
    assert bind_text("SELECT /* /* */ %s */ %s", [1], engine="postgres") == "SELECT /* /* */ %%s */ %s"
    assert bind_text("SELECT E'\\' %s ', %s", [1], engine="postgres") == "SELECT E'\\' %%s ', %s"
    # standard-conforming: a backslash ends nothing special in '...'
    assert bind_text("SELECT '\\', %s", [1], engine="postgres") == "SELECT '\\', %s"
    # a$b$ is an identifier, not a dollar quote
    assert bind_text("SELECT a$b$ , %s", [1], engine="postgres") == "SELECT a$b$ , %s"


@pytest.mark.parametrize(
    ("sql", "params", "needle"),
    [
        ("SELECT %s, %s", [1], "2 placeholder(s)"),
        ("SELECT %s", [1, 2], "2 positional value(s)"),
        ("SELECT %(a)s", [1], "named placeholders"),
        ("SELECT %s", {"a": 1}, "positional placeholders"),
        ("SELECT %(a)s, %(b)s", {"a": 1}, "not supplied: ['b']"),
        ("SELECT %(a)s", {"a": 1, "b": 2}, "['b'] were supplied"),
    ],
)
def test_s1_placeholders_must_match_the_values(sql: str, params: Any, needle: str) -> None:
    with pytest.raises(ToolFailure) as info:
        bind_text(sql, params, engine="mysql")
    assert info.value.category == ErrorCategory.VALIDATION and needle in str(info.value)


def test_s1_nothing_bound_is_sent_verbatim() -> None:
    assert bind_text("SELECT '%s' LIKE 'a%'", None, engine="mysql") == "SELECT '%s' LIKE 'a%'"


# --- connectors: every text the driver formats goes through bind_text ------


def _resolved(body: dict[str, Any]) -> ResolvedConnection:
    os.environ["UDBMCP_TEST_U"] = "x"
    return ResolvedConnection("c", ConnectionConfig.model_validate({**body, "username_env": "UDBMCP_TEST_U"}))


def _mysql() -> Any:
    from universal_db_mcp.connectors.mysql import MySQLConnector

    resolved = _resolved({"type": "mysql", "host": "h", "database": "d"})
    return MySQLConnector(resolved, EffectivePolicy.build(SecurityConfig(), resolved))


class _MyCursor:
    def __init__(self, sent: list[str], description: list[tuple[Any, ...]]) -> None:
        self._sent = sent
        self.description = description
        self._rows: list[tuple[Any, ...]] = [("v",)]

    def execute(self, sql: str, args: Any = None) -> None:
        self._sent.append(_pymysql_sent(sql, args))

    def mogrify(self, sql: str, args: Any = None) -> str:
        return _pymysql_sent(sql, args)

    def fetchmany(self, n: int) -> list[tuple[Any, ...]]:
        rows, self._rows = self._rows, []
        return rows

    def close(self) -> None:
        return None


class _MyConn:
    def __init__(self, sent: list[str], description: list[tuple[Any, ...]]) -> None:
        self._sent = sent
        self._description = description
        self.server_version = "9.1.0"

    def thread_id(self) -> int:
        return 7

    def cursor(self) -> _MyCursor:
        return _MyCursor(self._sent, self._description)

    def close(self) -> None:
        return None


def test_s1_mysql_connector_refuses_the_repro_before_it_connects() -> None:
    conn = _mysql()
    conn._connect = lambda: pytest.fail("must not connect")  # type: ignore[method-assign]
    with pytest.raises(ToolFailure) as info:
        conn._execute(QuerySpec(sql="SELECT '%s' AS c", parameters=["MARKER"]))
    assert info.value.category == ErrorCategory.VALIDATION


def test_s1_mysql_probe_and_capped_rewrite_send_the_validated_text() -> None:
    """The LIMIT 0 describe probe and the cell-cap rewrite are formatted by
    PyMySQL too: neither may fill the literal's %s."""
    sent: list[str] = []
    conn = _mysql()
    conn._connect = lambda: _MyConn(sent, [("notes", 252, None, 4294967295)])  # type: ignore[method-assign]
    sql = "SELECT notes FROM t WHERE tag = '%s' AND id = %s AND n LIKE 'a%'"
    conn._execute(QuerySpec(sql=sql, parameters=[5], max_cell_bytes=100))
    validated = sql.replace("id = %s", "id = 5")
    assert sent[0] == validated + "\nLIMIT 0"
    assert sent[1] == validated.replace("SELECT notes", "SELECT LEFT(notes, 101) AS `notes`")


def test_s1_mysql_prepared_describe_mogrifies_the_validated_text() -> None:
    conn = _mysql()
    pymysql = pytest.importorskip("pymysql")
    seen: list[str] = []

    class _Real(pymysql.connections.Connection):  # type: ignore[misc, name-defined]
        def __init__(self) -> None:
            pass

        def cursor(self) -> Any:
            return _MyCursor(seen, [])

        def _execute_command(self, command: int, text: Any) -> None:
            if command == pymysql.constants.COMMAND.COM_STMT_PREPARE:
                seen.append(text)
                raise pymysql.err.OperationalError(1295, "not supported")

    conn._module = pymysql
    sql = "SELECT COUNT(*) FROM (SELECT 1 FROM t WHERE x = '%s' AND y = %s) q"
    try:
        conn._prepared_description(_Real(), sql, [3])
    except pymysql.MySQLError:
        pass
    assert seen == [sql.replace("y = %s", "y = 3")]


def _pg() -> Any:
    from universal_db_mcp.connectors.postgres import PostgresConnector

    resolved = _resolved({"type": "postgres", "host": "h", "database": "d"})
    return PostgresConnector(resolved, EffectivePolicy.build(SecurityConfig(), resolved))


class _PgCol:
    """A psycopg Column: an int4 named 'c'."""

    name = "c"
    type_code = 23
    display_size = None

    def __getitem__(self, i: int) -> str:
        return self.name


class _PgCursor:
    def __init__(self, calls: list[tuple[str, Any]]) -> None:
        self._calls = calls
        self.description: list[Any] = [_PgCol()]

    def __enter__(self) -> _PgCursor:
        return self

    def __exit__(self, *a: object) -> None:
        return None

    def execute(self, sql: str, args: Any = None) -> None:
        if args is not None:
            from psycopg._queries import PostgresQuery
            from psycopg.adapt import Transformer

            q = PostgresQuery(Transformer())
            q.convert(sql, args)  # psycopg's own parse: raises on a stray '%'
            self._calls.append((q.query.decode(), args))
        else:
            self._calls.append((sql, None))

    def fetchmany(self, n: int) -> list[Any]:
        return []


class _PgConn:
    def __init__(self, calls: list[tuple[str, Any]]) -> None:
        self._calls = calls

    def cursor(self, name: str | None = None) -> _PgCursor:
        return _PgCursor(self._calls)

    def rollback(self) -> None:
        return None

    def close(self) -> None:
        return None


def _pg_run(sql: str, params: Any) -> list[tuple[str, Any]]:
    pytest.importorskip("psycopg")
    calls: list[tuple[str, Any]] = []
    conn = _pg()
    conn._connect = lambda: _PgConn(calls)
    conn._execute(QuerySpec(sql=sql, parameters=params))
    return calls


@pytest.mark.parametrize("params", [[], {}])
def test_a3_postgres_empty_parameters_send_the_text_verbatim(params: Any) -> None:
    """parameters=[] reached psycopg as () and its '%' parse failed a LIKE
    'abc%' client-side (ProgrammingError)."""
    assert _pg_run("SELECT * FROM t WHERE name LIKE 'abc%'", params) == [
        ("SELECT * FROM t WHERE name LIKE 'abc%'", None)
    ]


def test_h2_postgres_named_parameter_inside_a_dollar_quote_is_text() -> None:
    """':real' inside $doc$...$doc$ was rewritten to a placeholder: the row
    came back ' hello $1 ' (silent data change)."""
    ((sent, args),) = _pg_run("SELECT $doc$ hello :real $doc$ AS d, :real AS r", {"real": 1})
    assert sent == "SELECT $doc$ hello :real $doc$ AS d, $1 AS r" and args == {"real": 1}


def test_s1_postgres_percent_s_in_a_literal_is_not_a_parameter() -> None:
    ((sent, _args),) = _pg_run("SELECT '%s' AS a, %s AS b, 'x%' AS c", [1])
    assert sent == "SELECT '%s' AS a, $1 AS b, 'x%' AS c"


def _ch(monkeypatch: pytest.MonkeyPatch) -> tuple[Any, list[str]]:
    from clickhouse_connect.driver.query import QueryContext

    from universal_db_mcp.connectors import clickhouse as ch_module

    sent: list[str] = []

    class _Stream:
        def __init__(self) -> None:
            self.source = types.SimpleNamespace(column_names=("a",))

        def __enter__(self) -> _Stream:
            return self

        def __exit__(self, *a: object) -> None:
            return None

        def __iter__(self) -> Any:
            return iter([])

    class _Client:
        def __init__(self) -> None:
            self.params: dict[str, Any] = {}
            self.query_limit = 0
            self.server_settings = {"readonly": types.SimpleNamespace(value="1", readonly=1)}
            self._backend = types.SimpleNamespace(execute_query=lambda *a, **k: None)

        def set_client_setting(self, name: str, value: Any) -> None:
            self.params[name] = value

        def query_column_block_stream(self, query: str, parameters: Any = None, settings: Any = None) -> Any:
            sent.append(QueryContext(query, parameters=parameters).final_query)  # the real driver's binding
            return _Stream()

        def command(self, *a: Any, **k: Any) -> str:
            return "ok"

        def close(self) -> None:
            return None

    module = types.SimpleNamespace(get_client=lambda **kw: _Client())
    monkeypatch.setattr(ch_module, "open_module", lambda *_a, **_k: module)
    resolved = _resolved({"type": "clickhouse", "host": "h", "database": "d"})
    return ch_module.ClickHouseConnector(resolved, EffectivePolicy.build(SecurityConfig(), resolved)), sent


def test_s1_clickhouse_connector_sends_the_validated_statement(monkeypatch: pytest.MonkeyPatch) -> None:
    """p03S-1 end to end at the connector: the engine received the UNION."""
    conn, sent = _ch(monkeypatch)
    sql = "SELECT a FROM main.t WHERE a = '%(x)s' AND b LIKE 'p%' AND c = %(y)s"
    with pytest.raises(ToolFailure):
        conn._execute(QuerySpec(sql=sql, parameters={"x": " UNION ALL SELECT password FROM secret.users --", "y": 2}))
    conn._execute(QuerySpec(sql=sql, parameters={"y": 2}))
    assert sent == [sql.replace("%(y)s", "2")]


def test_s1_clickhouse_connector_refuses_a_mismatch_as_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    conn, sent = _ch(monkeypatch)
    with pytest.raises(ToolFailure) as info:
        conn._execute(QuerySpec(sql="SELECT a FROM t WHERE a = '%s'", parameters=["x"]))
    assert info.value.category == ErrorCategory.VALIDATION and sent == []


def test_s1_clickhouse_server_side_binding_is_left_to_the_server(monkeypatch: pytest.MonkeyPatch) -> None:
    """{name:Type} placeholders go to the server as parameters: the driver
    formats nothing, so nothing is doubled."""
    conn, sent = _ch(monkeypatch)
    sql = "SELECT a FROM t WHERE a = {x:String} AND b LIKE 'p%'"
    conn._execute(QuerySpec(sql=sql, parameters={"x": "v"}))
    assert sent == [sql]


# --- p03L-2: the driver's columns-only LIMIT 0 request ----------------------


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT * FROM d.big UNION ALL SELECT * FROM d.big LIMIT 0",
        "SELECT * FROM d.big #! LIMIT 0",
        "SELECT * FROM d.big LIMIT %(n)s",
    ],
)
def test_p03l2_a_statement_that_is_not_a_whole_limit_0_streams(monkeypatch: pytest.MonkeyPatch, sql: str) -> None:
    from clickhouse_connect.driver._backend.httpcommon import columns_only_re
    from clickhouse_connect.driver.query import remove_sql_comments

    conn, sent = _ch(monkeypatch)
    params = {"n": 0} if "%(n)s" in sql else None
    conn._execute(QuerySpec(sql=sql, parameters=params))
    (final,) = sent
    assert columns_only_re.search(remove_sql_comments(final)) is None, "would be a whole-response JSON request"
    assert final.startswith(sql.replace("%(n)s", "0")) and final.endswith("\n#!''")


def test_p03l2_a_whole_limit_0_keeps_the_columns_only_request(monkeypatch: pytest.MonkeyPatch) -> None:
    conn, sent = _ch(monkeypatch)
    conn._execute(QuerySpec(sql="SELECT a, b FROM d.t WHERE x = 1 LIMIT 0"))
    assert sent == ["SELECT a, b FROM d.t WHERE x = 1 LIMIT 0"]


def test_p03l2_explain_is_never_a_columns_only_request() -> None:
    from clickhouse_connect.driver._backend.httpcommon import columns_only_re
    from clickhouse_connect.driver.query import remove_sql_comments

    from universal_db_mcp.connectors.clickhouse import _streamed

    text = _streamed("EXPLAIN SELECT a FROM t LIMIT 0", probe_ok=False)
    assert columns_only_re.search(remove_sql_comments(text)) is None


def test_s1_value_search_with_a_percent_name_is_doubled_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """The search statement is plain SQL now; the driver boundary doubles
    a '%' in a quoted name exactly once."""
    conn, sent = _ch(monkeypatch)
    where = conn.like_predicate("lowerUTF8(`pct_%`)", conn.placeholder(1))
    sql = conn.build_search_query("s", "t%x", ["pct_%"], where, 5)
    assert "%%" not in sql
    conn._execute(QuerySpec(sql=sql, parameters=conn.pack_parameters(["%z%"])))
    assert "`pct_%`" in sent[0] and "`t%x`" in sent[0] and "'%z%'" in sent[0]



# --------------------------------------------------------------------------
# A4: PostgreSQL 10 list_routines fallback
# --------------------------------------------------------------------------


class _UndefinedColumn(Exception):
    sqlstate = "42703"


class _Pg10Conn:
    """PostgreSQL 10 under a non-autocommit psycopg connection: the failed
    prokind query aborts the transaction until a rollback."""

    def __init__(self) -> None:
        self.aborted = False
        self.ran: list[str] = []

    def __enter__(self) -> _Pg10Conn:
        return self

    def __exit__(self, *a: object) -> None:
        return None

    def execute(self, sql: str, params: Any = None) -> Any:
        if self.aborted:
            raise RuntimeError("25P02 current transaction is aborted, commands ignored until end of transaction block")
        if "prokind" in sql:
            self.aborted = True
            raise _UndefinedColumn('column p.prokind does not exist')
        self.ran.append(sql)
        return types.SimpleNamespace(fetchall=lambda: [("public", "f", "function")])

    def rollback(self) -> None:
        self.aborted = False


def test_a4_postgres10_list_routines_falls_back_after_a_rollback() -> None:
    conn = _pg()
    fake = _Pg10Conn()
    conn._connect = lambda: fake
    routines = conn.list_routines("public")
    assert [(r.schema, r.name, r.kind) for r in routines] == [("public", "f", "function")]
    assert len(fake.ran) == 1 and "proisagg" in fake.ran[0]


def test_a4_postgres_list_routines_other_errors_are_not_masked() -> None:
    from universal_db_mcp.connectors.base import ConnectorError

    class _Denied(_Pg10Conn):
        def execute(self, sql: str, params: Any = None) -> Any:
            raise PermissionError("42501 permission denied")

    conn = _pg()
    conn._connect = lambda: _Denied()
    with pytest.raises(ConnectorError, match="permission denied"):
        conn.list_routines(None)


# --------------------------------------------------------------------------
# T2: MySQL 1045 keeps its errno and hint; R2: fingerprinting is total;
# X8: the ClickHouse login name in an auth failure
# --------------------------------------------------------------------------


def test_t2_mysql_access_denied_keeps_errno_and_hint() -> None:
    from universal_db_mcp.security.redact import scrub_exception

    pymysql = pytest.importorskip("pymysql")
    exc = pymysql.err.OperationalError(1045, "Access denied for user 'svc_ro'@'172.17.0.1' (using password: YES)")
    text = scrub_exception(exc)
    assert text == "OperationalError: (1045, \"Access denied for user <redacted>@'172.17.0.1' (using password: YES)\")"
    assert "svc_ro" not in text


@pytest.mark.parametrize("shape", ["password=hunter2)", "password: hunter2\")", "pwd=hunter2'"])
def test_t2_a_password_value_is_still_cut_whole(shape: str) -> None:
    from universal_db_mcp.security.redact import redact_text

    out = redact_text(f"connect failed ({shape}")
    assert "hunter2" not in out and "<redacted>" in out


@pytest.mark.parametrize(
    "sql", ["SELECT 1 /* \udcff */", "SELECT '\ud800'", "\ud800", "SELECT 1 -- \udfff\n"]
)
def test_r2_a_lone_surrogate_never_breaks_the_fingerprint(sql: str) -> None:
    """sql_fingerprint encoded strictly: a lone surrogate in a comment raised
    in the audit path and the executed statement left no audit record."""
    from universal_db_mcp.security.redact import sql_fingerprint

    fp = sql_fingerprint(sql)
    assert fp.startswith("sha256:") and fp == sql_fingerprint(sql)


@pytest.mark.parametrize("user", ["svc_ro", "we ird", "a:b"])
def test_x8_clickhouse_auth_failure_hides_the_login_name(user: str) -> None:
    from universal_db_mcp.security.redact import redact_text

    text = (
        f"DatabaseError: Received ClickHouse exception, code: 516, server response: Code: 516. DB::Exception: "
        f"{user}: Authentication failed: password is incorrect, or there is no user with such name. "
        "(AUTHENTICATION_FAILED)"
    )
    out = redact_text(text)
    assert user not in out
    assert "DB::Exception: <redacted>: Authentication failed" in out and "code: 516" in out


# --------------------------------------------------------------------------
# T1: information_schema views that carry definitions and DEFAULT values
# --------------------------------------------------------------------------

_T1_DEFINITION_VIEWS = [
    ("mysql", "information_schema", "VIEWS"),
    ("mysql", "information_schema", "ROUTINES"),
    ("mysql", "INFORMATION_SCHEMA", "COLUMNS"),
    ("mysql", "information_schema", "TRIGGERS"),
    ("mysql", "information_schema", "EVENTS"),
    ("mysql", "information_schema", "CHECK_CONSTRAINTS"),
    ("mysql", "information_schema", "INNODB_COLUMNS"),
    ("postgres", "information_schema", "views"),
    ("postgres", "information_schema", "routines"),
    ("postgres", "information_schema", "columns"),
    ("postgres", "information_schema", "triggers"),
    ("postgres", "information_schema", "check_constraints"),
    ("postgres", "information_schema", "parameters"),
    ("postgres", "information_schema", "attributes"),
    ("postgres", "information_schema", "domains"),
    ("clickhouse", "INFORMATION_SCHEMA", "COLUMNS"),
    ("clickhouse", "information_schema", "views"),
    ("mssql", "INFORMATION_SCHEMA", "VIEWS"),
    ("mssql", "INFORMATION_SCHEMA", "ROUTINES"),
    ("mssql", "INFORMATION_SCHEMA", "COLUMNS"),
    ("mssql", "INFORMATION_SCHEMA", "CHECK_CONSTRAINTS"),
    ("mssql", "INFORMATION_SCHEMA", "DOMAINS"),
]


@pytest.mark.parametrize(("engine", "schema", "name"), _T1_DEFINITION_VIEWS)
def test_t1_definition_and_default_views_are_refused_and_unlisted(engine: str, schema: str, name: str) -> None:
    """Under the default allowed_system_schemas [information_schema], db_query
    read other schemas' VIEW_DEFINITION, ROUTINE_DEFINITION and a masked
    column's COLUMN_DEFAULT; main refused them (POLICY_VIOLATION)."""
    from universal_db_mcp.discovery.system_schemas import is_session_sql_view
    from universal_db_mcp.security.policy import check_not_session_sql

    assert is_session_sql_view(engine, schema, name)
    with pytest.raises(ToolFailure) as info:
        check_not_session_sql(engine, schema, name)
    assert info.value.category == ErrorCategory.POLICY and "definitions" in str(info.value)


@pytest.mark.parametrize(
    ("engine", "schema", "name"),
    [
        ("mysql", "information_schema", "TABLES"),
        ("mysql", "information_schema", "SCHEMATA"),
        ("mysql", "information_schema", "KEY_COLUMN_USAGE"),
        ("postgres", "information_schema", "tables"),
        ("postgres", "information_schema", "table_constraints"),
        ("clickhouse", "information_schema", "tables"),
        ("mssql", "INFORMATION_SCHEMA", "TABLES"),
        ("postgres", "app", "columns"),  # an application's own table of the name
        ("mysql", "shop", "views"),
    ],
)
def test_t1_names_only_catalog_views_stay_readable(engine: str, schema: str, name: str) -> None:
    from universal_db_mcp.discovery.system_schemas import is_session_sql_view

    assert not is_session_sql_view(engine, schema, name)


def test_t1_guard_refuses_view_definitions_under_the_default_config() -> None:
    """End to end through the guard with the default security config and
    information_schema in the listing (as list_tables returns it)."""
    from universal_db_mcp.security.sql_guard import SqlGuard, StaticResolver

    resolved = _resolved({"type": "mysql", "host": "h", "database": "shop"})
    policy = EffectivePolicy.build(SecurityConfig(), resolved)
    listed: set[tuple[str | None, str]] = {
        ("information_schema", "views"), ("information_schema", "tables"), ("information_schema", "columns")
    }
    guard = SqlGuard("mysql", policy, StaticResolver(listed))
    for sql in (
        "SELECT table_schema, view_definition FROM information_schema.views WHERE table_schema = 'hr'",
        "SELECT column_default FROM information_schema.columns WHERE table_name = 'salaries'",
    ):
        with pytest.raises(ToolFailure) as info:
            guard.validate_select(sql)
        assert info.value.category == ErrorCategory.POLICY, sql
    guard.validate_select("SELECT table_schema, table_name FROM information_schema.tables")


# --------------------------------------------------------------------------
# E7: more views of other sessions' statements
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("engine", "schema", "name"),
    [
        ("oracle", None, "V$DIAG_ALERT_EXT"),
        ("oracle", "SYS", "V_$DIAG_ALERT_EXT"),
        ("oracle", None, "GV$DIAG_ALERT_EXT"),
        ("oracle", None, "V$RESULT_CACHE_OBJECTS"),
        ("oracle", "SYS", "GV_$RESULT_CACHE_OBJECTS"),
        ("clickhouse", "system", "zookeeper"),
        ("clickhouse", "system", "zookeeper_log"),
        ("clickhouse", "system", "zookeeper_log_1"),
        ("postgres", "public", "pg_show_plans"),
        ("postgres", None, "pg_show_plans"),
        ("postgres", "ext", "pg_store_plans"),
    ],
)
def test_e7_statement_views_are_refused(engine: str, schema: str | None, name: str) -> None:
    from universal_db_mcp.discovery.system_schemas import is_session_sql_view

    assert is_session_sql_view(engine, schema, name)


# --------------------------------------------------------------------------
# E1: SQL Server's legacy table hints written without WITH
# --------------------------------------------------------------------------


def _mssql_guard() -> Any:
    from universal_db_mcp.security.sql_guard import SqlGuard, StaticResolver

    resolved = _resolved({"type": "mssql", "host": "h", "database": "d"})
    policy = EffectivePolicy.build(SecurityConfig(), resolved)
    return SqlGuard("mssql", policy, StaticResolver({("ocean", "buoys"), ("dbo", "t")}))


@pytest.mark.parametrize(
    "hints", ["TABLOCKX", "UPDLOCK", "XLOCK", "SERIALIZABLE", "PAGLOCK", "TABLOCK", "HOLDLOCK", "REPEATABLEREAD",
              "ROWLOCK", "NOLOCK, XLOCK", "tablockx"],
)
def test_e1_legacy_lock_hint_without_with_is_refused(hints: str) -> None:
    """`b (TABLOCKX)` is a table hint to SQL Server (sqlglot reads a column
    alias list): an exclusive table lock held until the rollback."""
    guard = _mssql_guard()
    for sql in (f"SELECT buoy_id FROM ocean.buoys b ({hints})", f"SELECT buoy_id FROM ocean.buoys AS b ({hints})"):
        with pytest.raises(ToolFailure) as info:
            guard.validate_select(sql)
        assert info.value.category == ErrorCategory.POLICY, sql


@pytest.mark.parametrize("hints", ["NOLOCK", "READUNCOMMITTED", "NOLOCK, READPAST"])
def test_e1_relaxing_legacy_hints_stay_accepted(hints: str) -> None:
    _mssql_guard().validate_select(f"SELECT buoy_id FROM ocean.buoys b ({hints})")


def test_e1_a_derived_tables_column_list_is_not_a_hint() -> None:
    _mssql_guard().validate_select("SELECT c1 FROM (SELECT buoy_id FROM ocean.buoys) AS d (c1)")


# --------------------------------------------------------------------------
# H1: optimizer hints are comments to the engine, not function calls
# --------------------------------------------------------------------------


def _guard(engine: str, objects: set[tuple[str | None, str]], database: str = "d") -> Any:
    from universal_db_mcp.security.sql_guard import SqlGuard, StaticResolver

    resolved = _resolved({"type": engine, "host": "h", "database": database})
    return SqlGuard(engine, EffectivePolicy.build(SecurityConfig(), resolved), StaticResolver(objects))


@pytest.mark.parametrize(
    ("engine", "sql"),
    [
        ("oracle", "SELECT /*+ INDEX(b bookings_ix) LEADING(b) FULL(b) USE_NL(b) */ b.id FROM travel.bookings b"),
        ("oracle", "SELECT /*+ PARALLEL(4) NO_MERGE */ id FROM travel.bookings"),
        ("mysql", "SELECT /*+ BKA(c) NO_RANGE_OPTIMIZATION(c PRIMARY) JOIN_ORDER(c) */ c.id FROM shop.cuppings c"),
    ],
)
def test_h1_optimizer_hints_are_accepted(engine: str, sql: str) -> None:
    guard = _guard(engine, {("travel", "bookings"), ("shop", "cuppings")})
    result = guard.validate_select(sql)
    assert [r.name.lower() for r in result.tables] in (["bookings"], ["cuppings"])


@pytest.mark.parametrize(
    "hint", ["MAX_EXECUTION_TIME(0)", "SET_VAR(max_execution_time = 0)", "RESOURCE_GROUP(rg)", "bka(c) set_var(x=1)"]
)
def test_h1_mysql_hints_that_change_the_session_stay_refused(hint: str) -> None:
    """Inert does not mean open: these lift the statement ceiling or move
    the statement to another resource group."""
    guard = _guard("mysql", {("shop", "cuppings")})
    with pytest.raises(ToolFailure) as info:
        guard.validate_select(f"SELECT /*+ {hint} */ c.id FROM shop.cuppings c")
    assert info.value.category == ErrorCategory.POLICY


def test_h1_a_hint_names_no_object_for_authorization() -> None:
    """Names inside a hint are not table references: they authorize nothing
    and are not looked up (an unlisted name there is no refusal either)."""
    guard = _guard("oracle", {("travel", "bookings")})
    result = guard.validate_select("SELECT /*+ INDEX(hr.salaries s_ix) */ id FROM travel.bookings")
    assert [(r.schema or "").lower() for r in result.tables] == ["travel"]


# --------------------------------------------------------------------------
# M4 (guard side): a FROM item binds to a CTE only as the engine folds names
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("engine", "sql"),
    [
        # Oracle upper-cases é to É: FROM é reads table É, not the CTE "é"
        ("oracle", 'WITH "é" AS (SELECT 1 AS x FROM DUAL) SELECT * FROM é'),
        ("oracle", 'WITH "e" AS (SELECT 1 AS x FROM DUAL) SELECT * FROM e'),
        ("oracle", 'WITH "зарплаты" AS (SELECT 1 AS x FROM DUAL) SELECT * FROM зарплаты'),
        # PostgreSQL folds ASCII only (UTF-8) or by the locale (single-byte encodings)
        ("postgres", 'WITH "ölstand" AS (SELECT 1 AS x) SELECT * FROM Ölstand'),
        ("postgres", 'WITH "Ölstand" AS (SELECT 1 AS x) SELECT * FROM Ölstand'),
        ("db2", 'WITH "é" AS (SELECT 1 AS x FROM SYSIBM.SYSDUMMY1) SELECT * FROM é'),
        # Oracle keeps ß (no expansion to SS): FROM ß is table ß
        ("oracle", 'WITH "SS" AS (SELECT 1 AS x FROM DUAL) SELECT * FROM ß'),
    ],
)
def test_m4_a_quoted_cte_does_not_cover_a_differently_folded_name(engine: str, sql: str) -> None:
    guard = _guard(engine, {("travel", "bookings")})
    with pytest.raises(ToolFailure) as info:
        guard.validate_select(sql)
    assert info.value.category == ErrorCategory.POLICY


@pytest.mark.parametrize(
    ("engine", "sql"),
    [
        ("oracle", "WITH e AS (SELECT 1 AS x FROM DUAL) SELECT * FROM E"),
        ("oracle", 'WITH "E" AS (SELECT 1 AS x FROM DUAL) SELECT * FROM e'),
        ("postgres", "WITH s AS (SELECT 1 AS x) SELECT * FROM S"),
        ("postgres", 'WITH "s" AS (SELECT 1 AS x) SELECT * FROM S'),
        ("mysql", "WITH s AS (SELECT 1 AS x) SELECT * FROM S"),
        ("mysql", 'WITH "É" AS (SELECT 1 AS x) SELECT * FROM É'),
    ],
)
def test_m4_a_cte_the_engine_binds_stays_a_cte(engine: str, sql: str) -> None:
    _guard(engine, {("travel", "bookings")}).validate_select(sql)


@pytest.mark.parametrize(
    ("engine", "sql"),
    [
        ("oracle", 'WITH "É" AS (SELECT 1 AS x FROM DUAL) SELECT * FROM é'),
        ("postgres", 'WITH "ölstand" AS (SELECT 1 AS x) SELECT * FROM "ölstand"'),
    ],
)
def test_m4_a_non_ascii_cte_is_refused_where_names_fold(engine: str, sql: str) -> None:
    """Owner decision 2026-10-03 (review cr3 VD-2): on Oracle, Db2 and
    PostgreSQL a CTE name outside ASCII is refused, even where the engine
    would bind it, rather than modelling each engine's Unicode folding."""
    with pytest.raises(ToolFailure) as info:
        _guard(engine, {("travel", "bookings")}).validate_select(sql)
    assert info.value.category == ErrorCategory.POLICY and "ASCII" in str(info.value)


# --------------------------------------------------------------------------
# S2 (guard side): an empty quoted qualifier is no qualifier
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("engine", "sql"),
    [
        ("oracle", 'SELECT * FROM "".ALL_USERS'),
        ("oracle", 'SELECT u.username FROM "".ALL_USERS u'),
        ("postgres", 'SELECT * FROM "".pg_roles'),
        ("mysql", "SELECT * FROM ``.user"),
        ("mssql", "SELECT * FROM [].syslogins"),
        ("mssql", 'SELECT * FROM "".sysusers'),
        ("postgres", 'SELECT "".t.a FROM public.t'),
    ],
)
def test_s2_an_empty_quoted_qualifier_is_refused(engine: str, sql: str) -> None:
    """An empty qualifier ("".ALL_USERS) passed as a bare name the bare-name
    dictionary rules did not see; engines refuse a zero-length delimited
    name, so the guard does too, whatever default_deny says."""
    from universal_db_mcp.security.sql_guard import SqlGuard, StaticResolver

    resolved = _resolved({"type": engine, "host": "h", "database": "d"})
    policy = EffectivePolicy.build(SecurityConfig(default_deny_objects=False), resolved)
    guard = SqlGuard(engine, policy, StaticResolver({("public", "t")}))
    with pytest.raises(ToolFailure) as info:
        guard.validate_select(sql)
    assert info.value.category in (ErrorCategory.POLICY, "AUTHORIZATION_DENIED"), str(info.value)


# --------------------------------------------------------------------------
# E4: star over a join with duplicate names on MySQL 5.7 / MariaDB
# E5: a describe the prepared-statement protocol cannot do
# --------------------------------------------------------------------------


class _MyError(Exception):
    """PyMySQL's error shape: (errno, message)."""


class _E4Cursor:
    def __init__(self, conn: _E4Conn) -> None:
        self._conn = conn
        self.description: list[tuple[Any, ...]] | None = None
        self._result: Any = None
        self._rows: list[tuple[Any, ...]] = []

    def execute(self, sql: str, args: Any = None) -> None:
        self._conn.sent.append(sql)
        if "udbmcp_q(" in sql and not self._conn.column_lists:
            raise _MyError(1064, "You have an error in your SQL syntax")
        if "FROM (\n" in sql and "udbmcp_q(" not in sql:
            raise _MyError(1060, "Duplicate column name 'id'")
        self.description = self._conn.desc
        self._result = types.SimpleNamespace(fields=[types.SimpleNamespace(table_name=t) for t in self._conn.tables])
        self._rows = [] if sql.endswith("LIMIT 0") else [(1, "n" * 50, 2, "acme")]

    def fetchmany(self, n: int) -> list[tuple[Any, ...]]:
        rows, self._rows = self._rows, []
        return rows

    def close(self) -> None:
        return None


class _E4Conn:
    def __init__(self, version: str, *, column_lists: bool) -> None:
        self.server_version = version
        self.column_lists = column_lists
        self.sent: list[str] = []
        self.desc = [("id", 3, None, 11), ("notes", 252, None, 262140), ("id", 3, None, 11), ("name", 253, None, 400)]
        self.tables = ["o", "o", "c", "c"]

    def thread_id(self) -> int:
        return 1

    def cursor(self) -> _E4Cursor:
        return _E4Cursor(self)

    def close(self) -> None:
        return None


@pytest.mark.parametrize("version", ["5.7.44-log", "10.11.6-MariaDB"])
def test_e4_star_over_a_join_with_duplicate_names_is_cut_in_place(version: str) -> None:
    """MySQL 5.7 and MariaDB take no derived column list (1064): the only
    rewrite for duplicate names was refused and the query failed; main
    returned the rows."""
    conn = _mysql()
    conn._module = types.SimpleNamespace(MySQLError=_MyError)
    fake = _E4Conn(version, column_lists=False)
    conn._connect = lambda: fake  # type: ignore[method-assign]
    sql = "SELECT * FROM orders o JOIN customers c ON o.customer_id = c.id"
    out = conn._execute(QuerySpec(sql=sql, max_cell_bytes=10))
    assert fake.sent[0] == sql + "\nLIMIT 0"
    assert fake.sent[1] == (
        "SELECT `o`.`id` AS `id`, LEFT(`o`.`notes`, 11) AS `notes`, `c`.`id` AS `id`, LEFT(`c`.`name`, 11) AS `name` "
        "FROM orders o JOIN customers c ON o.customer_id = c.id"
    )
    assert [c for c, _t in out.columns] == ["id", "notes", "id", "name"] and out.rows


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT * FROM orders o JOIN customers c USING (id)",
        "SELECT * FROM orders o NATURAL JOIN customers c",
        "SELECT * FROM orders o JOIN customers c ON o.customer_id = c.id ORDER BY notes",
    ],
)
def test_e4_star_is_not_spelled_out_where_it_would_change_the_result(sql: str) -> None:
    """USING and NATURAL joins merge their columns; an ORDER BY of a cut
    column would order by the cut value: no in-place rewrite, and the
    statement is refused as before rather than answered differently."""
    from universal_db_mcp.connectors.base import ConnectorError

    conn = _mysql()
    conn._module = types.SimpleNamespace(MySQLError=_MyError)
    fake = _E4Conn("5.7.44-log", column_lists=False)
    conn._connect = lambda: fake  # type: ignore[method-assign]
    with pytest.raises(ConnectorError, match="could not be cut"):
        conn._execute(QuerySpec(sql=sql, max_cell_bytes=10))
    assert not any("`o`.`notes`" in s for s in fake.sent)


def test_e5_a_prepare_the_server_cannot_hold_runs_the_statement_as_written() -> None:
    """max_prepared_stmt_count reached (1461): SELECT 1, COUNT(*), UNION and
    CTEs failed although nothing needed cutting; main ran them."""
    pymysql = pytest.importorskip("pymysql")
    conn = _mysql()
    conn._module = pymysql

    class _Real(pymysql.connections.Connection):  # type: ignore[misc, name-defined]
        def __init__(self) -> None:
            self.sent: list[str] = []

        def cursor(self) -> Any:
            return _MyCursor(self.sent, [("1", 8, None, 1)])

        def _execute_command(self, command: int, text: Any) -> None:
            return None

        def _read_packet(self, *a: Any) -> Any:  # the prepare's answer: an error packet
            raise pymysql.err.OperationalError(1461, "Can't create more than max_prepared_stmt_count statements")

        def thread_id(self) -> int:
            return 1

        def close(self) -> None:
            return None

    real = _Real()
    conn._connect = lambda: real  # type: ignore[method-assign]
    out = conn._execute(QuerySpec(sql="SELECT 1 UNION SELECT 2"))
    assert real.sent == ["SELECT 1 UNION SELECT 2"] and out.rows


def test_e5_the_statements_own_prepare_error_is_still_its_error() -> None:
    pymysql = pytest.importorskip("pymysql")
    conn = _mysql()
    conn._module = pymysql

    class _Real(pymysql.connections.Connection):  # type: ignore[misc, name-defined]
        def __init__(self) -> None:
            pass

        def cursor(self) -> Any:
            return _MyCursor([], [])

        def _execute_command(self, command: int, text: Any) -> None:
            return None

        def _read_packet(self, *a: Any) -> Any:
            raise pymysql.err.OperationalError(1317, "Query execution was interrupted")

        def thread_id(self) -> int:
            return 1

        def close(self) -> None:
            return None

    conn._connect = lambda: _Real()  # type: ignore[method-assign]
    from universal_db_mcp.connectors.base import ConnectorError

    with pytest.raises(ConnectorError, match="1317"):
        conn._execute(QuerySpec(sql="SELECT 1 UNION SELECT 2"))
