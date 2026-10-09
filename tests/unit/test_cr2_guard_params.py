"""Regression tests for the second /code-review max pass (review of 33a8477)
on the parameter binding, the guard, the redaction helpers, the system-schema
lists and the MySQL / PostgreSQL / ClickHouse connectors.

Ids are the review's (cr2 FINAL.json / VERDICTS.md): SW-1 ('%%'), V7-e/V7-h
(X8 ReDoS), V6-a (p03L-2 residual), V7-c/V7-i (_streamed regexes), V9-a/V7-g
(T1 residual), V10-c (MySQL positional GROUP BY), V10-a/V7-b (PostgreSQL
parameters), V1-e (SQLite ""), V7-a (MySQL hint bodies), V10-e/V10-d (E4, X1).
"""

from __future__ import annotations

import time
from typing import Any

import pytest
import test_cr_fix_guard_params as base

from universal_db_mcp.errors import ToolFailure
from universal_db_mcp.models.responses import ErrorCategory
from universal_db_mcp.security.sql_guard import bind_text, translate_paramstyle

# --------------------------------------------------------------------------
# SW-1: the DBAPI '%%' escape is one '%' again when values are bound
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("sql", "params", "sent"),
    [
        ("SELECT '50%%' = %s AS eq", ["50%"], "SELECT '50%' = '50%' AS eq"),
        (
            "SELECT DATE_FORMAT(d, '%%Y-%%m') = %s FROM t",
            ["2026-09"],
            "SELECT DATE_FORMAT(d, '%Y-%m') = '2026-09' FROM t",
        ),
        ("SELECT STR_TO_DATE(%s, '%%d/%%m/%%Y')", ["1/2/2026"], "SELECT STR_TO_DATE('1/2/2026', '%d/%m/%Y')"),
        ("SELECT \"50%%\" = %s", ["x"], "SELECT \"50%\" = 'x'"),  # "..." is a string on MySQL
        # a lone '%' still arrives as written, '%%%' is '%' then a lone '%'
        ("SELECT 1 FROM t WHERE s LIKE 'a%' AND u LIKE '%%%' AND v = %s", [1],
         "SELECT 1 FROM t WHERE s LIKE 'a%' AND u LIKE '%%' AND v = 1"),
        # a placeholder inside a literal stays text, escaped or not
        ("SELECT '%s', '%%s', %s", [1], "SELECT '%s', '%s', 1"),
        # quoted names and comments arrive byte for byte: the guard authorized that name
        ("SELECT `p%%q` /* 5%% */ , %s", [1], "SELECT `p%%q` /* 5%% */ , 1"),
    ],
)
def test_sw1_mysql_double_percent_in_a_literal_is_one_percent(sql: str, params: Any, sent: str) -> None:
    assert base._pymysql_sent(bind_text(sql, params, engine="mysql"), params) == sent


def test_sw1_postgres_double_percent_in_a_literal_is_one_percent() -> None:
    ((sent, _),) = base._pg_run("SELECT '50%%' = %s AS eq, format('%%s-%%s', 1, 2) AS f, 'a%' AS g", ["50%"])
    assert sent == "SELECT '50%' = $1 AS eq, format('%s-%s', 1, 2) AS f, 'a%' AS g"
    # a quoted name and a dollar quote: a $tag$ body is a string, a "..." a name
    ((sent, _),) = base._pg_run('SELECT $t$5%%$t$ AS "p%%", %s', [1])
    assert sent == 'SELECT $t$5%$t$ AS "p%%", $1'


def test_sw1_clickhouse_double_percent_in_a_literal_is_one_percent() -> None:
    sql = "SELECT '50%%' = %(v)s AS eq, `p%%`, \"q%%\", formatDateTime(now(), '%%Y') FROM t WHERE s LIKE 'a%'"
    sent = base._clickhouse_sent(bind_text(sql, {"v": "50%"}, engine="clickhouse"), {"v": "50%"})
    assert sent == "SELECT '50%' = '50%' AS eq, `p%%`, \"q%%\", formatDateTime(now(), '%Y') FROM t WHERE s LIKE 'a%'"


@pytest.mark.parametrize("engine", ["mysql", "postgres", "clickhouse"])
@pytest.mark.parametrize("sql", ["SELECT 7 %% 3, %s", "SELECT 7 %%s FROM t WHERE a = %s", "SELECT 7 %%(a)s, %s"])
def test_sw1_double_percent_in_code_is_refused(engine: str, sql: str) -> None:
    """In code the guard never read '%%' as modulo; where it parsed at all
    (PostgreSQL: 7 %%s is 7 % <placeholder>) the engine would get a column."""
    with pytest.raises(ToolFailure) as info:
        bind_text(sql, [1], engine=engine)
    assert info.value.category == ErrorCategory.VALIDATION and "'%%' outside a string literal" in str(info.value)


@pytest.mark.parametrize("engine", ["mysql", "postgres", "clickhouse"])
@pytest.mark.parametrize("sql", ["SELECT 1000000 %ssn, %s FROM t", "SELECT %s'x'", "SELECT %(a)sx FROM t"])
def test_sw1_a_placeholder_glued_to_a_name_is_refused(engine: str, sql: str) -> None:
    """PostgreSQL's parser reads '%ssn' as a placeholder aliased 'sn'; the
    engine would get modulo the column ssn, past the guard and masking."""
    params: Any = {"a": 1} if "%(a)s" in sql else [1]
    with pytest.raises(ToolFailure) as info:
        bind_text(sql, params, engine=engine)
    assert info.value.category == ErrorCategory.VALIDATION and "directly followed by" in str(info.value)


@pytest.mark.parametrize(
    ("sql", "params"),
    [
        # the previous review's injection repros still fail closed
        ("SELECT '%s' AS c", ["MARKER"]),
        ("SELECT a FROM d.t WHERE name = '%(x)s'", {"x": "' UNION ALL SELECT secret FROM d.denied --"}),
        ("SELECT a FROM d.t /* %(x)s */ WHERE 1", {"x": "*/ UNION ALL SELECT 1 /*"}),
        ("SELECT %(a)s", {"a": 1, "b": 2}),
        # '%%' does not turn a literal's placeholder back into a parameter
        ("SELECT '%%%s' AS c", ["x"]),
    ],
)
@pytest.mark.parametrize("engine", ["mysql", "postgres", "clickhouse"])
def test_sw1_injection_repros_still_fail_closed(engine: str, sql: str, params: Any) -> None:
    with pytest.raises(ToolFailure) as info:
        bind_text(sql, params, engine=engine)
    assert info.value.category == ErrorCategory.VALIDATION


def test_sw1_bind_text_is_linear() -> None:
    sql = "SELECT '" + "%%" * 30000 + "' = %s, `" + "%" * 2000 + "`"
    start = time.perf_counter()
    bind_text(sql, [1], engine="mysql")
    assert time.perf_counter() - start < 2.0


# --------------------------------------------------------------------------
# V10-a / V7-b: PostgreSQL arrays and slices next to parameters
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("sql", "params", "sent"),
    [
        ("SELECT ARRAY[%s]", [1], "SELECT ARRAY[$1]"),
        ("SELECT 1 WHERE 2 = ANY(ARRAY[%s, %s])", [1, 2], "SELECT 1 WHERE 2 = ANY(ARRAY[$1, $2])"),
        ("SELECT (ARRAY[1,2,3])[%s:%s]", [1, 2], "SELECT (ARRAY[1,2,3])[$1:$2]"),
        ("SELECT ARRAY[%s::int, %s]", [1, 2], "SELECT ARRAY[$1::int, $2]"),
        ("SELECT ARRAY[:a, :b]", {"a": 1, "b": 2}, "SELECT ARRAY[$1, $2]"),
        ("SELECT (ARRAY[10,20,30])[:i]", {"i": 2}, "SELECT (ARRAY[10,20,30])[$1]"),
        (
            "SELECT (ARRAY[10,20,30])[1:n] AS s FROM (VALUES (1),(2)) AS q(n) WHERE n = :lim",
            {"lim": 2},
            "SELECT (ARRAY[10,20,30])[1:n] AS s FROM (VALUES (1),(2)) AS q(n) WHERE n = $1",
        ),
        (
            "SELECT n, (ARRAY[10,20,30])[1:n] FROM (VALUES (1)) AS q(n) WHERE n <= :n",
            {"n": 3},
            "SELECT n, (ARRAY[10,20,30])[1:n] FROM (VALUES (1)) AS q(n) WHERE n <= $1",
        ),
        (
            "SELECT a[lo:hi], a[2:array_length(a,1)] FROM q WHERE lo >= :m",
            {"m": 1},
            "SELECT a[lo:hi], a[2:array_length(a,1)] FROM q WHERE lo >= $1",
        ),
        (
            "SELECT CAST(:k AS int)::text AS k, '{1}'::int[]",
            {"k": 5},
            "SELECT CAST($1 AS int)::text AS k, '{1}'::int[]",
        ),
    ],
)
def test_v10a_v7b_postgres_arrays_and_slices_bind(sql: str, params: Any, sent: str) -> None:
    ((text, _),) = base._pg_run(sql, params)
    assert text == sent


def test_v7b_a_slice_name_is_not_a_parameter_name() -> None:
    """[1:n] is a slice to the column n: supplying 'n' alone is refused as an
    unused name, never bound into the slice ('[1$1]')."""
    sql, params = translate_paramstyle("SELECT a[1:n] FROM q", {"n": 3}, engine="postgres")
    with pytest.raises(ToolFailure) as info:
        bind_text(sql, params, engine="postgres")
    assert "['n'] were supplied" in str(info.value)


# --------------------------------------------------------------------------
# V7-e / V7-h: X8's ClickHouse-login redaction was quadratic
# --------------------------------------------------------------------------


def test_v7e_clickhouse_login_scan_matches_the_regex_it_replaces() -> None:
    import random
    import re

    from universal_db_mcp.security.redact import _redact_clickhouse_login

    regex = re.compile(r"(DB::Exception: )[^\n]*?(?=: Authentication failed)")
    rng = random.Random(7)  # noqa: S311 - test data, not a secret
    tokens = ["DB::Exception: ", ": Authentication failed", "\n", "a", ": ", " "]
    for _ in range(20000):
        text = "".join(rng.choice(tokens) for _ in range(rng.randint(0, 10)))
        assert _redact_clickhouse_login(text) == regex.sub(r"\1<redacted>", text), text


@pytest.mark.parametrize("kib", [64, 128, 256])
def test_v7h_redaction_of_an_echoed_parameter_is_linear(kib: int) -> None:
    """The verdict's repro: PG echoes a 'DB::Exception: ' * N parameter in
    'invalid input syntax'; scrub_exception blocked the loop 0.95/3.8/14 s."""
    from universal_db_mcp.security.redact import redact_text, scrub_exception

    value = "DB::Exception: " * (kib * 1024 // 15)
    exc = ValueError(f'invalid input syntax for type integer: "{value}"')
    start = time.perf_counter()
    scrub_exception(exc)
    redact_text(value)
    redact_text(("password user for uid login DB::Exception: x" + " " * 40) * (kib * 1024 // 90))
    assert time.perf_counter() - start < 2.0


def test_x8_login_still_redacted_and_cut_text_shows_no_partial_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    from universal_db_mcp.security import redact

    login = "svc ro: x"
    exc = RuntimeError(f"HTTPDriver: Code: 516. DB::Exception: {login}: Authentication failed: password is incorrect")
    assert login not in redact.scrub_exception(exc) and "Authentication failed" in redact.scrub_exception(exc)
    secret = "S3cr3t-Value-0123456789"
    monkeypatch.setattr(redact, "_REGISTERED_SECRETS", [secret])
    # 'token=<long value>' shrinks to a few characters; the secret is cut in
    # two by the length cap: no part of it may be shown
    text = "token=" + "A" * (redact._SCRUB_MAX_CHARS - 40) + " " + secret
    assert len("RuntimeError: " + text) > redact._SCRUB_MAX_CHARS > len("RuntimeError: " + text) - len(secret)
    shown = redact.scrub_exception(RuntimeError(text))
    assert "S3cr" not in shown and shown.startswith("RuntimeError: ") and shown.endswith(" [...]")
    # a long error that stays long is shown as before: its first 500 characters
    long_text = "x " * redact._SCRUB_MAX_CHARS + secret
    assert redact.scrub_exception(RuntimeError(long_text)) == ("RuntimeError: " + long_text)[:500]
    # a short error is unchanged by the cap
    assert redact.scrub_exception(RuntimeError(f"bad {secret} here")) == "RuntimeError: bad <redacted> here"


# --------------------------------------------------------------------------
# V6-a: p03L-2 residual (a bound value ends the text in LIMIT 0 for the
# driver); V7-c / V7-i: _streamed's quadratic passes
# --------------------------------------------------------------------------


def _columns_only(final: str) -> bool:
    from clickhouse_connect.driver._backend.httpcommon import columns_only_re
    from clickhouse_connect.driver.query import remove_sql_comments

    return columns_only_re.search(remove_sql_comments(final)) is not None


@pytest.mark.parametrize(
    ("sql", "params"),
    [
        ("SELECT n, s FROM d.big WHERE 'k' != %(p0)s", {"p0": "x' LIMIT 0 --"}),
        ("SELECT n, s FROM d.big WHERE 'k' != %s", ["x' LIMIT 0 --"]),
        ("SELECT n, s FROM d.big WHERE 'k' != %(p0)s", {"p0": "x' LıMıT 0 --"}),  # dotless i folds onto I
        ("SELECT n, s FROM d.big WHERE s IN %(p0)s", {"p0": ["a", "x' LIMIT 0 --"]}),
        ("SELECT n, s FROM d.big WHERE 'k' != %(p0)s AND 1 = %(p1)s", {"p0": "x' /*", "p1": "*/ LIMIT 0 --"}),
    ],
)
def test_v6a_a_bound_value_never_makes_a_columns_only_request(
    monkeypatch: pytest.MonkeyPatch, sql: str, params: Any
) -> None:
    """The verdict's repro: the driver sent ... != 'x\\' LIMIT 0 --' + FORMAT
    JSON and read a 101 MiB body whole, past the budget, ceilings and KILL."""
    conn, sent = base._ch(monkeypatch)
    conn._execute(base.QuerySpec(sql=sql, parameters=params))
    (final,) = sent
    assert not _columns_only(final), final
    assert final.endswith("\n#!''")


def test_v6a_the_repro_reaches_the_columns_only_branch_without_the_probe() -> None:
    """The premise: without the probe the driver's own reading of the bound
    text ends in LIMIT 0 (its comment regex ignores the escaped quote)."""
    from clickhouse_connect.driver.binding import bind_query

    final, _ = bind_query("SELECT n FROM d.big WHERE 'k' != %(p0)s", {"p0": "x' LIMIT 0 --"})
    assert _columns_only(str(final))


def test_v6a_text_without_limit_is_sent_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    conn, sent = base._ch(monkeypatch)
    conn._execute(base.QuerySpec(sql="SELECT a FROM d.t WHERE b = %(p0)s  ", parameters={"p0": "v"}))
    assert sent == ["SELECT a FROM d.t WHERE b = 'v'  "]


@pytest.mark.parametrize(
    ("sql", "params"),
    [
        ("SELECT 1" + " " * 60000 + "AS a LIMIT %(n)s", {"n": 5}),
        ("SELECT 1" + " ;" * 30000 + " LIMIT 0", None),
        ("SELECT 1 AS `" + "/* " * 21000 + "` LIMIT 5", None),
        ("SELECT 1 AS `" + "/* " * 21000 + "`", {"x": "LIMIT"}),
    ],
)
def test_v7c_v7i_streamed_is_linear(sql: str, params: Any) -> None:
    """60 KiB of whitespace before LIMIT %(n)s stalled the loop 6-7 s in
    re.sub(r'[\\s;]*\\Z'); 21,000 '/* ' cost a second driver comment pass."""
    from universal_db_mcp.connectors.clickhouse import _streamed

    start = time.perf_counter()
    text = _streamed(sql, probe_ok=True, params=params)
    assert time.perf_counter() - start < 1.2
    assert not _columns_only(text) or sql.endswith("LIMIT 0")


# --------------------------------------------------------------------------
# V10-c: MySQL reads (2), ((2)), 2 COLLATE x and +2 as positions
# --------------------------------------------------------------------------


@pytest.mark.parametrize("term", ["(2)", "((2))", "+2", "2 COLLATE utf8mb4_bin", "2"])
def test_v10c_mysql_parenthesized_positions_are_compared(term: str) -> None:
    import sqlglot

    from universal_db_mcp.connectors.mysql import _mysql_compared_outputs

    for clause in ("GROUP BY", "ORDER BY"):
        tree = sqlglot.parse_one(f"SELECT count(*) AS n, body, id FROM docs {clause} {term}", read="mysql")
        assert _mysql_compared_outputs(tree, ["n", "body", "id"]) == {1}, clause  # type: ignore[arg-type]


@pytest.mark.parametrize("term", ["?", "(?)", "? COLLATE utf8mb4_bin"])
def test_v10c_mysql_a_bound_term_compares_every_output(term: str) -> None:
    """PyMySQL writes an int (or bool, or integral Decimal) into the text as
    an integer literal, which MySQL reads as a position."""
    import sqlglot

    from universal_db_mcp.connectors.mysql import _mysql_compared_outputs

    tree = sqlglot.parse_one(f"SELECT id, body FROM docs ORDER BY {term}", read="mysql")
    assert _mysql_compared_outputs(tree, ["id", "body"]) == {0, 1}  # type: ignore[arg-type]


@pytest.mark.parametrize("term", ["NULL", "'2'", "2.0", "-(-2)", "(SELECT 2)", "0x2", "RAND()", "COUNT(*)"])
def test_v10c_mysql_a_constant_term_compares_no_output(term: str) -> None:
    """Review round 3 (#11): MySQL 9.7 sorts and groups by these terms'
    values (live), so they compare no output and the in-place cut stays."""
    import sqlglot

    from universal_db_mcp.connectors.mysql import _mysql_compared_outputs

    tree = sqlglot.parse_one(f"SELECT id, body FROM docs ORDER BY {term}", read="mysql")
    assert _mysql_compared_outputs(tree, ["id", "body"]) == set()  # type: ignore[arg-type]


def test_v10c_mysql_column_terms_still_let_other_outputs_be_cut() -> None:
    import sqlglot

    from universal_db_mcp.connectors.mysql import _mysql_compared_outputs

    tree = sqlglot.parse_one("SELECT id, body FROM docs ORDER BY id, LEFT(body, 2) DESC, (1)", read="mysql")
    assert _mysql_compared_outputs(tree, ["id", "body", "x"]) == {0, 1}  # type: ignore[arg-type]


def test_v10c_mysql_group_by_a_parenthesized_position_is_not_cut_in_place() -> None:
    """The verdict's repro: GROUP BY (2) over a cut TEXT column merged
    'A'*200+'z' and 'A'*200+'a' into one group."""
    from universal_db_mcp.connectors.mysql import _mysql_capped_select, _mysql_select

    description = [("n", 8, None, 21), ("body", 252, None, 65535)]
    for sql in (
        "SELECT count(*) AS n, body FROM docs GROUP BY (2)",
        "SELECT id AS n, body FROM docs ORDER BY (2) DESC, 1",
    ):
        select = _mysql_select(sql)
        assert select is not None
        assert _mysql_capped_select(select, description, {1}, 100) is None, sql
    select = _mysql_select("SELECT id AS n, body FROM docs ORDER BY (1)")
    assert select is not None and _mysql_capped_select(select, description, {1}, 100) is not None


# --------------------------------------------------------------------------
# V9-a / V7-g: T1 residual - more information_schema views with definitions
# --------------------------------------------------------------------------


def _guard(engine: str, listed: set[tuple[str | None, str]], database: str = "shop") -> Any:
    from universal_db_mcp.config import SecurityConfig
    from universal_db_mcp.security.policy import EffectivePolicy
    from universal_db_mcp.security.sql_guard import SqlGuard, StaticResolver

    body = {"type": engine, "host": "h", "database": database}
    resolved = base._resolved(body)
    return SqlGuard(engine, EffectivePolicy.build(SecurityConfig(), resolved), StaticResolver(listed))


@pytest.mark.parametrize(
    ("engine", "schema", "name"),
    [
        ("mysql", "information_schema", "LIBRARIES"),  # LIBRARY_DEFINITION (MySQL 9)
        ("mysql", "information_schema", "JSON_DUALITY_VIEW_TABLES"),  # WHERE_CLAUSE (MySQL 9)
        ("mssql", "INFORMATION_SCHEMA", "ROUTINE_COLUMNS"),  # a table-valued function's COLUMN_DEFAULT
    ],
)
def test_t1r_more_definition_views_are_refused_and_unlisted(engine: str, schema: str, name: str) -> None:
    from universal_db_mcp.discovery.system_schemas import is_session_sql_view
    from universal_db_mcp.security.policy import check_not_session_sql

    assert is_session_sql_view(engine, schema, name)
    with pytest.raises(ToolFailure) as info:
        check_not_session_sql(engine, schema, name)
    assert info.value.category == ErrorCategory.POLICY


@pytest.mark.parametrize("engine", ["mysql", "clickhouse"])
def test_t1r_statistics_expression_is_refused_index_names_stay_readable(engine: str) -> None:
    """The verdict's repro (live MySQL 9.7): a functional key part's
    EXPRESSION, (`password` = _utf8mb4'hunter2'), of a schema outside
    allowed_schemas came back through information_schema.statistics."""
    guard = _guard(engine, {("information_schema", "statistics"), ("information_schema", "tables")})
    for sql in (
        "SELECT table_schema, index_name, expression FROM information_schema.statistics WHERE expression IS NOT NULL",
        "SELECT * FROM information_schema.statistics",
        "SELECT s.* FROM information_schema.statistics AS s",
        "SELECT index_name FROM information_schema.statistics WHERE EXPRESSION LIKE '%hunter%'",
    ):
        with pytest.raises(ToolFailure) as info:
            guard.validate_select(sql)
        assert info.value.category in (ErrorCategory.POLICY, ErrorCategory.VALIDATION), sql
        assert "EXPRESSION" in str(info.value), sql
    guard.validate_select(
        "SELECT index_name, column_name, seq_in_index, non_unique FROM information_schema.statistics "
        "WHERE table_schema = 'shop' AND table_name = 'orders'"
    )
    guard.validate_select("SELECT COUNT(*) FROM information_schema.statistics")


def test_t1r_tools_reading_every_column_of_statistics_are_refused() -> None:
    from universal_db_mcp.security.policy import check_not_session_sql

    with pytest.raises(ToolFailure) as info:
        check_not_session_sql("mysql", "information_schema", "STATISTICS")
    assert info.value.category == ErrorCategory.POLICY and "EXPRESSION" in str(info.value)
    check_not_session_sql("mysql", "information_schema", "STATISTICS", columns_checked=True)


# --------------------------------------------------------------------------
# V1-e: SQLite reads "" as an empty string (or a column named ""), not a
# qualifier; the S2 refusal of empty quoted qualifiers stays elsewhere
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "sql",
    [
        'SELECT a FROM t WHERE b = ""',
        'SELECT coalesce(b, "") AS c FROM t',
        'SELECT "" AS x',
        "SELECT a FROM t WHERE b <> \"\" AND b IS NOT NULL",
    ],
)
def test_v1e_sqlite_empty_double_quotes_are_a_string(sql: str) -> None:
    guard = _guard("sqlite", {("main", "t")}, database="x.db")
    guard.validate_select(sql)


@pytest.mark.parametrize(
    ("engine", "sql"),
    [
        ("sqlite", 'SELECT * FROM "".t'),
        ("sqlite", 'SELECT "".a FROM t'),
        ("sqlite", 'SELECT t."" FROM t'),
        ("postgres", 'SELECT a FROM public.t WHERE b = ""'),
        ("oracle", 'SELECT * FROM "".ALL_USERS'),
    ],
)
def test_v1e_empty_quoted_names_elsewhere_stay_refused(engine: str, sql: str) -> None:
    guard = _guard(engine, {("main", "t"), ("public", "t")}, database="x.db" if engine == "sqlite" else "d")
    with pytest.raises(ToolFailure):
        guard.validate_select(sql)


# --------------------------------------------------------------------------
# V7-a: MySQL session hints behind a hint body sqlglot keeps as raw text
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "hint",
    [
        "INDEX(t PRIMARY, idx2) MAX_EXECUTION_TIME(0)",
        "BNL(@qb1 t) SET_VAR(sort_buffer_size=4294967295)",
        "JOIN_PREFIX(t@qb1) RESOURCE_GROUP(rg)",
        "NO_RANGE_OPTIMIZATION(t PRIMARY) MAX_EXECUTION_TIME(0)",
        "MAX_EXECUTION_TIME(0) INDEX(t PRIMARY, idx2)",
        "QB_NAME(qb1) max_execution_time (0)",
        "NO_ICP(t) ſet_var(max_execution_time=1)",  # long s: Python and MySQL read it as s
        "INDEX(t idx2) /* c */ Max_Execution_Time(0)",
    ],
)
def test_v7a_mysql_session_hints_are_refused_however_the_body_parses(hint: str) -> None:
    """The verdict: with an unparsed hint body (a raw string to sqlglot),
    sort_buffer_size was raised and the max_execution_time ceiling lifted
    (live); H1 claimed these stay refused."""
    guard = _guard("mysql", {("d", "t")}, database="d")
    with pytest.raises(ToolFailure) as info:
        guard.validate_select(f"SELECT /*+ {hint} */ a FROM d.t")
    assert info.value.category == ErrorCategory.POLICY


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT /*+ INDEX(t PRIMARY, idx2) BKA(t) */ a FROM d.t",
        "SELECT /* max_execution_time(0) is a plain comment here */ a FROM d.t",
        "SELECT 'MAX_EXECUTION_TIME(0)' AS a FROM d.t",
        "SELECT a AS set_var FROM d.t",
    ],
)
def test_v7a_other_hints_and_mentions_stay_accepted(sql: str) -> None:
    guard = _guard("mysql", {("d", "t")}, database="d")
    guard.validate_select(sql)


# --------------------------------------------------------------------------
# V10-d (X1 residual): a cancel that finds the session idle
# --------------------------------------------------------------------------


def test_x1_mysql_cancel_ends_the_session_not_only_the_running_statement(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """KILL QUERY on a session between two statements (the describe probe
    and the statement) ended nothing, and the statement then ran to its end.
    KILL CONNECTION ends the session whatever it is doing."""
    import threading

    import test_hardening_2026_09_27_connectors_sql as hc

    state = hc._Rows(hc._TEN, [hc._Col("n", 3, 11)])
    state.blocked = threading.Event()
    conn, _fake = hc._my_module(tmp_path, monkeypatch, state)
    worker = threading.Thread(target=lambda: _swallow(conn.execute_query, hc.QuerySpec(sql="SELECT n FROM t")))
    worker.start()
    try:
        assert state.fetching.wait(5)
        assert conn.cancel_current() is True
    finally:
        state.blocked.set()
        worker.join(5)
    assert [s for s, _ in state.statements if s.startswith("KILL")] == ["KILL CONNECTION 4242"]


def _swallow(fn: Any, *args: Any) -> Any:
    try:
        return fn(*args)
    except Exception as exc:  # noqa: BLE001 - the caller inspects the result
        return exc


def test_x1_mysql_a_cancel_before_the_session_is_known_stops_the_run(monkeypatch: pytest.MonkeyPatch) -> None:
    """The deadline fires after the connect, before the connector knows the
    session's id: nothing to KILL, so the run must not start the statement."""
    import threading

    import test_hardening_2026_09_27_connectors_sql as hc

    state = hc._Rows(hc._TEN, [hc._Col("n", 3, 11)])
    conn = hc._my(monkeypatch, state)
    asked, release = threading.Event(), threading.Event()

    class _SlowId(hc._RowConn):
        def thread_id(self) -> int:
            asked.set()
            release.wait(5)
            return 4242

    monkeypatch.setattr(conn, "_connect", lambda: _SlowId(state))
    results: list[Any] = []
    spec = hc.QuerySpec(sql="SELECT n FROM t")
    worker = threading.Thread(target=lambda: results.append(_swallow(conn.execute_query, spec)))
    worker.start()
    try:
        assert asked.wait(5)
        assert conn.cancel_current() is True
    finally:
        release.set()
        worker.join(5)
    assert isinstance(results[0], Exception), results
    assert not [s for s, _ in state.statements if "SELECT n" in s], state.statements
    assert conn.cancel_current() is False, "nothing runs any more"


def test_x1_postgres_a_cancel_after_declare_stops_before_the_first_fetch(monkeypatch: pytest.MonkeyPatch) -> None:
    """DECLARE plans the statement and runs nothing; a cancel request that
    reaches the idle session then is lost, and the FETCH ran the statement."""
    import test_hardening_2026_09_27_connectors_sql as hc

    state = hc._Rows(hc._TEN, [hc._Col("n", 23)])

    class _Recording(hc._RowConn):
        def cancel_safe(self, *, timeout: float = 30.0) -> None:
            self._s.log.append("cancel_safe")

    conn = hc._pg(monkeypatch, state)
    monkeypatch.setattr(conn, "_connect", lambda: _Recording(state))
    state.fail = lambda sql: None if conn.cancel_current() else None  # the deadline fires at DECLARE
    with pytest.raises(Exception, match="cancel"):
        conn.execute_query(hc.QuerySpec(sql="SELECT n FROM t"))
    assert state.fetch_sizes == [] and "cancel_safe" in state.log and "rollback" in state.log


def test_x1_postgres_a_cancel_between_fetches_stops_the_next_one(monkeypatch: pytest.MonkeyPatch) -> None:
    import types as _types

    import test_hardening_2026_09_27_connectors_sql as hc

    state = hc._Rows(hc._TEN * 300, [hc._Col("n", 23)])

    class _Recording(hc._RowConn):
        def cancel_safe(self, *, timeout: float = 30.0) -> None:
            self._s.log.append("cancel_safe")

    conn = hc._pg(monkeypatch, state)
    monkeypatch.setattr(conn, "_connect", lambda: _Recording(state))
    state.fetching = _types.SimpleNamespace(set=lambda: conn.cancel_current())  # type: ignore[assignment]
    with pytest.raises(Exception, match="cancel"):
        conn.execute_query(hc.QuerySpec(sql="SELECT n FROM t", max_rows=3000))
    assert len(state.fetch_sizes) == 1
    # the next run on a fresh request is not cancelled by the old flag
    state.fetching = _types.SimpleNamespace(set=lambda: None)  # type: ignore[assignment]
    assert conn.execute_query(hc.QuerySpec(sql="SELECT n FROM t", max_rows=5)).rows


# --------------------------------------------------------------------------
# V10-e (E4 residual): o.*, c.* over a join on MySQL 5.7 / MariaDB
# --------------------------------------------------------------------------


@pytest.mark.parametrize("version", ["5.7.44-log", "10.11.6-MariaDB"])
@pytest.mark.parametrize("stars", ["o.*, c.*", "o.* , /* both */ c.*", "*"])
def test_v10e_qualified_stars_over_a_join_are_cut_in_place(version: str, stars: str) -> None:
    import types as _types

    conn = base._mysql()
    conn._module = _types.SimpleNamespace(MySQLError=base._MyError)
    fake = base._E4Conn(version, column_lists=False)
    conn._connect = lambda: fake
    sql = f"SELECT {stars} FROM orders o JOIN customers c ON o.customer_id = c.id"
    out = conn._execute(base.QuerySpec(sql=sql, max_cell_bytes=10))
    assert fake.sent[1] == (
        "SELECT `o`.`id` AS `id`, LEFT(`o`.`notes`, 11) AS `notes`, `c`.`id` AS `id`, LEFT(`c`.`name`, 11) AS `name` "
        "FROM orders o JOIN customers c ON o.customer_id = c.id"
    )
    assert [c for c, _t in out.columns] == ["id", "notes", "id", "name"] and out.rows


def test_v10e_a_star_beside_another_entry_is_still_refused_on_57() -> None:
    """Documented residual: a bare '*' beside another entry over a join with
    duplicate names has no exact in-place spelling here ('o.*, c.name' has:
    the select-list rewrite spells the one qualified star); MySQL 5.7 /
    MariaDB refuse it as before rather than answer differently."""
    import types as _types

    from universal_db_mcp.connectors.base import ConnectorError

    conn = base._mysql()
    conn._module = _types.SimpleNamespace(MySQLError=base._MyError)
    fake = base._E4Conn("5.7.44-log", column_lists=False)
    conn._connect = lambda: fake
    with pytest.raises(ConnectorError, match="could not be cut"):
        conn._execute(base.QuerySpec(sql="SELECT *, c.name FROM orders o JOIN customers c ON 1", max_cell_bytes=10))


# --------------------------------------------------------------------------
# Cross-owner: public cte_key / named_placeholders; bounded catalog caches
# --------------------------------------------------------------------------


def test_public_cte_key_is_the_guards() -> None:
    from universal_db_mcp.security.sql_guard import cte_key

    # ASCII-exact since review cr3 VD-2 (non-ASCII CTE names are refused on Oracle, Db2, PostgreSQL)
    assert cte_key("oracle", "ς") != cte_key("oracle", "σ") and cte_key("oracle", "ab") == "AB"
    assert cte_key("postgres", "Ab") == "ab" and cte_key("mysql", "Ab") == "ab"
    guard = _guard("oracle", set(), database="d")
    assert guard._cte_key("ς") == cte_key("oracle", "ς")


def test_public_named_placeholders_read_a_code_view() -> None:
    from universal_db_mcp.security.sql_guard import code_view, named_placeholders

    view = code_view("SELECT a[1:n], ':x', \"y:z\", :y, x::int /* :c */ FROM t WHERE b = :b", "postgres")
    assert named_placeholders(view) == {"y", "b"}


def test_catalog_checks_are_cached_and_bounded() -> None:
    from universal_db_mcp.discovery import system_schemas as ss

    names = [("APP", f"T_{i}") for i in range(10000)]
    for schema, name in names:
        ss.is_session_sql_view("oracle", schema, name)
    start = time.perf_counter()
    for schema, name in names:
        ss.is_session_sql_view("oracle", schema, name)
        ss.loose_name(name)
    assert time.perf_counter() - start < 0.4
    assert ss.is_session_sql_view("mysql", "information_schema", "PROCESSLıST")
    assert ss._LOOSE_CACHE.max_entries == ss._SESSION_SQL_CACHE.max_entries == 32768
    long_name = "x" * 70000
    before = len(ss._LOOSE_CACHE)
    ss.loose_name(long_name)
    assert len(ss._LOOSE_CACHE) == before, "a long name is computed, not kept"
