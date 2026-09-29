"""Converging round, 2026-09-28: the guard closes classes, not repros.

1. ClickHouse reads a table wherever a name may stand for one: in the
   functional in(v, db.t), which sqlglot misparses after IN (`x IN in(v,
   db.t)` is In(this=In(x), expressions=[v, db.t])), in the other
   IN-family functions (notIn, globalIn, nullIn, ...) and in the functions
   that name a table or dictionary (joinGet, dictGet*, hasColumnInTable).
   A misparsed IN (one with nothing after it, or IN straight after IN) and
   those functions are refused, and every column-shaped a.b whose qualifier
   is no FROM item in reach (live, 26.3: a select alias, a WITH value, an
   ARRAY JOIN alias or a CTE outside the FROM do not stop ClickHouse reading
   the table a.b there; a FROM item of that name does) is authorized as the
   table a.b.
2. PostgreSQL decodes a Unicode-escape identifier U&"..." that sqlglot
   reads as `U & "..."`: U&"sea_temp_\\0063" returned a masked column in
   clear. Such an identifier is refused on PostgreSQL and on Db2 (parsed as
   PostgreSQL); strings keep U&'...'.
3. Oracle reads t@link, "T"@link, t @link and t/**/@link as a database
   link, which sqlglot parses as a table alias: a remote read past every
   allowlist, and a remote DUAL admitted as the local one. On Oracle any '@'
   outside a literal, a quoted identifier or a comment is refused.
4. Column statistics hold a column's values (histogram buckets, most common
   values, low and high keys): they are refused whatever
   allowed_system_schemas opens, like the views of other sessions' SQL, and
   the catalog views that carry low and high values beside every column's
   description (Oracle's *_TAB_COLUMNS, Db2's SYSCAT.COLUMNS) are readable
   through a query only without those columns, without * and without a
   column list after the alias, also where the name is a CTE's elsewhere
   in the statement (6, review round 2).
5. Server and session variables (@@datadir, @@VERSION) are refused, and
   MySQL's user variables, which carry a value from one statement to the
   next on the pooled session past the masking of the first.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
from test_hardening_2026_09_27_qualified_names import (
    OCEAN,
    REMOTE,
    _call,
    _call_error,
    _entries,
    _guard,
    _policy,
    _refused,
    _server,
)
from test_hardening_2026_09_27_server import SECRETS, _AnswerFake, _fake_app_server
from test_hardening_2026_09_28_final_guard_server import _app_server

from universal_db_mcp.connectors.base import TableSummary
from universal_db_mcp.discovery.system_schemas import is_column_statistics_view, is_session_sql_view, value_columns
from universal_db_mcp.errors import ToolFailure
from universal_db_mcp.models.responses import ErrorCategory
from universal_db_mcp.security.sql_guard import SqlGuard, StaticResolver

_POLICIES = [
    pytest.param(["ocean"], True, id="allowlist-default-deny"),
    pytest.param(["ocean"], False, id="allowlist"),
    pytest.param([], True, id="default-deny"),
    pytest.param([], False, id="neither"),
]


def _ch(allowed: list[str], deny: bool) -> SqlGuard:
    return _guard("clickhouse", allowed, OCEAN if deny else None, deny=deny)


# ---- 1. ClickHouse reads a table wherever a name may stand for one --------------------

_FUNCTIONAL_IN = [
    "SELECT 1 IN in(0, system.one) AS hit",
    "SELECT 1 NOT IN in(0, system.one) AS hit",
    "SELECT 1 GLOBAL IN in(0, system.one) AS hit",
    "SELECT 1 GLOBAL NOT IN in(0, system.one) AS hit",
    "SELECT 1 IN IN (0, system.one) AS hit",
    "SELECT CASE WHEN 1 IN in(0, system.one) THEN 1 END AS hit",
    "SELECT 0 IN in(0, system.one) = 1 AS hit",
    "SELECT count() AS n FROM ocean.buoys WHERE 1 IN in(0, system.one)",
    "SELECT count() AS n FROM ocean.buoys WHERE 1 IN in(0, hr.salaries)",
    "SELECT 1 IN in(0, salaries) AS hit",  # a bare name reads the current database's table
    "SELECT 1 IN in(0, buoys) AS hit",
    "SELECT buoy_id IN in FROM ocean.buoys",
    "SELECT 1 IN in AS hit",
    "SELECT 1 IN in() AS hit",
]


@pytest.mark.parametrize(("allowed", "deny"), _POLICIES)
@pytest.mark.parametrize("sql", _FUNCTIONAL_IN)
def test_clickhouse_a_misparsed_in_is_refused(sql: str, allowed: list[str], deny: bool) -> None:
    # live (26.3): SELECT 1 IN in(0, system.one) is [(1,)], with 5 it is [(0,)], past a closed system
    guard = _ch(allowed, deny)
    for label, validate, prefix in _entries(guard):
        exc = _refused(validate, prefix + sql)
        assert exc.category == ErrorCategory.POLICY, (label, str(exc))
        assert "in(" in str(exc) and "reads the table" in str(exc), (label, str(exc))


@pytest.mark.parametrize("engine", [*REMOTE, "sqlite"])
def test_an_in_with_nothing_after_it_is_refused_on_every_engine(engine: str) -> None:
    # no engine reads it as sqlglot does; ClickHouse reads in(v, t) as v IN t
    guard = _guard(engine, [], None, deny=False)
    for sql in ("SELECT 1 IN in(0, 1) AS hit", "SELECT 1 IN IN (0, 1) AS hit"):
        exc = _refused(guard.validate_select, sql)
        assert "in(" in str(exc) or "could not be parsed" in str(exc), (engine, sql, str(exc))


_TABLE_ARGUMENT_FUNCTIONS = [
    "notIn(0, system.one)",
    "globalIn(0, system.one)",
    "globalNotIn(0, system.one)",
    "nullIn(0, system.one)",
    "notNullIn(0, system.one)",
    "globalNullIn(0, system.one)",
    "globalNotNullIn(0, system.one)",
    "inIgnoreSet(0, system.one)",
    "notInIgnoreSet(0, system.one)",
    "joinGet(hr.salaries_join, 'salary', 1)",
    "joinGet('hr.salaries_join', 'salary', 1)",
    "joinGetOrNull(hr.salaries_join, 'salary', 1)",
    "dictGet(hr.salaries_dict, 'salary', toUInt64(1))",
    "dictGet('hr.salaries_dict', 'salary', toUInt64(1))",
    "dictGetString('hr.salaries_dict', 'name', toUInt64(1))",
    "dictGetOrDefault('hr.d', 'salary', toUInt64(1), 0)",
    "dictGetOrNull('hr.d', 'salary', toUInt64(1))",
    "dictHas('hr.d', toUInt64(1))",
    "dictGetHierarchy('hr.d', toUInt64(1))",
    "dictIsIn('hr.d', toUInt64(1), toUInt64(2))",
    "dictGetChildren('hr.d', toUInt64(1))",
    "dictGetDescendants('hr.d', toUInt64(1))",
    "dictGetAll('hr.d', 'salary', toUInt64(1))",
    "hasColumnInTable('hr', 'salaries', 'salary')",
]


@pytest.mark.parametrize(("allowed", "deny"), _POLICIES)
@pytest.mark.parametrize("call", _TABLE_ARGUMENT_FUNCTIONS)
def test_clickhouse_functions_that_name_a_table_or_dictionary_are_refused(
    call: str, allowed: list[str], deny: bool
) -> None:
    # live (26.3): nullIn(0, system.one), globalIn(..), notNullIn(..), inIgnoreSet(..) read system.one
    guard = _ch(allowed, deny)
    for label, validate, prefix in _entries(guard):
        exc = _refused(validate, prefix + f"SELECT {call} AS x")
        assert exc.category == ErrorCategory.POLICY, (label, str(exc))
        assert "names a table or dictionary" in str(exc), (label, str(exc))


@pytest.mark.parametrize(
    "name",
    ["join_get", "JOIN_GET_OR_NULL", "not_in", "global_in", "global_not_null_in", "null_in", "in_ignore_set",
     "not_in_ignore_set", "has_column_in_table", "dict_get", "dict_get_or_default", "dict_has", "in"],
)
def test_clickhouse_table_argument_functions_match_as_sqlglot_would_name_them(name: str) -> None:
    # review, 2026-09-28: a Func class sqlglot learns is named by sql_name(), in snake case
    from sqlglot import exp

    from universal_db_mcp.security import sql_guard

    assert sql_guard._names_a_table_argument(name), name
    learned = type("".join(p.title() for p in name.split("_")), (exp.Func,), {"arg_types": {"expressions": False}})
    assert sql_guard._names_a_table_argument(sql_guard._func_name(learned()) or ""), learned.__name__


@pytest.mark.parametrize("name", ["index", "intDiv", "if", "ifNull", "indexOf", "inline", "ARRAY_CONTAINS", "tuple"])
def test_other_function_names_are_not_table_argument_functions(name: str) -> None:
    from universal_db_mcp.security import sql_guard

    assert not sql_guard._names_a_table_argument(name), name


# ClickHouse drops parentheses, an alias and a unary plus around the one item
# after IN and reads a lone name there as a table (live, 26.3, database
# system: 0 IN ((one AS z)) is 1, with 5 it is 0, past an allowlist and
# default-deny); sqlglot keeps the alias, and cannot parse IN (one AS z)
_ALIASED_SINGLE_NAMES = [
    "SELECT 0 IN ((one AS z)) AS hit",
    "SELECT 0 IN (((one AS z))) AS hit",
    "SELECT 0 IN (((one AS y) AS z)) AS hit",
    "SELECT 0 IN (+(one AS z)) AS hit",
    "SELECT 0 IN ((+one AS z)) AS hit",
    "SELECT 0 IN (((one) AS z)) AS hit",
    "SELECT 0 NOT IN ((one AS z)) AS hit",
    "SELECT 0 GLOBAL IN ((one AS z)) AS hit",
    "SELECT 0 GLOBAL NOT IN ((one AS z)) AS hit",
    "SELECT 0 IN ((system.one AS z)) AS hit",
    "SELECT count() AS n FROM ocean.buoys WHERE 0 IN ((one AS z))",
    "SELECT count() AS n FROM ocean.buoys AS b WHERE b.buoy_id IN ((hr.salaries AS z))",
]


@pytest.mark.parametrize(("allowed", "deny"), _POLICIES)
@pytest.mark.parametrize("sql", _ALIASED_SINGLE_NAMES)
def test_clickhouse_an_aliased_single_name_after_in_is_refused(sql: str, allowed: list[str], deny: bool) -> None:
    guard = _ch(allowed, deny)
    for label, validate, prefix in _entries(guard):
        exc = _refused(validate, prefix + sql)
        assert exc.category == ErrorCategory.POLICY, (label, str(exc))
        assert "IN (<name>) with a single name" in str(exc), (label, str(exc))


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT buoy_id FROM ocean.buoys WHERE buoy_id IN ((1 AS z))",
        "SELECT buoy_id FROM ocean.buoys WHERE buoy_id IN ((1 AS z), 2)",
    ],
)
def test_clickhouse_an_aliased_value_after_in_stays_readable(sql: str) -> None:
    assert _ch(["ocean"], True).validate_select(sql).kind == "select"


# a.b where a is no FROM item in reach: ClickHouse reads the table a.b where a table may stand
_UNBOUND_QUALIFIERS = [
    ("SELECT system.one AS x", "system", "one"),
    ("SELECT hr.salaries AS x FROM ocean.buoys", "hr", "salaries"),
    ("SELECT b.buoy_id FROM ocean.buoys b WHERE hr.salaries = 1", "hr", "salaries"),
    # a FROM item of that name in a sibling query is out of reach (live: in(0, system.one) read the table)
    ("SELECT (SELECT 1 FROM ocean.buoys AS system) AS q, system.one AS x", "system", "one"),
    # a CTE outside the FROM does not bind it (live)
    ("WITH system AS (SELECT 1 AS one) SELECT system.one AS x", "system", "one"),
    ("SELECT buoy_id FROM ocean.buoys UNION ALL SELECT system.one AS x", "system", "one"),
    # nor does a FROM item of the query that holds a CTE body or a derived table in its FROM (live, 26.3:
    # WITH c AS (SELECT 0 IN ((system.one AS z)) AS x) SELECT c.x FROM c, numbers(1) AS system read the
    # table, as did SELECT d.x FROM (SELECT 0 IN ((system.one AS z)) AS x) AS d, numbers(1) AS system)
    ("WITH c AS (SELECT system.one AS x) SELECT c.x FROM c, ocean.buoys AS system", "system", "one"),
    ("WITH c AS (SELECT hr.salaries AS x) SELECT c.x FROM c, ocean.buoys AS hr", "hr", "salaries"),
    ("SELECT d.x FROM (SELECT system.one AS x) AS d, ocean.buoys AS system", "system", "one"),
    ("SELECT d.x FROM ocean.buoys AS hr JOIN (SELECT hr.salaries AS x) AS d ON 1 = 1", "hr", "salaries"),
    ("SELECT d.x FROM ((SELECT hr.salaries AS x)) AS d, ocean.buoys AS hr", "hr", "salaries"),
    ("SELECT d.x FROM (SELECT hr.salaries AS x UNION ALL SELECT 2 AS x) AS d, ocean.buoys AS hr", "hr", "salaries"),
    ("SELECT d.x FROM (SELECT (SELECT hr.salaries) AS x) AS d, ocean.buoys AS hr", "hr", "salaries"),
    ("SELECT e.y FROM (SELECT d.x AS y FROM (SELECT hr.salaries AS x) AS d) AS e, ocean.buoys AS hr", "hr", "salaries"),
    ("SELECT d.y FROM (WITH c AS (SELECT hr.salaries AS x) SELECT x AS y FROM c) AS d, ocean.buoys AS hr", "hr",
     "salaries"),
]


@pytest.mark.parametrize(("sql", "schema", "name"), _UNBOUND_QUALIFIERS)
def test_clickhouse_an_unbound_qualifier_names_a_table_that_is_authorized(sql: str, schema: str, name: str) -> None:
    # under the allowlist: schema not permitted; under default-deny: not resolvable
    for allowed, deny in (["ocean"], True), (["ocean"], False), ([], True):
        guard = _ch(allowed, deny)
        for label, validate, prefix in _entries(guard):
            exc = _refused(validate, prefix + sql)
            assert exc.category in (ErrorCategory.AUTHZ, ErrorCategory.POLICY), (label, str(exc))
            assert f"'{schema}.{name}'" in str(exc) and "qualify a column" in str(exc), (label, str(exc))
    # with neither, a system schema stays closed, any other one is read as named
    guard = _ch([], False)
    if schema == "system":
        exc = _refused(guard.validate_select, sql)
        assert exc.category == ErrorCategory.AUTHZ and "system schema" in str(exc), str(exc)
    else:
        refs = guard.validate_select(sql).tables
        assert (schema, name) in [(r.schema, r.name) for r in refs]


# a.b where a is an ARRAY JOIN, select or WITH alias: the subcolumn b of that
# value in an expression (live, 26.3: n.x of ARRAY JOIN arr AS n is 1, t.x of
# a named tuple t is 1), the table a.b where a table may stand (live: in(0,
# system.one) past ARRAY JOIN [1] AS system read the table)
_VALUE_QUALIFIERS = [
    ("SELECT n.x FROM ocean.buoys ARRAY JOIN tags AS n", "n", "x"),
    ("SELECT n.x FROM ocean.buoys AS b ARRAY JOIN b.tags AS n WHERE n.y = 1", "n", "x"),
    ("SELECT CAST((1, 'a'), 'Tuple(x UInt8, y String)') AS t, t.x", "t", "x"),
    ("WITH CAST((1, 'a'), 'Tuple(x UInt8, y String)') AS t SELECT t.x", "t", "x"),
    ("SELECT 1 AS system, system.one AS x", "system", "one"),
    ("WITH 1 AS system SELECT system.one AS x", "system", "one"),
    ("SELECT 1 AS x FROM ocean.buoys ARRAY JOIN [1] AS system WHERE system.one = 1", "system", "one"),
]


@pytest.mark.parametrize(("sql", "alias", "name"), _VALUE_QUALIFIERS)
def test_clickhouse_a_value_alias_qualifier_is_authorized_and_named_by_index(sql: str, alias: str, name: str) -> None:
    # review, 2026-09-28: the hint said <table>.n.x, which ClickHouse rejects for an ARRAY JOIN alias
    for allowed, deny in (["ocean"], True), (["ocean"], False), ([], True):
        exc = _refused(_ch(allowed, deny).validate_select, sql)
        assert exc.category in (ErrorCategory.AUTHZ, ErrorCategory.POLICY), str(exc)
        assert f"'{alias}.{name}'" in str(exc) and f"by its index ({alias}.1)" in str(exc), str(exc)
        assert "<table>." not in str(exc), str(exc)
    # with neither, a system schema stays closed; any other a.b is the value's subcolumn, no table read
    guard = _ch([], False)
    if alias == "system":
        assert "system schema" in str(_refused(guard.validate_select, sql))
    else:
        assert all(r.schema != alias for r in guard.validate_select(sql).tables)


_BOUND_QUALIFIERS = [
    "SELECT b.buoy_id FROM ocean.buoys b",
    "SELECT b.buoy_id FROM ocean.buoys AS b",
    "SELECT buoys.buoy_id FROM ocean.buoys",
    "SELECT buoys.buoy_id FROM ocean.buoys AS b",  # the table's own name binds too (live)
    "SELECT ocean.buoys.buoy_id FROM ocean.buoys",  # three parts are never a table (live)
    "SELECT b.station.name FROM ocean.buoys b",
    "SELECT station.name.first FROM ocean.buoys",
    "SELECT tup.1 FROM ocean.buoys",
    "SELECT d.x FROM (SELECT buoy_id AS x FROM ocean.buoys) d",
    "WITH c AS (SELECT buoy_id FROM ocean.buoys) SELECT c.buoy_id FROM c",
    "SELECT b.buoy_id FROM ocean.buoys b JOIN ocean.readings r ON r.buoy_id = b.buoy_id",
    "SELECT b.buoy_id FROM ocean.buoys b WHERE b.buoy_id IN (SELECT r.buoy_id FROM ocean.readings r"
    " WHERE r.buoy_id = b.buoy_id)",
    "SELECT b.buoy_id FROM ocean.buoys AS b WHERE (SELECT b.buoy_id) = 1",  # an outer FROM item is in reach
    # so it is from a CTE or derived table inside a subquery, and a scalar WITH sees its query's FROM (live)
    "SELECT (SELECT d.x FROM (SELECT b.buoy_id AS x) AS d) AS y FROM ocean.buoys AS b",
    "SELECT (WITH c AS (SELECT b.buoy_id AS x) SELECT x FROM c) AS y FROM ocean.buoys AS b",
    "SELECT b.buoy_id FROM ocean.buoys AS b WHERE 1 IN (SELECT d.x FROM (SELECT b.buoy_id AS x) AS d)",
    "WITH (SELECT b.buoy_id) AS m SELECT m FROM ocean.buoys AS b",
    "SELECT n.1 FROM ocean.buoys ARRAY JOIN tags AS n",
    "SELECT arrayMap(x -> x.a, [tuple(1)]) AS m FROM ocean.buoys",
    "SELECT b.* FROM ocean.buoys b",
    "SELECT count() AS n FROM ocean.buoys",
]


@pytest.mark.parametrize(("allowed", "deny"), _POLICIES)
@pytest.mark.parametrize("sql", _BOUND_QUALIFIERS)
def test_clickhouse_a_qualifier_a_from_item_binds_stays_a_column(sql: str, allowed: list[str], deny: bool) -> None:
    guard = _ch(allowed, deny)
    for label, validate, prefix in _entries(guard):
        result = validate(prefix + sql)
        assert result.kind in ("select", "explain"), label
        assert all(r.schema in (None, "ocean") for r in result.tables), (label, result.tables)


@pytest.mark.parametrize("engine", [e for e in REMOTE if e != "clickhouse"])
def test_other_engines_leave_an_unbound_qualifier_to_the_engine(engine: str) -> None:
    # none of them reads a.b as a table in an expression: the engine rejects the column
    guard = _guard(engine, ["ocean"], OCEAN)
    assert guard.validate_select("SELECT b.buoy_id, hr.salaries FROM ocean.buoys b").kind == "select"


@pytest.mark.parametrize("shape", ["union", "columns", "correlated"])
def test_the_clickhouse_qualifier_scopes_are_read_once_per_query(monkeypatch: Any, shape: str) -> None:
    """A long UNION, thousands of qualified columns, or subqueries each
    naming the outer FROM item: each query's FROM names are read once."""
    import sqlglot
    from sqlglot import exp

    import universal_db_mcp.security.sql_guard as sql_guard

    n = 1400
    if shape == "union":
        sql = " UNION ALL ".join(["SELECT b.buoy_id FROM ocean.buoys b"] * n)
    elif shape == "columns":
        sql = "SELECT " + ", ".join(f"b.c{i}" for i in range(n * 4)) + " FROM ocean.buoys b"
    else:
        sql = "SELECT " + ", ".join(f"(SELECT b.c{i}) AS x{i}" for i in range(n // 2)) + " FROM ocean.buoys b"
    assert len(sql) <= sql_guard._MAX_SQL_BYTES
    selects = sum(1 for _ in sqlglot.parse_one(sql, read="clickhouse").find_all(exp.Select))
    calls = []
    names = sql_guard._clickhouse_from_names

    def counted(select: exp.Select) -> frozenset[str]:
        calls.append(select)
        return names(select)

    monkeypatch.setattr(sql_guard, "_clickhouse_from_names", counted)
    result = _ch([], True).validate_select(sql)
    assert {(r.schema, r.name) for r in result.tables} == {("ocean", "buoys")}
    assert len(calls) == selects, (len(calls), selects)


_CH_IN_TOOLS = [
    "SELECT 1 IN in(0, system.one) AS hit",
    "SELECT 1 NOT IN in(0, system.one) AS hit",
    "SELECT 1 GLOBAL IN in(0, system.one) AS hit",
    "SELECT 1 IN IN (0, system.one) AS hit",
    "SELECT CASE WHEN 1 IN in(0, hr.salaries) THEN 1 END AS hit",
    "SELECT count() AS n FROM ocean.buoys WHERE 1 IN in(0, system.one)",
    "SELECT nullIn(0, system.one) AS hit",
    "SELECT system.one AS hit",
    "SELECT 0 IN ((one AS z)) AS hit",
    "SELECT 0 NOT IN (((one AS y) AS z)) AS hit",
    "SELECT count() AS n FROM ocean.buoys WHERE 0 IN ((one AS z))",
    "WITH c AS (SELECT 0 IN ((system.one AS z)) AS x) SELECT c.x FROM c, ocean.buoys AS system",
    "WITH c AS (SELECT system.one AS x) SELECT c.x FROM c, ocean.buoys AS system",
    "SELECT d.x FROM (SELECT system.one AS x) AS d, ocean.buoys AS system",
]


@pytest.mark.parametrize(("allowed", "deny"), _POLICIES)
def test_clickhouse_query_tools_refuse_the_table_reads_before_the_engine_sees_them(
    tmp_path: Path, monkeypatch: Any, allowed: list[str], deny: bool
) -> None:
    server, fake = _server(tmp_path, monkeypatch, "clickhouse", allowed, deny=deny)
    for sql in _CH_IN_TOOLS:
        for tool, args in (
            ("db_query", {"connection_id": "remote", "sql": sql}),
            ("db_validate_query", {"connection_id": "remote", "sql": sql}),
            ("db_explain", {"connection_id": "remote", "sql": "EXPLAIN " + sql}),
        ):
            text = _call_error(server, tool, args)
            assert "POLICY_VIOLATION" in text or "AUTHORIZATION_DENIED" in text, (tool, sql, text)
        env = _call(server, "db_federated_query", {"sql": sql, "connections": ["remote"]})
        assert env["data"]["connections_run"] == 0, sql
    assert fake.statements == [] and fake.plans == []


# ---- 2. identifier escapes an engine decodes and sqlglot does not ---------------------

_UNICODE_ESCAPED = [
    'SELECT U&"sea_temp_\\0063" AS x FROM ocean.readings',
    'SELECT u&"sea_temp_\\0063" AS x FROM ocean.readings',
    'SELECT U&"sea_temp_\\0063" FROM ocean.readings',
    'SELECT r.U&"sea_temp_\\0063" AS x FROM ocean.readings AS r',
    'SELECT buoy_id FROM ocean.readings WHERE U&"sea_temp_\\0063" > 30',
    'SELECT x FROM (SELECT U&"sea_temp_\\0063" AS x FROM ocean.readings) AS d',
    'SELECT * FROM ocean.U&"r\\0065adings"',
    'SELECT * FROM U&"oc\\0065an".readings',
]


@pytest.mark.parametrize(("allowed", "deny"), _POLICIES)
@pytest.mark.parametrize("engine", ["postgres", "db2"])
@pytest.mark.parametrize("sql", _UNICODE_ESCAPED)
def test_a_unicode_escape_identifier_is_refused(engine: str, sql: str, allowed: list[str], deny: bool) -> None:
    guard = _guard(engine, allowed, OCEAN if deny else None, deny=deny)
    for label, validate, prefix in _entries(guard):
        exc = _refused(validate, prefix + sql)
        assert exc.category == ErrorCategory.POLICY, (label, str(exc))
        assert "U&" in str(exc) or "could not be parsed" in str(exc), (label, str(exc))
    if "UESCAPE" not in sql and "FROM ocean.U&" not in sql and "FROM U&" not in sql:
        assert "Unicode escapes" in str(_refused(guard.validate_select, sql)), sql


@pytest.mark.parametrize("engine", ["postgres", "db2"])
@pytest.mark.parametrize(
    "sql",
    [
        "SELECT U&'\\0041' AS x FROM ocean.readings",  # a Unicode-escape string is a value
        "SELECT 'U&\"x\"' AS x FROM ocean.readings",
        "SELECT buoy_id AS x FROM ocean.readings /* U&\"x\" */",
        'SELECT "U&""x" FROM ocean.readings',  # a quoted name that holds the text
        'SELECT buoy_id & "flags" AS x FROM ocean.readings',
        'SELECT buoy_id FROM ocean.readings AS U WHERE U.buoy_id & 1 = 1',
    ],
)
def test_unicode_escape_strings_and_plain_names_stay_readable(engine: str, sql: str) -> None:
    assert _guard(engine, ["ocean"], OCEAN).validate_select(sql).kind == "select"


@pytest.mark.parametrize("engine", ["mysql", "oracle", "mssql", "sqlite"])
def test_u_ampersand_is_an_ordinary_operand_elsewhere(engine: str) -> None:
    table = "ocean.readings" if engine != "sqlite" else "readings"
    guard = _guard(engine, [], None, deny=False)
    assert guard.validate_select(f'SELECT U&"x" AS y FROM {table}').kind == "select"


@pytest.mark.parametrize(
    "sql",
    [
        'SELECT U&"ss\\006e" AS x FROM app.customers',
        'SELECT u&"ss\\006e" FROM app.customers',
        'SELECT c.U&"ss\\006e" AS x FROM app.customers AS c',
    ],
)
def test_postgres_an_escaped_masked_column_never_reaches_the_engine(tmp_path: Path, monkeypatch: Any, sql: str) -> None:
    # live (review, 2026-09-28): U&"sea_temp_\0063" returned the masked sea_temp_c in clear
    fake = _AnswerFake(["x"], [SECRETS[0]])
    server, _ = _fake_app_server(tmp_path, monkeypatch, fake, engine="postgres", allowed=["app"], deny=True)
    for tool, args in (
        ("db_query", {"connection_id": "remote", "sql": sql}),
        ("db_validate_query", {"connection_id": "remote", "sql": sql}),
        ("db_explain", {"connection_id": "remote", "sql": "EXPLAIN " + sql}),
    ):
        text = _call_error(server, tool, args)
        assert "POLICY_VIOLATION" in text and "Unicode escapes" in text, (tool, text)
        assert SECRETS[0] not in text


_PG_AT_OPERATORS = [
    "SELECT @ sea_temp_c AS x FROM ocean.readings",  # the absolute value, read as a parameter
    "SELECT @sea_temp_c FROM ocean.readings",
    "SELECT buoy_id FROM ocean.readings WHERE @ sea_temp_c > 30",
    "SELECT sea_temp_c @@@ sea_temp_c AS x FROM ocean.readings",
    "SELECT station ^@ station AS x FROM ocean.readings",
    "SELECT 1 @ 2",
]


@pytest.mark.parametrize(("allowed", "deny"), _POLICIES)
@pytest.mark.parametrize("engine", ["postgres", "db2"])
@pytest.mark.parametrize("sql", _PG_AT_OPERATORS)
def test_postgres_an_at_operator_is_refused(engine: str, sql: str, allowed: list[str], deny: bool) -> None:
    # live (mock_pg, mask_columns [sea_temp_c]): SELECT @ sea_temp_c AS x returned 29.1 and 32.8 in clear
    guard = _guard(engine, allowed, OCEAN if deny else None, deny=deny)
    for label, validate, prefix in _entries(guard):
        exc = _refused(validate, prefix + sql)
        assert exc.category == ErrorCategory.POLICY, (label, str(exc))
        assert "abs(x)" in str(exc), (label, str(exc))


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT buoy_id FROM ocean.readings WHERE buoy_id = $1",
        "SELECT buoy_id FROM ocean.readings WHERE buoy_id IN $1",
        "SELECT abs(sea_temp_c) AS x FROM ocean.readings",
        "SELECT buoy_id FROM ocean.readings WHERE tags @> ARRAY['a'] AND tags <@ ARRAY['a']",
        "SELECT buoy_id FROM ocean.readings WHERE doc @@ query",
        "SELECT buoy_id FROM ocean.readings WHERE doc @? path",
        "SELECT '@' || station AS s, $$a @ b$$ AS t FROM ocean.readings",
    ],
)
def test_postgres_placeholders_and_other_operators_stay_readable(sql: str) -> None:
    assert _guard("postgres", ["ocean"], OCEAN).validate_select(sql).kind == "select"


def test_postgres_an_absolute_value_of_a_masked_column_never_reaches_the_engine(
    tmp_path: Path, monkeypatch: Any
) -> None:
    fake = _AnswerFake(["x"], [SECRETS[0]])
    server, _ = _fake_app_server(tmp_path, monkeypatch, fake, engine="postgres", allowed=["app"], deny=True)
    for sql in ("SELECT @ ssn AS x FROM app.customers", "SELECT @ssn FROM app.customers"):
        text = _call_error(server, "db_query", {"connection_id": "remote", "sql": sql})
        assert "POLICY_VIOLATION" in text and "abs(x)" in text, text
        assert SECRETS[0] not in text


# ---- 3. Oracle database links ------------------------------------------------------

_TRAVEL = {("travel", "bookings")}
_DB_LINKS = [
    'SELECT * FROM "DUAL"@lnk',
    'SELECT dummy FROM "SYS"."DUAL"@lnk',
    "SELECT dummy FROM dual @lnk",
    "SELECT dummy FROM sys.dual/**/@lnk",
    "SELECT dummy FROM DUAL@lnk",
    'SELECT * FROM travel."BOOKINGS"@lnk',
    'SELECT * FROM travel."BOOKINGS"@"LNK"',
    "SELECT * FROM travel.bookings @lnk",
    "SELECT * FROM travel.bookings/**/@lnk",
    "SELECT * FROM travel.bookings @ lnk",
    "SELECT * FROM travel.bookings@lnk b",
    "SELECT * FROM travel.bookings@ lnk",
    "SELECT booking_id@lnk FROM travel.bookings",
    "SELECT b.booking_id FROM travel.bookings b WHERE b.booking_id IN (SELECT booking_id FROM travel.bookings @lnk)",
    "WITH r AS (SELECT booking_id FROM travel.bookings @lnk) SELECT booking_id FROM r",
]


@pytest.mark.parametrize(
    ("allowed", "deny"),
    [(["travel"], True), (["travel"], False), ([], True), ([], False)],
    ids=["allowlist-default-deny", "allowlist", "default-deny", "neither"],
)
@pytest.mark.parametrize("sql", _DB_LINKS)
def test_oracle_a_database_link_is_refused_in_every_spelling(sql: str, allowed: list[str], deny: bool) -> None:
    # live (review, 2026-09-28): each reached Oracle as a link read (ORA-02019 without one)
    guard = _guard("oracle", allowed, _TRAVEL if deny else None, deny=deny)
    for label, validate, prefix in _entries(guard):
        exc = _refused(validate, prefix + sql)
        assert exc.category == ErrorCategory.POLICY, (label, str(exc))
        assert "database links" in str(exc) or "could not be parsed" in str(exc), (label, str(exc))


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT '@lnk' AS a FROM DUAL",
        "SELECT 'a' || '@' || 'b' AS s FROM travel.bookings",
        'SELECT "a@b" FROM travel.bookings',
        "SELECT booking_id FROM travel.bookings /* @lnk */",
        "SELECT booking_id FROM travel.bookings -- @lnk\n",
        "SELECT booking_id FROM travel.bookings WHERE booking_id IN :p",
        "SELECT dummy FROM DUAL",
    ],
)
def test_oracle_an_at_sign_in_a_literal_name_or_comment_stays_readable(sql: str) -> None:
    guard = _guard("oracle", ["travel"], _TRAVEL)
    assert guard.validate_select(sql).kind == "select"


@pytest.mark.parametrize("engine", ["mssql", "mysql"])
def test_an_at_sign_keeps_its_meaning_elsewhere(engine: str) -> None:
    # T-SQL's @p, beside a driver placeholder
    sql = {"mssql": "SELECT buoy_id FROM ocean.buoys WHERE buoy_id = @p",
           "mysql": "SELECT buoy_id FROM ocean.buoys WHERE buoy_id = %s"}[engine]
    assert _guard(engine, ["ocean"], OCEAN).validate_select(sql).kind == "select"


@pytest.mark.parametrize("sql", ['SELECT dummy FROM "DUAL"@lnk', "SELECT * FROM ocean.buoys @lnk"])
def test_oracle_query_tools_refuse_a_link_before_the_engine_sees_it(tmp_path: Path, monkeypatch: Any, sql: str) -> None:
    server, fake = _server(tmp_path, monkeypatch, "oracle", [], deny=False)
    for tool, args in (
        ("db_query", {"connection_id": "remote", "sql": sql}),
        ("db_validate_query", {"connection_id": "remote", "sql": sql}),
        ("db_explain", {"connection_id": "remote", "sql": "EXPLAIN " + sql}),
    ):
        text = _call_error(server, tool, args)
        assert "POLICY_VIOLATION" in text and "database links" in text, (tool, text)
    assert fake.statements == [] and fake.plans == []


# ---- 4. column statistics hold a column's values -----------------------------------

_STATISTICS = [
    ("mysql", "information_schema", "SELECT histogram FROM information_schema.COLUMN_STATISTICS"),
    ("mysql", "information_schema", "SELECT * FROM INFORMATION_SCHEMA.column_statistics"),
    ("mysql", "mysql", "SELECT min_value, max_value, histogram FROM mysql.column_stats"),
    ("mysql", "mysql", "SELECT * FROM mysql.column_statistics"),
    ("postgres", "pg_catalog", "SELECT most_common_vals FROM pg_catalog.pg_stats"),
    ("postgres", "pg_catalog", "SELECT most_common_vals FROM pg_stats"),  # pg_catalog is searched first
    ("postgres", "pg_catalog", "SELECT histogram_bounds FROM PG_STATS"),
    ("postgres", "pg_catalog", "SELECT most_common_vals FROM pg_catalog.pg_stats_ext"),
    ("postgres", "pg_catalog", "SELECT most_common_vals FROM pg_stats_ext_exprs"),
    ("postgres", "pg_catalog", "SELECT stavalues1 FROM pg_catalog.pg_statistic"),
    ("postgres", "pg_catalog", "SELECT stxdmcv FROM pg_statistic_ext_data"),
    ("oracle", "sys", "SELECT endpoint_actual_value FROM SYS.ALL_TAB_HISTOGRAMS"),
    ("oracle", "sys", "SELECT endpoint_actual_value FROM ALL_TAB_HISTOGRAMS"),
    ("oracle", "sys", "SELECT endpoint_value FROM DBA_TAB_HISTOGRAMS"),
    ("oracle", "sys", "SELECT endpoint_value FROM USER_PART_HISTOGRAMS"),
    ("oracle", "sys", "SELECT endpoint_value FROM SYS.CDB_SUBPART_HISTOGRAMS"),
    ("oracle", "sys", "SELECT low_value, high_value FROM ALL_TAB_COL_STATISTICS"),
    ("oracle", "sys", "SELECT low_value FROM DBA_PART_COL_STATISTICS"),
    ("oracle", "sys", "SELECT low_value FROM USER_SUBPART_COL_STATISTICS"),
    ("oracle", "sys", "SELECT low_value FROM ALL_COL_PENDING_STATS"),
    ("oracle", "sys", "SELECT endpoint_value FROM DBA_TAB_HISTGRM_PENDING_STATS"),
    ("oracle", "sys", "SELECT * FROM SYS.HISTGRM$"),
    ("oracle", "sys", "SELECT lowval, hival FROM SYS.HIST_HEAD$"),
    ("oracle", "sys", "SELECT lowval FROM SYS.WRI$_OPTSTAT_HISTHEAD_HISTORY"),
    ("oracle", "sys", "SELECT endpoint FROM SYS.WRI$_OPTSTAT_HISTGRM_HISTORY"),
    # review, 2026-09-28: the PUBLIC synonyms of *_TAB_HISTOGRAMS returned a masked column's endpoints
    ("oracle", "sys", "SELECT column_name, endpoint_actual_value FROM ALL_HISTOGRAMS"),
    ("oracle", "sys", "SELECT endpoint_actual_value FROM USER_HISTOGRAMS"),
    ("oracle", "sys", "SELECT endpoint_value FROM DBA_HISTOGRAMS"),
    # readable by PUBLIC (live: EXU10ASCU returned TRAVELLER_ID's low and high values), and the
    # export, Data Pump and In-Memory views of the same values (the fixture's catalog, as SYSTEM)
    ("oracle", "sys", "SELECT low_value, high_value FROM SYS.SQT_TAB_COL_STATISTICS"),
    ("oracle", "sys", "SELECT colname, lowval, hival FROM SYS.EXU10ASCU"),
    ("oracle", "sys", "SELECT lowval, hival FROM SYS.EXU8ASC"),
    ("oracle", "sys", "SELECT endptval FROM SYS.EXU8HSTU"),
    ("oracle", "sys", "SELECT epvalue, epvalue_raw FROM SYS.FINALHIST$"),
    ("oracle", "sys", "SELECT lowval, hival FROM SYS.KU$_COL_STATS_VIEW"),
    ("oracle", "sys", "SELECT epvalue FROM SYS.KU$_10_1_HISTGRM_MAX_VIEW"),
    ("oracle", "sys", "SELECT minimum_value, maximum_value FROM SYS.V_$IM_COL_CU"),
    ("oracle", "sys", "SELECT minimum_value FROM GV$IM_IMECOL_CU"),
    # DBMS_COMPARISON keeps scan bounds and the index values of the rows that differ
    ("oracle", "sys", "SELECT min_value, max_value FROM DBA_COMPARISON_SCAN_VALUES"),
    ("oracle", "sys", "SELECT index_value FROM USER_COMPARISON_ROW_DIF"),
    ("oracle", "sys", "SELECT cyclic_index_value FROM SYS.DBA_COMPARISON"),
    ("oracle", "sys", "SELECT min_val, max_val FROM SYS.COMPARISON_SCAN_VAL$"),
    ("db2", "syscat", "SELECT colvalue FROM SYSCAT.COLDIST"),
    ("db2", "sysstat", "SELECT colvalue FROM SYSSTAT.COLDIST"),
    ("db2", "sysstat", "SELECT high2key FROM SYSSTAT.COLUMNS"),
    ("db2", "syscat", "SELECT colvalue FROM SYSCAT.COLGROUPDIST"),
    ("db2", "sysibm", "SELECT colvalue FROM SYSIBM.SYSCOLDIST"),
    ("db2", "sysibm", "SELECT highvalue FROM SYSIBM.SYSCOLSTATS"),
    ("mssql", "sys", "SELECT min_data_id, max_data_id FROM sys.column_store_segments"),
    ("mssql", "sys", "SELECT min_data_id, max_data_id FROM sys.syscscolsegments"),  # its base table (DAC)
]


@pytest.mark.parametrize(
    ("allowed", "deny"),
    [(["app"], True), (["app"], False), ([], True), ([], False)],
    ids=["allowlist-default-deny", "allowlist", "default-deny", "neither"],
)
@pytest.mark.parametrize(("engine", "schema", "sql"), _STATISTICS)
def test_column_statistics_are_always_refused(
    engine: str, schema: str, sql: str, allowed: list[str], deny: bool
) -> None:
    # live (review, 2026-09-28): COLUMN_STATISTICS returned a masked column's buckets under the
    # default allowed_system_schemas, pg_stats its most common values with pg_catalog opened
    guard = _opened(engine, schema, sql, allowed, deny)
    for label, validate, prefix in _entries(guard):
        exc = _refused(validate, prefix + sql)
        assert exc.category == ErrorCategory.POLICY, (label, str(exc))
        assert "column statistics" in str(exc) and "allowed_system_schemas" in str(exc), (label, str(exc))


@pytest.mark.parametrize(("engine", "schema", "sql"), _STATISTICS)
def test_the_policy_refuses_column_statistics_to_every_tool(engine: str, schema: str, sql: str) -> None:
    from sqlglot import exp, parse_one

    from universal_db_mcp.security.sql_guard import sqlglot_dialect

    table = next(parse_one(sql, read=sqlglot_dialect(engine)).find_all(exp.Table))
    policy = _policy(engine, [], system_schemas=[schema])
    for written in {table.db or schema, schema}:
        # the listings leave out what is_session_sql_view matches
        assert is_session_sql_view(engine, written, table.name), (written, table.name)
        with pytest.raises(ToolFailure) as info:
            policy.check_object(written, table.name)
        assert info.value.category == ErrorCategory.POLICY and "column statistics" in str(info.value)


@pytest.mark.parametrize(
    ("engine", "schema", "name"),
    [
        ("postgres", "app", "pg_stats"),  # a user table of that name, qualified
        ("mysql", "app", "column_statistics"),
        ("mysql", None, "column_stats"),  # bare: MySQL binds it to the connection's database
        ("db2", "APP", "COLDIST"),
        ("mssql", "dbo", "column_store_segments"),
        ("clickhouse", "system", "columns"),
        ("sqlite", None, "pg_stats"),
        # review, round 2: Oracle's are SYS objects and PUBLIC synonyms, an application's namesake is its own
        ("oracle", "app", "user_histograms"),
        ("oracle", "travel", "all_histograms"),
        ("oracle", "app", "all_tab_histograms"),
        ("oracle", "app", "user_comparison"),
        ("oracle", "app", "dba_comparison_row_dif"),
        ("oracle", "app", "comparison$"),
        ("oracle", "app", "histgrm$"),
        ("oracle", "app", "exu8asc"),
    ],
)
def test_statistics_namesakes_elsewhere_are_ordinary_tables(engine: str, schema: str | None, name: str) -> None:
    assert not is_session_sql_view(engine, schema, name)


def _opened(engine: str, schema: str, sql: str, allowed: list[str], deny: bool) -> SqlGuard:
    """A guard whose policy opens the view's schema and whose resolver lists
    every table the statement names, in that schema."""
    from sqlglot import exp, parse_one

    from universal_db_mcp.security.sql_guard import sqlglot_dialect

    text = re.sub(r"\s+WITH\s+UR\s*$", "", sql)  # Db2's read tail, which sqlglot does not parse
    tables = {(schema, t.name.lower()) for t in parse_one(text, read=sqlglot_dialect(engine)).find_all(exp.Table)}
    policy = _policy(engine, allowed, deny=deny, system_schemas=[schema])
    return SqlGuard(engine, policy, StaticResolver(tables | {("app", "t")}))


_VALUE_COLUMNS = [
    ("oracle", "sys", "SELECT low_value FROM SYS.ALL_TAB_COLUMNS"),
    ("oracle", "sys", "SELECT column_name, high_value FROM ALL_TAB_COLUMNS"),
    ("oracle", "sys", 'SELECT "LOW_VALUE" FROM SYS.DBA_TAB_COLS'),
    ("oracle", "sys", "SELECT * FROM USER_TAB_COLUMNS"),
    ("oracle", "sys", "SELECT c.* FROM SYS.ALL_TAB_COLS c"),
    ("oracle", "sys", "SELECT x.h FROM (SELECT high_value AS h FROM SYS.CDB_TAB_COLUMNS) x"),
    ("oracle", "sys", "SELECT h FROM (SELECT * FROM SYS.ALL_TAB_COLUMNS) x"),
    ("oracle", "sys", "SELECT low_value FROM ALL_NESTED_TABLE_COLS"),
    ("db2", "syscat", "SELECT high2key, low2key FROM SYSCAT.COLUMNS"),
    ("db2", "syscat", "SELECT * FROM SYSCAT.COLUMNS WITH UR"),
    ("db2", "syscat", "SELECT c.* FROM SYSCAT.COLUMNS c"),
    ("db2", "sysibm", "SELECT high2key FROM SYSIBM.SYSCOLUMNS"),
    # review, 2026-09-28: COLS is the PUBLIC synonym of USER_TAB_COLUMNS (live: TRAVELLER_ID's low and
    # high values under 'neither'), SYSCAT.SYSCOLUMNS_UNION another view over SYSIBM.SYSCOLUMNS
    ("oracle", "sys", "SELECT column_name, low_value, high_value FROM COLS"),
    ("oracle", "sys", "SELECT * FROM COLS"),
    ("db2", "syscat", "SELECT name, high2key, low2key FROM SYSCAT.SYSCOLUMNS_UNION"),
    ("db2", "syscat", "SELECT * FROM SYSCAT.SYSCOLUMNS_UNION"),
]


@pytest.mark.parametrize(
    ("allowed", "deny"),
    [(["app"], True), (["app"], False), ([], True), ([], False)],
    ids=["allowlist-default-deny", "allowlist", "default-deny", "neither"],
)
@pytest.mark.parametrize(("engine", "schema", "sql"), _VALUE_COLUMNS)
def test_the_low_and_high_values_of_a_column_catalog_are_refused(
    engine: str, schema: str, sql: str, allowed: list[str], deny: bool
) -> None:
    guard = _opened(engine, schema, sql, allowed, deny)
    for label, validate, prefix in _entries(guard):
        exc = _refused(validate, prefix + sql)
        assert exc.category == ErrorCategory.POLICY, (label, str(exc))
        assert "low and high values" in str(exc), (label, str(exc))


@pytest.mark.parametrize(
    ("engine", "schema", "sql"),
    [
        ("oracle", "sys", "SELECT column_name, data_type, nullable FROM SYS.ALL_TAB_COLUMNS WHERE owner = 'APP'"),
        ("oracle", "sys", "SELECT COUNT(*) AS n FROM SYS.ALL_TAB_COLS"),
        ("oracle", "sys", "SELECT num_distinct, density, histogram FROM SYS.DBA_TAB_COLUMNS"),
        ("db2", "syscat", "SELECT colname, typename FROM SYSCAT.COLUMNS WHERE tabschema = 'APP' WITH UR"),
        ("db2", "syscat", "SELECT COUNT(*) AS n FROM SYSCAT.COLUMNS"),
        ("oracle", "sys", "SELECT * FROM SYS.ALL_TABLES"),  # a catalog view without values
        ("db2", "syscat", "SELECT * FROM SYSCAT.TABLES"),
    ],
)
def test_the_rest_of_a_column_catalog_stays_readable(engine: str, schema: str, sql: str) -> None:
    guard = _opened(engine, schema, sql, ["app"], True)
    assert guard.validate_select(sql).kind == "select"


def test_a_value_column_name_elsewhere_is_an_ordinary_column() -> None:
    guard = _guard("oracle", ["travel"], _TRAVEL)
    assert guard.validate_select("SELECT low_value, b.* FROM travel.bookings b").kind == "select"


@pytest.mark.parametrize(
    ("engine", "schema", "name"),
    [("oracle", "SYS", "ALL_TAB_COLUMNS"), ("oracle", None, "USER_TAB_COLS"), ("db2", "SYSCAT", "COLUMNS"),
     ("db2", "SYSIBM", "SYSCOLUMNS"), ("oracle", None, "COLS"), ("db2", "SYSCAT", "SYSCOLUMNS_UNION")],
)
def test_the_per_object_tools_refuse_a_column_catalog_with_values(engine: str, schema: str | None, name: str) -> None:
    # db_sample_table and db_profile_table read every column; the listings keep the view
    policy = _policy(engine, [], system_schemas=["sys", "syscat", "sysibm"])
    with pytest.raises(ToolFailure) as info:
        policy.check_object(schema or "SYS", name)
    assert info.value.category == ErrorCategory.POLICY and "low and high values" in str(info.value)
    assert not is_session_sql_view(engine, schema, name)


def test_column_statistics_are_left_out_of_listings_and_refused_by_the_tools(tmp_path: Path, monkeypatch: Any) -> None:
    # the default allowed_system_schemas opens information_schema
    catalog = [
        TableSummary("ocean", "buoys", "table"),
        TableSummary("information_schema", "TABLES", "view"),
        TableSummary("information_schema", "COLUMN_STATISTICS", "view"),
    ]
    server, fake = _app_server(tmp_path, monkeypatch, "mysql", ["ocean"], catalog)
    tables = _call(server, "db_list_tables", {"connection_id": "remote", "schema": "information_schema"})
    assert "COLUMN_STATISTICS" not in [t["name"] for t in tables["data"]["tables"]]
    for tool, args in (
        ("db_query", {"connection_id": "remote", "sql": "SELECT histogram FROM information_schema.COLUMN_STATISTICS"}),
        ("db_sample_table", {"connection_id": "remote", "object_name": "information_schema.COLUMN_STATISTICS"}),
    ):
        text = _call_error(server, tool, args)
        assert "POLICY_VIOLATION" in text and "column statistics" in text, (tool, text)
    assert not [s for s in fake.statements if "COLUMN_STATISTICS" in s.upper()], fake.statements


# ---- 4b. every catalog object that carries those values, from each fixture -----------
# Review, 2026-09-28: the lists named the well-known views, while each catalog
# holds more - Oracle's PUBLIC synonyms under other names (ALL_HISTOGRAMS,
# COLS, ALL_OUTLINES), the export, Data Pump and In-Memory views of the same
# values, and the views the catalog role reads (automatic SQL tuning sets,
# workload capture, SQL Firewall logs), which the unprivileged account used
# before does not see. So the lists are pinned to each fixture's catalog, read
# by an account that sees every dictionary object: Oracle 23.26 as SYSTEM, Db2
# 11.5 as the instance owner, PostgreSQL 17 and MySQL 9.7 as superuser, SQL
# Server 2022 as sa, ClickHouse 26.3 as default. Each object whose columns
# hold a column's values or other sessions' statements is refused, or its
# value columns are (COLUMN_VALUE_COLUMNS), or it is excused below with the
# reason it holds neither.

_CATALOG_ROLE_SESSION_SQL = [
    ("oracle", "sys", "SELECT sql_text FROM DBA_AUTOSQLSET_SQLTEXT"),
    ("oracle", "sys", "SELECT sql_text FROM CDB_AUTOSTS_SQLTEXT"),  # its PUBLIC synonym
    ("oracle", "sys", "SELECT bind_data FROM SYS.DBA_AUTOSQLSET_SQLSTAT"),
    ("oracle", "sys", "SELECT access_predicates, filter_predicates FROM SYS.CDB_AUTOSQLSET_SQLPLAN"),
    ("oracle", "sys", "SELECT sql_text FROM SYS.SWR$_SQLTEXT"),
    ("oracle", "sys", "SELECT sql_text FROM ALL_OUTLINES"),  # the PUBLIC synonym of USER_OUTLINES
    ("oracle", "outln", "SELECT sql_text FROM OUTLN.OL$"),
    ("oracle", "sys", "SELECT sql_text FROM SYS.AWR_BASE_SQLTEXT"),
    ("oracle", "sys", "SELECT bind_data FROM SYS.DBA_HIST_APP_SQLSTAT"),
    ("oracle", "sys", "SELECT bind_data FROM SYS.WRH$_SQLSTAT_BL"),
    ("oracle", "sys", "SELECT sql_text FROM SYS.DBA_WORKLOAD_CAPTURE_SQLTEXT"),
    ("oracle", "sys", "SELECT bind_value FROM SYS.WRR$_REPLAY_SQL_BINDS"),
    ("oracle", "sys", "SELECT sql_text FROM SYS.DBA_SQL_FIREWALL_VIOLATIONS"),
    ("oracle", "sys", "SELECT sql_text FROM SYS.DBA_LOCKDOWN_ERRORS"),
    ("oracle", "sys", "SELECT sql_text, translated_text FROM SYS.DBA_SQL_TRANSLATIONS"),
    ("oracle", "sys", "SELECT undo_sql FROM SYS.V_$FLASHBACK_TXN_MODS"),
    ("oracle", "sys", "SELECT access_predicates FROM GV$ALL_SQL_PLAN"),
    ("oracle", "sys", "SELECT sql_fulltext FROM V$MAPPED_SQL"),
    ("oracle", "sys", "SELECT sql_text FROM SYS.GV_$UNIFIED_AUDIT_TRAIL_TBL"),
    ("oracle", "audsys", "SELECT sql_text FROM AUDSYS.DV$ENFORCEMENT_AUDIT"),
    ("oracle", "system", "SELECT sql_text FROM SYSTEM.MVIEW$_ADV_WORKLOAD"),
    # the Query Store's base tables (read over the dedicated admin connection only)
    ("mssql", "sys", "SELECT query_sql_text FROM sys.plan_persist_query_text"),
    ("mssql", "sys", "SELECT query_plan FROM sys.plan_persist_plan"),
]


@pytest.mark.parametrize(
    ("allowed", "deny"),
    [(["app"], True), (["app"], False), ([], True), ([], False)],
    ids=["allowlist-default-deny", "allowlist", "default-deny", "neither"],
)
@pytest.mark.parametrize(("engine", "schema", "sql"), _CATALOG_ROLE_SESSION_SQL)
def test_the_catalog_roles_views_of_other_sessions_sql_are_refused(
    engine: str, schema: str, sql: str, allowed: list[str], deny: bool
) -> None:
    guard = _opened(engine, schema, sql, allowed, deny)
    for label, validate, prefix in _entries(guard):
        exc = _refused(validate, prefix + sql)
        assert exc.category == ErrorCategory.POLICY, (label, str(exc))
        assert "other sessions' SQL" in str(exc), (label, str(exc))


# Oracle's PUBLIC synonyms of a table or view under another name than the
# target's (SYNONYM=OWNER.TARGET), less the CDB_ROPP$X$* and CDB_RPP$X$*
# control file tables: a bare name the engine binds to the target unasked
_ORACLE_RENAMED_SYNONYMS = """
ALL_AW_CUBE_ENABLED_HIERCOMBO=OLAPSYS.ALL$AW_CUBE_ENABLED_HIERCOMBO
ALL_AW_CUBE_ENABLED_VIEWS=OLAPSYS.ALL$AW_CUBE_ENABLED_VIEWS
ALL_AW_DIM_ENABLED_VIEWS=OLAPSYS.ALL$AW_DIM_ENABLED_VIEWS ALL_HISTOGRAMS=SYS.ALL_TAB_HISTOGRAMS
ALL_HIST_SAGAS=SYS.DBA_HIST_SAGAS ALL_INCOMPLETE_SAGAS=SYS.DBA_INCOMPLETE_SAGAS ALL_JOBS=SYS.USER_JOBS
ALL_OLAP2_AWS=SYS.ALL$OLAP2_AWS ALL_OLAP2_AW_ATTRIBUTES=OLAPSYS.ALL$OLAP2_AW_ATTRIBUTES
ALL_OLAP2_AW_CATALOGS=OLAPSYS.ALL$OLAP2_AW_CATALOGS
ALL_OLAP2_AW_CATALOG_MEASURES=OLAPSYS.ALL$OLAP2_AW_CATALOG_MEASURES
ALL_OLAP2_AW_CUBES=OLAPSYS.ALL$OLAP2_AW_CUBES ALL_OLAP2_AW_CUBE_AGG_LVL=OLAPSYS.ALL$OLAP2_AW_CUBE_AGG_LVL
ALL_OLAP2_AW_CUBE_AGG_MEAS=OLAPSYS.ALL$OLAP2_AW_CUBE_AGG_MEAS
ALL_OLAP2_AW_CUBE_AGG_OP=OLAPSYS.ALL$OLAP2_AW_CUBE_AGG_OP
ALL_OLAP2_AW_CUBE_AGG_SPECS=OLAPSYS.ALL$OLAP2_AW_CUBE_AGG_SPECS
ALL_OLAP2_AW_CUBE_DIM_USES=OLAPSYS.ALL$OLAP2_AW_CUBE_DIM_USES
ALL_OLAP2_AW_CUBE_MEASURES=OLAPSYS.ALL$OLAP2_AW_CUBE_MEASURES
ALL_OLAP2_AW_DIMENSIONS=OLAPSYS.ALL$OLAP2_AW_DIMENSIONS
ALL_OLAP2_AW_DIM_HIER_LVL_ORD=OLAPSYS.ALL$OLAP2_AW_DIM_HIER_LVL_ORD
ALL_OLAP2_AW_DIM_LEVELS=OLAPSYS.ALL$OLAP2_AW_DIM_LEVELS ALL_OLAP2_AW_PHYS_OBJ=OLAPSYS.ALL$OLAP2_AW_PHYS_OBJ
ALL_OLAP2_AW_PHYS_OBJ_PROP=OLAPSYS.ALL$OLAP2_AW_PHYS_OBJ_PROP ALL_OUTLINES=SYS.USER_OUTLINES
ALL_OUTLINE_HINTS=SYS.USER_OUTLINE_HINTS ALL_SAGAS=SYS.DBA_SAGAS ALL_SAGA_BROKERS=SYS.DBA_SAGA_BROKERS
ALL_SAGA_DETAILS=SYS.DBA_SAGA_DETAILS ALL_SAGA_ERRORS=SYS.DBA_SAGA_ERRORS
ALL_SAGA_FINALIZATION=SYS.DBA_SAGA_FINALIZATION ALL_SAGA_PARTICIPANTS=SYS.DBA_SAGA_PARTICIPANTS
ALL_SAGA_PARTICIPANT_SET=SYS.DBA_SAGA_PARTICIPANT_SET ALL_SAGA_PENDING=SYS.DBA_SAGA_PENDING
ALL_SDO_INDEX_HISTOGRAMS=MDSYS.ALL_SDO_INDEX_HISTOGRAM ALL_SNAPSHOT_REFRESH_TIMES=SYS.ALL_MVIEW_REFRESH_TIMES
BLOCKER_RESOLVER_PARAMETERS=SYS.HANG_MANAGER_PARAMETERS CAT=SYS.USER_CATALOG
CDB_AUTOSTS_ATTRNAME=SYS.CDB_AUTOSQLSET_ATTRNAME CDB_AUTOSTS_OPTENV=SYS.CDB_AUTOSQLSET_OPTENV
CDB_AUTOSTS_SNAPSHOT=SYS.CDB_AUTOSQLSET_SNAPSHOT CDB_AUTOSTS_SNAPSHOT_ERROR=SYS.CDB_AUTOSQLSET_SNAPSHOT_ERROR
CDB_AUTOSTS_SQLPLAN=SYS.CDB_AUTOSQLSET_SQLPLAN CDB_AUTOSTS_SQLSTAT=SYS.CDB_AUTOSQLSET_SQLSTAT
CDB_AUTOSTS_SQLTEXT=SYS.CDB_AUTOSQLSET_SQLTEXT CDB_BLOCKER_RESOLVER_PARAMETERS=SYS.CDB_HANG_MANAGER_PARAMETERS
CDB_XS_ENB_AUDIT_POLICIES=SYS.CDB_XS_ENABLED_AUDIT_POLICIES CLIENT_RESULT_CACHE_STATS$=SYS.CRCSTATS_$
CLU=SYS.USER_CLUSTERS COLS=SYS.USER_TAB_COLUMNS DATAPUMP_DIR_OBJS=SYS.LOADER_DIR_OBJS
DBA_APPLY_OBJECT_DEPENDENCIES=SYS._DBA_APPLY_OBJECT_CONSTRAINTS
DBA_APPLY_VALUE_DEPENDENCIES=SYS._DBA_APPLY_CONSTRAINT_COLUMNS DBA_AUTOSTS_ATTRNAME=SYS.DBA_AUTOSQLSET_ATTRNAME
DBA_AUTOSTS_OPTENV=SYS.DBA_AUTOSQLSET_OPTENV DBA_AUTOSTS_SNAPSHOT=SYS.DBA_AUTOSQLSET_SNAPSHOT
DBA_AUTOSTS_SNAPSHOT_ERROR=SYS.DBA_AUTOSQLSET_SNAPSHOT_ERROR DBA_AUTOSTS_SQLPLAN=SYS.DBA_AUTOSQLSET_SQLPLAN
DBA_AUTOSTS_SQLSTAT=SYS.DBA_AUTOSQLSET_SQLSTAT DBA_AUTOSTS_SQLTEXT=SYS.DBA_AUTOSQLSET_SQLTEXT
DBA_BLOCKER_RESOLVER_PARAMETERS=SYS.DBA_HANG_MANAGER_PARAMETERS DBA_HISTOGRAMS=SYS.DBA_TAB_HISTOGRAMS
DBA_LOCKS=SYS.DBA_LOCK DBA_SNAPSHOT_LOG_FILTER_COLS=SYS.DBA_MVIEW_LOG_FILTER_COLS
DBA_SNAPSHOT_REFRESH_TIMES=SYS.DBA_MVIEW_REFRESH_TIMES DBA_SODA_COLLECTIONS=XDB.JSON$DBA_COLLECTION_METADATA
DBA_SQLSET_DEFINITIONS=SYS.DBA_SQLSET DBA_XS_ENB_AUDIT_POLICIES=SYS.DBA_XS_ENABLED_AUDIT_POLICIES
DBA_XS_PRIVILEGE_GRANTS=SYS.DBA_XS_COLUMN_CONSTRAINTS DICT=SYS.DICTIONARY EXT_TO_OBJ=SYS.EXT_TO_OBJ_VIEW
GV$GC_ELEMENTS_WITH_COLLISIONS=SYS.GV_$GC_ELEMENTS_W_COLLISIONS GV$GES_CONVERT_LOCAL=SYS.GV_$DLM_CONVERT_LOCAL
GV$GES_CONVERT_REMOTE=SYS.GV_$DLM_CONVERT_REMOTE GV$GES_LATCH=SYS.GV_$DLM_LATCH GV$GES_RESOURCE=SYS.GV_$DLM_RESS
GV$GES_STATISTICS=SYS.GV_$DLM_MISC GV$GES_TRAFFIC_CONTROLLER=SYS.GV_$DLM_TRAFFIC_CONTROLLER
GV$GOLDENGATE_MESSAGE_TRACKING=SYS.GV_$GOLDENGATE_MESSAGETRACKING
GV$PGA_TARGET_ADVICE_HISTOGRAM=SYS.GV_$PGATARGET_ADVICE_HISTOGRAM
GV$REPLAY_CONTEXT_SYSTIMESTAMP=SYS.GV_$REPLAYCONTEXT_SYSTIMESTAMP
GV$RSRC_CONSUMER_GROUP_CPU_MTH=SYS.GV_$RSRC_CONSUME_GROUP_CPU_MTH GV$TEMPSEG_USAGE=SYS.GV_$SORT_USAGE
GV$XS_SESSION_NS_ATTRIBUTE=SYS.GV_$XS_SESSION_NS_ATTRIBUTES GV$XS_SESSION_ROLE=SYS.GV_$XS_SESSION_ROLES
IND=SYS.USER_INDEXES LBAC_AUDIT_ACTIONS=LBACSYS.OLS$AUDIT_ACTIONS
LOGSTDBY_UNSUPPORTED_TABLES=SYS.DBA_LOGSTDBY_UNSUPPORTED_TABLE MV_CAPABILITIES_TABLE=SYS.MV_CAPABILITIES_TABLE$
OBJ=SYS.USER_OBJECTS PLAN_TABLE=SYS.PLAN_TABLE$ PRODUCT_PROFILE=SYSTEM.PRODUCT_PRIVS
PRODUCT_USER_PROFILE=SYSTEM.PRODUCT_PRIVS RECYCLEBIN=SYS.USER_RECYCLEBIN REWRITE_TABLE=SYS.REWRITE_TABLE$
SDO_INDEX_HISTOGRAM=MDSYS.USER_SDO_INDEX_HISTOGRAM SDO_INDEX_HISTOGRAMS=MDSYS.USER_SDO_INDEX_HISTOGRAM
SDO_INDEX_METADATA=MDSYS.USER_SDO_INDEX_METADATA SDO_SRS_NAMESPACE=MDSYS.SRSNAMESPACE_TABLE
SEQ=SYS.USER_SEQUENCES SM$VERSION=SYS.SM_$VERSION SYN=SYS.USER_SYNONYMS TABS=SYS.USER_TABLES
USER_HISTOGRAMS=SYS.USER_TAB_HISTOGRAMS USER_SDO_INDEX_HISTOGRAMS=MDSYS.USER_SDO_INDEX_HISTOGRAM
USER_SNAPSHOT_REFRESH_TIMES=SYS.USER_MVIEW_REFRESH_TIMES USER_SODA_COLLECTIONS=XDB.JSON$USER_COLLECTION_METADATA
USER_SQLSET_DEFINITIONS=SYS.USER_SQLSET V$GC_ELEMENTS_WITH_COLLISIONS=SYS.V_$GC_ELEMENTS_W_COLLISIONS
V$GES_CONVERT_LOCAL=SYS.V_$DLM_CONVERT_LOCAL V$GES_CONVERT_REMOTE=SYS.V_$DLM_CONVERT_REMOTE
V$GES_LATCH=SYS.V_$DLM_LATCH V$GES_RESOURCE=SYS.V_$DLM_RESS V$GES_STATISTICS=SYS.V_$DLM_MISC
V$GES_TRAFFIC_CONTROLLER=SYS.V_$DLM_TRAFFIC_CONTROLLER V$TEMPSEG_USAGE=SYS.V_$SORT_USAGE
V$XS_SESSION_NS_ATTRIBUTE=SYS.V_$XS_SESSION_NS_ATTRIBUTES V$XS_SESSION_ROLE=SYS.V_$XS_SESSION_ROLES
X$KXFTASK=SYS.V_$KXFTASK __SCHEMA=SYS.__GRAPHQL_SCHEMA __TYPE=SYS.__GRAPHQL_TYPES
""".split()

def test_a_renamed_public_synonym_is_refused_as_its_target_is() -> None:
    # review, 2026-09-28: ALL_HISTOGRAMS, USER_HISTOGRAMS and COLS returned what their targets are refused for
    assert len(_ORACLE_RENAMED_SYNONYMS) == 120
    for pair in _ORACLE_RENAMED_SYNONYMS:
        synonym, target = pair.split("=")
        owner, name = target.split(".", 1)
        assert is_session_sql_view("oracle", None, synonym) == is_session_sql_view("oracle", owner, name), pair
        assert is_column_statistics_view("oracle", None, synonym) == is_column_statistics_view(
            "oracle", owner, name
        ), pair
        assert value_columns("oracle", None, synonym) == value_columns("oracle", owner, name), pair


# The objects with a column named like a value taken from a column's data -
# LOW_VALUE, HIGH_VALUE, LOWVAL, HIVAL, ENDPOINT*, ENDPT*, EPVALUE*, MIN/MAX
# VALUE or VAL, MINIMUM, MAXIMUM, BUCKET, HISTOGRAM, COLVALUE, HIGH2KEY,
# LOW2KEY, MOST_COMMON_*, STAVALUES*, a partition's bounds - or of a type
# that holds such values (anyarray, pg_mcv_list)
_ORACLE_VALUE_OBJECTS = """
GSMADMIN_INTERNAL.GSM SYS.ALL_COL_PENDING_STATS SYS.ALL_IND_PARTITIONS SYS.ALL_IND_SUBPARTITIONS
SYS.ALL_NESTED_TABLE_COLS SYS.ALL_PART_COL_STATISTICS SYS.ALL_PART_HISTOGRAMS SYS.ALL_SEQUENCES
SYS.ALL_SUBPART_COL_STATISTICS SYS.ALL_SUBPART_HISTOGRAMS SYS.ALL_TAB_COLS SYS.ALL_TAB_COLS_V$
SYS.ALL_TAB_COLUMNS SYS.ALL_TAB_COL_STATISTICS SYS.ALL_TAB_HISTGRM_PENDING_STATS SYS.ALL_TAB_HISTOGRAMS
SYS.ALL_TAB_PARTITIONS SYS.ALL_TAB_SUBPARTITIONS SYS.AWR_BASE_CON_EXAMETRIC_SUMMARY
SYS.AWR_BASE_CON_SYSMETRIC_SUMMARY SYS.AWR_BASE_SYSMETRIC_SUMMARY SYS.AWR_CDB_CON_SYSMETRIC_SUMM
SYS.AWR_CDB_SYSMETRIC_SUMMARY SYS.AWR_PDB_CON_SYSMETRIC_SUMM SYS.AWR_PDB_SYSMETRIC_SUMMARY
SYS.AWR_ROOT_CON_SYSMETRIC_SUMM SYS.AWR_ROOT_SYSMETRIC_SUMMARY SYS.CDB_COL_PENDING_STATS
SYS.CDB_COMPARISON_SCAN_VALUES SYS.CDB_HIST_CON_SYSMETRIC_SUMM SYS.CDB_HIST_SYSMETRIC_SUMMARY
SYS.CDB_IND_PARTITIONS SYS.CDB_IND_SUBPARTITIONS SYS.CDB_LOCKDOWN_PROFILES SYS.CDB_NESTED_TABLE_COLS
SYS.CDB_PART_COL_STATISTICS SYS.CDB_PART_HISTOGRAMS SYS.CDB_ROLLING_PARAMETERS SYS.CDB_SEQUENCES
SYS.CDB_SUBPART_COL_STATISTICS SYS.CDB_SUBPART_HISTOGRAMS SYS.CDB_TAB_COLS SYS.CDB_TAB_COLS_V$
SYS.CDB_TAB_COLUMNS SYS.CDB_TAB_COL_STATISTICS SYS.CDB_TAB_HISTGRM_PENDING_STATS SYS.CDB_TAB_HISTOGRAMS
SYS.CDB_TAB_PARTITIONS SYS.CDB_TAB_SUBPARTITIONS SYS.DBA_COL_PENDING_STATS SYS.DBA_COMPARISON_SCAN_VALUES
SYS.DBA_HIST_CON_SYSMETRIC_SUMM SYS.DBA_HIST_SYSMETRIC_SUMMARY SYS.DBA_IND_PARTITIONS SYS.DBA_IND_SUBPARTITIONS
SYS.DBA_LOCKDOWN_PROFILES SYS.DBA_NESTED_TABLE_COLS SYS.DBA_PART_COL_STATISTICS SYS.DBA_PART_HISTOGRAMS
SYS.DBA_ROLLING_PARAMETERS SYS.DBA_SEQUENCES SYS.DBA_SUBPART_COL_STATISTICS SYS.DBA_SUBPART_HISTOGRAMS
SYS.DBA_TAB_COLS SYS.DBA_TAB_COLS_V$ SYS.DBA_TAB_COLUMNS SYS.DBA_TAB_COL_STATISTICS
SYS.DBA_TAB_HISTGRM_PENDING_STATS SYS.DBA_TAB_HISTOGRAMS SYS.DBA_TAB_PARTITIONS SYS.DBA_TAB_SUBPARTITIONS
SYS.EXU10ASC SYS.EXU10ASCU SYS.EXU8ASC SYS.EXU8ASCU SYS.EXU8HST SYS.EXU8HSTU SYS.EXU8SEQ SYS.EXU8SEQU
SYS.FINALHIST$ SYS.GV_$ARCHIVED_LOG SYS.GV_$CON_SYSMETRIC_SUMMARY SYS.GV_$FOREIGN_ARCHIVED_LOG SYS.GV_$IM_COL_CU
SYS.GV_$IM_IMECOL_CU SYS.GV_$REQDIST SYS.GV_$SESSION_CURSOR_CACHE SYS.GV_$SYSMETRIC_SUMMARY SYS.HISTGRM$
SYS.HIST_HEAD$ SYS.KU$_10_1_HISTGRM_MAX_VIEW SYS.KU$_10_1_HISTGRM_MIN_VIEW SYS.KU$_10_1_PTAB_COL_STATS_VIEW
SYS.KU$_10_1_TAB_COL_STATS_VIEW SYS.KU$_COL_STATS_VIEW SYS.KU$_HISTGRM_VIEW SYS.KU$_IDCOL_SEQ_VIEW
SYS.KU$_SEQUENCE_VIEW SYS.LOCKDOWN_PROF$ SYS.ROLLING$PARAMETERS SYS.SEQ$ SYS.SQT_TAB_COL_STATISTICS
SYS.USER_COL_PENDING_STATS SYS.USER_COMPARISON_SCAN_VALUES SYS.USER_IND_PARTITIONS SYS.USER_IND_SUBPARTITIONS
SYS.USER_NESTED_TABLE_COLS SYS.USER_PART_COL_STATISTICS SYS.USER_PART_HISTOGRAMS SYS.USER_SEQUENCES
SYS.USER_SUBPART_COL_STATISTICS SYS.USER_SUBPART_HISTOGRAMS SYS.USER_TAB_COLS SYS.USER_TAB_COLS_V$
SYS.USER_TAB_COLUMNS SYS.USER_TAB_COL_STATISTICS SYS.USER_TAB_HISTGRM_PENDING_STATS SYS.USER_TAB_HISTOGRAMS
SYS.USER_TAB_PARTITIONS SYS.USER_TAB_SUBPARTITIONS SYS.V_$ARCHIVED_LOG SYS.V_$CON_SYSMETRIC_SUMMARY
SYS.V_$DIAG_IPS_CONFIGURATION SYS.V_$FOREIGN_ARCHIVED_LOG SYS.V_$IM_COL_CU SYS.V_$IM_IMECOL_CU SYS.V_$REQDIST
SYS.V_$SESSION_CURSOR_CACHE SYS.V_$SYSMETRIC_SUMMARY SYS.WRH$_CON_EXAMETRIC_SUMMARY
SYS.WRH$_CON_EXAMETRIC_SUMMARY_BL SYS.WRH$_CON_SYSMETRIC_SUMMARY SYS.WRH$_CON_SYSMETRIC_SUMMARY_BL
SYS.WRH$_SYSMETRIC_SUMMARY SYS.WRH$_SYSMETRIC_SUMMARY_BL SYS.WRI$_OPTSTAT_HISTGRM_HISTORY
SYS.WRI$_OPTSTAT_HISTHEAD_HISTORY
""".split()
_DB2_VALUE_OBJECTS = """
SYSCAT.COLDIST SYSCAT.COLGROUPDIST SYSCAT.COLIDENTATTRIBUTES SYSCAT.COLUMNS SYSCAT.DATAPARTITIONS
SYSCAT.HISTOGRAMTEMPLATEUSE SYSCAT.SEQUENCES SYSCAT.SYSCOLUMNS_UNION SYSCAT.THRESHOLDS SYSIBM.SYSCOLDIST
SYSIBM.SYSCOLGROUPDIST SYSIBM.SYSCOLUMNS SYSIBM.SYSDATAPARTITIONS SYSIBM.SYSHISTOGRAMTEMPLATEUSE SYSIBM.SYSSEQUENCES
SYSIBM.SYSTHRESHOLDS SYSIBMADM.DBCFG SYSIBMADM.DBMCFG SYSIBMADM.ENV_CF_SYS_RESOURCES SYSIBMADM.ENV_SYS_RESOURCES
SYSSTAT.COLDIST SYSSTAT.COLGROUPDIST SYSSTAT.COLUMNS
""".split()
_POSTGRES_VALUE_OBJECTS = """
pg_catalog.pg_attribute pg_catalog.pg_class pg_catalog.pg_sequences pg_catalog.pg_statistic
pg_catalog.pg_statistic_ext_data pg_catalog.pg_statistic_ext_data_stxoid_inh_index pg_catalog.pg_stats
pg_catalog.pg_stats_ext pg_catalog.pg_stats_ext_exprs
""".split()
_MYSQL_VALUE_OBJECTS = """
information_schema.COLUMN_STATISTICS information_schema.PARTITIONS
performance_schema.events_statements_histogram_by_digest performance_schema.events_statements_histogram_global
performance_schema.variables_info performance_schema.variables_metadata sys.schema_auto_increment_columns
""".split()
_CLICKHOUSE_VALUE_OBJECTS = """
system.columns system.detached_parts system.dropped_tables_parts system.merges system.part_log system.parts
system.parts_columns system.projection_parts system.projection_parts_columns system.replicated_fetches
""".split()
_MSSQL_VALUE_OBJECTS = """
sys.column_store_segments sys.syscscolsegments sys.dm_db_stats_histogram sys.partition_range_values
""".split()

# A partition's bounds are a documented residual (system_schemas.py, beside
# COLUMN_VALUE_COLUMNS): a site that partitions on a masked column shows
# values of it there
_PARTITION_BOUNDS = "a partition's bounds (the documented residual)"
_HOLDS_NO_COLUMN_VALUES: dict[str, list[tuple[str, str]]] = {
    "oracle": [
        (r"sys\.(?:all|cdb|dba|user)_(?:tab|ind)_(?:sub)?partitions", _PARTITION_BOUNDS),
        (r"sys\.(?:(?:all|cdb|dba|user)_sequences|seq\$|exu8sequ?|ku\$_(?:sequence|idcol_seq)_view)",
         "a sequence's bounds"),
        (r"sys\.[\w$]*(?:sysmetric|exametric)_summ\w*", "metric values"),
        (r"sys\.(?:(?:cdb|dba)_(?:rolling_parameters|lockdown_profiles)|rolling\$parameters|lockdown_prof\$)",
         "a parameter's limits"),
        (r"sys\.g?v_\$(?:session_cursor_cache|reqdist|diag_ips_configuration|(?:foreign_)?archived_log)",
         "counters and settings"),
        (r"gsmadmin_internal\.gsm", "a service's endpoints"),
    ],
    "db2": [
        (r"sys(?:cat|ibm)\.(?:sys)?datapartitions", _PARTITION_BOUNDS),
        (r"sys(?:cat|ibm)\.(?:sys)?(?:sequences|thresholds|histogramtemplateuse)|syscat\.colidentattributes",
         "a sequence's or threshold's bounds, a histogram template's type"),
        (r"sysibmadm\.(?:dbm?cfg|env_(?:cf_)?sys_resources)", "configuration values"),
    ],
    "postgres": [
        (r"pg_catalog\.pg_class", _PARTITION_BOUNDS),
        (r"pg_catalog\.pg_attribute", "attmissingval: the DEFAULT a column was added with, from its DDL"),
        (r"pg_catalog\.pg_sequences", "a sequence's bounds"),
        (r"pg_catalog\.pg_statistic_ext_data_stxoid_inh_index", "an index on an id and a flag"),
    ],
    "mysql": [
        (r"information_schema\.partitions", _PARTITION_BOUNDS),
        (r"performance_schema\.variables_(?:info|metadata)|sys\.schema_auto_increment_columns",
         "a variable's or a type's limits"),
    ],
    "clickhouse": [
        (r"system\.(?:(?:detached_|dropped_tables_|projection_)?parts(?:_columns)?|merges|part_log|replicated_fetches)",
         _PARTITION_BOUNDS),
        (r"system\.columns", "statistics: the types of statistics declared on a column"),
    ],
    "mssql": [(r"sys\.partition_range_values", _PARTITION_BOUNDS)],
}

# Oracle objects with a column named like statement text, bind values or plan
# predicates (SQL_TEXT, SQL_FULLTEXT, SQLTEXT, STATEMENT, STMT, BIND_DATA,
# BIND*VAL*, ACCESS_PREDICATES, FILTER_PREDICATES, OTHER_XML, UNDO_SQL, ...)
_ORACLE_STATEMENT_OBJECTS = """
AUDSYS.AUD$UNIFIED AUDSYS.CDB_UNIFIED_AUDIT_TRAIL AUDSYS.DV$CONFIGURATION_AUDIT AUDSYS.DV$ENFORCEMENT_AUDIT
AUDSYS.UNIFIED_AUDIT_TRAIL DBSNMP.MGMT_BASELINE_SQL DBSNMP.MGMT_RESPONSE_BASELINE DVSYS.DBA_DV_SIMULATION_LOG
DVSYS.SIMULATION_LOG$ OUTLN.OL$ SYS.AC_VER$_SQLPLANS SYS.AC_VER$_SQLSET_PLANS SYS.AC_VER$_SQLSET_STATEMENTS
SYS.ALL_SQLSET_PLANS SYS.ALL_SQLSET_STATEMENTS SYS.ALL_SQL_TRANSLATIONS SYS.ASSERT$ SYS.ASSERTSTMT$ SYS.AUD$
SYS.AWR_BASE_SQLSTAT SYS.AWR_BASE_SQLTEXT SYS.AWR_BASE_SQL_PLAN SYS.AWR_CDB_APP_SQLSTAT SYS.AWR_CDB_SQLBIND
SYS.AWR_CDB_SQLSTAT SYS.AWR_CDB_SQLTEXT SYS.AWR_CDB_SQL_PLAN SYS.AWR_PDB_APP_SQLSTAT SYS.AWR_PDB_SQLBIND
SYS.AWR_PDB_SQLSTAT SYS.AWR_PDB_SQLTEXT SYS.AWR_PDB_SQL_PLAN SYS.AWR_ROOT_APP_SQLSTAT SYS.AWR_ROOT_SQLBIND
SYS.AWR_ROOT_SQLSTAT SYS.AWR_ROOT_SQLTEXT SYS.AWR_ROOT_SQL_PLAN SYS.BOOTSTRAP$ SYS.CDB_ADVISOR_SQLA_WK_STMTS
SYS.CDB_ADVISOR_SQLPLANS SYS.CDB_ADVISOR_SQLW_STMTS SYS.CDB_AUDIT_EXISTS SYS.CDB_AUDIT_OBJECT
SYS.CDB_AUDIT_STATEMENT SYS.CDB_AUDIT_TRAIL SYS.CDB_AUTOSQLSET_SQLPLAN SYS.CDB_AUTOSQLSET_SQLSTAT
SYS.CDB_AUTOSQLSET_SQLTEXT SYS.CDB_AUTO_INDEX_IND_ACTIONS SYS.CDB_AUTO_INDEX_SQL_ACTIONS
SYS.CDB_COMMON_AUDIT_TRAIL SYS.CDB_FGA_AUDIT_TRAIL SYS.CDB_HIST_APP_SQLSTAT SYS.CDB_HIST_SQLBIND
SYS.CDB_HIST_SQLSTAT SYS.CDB_HIST_SQLTEXT SYS.CDB_HIST_SQL_PLAN SYS.CDB_LOCKDOWN_ERRORS SYS.CDB_MVREF_STMT_STATS
SYS.CDB_PARALLEL_EXECUTE_TASKS SYS.CDB_REGISTRY_ERROR SYS.CDB_REPLAY_UPGRADE_ERRORS SYS.CDB_RESUMABLE
SYS.CDB_SQLSET_PLANS SYS.CDB_SQLSET_STATEMENTS SYS.CDB_SQLTUNE_PLANS SYS.CDB_SQL_ERROR_MITIGATIONS
SYS.CDB_SQL_PATCHES SYS.CDB_SQL_PLAN_BASELINES SYS.CDB_SQL_PROFILES SYS.CDB_SQL_QUARANTINE
SYS.CDB_SQL_TRANSLATIONS SYS.CDB_STREAMS_STMTS SYS.CDB_TUNE_MVIEW SYS.CDB_WI_STATEMENTS
SYS.CDB_WORKLOAD_REPLAY_IFSLA SYS.CDB_WORKLOAD_SQL_MAP SYS.CDB_XSTREAM_STMTS SYS.DATA_PUMP_XPL_TABLE$
SYS.DBA_ADVISOR_SQLA_WK_STMTS SYS.DBA_ADVISOR_SQLPLANS SYS.DBA_ADVISOR_SQLW_STMTS SYS.DBA_AUDIT_EXISTS
SYS.DBA_AUDIT_OBJECT SYS.DBA_AUDIT_STATEMENT SYS.DBA_AUDIT_TRAIL SYS.DBA_AUTOSQLSET_SQLPLAN
SYS.DBA_AUTOSQLSET_SQLSTAT SYS.DBA_AUTOSQLSET_SQLTEXT SYS.DBA_AUTO_INDEX_IND_ACTIONS
SYS.DBA_AUTO_INDEX_SQL_ACTIONS SYS.DBA_AWRAPP_SQLSTAT SYS.DBA_COMMON_AUDIT_TRAIL SYS.DBA_FGA_AUDIT_TRAIL
SYS.DBA_HIST_APP_SQLSTAT SYS.DBA_HIST_SQLBIND SYS.DBA_HIST_SQLSTAT SYS.DBA_HIST_SQLTEXT SYS.DBA_HIST_SQL_PLAN
SYS.DBA_LOCKDOWN_ERRORS SYS.DBA_MVREF_STMT_STATS SYS.DBA_OUTLINES SYS.DBA_PARALLEL_EXECUTE_TASKS
SYS.DBA_REGISTRY_ERROR SYS.DBA_REPLAY_UPGRADE_ERRORS SYS.DBA_REPLAY_UPGRADE_STATEMENTS SYS.DBA_RESUMABLE
SYS.DBA_SQLSET_PLANS SYS.DBA_SQLSET_STATEMENTS SYS.DBA_SQLTUNE_PLANS SYS.DBA_SQL_ERROR_MITIGATIONS
SYS.DBA_SQL_FIREWALL_ALLOWED_SQL SYS.DBA_SQL_FIREWALL_CAPTURE_LOGS SYS.DBA_SQL_FIREWALL_SQL_LOGS
SYS.DBA_SQL_FIREWALL_VIOLATIONS SYS.DBA_SQL_PATCHES SYS.DBA_SQL_PLAN_BASELINES SYS.DBA_SQL_PROFILES
SYS.DBA_SQL_QUARANTINE SYS.DBA_SQL_TRANSLATIONS SYS.DBA_STREAMS_STMTS SYS.DBA_TUNE_MVIEW SYS.DBA_WI_STATEMENTS
SYS.DBA_WORKLOAD_CAPTURE_SQLTEXT SYS.DBA_WORKLOAD_LONG_SQLTEXT SYS.DBA_WORKLOAD_REPLAY_IFSLA
SYS.DBA_WORKLOAD_SQL_MAP SYS.DBA_XSTREAM_STMTS SYS.DBMS_PARALLEL_EXECUTE_TASK$ SYS.DIAG$_SQL_ERROR SYS.EXU9RLS
SYS.FGA_LOG$ SYS.FGA_LOG$FOR_EXPORT SYS.FGA_LOG$FOR_EXPORT_TBL SYS.FLASHBACK_TRANSACTION_QUERY SYS.FW$SQL_LOG
SYS.GV_$ADVISOR_CURRENT_SQLPLAN SYS.GV_$ALL_SQL_BIND_CAPTURE SYS.GV_$ALL_SQL_MONITOR SYS.GV_$ALL_SQL_PLAN
SYS.GV_$ALL_SQL_PLAN_MONITOR SYS.GV_$LOGMNR_CONTENTS SYS.GV_$MAPPED_SQL SYS.GV_$OPEN_CURSOR
SYS.GV_$RECENT_SQL_MONITOR SYS.GV_$SQL SYS.GV_$SQLAREA SYS.GV_$SQLAREA_PLAN_HASH SYS.GV_$SQLSTATS
SYS.GV_$SQLSTATS_PLAN_HASH SYS.GV_$SQLTEXT SYS.GV_$SQLTEXT_WITH_NEWLINES SYS.GV_$SQL_BIND_CAPTURE
SYS.GV_$SQL_CS_STATISTICS SYS.GV_$SQL_HISTORY SYS.GV_$SQL_HISTORY_STATS SYS.GV_$SQL_LOCAL_LAST_EXEC
SYS.GV_$SQL_MONITOR SYS.GV_$SQL_PLAN SYS.GV_$SQL_PLAN_MONITOR SYS.GV_$SQL_PLAN_STATISTICS_ALL
SYS.GV_$SQL_REDIRECTION SYS.GV_$SQL_SHARED_MEMORY SYS.GV_$SQL_TESTCASES SYS.GV_$UNIFIED_AUDIT_TRAIL
SYS.GV_$UNIFIED_AUDIT_TRAIL_TBL SYS.GV_$XML_AUDIT_TRAIL SYS.JIREFRESHSQL$ SYS.KU$_OUTLINE_VIEW
SYS.LOCKDOWN_ERROR$ SYS.MVREF$_STMT_STATS SYS.PDB_SYNC_STMT$ SYS.PLAN_TABLE$ SYS.PLSCOPE_SQL$ SYS.REGISTRY$ERROR
SYS.SNAP_REFOP$ SYS.SQL$TEXT SYS.SQL$TEXT_DATAPUMP SYS.SQL$TEXT_DATAPUMP_TBL SYS.SQLOBJ$AUXDATA
SYS.SQLOBJ$AUXDATA_DATAPUMP SYS.SQLOBJ$AUXDATA_DATAPUMP_TBL SYS.SQLOBJ$PLAN SYS.SQLOBJ$PLAN_DATAPUMP
SYS.SQLOBJ$PLAN_DATAPUMP_TBL SYS.SQLTXL_SQL$ SYS.SQL_LOG$ SYS.STREAMS$_STMT_HANDLER_STMTS SYS.SWR$_SQLSTAT_DELTA
SYS.SWR$_SQLTEXT SYS.SYNCREF$_STEP_STATUS SYS.USER_ADVISOR_SQLA_WK_STMTS SYS.USER_ADVISOR_SQLPLANS
SYS.USER_ADVISOR_SQLW_STMTS SYS.USER_AUDIT_OBJECT SYS.USER_AUDIT_STATEMENT SYS.USER_AUDIT_TRAIL
SYS.USER_MVREF_STMT_STATS SYS.USER_OUTLINES SYS.USER_PARALLEL_EXECUTE_TASKS SYS.USER_RESUMABLE
SYS.USER_SQLSET_PLANS SYS.USER_SQLSET_STATEMENTS SYS.USER_SQLTUNE_PLANS SYS.USER_SQL_TRANSLATIONS
SYS.USER_TUNE_MVIEW SYS.V_$ADVISOR_CURRENT_SQLPLAN SYS.V_$ALL_SQL_BIND_CAPTURE SYS.V_$ALL_SQL_MONITOR
SYS.V_$ALL_SQL_PLAN SYS.V_$ALL_SQL_PLAN_MONITOR SYS.V_$FLASHBACK_TXN_MODS SYS.V_$LOGMNR_CONTENTS
SYS.V_$MAPPED_SQL SYS.V_$OPEN_CURSOR SYS.V_$RECENT_SQL_MONITOR SYS.V_$SQL SYS.V_$SQLAREA
SYS.V_$SQLAREA_PLAN_HASH SYS.V_$SQLSTATS SYS.V_$SQLSTATS_PLAN_HASH SYS.V_$SQLTEXT SYS.V_$SQLTEXT_WITH_NEWLINES
SYS.V_$SQL_BIND_CAPTURE SYS.V_$SQL_CS_STATISTICS SYS.V_$SQL_HISTORY SYS.V_$SQL_HISTORY_STATS
SYS.V_$SQL_LOCAL_LAST_EXEC SYS.V_$SQL_MONITOR SYS.V_$SQL_PLAN SYS.V_$SQL_PLAN_MONITOR
SYS.V_$SQL_PLAN_STATISTICS_ALL SYS.V_$SQL_REDIRECTION SYS.V_$SQL_SHARED_MEMORY SYS.V_$SQL_TESTCASES
SYS.V_$UNIFIED_AUDIT_TRAIL SYS.V_$XML_AUDIT_TRAIL SYS.WI$_STATEMENT SYS.WRH$_APP_SQLSTAT SYS.WRH$_APP_SQLSTAT_BL
SYS.WRH$_AWRAPP_SQLSTAT SYS.WRH$_AWRAPP_SQLSTAT_BL SYS.WRH$_SQLSTAT SYS.WRH$_SQLSTAT_BL SYS.WRH$_SQLTEXT
SYS.WRH$_SQLTEXT_BL SYS.WRH$_SQL_PLAN SYS.WRH$_SQL_PLAN_BL SYS.WRHS$_SQLTEXT SYS.WRHS$_SQL_PLAN
SYS.WRI$_ADV_AUTOMV_MV_CAND SYS.WRI$_ADV_AUTOMV_MV_SAMP SYS.WRI$_ADV_SQLT_PLANS SYS.WRI$_ADV_SQLW_STMTS
SYS.WRI$_SQLSET_PLANS SYS.WRI$_SQLSET_PLAN_LINES SYS.WRI$_SQLSET_WORKSPACE_PLANS SYS.WRI$_STS_SQLTEXT
SYS.WRR$_CAPTURE_LONG_SQLTEXT SYS.WRR$_CAPTURE_SQLTEXT SYS.WRR$_CAPTURE_SQL_TMP SYS.WRR$_REPLAY_IFSLA
SYS.WRR$_REPLAY_SQL_BINDS SYS.WRR$_REPLAY_SQL_MAP SYS.WRR$_REPLAY_SQL_TEXT SYS._DBA_STREAMS_STMTS
SYSTEM.MVIEW$_ADV_PRETTY SYSTEM.MVIEW$_ADV_WORKLOAD SYSTEM.OL$
""".split()
# Statement text in these is an object's definition, an upgrade or install
# script, the caller's own session (PLAN_TABLE$ is a global temporary table)
# or a hash, not another session's statement
_ORACLE_STATEMENT_DEFINITIONS = re.compile(
    r"sys\.(?:assert\$|assertstmt\$|bootstrap\$|exu9rls|jirefreshsql\$|plscope_sql\$|snap_refop\$|plan_table\$"
    r"|syncref\$_step_status|streams\$_stmt_handler_stmts|_?(?:cdb|dba)_(?:streams|xstream)_stmts"
    r"|(?:cdb|dba|user)_(?:tune_mview|mvref_stmt_stats)|mvref\$_stmt_stats|registry\$error"
    r"|(?:cdb|dba)_(?:registry_error|replay_upgrade_(?:errors|statements)|auto_index_(?:ind|sql)_actions)"
    r"|g?v_\$sql_(?:cs_statistics|history_stats))",
    re.IGNORECASE,
)


def _excused(engine: str, obj: str) -> str | None:
    rules = _HOLDS_NO_COLUMN_VALUES.get(engine, [])
    return next((why for pattern, why in rules if re.fullmatch(pattern, obj, re.IGNORECASE)), None)


@pytest.mark.parametrize(
    ("engine", "objects"),
    [
        ("oracle", _ORACLE_VALUE_OBJECTS),
        ("db2", _DB2_VALUE_OBJECTS),
        ("postgres", _POSTGRES_VALUE_OBJECTS),
        ("mysql", _MYSQL_VALUE_OBJECTS),
        ("clickhouse", _CLICKHOUSE_VALUE_OBJECTS),
        ("mssql", _MSSQL_VALUE_OBJECTS),
    ],
)
def test_every_catalog_object_that_carries_column_values_is_refused_or_its_values_are(
    engine: str, objects: list[str]
) -> None:
    wrong = []
    for obj in objects:
        schema, name = obj.split(".", 1)
        refused = is_session_sql_view(engine, schema, name) or bool(value_columns(engine, schema, name))
        if refused == bool(_excused(engine, obj)):
            wrong.append(obj)  # neither refused nor excused, or excused and refused as well
    assert wrong == [], wrong


def test_every_oracle_object_that_carries_other_sessions_statements_is_refused() -> None:
    assert len(_ORACLE_STATEMENT_OBJECTS) == 269
    wrong = []
    for obj in _ORACLE_STATEMENT_OBJECTS:
        refused = is_session_sql_view("oracle", *obj.split(".", 1))
        if refused == bool(_ORACLE_STATEMENT_DEFINITIONS.fullmatch(obj)):
            wrong.append(obj)
    assert wrong == [], wrong


def test_oracle_synonyms_of_column_values_never_reach_the_engine(tmp_path: Path, monkeypatch: Any) -> None:
    # live (review, 2026-09-28), mock_oracle under 'neither' with traveller_id masked: ALL_HISTOGRAMS
    # returned its endpoints 1, 2 and 3, COLS its low and high values
    server, fake = _server(tmp_path, monkeypatch, "oracle", [], deny=False)
    for sql, why in (
        ("SELECT column_name, endpoint_actual_value FROM ALL_HISTOGRAMS WHERE table_name = 'BOOKINGS'",
         "column statistics"),
        ("SELECT endpoint_actual_value FROM USER_HISTOGRAMS", "column statistics"),
        ("SELECT column_name, low_value, high_value FROM COLS WHERE table_name = 'BOOKINGS'", "low and high values"),
        ("SELECT sql_text FROM ALL_OUTLINES", "other sessions' SQL"),
    ):
        for tool, args in (
            ("db_query", {"connection_id": "remote", "sql": sql}),
            ("db_validate_query", {"connection_id": "remote", "sql": sql}),
            ("db_explain", {"connection_id": "remote", "sql": "EXPLAIN " + sql}),
        ):
            text = _call_error(server, tool, args)
            assert "POLICY_VIOLATION" in text and why in text, (tool, sql, text)
    for name in ("ALL_HISTOGRAMS", "COLS"):
        text = _call_error(server, "db_sample_table", {"connection_id": "remote", "object_name": name})
        assert "POLICY_VIOLATION" in text, text
    assert fake.statements == [] and fake.plans == []


# ---- 5. server and session variables --------------------------------------------------

_VARIABLES = [
    ("mysql", "SELECT @@datadir, @@hostname, @@secure_file_priv, @@version, @@version_compile_os"),
    ("mysql", "SELECT @@global.hostname AS h"),
    ("mysql", "SELECT @@session.sql_mode AS m"),
    ("mysql", "SELECT buoy_id FROM ocean.buoys WHERE @@version LIKE '8%'"),
    ("mssql", "SELECT @@VERSION AS v"),
    ("mssql", "SELECT @@SERVERNAME AS s"),
]


@pytest.mark.parametrize(("allowed", "deny"), _POLICIES)
@pytest.mark.parametrize(("engine", "sql"), _VARIABLES)
def test_server_variables_are_refused(engine: str, sql: str, allowed: list[str], deny: bool) -> None:
    guard = _guard(engine, allowed, OCEAN if deny else None, deny=deny)
    for label, validate, prefix in _entries(guard):
        exc = _refused(validate, prefix + sql)
        assert exc.category == ErrorCategory.POLICY, (label, str(exc))
        assert "@@" in str(exc), (label, str(exc))
        # the version is not the reason: db_test_connection reports it (review, 2026-09-28)
        assert "(version," not in str(exc) and "db_test_connection" in str(exc), (label, str(exc))


@pytest.mark.parametrize("engine", ["mysql", "clickhouse", "postgres"])
def test_the_server_version_stays_readable_on_purpose(engine: str) -> None:
    # sqlglot reads version() as CurrentVersion; db_test_connection hands the same text to any caller
    assert _guard(engine, ["ocean"], OCEAN).validate_select("SELECT version() AS v").kind == "select"


@pytest.mark.parametrize(("allowed", "deny"), _POLICIES)
@pytest.mark.parametrize(
    "sql",
    [
        "SELECT (@x := station) AS s FROM ocean.buoys",  # stores a value on the pooled session ...
        "SELECT @x := 1 AS one",
        "SELECT @x AS s",  # ... which a later statement read back past the masking of the first
        "SELECT station FROM ocean.buoys WHERE buoy_id = @id",
    ],
)
def test_mysql_user_variables_are_refused(sql: str, allowed: list[str], deny: bool) -> None:
    guard = _guard("mysql", allowed, OCEAN if deny else None, deny=deny)
    for label, validate, prefix in _entries(guard):
        exc = _refused(validate, prefix + sql)
        assert exc.category == ErrorCategory.POLICY, (label, str(exc))
        assert "user variables" in str(exc), (label, str(exc))


@pytest.mark.parametrize(
    ("engine", "sql"),
    [
        ("mssql", "SELECT buoy_id FROM ocean.buoys WHERE buoy_id IN (@a, @b)"),  # T-SQL parameters stay
        ("mysql", "SELECT buoy_id FROM ocean.buoys WHERE buoy_id IN %(p1)s"),
        ("mysql", "SELECT buoy_id FROM ocean.buoys WHERE buoy_id = :p"),
        ("mysql", "SELECT 'a@@b' AS s, `x@y` FROM ocean.buoys"),
    ],
)
def test_parameters_and_at_signs_in_literals_stay_readable(engine: str, sql: str) -> None:
    assert _guard(engine, ["ocean"], OCEAN).validate_select(sql).kind == "select"


# ---- 6. the column catalogs' value columns, review round 2 ---------------------------
# A bare name some CTE of the statement declares was skipped by the walk, and
# the server checks one no CTE in reach declares with a probe, SELECT 1 FROM
# <name>, which names none of the statement's columns: on Oracle a COLS or
# ALL_TAB_COLUMNS beside an inline view declaring a CTE of that name handed
# back a masked column's LOW_VALUE and HIGH_VALUE (live, mock_oracle, under
# 'neither' and under default-deny with SYS opened). A Db2 correlation column
# list renames HIGH2KEY and LOW2KEY by position, and the rule walked the whole
# statement once per reference (70 s for one 64 KiB statement).

_TRAVELLERS = "WHERE c.table_name = 'TRAVELLERS' AND c.column_name = 'TRAVELLER_ID'"
_CTE_NAMESAKES = [
    ("oracle", "sys", "SELECT c.column_name, c.low_value, c.high_value FROM (WITH cols AS (SELECT 1 AS n FROM dual) "
                      f"SELECT n FROM cols) x, cols c {_TRAVELLERS}"),
    ("oracle", "sys", "SELECT c.column_name, c.low_value, c.high_value FROM (WITH all_tab_columns AS (SELECT 1 AS n "
                      f"FROM dual) SELECT n FROM all_tab_columns) x, all_tab_columns c {_TRAVELLERS}"),
    ("oracle", "sys", "SELECT c.* FROM (WITH cols AS (SELECT 1 AS n FROM dual) SELECT n FROM cols) x, cols c"),
    ("oracle", "sys", "SELECT c.high_value FROM (WITH user_tab_columns AS (SELECT 1 AS n FROM dual) "
                      "SELECT n FROM user_tab_columns) x, user_tab_columns c"),
    ("oracle", "sys", "WITH cols AS (SELECT 1 AS n FROM dual) SELECT n FROM cols, (SELECT low_value FROM dual) v"),
    # Db2 binds the bare name to a schema the catalog places it in (_check_ref's candidates)
    ("db2", "syscat", "SELECT c.high2key FROM (WITH columns AS (SELECT 1 AS n FROM sysibm.sysdummy1) "
                      "SELECT n FROM columns) x, columns c"),
    ("db2", "syscat", "SELECT c.a FROM (WITH columns AS (SELECT 1 AS n FROM sysibm.sysdummy1) "
                      "SELECT n FROM columns) x, columns c (a, b)"),
]


@pytest.mark.parametrize(
    ("allowed", "deny"),
    [(["app"], True), (["app"], False), ([], True), ([], False)],
    ids=["allowlist-default-deny", "allowlist", "default-deny", "neither"],
)
@pytest.mark.parametrize(("engine", "schema", "sql"), _CTE_NAMESAKES)
def test_a_column_catalog_named_like_a_cte_keeps_its_value_columns_refused(
    engine: str, schema: str, sql: str, allowed: list[str], deny: bool
) -> None:
    guard = _opened(engine, schema, sql, allowed, deny)
    for label, validate, prefix in _entries(guard):
        exc = _refused(validate, prefix + sql)
        assert exc.category == ErrorCategory.POLICY, (label, str(exc))
        assert "low and high values" in str(exc) and "CTE" in str(exc), (label, str(exc))


@pytest.mark.parametrize(
    ("engine", "schema", "sql"),
    [
        ("oracle", "sys", f"SELECT c.column_name FROM (WITH cols AS (SELECT 1 AS n FROM dual) SELECT n FROM cols) x, "
                          f"cols c {_TRAVELLERS}"),
        ("oracle", "sys", "WITH cols AS (SELECT 1 AS n FROM dual) SELECT n FROM cols"),
        ("oracle", "sys", "WITH cols AS (SELECT 1 AS n FROM dual) SELECT COUNT(*) AS k FROM cols"),
        ("oracle", "sys", "WITH t AS (SELECT 1 AS n FROM dual) SELECT * FROM t"),  # no catalog named
        ("db2", "syscat", "WITH columns AS (SELECT 1 AS n FROM sysibm.sysdummy1) SELECT n FROM columns"),
    ],
)
@pytest.mark.parametrize("deny", [True, False], ids=["default-deny", "neither"])
def test_a_cte_named_like_a_column_catalog_stays_readable_without_its_value_columns(
    engine: str, schema: str, sql: str, deny: bool
) -> None:
    assert _opened(engine, schema, sql, [], deny).validate_select(sql).kind == "select"


@pytest.mark.parametrize(
    ("deny", "system_schemas", "tables"),
    [
        (False, None, [("TRAVEL", "TRAVELLERS")]),
        (True, ["information_schema", "sys"], [("TRAVEL", "TRAVELLERS"), ("SYS", "ALL_TAB_COLUMNS"), ("SYS", "COLS")]),
    ],
    ids=["neither", "default-deny-sys-opened"],
)
def test_the_server_path_refuses_a_column_catalog_named_like_an_out_of_scope_cte(
    deny: bool, system_schemas: list[str] | None, tables: list[tuple[str, str]]
) -> None:
    """Through _validate_in_scope, whose probe of an out-of-scope CTE name
    names none of the statement's columns (live: TRAVELLER_ID's raw low and
    high values, NUMBER 1 and 8, under both policies)."""
    from test_hardening_2026_09_28_final_guard_server import _listed_guard

    from universal_db_mcp.server import _validate_in_scope

    for view in ("cols", "all_tab_columns"):
        inline = f"(WITH {view} AS (SELECT 1 AS n FROM dual) SELECT n FROM {view}) x"
        for columns in ("c.column_name, c.low_value, c.high_value", "c.high_value", "c.*"):
            sql = f"SELECT {columns} FROM {inline}, {view} c {_TRAVELLERS}"
            guard = _listed_guard("oracle", [], tables, deny=deny, system_schemas=system_schemas)
            with pytest.raises(ToolFailure) as info:
                _validate_in_scope(guard, "oracle", lambda g, s=sql: g.validate_select(s))
            assert "low and high values" in str(info.value), (sql, str(info.value))
        sql = f"SELECT c.column_name FROM {inline}, {view} c {_TRAVELLERS}"
        guard = _listed_guard("oracle", [], tables, deny=deny, system_schemas=system_schemas)
        result = _validate_in_scope(guard, "oracle", lambda g, s=sql: g.validate_select(s))
        assert view in [t.name.lower() for t in result.tables], result.tables


def test_a_column_catalog_named_like_a_cte_never_reaches_the_engine(tmp_path: Path, monkeypatch: Any) -> None:
    server, fake = _server(tmp_path, monkeypatch, "oracle", [], deny=False)
    sql = (
        "SELECT c.column_name, c.low_value, c.high_value FROM (WITH cols AS (SELECT 1 AS n FROM dual) "
        f"SELECT n FROM cols) x, cols c {_TRAVELLERS}"
    )
    for tool, args in (
        ("db_query", {"connection_id": "remote", "sql": sql}),
        ("db_validate_query", {"connection_id": "remote", "sql": sql}),
        ("db_explain", {"connection_id": "remote", "sql": "EXPLAIN " + sql}),
    ):
        text = _call_error(server, tool, args)
        assert "POLICY_VIOLATION" in text and "low and high values" in text, (tool, text)
    assert fake.statements == [] and fake.plans == []


@pytest.mark.parametrize("deny", [True, False], ids=["default-deny", "neither"])
@pytest.mark.parametrize(
    "sql",
    [
        "SELECT high2key FROM columns",
        "SELECT c.low2key FROM columns c",
        "SELECT * FROM columns",
        "SELECT c.hk FROM columns c (s, t, n, hk)",
    ],
)
def test_a_bare_name_the_catalog_places_in_a_column_catalog_keeps_its_value_columns_refused(
    sql: str, deny: bool
) -> None:
    # the candidates _check_ref re-authorizes a bare name in, each with the statement's columns
    policy = _policy("db2", [], deny=deny, system_schemas=["syscat"])
    guard = SqlGuard("db2", policy, StaticResolver({("syscat", "columns"), ("app", "t")}))
    exc = _refused(guard.validate_select, sql)
    assert exc.category == ErrorCategory.POLICY and "low and high values" in str(exc), str(exc)
    assert guard.validate_select("SELECT colname, typename FROM columns").kind == "select"


_C58 = ", ".join(f"c{i}" for i in range(58))
_RENAMED = [
    ("db2", "syscat", "SELECT c.hk FROM syscat.columns c (s, t, n, hk)"),
    # live (review, round 2): Db2 ran it, c18 and c19 being HIGH2KEY and LOW2KEY
    ("db2", "syscat", f"SELECT c.c0, c.c1, c.c2, c.c18, c.c19 FROM syscat.columns AS c ({_C58}) WHERE c.c17 > 1 "
                      "FETCH FIRST 2 ROWS ONLY"),
    ("db2", "syscat", "SELECT x.k FROM SYSCAT.SYSCOLUMNS_UNION AS x (a, b, c, k) WITH UR"),
    ("db2", "sysibm", "SELECT x.k FROM SYSIBM.SYSCOLUMNS x (a, b, k)"),
    ("oracle", "sys", "SELECT c.a FROM SYS.ALL_TAB_COLUMNS c (a, b)"),  # Oracle rejects it; refused all the same
]


@pytest.mark.parametrize(
    ("allowed", "deny"),
    [(["app"], True), (["app"], False), ([], True), ([], False)],
    ids=["allowlist-default-deny", "allowlist", "default-deny", "neither"],
)
@pytest.mark.parametrize(("engine", "schema", "sql"), _RENAMED)
def test_a_column_list_after_a_column_catalog_alias_is_refused(
    engine: str, schema: str, sql: str, allowed: list[str], deny: bool
) -> None:
    guard = _opened(engine, schema, sql, allowed, deny)
    for label, validate, prefix in _entries(guard):
        exc = _refused(validate, prefix + sql)
        assert exc.category == ErrorCategory.POLICY, (label, str(exc))
        assert "low and high values" in str(exc) and "column list" in str(exc), (label, str(exc))


@pytest.mark.parametrize(
    ("engine", "schema", "sql"),
    [
        ("db2", "syscat", "SELECT t.a, t.b FROM SYSCAT.TABLES AS t (a, b)"),  # no value columns to rename
        ("db2", "app", "SELECT r.a FROM app.t AS r (a, b)"),
        ("postgres", "app", "SELECT r.a FROM app.t AS r (a, b)"),
    ],
)
def test_a_column_list_after_another_alias_stays_readable(engine: str, schema: str, sql: str) -> None:
    assert _opened(engine, schema, sql, ["app"], True).validate_select(sql).kind == "select"


@pytest.mark.parametrize(
    ("engine", "system_schemas", "unit", "sep"),
    [
        ("oracle", None, "cols c{i}", ", "),  # 'neither': a bare COLS is the PUBLIC synonym
        ("oracle", ["sys"], "SYS.ALL_TAB_COLUMNS c{i}", ", "),
        ("db2", ["syscat"], "SYSCAT.COLUMNS c{i}", ", "),
        ("db2", ["syscat"], "SELECT 1 AS n{i} FROM SYSCAT.COLUMNS", " UNION ALL "),
    ],
    ids=["oracle-bare", "oracle-qualified", "db2-join", "db2-union"],
)
def test_the_value_columns_rule_reads_each_statement_once(
    monkeypatch: Any, engine: str, system_schemas: list[str] | None, unit: str, sep: str
) -> None:
    """Thousands of references to a column catalog: the statement's names are
    read once, not once per reference (70 s for 5500 COLS before)."""
    import time

    import sqlglot
    from sqlglot import exp

    import universal_db_mcp.security.sql_guard as sql_guard

    head = "" if unit.startswith("SELECT") else "SELECT 1 AS one FROM "
    parts: list[str] = []
    while len(head) + len(sep.join([*parts, unit.format(i=len(parts))])) <= sql_guard._MAX_SQL_BYTES:
        parts.append(unit.format(i=len(parts)))
    sql = head + sep.join(parts)
    assert len(parts) > 1000, len(parts)
    parsed = sqlglot.parse_one(sql, read=sql_guard.sqlglot_dialect(engine))
    identifiers = sum(1 for _ in parsed.find_all(exp.Identifier))
    calls = 0
    folded = sql_guard.loose_name

    def counted(name: str) -> str:
        nonlocal calls
        calls += 1
        assert calls <= identifiers, "the statement's names were read again for another reference"
        return folded(name)

    monkeypatch.setattr(sql_guard, "loose_name", counted)
    deny = system_schemas is not None
    policy = _policy(engine, [], deny=deny, system_schemas=system_schemas)
    schema = (system_schemas or ["sys"])[0]
    guard = SqlGuard(engine, policy, StaticResolver({(schema, "all_tab_columns"), (schema, "columns")}))
    started = time.perf_counter()
    assert guard.validate_select(sql).kind == "select"
    elapsed = time.perf_counter() - started
    assert elapsed < 2.0, f"{elapsed:.2f}s for {len(parts)} references"


def test_oracle_column_catalog_namesakes_elsewhere_are_ordinary_tables() -> None:
    # review, round 2: TRAVEL.COLS was refused and hidden for the PUBLIC synonym's sake
    for schema, name in (("travel", "cols"), ("app", "all_tab_columns"), ("app", "user_tab_cols")):
        assert value_columns("oracle", schema, name) == frozenset(), (schema, name)
        _policy("oracle", [schema]).check_object(schema, name)
    guard = _guard("oracle", ["travel"], {("travel", "cols"), ("travel", "user_histograms")})
    for sql in (
        "SELECT * FROM travel.cols",
        "SELECT low_value FROM travel.cols",
        "SELECT * FROM travel.user_histograms",
    ):
        assert guard.validate_select(sql).kind == "select", sql


@pytest.mark.parametrize(
    ("schema", "name"),
    [(None, "COLS"), ("SYS", "ALL_TAB_COLUMNS"), ("sys", "user_tab_cols"), ("PUBLIC", "COLS"),
     ("PUBLIC", "ALL_TAB_COLS")],
)
def test_oracle_column_catalogs_are_matched_bare_under_sys_and_under_public(schema: str | None, name: str) -> None:
    # live (review, round 2): Oracle reads "PUBLIC".COLS as the PUBLIC synonym (PUBLIC.COLS is ORA-00903)
    assert value_columns("oracle", schema, name) == frozenset({"low_value", "high_value"})


@pytest.mark.parametrize(
    ("schema", "name"),
    [(None, "ALL_HISTOGRAMS"), ("PUBLIC", "USER_HISTOGRAMS"), ("SYS", "DBA_COMPARISON"),
     ("public", "all_tab_histograms"), ("SYS", "HISTGRM$"), (None, "user_comparison_row_dif")],
)
def test_oracle_column_statistics_are_matched_bare_under_sys_and_under_public(schema: str | None, name: str) -> None:
    assert is_column_statistics_view("oracle", schema, name) and is_session_sql_view("oracle", schema, name)


# Checks that stand behind an earlier, lexical one: each is pinned on its own
# (review, round 2: removing any of them failed no test).


@pytest.mark.parametrize("engine", [*REMOTE, "sqlite"])
def test_an_in_with_nothing_after_it_is_refused_by_the_walk_as_well(monkeypatch: Any, engine: str) -> None:
    from sqlglot import exp

    import universal_db_mcp.security.sql_guard as sql_guard

    guard = _guard(engine, [], None, deny=False)
    with pytest.raises(ToolFailure) as info:
        guard._check_in(exp.In(this=exp.column("x")))
    assert "IN with nothing after it" in str(info.value)
    monkeypatch.setattr(sql_guard, "_deny_in_after_in", lambda tokens: None)
    for sql in ("SELECT 1 IN in(0, 1) AS hit", "SELECT 1 NOT IN in(0, 1) AS hit", "SELECT 1 IN IN (0, 1) AS hit"):
        assert "IN with nothing after it" in str(_refused(guard.validate_select, sql)), (engine, sql)


@pytest.mark.parametrize(("allowed", "deny"), _POLICIES)
def test_an_oracle_at_parameter_is_refused_by_the_walk_as_well(
    monkeypatch: Any, allowed: list[str], deny: bool
) -> None:
    import universal_db_mcp.security.sql_guard as sql_guard

    monkeypatch.setattr(sql_guard, "_deny_oracle_database_links", lambda sql, tokens: None)
    guard = _guard("oracle", allowed, OCEAN if deny else None, deny=deny)
    for sql in ('SELECT 1 FROM "DUAL"@lnk', 'SELECT 1 FROM "DUAL" @lnk', "SELECT @x AS v FROM dual",
                "SELECT 1 AS one FROM dual WHERE 1 = @x"):
        exc = _refused(guard.validate_select, sql)
        assert "database links" in str(exc) and "Oracle reads '@' as a link" in str(exc), (sql, str(exc))


@pytest.mark.parametrize(("allowed", "deny"), _POLICIES)
@pytest.mark.parametrize(
    "sql",
    [
        "SELECT 0 IN (a.b.c.d.e) AS hit",
        "SELECT 0 IN (system.one.dummy.x.y) AS hit",
        "SELECT 0 IN ((system).one) AS hit",
    ],
)
def test_clickhouse_a_single_dotted_name_after_in_is_refused(sql: str, allowed: list[str], deny: bool) -> None:
    # sqlglot parses a name of five parts, or a parenthesized one's member, as a Dot, not a Column
    exc = _refused(_ch(allowed, deny).validate_select, sql)
    assert "IN (<name>) with a single name" in str(exc), str(exc)
