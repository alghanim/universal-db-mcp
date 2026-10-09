"""Owner decision 2026-09-27: under a schema allowlist a statement names the
schema of every table it reads.

The resolver approved the bare name 'buoys' because ocean.buoys is allowed,
while PostgreSQL's search_path bound the same text to public.buoys: the
engine, not the policy, chose the schema. So when a connection's
allowed_schemas is non-empty, every table reference in db_query,
db_validate_query, db_explain, db_federated_query and db_federated_join must
be schema-qualified (for MySQL and ClickHouse the schema is the database);
an unqualified one is refused with the allowed schemas and the spelling to
use. CTE names, derived-table and table aliases, columns, table functions
(refused by their own rule), SQLite and connections without an allowlist are
unaffected, and every statement the server builds itself (sample, profile,
top values, value search) already names its schema, so it keeps working.
"""

from __future__ import annotations

import asyncio
import json
import re
import sqlite3
from pathlib import Path
from typing import Any

import pytest
import sqlglot
from sqlglot import exp

from universal_db_mcp.config import ConnectionConfig, SecurityConfig, load_resolved
from universal_db_mcp.connectors import registry
from universal_db_mcp.connectors.base import ColumnInfo, NameBinding, QueryOutcome, TableSummary
from universal_db_mcp.errors import ToolFailure
from universal_db_mcp.models.responses import ErrorCategory
from universal_db_mcp.security.policy import EffectivePolicy
from universal_db_mcp.security.sql_guard import SqlGuard, StaticResolver, sqlglot_dialect
from universal_db_mcp.server import AppContext, build_server

REMOTE = ["postgres", "mysql", "oracle", "mssql", "db2", "clickhouse"]
OCEAN = {("ocean", "buoys"), ("ocean", "readings")}


def _policy(
    engine: str, allowed: list[str], *, deny: bool = True, system_schemas: list[str] | None = None
) -> EffectivePolicy:
    body: dict[str, Any] = {"type": engine, "database": "d", "username_env": "U", "allowed_schemas": allowed}
    if engine != "sqlite":
        body["host"] = "h"
    cfg = ConnectionConfig.model_validate(body)
    security = SecurityConfig(default_deny_objects=deny)
    if system_schemas is not None:
        security = SecurityConfig(default_deny_objects=deny, allowed_system_schemas=system_schemas)
    return EffectivePolicy.build(security, type("R", (), {"config": cfg, "name": "c"})())


def _guard(
    engine: str, allowed: list[str], objects: set[tuple[str | None, str]] | None = OCEAN, *, deny: bool = True
) -> SqlGuard:
    return SqlGuard(engine, _policy(engine, allowed, deny=deny), None if objects is None else StaticResolver(objects))


def _refused(fn: Any, sql: str) -> ToolFailure:
    with pytest.raises(ToolFailure) as info:
        fn(sql)
    return info.value


def _entries(guard: SqlGuard) -> list[tuple[str, Any, str]]:
    """Every guard entry the query tools use: db_query and the federated
    tools (validate_select), db_explain (validate_explain) and
    db_validate_query (validate_any, both operations)."""
    return [
        ("select", guard.validate_select, ""),
        ("explain", guard.validate_explain, "EXPLAIN "),
        ("validate", guard.validate_any, ""),
        ("validate-explain", lambda s: guard.validate_any(s, "explain"), "EXPLAIN "),
    ]


# ---- the guard ---------------------------------------------------------------


@pytest.mark.parametrize("deny", [True, False], ids=["default-deny", "no-default-deny"])
@pytest.mark.parametrize("engine", REMOTE)
def test_a_bare_name_is_refused_even_when_an_allowed_schema_holds_it(engine: str, deny: bool) -> None:
    # the shadowing case: ocean.buoys is permitted, the engine binds 'buoys' itself
    guard = _guard(engine, ["ocean"], deny=deny)
    for label, validate, prefix in _entries(guard):
        exc = _refused(validate, prefix + "SELECT buoy_id FROM buoys")
        assert exc.category == ErrorCategory.AUTHZ, (label, str(exc))
        text = str(exc)
        assert "unqualified table 'buoys'" in text and "[ocean]" in text, (label, text)
        assert text.endswith("write ocean.buoys"), (label, text)


@pytest.mark.parametrize("engine", REMOTE)
@pytest.mark.parametrize(
    "sql",
    [
        "SELECT buoy_id FROM ocean.buoys",
        "SELECT b.buoy_id FROM ocean.buoys b JOIN ocean.readings r ON r.buoy_id = b.buoy_id",
        # an alias spelled like a table, and a column qualified by the table's own name
        "SELECT readings.buoy_id FROM ocean.buoys readings",
        "SELECT buoys.buoy_id FROM ocean.buoys",
        "SELECT d.x FROM (SELECT buoy_id AS x FROM ocean.buoys) d",
        "WITH recent AS (SELECT buoy_id FROM ocean.readings) SELECT buoy_id FROM recent",
        "WITH a AS (SELECT buoy_id FROM ocean.buoys), b AS (SELECT buoy_id FROM a) "
        "SELECT a.buoy_id FROM a JOIN b ON a.buoy_id = b.buoy_id",
        "SELECT buoy_id FROM ocean.buoys WHERE buoy_id IN (SELECT buoy_id FROM ocean.readings)",
        "SELECT buoy_id FROM ocean.buoys UNION ALL SELECT buoy_id FROM ocean.readings",
        "SELECT (SELECT COUNT(*) FROM ocean.readings) AS n FROM ocean.buoys",
        "SELECT 1 AS one",
    ],
)
def test_qualified_tables_ctes_aliases_and_columns_are_not_refused(engine: str, sql: str) -> None:
    guard = _guard(engine, ["ocean"])
    for label, validate, prefix in _entries(guard):
        assert validate(prefix + sql).kind in ("select", "explain"), label


@pytest.mark.parametrize("engine", REMOTE)
@pytest.mark.parametrize(
    "sql",
    [
        "SELECT b.buoy_id FROM ocean.buoys b JOIN readings r ON r.buoy_id = b.buoy_id",
        "SELECT buoy_id FROM ocean.buoys WHERE buoy_id IN (SELECT buoy_id FROM readings)",
        "SELECT buoy_id FROM ocean.buoys b WHERE EXISTS (SELECT 1 FROM readings r WHERE r.buoy_id = b.buoy_id)",
        "SELECT d.x FROM (SELECT buoy_id AS x FROM readings) d",
        "WITH recent AS (SELECT buoy_id FROM readings) SELECT buoy_id FROM recent",
        "SELECT buoy_id FROM ocean.buoys UNION ALL SELECT buoy_id FROM readings",
        "SELECT (SELECT COUNT(*) FROM readings) AS n FROM ocean.buoys",
    ],
)
def test_a_bare_name_anywhere_in_the_statement_is_refused(engine: str, sql: str) -> None:
    guard = _guard(engine, ["ocean"])
    for label, validate, prefix in _entries(guard):
        exc = _refused(validate, prefix + sql)
        assert exc.category == ErrorCategory.AUTHZ, (label, str(exc))
        assert "unqualified table 'readings'" in str(exc) and str(exc).endswith("write ocean.readings"), label


@pytest.mark.parametrize("engine", REMOTE)
def test_without_an_allowlist_bare_names_resolve_as_before(engine: str) -> None:
    # default-deny: the resolver decides; neither: the engine does, as before
    assert _guard(engine, [], {("ocean", "buoys")}).validate_select("SELECT * FROM buoys").kind == "select"
    assert _guard(engine, [], None, deny=False).validate_select("SELECT * FROM buoys").kind == "select"
    exc = _refused(_guard(engine, [], {("ocean", "buoys")}).validate_select, "SELECT * FROM salaries")
    assert "could not be resolved" in str(exc)


@pytest.mark.parametrize("deny", [True, False], ids=["default-deny", "no-default-deny"])
@pytest.mark.parametrize("allowed", [[], ["main"]], ids=["no-allowlist", "main"])
def test_sqlite_keeps_bare_names(allowed: list[str], deny: bool) -> None:
    # 'main' is SQLite's one schema: a bare name cannot bind anywhere else
    guard = _guard("sqlite", allowed, {("main", "customers")}, deny=deny)
    for sql in ("SELECT * FROM customers", "SELECT * FROM main.customers"):
        for label, validate, prefix in _entries(guard):
            assert validate(prefix + sql).kind in ("select", "explain"), (label, sql)


@pytest.mark.parametrize(
    ("engine", "sql"),
    [
        ("postgres", "SELECT * FROM generate_series(1, 2)"),
        ("clickhouse", "SELECT * FROM numbers(2)"),
        ("mssql", "SELECT * FROM STRING_SPLIT('a,b', ',')"),
        ("oracle", "SELECT * FROM TABLE(sys.odcinumberlist(1, 2))"),
    ],
)
def test_table_functions_keep_their_own_refusal(engine: str, sql: str) -> None:
    exc = _refused(_guard(engine, ["ocean"]).validate_select, sql)
    assert exc.category == ErrorCategory.POLICY and "table functions" in str(exc)


def test_the_refusal_names_the_allowed_schemas_and_where_the_table_is() -> None:
    objects = {("ocean", "buoys"), ("archive", "buoys"), ("reporting", "kpis"), ("hr", "salaries")}
    guard = _guard("postgres", ["ocean", "archive", "reporting"], objects)
    prefix = "unqualified table '{}' is not permitted: connection 'c' allows only schemas [archive, ocean, reporting]"
    # two allowed schemas hold it: both spellings, the caller picks
    text = str(_refused(guard.validate_select, "SELECT * FROM buoys"))
    assert text.startswith("AUTHORIZATION_DENIED: " + prefix.format("buoys"))
    assert text.endswith("write archive.buoys or ocean.buoys")
    # one does: that one
    assert str(_refused(guard.validate_select, "SELECT * FROM kpis")).endswith("write reporting.kpis")
    # only a schema the allowlist leaves out does (or none, pg_roles): any allowed schema
    for name in ("salaries", "pg_roles"):
        text = str(_refused(guard.validate_select, f"SELECT * FROM {name}"))
        assert text.startswith("AUTHORIZATION_DENIED: " + prefix.format(name))
        assert text.endswith(f"qualify it with an allowed schema, for example archive.{name}"), text


@pytest.mark.parametrize(
    ("engine", "sql", "spelling"),
    [
        ("postgres", 'SELECT * FROM "Buoys"', 'ocean."Buoys"'),
        ("mssql", "SELECT * FROM [Buoys]", "ocean.[Buoys]"),
        ("mysql", "SELECT * FROM `Buoys`", "ocean.`Buoys`"),
        ("oracle", "SELECT * FROM BUOYS", "ocean.BUOYS"),
    ],
)
def test_the_suggested_spelling_keeps_the_quoting_as_written(engine: str, sql: str, spelling: str) -> None:
    guard = _guard(engine, ["OCEAN"], {("ocean", "Buoys")})
    assert str(_refused(guard.validate_select, sql)).endswith(f"write {spelling}")


def test_a_system_schema_the_administrator_opened_is_offered_too() -> None:
    policy = _policy("mysql", ["testdb"], system_schemas=["information_schema"])
    guard = SqlGuard("mysql", policy, StaticResolver({("information_schema", "tables"), ("testdb", "cuppings")}))
    assert str(_refused(guard.validate_select, "SELECT * FROM tables")).endswith("write information_schema.tables")
    assert guard.validate_select("SELECT * FROM information_schema.tables").kind == "select"


# ---- the tools (a recording remote connector, no database) ------------------

_TEXT = {"postgres": "text", "mysql": "varchar", "oracle": "VARCHAR2", "mssql": "nvarchar", "db2": "VARCHAR",
         "clickhouse": "String"}
_INT = {"postgres": "integer", "mysql": "int", "oracle": "NUMBER", "mssql": "int", "db2": "INTEGER",
        "clickhouse": "Int32"}
# how each engine's catalog spells the schema (Oracle and Db2 store an
# unquoted name in upper case, and look it up so)
_OCEAN = {"postgres": "ocean", "mysql": "ocean", "oracle": "OCEAN", "mssql": "ocean", "db2": "OCEAN",
          "clickhouse": "ocean"}
# engines whose connector says how a session binds a bare name (name_binding)
_ASKED_ENGINES = frozenset({"postgres", "oracle", "mssql", "db2"})
# each engine's driver placeholder in the statements the server builds
_PLACEHOLDER = re.compile(r"%\(\w+\)s|%s|:\d+|\?")


def _recording(engine: str, app: AppContext, catalog: list[TableSummary] | None = None) -> Any:
    """The engine's real connector (its own SQL builders) with the catalog
    and the driver replaced: every statement it is handed is recorded and
    answered with one row, the schema each listing is asked for as well,
    and nothing connects."""
    ocean = _OCEAN[engine]
    spelled = str.upper if engine in ("oracle", "db2") else str
    tables = catalog or [
        TableSummary(ocean, spelled("buoys"), "table"), TableSummary(ocean, spelled("readings"), "table")
    ]
    columns = [
        ColumnInfo(t.schema, t.name, c, typ)
        for t in tables
        for c, typ in (("buoy_id", _INT[engine]), ("station", _TEXT[engine]))
    ]

    class Recording(registry.connector_class(engine)):  # type: ignore[misc]
        statements: list[str]
        plans: list[str]
        listed: list[str | None]
        binding: NameBinding | None
        binding_asked: int

        def name_binding(self) -> NameBinding | None:
            self.binding_asked += 1
            return self.binding

        def synonym_chains(self, _names: list[tuple[str | None, str]]) -> dict[Any, list[Any]]:
            return {}  # no synonyms (a test sets its own)

        def list_tables(self, _schema: str | None, kinds: set[str], _search: str | None) -> list[TableSummary]:
            return [t for t in tables if t.kind in kinds]

        def list_schemas(self, _catalog: str | None, _search: str | None) -> list[str]:
            return sorted({t.schema for t in tables if t.schema})

        def list_views(self, schema: str | None) -> list[Any]:
            self.listed.append(schema)
            return []

        def list_routines(self, schema: str | None) -> list[Any]:
            self.listed.append(schema)
            return []

        def list_columns(self, schema: str | None, table: str) -> list[ColumnInfo]:
            return [c for c in columns if c.table == table and (schema is None or c.schema == schema)]

        def list_all_columns(self, schema: str | None) -> list[ColumnInfo]:
            return [c for c in columns if schema is None or c.schema == schema]

        def list_indexes(self, _schema: str | None, _table: str | None) -> list[Any]:
            return []

        def get_foreign_keys(self, _schema: str | None, _table: str | None) -> list[Any]:
            return []

        def get_statistics(self, _schema: str | None, _table: str) -> dict[str, Any]:
            return {"row_estimate": None}

        def execute_query(self, spec: Any) -> QueryOutcome:
            self.statements.append(spec.sql)
            parsed = sqlglot.parse_one(_PLACEHOLDER.sub("'x'", spec.sql), read=sqlglot_dialect(engine))
            names = [s.alias_or_name for s in parsed.selects]
            if names == ["*"]:
                names = [c.name for c in columns if c.table.lower() == next(parsed.find_all(exp.Table)).name.lower()]
            return QueryOutcome(columns=[(n, "text") for n in names], rows=[[2] * len(names)], truncated=False,
                                rows_seen=1, elapsed_ms=0)

        def explain(self, sql: str, analyze: bool) -> dict[str, Any]:
            self.plans.append(sql)
            return {"format": "text", "plan": ["recorded"]}

    fake = Recording(app.resolved["remote"], app._policy_for("remote"))
    fake.statements, fake.plans, fake.listed = [], [], []
    # the session's first schema for a bare name, as the engines that are asked answer (the others bind one
    # only in the connection's database)
    fake.binding = NameBinding((ocean,), ignores_case=engine == "mssql") if engine in _ASKED_ENGINES else None
    fake.binding_asked = 0
    return fake


def _server(
    tmp_path: Path,
    monkeypatch: Any,
    engine: str,
    allowed: list[str],
    *,
    deny: bool = True,
    second: bool = False,
    catalog: list[TableSummary] | None = None,
) -> tuple[Any, Any]:
    monkeypatch.setenv("UDBMCP_T_USER", "tester")
    conn = (
        f"    type: {engine}\n    host: 127.0.0.1\n    port: 5999\n    database: testdb\n"
        f"    username_env: UDBMCP_T_USER\n    allowed_schemas: {json.dumps(allowed)}\n"
    )
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "application:\n  transport: stdio\n"
        f"  audit_path: {tmp_path / 'audit.jsonl'}\n"
        f"  metadata_cache_path: {tmp_path / 'cache.sqlite'}\n"
        f"security:\n  require_remote_tls: false\n  default_deny_objects: {str(deny).lower()}\n"
        f"connections:\n  remote:\n{conn}" + (f"  other:\n{conn}" if second else ""),
        encoding="utf-8",
    )
    app_cfg, resolved = load_resolved(cfg)
    app = AppContext(app_cfg, resolved)
    fake = _recording(engine, app, catalog)
    app.connectors["remote"] = fake
    if second:
        app.connectors["other"] = fake
    return build_server(app), fake


def _call(server: Any, name: str, args: dict[str, Any]) -> dict[str, Any]:
    result = asyncio.run(server.call_tool(name, args))
    assert result.structured_content is not None
    return result.structured_content


def _call_error(server: Any, name: str, args: dict[str, Any]) -> str:
    with pytest.raises(Exception) as info:  # noqa: PT011 - the ToolError text is what is asserted
        _call(server, name, args)
    return str(info.value)


_BARE = "SELECT buoy_id FROM buoys"
_QUALIFIED = "SELECT buoy_id FROM ocean.buoys"


@pytest.mark.parametrize("deny", [True, False], ids=["default-deny", "no-default-deny"])
@pytest.mark.parametrize("engine", REMOTE)
def test_query_tools_refuse_a_bare_name_before_the_engine_sees_it(
    tmp_path: Path, monkeypatch: Any, engine: str, deny: bool
) -> None:
    server, fake = _server(tmp_path, monkeypatch, engine, ["ocean"], deny=deny, second=True)
    calls = [
        ("db_query", {"connection_id": "remote", "sql": _BARE}),
        ("db_validate_query", {"connection_id": "remote", "sql": _BARE}),
        ("db_validate_query", {"connection_id": "remote", "sql": "EXPLAIN " + _BARE, "operation": "explain"}),
        ("db_explain", {"connection_id": "remote", "sql": "EXPLAIN " + _BARE}),
        ("db_federated_join", {"left": {"connection": "remote", "sql": _QUALIFIED},
                               "right": {"connection": "other", "sql": _BARE}, "on": [["buoy_id", "buoy_id"]]}),
    ]
    for tool, args in calls:
        text = _call_error(server, tool, args)
        assert "AUTHORIZATION_DENIED" in text and "unqualified table 'buoys'" in text, (tool, text)
        assert f"write {_OCEAN[engine]}.buoys" in text, (tool, text)
    # one failing connection is a warning in the federated query; neither runs a bare name
    env = _call(server, "db_federated_query", {"sql": _BARE, "connections": ["remote", "other"]})
    assert env["data"]["connections_run"] == 0
    assert all("unqualified table 'buoys'" in r["error"] for r in env["data"]["results"])
    assert not [s for s in fake.statements + fake.plans if "buoys" in s and "ocean" not in s.lower()]


@pytest.mark.parametrize("engine", REMOTE)
def test_query_tools_run_qualified_statements(tmp_path: Path, monkeypatch: Any, engine: str) -> None:
    server, fake = _server(tmp_path, monkeypatch, engine, ["ocean"], second=True)
    assert _call(server, "db_query", {"connection_id": "remote", "sql": _QUALIFIED})["data"]["rows"] == [[2]]
    valid = _call(server, "db_validate_query", {"connection_id": "remote", "sql": _QUALIFIED})["data"]
    assert valid["valid"] and valid["referenced_objects"] == [{"schema": "ocean", "name": "buoys", "catalog": None}]
    _call(server, "db_explain", {"connection_id": "remote", "sql": "EXPLAIN " + _QUALIFIED})
    assert fake.plans == [_QUALIFIED]
    env = _call(server, "db_federated_query", {"sql": _QUALIFIED, "connections": ["remote", "other"]})
    assert env["data"]["connections_run"] == 2
    joined = _call(server, "db_federated_join", {"left": {"connection": "remote", "sql": _QUALIFIED},
                                                 "right": {"connection": "other", "sql": _QUALIFIED},
                                                 "on": [["buoy_id", "buoy_id"]]})
    assert joined["data"]["rows"] == [[2, 2]]


def test_a_cte_out_of_reach_does_not_cover_a_bare_name(tmp_path: Path, monkeypatch: Any) -> None:
    server, _ = _server(tmp_path, monkeypatch, "postgres", ["ocean"])
    # the CTE inside EXISTS is not in reach of the outer FROM, which reads a table
    sql = "SELECT buoy_id FROM buoys WHERE EXISTS (WITH buoys AS (SELECT 1 AS buoy_id) SELECT 1 FROM buoys)"
    text = _call_error(server, "db_validate_query", {"connection_id": "remote", "sql": sql})
    assert "unqualified table 'buoys'" in text and "does not cover this reference" in text, text


@pytest.mark.parametrize("engine", REMOTE)
def test_without_an_allowlist_the_query_tools_take_bare_names_as_before(
    tmp_path: Path, monkeypatch: Any, engine: str
) -> None:
    server, fake = _server(tmp_path, monkeypatch, engine, [])
    assert _call(server, "db_query", {"connection_id": "remote", "sql": _BARE})["data"]["rows"] == [[2]]
    assert fake.statements == [_BARE]


def test_sqlite_with_an_allowlist_keeps_bare_names(tmp_path: Path) -> None:
    db = tmp_path / "shop.db"
    with sqlite3.connect(db) as c:
        c.execute("CREATE TABLE customers (customer_id INTEGER PRIMARY KEY, city TEXT)")
        c.execute("INSERT INTO customers VALUES (1, 'Lisbon')")
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "application:\n  transport: stdio\n"
        f"  audit_path: {tmp_path / 'audit.jsonl'}\n"
        f"  metadata_cache_path: {tmp_path / 'cache.sqlite'}\n"
        f"connections:\n  shop:\n    type: sqlite\n    database: {db}\n    allowed_schemas: [main]\n",
        encoding="utf-8",
    )
    app_cfg, resolved = load_resolved(cfg)
    server = build_server(AppContext(app_cfg, resolved))
    for sql in ("SELECT city FROM customers", "SELECT city FROM main.customers"):
        assert _call(server, "db_query", {"connection_id": "shop", "sql": sql})["data"]["rows"] == [["Lisbon"]]
    assert _call(server, "db_explain", {"connection_id": "shop", "sql": "EXPLAIN SELECT city FROM customers"})


def _tables_named(engine: str, sql: str) -> list[tuple[str, str]]:
    parsed = sqlglot.parse_one(_PLACEHOLDER.sub("'x'", sql), read=sqlglot_dialect(engine))
    return [(t.db, t.name) for t in parsed.find_all(exp.Table)]


@pytest.mark.parametrize("deny", [True, False], ids=["default-deny", "no-default-deny"])
@pytest.mark.parametrize("engine", REMOTE)
def test_statements_the_server_builds_name_the_allowed_schema(
    tmp_path: Path, monkeypatch: Any, engine: str, deny: bool
) -> None:
    """Sample, profile (with top values) and value search, reached with a bare
    and a qualified name: every table each statement reads is ocean's, so
    the engine never picks the schema and the guard's rule holds for them."""
    server, fake = _server(tmp_path, monkeypatch, engine, ["ocean"], deny=deny)
    for name in ("buoys", "ocean.buoys"):
        _call(server, "db_sample_table", {"connection_id": "remote", "object_name": name})
        _call(server, "db_profile_table", {"connection_id": "remote", "object_name": name})
    _call(server, "db_search_values", {"query": "north"})
    kinds = {"sample": 0, "top values": 0, "search": 0}
    for sql in fake.statements:
        named = _tables_named(engine, sql)
        assert named and all(schema.lower() == "ocean" for schema, _ in named), (sql, named)
        kinds["top values" if " cnt" in sql else "search" if "LIKE" in sql.upper() else "sample"] += 1
    assert all(kinds.values()), kinds
    policy = _policy(engine, ["ocean"], deny=deny)
    for sql in fake.statements:
        for schema, table in _tables_named(engine, sql):
            policy.check_object(schema, table)


# ---- a table named after IN (review of this decision, 2026-09-28) -------------
#
# ClickHouse reads `x IN t`, `x IN db.t` and `x IN (db.t)` as
# `x IN (SELECT * FROM db.t)`, and SQLite reads `x IN t` the same way, but
# sqlglot parses the name as a column, so no table check saw it: under
# allowed_schemas [default] `SELECT (...) IN telecom.subscribers` answered
# 1 or 0 for a guessed row (live, loopback fixture). A ClickHouse server-side
# {name:Identifier} parameter names a table the same way, after validation.

_CH_POLICIES = [
    pytest.param(["ocean"], True, id="allowlist-default-deny"),
    pytest.param(["ocean"], False, id="allowlist"),
    pytest.param([], True, id="default-deny"),
    pytest.param([], False, id="neither"),
]


@pytest.mark.parametrize(("allowed", "deny"), _CH_POLICIES)
@pytest.mark.parametrize(
    "sql",
    [
        "SELECT 1 IN salaries",
        "SELECT 1 IN hr.salaries",
        "SELECT (1, 'a') IN hr.salaries AS leaked",
        "SELECT buoy_id FROM ocean.buoys WHERE buoy_id GLOBAL NOT IN hr.salaries",
        "SELECT buoy_id FROM ocean.buoys WHERE buoy_id NOT IN `hr`.`salaries`",
        "SELECT 1 IN (hr.salaries)",
        "SELECT 1 IN (salaries)",
        "SELECT 1 IN ((hr.salaries))",
        "SELECT buoy_id FROM ocean.buoys WHERE buoy_id GLOBAL IN (hr.salaries)",
        "SELECT CASE WHEN 1 IN hr.salaries THEN 1 END",
    ],
)
def test_clickhouse_refuses_a_table_named_after_in(allowed: list[str], deny: bool, sql: str) -> None:
    guard = _guard("clickhouse", allowed, OCEAN if deny else None, deny=deny)
    for label, validate, prefix in _entries(guard):
        exc = _refused(validate, prefix + sql)
        assert exc.category == ErrorCategory.POLICY, (label, str(exc))
        assert "IN (SELECT <column> FROM <schema>.<table>)" in str(exc), (label, str(exc))


@pytest.mark.parametrize(("allowed", "deny"), _CH_POLICIES)
@pytest.mark.parametrize(
    "sql",
    [
        "SELECT 1 IN {t:Identifier}",
        "SELECT 1 IN ({t:Identifier})",
        "SELECT 1 IN {d:Identifier}.{t:Identifier}",
        "SELECT * FROM {d:Identifier}.buoys",
        "SELECT {c:Identifier} AS x FROM ocean.buoys",
        "SELECT b.{c: identifier} FROM ocean.buoys b",
    ],
)
def test_clickhouse_refuses_identifier_parameters(allowed: list[str], deny: bool, sql: str) -> None:
    guard = _guard("clickhouse", allowed, OCEAN if deny else None, deny=deny)
    for label, validate, prefix in _entries(guard):
        exc = _refused(validate, prefix + sql)
        assert exc.category == ErrorCategory.POLICY, (label, str(exc))
        assert "{name:Identifier}" in str(exc), (label, str(exc))


@pytest.mark.parametrize(("allowed", "deny"), _CH_POLICIES)
@pytest.mark.parametrize(
    "sql",
    [
        "SELECT 1 IN (1, 2)",
        "SELECT 1 IN [1, 2]",
        "SELECT (1, 2) IN ((1, 2), (3, 4))",
        "SELECT buoy_id IN (1, 2) FROM ocean.buoys",
        "SELECT buoy_id FROM ocean.buoys WHERE buoy_id IN (SELECT buoy_id FROM ocean.readings)",
        "SELECT buoy_id FROM ocean.buoys WHERE buoy_id GLOBAL IN (SELECT buoy_id FROM ocean.readings)",
        "SELECT buoy_id FROM ocean.buoys WHERE 1 IN (buoy_id, 2)",
        "SELECT buoy_id FROM ocean.buoys WHERE buoy_id = {v:UInt32}",
        "SELECT 1 IN ({v:UInt32})",
    ],
)
def test_clickhouse_keeps_value_lists_subqueries_and_value_parameters(allowed: list[str], deny: bool, sql: str) -> None:
    guard = _guard("clickhouse", allowed, OCEAN if deny else None, deny=deny)
    for label, validate, prefix in _entries(guard):
        assert validate(prefix + sql).kind in ("select", "explain"), label


@pytest.mark.parametrize("engine", [*REMOTE, "sqlite"])
def test_a_bare_name_after_in_is_refused_on_every_engine(engine: str) -> None:
    # SQLite reads `x IN t` (and `x IN sqlite_master`) as the table's rows; the
    # other engines reject the syntax, so refusing it loses nothing there
    guard = _guard(engine, [], {("main", "t"), ("ocean", "t")})
    for sql in ("SELECT 1 IN t", "SELECT 1 IN main.t", "SELECT ('table', 't') IN sqlite_master"):
        exc = _refused(guard.validate_select, sql)
        assert "IN (SELECT <column> FROM <schema>.<table>)" in str(exc), (engine, sql, str(exc))


@pytest.mark.parametrize("engine", ["postgres", "mysql", "oracle", "mssql", "db2", "sqlite"])
def test_a_single_column_in_parentheses_stays_a_column_off_clickhouse(engine: str) -> None:
    guard = _guard(engine, ["ocean"] if engine != "sqlite" else [], OCEAN | {("main", "t")})
    table = "ocean.buoys" if engine != "sqlite" else "t"
    assert guard.validate_select(f"SELECT buoy_id FROM {table} WHERE 1 IN (buoy_id)").kind == "select"


@pytest.mark.parametrize("deny", [True, False], ids=["default-deny", "no-default-deny"])
def test_clickhouse_query_tools_refuse_in_table_before_the_engine_sees_it(
    tmp_path: Path, monkeypatch: Any, deny: bool
) -> None:
    server, fake = _server(tmp_path, monkeypatch, "clickhouse", ["ocean"], deny=deny)
    for sql in ("SELECT 1 IN hr.salaries AS leaked", "SELECT 1 IN (hr.salaries) AS leaked", "SELECT 1 IN salaries"):
        for tool, args in (
            ("db_query", {"connection_id": "remote", "sql": sql}),
            ("db_validate_query", {"connection_id": "remote", "sql": sql}),
            ("db_explain", {"connection_id": "remote", "sql": "EXPLAIN " + sql}),
        ):
            text = _call_error(server, tool, args)
            assert "IN (SELECT <column> FROM <schema>.<table>)" in text, (tool, text)
        env = _call(server, "db_federated_query", {"sql": sql, "connections": ["remote"]})
        assert env["data"]["connections_run"] == 0
    text = _call_error(server, "db_query", {"connection_id": "remote", "sql": "SELECT 1 IN ({t:Identifier})",
                                            "parameters": {"t": "salaries"}})
    assert "{name:Identifier}" in text, text
    assert fake.statements == [] and fake.plans == []


# ---- schemas whose names differ only in case (review, 2026-09-28) -------------
#
# Entries matched catalog schema names ignoring case, and so did every check:
# with allowed_schemas [ocean], a PostgreSQL catalog holding both ocean and
# "Ocean" listed both, and the guard approved "Ocean".secrets, default-deny
# or not. To PostgreSQL, Oracle and Db2 (quoted names), ClickHouse, MySQL
# with lower_case_table_names=0 and SQL Server under a case-sensitive
# collation those are two schemas, and the administrator named one. Where
# the catalog holds a name in several spellings, an entry written in one case
# now admits the one the engine folds the entry to as an unquoted name, or
# else the one written exactly as the entry (owner decision 2026-09-28: a
# lower-case Oracle entry keeps the upper-case schema), and a mixed-case entry
# the one written exactly, or else the folded one; the others are left out of
# every listing and refused.


@pytest.mark.parametrize(
    ("engine", "entries", "listed", "shadowed"),
    [
        ("postgres", ["ocean"], ["ocean", "Ocean", "hr", None], {"Ocean"}),
        # a mixed-case entry names its exact spelling first (review, 2026-09-28)
        ("postgres", ["Ocean"], ["ocean", "Ocean"], {"ocean"}),
        # one written in one case is read as an unquoted name first (owner decision 2026-09-28)
        ("postgres", ["OCEAN"], ["ocean", "Ocean"], {"Ocean"}),
        ("postgres", ["Ocean"], ["Ocean", "OCEAN"], {"OCEAN"}),  # else as written, where the fold is not held
        ("postgres", ["ocean", "Ocean"], ["ocean", "Ocean"], set()),  # both named
        ("postgres", ["ocean"], ["Ocean"], set()),  # one spelling: admitted whatever the case, as before
        ("oracle", ["TRAVEL"], ["TRAVEL", "travel"], {"travel"}),
        ("oracle", ["Travel"], ["TRAVEL", "travel"], {"travel"}),  # folds to TRAVEL
        ("db2", ["db2inst1"], ["DB2INST1", "Db2Inst1"], {"Db2Inst1"}),
        ("clickhouse", ["Telecom"], ["telecom", "TELECOM"], {"telecom", "TELECOM"}),  # no folding: neither
        ("mysql", ["hr"], ["hr", "HR"], {"HR"}),
        ("mssql", ["sales"], ["Sales", "sales"], {"Sales"}),
    ],
)
def test_an_entry_admits_one_spelling_of_a_schema_the_catalog_holds_in_several(
    engine: str, entries: list[str], listed: list[str | None], shadowed: set[str]
) -> None:
    assert _policy(engine, entries).shadowed_spellings(listed) == shadowed


def test_without_an_allowlist_no_spelling_is_shadowed() -> None:
    assert _policy("postgres", []).shadowed_spellings(["ocean", "Ocean"]) == frozenset()


def _live_guard(
    engine: str,
    allowed: list[str],
    tables: list[tuple[str, str]],
    shadowed: set[str],
    *,
    deny: bool,
    system_schemas: list[str] | None = None,
) -> SqlGuard:
    """The guard as _validated builds it: the resolver over the pinned listing."""
    from universal_db_mcp.server import _LiveResolver

    listing = [TableSummary(schema, name, "table") for schema, name in tables]
    policy = _policy(engine, allowed, deny=deny, system_schemas=system_schemas)
    return SqlGuard(engine, policy, _LiveResolver(listing, frozenset(shadowed)))


_CASE_CASES = [
    # engine, allowed, listing, shadowed, refused (-> suggested spelling or None), accepted
    ("postgres", ["ocean"], [("ocean", "buoys")], {"Ocean"},
     {'SELECT * FROM "Ocean".buoys': "ocean.buoys", 'SELECT * FROM "OCEAN".buoys': "ocean.buoys"},
     ["SELECT * FROM ocean.buoys", "SELECT * FROM OCEAN.buoys", 'SELECT * FROM "ocean".buoys']),
    # no namesake listed: a quoted spelling still names another schema
    ("postgres", ["ocean"], [("ocean", "buoys")], set(),
     {'SELECT * FROM "Ocean".buoys': "ocean.buoys"}, ["SELECT * FROM Ocean.buoys"]),
    # a mixed-case catalog schema: the hint quotes it
    ("postgres", ["ocean"], [("Ocean", "buoys")], set(),
     {"SELECT * FROM ocean.buoys": '"Ocean".buoys'}, ['SELECT * FROM "Ocean".buoys']),
    ("oracle", ["travel"], [("TRAVEL", "BOOKINGS")], set(),
     {'SELECT * FROM "travel".bookings': "TRAVEL.bookings", 'SELECT * FROM "Travel".bookings': "TRAVEL.bookings"},
     ["SELECT * FROM travel.bookings", 'SELECT * FROM "TRAVEL".bookings']),
    ("db2", ["db2inst1"], [("DB2INST1", "T")], set(),
     {'SELECT * FROM "db2inst1".t': "DB2INST1.t"}, ["SELECT * FROM db2inst1.t", "SELECT * FROM DB2INST1.t"]),
    ("clickhouse", ["telecom"], [("telecom", "subscribers")], set(),
     {"SELECT * FROM Telecom.subscribers": "telecom.subscribers"}, ["SELECT * FROM telecom.subscribers"]),
    ("mysql", ["testdb"], [("testdb", "cuppings")], set(),
     {"SELECT * FROM TESTDB.cuppings": "testdb.cuppings"}, ["SELECT * FROM testdb.cuppings"]),
    # SQL Server: the collation decides, so only a listed namesake proves case matters
    ("mssql", ["ocean"], [("ocean", "buoys")], set(), {}, ["SELECT * FROM OCEAN.buoys", "SELECT * FROM ocean.buoys"]),
    ("mssql", ["ocean"], [("ocean", "buoys")], {"Ocean"},
     {"SELECT * FROM Ocean.buoys": "ocean.buoys", "SELECT * FROM OCEAN.buoys": "ocean.buoys"},
     ["SELECT * FROM ocean.buoys"]),
    # every spelling a namesake the allowlist does not name exactly
    ("clickhouse", ["Telecom"], [], {"telecom", "TELECOM"},
     {"SELECT * FROM telecom.subscribers": None, "SELECT * FROM TELECOM.subscribers": None}, []),
]


@pytest.mark.parametrize("deny", [True, False], ids=["default-deny", "no-default-deny"])
@pytest.mark.parametrize(("engine", "allowed", "tables", "shadowed", "refused", "accepted"), _CASE_CASES)
def test_a_qualified_schema_must_be_the_spelling_the_policy_admits(
    engine: str,
    allowed: list[str],
    tables: list[tuple[str, str]],
    shadowed: set[str],
    refused: dict[str, str | None],
    accepted: list[str],
    deny: bool,
) -> None:
    guard = _live_guard(engine, allowed, tables, shadowed, deny=deny)
    for sql, spelling in refused.items():
        for label, validate, prefix in _entries(guard):
            exc = _refused(validate, prefix + sql)
            text = str(exc)
            assert exc.category == ErrorCategory.AUTHZ and "differ only in case" in text, (label, sql, text)
            if spelling is not None:
                assert text.endswith(f"write {spelling}"), (label, sql, text)
    for sql in accepted:
        for label, validate, prefix in _entries(guard):
            assert validate(prefix + sql).kind in ("select", "explain"), (label, sql)


def test_sqlite_schema_names_ignore_case() -> None:
    guard = _live_guard("sqlite", ["main"], [("main", "t")], set(), deny=True)
    assert guard.validate_select("SELECT * FROM MAIN.t").kind == "select"


@pytest.mark.parametrize(
    ("engine", "allowed", "tables", "sql", "spelling"),
    [
        ("postgres", ["ocean"], [("Ocean", "buoys")], "SELECT * FROM buoys", 'write "Ocean".buoys'),
        ("oracle", ["travel"], [("TRAVEL", "BOOKINGS")], "SELECT * FROM bookings", "write TRAVEL.bookings"),
        # no permitted schema lists it: the example is still spelled as the catalog spells an allowed schema
        ("postgres", ["ocean"], [("Ocean", "buoys")], "SELECT * FROM nothere",
         'qualify it with an allowed schema, for example "Ocean".nothere'),
        ("oracle", ["travel"], [("TRAVEL", "BOOKINGS")], "SELECT * FROM nothere",
         "qualify it with an allowed schema, for example TRAVEL.nothere"),
    ],
)
def test_the_unqualified_hint_is_spelled_as_the_catalog_spells_the_schema(
    engine: str, allowed: list[str], tables: list[tuple[str, str]], sql: str, spelling: str
) -> None:
    text = str(_refused(_live_guard(engine, allowed, tables, set(), deny=True).validate_select, sql))
    assert text.endswith(spelling), text


_NAMESAKES = [
    TableSummary("ocean", "buoys", "table"),
    TableSummary("ocean", "readings", "table"),
    TableSummary("Ocean", "buoys", "table"),
    TableSummary("Ocean", "secrets", "table"),
    TableSummary("hr", "salaries", "table"),
]


@pytest.mark.parametrize("deny", [True, False], ids=["default-deny", "no-default-deny"])
def test_a_namesake_schema_is_left_out_of_listings_and_refused_by_every_tool(
    tmp_path: Path, monkeypatch: Any, deny: bool
) -> None:
    server, fake = _server(tmp_path, monkeypatch, "postgres", ["ocean"], deny=deny, catalog=_NAMESAKES)
    for _ in range(2):  # the second listing comes from the metadata cache
        tables = _call(server, "db_list_tables", {"connection_id": "remote"})["data"]["tables"]
        assert {(t["schema"], t["name"]) for t in tables} == {("ocean", "buoys"), ("ocean", "readings")}
    schemas = _call(server, "db_list_schemas", {"connection_id": "remote"})["data"]["schemas"]
    assert schemas == ["ocean"]
    catalog = _call(server, "db_get_catalog", {"connection_id": "remote"})["data"]["tables"]
    assert {t["schema"] for t in catalog} == {"ocean"}
    for sql in ('SELECT * FROM "Ocean".secrets', 'SELECT buoy_id FROM "Ocean".buoys'):
        for tool, args in (
            ("db_query", {"connection_id": "remote", "sql": sql}),
            ("db_validate_query", {"connection_id": "remote", "sql": sql}),
            ("db_explain", {"connection_id": "remote", "sql": "EXPLAIN " + sql}),
        ):
            text = _call_error(server, tool, args)
            assert "AUTHORIZATION_DENIED" in text and "differ only in case" in text, (tool, text)
    for tool, args in (
        ("db_sample_table", {"connection_id": "remote", "object_name": "Ocean.secrets"}),
        ("db_sample_table", {"connection_id": "remote", "schema": "Ocean", "object_name": "buoys"}),
        ("db_get_table", {"connection_id": "remote", "schema": "Ocean", "object_name": "secrets"}),
        ("db_list_columns", {"connection_id": "remote", "object_name": "Ocean.secrets"}),
        ("db_list_tables", {"connection_id": "remote", "schema": "Ocean"}),
        ("db_get_catalog", {"connection_id": "remote", "schema": "Ocean"}),
        ("db_list_views", {"connection_id": "remote", "schema": "Ocean"}),
        ("db_list_routines", {"connection_id": "remote", "schema": "Ocean"}),
    ):
        text = _call_error(server, tool, args)
        assert "AUTHORIZATION_DENIED" in text, (tool, args, text)
    # the admitted spelling, in any case the engine folds to it, still works
    assert _call(server, "db_query", {"connection_id": "remote", "sql": "SELECT buoy_id FROM OCEAN.buoys"})
    _call(server, "db_sample_table", {"connection_id": "remote", "object_name": "ocean.buoys"})
    _call(server, "db_list_views", {"connection_id": "remote", "schema": "ocean"})
    assert fake.listed == ["ocean"]
    assert not [s for s in fake.statements + fake.plans if "Ocean" in s], fake.statements


# ---- review polish, 2026-09-28 ---------------------------------------------------


@pytest.mark.parametrize(
    ("allowed", "deny"),
    [(["testdb"], True), (["testdb"], False), ([], True)],
    ids=["allowlist-default-deny", "allowlist", "default-deny"],
)
def test_mysql_dual_is_a_keyword_not_a_table(allowed: list[str], deny: bool) -> None:
    # agents write FROM DUAL all the time; on MySQL it names no object
    guard = _guard("mysql", allowed, {("testdb", "cuppings")} if deny else None, deny=deny)
    for sql in ("SELECT 1 AS x FROM DUAL", "SELECT CURRENT_TIMESTAMP AS t FROM dual"):
        for label, validate, prefix in _entries(guard):
            assert validate(prefix + sql).kind in ("select", "explain"), (label, sql)
    if allowed:
        # quoted, it is a table like any other
        assert "unqualified table 'DUAL'" in str(_refused(guard.validate_select, "SELECT 1 FROM `DUAL`"))


def test_mysql_query_tools_run_from_dual(tmp_path: Path, monkeypatch: Any) -> None:
    server, fake = _server(tmp_path, monkeypatch, "mysql", ["ocean"])
    assert _call(server, "db_query", {"connection_id": "remote", "sql": "SELECT 1 AS x FROM DUAL"})["data"]["rows"]
    assert fake.statements == ["SELECT 1 AS x FROM DUAL"]


def test_oracle_dual_needs_no_system_schema() -> None:
    # owner decision 2026-09-28: DUAL holds no data, bare or as SYS.DUAL, and
    # reading it opens nothing else in SYS (test_hardening_2026_09_28_final_guard_server)
    guard = _guard("oracle", ["travel"], {("travel", "bookings")})
    for sql in ("SELECT SYSDATE FROM DUAL", "SELECT SYSDATE FROM SYS.DUAL"):
        assert guard.validate_select(sql).kind == "select", sql
    policy = _policy("oracle", ["travel"], system_schemas=["sys"])
    opened = SqlGuard("oracle", policy, StaticResolver({("sys", "dual"), ("travel", "bookings")}))
    for sql in ("SELECT SYSDATE FROM DUAL", "SELECT SYSDATE FROM SYS.DUAL"):
        assert opened.validate_select(sql).kind == "select", sql


def test_a_catalog_qualified_name_without_a_schema_gets_the_catalog_refusal() -> None:
    exc = _refused(_guard("mssql", ["ocean"]).validate_select, "SELECT * FROM otherdb..salaries")
    assert "catalog-qualified reference 'otherdb'" in str(exc), str(exc)


@pytest.mark.parametrize("engine", ["mssql", "mysql"])
def test_a_cte_reference_in_another_case_is_told_to_match_the_declared_name(
    tmp_path: Path, monkeypatch: Any, engine: str
) -> None:
    # whether BUOYS names the CTE buoys is the collation's (a server setting's
    # on MySQL): refused as a table, with the spelling that does name the CTE
    server, _ = _server(tmp_path, monkeypatch, engine, ["ocean"])
    sql = "WITH buoys AS (SELECT 1 AS x) SELECT x FROM BUOYS"
    text = _call_error(server, "db_validate_query", {"connection_id": "remote", "sql": sql})
    assert "unqualified table 'BUOYS'" in text and "spell the reference as the CTE is declared (buoys)" in text, text
    ok = _call(server, "db_validate_query", {"connection_id": "remote", "sql": sql.replace("BUOYS", "buoys")})
    assert ok["data"]["valid"]


_SHOW_GUARDS = {"mysql": ("testdb", "cuppings"), "clickhouse": ("testdb", "cuppings")}


@pytest.mark.parametrize("deny", [True, False], ids=["default-deny", "no-default-deny"])
@pytest.mark.parametrize(
    ("engine", "sql", "refusal"),
    [
        ("mysql", "DESCRIBE cuppings", "unqualified table 'cuppings'"),
        ("mysql", "DESC cuppings", "unqualified table 'cuppings'"),
        ("mysql", "SHOW COLUMNS FROM cuppings", "unqualified table 'cuppings'"),
        ("mysql", "SHOW INDEX FROM cuppings", "unqualified table 'cuppings'"),
        ("mysql", "DESCRIBE hr.salaries", "schema 'hr' is not permitted"),
        ("mysql", "SHOW COLUMNS FROM hr.salaries", "schema 'hr' is not permitted"),
        ("mysql", "SHOW INDEX FROM hr.salaries", "schema 'hr' is not permitted"),
        ("mysql", "SHOW TABLES FROM hr", "schema 'hr' is not permitted"),
        ("clickhouse", "DESCRIBE TABLE cuppings", "unqualified table 'cuppings'"),
        ("clickhouse", "DESC hr.salaries", "schema 'hr' is not permitted"),
    ],
)
def test_show_and_describe_get_the_verdict_a_query_on_the_object_gets(
    engine: str, sql: str, refusal: str, deny: bool
) -> None:
    # db_validate_query (validate_any) reads SHOW/DESCRIBE; nothing runs them,
    # but the verdict must not call valid what the allowlist refuses
    guard = _guard(engine, ["testdb"], {_SHOW_GUARDS[engine]} if deny else None, deny=deny)
    exc = _refused(guard.validate_any, sql)
    assert exc.category == ErrorCategory.AUTHZ and refusal in str(exc), str(exc)


@pytest.mark.parametrize(
    ("engine", "sql"),
    [
        ("mysql", "DESCRIBE testdb.cuppings"),
        ("mysql", "SHOW COLUMNS FROM testdb.cuppings"),
        ("mysql", "SHOW INDEX FROM testdb.cuppings"),
        ("mysql", "SHOW TABLES FROM testdb"),
        ("mysql", "SHOW DATABASES"),
        ("mysql", "SHOW TABLES"),  # names no object
        ("clickhouse", "DESCRIBE TABLE testdb.cuppings"),
        ("clickhouse", "SHOW DATABASES"),
        ("clickhouse", "SHOW TABLES"),
    ],
)
def test_show_and_describe_of_an_allowed_object_stay_valid(engine: str, sql: str) -> None:
    guard = _guard(engine, ["testdb"], {_SHOW_GUARDS[engine]})
    result = guard.validate_any(sql)
    assert result.kind == "show"
    if "cuppings" in sql:
        assert [(t.schema, t.name) for t in result.tables] == [("testdb", "cuppings")]


@pytest.mark.parametrize("engine", ["mysql", "clickhouse"])
def test_show_and_describe_without_an_allowlist_are_unchanged(engine: str) -> None:
    guard = _guard(engine, [], None, deny=False)
    for sql in ("DESCRIBE cuppings", "SHOW TABLES"):
        assert guard.validate_any(sql).kind == "show"


@pytest.mark.parametrize("engine", ["postgres", "mysql", "clickhouse"])
def test_without_an_allowlist_schema_case_is_the_engines_business(engine: str) -> None:
    # every user schema is readable there, and no spelling is shadowed
    guard = _live_guard(engine, [], [("testdb", "cuppings")], set(), deny=engine != "clickhouse")
    assert guard.validate_select("SELECT * FROM TestDB.cuppings").kind == "select"
    if engine == "clickhouse":
        # default-deny reads a listed object only as ClickHouse, which compares names exactly, spells it
        # (re-attack round 2, test_hardening_2026_09_29_name_binding)
        guard = _live_guard(engine, [], [("testdb", "cuppings")], set(), deny=True)
        text = str(_refused(guard.validate_select, "SELECT * FROM TestDB.cuppings"))
        assert "not spelled as the catalog lists it" in text, text


@pytest.mark.parametrize("deny", [True, False], ids=["default-deny", "no-default-deny"])
def test_mysql_information_schema_is_named_in_any_case(deny: bool) -> None:
    # live (mock_mysql, Linux): INFORMATION_SCHEMA.TABLES and information_schema.tables
    # both answer, PERFORMANCE_SCHEMA.x is error 1049 (a database like any other)
    tables = [("testdb", "cuppings"), ("information_schema", "tables"), ("performance_schema", "global_status")]
    guard = _live_guard("mysql", ["testdb"], tables, set(), deny=deny,
                        system_schemas=["information_schema", "performance_schema"])
    for sql in ("SELECT * FROM INFORMATION_SCHEMA.TABLES", "SELECT * FROM Information_Schema.tables"):
        assert guard.validate_select(sql).kind == "select", sql
    exc = _refused(guard.validate_select, "SELECT * FROM PERFORMANCE_SCHEMA.global_status")
    assert "differ only in case" in str(exc)
