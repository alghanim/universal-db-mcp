"""Final hardening round, 2026-09-28: the guard and the server.

1. A value placeholder after IN is a value. The qualified-name stage refused
   every name sqlglot puts in In.field, and it puts a placeholder there too:
   ClickHouse's documented `x IN {ids:Array(UInt64)}` and a driver's
   `x IN %(p1)s` were refused on every connection as "it reads a table".
2. Owner decision 2026-09-28: Oracle's DUAL (bare or SYS.DUAL) and Db2's
   SYSIBM.SYSDUMMY1..4 hold no data and are always readable; nothing else in
   SYS or SYSIBM opens, and no refusal tells the caller to open all of SYS.
3. Views that show other sessions' SQL text (literals, bind values, plan
   predicates) hand back values column masking hides, so they are refused
   whatever security.allowed_system_schemas says, and left out of listings.
4. Review polish: SHOW TABLES FROM gets the schema-case check, ClickHouse's
   INFORMATION_SCHEMA is information_schema, an allowlist entry admits the
   spelling the engine folds it to before its exact spelling, the 9i Oracle
   owners are system schemas, and db_explain(analyze=true) says what it is.
5. ClickHouse binds a CTE's name its own way. A CTE naming itself outside
   the recursion of WITH RECURSIVE ... UNION ALL reads the table of that
   name, which the guard and the server took for the CTE, so default-deny
   and allowed_schemas never saw it. A CTE sees the ones declared after it;
   CTEs naming each other, a WITH ClickHouse copies into later branches of
   a set operation, and a WITH sqlglot hangs over branches it does not
   cover leave the binding to ClickHouse's resolution order: refused.
6. The metadata, sample and profile tools compare a schema argument with the
   whole schema list, as db_list_schemas does: a namesake holding only
   relation kinds the listing leaves out was read through them.

Fix-up round (review, 2026-09-28):
7. ClickHouse decodes backslash escapes in quoted identifiers, which sqlglot
   keeps as written: `msisd\\x6e` read the masked msisdn in clear, and
   system.`query_lo\\x67` other sessions' SQL. Such an identifier is refused.
8. More views show other sessions' statements or their values: MySQL's
   INNODB_TRX, lock-wait and data-lock views, ClickHouse's errors and
   error_log, Oracle's audit, SQL tuning set, baseline and profile views,
   Db2's explain tables, PostgreSQL's statement-statistics extensions.
9. The namesakes of an allowed schema come from the whole schema list: where
   the spelling the policy admits held nothing the listing lists, the
   listing held the namesake alone and admitted it.
10. MySQL prints the values it reads from const tables into TREE and JSON
    plans; db_explain returns neither for a statement naming a masked column.
11. A mixed-case allowlist entry names its exact spelling first.

Fix-up round 2 (review, 2026-09-28):
12. Engines read some names as other names: SQL Server's collation (full-width
    letters, ignorable characters, a trailing blank), Db2 (a delimited name's
    trailing blanks), Oracle (an unquoted ı or ſ) and MySQL's lookup of
    information_schema tables (ſ, ı, İ). A masked column or a session view was
    read that way in clear. Such a name is refused where the engine reads it
    as another, and the refusal lists match every spelling an engine reads.
13. Oracle 23ai adds views of other sessions' SQL, binds and plan predicates
    that the unprivileged account can read.
14. ClickHouse resolves a CTE's body where the CTE is used: a nested WITH
    declaring a name an outer CTE's body reads made that body read a table.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
import sqlglot
from sqlglot import exp
from test_hardening_2026_09_27_qualified_names import (
    OCEAN,
    REMOTE,
    _call,
    _call_error,
    _entries,
    _guard,
    _policy,
    _recording,
    _refused,
    _server,
)
from test_hardening_2026_09_27_server import SECRETS, _AnswerFake, _fake_app_server, _StatementFake

import universal_db_mcp.security.sql_guard as sql_guard
import universal_db_mcp.server as srv
from universal_db_mcp.config import load_resolved
from universal_db_mcp.connectors.base import TableSummary
from universal_db_mcp.discovery.system_schemas import is_listed_system_schema, is_session_sql_view
from universal_db_mcp.errors import ToolFailure
from universal_db_mcp.models.responses import ErrorCategory
from universal_db_mcp.security.sql_guard import SqlGuard, StaticResolver
from universal_db_mcp.server import AppContext, _Listing, _LiveResolver, build_server

_POLICIES = [
    pytest.param(["ocean"], True, id="allowlist-default-deny"),
    pytest.param(["ocean"], False, id="allowlist"),
    pytest.param([], True, id="default-deny"),
    pytest.param([], False, id="neither"),
]


def _listed_guard(
    engine: str,
    allowed: list[str],
    tables: list[tuple[str, str]],
    *,
    deny: bool,
    system_schemas: list[str] | None = None,
    schemas: list[str] | None = None,
) -> SqlGuard:
    """The guard exactly as _validated builds it: the resolver over the
    listing tables_for pins (its namesake spellings left out), with the
    whole schema list ``schemas`` where given."""
    policy = _policy(engine, allowed, deny=deny, system_schemas=system_schemas)
    listing = _Listing.pinned(policy, [TableSummary(schema, name, "table") for schema, name in tables], schemas or [])
    return SqlGuard(engine, policy, _LiveResolver(listing, listing.shadowed))


def _app_server(
    tmp_path: Path,
    monkeypatch: Any,
    engine: str,
    allowed: list[str],
    catalog: list[TableSummary],
    *,
    deny: bool = True,
    security: str = "",
) -> tuple[Any, Any]:
    """_server with extra security settings (YAML lines under security:)."""
    monkeypatch.setenv("UDBMCP_T_USER", "tester")
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "application:\n  transport: stdio\n"
        f"  audit_path: {tmp_path / 'audit.jsonl'}\n"
        f"  metadata_cache_path: {tmp_path / 'cache.sqlite'}\n"
        f"security:\n  require_remote_tls: false\n  default_deny_objects: {str(deny).lower()}\n{security}"
        f"connections:\n  remote:\n    type: {engine}\n    host: 127.0.0.1\n    port: 5999\n    database: testdb\n"
        f"    username_env: UDBMCP_T_USER\n    allowed_schemas: {json.dumps(allowed)}\n",
        encoding="utf-8",
    )
    app_cfg, resolved = load_resolved(cfg)
    app = AppContext(app_cfg, resolved)
    fake = _recording(engine, app, catalog)
    app.connectors["remote"] = fake
    return build_server(app), fake


# ---- 1. a value placeholder after IN ------------------------------------------

_VALUES_AFTER_IN = [
    # ClickHouse server-side parameters: the documented array idiom, bound as a literal
    ("clickhouse", "IN {ids:Array(UInt64)}"),
    ("clickhouse", "NOT IN {ids:Array(UInt64)}"),
    ("clickhouse", "GLOBAL IN {ids:Array(UInt64)}"),
    ("clickhouse", "GLOBAL NOT IN {ids:Array(String)}"),
    ("clickhouse", "IN {v:UInt32}"),
    # client-side placeholders (each driver's own and the guard's qmark/named)
    ("clickhouse", "IN %(p1)s"),
    ("clickhouse", "IN %s"),
    ("clickhouse", "IN ?"),
    ("postgres", "IN %(p1)s"),
    ("postgres", "NOT IN %(p1)s"),
    ("postgres", "IN %s"),
    ("postgres", "IN $1"),
    ("mysql", "IN %(p1)s"),
    ("mysql", "IN %s"),
    ("mysql", "IN ?"),
    ("mysql", "IN :p"),
    ("mssql", "IN ?"),
    ("mssql", "IN @p"),
    ("oracle", "IN :p"),
    ("db2", "IN ?"),
    # a constant is a value too (ClickHouse reads it as a one-element set)
    ("clickhouse", "IN 1"),
    ("clickhouse", "IN tuple(1, 2)"),
    ("clickhouse", "IN array(1, 2)"),
]


@pytest.mark.parametrize(("allowed", "deny"), _POLICIES)
@pytest.mark.parametrize(("engine", "form"), _VALUES_AFTER_IN)
def test_a_value_after_in_is_not_a_table(engine: str, form: str, allowed: list[str], deny: bool) -> None:
    guard = _guard(engine, allowed, OCEAN if deny else None, deny=deny)
    sql = f"SELECT buoy_id FROM ocean.buoys WHERE buoy_id {form}"
    for label, validate, prefix in _entries(guard):
        assert validate(prefix + sql).kind in ("select", "explain"), (label, sql)


@pytest.mark.parametrize("deny", [True, False], ids=["default-deny", "no-default-deny"])
@pytest.mark.parametrize("form", ["IN ?", "IN :p", "NOT IN ?"])
def test_sqlite_keeps_placeholders_after_in(form: str, deny: bool) -> None:
    guard = _guard("sqlite", [], {("main", "buoys")}, deny=deny)
    assert guard.validate_select(f"SELECT buoy_id FROM buoys WHERE buoy_id {form}").kind == "select"


@pytest.mark.parametrize(("allowed", "deny"), _POLICIES)
@pytest.mark.parametrize(
    "sql",
    [
        "SELECT 1 IN salaries",
        "SELECT 1 IN hr.salaries",
        "SELECT 1 IN `hr`.`salaries`",
        "SELECT 1 NOT IN hr.salaries",
        "SELECT 1 IN tuple(salaries)",  # a name inside a value is refused as well (fail closed)
    ],
)
def test_a_name_after_in_stays_refused(sql: str, allowed: list[str], deny: bool) -> None:
    guard = _guard("clickhouse", allowed, OCEAN if deny else None, deny=deny)
    for label, validate, prefix in _entries(guard):
        exc = _refused(validate, prefix + sql)
        assert exc.category == ErrorCategory.POLICY, (label, str(exc))
        assert "IN (SELECT <column> FROM <schema>.<table>)" in str(exc), (label, str(exc))
    # an identifier parameter keeps its own refusal: it names the table after validation
    exc = _refused(guard.validate_select, "SELECT 1 IN {t:Identifier}")
    assert "{name:Identifier}" in str(exc)


@pytest.mark.parametrize("deny", [True, False], ids=["default-deny", "no-default-deny"])
def test_clickhouse_array_parameter_reaches_the_engine(tmp_path: Path, monkeypatch: Any, deny: bool) -> None:
    # live, the review's repro: POLICY_VIOLATION here, [(2,)] from the engine itself
    server, fake = _server(tmp_path, monkeypatch, "clickhouse", ["ocean"], deny=deny)
    sql = "SELECT count() AS n FROM ocean.buoys WHERE buoy_id IN {ids:Array(UInt64)}"
    env = _call(server, "db_query", {"connection_id": "remote", "sql": sql, "parameters": {"ids": "[1,2]"}})
    assert env["data"]["rows"] == [[2]]
    assert fake.statements == [sql]
    assert _call(server, "db_validate_query", {"connection_id": "remote", "sql": sql})["data"]["valid"] is True


# ---- 2. Oracle DUAL and Db2 SYSIBM.SYSDUMMY1..4 (owner decision 2026-09-28) ------

_TRAVEL = {("travel", "bookings")}
_ORACLE_DUAL = [
    "SELECT SYSDATE FROM DUAL",
    "SELECT 1 AS one FROM dual",
    'SELECT 1 AS one FROM "DUAL"',
    "SELECT 1 AS one FROM SYS.DUAL",
    "SELECT 1 AS one FROM sys.dual",
    'SELECT 1 AS one FROM "SYS"."DUAL"',
    "SELECT b.booking_id FROM travel.bookings b CROSS JOIN DUAL",
    "SELECT (SELECT 1 FROM DUAL) AS x FROM travel.bookings",
]


@pytest.mark.parametrize(
    ("allowed", "deny"),
    [(["travel"], True), (["travel"], False), ([], True), ([], False)],
    ids=["allowlist-default-deny", "allowlist", "default-deny", "neither"],
)
@pytest.mark.parametrize("sql", _ORACLE_DUAL)
def test_oracle_dual_is_always_readable(sql: str, allowed: list[str], deny: bool) -> None:
    # SYS is closed (not in allowed_system_schemas) and the resolver does not list DUAL
    guard = _guard("oracle", allowed, _TRAVEL if deny else None, deny=deny)
    for label, validate, prefix in _entries(guard):
        assert validate(prefix + sql).kind in ("select", "explain"), (label, sql)
    listed = _listed_guard("oracle", allowed, [("TRAVEL", "BOOKINGS")], deny=deny)
    assert listed.validate_select(sql).kind == "select", sql


@pytest.mark.parametrize("deny", [True, False], ids=["default-deny", "no-default-deny"])
@pytest.mark.parametrize(
    ("sql", "refusal"),
    [
        ("SELECT username FROM SYS.ALL_USERS", "system schema"),
        ("SELECT name FROM SYS.OBJ$", "system schema"),
        ("SELECT name FROM SYS.USER$", "stored credentials"),  # refused before the schema is looked at
        ("SELECT * FROM SYS.DUAL_HISTORY", "system schema"),
        ('SELECT 1 FROM "sys".DUAL', "system schema"),  # a quoted lower-case "sys" is another schema
        ('SELECT 1 FROM "dual"', "unqualified table 'dual'"),  # and "dual" another name
        ("SELECT 1 FROM travel.DUAL", ""),  # a DUAL of an allowed schema is an ordinary table
    ],
)
def test_nothing_else_in_sys_opens(sql: str, refusal: str, deny: bool) -> None:
    guard = _guard("oracle", ["travel"], _TRAVEL if deny else None, deny=deny)
    if not refusal:
        if deny:
            assert "could not be resolved" in str(_refused(guard.validate_select, sql))
        else:
            assert guard.validate_select(sql).kind == "select"
        return
    text = str(_refused(guard.validate_select, sql))
    assert refusal in text, text
    # no refusal sends the caller to open the whole of SYS for DUAL
    assert "SYS.DUAL" not in text and "needs SYS" not in text, text


def test_a_database_link_on_dual_is_still_refused() -> None:
    exc = _refused(_guard("oracle", ["travel"], _TRAVEL).validate_select, "SELECT 1 FROM DUAL@remote")
    assert "database links" in str(exc)


@pytest.mark.parametrize("engine", [e for e in REMOTE if e != "oracle"])
def test_sys_dual_is_oracles_alone(engine: str) -> None:
    exc = _refused(_guard(engine, ["ocean"]).validate_select, "SELECT 1 AS one FROM SYS.DUAL")
    assert exc.category == ErrorCategory.AUTHZ, str(exc)


_DB2_DUMMY = [
    "SELECT 1 AS one FROM SYSIBM.SYSDUMMY1",
    "SELECT CURRENT_DATE AS d FROM SYSIBM.SYSDUMMY1 WITH UR",
    "SELECT 1 AS one FROM sysibm.sysdummy2",
    'SELECT 1 AS one FROM "SYSIBM"."SYSDUMMY3"',
    "SELECT 1 AS one FROM SYSIBM.SYSDUMMY4 FOR READ ONLY",
    "SELECT b.buoy_id FROM ocean.buoys b CROSS JOIN SYSIBM.SYSDUMMY1",
]


@pytest.mark.parametrize(("allowed", "deny"), _POLICIES)
@pytest.mark.parametrize("sql", _DB2_DUMMY)
def test_db2_sysdummy_is_always_readable(sql: str, allowed: list[str], deny: bool) -> None:
    guard = _guard("db2", allowed, OCEAN if deny else None, deny=deny)
    for label, validate, prefix in _entries(guard):
        assert validate(prefix + sql).kind in ("select", "explain"), (label, sql)


@pytest.mark.parametrize("deny", [True, False], ids=["default-deny", "no-default-deny"])
@pytest.mark.parametrize(
    ("sql", "refusal"),
    [
        ("SELECT * FROM SYSIBM.SYSTABLES", "system schema"),
        ("SELECT 1 FROM SYSIBM.SYSDUMMY5", "system schema"),
        ("SELECT * FROM SYSCAT.TABLES", "system schema"),
        ('SELECT 1 FROM "sysibm".SYSDUMMY1', "system schema"),
    ],
)
def test_nothing_else_in_sysibm_opens(sql: str, refusal: str, deny: bool) -> None:
    text = str(_refused(_guard("db2", ["ocean"], OCEAN if deny else None, deny=deny).validate_select, sql))
    assert refusal in text, text


def test_db2_bare_sysdummy_is_told_its_schema() -> None:
    # a bare name binds to CURRENT SCHEMA on Db2, so it is not the dummy table
    text = str(_refused(_guard("db2", ["ocean"]).validate_select, "SELECT 1 FROM SYSDUMMY1"))
    assert "unqualified table 'SYSDUMMY1'" in text and text.endswith("write SYSIBM.SYSDUMMY1"), text


@pytest.mark.parametrize(
    ("engine", "sql"),
    [("oracle", "SELECT SYSDATE AS d FROM DUAL"), ("oracle", "SELECT 1 AS one FROM SYS.DUAL"),
     ("db2", "SELECT 1 AS one FROM SYSIBM.SYSDUMMY1")],
)
def test_the_query_tools_run_the_dummy_tables(tmp_path: Path, monkeypatch: Any, engine: str, sql: str) -> None:
    server, fake = _server(tmp_path, monkeypatch, engine, ["ocean"])
    assert _call(server, "db_query", {"connection_id": "remote", "sql": sql})["data"]["rows"] == [[2]]
    assert fake.statements == [sql]
    assert _call(server, "db_validate_query", {"connection_id": "remote", "sql": sql})["data"]["valid"] is True
    _call(server, "db_explain", {"connection_id": "remote", "sql": "EXPLAIN " + sql})
    assert fake.plans == [sql]


def test_the_policy_admits_the_dummy_tables_as_the_catalog_spells_them() -> None:
    admitted = (("oracle", "SYS", "DUAL"), ("db2", "SYSIBM", "SYSDUMMY1"), ("db2", "SYSIBM", "SYSDUMMY4"))
    for engine, schema, name in admitted:
        for allowed in ([], ["ocean"]):
            _policy(engine, allowed).check_object(schema, name)
    # compared exactly: a quoted lower-case "sys"."dual" is another object, and SYS stays closed
    for engine, schema, name in (("oracle", "sys", "dual"), ("oracle", "SYS", "OBJ$"), ("db2", "SYSIBM", "SYSTABLES")):
        with pytest.raises(ToolFailure) as info:
            _policy(engine, []).check_object(schema, name)
        assert "system schema" in str(info.value)


@pytest.mark.parametrize("deny", [True, False], ids=["default-deny", "no-default-deny"])
def test_the_metadata_tools_describe_dual_where_the_connector_lists_it(
    tmp_path: Path, monkeypatch: Any, deny: bool
) -> None:
    # the Oracle connector lists SYS.DUAL whatever the policy (connectors, 2026-09-28)
    catalog = [TableSummary("TRAVEL", "BOOKINGS", "table"), TableSummary("SYS", "DUAL", "table")]
    server, _ = _app_server(tmp_path, monkeypatch, "oracle", [], catalog, deny=deny)
    for name in ("DUAL", "SYS.DUAL"):
        columns = _call(server, "db_list_columns", {"connection_id": "remote", "object_name": name})["data"]
        assert [c["name"] for c in columns["columns"]] == ["buoy_id", "station"], name
    text = _call_error(server, "db_list_columns", {"connection_id": "remote", "object_name": "SYS.OBJ$"})
    assert "system schema" in text, text


# ---- 3. views that show other sessions' SQL text --------------------------------

_SESSION_SQL = [
    ("mysql", "information_schema", "SELECT * FROM information_schema.PROCESSLIST"),
    ("mysql", "information_schema", "SELECT info FROM INFORMATION_SCHEMA.processlist"),
    ("mysql", "performance_schema", "SELECT * FROM performance_schema.threads"),
    ("mysql", "performance_schema", "SELECT * FROM performance_schema.processlist"),
    ("mysql", "performance_schema", "SELECT sql_text FROM performance_schema.events_statements_current"),
    ("mysql", "performance_schema", "SELECT sql_text FROM performance_schema.events_statements_history_long"),
    ("mysql", "performance_schema",
     "SELECT query_sample_text FROM performance_schema.events_statements_summary_by_digest"),
    ("mysql", "performance_schema", "SELECT sql_text FROM performance_schema.prepared_statements_instances"),
    ("mysql", "sys", "SELECT * FROM sys.processlist"),
    ("mysql", "sys", "SELECT * FROM sys.x$processlist"),
    ("mysql", "sys", "SELECT * FROM sys.session"),
    ("mysql", "sys", "SELECT * FROM sys.`x$session`"),
    ("mysql", "mysql", "SELECT argument FROM mysql.general_log"),
    ("mysql", "mysql", "SELECT sql_text FROM mysql.slow_log"),
    ("postgres", "pg_catalog", "SELECT query FROM pg_catalog.pg_stat_activity"),
    ("postgres", "pg_catalog", "SELECT query FROM pg_stat_activity"),  # pg_catalog is searched first
    ("clickhouse", "system", "SELECT query FROM system.processes"),
    ("clickhouse", "system", "SELECT query FROM system.query_log"),
    ("clickhouse", "system", "SELECT query FROM system.query_log_0"),  # the copy an upgrade keeps
    ("clickhouse", "system", "SELECT query FROM system.query_thread_log"),
    ("clickhouse", "system", "SELECT message FROM system.text_log"),
    ("clickhouse", "system", "SELECT attribute FROM system.opentelemetry_span_log"),
    ("clickhouse", "system", "SELECT query FROM system.query_cache"),
    ("clickhouse", "system", "SELECT query FROM system.asynchronous_insert_log"),
    ("clickhouse", "system", "SELECT query FROM system.asynchronous_inserts"),
    ("clickhouse", "system", "SELECT query FROM system.crash_log"),
    ("clickhouse", "system", "SELECT command FROM system.mutations"),
    ("clickhouse", "system", "SELECT query FROM system.distributed_ddl_queue"),
    ("oracle", "sys", "SELECT sql_text FROM V$SQL"),
    ("oracle", "sys", "SELECT * FROM v$session"),
    ("oracle", "sys", "SELECT * FROM GV$SQLAREA"),
    ("oracle", "sys", "SELECT * FROM SYS.V_$SQL"),
    ("oracle", "sys", "SELECT * FROM SYS.GV_$SESSION"),
    ("oracle", "sys", "SELECT * FROM V$SQLTEXT_WITH_NEWLINES"),
    ("oracle", "sys", "SELECT * FROM V$SQLSTATS"),
    ("oracle", "sys", "SELECT * FROM V$OPEN_CURSOR"),
    ("oracle", "sys", "SELECT * FROM V$SQL_BIND_CAPTURE"),
    ("oracle", "sys", "SELECT * FROM V$SQL_PLAN"),
    ("oracle", "sys", "SELECT * FROM V$SQL_MONITOR"),
    ("oracle", "sys", "SELECT * FROM DBA_HIST_SQLTEXT"),
    ("oracle", "sys", "SELECT * FROM SYS.DBA_HIST_SQLBIND"),
    ("oracle", "sys", "SELECT * FROM UNIFIED_AUDIT_TRAIL"),
    ("oracle", "sys", "SELECT * FROM DBA_AUDIT_TRAIL"),
    ("mssql", "sys", "SELECT * FROM sys.dm_exec_sessions"),
    ("mssql", "sys", "SELECT * FROM sys.dm_exec_requests"),
    ("mssql", "sys", "SELECT * FROM sys.dm_exec_connections"),
    ("mssql", "sys", "SELECT * FROM sysprocesses"),  # a compatibility view: readable unqualified
    ("mssql", "sys", "SELECT * FROM sys.sysprocesses"),
    ("mssql", "sys", "SELECT query_sql_text FROM sys.query_store_query_text"),
    ("mssql", "sys", "SELECT query_plan FROM sys.query_store_plan"),
    ("mssql", "sys", "SELECT target_data FROM sys.dm_xe_session_targets"),
    ("db2", "sysibmadm", "SELECT stmt_text FROM SYSIBMADM.MON_CURRENT_SQL"),
    ("db2", "sysibmadm", "SELECT stmt_text FROM SYSIBMADM.MON_PKG_CACHE_SUMMARY"),
    ("db2", "sysibmadm", "SELECT req_stmt_text FROM SYSIBMADM.MON_LOCKWAITS"),
    ("db2", "sysibmadm", "SELECT stmt_text FROM SYSIBMADM.LONG_RUNNING_SQL"),
    ("db2", "sysibmadm", "SELECT stmt_text FROM SYSIBMADM.SNAPDYN_SQL"),
    ("db2", "sysibmadm", "SELECT stmt_text FROM SYSIBMADM.SNAPSTMT"),
    ("db2", "sysibmadm", "SELECT stmt_text FROM SYSIBMADM.SNAPSUBSECTION"),
    ("db2", "sysibmadm", "SELECT stmt_text FROM SYSIBMADM.TOP_DYNAMIC_SQL"),
    ("db2", "sysibmadm", "SELECT stmt_text FROM SYSIBMADM.QUERY_PREP_COST"),
    # fix-up round (review, 2026-09-28): the same text, or values, elsewhere. MySQL: the
    # statement of every open transaction (readable with PROCESS, like PROCESSLIST), the
    # waiting and blocking statements, locked key values, other threads' user variables,
    # and the error log (innodb_print_all_deadlocks writes both statements there)
    ("mysql", "information_schema", "SELECT trx_query FROM information_schema.INNODB_TRX"),
    ("mysql", "information_schema", "SELECT lock_data FROM information_schema.innodb_locks"),  # 5.7, MariaDB
    ("mysql", "information_schema", "SELECT statement_text FROM information_schema.QUERY_CACHE_INFO"),  # MariaDB
    ("mysql", "information_schema", "SELECT word FROM information_schema.INNODB_FT_INDEX_CACHE"),
    ("mysql", "information_schema", "SELECT word FROM information_schema.innodb_ft_index_table"),
    ("mysql", "sys", "SELECT waiting_query, blocking_query FROM sys.innodb_lock_waits"),
    ("mysql", "sys", "SELECT waiting_query FROM sys.x$innodb_lock_waits"),
    ("mysql", "sys", "SELECT waiting_query FROM sys.schema_table_lock_waits"),
    ("mysql", "sys", "SELECT waiting_query FROM sys.`x$schema_table_lock_waits`"),
    ("mysql", "performance_schema", "SELECT lock_data FROM performance_schema.data_locks"),
    ("mysql", "performance_schema", "SELECT variable_value FROM performance_schema.user_variables_by_thread"),
    ("mysql", "performance_schema", "SELECT data FROM performance_schema.error_log"),
    # ClickHouse: last_error_message quotes the failing statement (live: another session's,
    # with its literals), and a materialized view's exception the values of an INSERT
    ("clickhouse", "system", "SELECT last_error_message FROM system.errors"),
    ("clickhouse", "system", "SELECT last_error_message FROM system.error_log"),
    ("clickhouse", "system", "SELECT last_error_message FROM system.error_log_1"),
    ("clickhouse", "system", "SELECT exception FROM system.query_views_log"),
    # Oracle: audit records, SQL tuning sets, baselines, profiles, patches, advisor
    # workloads, outlines and their base tables all keep SQL_TEXT and binds
    ("oracle", "sys", "SELECT sqltext, sqlbind FROM SYS.AUD$"),
    ("oracle", "sys", "SELECT lsqltext FROM SYS.FGA_LOG$"),
    ("oracle", "audsys", "SELECT sql_text FROM AUDSYS.AUD$UNIFIED"),
    ("oracle", "sys", "SELECT sql_text, sql_bind FROM SYS.DBA_AUDIT_OBJECT"),
    ("oracle", "sys", "SELECT sql_text FROM DBA_AUDIT_STATEMENT"),
    ("oracle", "sys", "SELECT sql_text FROM DBA_AUDIT_EXISTS"),
    ("oracle", "sys", "SELECT sql_text FROM USER_AUDIT_TRAIL"),  # the account's own: every agent sharing it
    ("oracle", "sys", "SELECT sql_text FROM ALL_SQLSET_STATEMENTS"),  # readable by the fixture's travel account
    ("oracle", "sys", "SELECT value_string FROM SYS.DBA_SQLSET_BINDS"),
    ("oracle", "sys", "SELECT filter_predicates FROM USER_SQLSET_PLANS"),
    ("oracle", "sys", "SELECT sql_text FROM DBA_SQL_PLAN_BASELINES"),
    ("oracle", "sys", "SELECT sql_text FROM DBA_SQL_PROFILES"),
    ("oracle", "sys", "SELECT sql_text FROM DBA_SQL_PATCHES"),
    ("oracle", "sys", "SELECT value FROM DBA_SQLTUNE_BINDS"),
    ("oracle", "sys", "SELECT sql_text FROM USER_ADVISOR_SQLW_STMTS"),
    ("oracle", "sys", "SELECT sql_text FROM DBA_OUTLINES"),
    ("oracle", "sys", "SELECT sql_text FROM DBA_RESUMABLE"),
    ("oracle", "sys", "SELECT bind_data FROM DBA_HIST_SQLSTAT"),
    ("oracle", "sys", "SELECT report FROM DBA_HIST_REPORTS_DETAILS"),
    ("oracle", "sys", "SELECT sql_text FROM SYS.WRH$_SQLTEXT"),
    # SQL Server: the plan cache's batch text, and distributed (PolyBase, PDW) requests
    ("mssql", "sys", "SELECT sql FROM sys.syscacheobjects"),
    ("mssql", "sys", "SELECT sql FROM syscacheobjects"),
    ("mssql", "sys", "SELECT command FROM sys.dm_exec_distributed_request_steps"),
    ("mssql", "sys", "SELECT command FROM sys.dm_pdw_exec_requests"),
    # Db2: the explain and design-advisor tables EXPLAIN PLAN and db2advis fill, in whatever
    # schema they were created (the connector's db_explain writes into them)
    ("db2", "systools", "SELECT statement_text FROM SYSTOOLS.EXPLAIN_STATEMENT"),
    ("db2", "systools", "SELECT predicate_text FROM SYSTOOLS.EXPLAIN_PREDICATE"),
    ("db2", "systools", "SELECT statement_text FROM SYSTOOLS.ADVISE_WORKLOAD"),
    ("db2", "db2inst1", "SELECT statement_text FROM DB2INST1.EXPLAIN_STATEMENT"),
    # PostgreSQL extensions: utility statements kept verbatim, literals kept, and the
    # constants of other sessions' predicates
    ("postgres", "public", "SELECT query FROM public.pg_stat_statements"),
    ("postgres", "public", "SELECT query FROM pg_stat_statements"),
    ("postgres", "monitor", "SELECT query FROM monitor.pg_stat_monitor"),
    ("postgres", "public", "SELECT constvalue FROM public.pg_qualstats"),
    # fix-up round 2 (review, 2026-09-28). MySQL finds an information_schema table by a
    # name that differs in ſ, ı or İ (live, 9.7: proceſſlist read other sessions' SQL)
    ("mysql", "information_schema", "SELECT info FROM information_schema.proceſſlist"),
    ("mysql", "information_schema", "SELECT info FROM information_schema.processlıst"),
    ("mysql", "information_schema", "SELECT info FROM information_schema.PROCESSLİST"),
    ("mysql", "information_schema", "SELECT trx_query FROM information_schema.ınnodb_trx"),
    ("mysql", "performance_schema", "SELECT sql_text FROM performance_schema.events_statementſ_history"),
    # Oracle 23ai: views of other sessions' SQL text, binds and plan predicates (other_xml
    # holds the peeked binds) the unprivileged account can read (live: travel, 23ai Free)
    ("oracle", "sys", "SELECT name, value_string FROM V$ALL_SQL_BIND_CAPTURE"),
    ("oracle", "sys", "SELECT value_string FROM GV$ALL_SQL_BIND_CAPTURE"),
    ("oracle", "sys", "SELECT sql_text, binds_xml FROM GV$RECENT_SQL_MONITOR"),
    ("oracle", "sys", "SELECT sql_text FROM V$RECENT_SQL_MONITOR"),
    ("oracle", "sys", "SELECT sql_text FROM SYS.GV_$RECENT_SQL_MONITOR"),
    ("oracle", "sys", "SELECT sql_text, binds_xml FROM V$ALL_SQL_MONITOR"),
    ("oracle", "sys", "SELECT other_xml FROM V$ALL_SQL_PLAN_MONITOR"),
    ("oracle", "sys", "SELECT other_xml FROM V$SQL_PLAN_MONITOR"),
    ("oracle", "sys", "SELECT sql_text FROM V$SQL_HISTORY"),
    ("oracle", "sys", "SELECT sql_text FROM GV$SQL_HISTORY"),
    ("oracle", "sys", "SELECT filter_predicates FROM V$ADVISOR_CURRENT_SQLPLAN"),
    # and, to an account with the catalog role (as V$SQL), the cursor text of the object
    # cache and shared-memory views, audit and trace records, and the undo SQL (the row
    # values) of other transactions (Oracle Database Reference)
    ("oracle", "sys", "SELECT name FROM V$DB_OBJECT_CACHE"),
    ("oracle", "sys", "SELECT sql_text FROM V$SQL_SHARED_MEMORY"),
    ("oracle", "sys", "SELECT sql_text FROM V$SQLSTATS_PLAN_HASH"),
    ("oracle", "sys", "SELECT sql_text, sql_binds FROM V$UNIFIED_AUDIT_TRAIL"),
    ("oracle", "sys", "SELECT sql_text, sql_bind FROM V$XML_AUDIT_TRAIL"),
    ("oracle", "sys", "SELECT payload FROM V$DIAG_SQL_TRACE_RECORDS"),
    ("oracle", "sys", "SELECT payload FROM V$DIAG_OPT_TRACE_RECORDS"),
    ("oracle", "sys", "SELECT undo_sql FROM FLASHBACK_TRANSACTION_QUERY"),
    ("oracle", "sys", "SELECT attr4 FROM USER_ADVISOR_OBJECTS"),
    ("oracle", "sys", "SELECT attr4 FROM SYS.DBA_ADVISOR_OBJECTS"),
]


def _opened(engine: str, schema: str, sql: str, allowed: list[str], deny: bool) -> SqlGuard:
    """A guard whose policy opens the view's schema and whose resolver lists
    every table the statement names, in that schema: nothing but the new
    rule stands between the caller and the view."""
    from sqlglot import exp, parse_one

    from universal_db_mcp.security.sql_guard import sqlglot_dialect

    tables = {(schema, t.name.lower()) for t in parse_one(sql, read=sqlglot_dialect(engine)).find_all(exp.Table)}
    policy = _policy(engine, allowed, deny=deny, system_schemas=[schema])
    return SqlGuard(engine, policy, StaticResolver(tables | {("app", "t")}))


@pytest.mark.parametrize(
    ("allowed", "deny"),
    [(["app"], True), (["app"], False), ([], True), ([], False)],
    ids=["allowlist-default-deny", "allowlist", "default-deny", "neither"],
)
@pytest.mark.parametrize(("engine", "schema", "sql"), _SESSION_SQL)
def test_views_of_other_sessions_sql_are_always_refused(
    engine: str, schema: str, sql: str, allowed: list[str], deny: bool
) -> None:
    guard = _opened(engine, schema, sql, allowed, deny)
    for label, validate, prefix in _entries(guard):
        exc = _refused(validate, prefix + sql)
        assert exc.category == ErrorCategory.POLICY, (label, str(exc))
        assert "other sessions' SQL" in str(exc) and "allowed_system_schemas" in str(exc), (label, str(exc))


@pytest.mark.parametrize(
    ("engine", "schema", "sql"),
    [
        ("mysql", "information_schema", "SELECT * FROM information_schema.TABLES"),
        ("mysql", "performance_schema", "SELECT * FROM performance_schema.global_status"),
        ("mysql", "sys", "SELECT * FROM sys.version"),
        ("postgres", "pg_catalog", "SELECT relname FROM pg_catalog.pg_class"),
        ("postgres", "pg_catalog", "SELECT relname FROM pg_catalog.pg_stat_user_tables"),
        ("clickhouse", "system", "SELECT name FROM system.tables"),
        ("clickhouse", "system", "SELECT dummy FROM system.one"),
        ("clickhouse", "system", "SELECT query FROM system.projections"),  # definitions only
        ("clickhouse", "system", "SELECT name, value FROM system.events"),
        ("mysql", "information_schema", "SELECT * FROM information_schema.INNODB_METRICS"),
        ("oracle", "sys", "SELECT query FROM SYS.ALL_MVIEWS"),  # definitions only
        ("db2", "systools", "SELECT * FROM SYSTOOLS.EXPLAIN_OPERATOR"),
        ("postgres", "public", "SELECT * FROM public.pg_stat_statements_info"),
        ("oracle", "sys", "SELECT table_name FROM SYS.ALL_TABLES"),
        ("oracle", "sys", "SELECT banner FROM SYS.V_$VERSION"),
        ("oracle", "sys", "SELECT statistic, last_query FROM SYS.V_$PQ_SESSTAT"),  # a count, named like a query
        ("oracle", "sys", "SELECT sql_id, in_bind FROM SYS.V_$ALL_ACTIVE_SESSION_HISTORY"),  # ids and flags only
        ("mssql", "sys", "SELECT name FROM sys.tables"),
        ("mssql", "sys", "SELECT * FROM sys.dm_db_index_usage_stats"),
        ("db2", "sysibmadm", "SELECT * FROM SYSIBMADM.ENV_INST_INFO"),
        ("db2", "sysibmadm", "SELECT * FROM SYSIBMADM.DBCFG"),
    ],
)
def test_the_rest_of_an_opened_system_schema_stays_readable(engine: str, schema: str, sql: str) -> None:
    guard = _opened(engine, schema, sql, ["app"], True)
    assert guard.validate_select(sql).kind == "select"


@pytest.mark.parametrize(("engine", "schema", "sql"), _SESSION_SQL)
def test_the_policy_refuses_them_to_every_tool(engine: str, schema: str, sql: str) -> None:
    from sqlglot import exp, parse_one

    from universal_db_mcp.security.sql_guard import sqlglot_dialect

    table = next(parse_one(sql, read=sqlglot_dialect(engine)).find_all(exp.Table))
    policy = _policy(engine, [], system_schemas=[schema])
    for written in {table.db or schema, schema}:
        assert is_session_sql_view(engine, written, table.name), (written, table.name)
        with pytest.raises(ToolFailure) as info:
            policy.check_object(written, table.name)
        assert info.value.category == ErrorCategory.POLICY


@pytest.mark.parametrize(
    ("engine", "schema", "name"),
    [
        ("mysql", "app", "processlist"),  # a user table of that name, qualified
        ("mysql", None, "processlist"),  # bare: MySQL binds it to the connection's database
        ("clickhouse", "app", "processes"),
        ("clickhouse", None, "query_log"),
        ("mssql", "dbo", "dm_exec_sessions"),
        ("db2", "APP", "MON_CURRENT_SQL"),
        ("postgres", "app", "pg_stat_activity"),
        ("sqlite", None, "pg_stat_activity"),
        ("mysql", "app", "innodb_trx"),
        ("clickhouse", "app", "errors"),
        ("mssql", "app", "syscacheobjects"),
        ("oracle", "TRAVEL", "AUDIT_TRAIL"),
    ],
)
def test_namesakes_elsewhere_are_ordinary_tables(engine: str, schema: str | None, name: str) -> None:
    assert not is_session_sql_view(engine, schema, name)


def test_they_are_left_out_of_listings_and_refused_by_the_metadata_tools(tmp_path: Path, monkeypatch: Any) -> None:
    catalog = [
        TableSummary("ocean", "buoys", "table"),
        TableSummary("system", "tables", "table"),
        TableSummary("system", "processes", "table"),
        TableSummary("system", "query_log", "table"),
    ]
    server, fake = _app_server(
        tmp_path, monkeypatch, "clickhouse", ["ocean"], catalog,
        security="  allowed_system_schemas: [information_schema, system]\n",
    )
    for _ in range(2):  # the second listing comes from the metadata cache
        tables = _call(server, "db_list_tables", {"connection_id": "remote", "schema": "system"})
        assert [t["name"] for t in tables["data"]["tables"]] == ["tables"]
    for tool, args in (
        ("db_query", {"connection_id": "remote", "sql": "SELECT query FROM system.processes"}),
        ("db_sample_table", {"connection_id": "remote", "object_name": "system.query_log"}),
        ("db_profile_table", {"connection_id": "remote", "schema": "system", "object_name": "processes"}),
    ):
        text = _call_error(server, tool, args)
        assert "POLICY_VIOLATION" in text and "other sessions' SQL" in text, (tool, text)
    _call(server, "db_search_values", {"query": "north", "schemas": ["system"]})
    assert not [s for s in fake.statements if "processes" in s or "query_log" in s], fake.statements


# ---- 4. review polish --------------------------------------------------------------


@pytest.mark.parametrize("deny", [True, False], ids=["default-deny", "no-default-deny"])
def test_show_tables_from_gets_the_schema_case_check(deny: bool) -> None:
    # SHOW COLUMNS FROM TESTDB.cuppings was refused while SHOW TABLES FROM TESTDB was valid
    guard = _listed_guard("mysql", ["testdb"], [("testdb", "cuppings")], deny=deny)
    for sql in ("SHOW TABLES FROM TESTDB", "SHOW COLUMNS FROM TESTDB.cuppings"):
        exc = _refused(guard.validate_any, sql)
        assert exc.category == ErrorCategory.AUTHZ and "differ only in case" in str(exc), (sql, str(exc))
    assert str(_refused(guard.validate_any, "SHOW TABLES FROM TESTDB")).endswith("write testdb")
    assert guard.validate_any("SHOW TABLES FROM testdb").kind == "show"


@pytest.mark.parametrize("deny", [True, False], ids=["default-deny", "no-default-deny"])
def test_clickhouse_information_schema_is_one_schema_in_both_cases(deny: bool) -> None:
    # ClickHouse serves the same views as INFORMATION_SCHEMA.TABLES and information_schema.tables
    tables = [("telecom", "subscribers"), ("information_schema", "tables"), ("INFORMATION_SCHEMA", "TABLES")]
    guard = _listed_guard("clickhouse", ["telecom"], tables, deny=deny)
    for sql in ("SELECT count() AS n FROM INFORMATION_SCHEMA.TABLES",
                "SELECT count() AS n FROM information_schema.tables"):
        assert guard.validate_select(sql).kind == "select", sql
    # any other schema keeps its case
    assert "differ only in case" in str(_refused(guard.validate_select, "SELECT * FROM Telecom.subscribers"))


@pytest.mark.parametrize(
    ("engine", "entries", "listed", "shadowed"),
    [
        # a lower-case entry keeps the conventional upper-case Oracle / Db2 schema
        ("oracle", ["travel"], ["TRAVEL", "travel"], {"travel"}),
        ("db2", ["moi"], ["MOI", "moi"], {"moi"}),
        # and an upper-case one PostgreSQL's lower-case schema
        ("postgres", ["OCEAN"], ["ocean", "OCEAN"], {"OCEAN"}),
        # a mixed-case entry names its exact spelling first (11: review, 2026-09-28)
        ("postgres", ["Ocean"], ["ocean", "Ocean"], {"ocean"}),
        ("oracle", ["Travel"], ["TRAVEL", "Travel"], {"TRAVEL"}),
        ("db2", ["Moi"], ["MOI", "Moi", "moi"], {"MOI", "moi"}),
        # and the folded one where the catalog does not hold it written so
        ("postgres", ["Ocean"], ["ocean", "OCEAN"], {"OCEAN"}),
        ("oracle", ["Travel"], ["TRAVEL", "travel"], {"travel"}),
        # the exact spelling where the catalog does not hold the folded one
        ("postgres", ["Ocean"], ["Ocean", "OCEAN"], {"OCEAN"}),
        ("oracle", ["Travel"], ["Travel", "travel"], {"travel"}),
        ("oracle", ["travel"], ["Travel", "travel"], {"Travel"}),
        # the other spelling as well, next to an entry written as the folded one
        ("oracle", ["TRAVEL", "travel"], ["TRAVEL", "travel"], set()),
        ("postgres", ["ocean", "Ocean"], ["ocean", "Ocean"], set()),
        ("db2", ["MOI", "moi"], ["MOI", "moi", "Moi"], {"Moi"}),
    ],
)
def test_an_entry_admits_the_spelling_the_engine_folds_it_to_first(
    engine: str, entries: list[str], listed: list[str], shadowed: set[str]
) -> None:
    assert _policy(engine, entries).shadowed_spellings(listed) == shadowed


@pytest.mark.parametrize("deny", [True, False], ids=["default-deny", "no-default-deny"])
def test_a_lower_case_oracle_entry_reads_the_upper_case_schema(deny: bool) -> None:
    # the review's p_eng.py: catalog OCEAN.BUOYS and a quoted "ocean".SECRETS, allowlist [ocean]
    guard = _listed_guard("oracle", ["ocean"], [("OCEAN", "BUOYS"), ("ocean", "SECRETS")], deny=deny)
    assert guard.validate_select("SELECT * FROM ocean.buoys").kind == "select"
    assert guard.validate_select("SELECT * FROM OCEAN.BUOYS").kind == "select"
    text = str(_refused(guard.validate_select, 'SELECT * FROM "ocean".secrets'))
    assert "differ only in case" in text and text.endswith("write OCEAN.secrets"), text
    assert str(_refused(guard.validate_select, "SELECT * FROM buoys")).endswith("write OCEAN.buoys")


@pytest.mark.parametrize("owner", ["AURORA$JIS$UTILITY$", "AURORA$ORB$UNAUTHENTICATED", "OSE$HTTP$ADMIN", "TRACESVR"])
def test_the_9i_oracle_owners_are_system_schemas(owner: str) -> None:
    assert is_listed_system_schema("oracle", owner)
    assert _policy("oracle", []).is_system_schema(owner)


def test_db_explain_analyze_says_it_never_executes(tmp_path: Path, monkeypatch: Any) -> None:
    # with the flag on the call reached the connector, which answered
    # CAPABILITY_UNSUPPORTED "EXPLAIN ANALYZE is policy-disabled"
    catalog = [TableSummary("ocean", "buoys", "table")]
    sql = "EXPLAIN SELECT buoy_id FROM ocean.buoys"
    for flag, category in (("true", "VALIDATION_ERROR"), ("false", "POLICY_VIOLATION")):
        server, fake = _app_server(
            tmp_path, monkeypatch, "postgres", ["ocean"], catalog, security=f"  allow_explain_analyze: {flag}\n"
        )
        text = _call_error(server, "db_explain", {"connection_id": "remote", "sql": sql, "analyze": True})
        assert category in text and "policy-disabled" not in text, (flag, text)
        if flag == "true":
            assert "plans are captured without executing the statement" in text, text
        assert fake.plans == []
        limitations = _call(server, "db_validate_query", {"connection_id": "remote", "sql": sql[8:]})["data"][
            "limitations"
        ]
        assert any("without executing" in lim and "EXPLAIN ANALYZE" in lim for lim in limitations), (flag, limitations)
        _call(server, "db_explain", {"connection_id": "remote", "sql": sql})
        assert fake.plans == [sql[8:]]



# ---- 5. ClickHouse binds a CTE's name its own way ---------------------------------
# Live on ClickHouse 26.3.3.20, in database system (whose table one holds a single
# row, dummy = 0), with literals only:
#   WITH RECURSIVE one AS (SELECT * FROM one) SELECT * FROM one            -> [0]: the table
#   WITH RECURSIVE one AS (SELECT 5 AS dummy UNION ALL
#                          SELECT dummy + 1 FROM one WHERE dummy < 7) ...  -> [5, 6, 7]
#   ... (SELECT dummy + 1 AS dummy FROM one UNION ALL SELECT 5 ...)        -> [1, 5]: the anchor reads the table
#   ... (SELECT * FROM (SELECT 5 AS dummy UNION ALL SELECT dummy + 1 FROM one ...))  -> [5, 1]
#   WITH a AS (SELECT dummy FROM one), one AS (SELECT 42 AS dummy) SELECT * FROM a  -> [42]: a later CTE
#   WITH one AS (SELECT dummy FROM b), b AS (SELECT dummy + 1 AS dummy FROM one)
#     SELECT * FROM one -> [1] (b read the table one); SELECT * FROM b -> UNKNOWN_TABLE b
#   WITH RECURSIVE one AS (<the recursion>) SELECT 'x', * FROM one UNION ALL SELECT 'y', * FROM one
#     -> x: 5, 6, 7; y: 5, 1 (the later branch gets a copy of the WITH without RECURSIVE)
#   (WITH one AS ... SELECT 'x' ...) UNION ALL SELECT 'y', * FROM one      -> y reads the copy too
#   (WITH one AS ... SELECT 'x' ... UNION ALL SELECT 'y' ...) UNION ALL SELECT 'z', * FROM one  -> z: the table
#   SELECT 'a', 1 UNION ALL WITH one AS (SELECT 42 AS dummy) SELECT 'b', * FROM one
#     UNION ALL SELECT 'c', * FROM one -> b: 42, c: 0 (sqlglot hangs the WITH over c as well)
# payroll is not a permitted object; ClickHouse reads the table of that name in each of these
_CH_TABLE_READS = [
    "WITH RECURSIVE payroll AS (SELECT * FROM payroll) SELECT * FROM payroll",
    "WITH payroll AS (SELECT * FROM payroll) SELECT * FROM payroll",
    "WITH RECURSIVE c AS (SELECT * FROM payroll), payroll AS (SELECT * FROM payroll) SELECT * FROM c",
    "WITH RECURSIVE payroll AS (SELECT * FROM (SELECT * FROM payroll)) SELECT * FROM payroll",
    # the anchor, and a UNION ALL that is not the body itself
    "WITH RECURSIVE payroll AS (SELECT id FROM payroll UNION ALL SELECT id + 1 FROM payroll WHERE id < 3)"
    " SELECT id FROM payroll",
    "WITH RECURSIVE payroll AS (SELECT 1 AS id WHERE 1 IN (SELECT id FROM payroll)"
    " UNION ALL SELECT id + 1 FROM payroll WHERE id < 3) SELECT id FROM payroll",
    "WITH RECURSIVE payroll AS (SELECT * FROM (SELECT 1 AS id UNION ALL SELECT id + 1 FROM payroll WHERE id < 3))"
    " SELECT id FROM payroll",
    # no RECURSIVE, or a recursion ClickHouse does not run (UNION DISTINCT)
    "WITH payroll AS (SELECT 1 AS id UNION ALL SELECT id + 1 FROM payroll WHERE id < 3) SELECT id FROM payroll",
    "WITH RECURSIVE payroll AS (SELECT 1 AS id UNION DISTINCT SELECT id + 1 FROM payroll WHERE id < 3)"
    " SELECT id FROM payroll",
    # names are case-sensitive, and a value's alias names no table
    "WITH RECURSIVE PAYROLL AS (SELECT 1 AS id UNION ALL SELECT id + 1 FROM payroll WHERE id < 3)"
    " SELECT id FROM PAYROLL",
    "WITH (SELECT 1) AS payroll SELECT * FROM payroll",
    "WITH RECURSIVE r AS (SELECT 1 AS id UNION ALL SELECT id + 1 FROM r WHERE id < 3),"
    " payroll AS (SELECT * FROM payroll) SELECT * FROM payroll",
    "WITH payroll AS (SELECT * FROM (WITH x AS (SELECT * FROM payroll) SELECT * FROM x)) SELECT * FROM payroll",
    # a WITH covers the set operation it heads, or the SELECT it precedes, and no further
    "(WITH payroll AS (SELECT 1 AS id) SELECT id FROM payroll UNION ALL SELECT id FROM payroll)"
    " UNION ALL SELECT id FROM payroll",
    "SELECT 1 AS id UNION ALL (WITH payroll AS (SELECT 1 AS id) SELECT id FROM payroll)"
    " UNION ALL SELECT id FROM payroll",
]
_CH_POLICIES = [(True, []), (True, ["app"]), (False, ["app"])]


def _qualified(sql: str, allowed: list[str]) -> str:
    # under an allowlist the permitted table is written qualified; a CTE's name stays bare
    return re.sub(r"\bFROM customers\b", "FROM app.customers", sql) if allowed else sql


@pytest.mark.parametrize(("deny", "allowed"), _CH_POLICIES)
@pytest.mark.parametrize("sql", _CH_TABLE_READS)
def test_clickhouse_reads_a_table_where_a_cte_does_not_cover_its_name(
    tmp_path: Path, monkeypatch: Any, deny: bool, allowed: list[str], sql: str
) -> None:
    """The review's repro: POLICY_VIOLATION for SELECT * FROM payroll, while
    WITH RECURSIVE payroll AS (SELECT * FROM payroll) reached the engine."""
    category = "AUTHORIZATION_DENIED" if allowed else "POLICY_VIOLATION"
    fake = _StatementFake("clickhouse")
    server, _ = _fake_app_server(tmp_path, monkeypatch, fake, engine="clickhouse", allowed=allowed, deny=deny)
    for tool in ("db_query", "db_validate_query"):
        text = _call_error(server, tool, {"connection_id": "remote", "sql": sql})
        assert category in text and "'payroll'" in text.lower(), (tool, text)
    env = _call(server, "db_federated_query", {"sql": sql, "connections": ["remote"]})
    assert category in env["data"]["results"][0]["error"], env
    assert fake.statements == []
    # the guard on its own, before the server's scope check
    exc = _refused(_guard("clickhouse", allowed, {("app", "customers")}, deny=deny).validate_select, sql)
    assert exc.category == category and "'payroll'" in str(exc).lower(), str(exc)


def test_clickhouse_names_the_table_a_cte_does_not_cover() -> None:
    guard = _guard("clickhouse", [], None, deny=False)
    result = guard.validate_select("WITH RECURSIVE payroll AS (SELECT * FROM payroll) SELECT * FROM payroll")
    assert [(r.schema, r.name) for r in result.tables] == [(None, "payroll")]
    exc = _refused(
        _guard("clickhouse", [], {("app", "customers")}).validate_select,
        "WITH payroll AS (SELECT * FROM payroll) SELECT * FROM payroll",
    )
    assert "a CTE of that name does not cover this reference" in str(exc), str(exc)


_CH_REFUSED = [
    # CTEs naming each other: which one reads a table depends on where ClickHouse starts
    ("WITH a AS (SELECT id FROM b), b AS (SELECT id FROM a) SELECT id FROM a", "name each other"),
    ("WITH a AS (SELECT id FROM b), b AS (SELECT id FROM c), c AS (SELECT id FROM a) SELECT id FROM c",
     "name each other"),
    ("WITH a AS (SELECT id FROM b), b AS (SELECT id FROM (WITH x AS (SELECT id FROM a) SELECT id FROM x))"
     " SELECT id FROM a", "name each other"),
    ("WITH RECURSIVE t AS (SELECT id FROM customers UNION ALL SELECT id + 1 FROM b WHERE id < 3),"
     " b AS (SELECT id FROM t) SELECT id FROM t", "name each other"),
    # WITH RECURSIVE heading a set operation recurses in its first branch only
    ("WITH RECURSIVE t AS (SELECT id FROM customers UNION ALL SELECT id + 1 FROM t WHERE id < 3)"
     " SELECT id FROM t UNION ALL SELECT id FROM t", "recurses only in the first branch"),
    ("WITH RECURSIVE t AS (SELECT id FROM customers UNION ALL SELECT id + 1 FROM t WHERE id < 3)"
     " SELECT id FROM t EXCEPT SELECT id FROM t", "recurses only in the first branch"),
    ("SELECT * FROM (WITH RECURSIVE t AS (SELECT id FROM customers UNION ALL SELECT id + 1 FROM t WHERE id < 3)"
     " SELECT id FROM t INTERSECT SELECT id FROM t)", "recurses only in the first branch"),
    # a WITH in parentheses at the start of a set operation covers the branches after them
    ("(WITH t AS (SELECT id FROM customers) SELECT id FROM t) UNION ALL SELECT id FROM t", "in parentheses"),
    ("((WITH t AS (SELECT id FROM customers) SELECT id FROM t) UNION ALL SELECT id FROM t)"
     " UNION ALL SELECT id FROM t", "in parentheses"),
    ("SELECT * FROM ((WITH t AS (SELECT id FROM customers) SELECT id FROM t) UNION ALL SELECT id FROM t)",
     "in parentheses"),
    # a WITH after a set operator: sqlglot hangs it over the branches after its SELECT
    ("SELECT id FROM customers UNION ALL WITH t AS (SELECT 1 AS id) SELECT id FROM t UNION ALL SELECT id FROM t",
     "after UNION, INTERSECT or EXCEPT"),
]


@pytest.mark.parametrize(("deny", "allowed"), [*_CH_POLICIES, (False, [])])
@pytest.mark.parametrize(("sql", "reason"), _CH_REFUSED)
def test_clickhouse_refuses_ctes_it_binds_by_resolution_order(
    tmp_path: Path, monkeypatch: Any, deny: bool, allowed: list[str], sql: str, reason: str
) -> None:
    sql = _qualified(sql, allowed)
    fake = _StatementFake("clickhouse")
    server, _ = _fake_app_server(tmp_path, monkeypatch, fake, engine="clickhouse", allowed=allowed, deny=deny)
    for tool in ("db_query", "db_validate_query"):
        text = _call_error(server, tool, {"connection_id": "remote", "sql": sql})
        assert "POLICY_VIOLATION" in text and reason in text, (tool, text)
    assert fake.statements == []


@pytest.mark.parametrize("engine", [*REMOTE, "sqlite"])
def test_a_with_after_a_set_operator_is_refused_on_every_engine(engine: str) -> None:
    """The engines but ClickHouse reject the text; sqlglot reads it as covering
    the branches after the SELECT it precedes, which ClickHouse does not."""
    sql = "SELECT 1 AS id UNION ALL WITH t AS (SELECT 2 AS id) SELECT id FROM t UNION ALL SELECT id FROM t"
    for deny in (True, False):
        exc = _refused(_guard(engine, [], None, deny=deny).validate_select, sql)
        assert exc.category == ErrorCategory.POLICY and "after UNION, INTERSECT or EXCEPT" in str(exc), str(exc)
    # in parentheses it covers what it says on every engine
    _guard(engine, [], None, deny=False).validate_select(
        "SELECT 1 AS id UNION ALL (WITH t AS (SELECT 2 AS id) SELECT id FROM t UNION ALL SELECT id FROM t)"
    )


_CH_CTES = [
    "WITH RECURSIVE t AS (SELECT id FROM customers UNION ALL SELECT id + 1 FROM t WHERE id < 3) SELECT id FROM t",
    "WITH RECURSIVE t AS ((SELECT id FROM customers) UNION ALL (SELECT id + 1 FROM t WHERE id < 3)) SELECT id FROM t",
    "WITH RECURSIVE t AS (SELECT id FROM customers UNION ALL"
    " (SELECT id + 1 FROM t WHERE id < 3 UNION ALL SELECT id + 2 FROM t WHERE id < 2)) SELECT id FROM t",
    "WITH RECURSIVE t AS ((SELECT id FROM customers UNION ALL SELECT id + 1 FROM t WHERE id < 3)"
    " UNION ALL SELECT id + 10 FROM t WHERE id < 5) SELECT id FROM t",
    "WITH RECURSIVE t AS (SELECT id FROM customers UNION ALL SELECT id + 1 FROM (SELECT id FROM t) d WHERE id < 3)"
    " SELECT id FROM t",
    "WITH RECURSIVE t AS (SELECT id FROM customers UNION ALL"
    " SELECT id + 1 FROM t WHERE id < 3 AND id IN (SELECT id FROM t)) SELECT id FROM t",
    # a CTE of the same name inside the branch is skipped as ClickHouse resolves it: the recursion
    "WITH RECURSIVE t AS (SELECT id FROM customers UNION ALL"
    " SELECT * FROM (WITH t AS (SELECT id + 1 AS id FROM t WHERE id < 3) SELECT id FROM t)) SELECT id FROM t",
    "WITH RECURSIVE t AS (SELECT id FROM customers UNION ALL SELECT id + 1 FROM t WHERE id < 3)"
    " SELECT id FROM (SELECT id FROM t UNION ALL SELECT id FROM t) d",
    "WITH RECURSIVE t AS (SELECT id FROM customers) SELECT id FROM t UNION ALL SELECT id FROM t",
    # a CTE sees the ones declared after it
    "WITH a AS (SELECT id FROM b), b AS (SELECT id FROM customers) SELECT id FROM a",
    "WITH RECURSIVE a AS (SELECT id FROM b), b AS (SELECT id FROM customers) SELECT id FROM a",
    "WITH a AS (SELECT id FROM b), b AS (SELECT id FROM c), c AS (SELECT id FROM customers) SELECT id FROM a",
    # a WITH heading a set operation covers every branch; one after a set operator, its own SELECT
    "WITH t AS (SELECT id FROM customers) SELECT id FROM t UNION ALL SELECT id FROM t",
    "SELECT id FROM customers UNION ALL WITH t AS (SELECT id FROM customers) SELECT id FROM t",
    "SELECT id FROM customers UNION ALL (WITH t AS (SELECT id FROM customers) SELECT id FROM t UNION ALL"
    " SELECT id FROM t)",
]


@pytest.mark.parametrize("allowed", [[], ["app"]])
@pytest.mark.parametrize("sql", _CH_CTES)
def test_clickhouse_ctes_in_reach_stay_ctes_under_default_deny(
    tmp_path: Path, monkeypatch: Any, allowed: list[str], sql: str
) -> None:
    sql = _qualified(sql, allowed)
    fake = _StatementFake("clickhouse")
    server, _ = _fake_app_server(tmp_path, monkeypatch, fake, engine="clickhouse", allowed=allowed, deny=True)
    env = _call(server, "db_validate_query", {"connection_id": "remote", "sql": sql})
    assert env["data"]["valid"] is True
    assert {r["name"] for r in env["data"]["referenced_objects"]} == {"customers"}, env["data"]
    _call(server, "db_query", {"connection_id": "remote", "sql": sql})
    assert fake.statements == [sql]


@pytest.mark.parametrize("sql", [*_CH_TABLE_READS, *_CH_CTES])
def test_the_guard_and_the_server_bind_clickhouse_ctes_alike(sql: str) -> None:
    """The guard checks as tables exactly the names the server finds no CTE
    in reach for, so the output walk binds each FROM item as both did."""
    result = _guard("clickhouse", [], None, deny=False).validate_select(sql)
    ctes = {cte.alias_or_name.lower() for cte in result.ast.find_all(exp.CTE)}
    checked = {r.name for r in result.tables if r.schema is None and r.name.lower() in ctes}
    assert {t.name for t in srv._cte_hidden_tables("clickhouse", result.ast)} == checked, sql


@pytest.mark.parametrize(
    ("sql", "columns"),
    [
        ("WITH a AS (SELECT * FROM zz), zz AS (SELECT ssn FROM customers) SELECT * FROM a", ["c"]),
        ("WITH a AS (SELECT zz.* FROM zz), zz AS (SELECT ssn FROM customers) SELECT a.* FROM a", ["c"]),
        ("WITH a AS (SELECT n FROM zz), zz AS (SELECT ssn AS n FROM customers) SELECT n FROM a", ["n"]),
    ],
)
def test_clickhouse_a_cte_naming_a_later_one_reads_but_is_masked_whole(
    tmp_path: Path, monkeypatch: Any, sql: str, columns: list[str]
) -> None:
    """The walk (sqlglot) sees only the CTEs before, and took zz for a base
    table with clean columns: the value came back unmasked."""
    fake = _AnswerFake(columns, [SECRETS[0]])
    server, _ = _fake_app_server(tmp_path, monkeypatch, fake, engine="clickhouse", allowed=[], deny=True)
    env = _call(server, "db_query", {"connection_id": "remote", "sql": sql})
    assert env["data"]["rows"] == [["<masked>"]], env
    assert any("could not all be traced" in w for w in env["warnings"]), env["warnings"]


def test_clickhouse_a_recursion_the_walk_binds_like_the_engine_stays_readable(
    tmp_path: Path, monkeypatch: Any
) -> None:
    sql = (
        "WITH RECURSIVE t AS (SELECT full_name AS a, 0 AS n FROM customers"
        " UNION ALL SELECT a, n + 1 AS n FROM t WHERE n < 1) SELECT a FROM t"
    )
    fake = _AnswerFake(["a"], ["Jane"])
    server, _ = _fake_app_server(tmp_path, monkeypatch, fake, engine="clickhouse", allowed=[], deny=True)
    assert _call(server, "db_query", {"connection_id": "remote", "sql": sql})["data"]["rows"] == [["Jane"]]


@pytest.mark.parametrize("shape", ["chain", "wide", "union", "recursion"])
def test_the_clickhouse_cte_scopes_are_read_in_linear_time(monkeypatch: Any, shape: str) -> None:
    """Thousands of CTEs each named by the next (or all by one FROM, or one by
    every branch of a long UNION or recursion): a walk up the tree is shared,
    not repeated per reference."""
    n = 1500
    if shape == "chain":
        body = ", ".join(["c0 AS (SELECT 1 AS a)", *(f"c{i} AS (SELECT a FROM c{i - 1})" for i in range(1, n))])
        sql = f"WITH {body} SELECT a FROM c{n - 1}"
    elif shape == "wide":
        sql = "WITH " + ", ".join(f"c{i} AS (SELECT 1 AS a)" for i in range(n))
        sql += " SELECT a FROM " + ", ".join(f"c{i}" for i in range(n))
    elif shape == "union":
        sql = "WITH c AS (SELECT 1 AS a) " + " UNION ALL ".join(["SELECT a FROM c"] * n)
    else:
        sql = "WITH RECURSIVE c AS (SELECT 1 AS a UNION ALL " + " UNION ALL ".join(["SELECT a FROM c"] * n) + ")"
        sql += " SELECT a FROM c"
    assert len(sql) <= sql_guard._MAX_SQL_BYTES
    nodes = sum(1 for _ in sqlglot.parse_one(sql, read="clickhouse").walk())

    class Steps(dict[tuple[int, str], Any]):
        """The walk's memo, counting what the walk asks of it and records."""

        count = 0

        def __contains__(self, key: object) -> bool:
            self.count += 1
            return super().__contains__(key)

        def __setitem__(self, key: tuple[int, str], value: Any) -> None:
            self.count += 1
            super().__setitem__(key, value)

    steps = Steps()
    binding = sql_guard._clickhouse_binding

    def walked(table: exp.Table, name: str, declared: Any, branch_of: Any, _memo: Any) -> Any:
        return binding(table, name, declared, branch_of, steps)

    monkeypatch.setattr(sql_guard, "_clickhouse_binding", walked)
    result = _guard("clickhouse", [], None, deny=False).validate_select(sql)
    assert result.tables == []
    assert steps.count <= 4 * nodes, (steps.count, nodes)


# ---- 6. a schema argument against the whole schema list ---------------------------


@pytest.mark.parametrize("deny", [True, False], ids=["default-deny", "no-default-deny"])
@pytest.mark.parametrize(
    ("engine", "schemas", "namesake"),
    [
        # PostgreSQL: "Ocean" holds only a partitioned parent, which the listing leaves out
        ("postgres", ["ocean", "Ocean", "parts"], "Ocean"),
        ("postgres", ["ocean", "OCEAN"], "OCEAN"),
        # SQL Server under a case-sensitive collation, the same
        ("mssql", ["dbo", "ocean", "Ocean"], "Ocean"),
        # Oracle: a quoted lower-case namesake of the conventional upper-case schema
        ("oracle", ["OCEAN", "ocean"], "ocean"),
    ],
)
@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("db_sample_table", {"object_name": "secrets"}),
        ("db_profile_table", {"object_name": "secrets"}),
        ("db_list_columns", {"object_name": "secrets"}),
        ("db_get_table", {"object_name": "secrets"}),
        ("db_list_tables", {}),
        ("db_list_indexes", {}),
    ],
)
def test_a_namesake_the_listing_leaves_out_is_refused_to_the_metadata_tools(
    tmp_path: Path,
    monkeypatch: Any,
    deny: bool,
    engine: str,
    schemas: list[str],
    namesake: str,
    tool: str,
    args: dict[str, Any],
) -> None:
    """Live on PostgreSQL (review, 2026-09-28): db_query refused "Ocean".secrets
    as a case namesake, while db_sample_table {schema: 'Ocean'} returned its row
    with default-deny off; db_list_schemas already hid it."""
    ocean = "OCEAN" if engine == "oracle" else "ocean"
    catalog = [TableSummary(ocean, "buoys", "table")]
    server, fake = _app_server(tmp_path, monkeypatch, engine, ["ocean"], catalog, deny=deny)
    fake.list_schemas = lambda _catalog, _search: list(schemas)
    text = _call_error(server, tool, {"connection_id": "remote", "schema": namesake, **args})
    assert "AUTHORIZATION_DENIED" in text and "differ only in case" in text, text
    assert fake.statements == [] and fake.listed == []
    if "object_name" in args:
        dotted = {"object_name": f'"{namesake}".secrets' if engine != "mssql" else f"[{namesake}].secrets"}
        text = _call_error(server, tool, {"connection_id": "remote", **dotted})
        assert "AUTHORIZATION_DENIED" in text, text
    # the permitted spelling still reads, and so does any spelling where the catalog holds one
    _call(server, "db_list_columns", {"connection_id": "remote", "schema": ocean, "object_name": "buoys"})
    visible = _call(server, "db_list_schemas", {"connection_id": "remote"})["data"]["schemas"]
    assert namesake not in visible and ocean in visible, visible


@pytest.mark.parametrize("deny", [True, False], ids=["default-deny", "no-default-deny"])
def test_a_schema_the_catalog_holds_in_one_spelling_is_named_in_any_case(
    tmp_path: Path, monkeypatch: Any, deny: bool
) -> None:
    # Oracle's conventional upper-case schema, named in lower case by an agent
    catalog = [TableSummary("OCEAN", "BUOYS", "table")]
    server, fake = _app_server(tmp_path, monkeypatch, "oracle", ["ocean"], catalog, deny=deny)
    fake.list_schemas = lambda _catalog, _search: ["OCEAN", "TRAVEL"]
    _call(server, "db_list_tables", {"connection_id": "remote", "schema": "ocean"})
    if deny:  # resolved through the listing, which spells it OCEAN
        _call(server, "db_list_columns", {"connection_id": "remote", "schema": "ocean", "object_name": "buoys"})


# ---- 7. ClickHouse decodes escapes in quoted identifiers ---------------------------
# Live on ClickHouse 26.3.3.20 (review, 2026-09-28), which reads \xHH, \n, \0, \\ and the
# rest in a backquoted or double-quoted name as it does in a string: SELECT * FROM `on\x65`
# in database system read system.one. sqlglot keeps the text as written, so the guard, the
# policy and the masking walk compared another name than the one ClickHouse read. With
# allowlist, default-deny and mask_columns [msisdn], SELECT `msisd\x6e` AS x returned the
# clear value; system.`query_lo\x67` read other sessions' SQL past the session-view refusal,
# and `s\x79stem`.`query_lo\x67` past the closed system schema.

_CH_ESCAPED = [
    "SELECT * FROM `on\\x65`",  # a table
    'SELECT * FROM "on\\x65"',
    "SELECT * FROM `s\\x79stem`.one",  # a schema
    'SELECT * FROM "s\\x79stem".one',
    "SELECT `msisd\\x6e` FROM telecom.subscribers",  # a column
    'SELECT "msisd\\x6e" FROM telecom.subscribers',
    "SELECT `msisd\\x6e` AS x FROM telecom.subscribers",  # an alias's source
    'SELECT "msisd\\x6e" AS x FROM telecom.subscribers',
    "SELECT concat(`msisd\\x6e`, '') AS x FROM telecom.subscribers",
    "SELECT s.`msisd\\x6e` AS x FROM telecom.subscribers AS s",
    "SELECT subscriber_id FROM telecom.subscribers WHERE `msisd\\x6e` = '1'",
    "WITH c AS (SELECT `msisd\\x6e` AS x FROM telecom.subscribers) SELECT x FROM c",  # a CTE's output
    "WITH c AS (SELECT msisdn AS `\\x78` FROM telecom.subscribers) SELECT x FROM c",
    "SELECT x FROM (SELECT msisdn AS \"\\x78\" FROM telecom.subscribers) AS d",
    "SELECT query FROM system.`query_lo\\x67`",  # the session views
    'SELECT query FROM system."query_lo\\x67"',
    "SELECT query FROM `s\\x79stem`.`query_lo\\x67`",
    "SELECT query FROM `s\\x79stem`.`pro\\x63esses`",
    "SELECT `msisdn\\0` FROM telecom.subscribers",
    "SELECT `a\\`b` FROM telecom.subscribers",  # even an escape sqlglot reads as ClickHouse does
    "SELECT `a\\\\b` FROM telecom.subscribers",
]


@pytest.mark.parametrize(
    ("deny", "allowed", "system"),
    [(True, ["telecom"], None), (False, [], None), (False, [], ["information_schema", "system"])],
    ids=["allowlist-default-deny", "neither", "system-opened"],
)
@pytest.mark.parametrize("sql", _CH_ESCAPED)
def test_clickhouse_an_escape_in_a_quoted_identifier_is_refused(
    sql: str, deny: bool, allowed: list[str], system: list[str] | None
) -> None:
    tables = [("telecom", "subscribers"), ("system", "one"), ("system", "query_log"), ("system", "processes")]
    guard = _listed_guard("clickhouse", allowed, tables, deny=deny, system_schemas=system)
    for label, validate, prefix in _entries(guard):
        exc = _refused(validate, prefix + sql)
        assert exc.category == ErrorCategory.POLICY, (label, str(exc))
        assert "escape" in str(exc) and "quoted identifier" in str(exc), (label, str(exc))


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT subscriber_id FROM telecom.subscribers WHERE plan = 'a\\x62\\n'",  # a string's escapes
        "SELECT `subscriber_id` AS `a``b` FROM `telecom`.`subscribers`",  # a doubled quote
        'SELECT "subscriber_id" FROM "telecom"."subscribers"',
    ],
)
def test_clickhouse_strings_and_plain_quoted_identifiers_stay_readable(sql: str) -> None:
    guard = _listed_guard("clickhouse", ["telecom"], [("telecom", "subscribers")], deny=True)
    assert guard.validate_select(sql).kind == "select"


@pytest.mark.parametrize("engine", ["postgres", "mysql", "sqlite"])
def test_a_backslash_in_a_quoted_identifier_is_clickhouses_alone(engine: str) -> None:
    # no other engine decodes it: a name with a backslash in it is that name
    quote = "`" if engine == "mysql" else '"'
    sql = f"SELECT {quote}a\\x62{quote} FROM ocean.buoys"
    assert _guard(engine, [], None, deny=False).validate_select(sql).kind == "select"


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT `ss\\x6e` AS x FROM app.customers",
        'SELECT "ss\\x6e" AS x FROM app.customers',
        "SELECT concat(`ss\\x6e`, '') AS x FROM app.customers",
    ],
)
def test_clickhouse_an_escaped_masked_column_never_reaches_the_engine(
    tmp_path: Path, monkeypatch: Any, sql: str
) -> None:
    fake = _AnswerFake(["x"], [SECRETS[0]])
    server, _ = _fake_app_server(tmp_path, monkeypatch, fake, engine="clickhouse", allowed=["app"], deny=True)
    text = _call_error(server, "db_query", {"connection_id": "remote", "sql": sql})
    assert "POLICY_VIOLATION" in text and "escape" in text, text
    assert SECRETS[0] not in text
    assert "escape" in _call_error(server, "db_validate_query", {"connection_id": "remote", "sql": sql})


# ---- 9. the namesakes of an allowed schema come from the whole schema list ---------
# Review, 2026-09-28: under allowed_schemas [ocean], with PostgreSQL's ocean holding
# nothing the listing lists (empty, or foreign tables and partitioned parents alone) and
# "OCEAN" a table, the listing held one spelling, shadowed nothing and admitted "OCEAN":
# db_query, db_sample_table and db_list_tables read "OCEAN".secrets, default-deny or not,
# while db_list_schemas, which reads the whole schema list, hid it.

_REVERSE = [
    # engine, allowed, the listing (the admitted spelling holds nothing listed), schema list, namesake
    ("postgres", ["ocean"], [TableSummary("OCEAN", "secrets", "table")], ["OCEAN", "ocean", "public"], "OCEAN"),
    ("postgres", ["ocean"], [TableSummary("Ocean", "secrets", "table")], ["Ocean", "ocean"], "Ocean"),
    ("oracle", ["travel"], [TableSummary("travel", "SECRETS", "table")], ["TRAVEL", "travel"], "travel"),
    ("mssql", ["ocean"], [TableSummary("Ocean", "secrets", "table")], ["dbo", "Ocean", "ocean"], "Ocean"),
]


@pytest.mark.parametrize("deny", [True, False], ids=["default-deny", "no-default-deny"])
@pytest.mark.parametrize(("engine", "allowed", "catalog", "schemas", "namesake"), _REVERSE)
def test_a_namesake_the_listing_holds_alone_is_refused(
    tmp_path: Path,
    monkeypatch: Any,
    deny: bool,
    engine: str,
    allowed: list[str],
    catalog: list[TableSummary],
    schemas: list[str],
    namesake: str,
) -> None:
    server, fake = _app_server(tmp_path, monkeypatch, engine, allowed, catalog, deny=deny)
    fake.list_schemas = lambda _catalog, _search: list(schemas)
    quoted = f"[{namesake}]" if engine == "mssql" else f'"{namesake}"'
    text = _call_error(server, "db_query", {"connection_id": "remote", "sql": f"SELECT * FROM {quoted}.secrets"})
    assert "AUTHORIZATION_DENIED" in text and "differ only in case" in text, text
    admitted = next(s for s in schemas if s.lower() == namesake.lower() and s != namesake)
    assert f"permitted one is spelled {admitted}" in text, text
    for args in ({"schema": namesake, "object_name": "secrets"}, {"object_name": f"{quoted}.secrets"}):
        text = _call_error(server, "db_sample_table", {"connection_id": "remote", **args})
        assert "AUTHORIZATION_DENIED" in text, (args, text)
    text = _call_error(server, "db_list_tables", {"connection_id": "remote", "schema": namesake})
    assert "AUTHORIZATION_DENIED" in text, text
    assert fake.statements == []
    listed = _call(server, "db_list_tables", {"connection_id": "remote"})["data"]["tables"]
    assert listed == [], listed
    # the admitted spelling is not taken for a namesake because it holds nothing listed
    assert _call(server, "db_list_tables", {"connection_id": "remote", "schema": admitted})["data"]["tables"] == []
    visible = _call(server, "db_list_schemas", {"connection_id": "remote"})["data"]["schemas"]
    assert namesake not in visible and admitted in visible, visible


def test_the_guard_compares_the_whole_schema_list() -> None:
    tables = [("OCEAN", "secrets")]
    alone = _listed_guard("postgres", ["ocean"], tables, deny=True)
    assert alone.validate_select('SELECT * FROM "OCEAN".secrets').kind == "select"  # one spelling: admitted
    guard = _listed_guard("postgres", ["ocean"], tables, deny=True, schemas=["OCEAN", "ocean"])
    text = str(_refused(guard.validate_select, 'SELECT * FROM "OCEAN".secrets'))
    assert "differ only in case" in text and text.endswith("write ocean.secrets"), text


def test_the_schema_list_is_read_once_per_ttl_and_only_under_an_allowlist(
    tmp_path: Path, monkeypatch: Any
) -> None:
    calls: list[str] = []

    def listing(_catalog: Any, _search: Any) -> list[str]:
        calls.append("list_schemas")
        return ["ocean"]

    for allowed, expected in ((["ocean"], 1), ([], 0)):
        calls.clear()
        (tmp_path / str(len(allowed))).mkdir()
        server, fake = _app_server(tmp_path / str(len(allowed)), monkeypatch, "postgres", allowed,
                                   [TableSummary("ocean", "buoys", "table")])
        fake.list_schemas = listing
        for _ in range(3):
            _call(server, "db_query", {"connection_id": "remote", "sql": "SELECT buoy_id FROM ocean.buoys"})
            _call(server, "db_list_tables", {"connection_id": "remote", "schema": "ocean"})
        assert len(calls) == expected, (allowed, calls)
    monkeypatch.setattr(srv, "_SCHEMA_NAMES_TTL", 0.0)
    calls.clear()
    (tmp_path / "ttl").mkdir()
    server, fake = _app_server(tmp_path / "ttl", monkeypatch, "postgres", ["ocean"],
                               [TableSummary("ocean", "buoys", "table")])
    fake.list_schemas = listing
    for _ in range(2):
        _call(server, "db_query", {"connection_id": "remote", "sql": "SELECT buoy_id FROM ocean.buoys"})
    assert len(calls) == 2, calls


# ---- 10. MySQL prints const-table values into TREE and JSON plans ------------------
# Live on MySQL 9.7.2 (review, 2026-09-28), allowed_schemas [testdb], default-deny,
# mask_columns [taster]: db_query SELECT taster ... WHERE cupping_id = 1 -> <masked>, while
#   EXPLAIN FORMAT=TREE SELECT b.batch_id FROM testdb.cuppings c JOIN testdb.roastery_batches b
#     ON b.bean_origin = c.taster WHERE c.cupping_id = 1  -> Filter: (b.bean_origin = 'R. Haddad')
#   EXPLAIN FORMAT=JSON SELECT * FROM testdb.cuppings WHERE cupping_id = 1
#     -> "query": "... select '1' AS `cupping_id`, ..., 'R. Haddad' AS `taster`, ..."
# MySQL reads a const table (a primary or unique key equality) while it plans; the
# tabular FORMAT=TRADITIONAL prints none of it (live, the same statements).

_MYSQL_TREE = [["-> Filter: (r.station = 'north')  (cost=0.35 rows=1)\n    -> Table scan on r\n"]]
_MYSQL_TABULAR = [["1", "SIMPLE", "b", "None", "const", "PRIMARY", "PRIMARY", "4", "const", "1", "100.0", "None"]]


def _mysql_explain_server(tmp_path: Path, monkeypatch: Any, plan: list[list[str]]) -> tuple[Any, list[str]]:
    catalog = [TableSummary("ocean", "buoys", "table"), TableSummary("ocean", "readings", "table")]
    server, fake = _app_server(tmp_path, monkeypatch, "mysql", ["ocean"], catalog,
                               security="  mask_columns: [station]\n")
    sent: list[str] = []

    def explain(sql: str, _analyze: bool) -> dict[str, Any]:
        sent.append(sql)
        return {"raw": plan}

    fake.explain = explain
    return server, sent


@pytest.mark.parametrize(
    "sql",
    [
        "EXPLAIN FORMAT=TREE SELECT r.buoy_id FROM ocean.buoys b JOIN ocean.readings r ON r.station = b.station"
        " WHERE b.buoy_id = 1",
        "EXPLAIN FORMAT=JSON SELECT r.buoy_id FROM ocean.buoys b JOIN ocean.readings r ON r.station = b.station"
        " WHERE b.buoy_id = 1",
        # the server's explain_format picks the format of a plain EXPLAIN
        "EXPLAIN SELECT r.buoy_id FROM ocean.buoys b JOIN ocean.readings r ON r.station = b.station"
        " WHERE b.buoy_id = 1",
        "EXPLAIN FORMAT=JSON SELECT * FROM ocean.buoys WHERE buoy_id = 1",  # the rewritten query lists every column
        "EXPLAIN FORMAT=JSON SELECT b.* FROM ocean.buoys b WHERE b.buoy_id = 1",
        "EXPLAIN FORMAT=JSON SELECT buoy_id FROM ocean.readings WHERE buoy_id = (SELECT station FROM ocean.buoys"
        " WHERE buoy_id = 1)",
        "EXPLAIN FORMAT=TREE SELECT r.buoy_id FROM ocean.buoys b JOIN ocean.readings r USING (station)"
        " WHERE b.buoy_id = 1",
        "EXPLAIN FORMAT=TREE SELECT r.buoy_id FROM ocean.buoys b NATURAL JOIN ocean.readings r WHERE b.buoy_id = 1",
    ],
)
def test_mysql_a_tree_or_json_plan_naming_a_masked_column_is_not_returned(
    tmp_path: Path, monkeypatch: Any, sql: str
) -> None:
    server, sent = _mysql_explain_server(tmp_path, monkeypatch, _MYSQL_TREE)
    text = _call_error(server, "db_explain", {"connection_id": "remote", "sql": sql})
    assert "POLICY_VIOLATION" in text and "FORMAT=TRADITIONAL" in text and "const" in text, text
    assert "north" not in text


@pytest.mark.parametrize(
    ("sql", "plan"),
    [
        # the tabular plan prints no value, whatever the statement names
        ("EXPLAIN FORMAT=TRADITIONAL SELECT r.buoy_id FROM ocean.buoys b JOIN ocean.readings r"
         " ON r.station = b.station WHERE b.buoy_id = 1", _MYSQL_TABULAR),
        ("EXPLAIN SELECT * FROM ocean.buoys WHERE buoy_id = 1", _MYSQL_TABULAR),  # MariaDB's plain EXPLAIN
        # nothing masked named: any format
        ("EXPLAIN FORMAT=TREE SELECT buoy_id FROM ocean.buoys WHERE buoy_id = 1", _MYSQL_TREE),
        ("EXPLAIN FORMAT=JSON SELECT count(*) AS n FROM ocean.buoys WHERE buoy_id = 1", _MYSQL_TREE),
    ],
)
def test_mysql_other_plans_are_returned(tmp_path: Path, monkeypatch: Any, sql: str, plan: list[list[str]]) -> None:
    server, sent = _mysql_explain_server(tmp_path, monkeypatch, plan)
    assert _call(server, "db_explain", {"connection_id": "remote", "sql": sql})["data"]["plan"] == {"raw": plan}
    assert sent == [sql[len("EXPLAIN "):]]


def test_the_const_table_rule_is_mysqls_alone(tmp_path: Path, monkeypatch: Any) -> None:
    catalog = [TableSummary("ocean", "buoys", "table")]
    server, fake = _app_server(tmp_path, monkeypatch, "postgres", ["ocean"], catalog,
                               security="  mask_columns: [station]\n")
    sql = "EXPLAIN SELECT * FROM ocean.buoys WHERE station = 'north'"
    assert _call(server, "db_explain", {"connection_id": "remote", "sql": sql})["data"]["plan"]
    assert fake.plans == [sql[len("EXPLAIN "):]]
    limitations = _call(server, "db_validate_query", {"connection_id": "remote", "sql": sql[8:]})["data"]
    assert not any("const tables" in lim for lim in limitations["limitations"]), limitations


def test_db_validate_query_states_the_mysql_plan_rule(tmp_path: Path, monkeypatch: Any) -> None:
    server, _ = _mysql_explain_server(tmp_path, monkeypatch, _MYSQL_TABULAR)
    sql = "SELECT buoy_id FROM ocean.buoys"
    limitations = _call(server, "db_validate_query", {"connection_id": "remote", "sql": sql})["data"]["limitations"]
    assert any("const tables" in lim and "FORMAT=TRADITIONAL" in lim for lim in limitations), limitations


# ---- 11. a mixed-case entry names its exact spelling first --------------------------


@pytest.mark.parametrize("deny", [True, False], ids=["default-deny", "no-default-deny"])
def test_a_mixed_case_postgres_entry_reads_the_schema_it_spells(deny: bool) -> None:
    # wave 2 admitted the spelling written; fold-first had moved 'Ocean' to ocean
    tables = [("ocean", "buoys"), ("Ocean", "secrets")]
    guard = _listed_guard("postgres", ["Ocean"], tables, deny=deny, schemas=["ocean", "Ocean"])
    assert guard.validate_select('SELECT * FROM "Ocean".secrets').kind == "select"
    text = str(_refused(guard.validate_select, "SELECT * FROM ocean.buoys"))
    assert "differ only in case" in text and text.endswith('write "Ocean".buoys'), text


@pytest.mark.parametrize("deny", [True, False], ids=["default-deny", "no-default-deny"])
def test_a_schema_outside_the_allowlist_is_not_offered_a_spelling(deny: bool) -> None:
    # the schema list names every schema; only a permitted one's spelling is a hint
    schemas = ["telecom", "hr", "system"]
    guard = _listed_guard("clickhouse", ["telecom"], [("telecom", "subscribers")], deny=deny, schemas=schemas)
    text = str(_refused(guard.validate_select, "SELECT * FROM Hr.salaries"))
    assert text == "AUTHORIZATION_DENIED: schema 'Hr' is not permitted on connection 'c'", text
    text = str(_refused(guard.validate_select, "SELECT * FROM hr.salaries"))
    assert text == "AUTHORIZATION_DENIED: schema 'hr' is not permitted on connection 'c'", text


# ---- 12. names an engine reads as other names ----------------------------------------
# Live, fix-up round 2 (review, 2026-09-28). SQL Server 2022 compares names under the
# database collation. On the fixture's SQL_Latin1_General_CP1_CI_AS that collation
# ignores 21,228 BMP code points outright (Ethiopic, Tibetan, Arabic tatweel, lone
# surrogates and more), and a trailing blank or U+3000. It also reads full-width letters,
# small capitals (ʀ, ɴ), super- and subscripts and ligatures (æ, þ, ß, ﬁ) as ASCII. Under
# allowlist [dbo], default-deny and mask_columns [^mrn$, fullname], SELECT ＭＲＮ, ＦullName
# FROM dbo.Patients returned both masked columns in clear. With sys opened,
# sys.ｓｙｓcacheobjects and sys.[syscacheobjects ] returned other sessions' SQL. Db2 drops
# the trailing blanks of a delimited name, aliases included: "IBMREQD " AS X came back in
# clear, and SYSIBMADM."MON_CURRENT_SQL " returned statement text. Oracle upper-cases an
# unquoted ı or ſ to I or S, so user_tableſ reads USER_TABLES; ß, ẞ, the Kelvin sign,
# ligatures and İ stay themselves.

_MSSQL_TABLES = [("dbo", "Patients"), ("sys", "syscacheobjects"), ("sys", "dm_exec_sessions")]
_MSSQL_POLICIES = [
    pytest.param(["dbo"], True, None, id="allowlist-default-deny"),
    pytest.param(["dbo"], False, None, id="allowlist"),
    pytest.param([], False, ["information_schema", "sys"], id="sys-opened"),
    pytest.param([], True, ["information_schema", "sys"], id="sys-opened-default-deny"),
]
_MSSQL_LOOSE = [
    "SELECT TOP 2 ＭＲＮ, FullName FROM dbo.Patients",  # full-width
    "SELECT TOP 2 p.ＭＲＮ AS x FROM dbo.Patients AS p",
    "SELECT TOP 2 PatientId FROM dbo.Patients WHERE ＭＲＮ LIKE 'M%'",
    "SELECT TOP 2 [MRN ] FROM dbo.Patients",  # a trailing blank
    "SELECT TOP 2 [FullName　] FROM dbo.Patients",
    "SELECT TOP 2 [MሀRN] FROM dbo.Patients",  # ignored outright
    "SELECT TOP 2 [MRـN] FROM dbo.Patients",
    "SELECT TOP 2 [Mʀn] FROM dbo.Patients",  # a small capital
    "SELECT TOP 2 [ﬁrst_name] FROM dbo.Patients",  # a ligature (ﬁ reads as fi)
    "SELECT x FROM (SELECT MRN AS 'xሀ' FROM dbo.Patients) AS q",  # a string alias
    "SELECT TOP 2 LEFT(sql, 60) AS s FROM sys.ｓｙｓcacheobjects",
    "SELECT TOP 2 LEFT(sql, 60) AS s FROM sys.[syscacheobjects ]",
    "SELECT session_id FROM ｓｙｓ.dm_exec_sessions",
    "SELECT TOP 2 * FROM ｄｂｏ.Patients",
    "SELECT TOP 2 * FROM dbo.[Patientsـ]",
    "ſelect TOP 2 MRN FROM dbo.Patients",  # a keyword sqlglot upper-cases to SELECT
]


@pytest.mark.parametrize(("allowed", "deny", "system"), _MSSQL_POLICIES)
@pytest.mark.parametrize("sql", _MSSQL_LOOSE)
def test_sql_server_refuses_a_name_outside_printable_ascii(
    sql: str, allowed: list[str], deny: bool, system: list[str] | None
) -> None:
    guard = _listed_guard("mssql", allowed, _MSSQL_TABLES, deny=deny, system_schemas=system)
    for label, validate, prefix in _entries(guard):
        exc = _refused(validate, prefix + sql)
        assert exc.category == ErrorCategory.POLICY, (label, str(exc))
        assert "collation" in str(exc) and "ASCII" in str(exc), (label, str(exc))


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT TOP 2 MRN, [FullName], [Full Name] FROM dbo.Patients",
        "SELECT TOP 2 MRN FROM dbo.Patients WHERE FullName = N'ＭＲＮ ملاحظة ʀሀ '",  # a literal
        "SELECT TOP 2 MRN /* ملاحظة ＭＲＮ */ FROM dbo.Patients -- [MRN ]\n",  # comments
        "SELECT £1 AS m, ¥2 AS n",  # money literals
        "SELECT TOP 2 [MRN] AS 'x y' FROM dbo.Patients",
    ],
)
def test_sql_server_names_in_ascii_and_non_ascii_text_stay_readable(sql: str) -> None:
    guard = _listed_guard("mssql", ["dbo"], _MSSQL_TABLES, deny=True)
    for label, validate, prefix in _entries(guard):
        assert validate(prefix + sql).kind in ("select", "explain"), (label, sql)


@pytest.mark.parametrize("deny", [True, False], ids=["default-deny", "no-default-deny"])
@pytest.mark.parametrize(
    "sql",
    [
        "SELECT TOP 2 ｓｓｎ FROM app.customers",
        "SELECT TOP 2 [ssn ] AS x FROM app.customers",
        "SELECT TOP 2 [ssሀn] AS x FROM app.customers",
        "SELECT TOP 2 x FROM (SELECT ssn AS [xـ] FROM app.customers) AS q",
    ],
)
def test_sql_server_a_masked_column_in_another_spelling_never_reaches_the_engine(
    tmp_path: Path, monkeypatch: Any, deny: bool, sql: str
) -> None:
    fake = _StatementFake("mssql")
    server, _ = _fake_app_server(tmp_path, monkeypatch, fake, engine="mssql", allowed=["app"], deny=deny)
    for tool in ("db_query", "db_validate_query"):
        text = _call_error(server, tool, {"connection_id": "remote", "sql": sql})
        assert "POLICY_VIOLATION" in text and "collation" in text, (tool, text)
    assert fake.statements == []


@pytest.mark.parametrize(
    "sql",
    [
        'SELECT "IBMREQD " AS X FROM SYSIBM.SYSDUMMY1',
        'SELECT "X   " FROM (SELECT IBMREQD AS X FROM SYSIBM.SYSDUMMY1) AS Q',
        'SELECT X FROM (SELECT IBMREQD AS "X " FROM SYSIBM.SYSDUMMY1) AS Q',
        'SELECT STMT_TEXT FROM SYSIBMADM."MON_CURRENT_SQL "',
        'SELECT STMT_TEXT FROM "SYSIBMADM ".MON_CURRENT_SQL',
        'SELECT * FROM "SYSIBM ".SYSDUMMY1',
    ],
)
@pytest.mark.parametrize("deny", [True, False], ids=["default-deny", "no-default-deny"])
def test_db2_refuses_a_delimited_name_with_trailing_blanks(sql: str, deny: bool) -> None:
    tables = [("SYSIBMADM", "MON_CURRENT_SQL"), ("APP", "T")]
    guard = _listed_guard("db2", [], tables, deny=deny, system_schemas=["information_schema", "sysibmadm"])
    for label, validate, prefix in _entries(guard):
        exc = _refused(validate, prefix + sql)
        assert exc.category == ErrorCategory.POLICY, (label, str(exc))
        assert "drops the blanks at its end" in str(exc), (label, str(exc))


@pytest.mark.parametrize(
    "sql",
    [
        'SELECT "IBMREQD" AS X FROM SYSIBM.SYSDUMMY1',
        "SELECT IBMREQD FROM SYSIBM.SYSDUMMY1 WHERE IBMREQD <> 'Y  '",
        'SELECT " X" FROM (SELECT IBMREQD AS " X" FROM SYSIBM.SYSDUMMY1) AS Q',  # leading blanks count
    ],
)
def test_db2_other_delimited_names_stay_readable(sql: str) -> None:
    guard = _listed_guard("db2", [], [("APP", "T")], deny=True)
    for label, validate, prefix in _entries(guard):
        assert validate(prefix + sql).kind in ("select", "explain"), (label, sql)


def test_db2_a_masked_column_with_trailing_blanks_never_reaches_the_engine(tmp_path: Path, monkeypatch: Any) -> None:
    fake = _StatementFake("db2")
    server, _ = _fake_app_server(tmp_path, monkeypatch, fake, engine="db2", allowed=["app"], deny=True)
    text = _call_error(server, "db_query", {"connection_id": "remote", "sql": 'SELECT "SSN " AS X FROM APP.CUSTOMERS'})
    assert "POLICY_VIOLATION" in text and "drops the blanks at its end" in text, text
    assert fake.statements == []


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT sql_text FROM v$ſql",
        "SELECT * FROM user_tableſ",
        "SELECT ſſn FROM travel.customers",
        "SELECT full_name FROM travel.customers WHERE ınıtial > 0",
        "SELECT x FROM (SELECT ssn AS ſ FROM travel.customers) q",
    ],
)
@pytest.mark.parametrize("deny", [True, False], ids=["default-deny", "no-default-deny"])
def test_oracle_refuses_an_unquoted_name_it_folds_onto_ascii(sql: str, deny: bool) -> None:
    guard = _listed_guard("oracle", [], [("TRAVEL", "CUSTOMERS")], deny=deny)
    for label, validate, prefix in _entries(guard):
        exc = _refused(validate, prefix + sql)
        assert exc.category == ErrorCategory.POLICY, (label, str(exc))
        assert "upper-cases" in str(exc), (label, str(exc))


@pytest.mark.parametrize(
    "sql",
    [
        'SELECT "ſſn" FROM travel.customers',  # quoted: exactly that name
        "SELECT 'ſı' AS x FROM DUAL",
        "SELECT straße, şehir, İl FROM travel.customers",  # Oracle keeps these as they are (live)
    ],
)
def test_oracle_other_names_stay_readable(sql: str) -> None:
    guard = _listed_guard("oracle", [], [("TRAVEL", "CUSTOMERS")], deny=True)
    for label, validate, prefix in _entries(guard):
        assert validate(prefix + sql).kind in ("select", "explain"), (label, sql)


@pytest.mark.parametrize(
    ("engine", "schema", "name"),
    [
        ("mysql", "information_schema", "proceſſlist"),
        ("mysql", "INFORMATION_SCHEMA", "PROCESSLİST"),
        ("mysql", "information_schema", "processlıst"),
        ("mssql", "sys", "ｓｙｓcacheobjects"),
        ("mssql", "sys", "syscacheobjects "),
        ("mssql", "ｓｙｓ", "dm_exec_sessions"),
        ("mssql", None, "sysprocesses　"),
        ("db2", "SYSIBMADM", "MON_CURRENT_SQL "),
        ("db2", "SYSIBMADM ", "MON_CURRENT_SQL"),
        ("oracle", None, "v$ſql"),
        ("oracle", "SYS", "GV_$SESSıON"),
    ],
)
def test_the_session_view_list_matches_every_spelling_an_engine_reads(
    engine: str, schema: str | None, name: str
) -> None:
    """The guard refuses these spellings by the rules above; the policy (every
    tool's check, and the listings) matches them on its own as well."""
    assert is_session_sql_view(engine, schema, name)
    with pytest.raises(ToolFailure) as info:
        _policy(engine, [], system_schemas=["information_schema", "sys", "sysibmadm"]).check_object(
            schema or "sys", name
        )
    assert info.value.category == ErrorCategory.POLICY


@pytest.mark.parametrize(
    ("engine", "schema"),
    [("mssql", "ｓｙｓ"), ("mssql", "sys "), ("mysql", "ınformation_schema"), ("db2", "SYSIBMADM "),
     ("oracle", "ＳＹＳ"), ("postgres", "pg_catalog　")],
)
def test_a_system_schema_is_one_in_every_spelling(engine: str, schema: str) -> None:
    assert is_listed_system_schema(engine, schema)
    with pytest.raises(ToolFailure) as info:
        _policy(engine, []).check_object(schema, "t")
    assert info.value.category == ErrorCategory.AUTHZ and "system schema" in str(info.value)


@pytest.mark.parametrize(
    ("pattern", "name"),
    [("(?i)^mrn$", "ＭＲＮ"), ("(?i)^mrn$", "MRN "), ("(?i)^mrn$", "　mrn"), ("(?i)fullname", "ＦullName"),
     ("^ssn$", "ſſn"), ("^ssn$", "ｓｓｎ"), ("(?i)^first_name$", "ﬁrst_name")],
)
def test_a_mask_pattern_sees_a_name_in_its_compatibility_and_padded_spellings(pattern: str, name: str) -> None:
    assert srv._sensitive_name([re.compile(pattern)], name)


# ---- 14. ClickHouse resolves a CTE's body where the CTE is used ---------------------
# Live on ClickHouse 26.3.3.20 (review, 2026-09-28), connection database system,
# default-deny on, with or without allowlist [telecom]:
#   WITH b AS (SELECT 'x' AS query), processes AS (SELECT * FROM b)
#   SELECT query FROM (WITH b AS (SELECT * FROM processes) SELECT * FROM processes)
# returned system.processes' query text, while SELECT * FROM processes was refused. The
# body of processes is resolved inside the subquery, where b is the inner b; the inner b
# reads processes, which is being resolved, so ClickHouse reads the table. The guard bound
# every name lexically, where it is written, and took that last processes for the CTE.
_CH_DYNAMIC = [
    "WITH b AS (SELECT 'x' AS query), payroll AS (SELECT * FROM b)"
    " SELECT query FROM (WITH b AS (SELECT * FROM payroll) SELECT * FROM payroll)",
    "WITH b AS (SELECT 42 AS id), payroll AS (SELECT * FROM b)"
    " SELECT * FROM (WITH b AS (SELECT * FROM payroll) SELECT * FROM payroll)",
    "WITH b AS (SELECT 42 AS id), payroll AS (SELECT * FROM b), a AS (SELECT * FROM payroll)"
    " SELECT * FROM (WITH b AS (SELECT * FROM a) SELECT * FROM payroll)",
    # b is a table where payroll's body is written, the inner CTE where payroll is used
    "WITH payroll AS (SELECT * FROM b) SELECT * FROM (WITH b AS (SELECT * FROM payroll) SELECT * FROM payroll)",
    # the inner WITH in another CTE's body, or behind a further CTE
    "WITH b AS (SELECT 1 AS id), payroll AS (SELECT * FROM b),"
    " c AS (WITH b AS (SELECT * FROM payroll) SELECT * FROM payroll) SELECT * FROM c",
    "WITH b AS (SELECT 1 AS id), payroll AS (SELECT * FROM (SELECT * FROM b) d)"
    " SELECT * FROM (SELECT * FROM (WITH b AS (SELECT * FROM payroll) SELECT * FROM payroll) e) f",
    # a name the body of an inner CTE reads by skipping itself
    "WITH b AS (SELECT 1 AS id), payroll AS (WITH b AS (SELECT * FROM b) SELECT * FROM b)"
    " SELECT * FROM (WITH b AS (SELECT * FROM payroll) SELECT * FROM payroll)",
]


@pytest.mark.parametrize(("deny", "allowed"), [*_CH_POLICIES, (False, [])])
@pytest.mark.parametrize("sql", _CH_DYNAMIC)
def test_clickhouse_refuses_a_name_a_cte_body_reads_declared_again_elsewhere(
    tmp_path: Path, monkeypatch: Any, deny: bool, allowed: list[str], sql: str
) -> None:
    fake = _StatementFake("clickhouse")
    server, _ = _fake_app_server(tmp_path, monkeypatch, fake, engine="clickhouse", allowed=allowed, deny=deny)
    for tool in ("db_query", "db_validate_query"):
        text = _call_error(server, tool, {"connection_id": "remote", "sql": sql})
        assert "POLICY_VIOLATION" in text and "where the CTE is used" in text, (tool, text)
    assert fake.statements == []


_CH_NESTED_CTES = [
    # a CTE's body with a WITH of its own, in one CTE or in two
    "WITH a AS (WITH b AS (SELECT id FROM customers) SELECT id FROM b) SELECT id FROM a",
    "WITH a AS (WITH b AS (SELECT id FROM customers) SELECT id FROM b),"
    " c AS (WITH b AS (SELECT id + 1 AS id FROM customers) SELECT id FROM b)"
    " SELECT id FROM a UNION ALL SELECT id FROM c",
    # an outer CTE read from a nested WITH that declares other names
    "WITH a AS (SELECT id FROM customers) SELECT id FROM (WITH b AS (SELECT id FROM a) SELECT id FROM b)",
    "WITH a AS (SELECT id FROM customers), c AS (SELECT id FROM a)"
    " SELECT id FROM (WITH b AS (SELECT id FROM c) SELECT id FROM b)",
    # a nested WITH declaring the name of a CTE whose body reads only tables
    "WITH a AS (SELECT id FROM customers)"
    " SELECT id FROM (WITH a AS (SELECT id + 1 AS id FROM customers) SELECT id FROM a)",
]


@pytest.mark.parametrize("allowed", [[], ["app"]])
@pytest.mark.parametrize("sql", _CH_NESTED_CTES)
def test_clickhouse_nested_withs_that_bind_alike_stay_readable(
    tmp_path: Path, monkeypatch: Any, allowed: list[str], sql: str
) -> None:
    sql = _qualified(sql, allowed)
    fake = _StatementFake("clickhouse")
    server, _ = _fake_app_server(tmp_path, monkeypatch, fake, engine="clickhouse", allowed=allowed, deny=True)
    env = _call(server, "db_validate_query", {"connection_id": "remote", "sql": sql})
    assert {r["name"] for r in env["data"]["referenced_objects"]} == {"customers"}, env["data"]
    _call(server, "db_query", {"connection_id": "remote", "sql": sql})
    assert fake.statements == [sql]
