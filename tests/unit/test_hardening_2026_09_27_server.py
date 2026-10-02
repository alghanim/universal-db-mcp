"""Hardening pass 2026-09-27, server group, pinned end to end.

F01: column masking follows the value's position through set operations,
explicit column lists, derived tables and whole-row references, not the name
the driver happens to report; what cannot be traced is masked (fail closed).
F16: driver error text never carries a value back (to the model, the audit
log or the history), and a data error is not labelled a connection error.
F05: an unqualified name resolves through the schema allowlist even when
default_deny_objects is false. F19: db_get_table masks sensitive DEFAULT
literals like the other metadata tools. F21: schema listings and foreign-key
targets never name a schema the allowlist hides.

Part 2. F42: schema-wide catalog lists are assigned to tables by their exact
name. F09: repeated connection ids are searched once and lists are bounded.
F22: an unknown connection id or an oversized statement cannot bloat the
audit log or the history. F23: value search, sampling and profiling leave a
per-statement audit record. F41: every column a search predicate reads is
also projected. F40: sibling surrogate keys are not join candidates and
inference output is bounded. F18: security.max_response_bytes bounds every
listing, the federated merged view and the review recommendations.

Part 3. F60: parameter values are JSON scalars before any driver sees them.
F66: a list cursor is bound to the filters of the listing it pages. F67: a
call the SDK refuses (unknown tool, invalid arguments) is audited. F72: the
audit identity is the OS account, not the environment. F82: a '%' in a
catalog name survives the %-formatting drivers. F84: the catalog fan-out of
inference, catalog and data dictionary honours the discovery time budget.
F85: a freed poisoned connector never condemns a new one at its address.
F95: the truncation warning claims nothing about where limits were applied.

Review round 1. F01: SQL Server FOR JSON / FOR XML fold every value into one
column; case-sensitive mask patterns fold like the engines everywhere a name
is matched; the taint walk takes bounded rounds and time. F16: a driver
wrapper is recognised only where the driver puts it, and bare numbers are
redacted. F05: a bare dictionary name (pg_roles, ALL_USERS) needs its system
schema even without an allowlist. Also: definitions naming a sensitive column
beside a literal are withheld, masked rows are cut to the byte ceiling again,
caller strings in error text are bounded, a response is serialized once, and
a natural key shared by extension tables still references its hub.

Review round 2. F01: a CTE referenced through a column list (t AS d(w, x)),
PostgreSQL attribute notation over a row (b.row_to_json), ClickHouse tuple
access through an alias (x.1) and a parenthesized table are traced. F16: the
XML input libxml echoes is cut. F05: schema='' is no schema, and an Oracle
bare name resolves through the catalog (a PUBLIC synonym may answer it
otherwise). F85: a discarded connector is closed once no worker uses it.
F19: SQLite double-quoted literals and index definitions are withheld beside
a sensitive column, and index definitions are capped.

Integration wave. I05: SQLite's own catalog is neither listed nor read by
the metadata and sample tools, nor by a statement; on SQLite a statement
reads only listed tables, default-deny or not. I06: a row matching in two
column chunks is one hit, keyed or not. I07: a timeout is an error in the
audit, whoever stopped the statement. I08: a connector's own refusal keeps
its numbers; a connector that cannot be built does not echo the install
path. I09: binary (FixedString) cells are matched as text. I10:
db_test_connection reports the audit records a fail-open server lost. I11:
db_list_connections says whether the server-side read-only session is on.
I12: a site-defined function over a PostgreSQL base table's row (b.fn) is
masked.

Integration round 3. I05: a CTE the reference cannot see (declared inside
EXISTS, a subquery, another UNION branch, after it, or spelled otherwise
than the engine folds it) no longer hides a table from the statement checks,
on any engine. The taint walk binds a FROM item as the engine does (folded
names, a CTE naming itself recursive without the keyword), or masks the
result whole where it cannot.
"""

from __future__ import annotations

import asyncio
import base64
import dataclasses
import errno
import gc
import hashlib
import json
import os
import re
import sqlite3
import sys
import threading
import time
from pathlib import Path
from typing import Any

import anyio
import pytest
import sqlglot
from sqlglot import exp

import universal_db_mcp.server as srv
from universal_db_mcp.config import load_resolved
from universal_db_mcp.connectors import registry
from universal_db_mcp.connectors.base import (
    ColumnInfo,
    ConnectorError,
    DatabaseConnector,
    IndexInfo,
    KeyInfo,
    QueryOutcome,
    RoutineInfo,
    SynonymInfo,
    TableSummary,
)
from universal_db_mcp.connectors.clickhouse import ClickHouseConnector
from universal_db_mcp.connectors.mysql import MySQLConnector
from universal_db_mcp.connectors.postgres import PostgresConnector
from universal_db_mcp.connectors.sqlite import SQLiteConnector
from universal_db_mcp.discovery.inference import TableFacts, TableRef, infer_relationships
from universal_db_mcp.errors import ToolFailure
from universal_db_mcp.models.capabilities import CapabilityState
from universal_db_mcp.security.sql_guard import bind_text
from universal_db_mcp.server import AppContext, build_server
from universal_db_mcp.services.audit import AuditWriteFailure

SECRETS = ("999-90-1111", "999-90-2222", "999-90-3333")


def _seed(db: Path) -> None:
    c = sqlite3.connect(db)
    c.executescript(
        """
        CREATE TABLE customers (
            customer_id INTEGER PRIMARY KEY, full_name TEXT, email TEXT DEFAULT 'nobody@example.invalid',
            ssn TEXT DEFAULT 'unknown');
        """
    )
    c.executemany(
        "INSERT INTO customers VALUES (?,?,?,?)",
        [(i + 1, f"User {i}", f"u{i}@example.invalid", s) for i, s in enumerate(SECRETS)],
    )
    c.commit()
    c.close()


def _server(tmp_path: Path, *, security: str = "", names: tuple[str, ...] = ("shop",)) -> tuple[Any, AppContext]:
    conns = ""
    for name in names:
        db = tmp_path / f"{name}.db"
        _seed(db)
        conns += f"  {name}:\n    type: sqlite\n    database: {db}\n"
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "application:\n  transport: stdio\n"
        f"  audit_path: {tmp_path / 'audit.jsonl'}\n"
        f"  metadata_cache_path: {tmp_path / 'cache.sqlite'}\n"
        f"security:\n  max_concurrent_queries: 4\n{security}"
        f"connections:\n{conns}",
        encoding="utf-8",
    )
    app_cfg, resolved = load_resolved(cfg)
    app = AppContext(app_cfg, resolved)
    return build_server(app), app


def _call(server: Any, name: str, args: dict[str, Any]) -> dict[str, Any]:
    result = asyncio.run(server.call_tool(name, args))
    assert result.structured_content is not None
    return result.structured_content


def _call_error(server: Any, name: str, args: dict[str, Any]) -> str:
    with pytest.raises(Exception) as info:  # noqa: PT011 - the ToolError text is what is asserted
        _call(server, name, args)
    return str(info.value)


def _assert_no_secret(payload: Any) -> None:
    text = json.dumps(payload, default=str)
    for secret in SECRETS:
        assert secret not in text, (secret, text[:600])


# ------------------------------------------------------ F01 positional masking

_TAINTED_SHAPES = [
    ("SELECT upper(ssn) FROM customers", 0),
    ("SELECT ssn||'' FROM customers", 0),
    ("SELECT full_name FROM customers UNION ALL SELECT ssn FROM customers", 0),
    ("WITH c(a) AS (SELECT ssn FROM customers) SELECT a FROM c", 0),
    ("WITH c(a) AS (SELECT ssn FROM customers) SELECT * FROM c", 0),
    ("SELECT upper(c) FROM (SELECT ssn AS c FROM customers) s", 0),
    ("SELECT customer_id, upper(ssn) FROM customers", 1),
]


@pytest.mark.parametrize(("sql", "index"), _TAINTED_SHAPES)
def test_db_query_masks_the_tainted_position(tmp_path: Path, sql: str, index: int) -> None:
    server, _ = _server(tmp_path)
    env = _call(server, "db_query", {"connection_id": "shop", "sql": sql})
    rows = env["data"]["rows"]
    assert rows and all(r[index] == "<masked>" for r in rows), rows
    assert any("masked by policy" in w for w in env["warnings"]), env["warnings"]
    _assert_no_secret(env)
    # only the tainted position is masked
    assert all(v != "<masked>" for r in rows for i, v in enumerate(r) if i != index), rows


def test_db_query_leaves_benign_expressions_unmasked(tmp_path: Path) -> None:
    server, _ = _server(tmp_path)
    env = _call(server, "db_query", {"connection_id": "shop", "sql": "SELECT upper(full_name) FROM customers"})
    assert env["data"]["rows"][0] == ["USER 0"]
    assert not any("masked" in w for w in env["warnings"])


@pytest.mark.parametrize("driver_name", ["upper", "1", "", "concat_ws_" + "x" * 245])
def test_generic_driver_column_names_do_not_unmask(tmp_path: Path, monkeypatch: Any, driver_name: str) -> None:
    """PostgreSQL reports 'upper', Db2 '1', SQL Server '' and MySQL a name cut
    at 255 characters: none of them names the source column."""
    real = SQLiteConnector.execute_query

    def renamed(self: SQLiteConnector, spec: Any) -> QueryOutcome:
        out = real(self, spec)
        return dataclasses.replace(out, columns=[(driver_name, t) for _n, t in out.columns])

    monkeypatch.setattr(SQLiteConnector, "execute_query", renamed)
    server, _ = _server(tmp_path)
    env = _call(server, "db_query", {"connection_id": "shop", "sql": "SELECT upper(ssn) FROM customers"})
    assert all(r == ["<masked>"] for r in env["data"]["rows"]), env["data"]["rows"]
    assert any("masked by policy" in w for w in env["warnings"])
    _assert_no_secret(env)


def test_apply_masking_by_position_with_synthetic_driver_names(demo_policy: Any) -> None:
    for name in ("upper", "1", "", "x" * 255):
        ast = sqlglot.parse_one("SELECT upper(ssn) FROM customers", read="postgres")
        positions = srv._sensitive_output_positions(demo_policy, ast, 1)
        state: dict[str, Any] = {"warnings": []}
        cols, rows = srv._apply_masking(demo_policy, [(name, "text")], [["999-90-1111"]], state, positions=positions)
        assert rows == [["<masked>"]] and cols[0][1].endswith("(masked)"), name
        assert any("masked by policy" in w for w in state["warnings"])


@pytest.mark.parametrize(
    ("sql", "width", "expected"),
    [
        ("SELECT x FROM (SELECT ssn FROM customers) AS q(x)", 1, {0}),
        ("SELECT CAST(b AS TEXT) FROM customers b", 1, {0}),
        ("SELECT customer_id, b::text FROM customers AS b", 2, {1}),
        ("SELECT to_json(b.*) FROM customers b", 1, {0}),
        ("SELECT id FROM (SELECT customer_id AS id, ssn FROM customers) q", 1, set()),
        ("SELECT * FROM customers", 4, set()),  # the driver reports the table's own names
        ("SELECT *, upper(ssn) FROM customers", 5, {4}),
        ("SELECT * FROM (SELECT ssn AS a FROM customers) x JOIN (SELECT full_name AS b FROM customers) y ON true",
         2, {0}),
        ("SELECT * FROM (SELECT full_name AS b FROM customers) y, (SELECT ssn AS a FROM customers) x", 2, {1}),
        ("SELECT (SELECT max(ssn) FROM customers) AS m", 1, {0}),
        ("SELECT full_name FROM customers INTERSECT SELECT ssn FROM customers", 1, {0}),
        ("SELECT a, b FROM (SELECT full_name AS a, customer_id AS b FROM customers "
         "UNION SELECT customer_id, ssn FROM customers) u", 2, {1}),
        ("WITH RECURSIVE t(n, v) AS (SELECT 1, ssn FROM customers UNION ALL SELECT n + 1, v FROM t WHERE n < 3) "
         "SELECT n, v FROM t", 2, {1}),
        ("WITH RECURSIVE t(n, v) AS (SELECT 1, ssn FROM customers UNION ALL SELECT v, v FROM t WHERE n < 3) "
         "SELECT n FROM t", 1, {0}),
        ("(SELECT ssn FROM customers)", 1, {0}),
        ("SELECT count(*) FROM customers", 1, set()),
    ],
)
def test_sensitive_output_positions(demo_policy: Any, sql: str, width: int, expected: set[int]) -> None:
    ast = sqlglot.parse_one(sql, read="postgres")
    assert srv._sensitive_output_positions(demo_policy, ast, width) == expected


@pytest.mark.parametrize(
    ("sql", "width", "expected"),
    [
        ("WITH ssn AS x SELECT x FROM customers", 1, {0}),  # a scalar alias, not a query
        ("WITH ssn AS x, x AS y SELECT customer_id, y FROM customers", 2, {1}),
        ("SELECT ssn AS x, x FROM customers", 2, {0, 1}),  # a bare name may be a sibling alias
        ("SELECT customer_id AS x, x FROM customers", 2, set()),
        ("SELECT upper(x) FROM customers ARRAY JOIN [ssn] AS x", 1, {0}),
    ],
)
def test_clickhouse_alias_forms_are_traced(demo_policy: Any, sql: str, width: int, expected: set[int]) -> None:
    ast = sqlglot.parse_one(sql, read="clickhouse")
    assert srv._sensitive_output_positions(demo_policy, ast, width) == expected


@pytest.mark.parametrize(
    ("dialect", "sql", "width", "expected"),
    [
        # a table alias column list renames the base table's columns positionally
        ("postgres", "SELECT d FROM customers AS t(a, b, c, d)", 1, {0}),
        ("postgres", "SELECT t.d FROM customers t(a, b, c, d)", 1, {0}),
        ("postgres", "SELECT * FROM customers AS t(a, b, c, d)", 4, {0, 1, 2, 3}),
        ("postgres", "SELECT t.full_name FROM customers t(a)", 1, set()),
        # a table function's columns are its own, never those of a lateral source before it
        ("postgres", "SELECT u.v FROM (SELECT 1 AS k) q, customers c, unnest(ARRAY[c.ssn]) AS u(v)", 1, {0}),
        ("postgres", "SELECT v FROM (SELECT 1 AS k) q, customers c, unnest(ARRAY[c.ssn]) AS u(v)", 1, {0}),
        # a LATERAL subquery with a FROM of its own still reads the sources before it
        ("postgres", "SELECT l.y FROM (SELECT ssn AS x FROM customers) q, LATERAL (SELECT x AS y FROM customers c2) l",
         1, {0}),
        ("tsql", "SELECT y FROM (VALUES (1)) v(x) CROSS APPLY (SELECT TOP 1 ssn AS y FROM customers) z", 1, {0}),
        ("tsql", "SELECT x FROM (VALUES (1)) v(x) CROSS APPLY (SELECT TOP 1 ssn AS y FROM customers) z", 1, set()),
        # derived tables without an alias (PostgreSQL 16+, ClickHouse)
        ("postgres", "SELECT x FROM (SELECT ssn AS x FROM customers), (SELECT 1 AS y)", 1, {0}),
        ("postgres", "SELECT * FROM (SELECT ssn AS x FROM customers), (SELECT 1 AS y)", 2, {0}),
        ("postgres", "SELECT * FROM (SELECT 1 AS y), (SELECT ssn AS x FROM customers)", 2, {1}),
        # ClickHouse: an alias defined in WHERE or ORDER BY is visible in the SELECT list
        ("clickhouse", "SELECT upper(x) FROM customers WHERE (ssn AS x) != ''", 1, {0}),
        ("clickhouse", "SELECT x FROM customers ORDER BY (ssn AS x)", 1, {0}),
        ("clickhouse", "SELECT y FROM (SELECT ssn AS x FROM customers) WHERE (x AS y) != ''", 1, {0}),
        # ClickHouse COLUMNS('regex') selects columns the statement never names
        ("clickhouse", "SELECT upper(COLUMNS('ss.*')) FROM customers", 1, {0}),
        ("clickhouse", "SELECT COLUMNS('ss.*') APPLY(upper) FROM customers", 1, {0}),
        ("clickhouse", "SELECT customer_id, upper(COLUMNS('ss.*')) FROM customers", 2, {1}),
    ],
)
def test_output_positions_follow_every_source_form(
    demo_policy: Any, dialect: str, sql: str, width: int, expected: set[int]
) -> None:
    ast = sqlglot.parse_one(sql, read=dialect)
    assert srv._query_mask_positions(demo_policy, ast, [(f"c{i}", "t") for i in range(width)]) == expected


def test_case_sensitive_patterns_match_the_folded_spellings(demo_policy: Any) -> None:
    """Oracle and Db2 fold unquoted names to upper case: an administrator's
    ^NATIONAL_ID$ must catch national_id written in lower case."""
    policy = dataclasses.replace(demo_policy, sensitive_patterns=[re.compile(r"^NATIONAL_ID$")])
    for sql in ("SELECT upper(national_id) FROM citizens", 'SELECT upper("NATIONAL_ID") FROM citizens'):
        ast = sqlglot.parse_one(sql, read="oracle")
        assert srv._sensitive_output_positions(policy, ast, 1) == {0}, sql


def test_alias_chains_are_traced_in_linear_time(demo_policy: Any) -> None:
    # every alias reads the next one: the old name fixpoint was quadratic
    # (14 s for this 60 KiB statement, on the event loop)
    n = 4000
    sql = "SELECT " + ", ".join(f"a{i} AS a{i + 1}" for i in reversed(range(n))) + ", ssn AS a0 FROM customers"
    ast = sqlglot.parse_one(sql, read="clickhouse")
    started = time.perf_counter()
    names = srv._sensitive_output_names(demo_policy, ast)
    positions = srv._query_mask_positions(demo_policy, ast, [(f"a{i}", "t") for i in range(n + 1)])
    assert time.perf_counter() - started < 3.0
    assert names == frozenset(f"a{i}" for i in range(n + 1))
    assert positions == set(range(n + 1))


_JSON_COLUMN = "JSON_F52E2B61-18A1-11d1-B105-00805F49916B"
_XML_COLUMN = "XML_F52E2B61-18A1-11d1-B105-00805F49916B"


@pytest.mark.parametrize(
    ("sql", "driver"),
    [
        # a star over a base table: its sensitive columns ride inside the one folded column
        ("SELECT TOP 2 * FROM customers FOR JSON PATH", _JSON_COLUMN),
        ("SELECT TOP 2 c.* FROM customers c FOR JSON AUTO", _JSON_COLUMN),
        ("SELECT TOP 2 * FROM customers FOR XML RAW", _XML_COLUMN),
        ("SELECT customer_id, ssn FROM customers FOR JSON PATH", _JSON_COLUMN),
        # a clean alias spelled like the driver's own column name proves nothing
        (f"SELECT full_name AS [{_JSON_COLUMN}], ssn FROM (VALUES (1, 'Ada', 'x')) v(id, full_name, ssn) FOR JSON PATH",
         _JSON_COLUMN),
        (f"SELECT full_name AS [{_XML_COLUMN}], ssn FROM customers FOR XML PATH", _XML_COLUMN),
    ],
)
def test_for_json_and_for_xml_fold_every_value_into_one_masked_column(demo_policy: Any, sql: str, driver: str) -> None:
    ast = sqlglot.parse_one(sql, read="tsql")
    assert srv._query_mask_positions(demo_policy, ast, [(driver, "str")]) == {0}
    state: dict[str, Any] = {"warnings": []}
    _cols, rows = srv._apply_masking(
        demo_policy, [(driver, "str")], [['[{"ssn":"999-90-1111"}]']], state,
        positions=srv._query_mask_positions(demo_policy, ast, [(driver, "str")]),
    )
    assert rows == [["<masked>"]]


def test_for_json_over_clean_columns_stays_readable(demo_policy: Any) -> None:
    ast = sqlglot.parse_one("SELECT customer_id, full_name FROM customers FOR JSON PATH", read="tsql")
    assert srv._query_mask_positions(demo_policy, ast, [(_JSON_COLUMN, "str")]) == set()


def test_an_unmapped_result_is_masked_whole_when_anything_is_tainted(demo_policy: Any) -> None:
    """Positions that cannot be laid over the driver's columns: a name the
    statement gives a clean column proves nothing while any column is tainted
    (or a star run is involved), because the driver may report any value under
    any name."""
    ast = sqlglot.parse_one("SELECT customer_id AS a, ssn AS b FROM customers", read="postgres")
    assert srv._query_mask_positions(demo_policy, ast, [("a", "t"), ("b", "t"), ("c", "t")]) == {0, 1, 2}
    # a star run (a folded result reports fewer columns than were projected)
    ast = sqlglot.parse_one("SELECT *, customer_id AS a, full_name AS b FROM customers", read="postgres")
    assert srv._query_mask_positions(demo_policy, ast, [("a", "t")]) == {0}
    # nothing tainted and no star: the traced names stay readable
    ast = sqlglot.parse_one("SELECT customer_id AS a, full_name AS b FROM customers", read="postgres")
    assert srv._query_mask_positions(demo_policy, ast, [("a", "t"), ("b", "t"), ("c", "t")]) == {2}


def _case_policy(demo_policy: Any, pattern: str) -> Any:
    return dataclasses.replace(demo_policy, sensitive_patterns=[re.compile(pattern)])


@pytest.mark.parametrize("pattern", ["^passport_no$", "^PASSPORT_NO$"])
def test_case_sensitive_patterns_match_driver_and_catalog_names_in_either_case(
    demo_policy: Any, pattern: str
) -> None:
    """Oracle and Db2 report NATIONAL_ID, PostgreSQL national_id: the name
    heuristics (a base-table star, sampling, profiling, value search, DEFAULT
    masking) fold like the positional tracer does."""
    policy = _case_policy(demo_policy, pattern)
    for driver in (["ID", "PASSPORT_NO"], ["id", "passport_no"]):
        ast = sqlglot.parse_one("SELECT * FROM travellers", read="oracle")
        columns = [(n, "t") for n in driver]
        positions = srv._query_mask_positions(policy, ast, columns)
        assert srv._mask_columns(policy, columns, positions=positions) == {1}, driver
        assert srv._sensitive(policy, driver[1]) and not srv._sensitive(policy, driver[0])
    assert srv._masked_default(policy, "Passport_No", "'X1234567'") == "<masked>"


def test_case_sensitive_patterns_protect_star_sample_profile_and_search(tmp_path: Path) -> None:
    script = (
        "CREATE TABLE travellers (traveller_id INTEGER PRIMARY KEY, PASSPORT_NO TEXT, nationality TEXT);"
        "INSERT INTO travellers VALUES (1, 'AE3305677', 'AE'), (2, 'CL9902873', 'CL'), (3, 'JP7712094', 'JP');"
    )
    server, _ = _sqlite_server(tmp_path, {"shop": script}, security="  mask_columns: ['^passport_no$']\n")
    secrets = ("AE3305677", "CL9902873", "JP7712094")
    calls = [
        ("db_query", {"connection_id": "shop", "sql": "SELECT * FROM travellers"}),
        ("db_sample_table", {"connection_id": "shop", "object_name": "travellers"}),
        ("db_profile_table", {"connection_id": "shop", "object_name": "travellers", "sample_rows": 10}),
        ("db_search_values", {"query": "AE3305677", "match": "exact"}),
    ]
    for tool, args in calls:
        env = _call(server, tool, args)
        env["data"].pop("query", None)  # the caller's own needle
        text = json.dumps(env)
        assert not any(s in text for s in secrets), (tool, text[:500])
    sample = _call(server, "db_sample_table", {"connection_id": "shop", "object_name": "travellers"})
    assert all(r[1] == "<masked>" for r in sample["data"]["rows"]), sample["data"]
    profile = _call(server, "db_profile_table", {"connection_id": "shop", "object_name": "travellers"})
    assert any("PASSPORT_NO" in w and "null ratio only" in w for w in profile["warnings"]), profile["warnings"]


def test_a_long_alias_chain_across_many_scopes_is_traced_quickly(demo_policy: Any) -> None:
    """Each link of a ClickHouse alias chain used to take one round over every
    scope, and each scalar subquery added a round to the bound: quadratic
    (34 s for a 42 KB statement, after it had run)."""
    n = 800
    sql = (
        "SELECT " + ", ".join(f"a{i + 1} AS a{i}" for i in range(n)) + f", ssn AS a{n}, "
        + ", ".join("(SELECT 1)" for _ in range(n)) + " FROM customers"
    )
    ast = sqlglot.parse_one(sql, read="clickhouse")
    started = time.perf_counter()
    positions = srv._query_mask_positions(demo_policy, ast, [(f"c{i}", "t") for i in range(2 * n + 1)])
    assert time.perf_counter() - started < 2.0
    assert positions == set(range(n + 1)), "traced exactly: the chain is tainted, the subqueries are not"


def test_a_statement_that_does_not_settle_in_bounded_rounds_is_masked_whole(demo_policy: Any, monkeypatch: Any) -> None:
    monkeypatch.setattr(srv, "_TAINT_MAX_ROUNDS", 1)
    ast = sqlglot.parse_one("SELECT customer_id, full_name FROM customers", read="postgres")
    columns = [("customer_id", "t"), ("full_name", "t")]
    assert srv._sensitive_output_positions(demo_policy, ast, 2) is None
    assert srv._query_mask_positions(demo_policy, ast, columns) == {0, 1}
    monkeypatch.setattr(srv, "_TAINT_MAX_ROUNDS", 16)
    monkeypatch.setattr(srv, "_TAINT_BUDGET_SECONDS", -1.0)
    assert srv._sensitive_output_positions(demo_policy, ast, 2) is None


def test_db_query_fails_closed_when_the_driver_reports_other_columns(tmp_path: Path, monkeypatch: Any) -> None:
    real = SQLiteConnector.execute_query

    def extra_column(self: SQLiteConnector, spec: Any) -> QueryOutcome:
        out = real(self, spec)
        return dataclasses.replace(
            out, columns=[*out.columns, ("mystery", "text")], rows=[[*r, "999-90-1111"] for r in out.rows]
        )

    monkeypatch.setattr(SQLiteConnector, "execute_query", extra_column)
    server, _ = _server(tmp_path)
    env = _call(server, "db_query", {"connection_id": "shop", "sql": "SELECT customer_id, full_name FROM customers"})
    assert env["data"]["rows"][0] == [1, "User 0", "<masked>"]
    assert any("fail closed" in w for w in env["warnings"]), env["warnings"]
    _assert_no_secret(env)


def test_untraceable_output_fails_closed(demo_policy: Any) -> None:
    # the driver reported more columns than the statement projects: only the
    # names the statement proves clean survive
    ast = sqlglot.parse_one("SELECT customer_id, full_name FROM customers", read="sqlite")
    columns = [("customer_id", "integer"), ("full_name", "text"), ("mystery", "text")]
    assert srv._sensitive_output_positions(demo_policy, ast, len(columns)) is None
    state: dict[str, Any] = {"warnings": []}
    cols, rows = srv._apply_masking(
        demo_policy, columns, [[1, "Ada", "999-90-1111"]], state,
        positions=srv._query_mask_positions(demo_policy, ast, columns),
    )
    assert rows == [[1, "Ada", "<masked>"]]
    # two stars around an engine-named tainted column: every column is suspect
    ast = sqlglot.parse_one(
        "SELECT a.*, upper(b.ssn), b.* FROM customers a JOIN customers b ON a.customer_id = b.customer_id",
        read="postgres",
    )
    columns = [(f"c{i}", "text") for i in range(9)]
    assert srv._query_mask_positions(demo_policy, ast, columns) == set(range(9))


def test_mask_action_omit_drops_exactly_the_tainted_positions(tmp_path: Path) -> None:
    server, _ = _server(tmp_path, security="  mask_action: omit\n")
    env = _call(server, "db_query", {"connection_id": "shop", "sql": "SELECT customer_id, upper(ssn) FROM customers"})
    assert [c["name"] for c in env["data"]["columns"]] == ["customer_id"]
    assert env["data"]["rows"][0] == [1]
    env = _call(
        server, "db_query",
        {"connection_id": "shop",
         "sql": "SELECT customer_id, full_name FROM customers UNION ALL SELECT customer_id, ssn FROM customers"},
    )
    assert [c["name"] for c in env["data"]["columns"]] == ["customer_id"]
    assert any("omitted" in w for w in env["warnings"])
    _assert_no_secret(env)


def test_federated_tools_mask_by_position(tmp_path: Path) -> None:
    server, _ = _server(tmp_path, names=("crm", "erp"))
    union = "SELECT customer_id, full_name FROM customers UNION ALL SELECT customer_id, ssn FROM customers"
    cte = "WITH c(k, a) AS (SELECT customer_id, ssn FROM customers) SELECT k, a FROM c"
    for sql in (union, cte):
        env = _call(server, "db_federated_query", {"sql": sql})
        merged = env["data"]["merged"]
        assert merged["rows"] and all(r[2] == "<masked>" for r in merged["rows"]), merged
        _assert_no_secret(env)
    env = _call(server, "db_federated_query", {"queries": {"crm": union, "erp": cte}})
    _assert_no_secret(env)
    env = _call(
        server, "db_federated_join",
        {"left": {"connection": "crm", "sql": union}, "right": {"connection": "erp", "sql": cte},
         "on": [["customer_id", "k"]], "join": "left"},
    )
    rows = env["data"]["rows"]
    assert rows and all(r[1] == "<masked>" or r[1].startswith("User") for r in rows)
    assert all(r[3] == "<masked>" for r in rows if r[3] is not None)
    _assert_no_secret(env)


# ------------------------------------------------------- F16 driver error text

_SENTINEL_ERROR = 'InvalidTextRepresentation: invalid input syntax for type integer: "SENTINEL-123"'


def _from_driver(text: str, category: str | None = None) -> ConnectorError:
    """A ConnectorError as translated_driver_errors raises it: from the
    driver's exception, whose text it carries."""
    exc = ConnectorError(text, category=category)
    exc.__cause__ = RuntimeError(text)
    return exc


def _raise_sentinel(*_a: Any, **_k: Any) -> Any:
    raise _from_driver(_SENTINEL_ERROR)


def test_driver_error_values_never_reach_the_model_or_the_audit(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr(SQLiteConnector, "execute_query", _raise_sentinel)
    monkeypatch.setattr(SQLiteConnector, "explain", _raise_sentinel)
    server, app = _server(tmp_path, names=("crm", "erp"))
    audit = tmp_path / "audit.jsonl"
    sql = "SELECT customer_id FROM customers"
    errors = [
        _call_error(server, "db_query", {"connection_id": "crm", "sql": sql}),
        _call_error(server, "db_sample_table", {"connection_id": "crm", "object_name": "customers"}),
        _call_error(server, "db_explain", {"connection_id": "crm", "sql": f"EXPLAIN QUERY PLAN {sql}"}),
        _call_error(
            server, "db_federated_join",
            {"left": {"connection": "crm", "sql": sql}, "right": {"connection": "erp", "sql": sql},
             "on": [["customer_id", "customer_id"]]},
        ),
    ]
    for text in errors:
        assert "SENTINEL" not in text and "InvalidTextRepresentation" in text, text
        assert "CONNECTION_ERROR:" in text, text
    fed = _call(server, "db_federated_query", {"sql": sql})
    search = _call(server, "db_search_values", {"query": "User"})
    for env in (fed, search):
        text = json.dumps(env)
        assert "SENTINEL" not in text and "InvalidTextRepresentation" in text, text
        last = audit.read_text(encoding="utf-8").splitlines()[-1]
        assert "SENTINEL" not in last and "InvalidTextRepresentation" in last, last
    assert "SENTINEL" not in audit.read_text(encoding="utf-8")
    assert "SENTINEL" not in json.dumps(list(app.history), default=str)


@pytest.mark.parametrize(
    ("raw", "kept", "gone"),
    [
        ("DatabaseError: Code: 6. DB::Exception: Cannot parse string 'x971501000001' as Int32: syntax error "
         "at begin of string. (CANNOT_PARSE_TEXT)", ["Code: 6", "Int32", "CANNOT_PARSE_TEXT"], ["x971501000001"]),
        ("DatabaseError: Code: 6. DB::Exception: Cannot parse string x971501000001 as Int32: syntax error",
         ["Code: 6", "Int32"], ["x971501000001"]),
        ("ProgrammingError: ('22018', \"[22018] [Microsoft][ODBC Driver 18 for SQL Server][SQL Server]Conversion "
         "failed when converting the varchar value 'O'Brien-123' to data type int. (245) (SQLExecDirectW)\")",
         ["[22018]", "(245)", "ProgrammingError"], ["Brien", "O'"]),
        ("DatabaseError: Code: 38. DB::Exception: Cannot parse date here: x971501000: Cannot parse Date from "
         "String. (CANNOT_PARSE_DATE)", ["Code: 38", "Cannot parse Date from String", "CANNOT_PARSE_DATE"],
         ["x971501000"]),
        ("DatabaseError: ORA-01722: invalid number", ["ORA-01722: invalid number"], []),
        ("DatabaseError: DPY-4010: invalid string value: abc-SECRET", ["DPY-4010"], ["abc-SECRET"]),
        ("InvalidTextRepresentation: invalid input syntax for type integer: \"MB-ALPHA|MB-BRAVO\"",
         ["InvalidTextRepresentation", "type integer"], ["MB-ALPHA", "MB-BRAVO"]),
        ("DataError: value 'x y z' unterminated", ["DataError"], ["x y z"]),
        # PostgreSQL prints a whole row without escaping the quotes inside it
        ('InvalidTextRepresentation: invalid input syntax for type integer: "(3,MB-ALPHA,"Jane Doe",7)"',
         ["InvalidTextRepresentation", "type integer"], ["MB-ALPHA", "Jane Doe"]),
        ("DatabaseError: Code: 60. DB::Exception: Table default.x doesn't exist. (UNKNOWN_TABLE)",
         ["Table default.x doesn't exist. (UNKNOWN_TABLE)"], []),
        ("ProgrammingError: ('42000', '[42000] [Microsoft][ODBC Driver 18 for SQL Server][SQL Server]Incorrect "
         "syntax near the keyword FROM. (156) (SQLExecDirectW)')", ["Incorrect syntax near the keyword FROM. (156)"],
         []),
        # the texts below are what the loopback fixtures return (scratchpad impl-server/resume/raw_echo.out)
        ("ConnectorError: DatabaseError: ORA-01722: unable to convert string value containing 'A' to a number:  "
         "ORA-03302: (ORA-01722 details) invalid string value: AE3305677 | CL9902873 | JP7712094 Help: "
         "https://docs.oracle.com/error-help/db/ora-01722/", ["ORA-01722", "ORA-03302", "invalid string value"],
         ["AE3305677", "CL9902873", "JP7712094"]),
        ("ConnectorError: DatabaseError: Received ClickHouse exception, code: 376, server response: Code: 376. "
         "DB::Exception: Cannot parse uuid 971501000001: Cannot parse UUID from String: while executing "
         "'FUNCTION toUUID(__table1.msisdn :: 1) -> toUUID(__table1.msisdn) UUID : 0'. (CANNOT_PARSE_UUID)",
         ["Code: 376", "Cannot parse UUID from String", "CANNOT_PARSE_UUID"], ["971501000001"]),
        ("ConnectorError: DatabaseError: Received ClickHouse exception, code: 675, server response: Code: 675. "
         "DB::Exception: Cannot parse IPv4 01000001: Cannot parse IPv4 from String: while executing 'x'. "
         "(CANNOT_PARSE_IPV4)", ["CANNOT_PARSE_IPV4"], ["01000001"]),
        # the line and the position are counted in the value, so they go too
        ("ConnectorError: InvalidTextRepresentation: invalid input syntax for type json DETAIL:  Token \"MB\" is "
         "invalid. CONTEXT:  JSON data, line 7: MB-ALPHA...", ["type json", "JSON data, line"], ["MB", "line 7"]),
        # PyMySQL renders (errno, 'message'): the quotes wrap the diagnostic, not a value
        ("ConnectorError: OperationalError: (3141, 'Invalid JSON text in argument 1 to function cast_as_json: "
         "\"Invalid value.\" at position 155.')", ["(3141, '", "Invalid JSON text in argument 1", "at position"],
         ["155", "Invalid value"]),
        ("ConnectorError: OperationalError: (1292, \"Truncated incorrect DOUBLE value: 'O'Brien-9'\")",
         ["1292", "Truncated incorrect DOUBLE value"], ["Brien"]),
    ],
)
def test_driver_text_sanitizer(raw: str, kept: list[str], gone: list[str]) -> None:
    clean = srv._sanitize_driver_text(raw)
    for part in kept:
        assert part in clean, (part, clean)
    for part in gone:
        assert part not in clean, (part, clean)


# Round 1 of review: a statement can build a value that looks like a driver
# wrapper, and engines print values as bare numbers.
_SPOOFED_AND_NUMERIC = [
    # a '[AAAAA] [' prefix made the echo look like pyodbc's wrapper
    ('ConnectorError: InvalidTextRepresentation: invalid input syntax for type integer: "[AAAAA] [MB-ALPHA|MB-BRAVO"',
     ["InvalidTextRepresentation", "type integer"], ["MB-ALPHA", "MB-BRAVO"]),
    ('X: invalid input syntax for type integer: "[AAAAA] [MB-ALPHA"', ["type integer"], ["MB-ALPHA"]),
    # ... and '(1, ' a PyMySQL one
    ("ConnectorError: InvalidTextRepresentation: invalid input syntax for type integer: \"(1, 'MB-ALPHA')\"",
     ["type integer"], ["MB-ALPHA"]),
    ('ConnectorError: InvalidTextRepresentation: invalid input syntax for type integer: "(1, "MB-ALPHA")"',
     ["type integer"], ["MB-ALPHA"]),
    # a genuine wrapper whose message quotes a spoofed one
    ("ConnectorError: DataError: ('22018', \"[22018] [Microsoft][ODBC Driver 18 for SQL Server][SQL Server]Conversion "
     "failed when converting the varchar value '[AAAAA] [MB-ALPHA' to data type int. (245) (SQLExecDirectW)\")",
     ["('22018', ", "[22018]", "(245) (SQLExecDirectW)"], ["MB-ALPHA"]),
    ("ConnectorError: OperationalError: (1292, \"Truncated incorrect DOUBLE value: '(1, 'MB-ALPHA')'\")",
     ["(1292, ", "Truncated incorrect DOUBLE value"], ["MB-ALPHA"]),
    # unquoted numbers: PostgreSQL chr() and make_time(), SQL Server error 220, ClickHouse sleep()
    ("ConnectorError: ProgramLimitExceeded: requested character too large for encoding: 77000000",
     ["requested character too large for encoding"], ["77"]),
    ("ConnectorError: DatetimeFieldOverflow: time field value out of range: 77:00:00",
     ["time field value out of range"], ["77"]),
    ("ConnectorError: DatetimeFieldOverflow: date field value out of range: 2024-77-01", ["out of range"], ["77"]),
    ("ConnectorError: DataError: ('22003', '[22003] [Microsoft][ODBC Driver 18 for SQL Server][SQL Server]Arithmetic "
     "overflow error for data type smallint, value = 123456789. (220) (SQLExecDirectW)')",
     ["('22003', ", "[22003]", "ODBC Driver 18", "value = ", "(220) (SQLExecDirectW)"], ["123456789"]),
    ("ConnectorError: DataError: value = -123456789.", ["value = "], ["123456789"]),
    ("ConnectorError: DatabaseError: Received ClickHouse exception, code: 160, server response: Code: 160. "
     "DB::Exception: The maximum sleep time is 3000000 microseconds. Requested: 77000000. (TOO_SLOW) "
     "(version 24.8.4.13 (official build))",
     ["code: 160", "Code: 160", "TOO_SLOW", "version 24.8.4.13"], ["77000000"]),
    ("ConnectorError: X: timestamp out of range: 7.7e+21, bytes 0x4D422D", ["timestamp out of range"],
     ["7.7", "e+21", "4D422D"]),
    ("ConnectorError: X: setseed parameter 77 is out of allowed range [-1,1]", ["setseed parameter"], ["77"]),
    # the engine's own codes survive
    ("ConnectorError: ProgrammingError: [IBM][CLI Driver][DB2/LINUXX8664] SQL0138N  A numeric argument of a "
     "built-in string function is out of range.  SQLSTATE=22011 SQLCODE=-138",
     ["DB2/LINUXX8664", "SQL0138N", "SQLSTATE=22011", "SQLCODE=-138"], []),
    ("ConnectorError: DatabaseError: ORA-12899: value too large for column (actual: 20, maximum: 10) "
     "Help: https://docs.oracle.com/error-help/db/ora-12899/", ["ORA-12899", "ora-12899"], ["20", "10"]),
    ("ConnectorError: SyntaxError: syntax error at end of input LINE 1: SELECT FROM", ["LINE 1:"], []),
]


@pytest.mark.parametrize(("raw", "kept", "gone"), _SPOOFED_AND_NUMERIC)
def test_driver_text_sanitizer_resists_spoofed_wrappers_and_numbers(raw: str, kept: list[str], gone: list[str]) -> None:
    clean = srv._sanitize_driver_text(raw)
    for part in kept:
        assert part in clean, (part, clean)
    for part in gone:
        assert part not in clean, (part, clean)


@pytest.mark.parametrize(
    "echo",
    [
        'InvalidTextRepresentation: invalid input syntax for type integer: "[AAAAA] [MB-ALPHA|MB-BRAVO"',
        "InvalidTextRepresentation: invalid input syntax for type integer: \"(1, 'MB-ALPHA|MB-BRAVO')\"",
        "ProgramLimitExceeded: requested character too large for encoding: 77000000",
    ],
)
def test_spoofed_and_numeric_echoes_never_reach_the_model_or_the_audit(
    tmp_path: Path, monkeypatch: Any, echo: str
) -> None:
    def raise_echo(*_a: Any, **_k: Any) -> Any:
        raise _from_driver(echo, category="QUERY_ERROR")

    monkeypatch.setattr(SQLiteConnector, "execute_query", raise_echo)
    server, app = _server(tmp_path, names=("crm", "erp"))
    text = _call_error(server, "db_query", {"connection_id": "crm", "sql": "SELECT customer_id FROM customers"})
    fed = json.dumps(_call(server, "db_federated_query", {"sql": "SELECT customer_id FROM customers"}))
    trail = (tmp_path / "audit.jsonl").read_text(encoding="utf-8") + json.dumps(list(app.history), default=str)
    for leaked in ("MB-ALPHA", "MB-BRAVO", "77000000"):
        assert leaked not in text and leaked not in fed and leaked not in trail, leaked
    assert "QUERY_ERROR: " in text, text


def test_audited_warnings_are_sanitized_once_where_they_are_built(tmp_path: Path, monkeypatch: Any) -> None:
    """A warning built from driver text is sanitized when it is built; the
    audit copy of the warnings is not sanitized again, which used to redact
    the server's own text (the connection a warning is about)."""
    monkeypatch.setattr(SQLiteConnector, "execute_query", _raise_sentinel)
    server, app = _server(tmp_path, names=("crm", "erp"))
    env = _call(server, "db_federated_query", {"sql": "SELECT customer_id FROM customers"})
    record = json.loads((tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()[-1])
    assert record["warnings"] == env["warnings"][: len(record["warnings"])]
    assert any(w.startswith("'crm': ") for w in record["warnings"]), record["warnings"]
    assert "SENTINEL" not in json.dumps(record) and "SENTINEL" not in json.dumps(list(app.history), default=str)


def test_query_error_category_is_honoured(tmp_path: Path, monkeypatch: Any) -> None:
    def query_error(*_a: Any, **_k: Any) -> Any:
        exc = ConnectorError("DivisionByZero: division by zero")
        exc.category = "QUERY_ERROR"  # type: ignore[attr-defined]
        raise exc

    server, _ = _server(tmp_path)
    monkeypatch.setattr(SQLiteConnector, "execute_query", query_error)
    text = _call_error(server, "db_query", {"connection_id": "shop", "sql": "SELECT 1"})
    assert "QUERY_ERROR: " in text and "CONNECTION_ERROR" not in text, text
    assert srv.ErrorCategory.QUERY == "QUERY_ERROR"
    monkeypatch.setattr(SQLiteConnector, "execute_query", _raise_sentinel)
    text = _call_error(server, "db_query", {"connection_id": "shop", "sql": "SELECT 1"})
    assert "CONNECTION_ERROR: " in text, text


@pytest.mark.parametrize(("category", "outcome"), [("POLICY_VIOLATION", "deny"), ("QUERY_ERROR", "error")])
def test_connector_refusal_is_audited_as_a_deny(tmp_path: Path, monkeypatch: Any, category: str, outcome: str) -> None:
    """A connector that refuses a statement (SQL Server's multi-statement
    check) raises ConnectorError(category='POLICY_VIOLATION'): a policy
    refusal, audited like the guard's own, not an error."""

    def refused(*_a: Any, **_k: Any) -> Any:
        raise ConnectorError("refused", category=category)

    server, _ = _server(tmp_path, names=("crm", "erp"))
    monkeypatch.setattr(SQLiteConnector, "execute_query", refused)
    audit = tmp_path / "audit.jsonl"
    text = _call_error(server, "db_query", {"connection_id": "crm", "sql": "SELECT 1"})
    assert text.startswith(f"Error executing tool db_query: {category}: "), text
    record = json.loads(audit.read_text(encoding="utf-8").splitlines()[-1])
    assert (record["outcome"], record["category"]) == (outcome, category)
    _call(server, "db_federated_query", {"sql": "SELECT 1"})
    statements = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines()]
    per_statement = [r for r in statements if r["action"] == "db_federated_query:statement"]
    assert per_statement and all((r["outcome"], r["category"]) == (outcome, category) for r in per_statement)


# ------------------------------------------------ fake remote connector (F05+)


class _Caps:
    def get(self, _name: str) -> CapabilityState:
        return CapabilityState.SUPPORTED


class _FakeConnector:
    """A duck-typed remote connector: catalog calls answer from fixed lists
    and record the (schema, name) they were asked for; no database exists."""

    get_table = DatabaseConnector.get_table  # the base composition every remote engine uses
    synonym_chains = DatabaseConnector.synonym_chains  # no synonyms
    name_binding = DatabaseConnector.name_binding  # a bare name is the listing's

    def __init__(
        self,
        tables: list[TableSummary],
        columns: list[ColumnInfo] | None = None,
        fks: list[KeyInfo] | None = None,
        schemas: list[str] | None = None,
    ) -> None:
        self.tables = tables
        self.columns = columns or []
        self.fks = fks or []
        self.schemas = schemas or []
        self.calls: list[tuple[str | None, str]] = []

    def capabilities(self) -> _Caps:
        return _Caps()

    def list_schemas(self, _catalog: str | None, _search: str | None) -> list[str]:
        return list(self.schemas)

    def list_tables(self, _schema: str | None, kinds: set[str], _search: str | None) -> list[TableSummary]:
        return [t for t in self.tables if t.kind in kinds]

    def list_columns(self, schema: str | None, table: str) -> list[ColumnInfo]:
        self.calls.append((schema, table))
        return [c for c in self.columns if c.table == table] or [ColumnInfo(schema, table, "id", "integer")]

    def list_all_columns(self, schema: str | None) -> list[ColumnInfo]:
        return [c for c in self.columns if c.schema == schema]

    def list_indexes(self, _schema: str | None, _table: str | None) -> list[Any]:
        return []

    def get_foreign_keys(self, _schema: str | None, table: str | None) -> list[KeyInfo]:
        return [k for k in self.fks if table is None or k.source_table == table]

    def get_statistics(self, _schema: str | None, _table: str) -> dict[str, Any]:
        return {"row_estimate": None}


def _fake_server(
    tmp_path: Path, monkeypatch: Any, fake: _FakeConnector, *, engine: str, allowed: list[str], deny: bool
) -> Any:
    return _fake_app_server(tmp_path, monkeypatch, fake, engine=engine, allowed=allowed, deny=deny)[0]


def _fake_app_server(
    tmp_path: Path, monkeypatch: Any, fake: Any, *, engine: str, allowed: list[str], deny: bool, security: str = ""
) -> tuple[Any, AppContext]:
    monkeypatch.setenv("UDBMCP_T_USER", "tester")
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "application:\n  transport: stdio\n"
        f"  audit_path: {tmp_path / 'audit.jsonl'}\n"
        f"  metadata_cache_path: {tmp_path / 'cache.sqlite'}\n"
        f"security:\n  require_remote_tls: false\n  default_deny_objects: {str(deny).lower()}\n{security}"
        "connections:\n  remote:\n"
        f"    type: {engine}\n    host: 127.0.0.1\n    port: 5999\n    database: testdb\n"
        f"    username_env: UDBMCP_T_USER\n    allowed_schemas: {json.dumps(allowed)}\n",
        encoding="utf-8",
    )
    app_cfg, resolved = load_resolved(cfg)
    app = AppContext(app_cfg, resolved)
    app.connectors["remote"] = fake
    return build_server(app), app


# ------------------------------------------- F05 allowlist for unqualified names

_OBJECT_TOOLS = [
    ("db_sample_table", {}),
    ("db_get_table", {}),
    ("db_list_columns", {}),
    ("db_get_statistics", {}),
    ("db_profile_table", {}),
    ("db_get_relationships", {}),
]


@pytest.mark.parametrize(("tool", "extra"), _OBJECT_TOOLS)
def test_unqualified_name_outside_the_allowlist_is_denied_without_default_deny(
    tmp_path: Path, monkeypatch: Any, tool: str, extra: dict[str, Any]
) -> None:
    fake = _FakeConnector([TableSummary("testdb", "cuppings", "table")])
    server = _fake_server(tmp_path, monkeypatch, fake, engine="mysql", allowed=["reporting"], deny=False)
    text = _call_error(server, tool, {"connection_id": "remote", "object_name": "cuppings", **extra})
    assert "AUTHORIZATION_DENIED" in text, text
    assert fake.calls == []


def test_unqualified_name_passes_through_without_allowlist_and_is_canonicalized_with_one(
    tmp_path: Path, monkeypatch: Any
) -> None:
    for allowed, expected in (([], (None, "cuppings")), (["testdb"], ("testdb", "cuppings"))):
        home = tmp_path / (allowed[0] if allowed else "none")
        home.mkdir()
        fake = _FakeConnector([TableSummary("testdb", "cuppings", "table")])
        server = _fake_server(home, monkeypatch, fake, engine="mysql", allowed=allowed, deny=False)
        _call(server, "db_list_columns", {"connection_id": "remote", "object_name": "cuppings"})
        assert fake.calls[-1] == expected, allowed


@pytest.mark.parametrize(
    ("engine", "name", "tables"),
    [
        ("postgres", "pg_roles", [TableSummary("public", "orders", "table")]),
        ("postgres", "PG_SETTINGS", []),
        ("oracle", "ALL_USERS", [TableSummary("TRAVEL", "TRAVELLERS", "table")]),
        ("oracle", "dba_users", []),
        # V$SESSION is refused on every connection (other sessions' SQL, 2026-09-28)
        ("oracle", "V$PARAMETER", []),
        ("mssql", "sysobjects", [TableSummary("dbo", "Patients", "table")]),
    ],
)
@pytest.mark.parametrize("tool", ["db_sample_table", "db_list_columns", "db_get_table"])
def test_a_bare_dictionary_name_without_an_allowlist_needs_the_system_schema(
    tmp_path: Path, monkeypatch: Any, engine: str, name: str, tables: list[TableSummary], tool: str
) -> None:
    """With no allowlist and no default-deny a bare name goes to the engine,
    which binds pg_roles to pg_catalog and ALL_USERS to a SYS view through a
    PUBLIC synonym: the spelling that bypassed allowed_system_schemas."""
    fake = _FakeConnector(tables)
    server = _fake_server(tmp_path, monkeypatch, fake, engine=engine, allowed=[], deny=False)
    text = _call_error(server, tool, {"connection_id": "remote", "object_name": name})
    assert "AUTHORIZATION_DENIED" in text and "system schema" in text, text
    assert fake.calls == []


def test_a_bare_dictionary_name_is_allowed_with_its_system_schema(tmp_path: Path, monkeypatch: Any) -> None:
    fake = _FakeConnector([])
    server, _ = _fake_app_server(
        tmp_path, monkeypatch, fake, engine="postgres", allowed=[], deny=False,
        security="  allowed_system_schemas: [pg_catalog]\n",
    )
    _call(server, "db_list_columns", {"connection_id": "remote", "object_name": "pg_roles"})
    assert fake.calls[-1] == (None, "pg_roles")


@pytest.mark.parametrize(
    ("engine", "tables", "name", "expected"),
    [
        # the catalog's own object with a dictionary-like name is read qualified,
        # so the engine cannot bind the bare name to its dictionary instead
        ("postgres", [TableSummary("public", "pg_custom", "table")], "pg_custom", ("public", "pg_custom")),
        ("oracle", [TableSummary("APP", "USER_ACCOUNTS", "table")], "user_accounts", ("APP", "USER_ACCOUNTS")),
        # an ordinary name still passes through as written
        ("postgres", [TableSummary("public", "orders", "table")], "orders", (None, "orders")),
        ("mysql", [], "user", (None, "user")),
        # except on Oracle, where a PUBLIC synonym may answer any bare name (review round 2)
        ("oracle", [TableSummary("TRAVEL", "TRAVELLERS", "table")], "TRAVELLERS", ("TRAVEL", "TRAVELLERS")),
    ],
)
def test_bare_names_without_an_allowlist_resolve_as_before_unless_the_dictionary_could_answer(
    tmp_path: Path, monkeypatch: Any, engine: str, tables: list[TableSummary], name: str, expected: tuple[Any, str]
) -> None:
    fake = _FakeConnector(tables)
    server = _fake_server(tmp_path, monkeypatch, fake, engine=engine, allowed=[], deny=False)
    _call(server, "db_list_columns", {"connection_id": "remote", "object_name": name})
    assert fake.calls[-1] == expected


@pytest.mark.parametrize("deny", [True, False])
def test_case_only_twins_are_refused_as_ambiguous_but_an_exact_spelling_wins(
    tmp_path: Path, monkeypatch: Any, deny: bool
) -> None:
    fake = _FakeConnector([TableSummary("app", "Orders", "table"), TableSummary("app", "orders", "table")])
    server = _fake_server(tmp_path, monkeypatch, fake, engine="postgres", allowed=["app"], deny=deny)
    _call(server, "db_list_columns", {"connection_id": "remote", "object_name": "Orders"})
    assert fake.calls[-1] == ("app", "Orders")
    _call(server, "db_list_columns", {"connection_id": "remote", "object_name": "orders"})
    assert fake.calls[-1] == ("app", "orders")
    text = _call_error(server, "db_list_columns", {"connection_id": "remote", "object_name": "ORDERS"})
    assert "VALIDATION_ERROR" in text and "differ only in case" in text, text
    if deny:
        _call(server, "db_list_columns", {"connection_id": "remote", "object_name": "app.orders"})
        assert fake.calls[-1] == ("app", "orders")
        text = _call_error(server, "db_list_columns", {"connection_id": "remote", "object_name": "APP.ORDERS"})
        assert "differ only in case" in text, text


# ------------------------------------------------- F19 get_table DEFAULT masking


@pytest.mark.parametrize("security", ["", "  mask_action: omit\n"])
def test_get_table_masks_sensitive_defaults_and_withholds_the_definition(tmp_path: Path, security: str) -> None:
    server, _ = _server(tmp_path, security=security)
    env = _call(server, "db_get_table", {"connection_id": "shop", "object_name": "customers"})
    cols = {c["name"]: c for c in env["data"]["columns"]}
    assert cols["ssn"]["default"] == "<masked>" and cols["ssn"]["sensitive"] is True
    assert cols["email"]["default"] == "'nobody@example.invalid'" and cols["email"]["sensitive"] is False
    assert "'unknown'" not in json.dumps(env)
    assert env["data"]["definition"] is None
    assert any("definition withheld" in w for w in env["warnings"])


def test_get_table_keeps_the_definition_without_a_sensitive_default(tmp_path: Path) -> None:
    server, _ = _server(tmp_path)
    db = tmp_path / "shop.db"
    c = sqlite3.connect(db)
    c.execute("CREATE TABLE plain (id INTEGER PRIMARY KEY, ssn TEXT, note TEXT DEFAULT 'n/a')")
    c.commit()
    c.close()
    env = _call(server, "db_get_table", {"connection_id": "shop", "object_name": "plain"})
    assert "CREATE TABLE plain" in env["data"]["definition"]
    assert not any("withheld" in w for w in env["warnings"])


def test_get_table_masks_defaults_of_the_base_composition(tmp_path: Path, monkeypatch: Any) -> None:
    fake = _FakeConnector(
        [TableSummary("app", "users", "table")],
        columns=[
            ColumnInfo("app", "users", "password", "text", default="'changeme'"),
            ColumnInfo("app", "users", "status", "text", default="'active'"),
        ],
    )
    server = _fake_server(tmp_path, monkeypatch, fake, engine="postgres", allowed=["app"], deny=True)
    env = _call(server, "db_get_table", {"connection_id": "remote", "object_name": "users"})
    cols = {c["name"]: c for c in env["data"]["columns"]}
    assert cols["password"]["default"] == "<masked>" and cols["password"]["sensitive"] is True
    assert cols["status"]["default"] == "'active'"
    assert "changeme" not in json.dumps(env)


@pytest.mark.parametrize(
    "ddl",
    [
        "CREATE TABLE users (id INTEGER, password TEXT CHECK (password <> 'Sup3rSecret'))",
        "CREATE TABLE users (id INTEGER, password TEXT, "
        "shadow TEXT GENERATED ALWAYS AS (coalesce(password, 'Sup3rSecret')))",
    ],
)
def test_get_table_withholds_a_definition_that_names_a_sensitive_column_beside_a_literal(
    tmp_path: Path, ddl: str
) -> None:
    server, _ = _sqlite_server(tmp_path, {"shop": ddl})
    env = _call(server, "db_get_table", {"connection_id": "shop", "object_name": "users"})
    assert "Sup3rSecret" not in json.dumps(env)
    assert env["data"]["definition"] is None and any("definition withheld" in w for w in env["warnings"])


def test_list_views_withholds_a_definition_that_names_a_sensitive_column_beside_a_literal(tmp_path: Path) -> None:
    script = (
        "CREATE TABLE users (id INTEGER, password TEXT, status TEXT);"
        "CREATE VIEW leaky AS SELECT id FROM users WHERE password = 'Sup3rSecret';"
        "CREATE VIEW plain AS SELECT id FROM users WHERE status = 'active';"
    )
    server, _ = _sqlite_server(tmp_path, {"shop": script})
    env = _call(server, "db_list_views", {"connection_id": "shop"})
    views = {v["name"]: v for v in env["data"]["views"]}
    assert "Sup3rSecret" not in json.dumps(env)
    assert views["leaky"]["definition"] is None and "'active'" in views["plain"]["definition"]
    assert any("definition" in w and "withheld" in w for w in env["warnings"]), env["warnings"]
    env = _call(server, "db_get_table", {"connection_id": "shop", "object_name": "leaky"})
    assert "Sup3rSecret" not in json.dumps(env)


# --------------------------------------------- F21 hidden schemas and FK targets


@pytest.mark.parametrize("engine", ["mysql", "clickhouse"])
def test_list_databases_applies_the_schema_allowlist(tmp_path: Path, monkeypatch: Any, engine: str) -> None:
    fake = _FakeConnector([], schemas=["app", "information_schema", "secret"])
    server = _fake_server(tmp_path, monkeypatch, fake, engine=engine, allowed=["app"], deny=True)
    dbs = _call(server, "db_list_databases", {"connection_id": "remote"})["data"]["databases"]
    schemas = _call(server, "db_list_schemas", {"connection_id": "remote"})["data"]["schemas"]
    assert dbs == schemas and "secret" not in dbs and "app" in dbs


def _fk_fake() -> _FakeConnector:
    return _FakeConnector(
        [TableSummary("app", "orders", "table"), TableSummary("app", "regions", "table")],
        columns=[
            ColumnInfo("app", "orders", "id", "integer"),
            ColumnInfo("app", "orders", "band_id", "integer"),
            ColumnInfo("app", "orders", "region_id", "integer"),
            ColumnInfo("app", "regions", "id", "integer"),
        ],
        fks=[
            KeyInfo("foreign_key", "fk_orders_band", ["band_id"], "secret", "salaries", ["band_code"],
                    source_schema="app", source_table="orders"),
            KeyInfo("foreign_key", "fk_orders_region", ["region_id"], "app", "regions", ["id"],
                    source_schema="app", source_table="orders"),
        ],
    )


def test_foreign_key_targets_in_hidden_schemas_are_redacted_everywhere(tmp_path: Path, monkeypatch: Any) -> None:
    server = _fake_server(tmp_path, monkeypatch, _fk_fake(), engine="postgres", allowed=["app"], deny=True)
    table = _call(server, "db_get_table", {"connection_id": "remote", "object_name": "orders"})
    rels = [
        _call(server, "db_get_relationships",
              {"connection_id": "remote", "object_name": "orders", "include_inferred": inferred})
        for inferred in (False, True)
    ]
    catalog = _call(server, "db_get_catalog", {"connection_id": "remote"})
    for env in (table, *rels, catalog):
        text = json.dumps(env)
        assert "secret" not in text and "salaries" not in text and "band_code" not in text, text
        assert "band_id" in text and "regions" in text, text  # local columns and the permitted FK stay
    fks = {fk["name"]: fk for fk in table["data"]["foreign_keys"]}
    assert fks["fk_orders_band"]["ref_table"] == "<not permitted>" and fks["fk_orders_band"]["ref_columns"] == []
    assert fks["fk_orders_band"]["columns"] == ["band_id"]
    assert fks["fk_orders_region"]["ref_table"] == "regions"
    declared = {d["constraint_name"]: d for d in rels[0]["data"]["declared"]}
    assert declared["fk_orders_band"]["to_table"] == "<not permitted>"
    assert declared["fk_orders_band"]["to_columns"] == [] and declared["fk_orders_band"]["from_columns"] == ["band_id"]
    assert declared["fk_orders_region"]["to_table"] == "app.regions"
    assert declared["fk_orders_region"]["to_columns"] == ["id"]


# ================================================================== part 2


def _sqlite_server(
    tmp_path: Path, scripts: dict[str, str], *, security: str = "", application: str = ""
) -> tuple[Any, AppContext]:
    conns = ""
    for name, script in scripts.items():
        db = tmp_path / f"{name}.db"
        c = sqlite3.connect(db)
        c.executescript(script)
        c.commit()
        c.close()
        conns += f"  {name}:\n    type: sqlite\n    database: {db}\n"
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "application:\n  transport: stdio\n"
        f"  audit_path: {tmp_path / 'audit.jsonl'}\n"
        f"  metadata_cache_path: {tmp_path / 'cache.sqlite'}\n{application}"
        f"security:\n  max_concurrent_queries: 4\n{security}"
        f"connections:\n{conns}",
        encoding="utf-8",
    )
    app_cfg, resolved = load_resolved(cfg)
    app = AppContext(app_cfg, resolved)
    return build_server(app), app


def _audit_lines(tmp_path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()]


class _CatalogFake(_FakeConnector):
    """The remote fake plus indexes and a statement runner: every statement
    is checked against the columns of the table it names (an unknown column
    is the engine's UndefinedColumn) and returns that table's rows."""

    quote_identifier = DatabaseConnector.quote_identifier
    escape_like = DatabaseConnector.escape_like
    like_predicate = DatabaseConnector.like_predicate
    text_expression = DatabaseConnector.text_expression
    placeholder = DatabaseConnector.placeholder
    pack_parameters = DatabaseConnector.pack_parameters
    build_search_query = DatabaseConnector.build_search_query
    LIKE_ESCAPE = DatabaseConnector.LIKE_ESCAPE

    def __init__(
        self,
        tables: list[TableSummary],
        *,
        columns: list[ColumnInfo],
        fks: list[KeyInfo] | None = None,
        indexes: list[IndexInfo] | None = None,
        rows: dict[str, list[dict[str, Any]]] | None = None,
    ) -> None:
        super().__init__(tables, columns=columns, fks=fks)
        self.indexes = indexes or []
        self.rows = rows or {}
        self.statements: list[str] = []

    def list_all_columns(self, schema: str | None) -> list[ColumnInfo]:
        return [c for c in self.columns if c.schema is None or c.schema.lower() == (schema or "").lower()]

    def list_indexes(self, _schema: str | None, table: str | None) -> list[IndexInfo]:
        return [i for i in self.indexes if table is None or i.table == table]

    def execute_query(self, spec: Any) -> QueryOutcome:
        self.statements.append(spec.sql)
        found = re.match(r'SELECT (.*) FROM "[^"]*"\."([^"]*)" WHERE (.*) LIMIT', spec.sql)
        assert found, spec.sql
        table = found.group(2)
        own = {c.name for c in self.columns if c.table == table}
        named = re.findall(r'"([^"]*)"', found.group(1) + " " + found.group(3))
        if not set(named) <= own:
            raise ConnectorError(f"UndefinedColumn: column does not exist on {table}")
        select = re.findall(r'"([^"]*)"', found.group(1))
        rows = [[r.get(n) for n in select] for r in self.rows.get(table, [])]
        return QueryOutcome(columns=[(n, "text") for n in select], rows=rows, truncated=False, rows_seen=len(rows),
                            elapsed_ms=0)


# --------------------------------------------- F42 exact (schema, table) split


def _case_fake() -> _CatalogFake:
    return _CatalogFake(
        [TableSummary("s", "Case_T", "table"), TableSummary("s", "case_t", "table")],
        columns=[
            ColumnInfo("s", "Case_T", "upper_only_col", "text"),
            ColumnInfo("s", "Case_T", "parent_ref", "integer"),
            ColumnInfo("s", "case_t", "id", "integer"),
            ColumnInfo("s", "case_t", "lower_col", "text"),
        ],
        fks=[KeyInfo("foreign_key", "fk_parent", ["parent_ref"], "s", "case_t", ["id"],
                     source_schema="s", source_table="Case_T")],
        indexes=[IndexInfo("case_t_pkey", ["id"], unique=True, primary=True, schema="s", table="case_t")],
        rows={"case_t": [{"id": 1, "lower_col": "memo in lower"}], "Case_T": [{"upper_only_col": "nothing"}]},
    )


def test_tables_differing_only_in_case_keep_their_own_columns_keys_and_statements(
    tmp_path: Path, monkeypatch: Any
) -> None:
    fake = _case_fake()
    server = _fake_server(tmp_path, monkeypatch, fake, engine="postgres", allowed=["s"], deny=True)
    catalog = {t["name"]: t for t in _call(server, "db_get_catalog", {"connection_id": "remote"})["data"]["tables"]}
    assert [c["name"] for c in catalog["Case_T"]["columns"]] == ["upper_only_col", "parent_ref"]
    assert catalog["Case_T"]["primary_key"] is None
    assert [k["name"] for k in catalog["Case_T"]["foreign_keys"]] == ["fk_parent"]
    assert [c["name"] for c in catalog["case_t"]["columns"]] == ["id", "lower_col"]
    assert catalog["case_t"]["primary_key"] == ["id"] and catalog["case_t"]["foreign_keys"] == []
    markdown = _call(server, "db_document_schema", {"connection_id": "remote"})["data"]["markdown"]
    upper, lower = markdown.split("## s.case_t")
    assert "lower_col" not in upper and "upper_only_col" not in lower and "fk_parent" not in lower
    env = _call(server, "db_search_values", {"query": "memo"})
    assert [(h["table"], h["matched_columns"]) for h in env["data"]["hits"]] == [("case_t", ["lower_col"])]
    assert env["warnings"] == [] and len(fake.statements) == 2
    rels = _call(server, "db_infer_relationships", {})["data"]["relationships"]
    declared = [(r["source"]["table"], r["target"]["table"]) for r in rels if r["kind"] == "declared"]
    assert declared == [("Case_T", "case_t")]


def test_a_bulk_list_spelled_in_another_case_still_matches_a_single_table(tmp_path: Path, monkeypatch: Any) -> None:
    fake = _CatalogFake(
        [TableSummary("s", "Orders", "table")],
        columns=[ColumnInfo("S", "ORDERS", "id", "integer"), ColumnInfo("S", "ORDERS", "memo", "text")],
        indexes=[IndexInfo("pk", ["id"], unique=True, primary=True, schema="S", table="ORDERS")],
        rows={"Orders": [{"id": 7, "memo": "memo seven"}]},
    )
    server = _fake_server(tmp_path, monkeypatch, fake, engine="postgres", allowed=["s"], deny=True)
    table = _call(server, "db_get_catalog", {"connection_id": "remote"})["data"]["tables"][0]
    assert [c["name"] for c in table["columns"]] == ["id", "memo"] and table["primary_key"] == ["id"]


# ------------------------------------------------ F09 connection-list bounds


def _spy_tables_for(monkeypatch: Any, fail: dict[str, BaseException] | None = None) -> list[str]:
    calls: list[str] = []
    real = AppContext.tables_for

    async def spy(self: AppContext, policy: Any, connector: Any) -> list[Any]:
        calls.append(policy.connection_id)
        if fail and policy.connection_id in fail:
            raise fail[policy.connection_id]
        return await real(self, policy, connector)

    monkeypatch.setattr(AppContext, "tables_for", spy)
    return calls


_INFER_SCRIPT = """
CREATE TABLE customers (customer_id INTEGER PRIMARY KEY, name TEXT);
INSERT INTO customers VALUES (1, 'User one');
CREATE TABLE orders (order_id INTEGER PRIMARY KEY, customer_id INTEGER, note TEXT);
INSERT INTO orders VALUES (1, 1, 'User note');
"""


def test_repeated_connection_ids_are_worked_on_once(tmp_path: Path, monkeypatch: Any) -> None:
    server, _ = _sqlite_server(tmp_path, {"shop": _INFER_SCRIPT})
    calls = _spy_tables_for(monkeypatch)
    once = _call(server, "db_search_metadata", {"query": "o", "connections": ["shop"]})
    calls.clear()
    many = _call(server, "db_search_metadata", {"query": "o", "connections": ["shop"] * 50})
    assert calls == ["shop"]
    assert many["data"]["matches"] == once["data"]["matches"]
    keys = [(m["connection_id"], m["schema"], m["name"]) for m in many["data"]["matches"]]
    assert len(keys) == len(set(keys)) == 2
    one = _call(server, "db_search_values", {"query": "user", "connections": ["shop"]})["data"]
    dup = _call(server, "db_search_values", {"query": "user", "connections": ["shop", "shop"]})["data"]
    assert (dup["hits"], dup["tables_searched"]) == (one["hits"], one["tables_searched"]) and one["hits"]
    one = _call(server, "db_infer_relationships", {"connections": ["shop"]})["data"]
    dup = _call(server, "db_infer_relationships", {"connections": ["shop", "shop"]})["data"]
    assert (dup["relationships"], dup["tables_considered"]) == (one["relationships"], one["tables_considered"])
    assert one["relationships"] and one["tables_considered"] == 2


def test_oversized_connection_lists_are_refused_before_any_io(tmp_path: Path, monkeypatch: Any) -> None:
    server, app = _server(tmp_path)
    calls = _spy_tables_for(monkeypatch)
    for tool, extra in (
        ("db_search_metadata", {"query": "x"}),
        ("db_search_values", {"query": "x"}),
        ("db_infer_relationships", {}),
        ("db_federated_query", {"sql": "SELECT 1"}),
    ):
        text = _call_error(server, tool, {"connections": ["shop"] * 1000, **extra})
        assert "at most 64" in text, text
    assert calls == []
    for bad, category in ((["shop"] * 65, "VALIDATION_ERROR"), ([], "VALIDATION_ERROR"),
                          (["shop", "ghost" * 100], "AUTHORIZATION_DENIED")):
        with pytest.raises(ToolFailure) as info:
            srv._select_connections(app, bad)
        assert info.value.category == category and len(str(info.value)) < 200
    assert srv._select_connections(app, ["shop"] * 64) == ["shop"]
    assert srv._select_connections(app, None) == ["shop"]


@pytest.mark.parametrize(
    ("tool", "extra"),
    [("db_search_metadata", {"query": "x"}), ("db_search_values", {"query": "x"}), ("db_infer_relationships", {})],
)
def test_a_repeated_dead_connection_fails_like_a_single_one(
    tmp_path: Path, monkeypatch: Any, tool: str, extra: dict[str, Any]
) -> None:
    server, _ = _server(tmp_path, names=("shop", "dead"))
    _spy_tables_for(monkeypatch, fail={"dead": ConnectorError("OperationalError: unable to open database file")})
    for conns in (["dead"], ["dead", "dead"]):
        assert "CONNECTION_ERROR" in _call_error(server, tool, {"connections": conns, **extra})


def test_a_raw_driver_error_on_one_connection_is_a_warning(tmp_path: Path, monkeypatch: Any) -> None:
    server, _ = _server(tmp_path, names=("flaky", "shop"))
    _spy_tables_for(monkeypatch, fail={"flaky": RuntimeError("driver exploded")})
    env = _call(server, "db_search_metadata", {"query": "cust"})
    assert [m["connection_id"] for m in env["data"]["matches"]] == ["shop"]
    assert any("flaky" in w and "driver exploded" in w for w in env["warnings"])


def test_inner_catalog_and_statement_failures_are_warnings(tmp_path: Path, monkeypatch: Any) -> None:
    server, _ = _sqlite_server(tmp_path, {"shop": _INFER_SCRIPT})
    real_query = SQLiteConnector.execute_query

    def flaky_query(self: Any, spec: Any) -> Any:
        if '"orders"' in spec.sql:
            raise RuntimeError("disk I/O error")
        return real_query(self, spec)

    monkeypatch.setattr(SQLiteConnector, "execute_query", flaky_query)
    env = _call(server, "db_search_values", {"query": "user"})
    assert [h["table"] for h in env["data"]["hits"]] == ["customers"]
    assert any("orders" in w and "disk I/O error" in w for w in env["warnings"])

    def broken(self: Any, schema: Any) -> Any:
        raise RuntimeError("catalog view missing")

    monkeypatch.setattr(SQLiteConnector, "list_all_columns", broken)
    env = _call(server, "db_infer_relationships", {})
    assert any("catalog view missing" in w for w in env["warnings"])


def test_search_ranking_runs_off_the_event_loop(tmp_path: Path, monkeypatch: Any) -> None:
    server, _ = _server(tmp_path)
    threads: list[threading.Thread] = []
    real = srv.rank_search

    def recording(*args: Any) -> Any:
        threads.append(threading.current_thread())
        return real(*args)

    monkeypatch.setattr(srv, "rank_search", recording)
    assert _call(server, "db_search_metadata", {"query": "cust"})["data"]["matches"]
    assert threads and threads[0] is not threading.main_thread()


# ------------------------------------------- F22 bounded ids and statements


_HUGE = "x" * 2_000_000


@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("db_sample_table", {"object_name": "a.b." + _HUGE}),
        ("db_sample_table", {"object_name": _HUGE}),
        ("db_sample_table", {"object_name": "customers", "schema": _HUGE}),
        ("db_sample_table", {"object_name": "customers", "columns": [_HUGE, "y" * 1000, *map(str, range(500))]}),
        ("db_profile_table", {"object_name": "customers", "columns": [_HUGE]}),
        ("db_list_tables", {"object_kinds": [_HUGE, "z" * 1000]}),
    ],
)
def test_caller_strings_are_echoed_bounded_in_error_text(tmp_path: Path, tool: str, args: dict[str, Any]) -> None:
    """An object name, schema, column or kind is whatever the caller sent
    (megabytes, over HTTP); the SDK also logs the error text."""
    server, _ = _server(tmp_path)
    text = _call_error(server, tool, {"connection_id": "shop", **args})
    assert len(text) < 4096, (tool, len(text))
    assert "VALIDATION_ERROR" in text or "AUTHORIZATION_DENIED" in text, text[:300]


def test_every_refusal_text_is_bounded(tmp_path: Path) -> None:
    """A refusal written elsewhere (the policy's schema checks) that names
    what the caller sent is cut before it reaches the model and the log."""
    _, app = _server(tmp_path)

    async def refuse() -> None:
        async with srv.tool_span(app, "db_list_views", "shop"):
            raise ToolFailure(srv.ErrorCategory.AUTHZ, f"schema '{_HUGE}' is not permitted")

    with pytest.raises(srv.ToolError) as info:
        anyio.run(refuse)
    assert str(info.value).startswith("AUTHORIZATION_DENIED: schema 'xxx") and len(str(info.value)) < 4096


def test_an_unknown_connection_id_is_recorded_as_a_marker_and_a_digest(tmp_path: Path) -> None:
    server, app = _server(tmp_path)
    huge = "x" * 1_000_000
    text = _call_error(server, "db_list_tables", {"connection_id": huge})
    assert "AUTHORIZATION_DENIED" in text and len(text.encode()) < 1024
    line = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()[-1]
    record = json.loads(line)
    assert len(line.encode()) < 2048
    assert record["connection_id"] == "<unknown>" and record["connection_id_len"] == 1_000_000
    assert record["connection_id_sha256"] == hashlib.sha256(huge.encode()).hexdigest()
    assert len(app.history[-1]["connection_id"]) <= 100
    _call(server, "db_list_tables", {"connection_id": "shop"})
    assert _audit_lines(tmp_path)[-1]["connection_id"] == "shop" and app.history[-1]["connection_id"] == "shop"
    fed = _call_error(server, "db_federated_join", {
        "left": {"connection": huge, "sql": "SELECT 1"}, "right": {"connection": "shop", "sql": "SELECT 1"},
        "on": [["a", "b"]]})
    assert len(fed.encode()) < 1024


def test_denied_calls_with_huge_ids_cannot_rotate_the_evidence_away(tmp_path: Path) -> None:
    server, _ = _sqlite_server(
        tmp_path, {"shop": "CREATE TABLE t (id INTEGER);"},
        application="  audit_max_bytes: 1048576\n  audit_max_backups: 2\n",
    )
    evidence = _call(server, "db_query", {"connection_id": "shop", "sql": "SELECT id FROM t"})["request_id"]
    for i in range(100):
        _call_error(server, "db_list_tables", {"connection_id": f"{i}-" + "y" * 100_000})
    files = sorted(tmp_path.glob("audit.jsonl*"))
    assert any(evidence in f.read_text(encoding="utf-8") for f in files if not f.name.endswith(".lock"))


def test_an_oversized_statement_is_audited_as_a_bounded_prefix(tmp_path: Path) -> None:
    server, app = _server(tmp_path, security="  audit_sql_text: true\n")
    sql = "SELECT '" + "z" * 1_000_000 + "'"
    env_text = _call_error(server, "db_query", {"connection_id": "shop", "sql": sql})
    assert "VALIDATION_ERROR" in env_text
    lines = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    call = [json.loads(line) for line in lines if '"db_query' in line]
    # refused before it ran: one record, its text left out (wave 4)
    assert [r["action"] for r in call] == ["db_query"]
    for line in (line for line in lines if '"db_query' in line):
        record = json.loads(line)
        assert len(line.encode()) <= 2048
        assert "sql_text" not in record and record["sql_len"] >= 1_000_000
        assert record["sql_sha256"] == hashlib.sha256(sql.encode()).hexdigest()
    assert all(len(json.dumps(h)) < 4096 for h in app.history)


# ---------------------------------------------- F23 per-statement audit trail

_MEMO_SCRIPT = """
CREATE TABLE notes (id INTEGER PRIMARY KEY, note TEXT);
INSERT INTO notes VALUES (1, 'a memo'), (2, 'other'), (3, 'memo two');
CREATE TABLE tickets (id INTEGER PRIMARY KEY, body TEXT);
INSERT INTO tickets VALUES (1, 'see memo');
"""


def test_value_search_audits_every_statement_without_the_needle(tmp_path: Path) -> None:
    server, _ = _sqlite_server(tmp_path, {"crm": _MEMO_SCRIPT, "erp": _MEMO_SCRIPT},
                               security="  audit_sql_text: true\n")
    env = _call(server, "db_search_values", {"query": "memo"})
    records = _audit_lines(tmp_path)
    stmts = [r for r in records if r["action"] == "db_search_values:statement"]
    assert {r["connection_id"] for r in stmts} == {"crm", "erp"} and len(stmts) == 4
    assert all(r["request_id"] == env["request_id"] and r["sql_fingerprint"] and r["outcome"] == "allow"
               and isinstance(r["row_count"], int) for r in stmts)
    assert sum(r["row_count"] for r in stmts) >= len(env["data"]["hits"]) == 6
    assert all("memo" not in json.dumps(r) and "?" in r["sql_text"] for r in stmts)
    span = next(r for r in records if r["action"] == "db_search_values")
    assert span["connection_ids"] == ["crm", "erp"]


def test_a_failing_search_statement_is_audited_and_the_search_goes_on(tmp_path: Path, monkeypatch: Any) -> None:
    server, _ = _sqlite_server(tmp_path, {"crm": _MEMO_SCRIPT})
    real = SQLiteConnector.execute_query

    def flaky(self: Any, spec: Any) -> Any:
        if '"tickets"' in spec.sql:
            raise ConnectorError("OperationalError: database is locked")
        return real(self, spec)

    monkeypatch.setattr(SQLiteConnector, "execute_query", flaky)
    env = _call(server, "db_search_values", {"query": "memo"})
    assert {h["table"] for h in env["data"]["hits"]} == {"notes"}
    stmts = [r for r in _audit_lines(tmp_path) if r["action"] == "db_search_values:statement"]
    assert sorted((r["outcome"], r.get("category")) for r in stmts) == [
        ("allow", None), ("error", "CONNECTION_ERROR")]


def test_a_failed_statement_audit_write_ends_the_search(tmp_path: Path, monkeypatch: Any) -> None:
    server, app = _sqlite_server(tmp_path, {"crm": _MEMO_SCRIPT})
    real = app.audit.record

    def failing(event: dict[str, Any]) -> None:
        if str(event.get("action", "")).endswith(":statement"):
            raise AuditWriteFailure("audit disk full")
        real(event)

    monkeypatch.setattr(app.audit, "record", failing)
    for tool, args in (
        ("db_search_values", {"query": "memo"}),
        ("db_review_schema", {"connection_id": "crm", "sample_rows": 5}),
    ):
        with pytest.raises(Exception):  # noqa: B017,PT011 - fail closed: any failure ends the call
            _call(server, tool, args)


def test_sample_and_profile_statements_are_fingerprinted(tmp_path: Path) -> None:
    server, _ = _server(tmp_path)
    sample = _call(server, "db_sample_table", {"connection_id": "shop", "object_name": "customers"})
    profile = _call(server, "db_profile_table", {"connection_id": "shop", "object_name": "customers"})
    records = _audit_lines(tmp_path)
    for env, tool in ((sample, "db_sample_table"), (profile, "db_profile_table")):
        stmts = [r for r in records if r["request_id"] == env["request_id"] and r["action"] == f"{tool}:statement"]
        assert stmts, tool
        assert all(r["sql_fingerprint"] and r["connection_id"] == "shop" and r["outcome"] == "allow" for r in stmts)


# ------------------------------------------------ F40 inference heuristic/bounds


def test_sibling_surrogate_keys_are_not_join_candidates(tmp_path: Path) -> None:
    script = "".join(
        f"CREATE TABLE t{i:03d} (id INTEGER PRIMARY KEY, uuid TEXT UNIQUE, note TEXT);" for i in range(300)
    )
    server, app = _sqlite_server(tmp_path, {"shop": script})
    started = time.monotonic()
    result = asyncio.run(server.call_tool("db_infer_relationships", {}))
    assert time.monotonic() - started < 30
    rels = result.structured_content["data"]["relationships"]
    per_column: dict[tuple[str, str], int] = {}
    for r in rels:
        if r["kind"] == "inferred_name_type" and r["source_columns"] == ["uuid"]:
            key = (r["source"]["table"], "uuid")
            per_column[key] = per_column.get(key, 0) + 1
    assert all(n <= 5 for n in per_column.values()) and not per_column
    assert len(result.content[0].text.encode()) <= app.cfg.security.max_response_bytes + 2048


_REFERENCE_SCRIPT = """
CREATE TABLE customers (customer_id INTEGER PRIMARY KEY, uuid TEXT UNIQUE, name TEXT);
CREATE TABLE customer_details (customer_id INTEGER PRIMARY KEY, bio TEXT);
CREATE TABLE orders (order_id INTEGER PRIMARY KEY, customer_id INTEGER, uuid TEXT UNIQUE);
CREATE TABLE products (id INTEGER PRIMARY KEY, uuid TEXT UNIQUE);
CREATE TABLE order_items (order_id INTEGER REFERENCES orders(order_id), product_id INTEGER, uuid TEXT UNIQUE);
"""


def test_inference_keeps_references_and_declared_keys(tmp_path: Path) -> None:
    server, _ = _sqlite_server(tmp_path, {"shop": _REFERENCE_SCRIPT})
    rels = _call(server, "db_infer_relationships", {})["data"]["relationships"]
    pairs = {(r["kind"], r["source"]["table"], tuple(r["source_columns"]), r["target"]["table"]) for r in rels}
    assert ("declared", "order_items", ("order_id",), "orders") in pairs
    assert ("inferred_name_type", "orders", ("customer_id",), "customers") in pairs
    # a 1:1 table whose own key is named for the target table is a reference
    assert ("inferred_name_type", "customer_details", ("customer_id",), "customers") in pairs
    assert ("inferred_name_pattern", "order_items", ("product_id",), "products") in pairs
    assert not [p for p in pairs if p[2] == ("uuid",)], "uuid is every table's own key, not a reference"


def test_inference_drops_sibling_keys_even_between_two_tables() -> None:
    def table(name: str) -> TableFacts:
        return TableFacts(
            ref=TableRef("c", "s", name), engine="postgres",
            columns=[ColumnInfo("s", name, "id", "integer"), ColumnInfo("s", name, "external_id", "text")],
            indexes=[IndexInfo("pk", ["id"], primary=True), IndexInfo("uq", ["external_id"], unique=True)],
            foreign_keys=[],
        )

    assert infer_relationships([table("a"), table("b")]) == []


def _keyed(name: str, key: str, *others: str) -> TableFacts:
    return TableFacts(
        ref=TableRef("c", "s", name), engine="postgres",
        columns=[ColumnInfo("s", name, c, "integer") for c in (key, *others)],
        indexes=[IndexInfo("pk", [key], primary=True)], foreign_keys=[],
    )


def test_a_natural_key_shared_by_extension_tables_still_references_its_hub() -> None:
    """employee_no is the key of employees and of four 1:1 extension tables:
    more than three tables share it, but a table that is not keyed by it and
    reads it references the table its name derives from."""
    facts = [
        _keyed("employees", "employee_no"),
        *(_keyed(f"emp_{x}", "employee_no") for x in "abcd"),
        _keyed("orders", "order_id", "employee_no"),
    ]
    found = {
        (r.source.table, r.target.table) for r in infer_relationships(facts)
        if r.kind == "inferred_name_type" and r.source_columns == ["employee_no"]
    }
    assert ("orders", "employees") in found
    assert not {t for s_, t in found if s_ == "orders" and t != "employees"}, found
    # a key name that names no table stays a convention: every table's own uuid
    uuids = [_keyed(f"t{i}", "uuid") for i in range(5)] + [_keyed("log", "log_id", "uuid")]
    assert not [r for r in infer_relationships(uuids) if r.kind == "inferred_name_type"]


def test_inferred_relationships_are_capped_and_say_so(tmp_path: Path, monkeypatch: Any) -> None:
    script = _REFERENCE_SCRIPT + "".join(
        f"CREATE TABLE extra{i} (id INTEGER PRIMARY KEY, customer_id INTEGER, product_id INTEGER);" for i in range(6)
    )
    server, _ = _sqlite_server(tmp_path, {"shop": script})
    full = _call(server, "db_infer_relationships", {})["data"]
    assert full["truncated"] is False and full["more_available"] == 0
    monkeypatch.setattr(srv, "_INFER_MAX_RELATIONSHIPS", 3)
    env = _call(server, "db_infer_relationships", {})
    data = env["data"]
    kinds = [r["kind"] for r in data["relationships"]]
    assert kinds.count("declared") == 1 and len(kinds) == 4, "declared keys are never dropped by the count cap"
    assert data["truncated"] is True and data["more_available"] == len(full["relationships"]) - 4
    assert any("not returned" in w for w in env["warnings"])
    monkeypatch.setattr(srv, "_INFER_MAX_RELATIONSHIPS", 1000)
    monkeypatch.setattr(srv, "_INFER_MAX_PER_COLUMN", 1)
    data = _call(server, "db_infer_relationships", {"cross_connection": True})["data"]
    columns = [
        (r["source"]["table"], tuple(r["source_columns"])) for r in data["relationships"] if r["kind"] != "declared"
    ]
    assert len(columns) == len(set(columns)) and data["truncated"] is (len(columns) < len(full["relationships"]) - 1)


def test_inference_runs_off_the_event_loop(tmp_path: Path, monkeypatch: Any) -> None:
    server, _ = _sqlite_server(tmp_path, {"shop": _REFERENCE_SCRIPT})
    threads: list[threading.Thread] = []
    real = srv.infer_relationships

    def recording(*args: Any, **kwargs: Any) -> Any:
        threads.append(threading.current_thread())
        return real(*args, **kwargs)

    monkeypatch.setattr(srv, "infer_relationships", recording)
    assert _call(server, "db_infer_relationships", {})["data"]["relationships"]
    assert threads and threads[0] is not threading.main_thread()


# ------------------------------------------ F41 search projection and chunks


def _wide_search_script(table: str, columns: int, rows: list[dict[str, str]]) -> str:
    cols = ", ".join(f"c{i} TEXT" for i in range(1, columns + 1))
    script = f"CREATE TABLE {table} (id INTEGER PRIMARY KEY, {cols});"
    for n, row in enumerate(rows, start=1):
        values = ", ".join(f"'{row.get(f'c{i}', 'x')}'" for i in range(1, columns + 1))
        script += f"INSERT INTO {table} VALUES ({n}, {values});"
    return script


@pytest.mark.parametrize("match", ["contains", "exact"])
def test_a_value_only_in_a_late_column_is_found(tmp_path: Path, match: str) -> None:
    server, _ = _sqlite_server(tmp_path, {"shop": _wide_search_script("wide", 10, [{"c10": "onlyinc10"}])})
    env = _call(server, "db_search_values", {"query": "onlyinc10", "match": match})
    assert [(h["table"], h["matched_columns"]) for h in env["data"]["hits"]] == [("wide", ["c10"])]
    assert env["data"]["hits"][0]["row"]["c10"] == "onlyinc10" and env["data"]["tables_partially_searched"] == []


def test_the_per_table_limit_is_not_spent_on_rows_it_cannot_show(tmp_path: Path) -> None:
    rows = [{"c10": "zz-needle"}] * 5 + [{"c1": "zz-needle"}]
    server, _ = _sqlite_server(tmp_path, {"shop": _wide_search_script("wide", 10, rows)})
    hits = _call(server, "db_search_values", {"query": "zz-needle", "max_hits_per_table": 5})["data"]["hits"]
    assert len(hits) == 5 and all(h["matched_columns"] for h in hits)


def test_a_text_column_after_seven_numeric_ones_is_searched(tmp_path: Path) -> None:
    nums = ", ".join(f"n{i} REAL" for i in range(1, 8))
    script = f"CREATE TABLE m (id INTEGER PRIMARY KEY, {nums}, notes TEXT);"
    script += "INSERT INTO m VALUES (1, 1, 2, 3, 4, 5, 6, 7, 'find-me-in-notes');"
    server, _ = _sqlite_server(tmp_path, {"shop": script})
    hits = _call(server, "db_search_values", {"query": "find-me"})["data"]["hits"]
    assert [h["matched_columns"] for h in hits] == [["notes"]]


def _record_statements(monkeypatch: Any) -> list[str]:
    seen: list[str] = []
    real = SQLiteConnector.execute_query

    def recording(self: Any, spec: Any) -> Any:
        seen.append(spec.sql)
        return real(self, spec)

    monkeypatch.setattr(SQLiteConnector, "execute_query", recording)
    return seen


def test_every_column_a_search_predicate_reads_is_projected(tmp_path: Path, monkeypatch: Any) -> None:
    rows = [{"c40": "deep-needle"}, {"c2": "deep-needle"}]
    server, _ = _sqlite_server(tmp_path, {"shop": _wide_search_script("wide", 40, rows)})
    seen = _record_statements(monkeypatch)
    env = _call(server, "db_search_values", {"query": "deep-needle", "max_hits_per_table": 10})
    assert sorted(h["matched_columns"][0] for h in env["data"]["hits"]) == ["c2", "c40"]
    assert len(seen) == 3, "40 text columns are searched in chunks of 16"
    for sql in seen:
        select, where = re.match(r"SELECT (.*) FROM .* WHERE (.*) LIMIT", sql).groups()  # type: ignore[union-attr]
        assert set(re.findall(r'"([^"]+)"', where)) <= set(re.findall(r'"([^"]+)"', select)), sql


def test_columns_left_unsearched_are_reported(tmp_path: Path, monkeypatch: Any) -> None:
    server, _ = _sqlite_server(tmp_path, {"shop": _wide_search_script("wide", 10, [{"c10": "hidden-needle"}])})
    monkeypatch.setattr(srv, "_SEARCH_CHUNK_COLUMNS", 4)
    monkeypatch.setattr(srv, "_SEARCH_MAX_COLUMNS", 8)
    env = _call(server, "db_search_values", {"query": "hidden-needle"})
    assert env["data"]["hits"] == [] and env["warnings"] != []
    assert env["data"]["tables_partially_searched"] == [
        {"connection": "shop", "schema": "main", "table": "wide", "columns_searched": 8, "columns_searchable": 10}
    ]
    assert any("wide" in w and "8 of 10 searchable columns" in w for w in env["warnings"])
    monkeypatch.setattr(srv, "_SEARCH_MAX_COLUMNS", 128)
    env = _call(server, "db_search_values", {"query": "hidden-needle"})
    assert [h["matched_columns"] for h in env["data"]["hits"]] == [["c10"]]


def test_a_row_matching_in_two_chunks_is_reported_once(tmp_path: Path, monkeypatch: Any) -> None:
    server, _ = _sqlite_server(tmp_path, {"shop": _wide_search_script("wide", 10, [{"c1": "twice", "c9": "twice"}])})
    monkeypatch.setattr(srv, "_SEARCH_CHUNK_COLUMNS", 4)
    hits = _call(server, "db_search_values", {"query": "twice"})["data"]["hits"]
    # the later chunk's match is added to the hit the earlier one made
    assert [h["matched_columns"] for h in hits] == [["c1", "c9"]]
    assert hits[0]["row"]["c1"] == hits[0]["row"]["c9"] == "twice"


def test_names_with_control_characters_are_never_put_into_search_sql(tmp_path: Path, monkeypatch: Any) -> None:
    fake = _CatalogFake(
        [TableSummary("s", "ok", "table"), TableSummary("s", "bad\x00name", "table")],
        columns=[
            ColumnInfo("s", "ok", "id", "integer"), ColumnInfo("s", "ok", "memo", "text"),
            ColumnInfo("s", "ok", "tab\tcol", "text"), ColumnInfo("s", "bad\x00name", "memo", "text"),
        ],
        rows={"ok": [{"id": 1, "memo": "memo here"}]},
    )
    server = _fake_server(tmp_path, monkeypatch, fake, engine="postgres", allowed=["s"], deny=True)
    env = _call(server, "db_search_values", {"query": "memo"})
    assert [h["table"] for h in env["data"]["hits"]] == ["ok"]
    assert all("\x00" not in sql and "\t" not in sql for sql in fake.statements) and len(fake.statements) == 1
    assert any("control characters" in w and w.startswith("2 ") for w in env["warnings"])


# ----------------------------------------------------- F18 response ceilings

_CEILING = 4096
_ALLOWANCE = 2048  # the envelope around a paged payload
_SLACK = 64 * 1024  # the backstop's allowance


def _wide_script(tables: int, columns: int) -> str:
    script = ""
    for t in range(tables):
        cols = ", ".join(f"col_{i:03d} TEXT DEFAULT 'd{i}'" for i in range(columns))
        script += (
            f"CREATE TABLE t{t:03d} (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES t{(t + 1) % tables:03d}(id), "
            f"uuid TEXT UNIQUE, {cols});"
            f"CREATE INDEX ix_t{t:03d} ON t{t:03d}(col_000, col_001);"
            f"INSERT INTO t{t:03d} (id, uuid, col_000) VALUES (1, 'u{t}', 'needle-{t}');"
        )
    return script + "CREATE VIEW v1 AS SELECT * FROM t000;"


@pytest.fixture(scope="module")
def wide(tmp_path_factory: pytest.TempPathFactory) -> Any:
    tmp_path = tmp_path_factory.mktemp("wide")
    server, _ = _sqlite_server(tmp_path, {"w": _wide_script(200, 40)}, security=f"  max_response_bytes: {_CEILING}\n")
    return server


_EVERY_TOOL: dict[str, dict[str, Any]] = {
    "db_list_connections": {},
    "db_test_connection": {"connection_id": "w"},
    "db_get_capabilities": {"connection_id": "w"},
    "db_list_catalogs": {"connection_id": "w"},
    "db_list_databases": {"connection_id": "w"},
    "db_list_schemas": {"connection_id": "w"},
    "db_list_tables": {"connection_id": "w"},
    "db_get_table": {"connection_id": "w", "object_name": "t000"},
    "db_list_columns": {"connection_id": "w", "object_name": "t000"},
    "db_list_views": {"connection_id": "w"},
    "db_list_synonyms": {"connection_id": "w"},
    "db_list_routines": {"connection_id": "w"},
    "db_search_metadata": {"query": "t"},
    "db_get_relationships": {"connection_id": "w", "object_name": "t000", "include_inferred": True},
    "db_get_statistics": {"connection_id": "w", "object_name": "t000"},
    "db_validate_query": {"connection_id": "w", "sql": "SELECT * FROM t000"},
    "db_query": {"connection_id": "w", "sql": "SELECT * FROM t000"},
    "db_federated_query": {"sql": "SELECT * FROM t000"},
    "db_federated_join": {"left": {"connection": "w", "sql": "SELECT id, col_000 FROM t000"},
                          "right": {"connection": "w", "sql": "SELECT id, col_001 FROM t001"}, "on": [["id", "id"]]},
    "db_sample_table": {"connection_id": "w", "object_name": "t000"},
    "db_explain": {"connection_id": "w", "sql": "EXPLAIN QUERY PLAN SELECT * FROM t000"},
    "db_get_query_history": {"limit": 100},
    "db_list_indexes": {"connection_id": "w"},
    "db_get_catalog": {"connection_id": "w", "page_size": 200},
    "db_review_schema": {"connection_id": "w", "max_tables": 5, "sample_rows": 5},
    "db_document_schema": {"connection_id": "w"},
    "db_profile_table": {"connection_id": "w", "object_name": "t000", "sample_rows": 5},
    "db_search_values": {"query": "needle"},
    "db_infer_relationships": {},
}
# One object's own detail: bounded by that object's width, and by the backstop.
_PER_OBJECT = {"db_get_table", "db_profile_table", "db_get_query_history"}


def test_the_ceiling_test_covers_every_registered_tool(wide: Any) -> None:
    assert {t.name for t in asyncio.run(wide.list_tools())} == set(_EVERY_TOOL)


@pytest.mark.parametrize("tool", sorted(_EVERY_TOOL))
def test_every_tool_response_fits_the_byte_ceiling(wide: Any, tool: str) -> None:
    try:
        env = _call(wide, tool, _EVERY_TOOL[tool])
    except Exception as exc:  # noqa: BLE001 - a refusal is a bounded outcome too
        text = str(exc)
        # only one object's own detail may be refused by the backstop: every
        # listing has a pager, and a pager hidden by the backstop is a regression
        refused = "LIMIT_EXCEEDED" in text and "security.max_response_bytes" in text
        assert "CAPABILITY_UNSUPPORTED" in text or (refused and tool in _PER_OBJECT), text
        return
    size = len(json.dumps(env["data"], separators=(",", ":"), ensure_ascii=False).encode())
    assert size <= _CEILING + (_SLACK if tool in _PER_OBJECT else _ALLOWANCE), (tool, size)
    assert len(json.dumps(env, separators=(",", ":"), ensure_ascii=False).encode()) <= _CEILING + _SLACK
    cut = any("security.max_response_bytes" in w for w in env.get("warnings", []))
    if cut:
        data = env["data"] if isinstance(env["data"], dict) else {}
        assert env.get("next_cursor") or env.get("truncated") or data.get("truncated") or data.get(
            "budget_exhausted") or (data.get("merged") or {}).get("truncated"), (tool, env.get("warnings"))


def _follow(server: Any, tool: str, args: dict[str, Any], key: str) -> tuple[list[Any], list[dict[str, Any]]]:
    items: list[Any] = []
    envs: list[dict[str, Any]] = []
    cursor = None
    for _ in range(1000):
        env = _call(server, tool, {**args, **({"cursor": cursor} if cursor else {})})
        envs.append(env)
        items.extend(env["data"][key])
        cursor = env.get("next_cursor")
        if not cursor:
            return items, envs
    raise AssertionError("the cursor never ended")


# 200 tables and the view v1 (never SQLite's own catalog); per table its key, ix_tNNN and the UNIQUE autoindex
@pytest.mark.parametrize(
    ("tool", "key", "total"), [("db_list_tables", "tables", 201), ("db_list_indexes", "indexes", 600)]
)
def test_listings_are_cut_by_bytes_and_resume_exactly_there(wide: Any, tool: str, key: str, total: int) -> None:
    items, envs = _follow(wide, tool, {"connection_id": "w"}, key)
    names = [json.dumps(i, sort_keys=True) for i in items]
    assert len(names) == len(set(names)) == total
    assert any("security.max_response_bytes" in w for w in envs[0]["warnings"]) and envs[0]["next_cursor"]
    for env in envs:
        assert len(json.dumps(env["data"], separators=(",", ":")).encode()) <= _CEILING


def test_catalog_pages_by_bytes_and_visits_every_table_once(tmp_path: Path) -> None:
    server, _ = _sqlite_server(tmp_path, {"shop": _wide_script(200, 120)})
    tables, envs = _follow(server, "db_get_catalog", {"connection_id": "shop", "page_size": 200}, "tables")
    assert envs[0].get("next_cursor") and any("security.max_response_bytes" in w for w in envs[0]["warnings"])
    assert sorted(t["name"] for t in tables) == [*(f"t{i:03d}" for i in range(200)), "v1"]
    for env in envs:
        assert len(json.dumps(env["data"], separators=(",", ":")).encode()) <= 1024 * 1024


class _ListingFake(_FakeConnector):
    def list_synonyms(self, _schema: str | None) -> list[SynonymInfo]:
        return [SynonymInfo("app", f"syn_{i:05d}", "app", f"target_{i:05d}", "table") for i in range(13000)]

    def list_routines(self, _schema: str | None) -> list[RoutineInfo]:
        return [RoutineInfo("app", f"fn_{i:05d}", "function", ["integer"], "integer") for i in range(13000)]


@pytest.mark.parametrize(("tool", "key", "first"), [("db_list_synonyms", "synonyms", "syn_"),
                                                    ("db_list_routines", "routines", "fn_")])
def test_synonyms_and_routines_are_paged(tmp_path: Path, monkeypatch: Any, tool: str, key: str, first: str) -> None:
    server = _fake_server(tmp_path, monkeypatch, _ListingFake([]), engine="postgres", allowed=["app"], deny=True)
    env = _call(server, tool, {"connection_id": "remote"})
    assert env["next_cursor"] and env["truncated"] is True and len(env["data"][key]) == 50
    again = _call(server, tool, {"connection_id": "remote", "cursor": env["next_cursor"]})
    assert again["data"][key][0]["name"] == f"{first}00050"


def test_federated_merged_view_is_charged_against_the_ceiling(tmp_path: Path) -> None:
    script = "CREATE TABLE notes (id INTEGER PRIMARY KEY, note TEXT);" + "".join(
        f"INSERT INTO notes VALUES ({i}, '{'n' * 60}');" for i in range(100)
    )
    server, _ = _sqlite_server(tmp_path, {"crm": script, "erp": script}, security=f"  max_response_bytes: {_CEILING}\n")
    env = _call(server, "db_federated_query", {"sql": "SELECT id, note FROM notes"})
    assert len(json.dumps(env["data"], separators=(",", ":")).encode()) <= _CEILING + _ALLOWANCE
    merged = env["data"]["merged"]
    assert merged["truncated"] is True and merged["row_count"] == len(merged["rows"])
    assert any("merged" in w and "security.max_response_bytes" in w for w in env["warnings"])


def test_review_recommendations_are_charged_against_the_ceiling(tmp_path: Path) -> None:
    script = "".join(
        f"CREATE TABLE r{i} (a TEXT, b TEXT, c TEXT, d TEXT);"
        + "".join(f"INSERT INTO r{i} VALUES ('x', 'y', 'z', 'w');" for _ in range(3))
        for i in range(6)
    )
    server, _ = _sqlite_server(tmp_path, {"shop": script}, security="  max_response_bytes: 3000\n")
    env = _call(server, "db_review_schema", {"connection_id": "shop", "sample_rows": 5})
    # every finding is sent twice (its table and recommendations); both count
    assert len(json.dumps(env["data"], separators=(",", ":")).encode()) <= 3000
    assert env.get("next_cursor") and any("security.max_response_bytes" in w for w in env["warnings"])


def test_a_first_entry_over_the_ceiling_is_trimmed(tmp_path: Path) -> None:
    cols = ", ".join(f"a_rather_long_column_name_{i:03d} TEXT" for i in range(60))
    script = f"CREATE TABLE big ({cols}); CREATE TABLE small (id INTEGER);"
    server, _ = _sqlite_server(tmp_path, {"shop": script}, security="  max_response_bytes: 700\n")
    doc = _call(server, "db_document_schema", {"connection_id": "shop"})
    assert len(json.dumps(doc["data"], separators=(",", ":")).encode()) <= 700 + _ALLOWANCE
    assert "a_rather_long_column_name_000" in doc["data"]["markdown"]
    assert "a_rather_long_column_name_059" not in doc["data"]["markdown"]
    assert any("big" in w and "columns" in w and "security.max_response_bytes" in w for w in doc["warnings"])
    catalog = _call(server, "db_get_catalog", {"connection_id": "shop"})
    first = catalog["data"]["tables"][0]
    assert first["name"] == "big" and first["columns_truncated"] is True and catalog["next_cursor"]
    assert len(json.dumps(catalog["data"], separators=(",", ":")).encode()) <= 700 + _ALLOWANCE


def test_definitions_and_comments_are_capped_by_max_cell_bytes(tmp_path: Path) -> None:
    cols = ", ".join(f"a_rather_long_column_name_{i:03d} TEXT" for i in range(10))
    view_cols = cols.replace(" TEXT", "")
    script = f"CREATE TABLE big (id INTEGER PRIMARY KEY, {cols}); CREATE VIEW v AS SELECT {view_cols} FROM big;"
    server, _ = _sqlite_server(tmp_path, {"shop": script}, security="  max_cell_bytes: 64\n")
    table = _call(server, "db_get_table", {"connection_id": "shop", "object_name": "big"})
    assert len(table["data"]["definition"].encode()) <= 64
    assert any("security.max_cell_bytes" in w for w in table["warnings"])
    views = _call(server, "db_list_views", {"connection_id": "shop"})
    assert len(views["data"]["views"][0]["definition"].encode()) <= 64
    assert any("security.max_cell_bytes" in w for w in views["warnings"])


def test_the_backstop_refuses_a_result_far_over_the_ceiling(tmp_path: Path, monkeypatch: Any) -> None:
    server, _ = _server(tmp_path, security=f"  max_response_bytes: {_CEILING}\n")
    monkeypatch.setattr(SQLiteConnector, "get_statistics", lambda self, schema, table: {"blob": "x" * 200_000})
    text = _call_error(server, "db_get_statistics", {"connection_id": "shop", "object_name": "customers"})
    assert "LIMIT_EXCEEDED" in text and "security.max_response_bytes" in text, text
    record = _audit_lines(tmp_path)[-1]
    assert (record["outcome"], record["category"]) == ("deny", "LIMIT_EXCEEDED")


def test_masked_rows_are_cut_again_to_the_byte_ceiling(tmp_path: Path) -> None:
    """The connector fits rows to security.max_response_bytes before masking;
    '<masked>' can be longer than what it replaced (every column is masked
    when the output cannot be traced), so the rows are cut again after it."""
    cols = ", ".join(f"pin_{i} INTEGER" for i in range(20))
    script = f"CREATE TABLE wide (id INTEGER, {cols});" + "".join(
        f"INSERT INTO wide VALUES ({i}{', 1' * 20});" for i in range(500)
    )
    server, _ = _sqlite_server(tmp_path, {"shop": script}, security=f"  max_response_bytes: {_CEILING}\n")
    env = _call(server, "db_query", {"connection_id": "shop", "max_rows": 500,
                                     "sql": "SELECT * FROM wide UNION ALL SELECT * FROM wide WHERE 0"})
    rows = env["data"]["rows"]
    assert rows and all(v == "<masked>" for r in rows for v in r)
    assert sum(len(json.dumps(r).encode()) for r in rows) <= _CEILING
    assert env["truncated"] is True and any(w.startswith("result truncated") for w in env["warnings"])
    fed = _call(server, "db_federated_query", {"max_rows_per_connection": 500,
                                               "sql": "SELECT * FROM wide UNION ALL SELECT * FROM wide WHERE 0"})
    result = fed["data"]["results"][0]
    assert result["truncated"] is True and sum(len(json.dumps(r).encode()) for r in result["rows"]) <= _CEILING


def test_a_response_is_serialized_once(tmp_path: Path, monkeypatch: Any) -> None:
    """The envelope is measured for the ceiling as the compact text the
    client receives; that text is sent as measured, not serialized again."""
    server, _ = _server(tmp_path)
    real = json.dumps
    envelopes: list[int] = []

    def counting(obj: Any, *args: Any, **kwargs: Any) -> str:
        if isinstance(obj, dict) and "request_id" in obj:
            envelopes.append(id(obj))
        return real(obj, *args, **kwargs)

    monkeypatch.setattr(srv, "json", type("_Json", (), {"dumps": staticmethod(counting), "loads": json.loads}))
    args = {"connection_id": "shop", "sql": "SELECT full_name FROM customers"}
    result = asyncio.run(server.call_tool("db_query", args))
    assert len(envelopes) == 1, envelopes
    assert json.loads(result.content[0].text) == result.structured_content


def test_envelope_warnings_are_bounded() -> None:
    st = {"request_id": "r", "start": time.monotonic()}
    env = srv._envelope(st, None, None, {}, warnings=[f"warning {i}" for i in range(500)])
    assert len(env["warnings"]) == 50 and env["warnings"][-1].startswith("451 further warning(s)")
    assert env["warnings"][:49] == [f"warning {i}" for i in range(49)]


def test_sample_and_profile_never_put_control_characters_into_sql(tmp_path: Path, monkeypatch: Any) -> None:
    script = (
        'CREATE TABLE plain (id INTEGER PRIMARY KEY, "odd\tcol" TEXT, note TEXT);'
        "INSERT INTO plain VALUES (1, 'x', 'y');"
        'CREATE TABLE "tab\there" (id INTEGER PRIMARY KEY);'
    )
    server, _ = _sqlite_server(tmp_path, {"shop": script})
    seen = _record_statements(monkeypatch)
    profile = _call(server, "db_profile_table", {"connection_id": "shop", "object_name": "plain", "sample_rows": 5})
    assert [c["name"] for c in profile["data"]["columns"]] == ["id", "note"]
    assert any("control characters" in w for w in profile["warnings"])
    sample = _call(server, "db_sample_table",
                   {"connection_id": "shop", "object_name": "plain", "columns": ["id", "odd\tcol"]})
    assert [c["name"] for c in sample["data"]["columns"]] == ["id"]
    assert any("control characters" in w for w in sample["warnings"])
    for tool in ("db_sample_table", "db_profile_table"):
        text = _call_error(server, tool, {"connection_id": "shop", "object_name": "tab\there"})
        assert "VALIDATION_ERROR" in text and "control character" in text, text
    review = _call(server, "db_review_schema", {"connection_id": "shop", "sample_rows": 5})
    assert [t["name"] for t in review["data"]["tables"]] == ["plain"]
    assert any("control character" in w for w in review["warnings"])
    assert seen and all("\t" not in sql for sql in seen)


# ------------------------------------------------ F60 scalar parameter values

_NOT_SCALAR = [
    ("SELECT ? AS x", [{"a": 1}]),
    ("SELECT ? AS x", [[1, 2]]),
    ("SELECT :p AS x", {"p": {"x": 1}}),
    ("SELECT ? AS x", [{"x' OR 1=1 -- ": 1}]),
    ("SELECT :p AS x", {"x' OR 1=1 -- ": 1}),
]


@pytest.mark.parametrize(("sql", "parameters"), _NOT_SCALAR)
def test_non_scalar_parameters_never_reach_the_driver(
    tmp_path: Path, monkeypatch: Any, sql: str, parameters: Any
) -> None:
    server, _ = _server(tmp_path)
    seen = _record_statements(monkeypatch)
    text = _call_error(server, "db_query", {"connection_id": "shop", "sql": sql, "parameters": parameters})
    assert "VALIDATION_ERROR" in text and "parameter" in text, text
    # refused before it ran: the call's record is the statement's (wave 4)
    records = _audit_lines(tmp_path)
    assert [(r["action"], r["outcome"], r["category"]) for r in records] == [("db_query", "deny", "VALIDATION_ERROR")]
    # the federated tool refuses the call itself, not each connection
    text = _call_error(server, "db_federated_query", {"sql": sql, "parameters": parameters})
    assert "VALIDATION_ERROR" in text and "parameter" in text, text
    assert seen == []


def test_scalar_parameters_are_still_bound(tmp_path: Path) -> None:
    server, _ = _server(tmp_path)
    env = _call(server, "db_query", {"connection_id": "shop", "sql": "SELECT ?, ?, ?, ?, ?",
                                     "parameters": [1, "x", None, 1.5, True]})
    assert env["data"]["rows"] == [[1, "x", None, 1.5, 1]]
    env = _call(server, "db_query", {"connection_id": "shop", "sql": "SELECT :name_1 AS v",
                                     "parameters": {"name_1": "ok"}})
    assert env["data"]["rows"] == [["ok"]]


# ------------------------------------------- F66 cursors bound to their filters

_LISTING_SCRIPT = "".join(f"CREATE TABLE t{i} (id INTEGER); CREATE VIEW v{i} AS SELECT id FROM t{i};" for i in range(8))


@pytest.mark.parametrize(
    ("tool", "key", "filters", "other"),
    [
        ("db_list_tables", "tables", {}, {"schema": "main"}),
        ("db_list_tables", "tables", {}, {"search": "t"}),
        ("db_list_tables", "tables", {}, {"object_kinds": ["table", "view"]}),
        ("db_list_tables", "tables", {"schema": "main", "search": "t"}, {"schema": "main"}),
        ("db_list_views", "views", {}, {"schema": "main"}),
    ],
)
def test_a_list_cursor_is_bound_to_the_filters_it_was_issued_for(
    tmp_path: Path, monkeypatch: Any, tool: str, key: str, filters: dict[str, Any], other: dict[str, Any]
) -> None:
    monkeypatch.setattr(srv, "_PAGE_SIZE", 3)
    server, _ = _sqlite_server(tmp_path, {"shop": _LISTING_SCRIPT})
    first = _call(server, tool, {"connection_id": "shop", **filters})
    assert first["next_cursor"] and len(first["data"][key]) == 3
    text = _call_error(server, tool, {"connection_id": "shop", **other, "cursor": first["next_cursor"]})
    assert "VALIDATION_ERROR" in text and "cursor does not apply to this operation" in text, text
    # the same filters (a schema spelled in another case filters the same list) still page
    same = {**filters, **({"schema": "MAIN"} if tool == "db_list_tables" and "schema" in filters else {})}
    second = _call(server, tool, {"connection_id": "shop", **same, "cursor": first["next_cursor"]})
    assert second["data"][key] and not {json.dumps(x) for x in second["data"][key]} & {
        json.dumps(x) for x in first["data"][key]
    }


def test_a_schema_cursor_is_bound_to_its_search(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr(srv, "_PAGE_SIZE", 3)
    fake = _FakeConnector([], schemas=[f"s{i}" for i in range(8)])
    server = _fake_server(tmp_path, monkeypatch, fake, engine="postgres", allowed=[], deny=True)
    first = _call(server, "db_list_schemas", {"connection_id": "remote"})
    text = _call_error(server, "db_list_schemas", {"connection_id": "remote", "search": "s",
                                                   "cursor": first["next_cursor"]})
    assert "cursor does not apply to this operation" in text, text
    second = _call(server, "db_list_schemas", {"connection_id": "remote", "cursor": first["next_cursor"]})
    assert second["data"]["schemas"] == ["s3", "s4", "s5"]


# ------------------------------------------------ F67 SDK rejections audited

_REJECTED = [
    ("db_query", {"connection_id": "shop", "sql": "SELECT 'SENTINEL-ARG'", "max_rows": "lots"}, ["max_rows"]),
    ("db_query", {"connection_id": "SENTINEL-ARG"}, ["sql"]),
    ("db_search_values", {"query": "SENTINEL-ARG", "connections": ["shop"] * 65}, ["connections"]),
    ("db_federated_query", {"queries": {"SENTINEL-ARG": 5}}, ["queries"]),
    ("db_drop_everything", {"connection_id": "shop", "sql": "SENTINEL-ARG"}, None),
]


@pytest.mark.parametrize(("tool", "args", "fields"), _REJECTED)
def test_a_call_the_sdk_rejects_is_audited(
    tmp_path: Path, tool: str, args: dict[str, Any], fields: list[str] | None
) -> None:
    server, app = _server(tmp_path)
    _call_error(server, tool, args)
    (record,) = _audit_lines(tmp_path)
    assert (record["action"], record["outcome"], record["category"]) == (tool, "deny", "VALIDATION_ERROR")
    assert record["caller"] == app.identity and len(record["request_id"]) == 32
    raw = json.dumps(args, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    assert record["arguments_sha256"] == hashlib.sha256(raw.encode()).hexdigest()
    assert record["reason"] == ("unknown tool" if fields is None else "invalid arguments")
    assert record.get("invalid_arguments") == fields
    assert "SENTINEL-ARG" not in json.dumps(record), "argument values are never recorded"
    assert app.history[-1]["action"] == tool and app.history[-1]["outcome"] == "deny"


def test_the_wire_path_audits_what_the_sdk_rejects(tmp_path: Path) -> None:
    """tools/call over a client session reaches the same audited path."""
    from mcp import Client

    server, _ = _server(tmp_path)

    async def session() -> list[bool]:
        async with Client(server) as client:
            bad = await client.call_tool("db_query", {"connection_id": "shop", "sql": "SELECT 1", "max_rows": "x"})
            unknown = await client.call_tool("db_nope", {})
            return [bad.is_error, unknown.is_error]

    assert anyio.run(session) == [True, True]
    assert [(r["action"], r["reason"]) for r in _audit_lines(tmp_path)] == [
        ("db_query", "invalid arguments"), ("db_nope", "unknown tool")
    ]


def test_a_rejected_tool_name_is_recorded_capped(tmp_path: Path) -> None:
    server, _ = _server(tmp_path)
    _call_error(server, "db_" + "x" * 10_000, {})
    (record,) = _audit_lines(tmp_path)
    assert record["action"] == ("db_" + "x" * 10_000)[:128]


def test_calls_the_handlers_see_are_audited_once(tmp_path: Path) -> None:
    server, _ = _server(tmp_path)
    _call(server, "db_list_connections", {})
    _call_error(server, "db_query", {"connection_id": "nope", "sql": "SELECT 1"})
    records = _audit_lines(tmp_path)
    assert [r["action"] for r in records if ":" not in r["action"]] == ["db_list_connections", "db_query"]
    assert not any("arguments_sha256" in r for r in records)


def test_a_rejected_call_whose_audit_write_fails_fails_closed(tmp_path: Path, monkeypatch: Any) -> None:
    server, app = _server(tmp_path)

    def broken(_record: dict[str, Any]) -> None:
        raise AuditWriteFailure("disk full")

    monkeypatch.setattr(app.audit, "record", broken)
    text = _call_error(server, "db_query", {"connection_id": "shop", "sql": "SELECT 1", "max_rows": "lots"})
    assert "CONFIG_ERROR" in text and "disk full" in text, text


# ------------------------------------------------ F72 identity from the OS

_POSIX_ONLY = pytest.mark.skipif(sys.platform == "win32", reason="the POSIX account database")


@_POSIX_ONLY
def test_the_audit_identity_is_the_os_account_not_the_environment(monkeypatch: Any) -> None:
    import pwd

    for var in ("USER", "LOGNAME", "LNAME", "USERNAME"):
        monkeypatch.setenv(var, "root")
    account = pwd.getpwuid(os.geteuid()).pw_name
    assert srv._process_identity() == account

    def unmapped(uid: int) -> Any:
        raise KeyError(f"getpwuid(): uid not found: {uid}")

    monkeypatch.setattr(pwd, "getpwuid", unmapped)
    assert srv._process_identity() == f"uid:{os.geteuid()}"


@_POSIX_ONLY
def test_audit_records_carry_the_numeric_uid(tmp_path: Path) -> None:
    server, _ = _server(tmp_path)
    _call(server, "db_query", {"connection_id": "shop", "sql": "SELECT 1"})
    _call_error(server, "db_nope", {})
    records = _audit_lines(tmp_path)
    assert len(records) == 3 and all(r["caller_uid"] == os.geteuid() for r in records)


# ----------------------------------------- F82 '%' in names, pyformat drivers


def _percent_fake(cls: Any) -> Any:
    """A real connector's SQL building (quoting, placeholders, the search
    statement) over a catalog with a '%' in a table and a column name, and no
    database: execute_query applies the driver's own %-formatting, as
    psycopg, PyMySQL and clickhouse-connect do whenever parameters are bound."""

    class Fake(cls):  # type: ignore[misc, valid-type]
        def __init__(self) -> None:
            self.statements: list[tuple[str, str]] = []

        def capabilities(self) -> _Caps:
            return _Caps()

        def list_schemas(self, _catalog: str | None, _search: str | None) -> list[str]:
            return ["s"]

        def list_tables(self, _schema: str | None, kinds: set[str], _search: str | None) -> list[TableSummary]:
            return [TableSummary("s", "t%x", "table")]

        def list_all_columns(self, _schema: str | None) -> list[ColumnInfo]:
            text = "String" if cls is ClickHouseConnector else "text"
            return [ColumnInfo("s", "t%x", "id", "integer"), ColumnInfo("s", "t%x", "pct%", text)]

        def list_indexes(self, _schema: str | None, _table: str | None) -> list[IndexInfo]:
            return []

        def execute_query(self, spec: Any) -> QueryOutcome:
            params = spec.parameters
            # what the connector hands the driver: every '%' that is not a
            # placeholder doubled (bind_text), then the driver's formatting
            text = bind_text(spec.sql, params, engine=cls.engine)
            sent = text % (tuple(params) if isinstance(params, list) else params)
            self.statements.append((spec.sql, sent))
            return QueryOutcome(columns=[("id", "integer"), ("pct%", "text")], rows=[[1, "zqxneedle"]],
                                truncated=False, rows_seen=1, elapsed_ms=0)

    return Fake()


@pytest.mark.parametrize("cls", [PostgresConnector, MySQLConnector, ClickHouseConnector])
def test_a_percent_in_a_catalog_name_survives_the_drivers_formatting(
    tmp_path: Path, monkeypatch: Any, cls: Any
) -> None:
    fake = _percent_fake(cls)
    server = _fake_server(tmp_path, monkeypatch, fake, engine=cls.engine, allowed=["s"], deny=True)
    env = _call(server, "db_search_values", {"query": "zqxneedle"})
    assert [(h["table"], h["matched_columns"]) for h in env["data"]["hits"]] == [("t%x", ["pct%"])], env["warnings"]
    ((built, sent),) = fake.statements
    # the server writes the names as the catalog spells them; the connector
    # escapes them for the driver's formatting (bind_text)
    assert fake.quote_identifier("pct%") in built and fake.quote_identifier("t%x") in built and "%%" not in built
    assert fake.quote_identifier("pct%") in sent and fake.quote_identifier("t%x") in sent and "%%" not in sent


def test_a_qmark_engine_keeps_a_percent_as_written(tmp_path: Path, monkeypatch: Any) -> None:
    script = 'CREATE TABLE "t%x" (id INTEGER PRIMARY KEY, "pct%" TEXT); INSERT INTO "t%x" VALUES (1, \'zqxneedle\');'
    server, _ = _sqlite_server(tmp_path, {"shop": script})
    seen = _record_statements(monkeypatch)
    env = _call(server, "db_search_values", {"query": "zqxneedle"})
    assert [(h["table"], h["matched_columns"]) for h in env["data"]["hits"]] == [("t%x", ["pct%"])]
    assert seen and all('"pct%"' in sql and '"t%x"' in sql and "%%" not in sql for sql in seen)


# --------------------------------------- F84 discovery budget over the catalog


class _Clock:
    """The server's monotonic clock, advanced only by the fake catalog: the
    budget tests do not depend on how fast the machine is."""

    def __init__(self) -> None:
        self.now = time.monotonic()

    def monotonic(self) -> float:
        return self.now


class _SlowCatalog(_FakeConnector):
    """One table per schema; each schema-wide column listing takes ``delay``
    (on the server's clock)."""

    def __init__(self, schemas: int, delay: float) -> None:
        names = [f"s{i:02d}" for i in range(schemas)]
        super().__init__(
            [TableSummary(s, "t", "table", row_estimate=1) for s in names],
            columns=[ColumnInfo(s, "t", "id", "integer") for s in names],
        )
        self.names = names
        self.delay = delay
        self.clock = _Clock()
        self.read: list[str | None] = []

    def list_all_columns(self, schema: str | None) -> list[ColumnInfo]:
        self.clock.now += self.delay
        self.read.append(schema)
        return super().list_all_columns(schema)


def _slow_catalog_server(tmp_path: Path, monkeypatch: Any, fake: _SlowCatalog, budget: float) -> Any:
    server, app = _fake_app_server(tmp_path, monkeypatch, fake, engine="postgres", allowed=fake.names, deny=True)
    app._policy_for("remote").discovery_time_budget_seconds = budget  # the config floor is 5 s
    monkeypatch.setattr(srv, "time", type("_Time", (), {
        "monotonic": staticmethod(fake.clock.monotonic), "strftime": staticmethod(time.strftime),
    }))
    return server


def test_inference_stops_reading_the_catalog_at_the_discovery_budget(tmp_path: Path, monkeypatch: Any) -> None:
    fake = _SlowCatalog(50, 0.2)
    server = _slow_catalog_server(tmp_path, monkeypatch, fake, 1.0)
    started = fake.clock.now
    env = _call(server, "db_infer_relationships", {})
    assert fake.clock.now - started < 2.0
    data = env["data"]
    assert data["budget_exhausted"] is True and 0 < len(fake.read) < 50
    assert data["tables_considered"] == len(fake.read)
    assert any("time budget" in w and "narrow" in w for w in env["warnings"]), env["warnings"]


def test_inference_reads_a_bounded_number_of_schemas(tmp_path: Path, monkeypatch: Any) -> None:
    fake = _SlowCatalog(8, 0.0)
    server = _slow_catalog_server(tmp_path, monkeypatch, fake, 60.0)
    monkeypatch.setattr(srv, "_DISCOVERY_INFER_MAX_SCHEMAS", 3)
    env = _call(server, "db_infer_relationships", {})
    assert fake.read == ["s00", "s01", "s02"] and env["data"]["tables_considered"] == 3
    assert env["data"]["budget_exhausted"] is False
    assert any("schemas" in w and "narrow" in w for w in env["warnings"]), env["warnings"]


@pytest.mark.parametrize("tool", ["db_get_catalog", "db_document_schema"])
def test_a_catalog_page_ends_at_the_discovery_budget(tmp_path: Path, monkeypatch: Any, tool: str) -> None:
    fake = _SlowCatalog(12, 0.1)
    server = _slow_catalog_server(tmp_path, monkeypatch, fake, 0.25)
    started = fake.clock.now
    env = _call(server, tool, {"connection_id": "remote", "page_size": 25})
    assert fake.clock.now - started < 1.0
    assert env["next_cursor"] and any("time budget" in w for w in env["warnings"]), env["warnings"]
    pages = [env]
    while pages[-1].get("next_cursor"):
        pages.append(_call(server, tool, {"connection_id": "remote", "page_size": 25,
                                          "cursor": pages[-1]["next_cursor"]}))
    assert sorted(fake.read) == fake.names, "every schema is read once, on the page that shows its tables"
    if tool == "db_get_catalog":
        assert sorted(t["schema"] for p in pages for t in p["data"]["tables"]) == fake.names
    else:
        assert sum(p["data"]["tables"] for p in pages) == 12


# ------------------------------------------------ F85 poisoned connectors


def _poison_by_cancellation(app: AppContext, connector: Any) -> None:
    """A request cancelled mid-query (client disconnect) poisons the
    connector it was using, exactly as tool_span does it."""

    async def cancelled() -> None:
        with anyio.move_on_after(0.05):
            async with srv.tool_span(app, "db_query", "shop", sql="SELECT 1") as st:
                st["connector"] = connector
                await anyio.sleep(5)

    anyio.run(cancelled)


def test_a_freed_poisoned_connector_never_condemns_a_new_one(tmp_path: Path) -> None:
    _, app = _server(tmp_path)
    orphan = registry.build_connector(app.resolved["shop"], app._policy_for("shop"))
    _poison_by_cancellation(app, orphan)
    assert len(app.poisoned_connectors) == 1
    del orphan
    gc.collect()
    assert len(app.poisoned_connectors) == 0
    for _ in range(200):  # whether or not one of them lands on the freed address
        healthy = registry.build_connector(app.resolved["shop"], app._policy_for("shop"))
        app.connectors["shop"] = healthy
        assert app.connection("shop")[0] is healthy


def test_a_connector_cancelled_mid_query_is_still_rebuilt(tmp_path: Path) -> None:
    _, app = _server(tmp_path)
    first, _ = app.connection("shop")
    _poison_by_cancellation(app, first)
    second, _ = app.connection("shop")
    assert second is not first
    assert len(app.poisoned_connectors) == 0, "a discarded connector is no longer tracked"
    assert app.connection("shop")[0] is second


# ------------------------------------------------ F95 truncation warning text


def test_the_truncation_warning_claims_nothing_about_where_limits_applied(tmp_path: Path) -> None:
    server, _ = _server(tmp_path)
    env = _call(server, "db_query", {"connection_id": "shop", "sql": "SELECT customer_id FROM customers",
                                     "max_rows": 1})
    assert env["truncated"] is True
    assert any(w.startswith("result truncated: limits are rows<=1, bytes<=") for w in env["warnings"])
    assert not any("server-side" in w or "full retrieval" in w for w in env["warnings"]), env["warnings"]


# ================================================================ review round 2
# F01: a CTE referenced through a column list, PostgreSQL attribute notation
# over a row and ClickHouse tuple access through an alias. F16: libxml echoes
# the XML input. F05: an empty schema argument and Oracle's PUBLIC synonyms.
# F85: a discarded connector is closed once no worker uses it. F19: SQLite's
# double-quoted literals and index definitions.

_CTE = "WITH t AS (SELECT customer_id, ssn FROM customers) "


@pytest.mark.parametrize(
    ("sql", "width", "expected"),
    [
        (_CTE + "SELECT x FROM t AS d(w, x)", 1, {0}),
        (_CTE + "SELECT d.x FROM t d(w, x)", 1, {0}),
        (_CTE + "SELECT upper(x) FROM t AS d(w, x)", 1, {0}),
        (_CTE + "SELECT w FROM t AS d(w, x)", 1, set()),
        (_CTE + "SELECT d.w FROM t AS d(w, x)", 1, set()),
        (_CTE + "SELECT d.* FROM t AS d(w, x)", 2, {1}),
        (_CTE + "SELECT * FROM t AS d(w, x)", 2, {1}),
        (_CTE + "SELECT x FROM t AS d(w, x) UNION ALL SELECT 'a'", 1, {0}),
        # one CTE under two column lists: each reference is renamed on its own
        (_CTE + "SELECT a.x, b.x FROM t AS a(w, x), t AS b(x, w)", 2, {0}),
        (_CTE + "SELECT a.x, b.x FROM t AS a(w, x) JOIN t AS b(x, w) ON true", 2, {0}),
        # a partial list renames the leading columns only
        ("WITH t AS (SELECT ssn AS s, customer_id FROM customers) SELECT x, customer_id FROM t AS d(x)", 2, {0}),
        # over a base table's star the new names prove nothing
        ("WITH t AS (SELECT * FROM customers) SELECT * FROM t AS d(a, b, c)", 4, {0, 1, 2, 3}),
        ("WITH t AS (SELECT * FROM customers) SELECT b FROM t AS d(a, b, c)", 1, {0}),
        # Db2 statements are parsed as PostgreSQL; its names fold to upper case
        ("WITH T AS (SELECT CUSTOMER_ID, SSN FROM CUSTOMERS) SELECT X FROM T AS D(W, X)", 1, {0}),
        ("WITH T AS (SELECT CUSTOMER_ID, SSN FROM CUSTOMERS) SELECT W FROM T AS D(W, X)", 1, set()),
    ],
)
def test_a_cte_referenced_through_a_column_list_is_renamed_positionally(
    demo_policy: Any, sql: str, width: int, expected: set[int]
) -> None:
    ast = sqlglot.parse_one(sql, read="postgres")
    assert srv._query_mask_positions(demo_policy, ast, [(f"c{i}", "t") for i in range(width)]) == expected


@pytest.mark.parametrize(
    ("sql", "expected"),
    [
        # t.fn is fn(t): the whole row, sensitive columns included (live: every callsign as JSON)
        ("SELECT b.row_to_json FROM customers b", {0}),
        ("SELECT b.to_json FROM customers b", {0}),
        ("SELECT b.to_jsonb FROM customers b", {0}),
        ("SELECT customers.row_to_json FROM customers", {0}),
        ("SELECT main.customers.to_json FROM main.customers", {0}),
        ("SELECT upper(b.row_to_json::text) AS full_name FROM customers b", {0}),
        ("SELECT b.json_agg FROM customers b", {0}),
        ("SELECT b.array_agg FROM customers b", {0}),
        ("SELECT b.concat FROM customers b", {0}),
        ("SELECT b.quote_literal FROM customers b", {0}),
        ("SELECT b.record_out FROM customers AS b(a)", {0}),
        # a name a derived table does not output can only be a function of its row
        ("SELECT d.to_json FROM (SELECT customer_id, ssn FROM customers) d", {0}),
        ("SELECT d.site_row_fn FROM (SELECT customer_id, ssn FROM customers) d", {0}),
        ("SELECT d.to_json FROM (SELECT * FROM customers) d", {0}),
        (_CTE + "SELECT d.to_json FROM t AS d(w, x)", {0}),
        # controls: a real column, and a row without a sensitive value
        ("SELECT b.full_name FROM customers b", set()),
        ("SELECT d.customer_id FROM (SELECT customer_id, ssn FROM customers) d", set()),
        ("SELECT d.to_json FROM (SELECT customer_id FROM customers) d", set()),
        ("SELECT d.full_name FROM (SELECT * FROM customers) d", set()),
    ],
)
def test_postgres_attribute_notation_is_a_whole_row_reference(demo_policy: Any, sql: str, expected: set[int]) -> None:
    policy = dataclasses.replace(demo_policy, engine="postgres")
    ast = sqlglot.parse_one(sql, read="postgres")
    assert srv._query_mask_positions(policy, ast, [("c0", "t")]) == expected


def test_attribute_notation_function_names_are_columns_on_other_engines(demo_policy: Any) -> None:
    """Only PostgreSQL reads t.to_json as to_json(t); elsewhere it is a column."""
    policy = dataclasses.replace(demo_policy, engine="mysql")
    ast = sqlglot.parse_one("SELECT b.to_json FROM customers b", read="mysql")
    assert srv._query_mask_positions(policy, ast, [("to_json", "t")]) == set()


@pytest.mark.parametrize(
    ("sql", "expected"),
    [
        ("SELECT x.1 FROM customers ARRAY JOIN [(ssn, 1)] AS x", {0}),
        ("SELECT x.1 AS y FROM customers ARRAY JOIN [(ssn, 1)] AS x", {0}),
        ("SELECT upper(x.1) FROM customers ARRAY JOIN [(ssn, 1)] AS x", {0}),
        ("WITH (ssn, 1) AS x SELECT x.1 FROM customers", {0}),
        ("WITH (ssn, 1) AS x, x AS y SELECT y.1 FROM customers", {0}),
        ("SELECT x.1 FROM customers WHERE ((ssn, 1) AS x).1 != ''", {0}),
        ("SELECT x.a FROM customers ARRAY JOIN [CAST((ssn, 1), 'Tuple(a String, b UInt8)')] AS x", {0}),
        # controls: the same shapes over a column that is not sensitive
        ("SELECT x.1 FROM customers ARRAY JOIN [(full_name, 1)] AS x", set()),
        ("WITH (full_name, 1) AS x SELECT x.1 FROM customers", set()),
        ("SELECT x.1 FROM customers WHERE ((full_name, 1) AS x).1 != ''", set()),
    ],
)
def test_clickhouse_tuple_access_through_an_alias_is_traced(demo_policy: Any, sql: str, expected: set[int]) -> None:
    demo_policy = dataclasses.replace(demo_policy, engine="clickhouse")  # tuple access is ClickHouse's
    ast = sqlglot.parse_one(sql, read="clickhouse")
    assert srv._query_mask_positions(demo_policy, ast, [("c0", "t")]) == expected


# the texts the loopback PostgreSQL returns (scratchpad impl-server/r2/pg_xml_raw.txt)
_XML_ECHOES = [
    ("ConnectorError: InvalidXmlContent: invalid XML content DETAIL:  line 1: Premature end of data in tag a line 1 "
     "<a>MB-ALPHA MB-BRAVO MB-CHARLIE                                ^",
     ["InvalidXmlContent", "invalid XML content"], ["MB-ALPHA", "MB-BRAVO", "MB-CHARLIE"]),
    ("ConnectorError: InvalidXmlContent: invalid XML content DETAIL:  line 1: Couldn't find end of Start Tag "
     "MB-ALPHAMB-BRAVOMB-CHARLIE line 1 <MB-ALPHAMB-BRAVOMB-CHARLIE                            ^",
     ["InvalidXmlContent", "invalid XML content"], ["MB-ALPHA", "MB-BRAVO"]),
    ("ConnectorError: InvalidXmlDocument: invalid XML document DETAIL:  line 1: Start tag expected, '<' not found "
     "MB-ALPHA MB-BRAVO MB-CHARLIE ^", ["InvalidXmlDocument", "invalid XML document"], ["MB-ALPHA", "MB-BRAVO"]),
    ("ConnectorError: InvalidXmlContent: invalid XML content DETAIL:  line 1: AttValue: \" or ' expected "
     "<a MB-ALPHA=1 MB-BRAVO=1 MB-CHARLIE=1>             ^ line 1: attributes construct error "
     "<a MB-ALPHA=1 MB-BRAVO=1 MB-CHARLIE=1>             ^", ["invalid XML content"], ["MB-ALPHA", "MB-BRAVO"]),
    ("ConnectorError: InvalidXmlDocument: could not parse XML document DETAIL:  line 1: Start tag expected, '<' "
     "not found MB-ALPHA MB-BRAVO MB-CHARLIE ^", ["could not parse XML document"], ["MB-ALPHA", "MB-BRAVO"]),
    # libxml's own "line N: message" detail under any other message
    ("ConnectorError: X: whatever DETAIL:  line 1: Namespace prefix MB on ALPHA is not defined <MB:ALPHA/> ^",
     ["X: whatever"], ["MB:ALPHA", "prefix MB"]),
    # value-free XML errors keep their text
    ("ConnectorError: InvalidXmlComment: invalid XML comment", ["InvalidXmlComment: invalid XML comment"], []),
    ("ConnectorError: InternalError_: invalid XPath expression DETAIL:  Invalid expression",
     ["invalid XPath expression DETAIL:  Invalid expression"], []),
]


@pytest.mark.parametrize(("raw", "kept", "gone"), _XML_ECHOES)
def test_driver_text_sanitizer_cuts_the_xml_input_echo(raw: str, kept: list[str], gone: list[str]) -> None:
    clean = srv._sanitize_driver_text(raw)
    for part in kept:
        assert part in clean, (part, clean)
    for part in gone:
        assert part not in clean, (part, clean)


def test_the_xml_input_echo_never_reaches_the_model_or_the_audit(tmp_path: Path, monkeypatch: Any) -> None:
    def raise_echo(*_a: Any, **_k: Any) -> Any:
        raise _from_driver(_XML_ECHOES[0][0].removeprefix("ConnectorError: "), category="QUERY_ERROR")

    monkeypatch.setattr(SQLiteConnector, "execute_query", raise_echo)
    server, app = _server(tmp_path, names=("crm", "erp"))
    sql = "SELECT customer_id FROM customers"
    text = _call_error(server, "db_query", {"connection_id": "crm", "sql": sql})
    fed = json.dumps(_call(server, "db_federated_query", {"sql": sql}))
    trail = (tmp_path / "audit.jsonl").read_text(encoding="utf-8") + json.dumps(list(app.history), default=str)
    for payload in (text, fed, trail):
        assert "MB-ALPHA" not in payload and "MB-CHARLIE" not in payload, payload[:600]
    assert "QUERY_ERROR: " in text and "invalid XML content" in text, text


@pytest.mark.parametrize("schema", ["", "  "])
@pytest.mark.parametrize("tool", ["db_sample_table", "db_list_columns", "db_get_table"])
def test_an_empty_schema_argument_is_no_schema(tmp_path: Path, monkeypatch: Any, tool: str, schema: str) -> None:
    """schema='' used to skip the bare-name rules: the connector then built an
    unqualified reference that PostgreSQL bound to pg_catalog."""
    fake = _FakeConnector([TableSummary("public", "orders", "table")])
    server = _fake_server(tmp_path, monkeypatch, fake, engine="postgres", allowed=[], deny=False)
    text = _call_error(server, tool, {"connection_id": "remote", "schema": schema, "object_name": "pg_roles"})
    assert "AUTHORIZATION_DENIED" in text and "system schema" in text, text
    assert fake.calls == []


def test_an_empty_schema_argument_resolves_through_the_allowlist(tmp_path: Path, monkeypatch: Any) -> None:
    fake = _FakeConnector([TableSummary("app", "orders", "table")])
    server = _fake_server(tmp_path, monkeypatch, fake, engine="postgres", allowed=["app"], deny=False)
    _call(server, "db_list_columns", {"connection_id": "remote", "schema": "", "object_name": "orders"})
    assert fake.calls[-1] == ("app", "orders")


@pytest.mark.parametrize("name", ["DATABASE_PROPERTIES", "TABLE_PRIVILEGES", "SYSTEM_PRIVILEGE_MAP", "BOOKINGZ"])
@pytest.mark.parametrize("tool", ["db_sample_table", "db_list_columns", "db_get_table"])
def test_an_oracle_bare_name_outside_the_catalog_needs_the_system_schema(
    tmp_path: Path, monkeypatch: Any, tool: str, name: str
) -> None:
    """Oracle binds a bare name it cannot find in the caller's schema to a
    PUBLIC synonym, and most of those name SYS views: a name list cannot
    cover them (DATABASE_PROPERTIES returned RECO_LOGIN_PASSWORD live)."""
    fake = _FakeConnector([TableSummary("TRAVEL", "TRAVELLERS", "table")])
    server = _fake_server(tmp_path, monkeypatch, fake, engine="oracle", allowed=[], deny=False)
    text = _call_error(server, tool, {"connection_id": "remote", "object_name": name})
    assert "AUTHORIZATION_DENIED" in text and "synonym" in text, text
    assert fake.calls == []


def test_an_oracle_bare_name_resolves_through_the_catalog(tmp_path: Path, monkeypatch: Any) -> None:
    fake = _FakeConnector([TableSummary("TRAVEL", "TRAVELLERS", "table"), TableSummary("TRAVEL", "TRIPS", "table"),
                           TableSummary("HR", "TRIPS", "table")])
    server = _fake_server(tmp_path, monkeypatch, fake, engine="oracle", allowed=[], deny=False)
    _call(server, "db_list_columns", {"connection_id": "remote", "object_name": "travellers"})
    assert fake.calls[-1] == ("TRAVEL", "TRAVELLERS")
    text = _call_error(server, "db_list_columns", {"connection_id": "remote", "object_name": "TRIPS"})
    assert "VALIDATION_ERROR" in text and "several schemas" in text, text


def test_an_oracle_bare_synonym_is_sent_as_written_with_the_system_schema(tmp_path: Path, monkeypatch: Any) -> None:
    fake = _FakeConnector([TableSummary("TRAVEL", "TRAVELLERS", "table")])
    server, _ = _fake_app_server(
        tmp_path, monkeypatch, fake, engine="oracle", allowed=[], deny=False,
        security="  allowed_system_schemas: [SYS]\n",
    )
    _call(server, "db_list_columns", {"connection_id": "remote", "object_name": "DATABASE_PROPERTIES"})
    assert fake.calls[-1] == (None, "DATABASE_PROPERTIES")


class _ClosingConnector:
    def __init__(self) -> None:
        self.closed = threading.Event()

    def close(self) -> None:
        self.closed.set()


def test_a_discarded_connector_is_closed_once_no_worker_uses_it(tmp_path: Path, monkeypatch: Any) -> None:
    _, app = _server(tmp_path)
    busy = {"yes": True}
    monkeypatch.setattr(app.executor, "has_live_worker", lambda _c: busy["yes"])
    old = _ClosingConnector()
    app.connectors["shop"] = old  # type: ignore[assignment]
    _poison_by_cancellation(app, old)
    fresh, _ = app.connection("shop")
    assert fresh is not old
    assert not old.closed.wait(0.2), "a connector whose abandoned worker still runs is not closed under it"
    busy["yes"] = False
    app.connection("shop")
    assert old.closed.wait(5), "the discarded connector was closed once its worker ended"


def test_sqlite_double_quoted_literals_beside_a_sensitive_column_are_withheld(tmp_path: Path) -> None:
    """SQLite reads "Sup3rDQ" as a string when no column has that name."""
    script = (
        'CREATE TABLE users (id INTEGER, password TEXT, CHECK (password <> "Sup3rDQ"));'
        'CREATE TABLE "quoted" ("id" INTEGER, "password" TEXT, "note" TEXT CHECK ("note" <> "x"));'
    )
    server, _ = _sqlite_server(tmp_path, {"shop": script})
    env = _call(server, "db_get_table", {"connection_id": "shop", "object_name": "users"})
    assert "Sup3rDQ" not in json.dumps(env)
    assert env["data"]["definition"] is None and any("definition withheld" in w for w in env["warnings"])
    # double-quoted names of the table and its columns are identifiers, not literals
    env = _call(server, "db_get_table", {"connection_id": "shop", "object_name": "quoted"})
    assert '"password" TEXT' in env["data"]["definition"], env


class _IndexFake(_FakeConnector):
    _INDEX = IndexInfo("ix_pw", ["email"], definition="CREATE INDEX ix_pw ON app.users USING btree (email) "
                       "WHERE (password = 'changeme-IDX'::text)", schema="app", table="users")
    _PLAIN = IndexInfo("ix_email", ["email"], definition="CREATE INDEX ix_email ON app.users USING btree (email) "
                       "WHERE (status = 'active'::text)", schema="app", table="users")

    def list_indexes(self, _schema: str | None, _table: str | None) -> list[Any]:
        return [self._INDEX, self._PLAIN]

    def get_table(self, schema: str | None, name: str) -> dict[str, Any]:
        return {**DatabaseConnector.get_table(self, schema, name),  # type: ignore[arg-type]
                "indexes": [i.__dict__ for i in self.list_indexes(schema, name)]}


def test_index_definitions_are_withheld_beside_a_sensitive_literal_everywhere(tmp_path: Path, monkeypatch: Any) -> None:
    columns = [ColumnInfo("app", "users", "email", "text"), ColumnInfo("app", "users", "password", "text")]
    fake = _IndexFake([TableSummary("app", "users", "table")], columns=columns)
    server = _fake_server(tmp_path, monkeypatch, fake, engine="postgres", allowed=["app"], deny=True)
    envs = [
        _call(server, "db_list_indexes", {"connection_id": "remote", "object_name": "users"}),
        _call(server, "db_list_indexes", {"connection_id": "remote", "schema": "app"}),
        _call(server, "db_get_table", {"connection_id": "remote", "object_name": "users"}),
        _call(server, "db_get_catalog", {"connection_id": "remote"}),
    ]
    for env in envs:
        text = json.dumps(env)
        assert "changeme-IDX" not in text, text[:600]
        assert "'active'::text" in text, text[:600]  # an index naming no sensitive column is kept
        assert any("index definition" in w and "withheld" in w for w in env["warnings"]), env["warnings"]


def test_index_definitions_are_capped_by_max_cell_bytes(tmp_path: Path, monkeypatch: Any) -> None:
    fake = _IndexFake([TableSummary("app", "users", "table")])
    fake._PLAIN = dataclasses.replace(_IndexFake._PLAIN, definition="CREATE INDEX ix ON app.users (" + "e" * 5000 + ")")
    server, _ = _fake_app_server(tmp_path, monkeypatch, fake, engine="postgres", allowed=["app"], deny=True,
                                 security="  max_cell_bytes: 64\n")
    for args in ({"object_name": "users"}, {"schema": "app"}):
        env = _call(server, "db_list_indexes", {"connection_id": "remote", **args})
        plain = next(i for i in env["data"]["indexes"] if i["name"] == "ix_email")
        assert len(plain["definition"].encode()) <= 64, len(plain["definition"])
        assert any("security.max_cell_bytes" in w for w in env["warnings"])


@pytest.mark.parametrize(
    ("sql", "width", "expected"),
    [
        # sqlglot reads PostgreSQL's (TABLE customers) as a table named TABLE: it is the table's row
        ("SELECT q.a FROM (TABLE customers) AS q(i, n, e, a)", 1, {0}),
        ("SELECT a FROM (TABLE customers) AS q(i, n, e, a)", 1, {0}),
        ("SELECT * FROM (TABLE customers) AS q(i, n, e, a)", 4, {0, 1, 2, 3}),
        ("SELECT * FROM (TABLE customers) q", 4, set()),  # the driver reports the table's own names
    ],
)
def test_a_parenthesized_table_reads_the_whole_table(
    demo_policy: Any, sql: str, width: int, expected: set[int]
) -> None:
    ast = sqlglot.parse_one(sql, read="postgres")
    assert srv._query_mask_positions(demo_policy, ast, [(f"c{i}", "t") for i in range(width)]) == expected


# ================================================================ integration wave
# I05: SQLite's own catalog (sqlite_schema, with every table's DDL) is neither
# listed nor readable through the metadata and sample tools. I06: a row that
# matches in two column chunks is one hit, with or without a key. I07: a
# statement that runs out of time is an error in the audit, whoever stopped
# it. I08: a connector's own refusal keeps its numbers; a connector that
# cannot even be built does not echo the install path. I09: a ClickHouse
# FixedString (bytes) is matched as text. I10: db_test_connection shows the
# audit records a fail-open server lost. I11: db_list_connections says
# whether the server-side read-only session is on. I12: PostgreSQL attribute
# notation over a base table's row (b.site_fn) is masked when the table has
# no column of that name.

_CATALOG_SECRET = "changeme-default-secret"
_CATALOG_SCRIPT = (
    f"CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, password TEXT DEFAULT '{_CATALOG_SECRET}');"
    "INSERT INTO users (id) VALUES (1);"
)


@pytest.mark.parametrize("deny", [True, False])
@pytest.mark.parametrize("name", ["sqlite_schema", "sqlite_master", "sqlite_sequence", "SQLITE_MASTER",
                                  "main.sqlite_schema", "temp.sqlite_temp_master"])
@pytest.mark.parametrize(("tool", "extra"), [*_OBJECT_TOOLS, ("db_list_indexes", {})])
def test_sqlite_catalog_tables_are_refused_by_every_object_tool(
    tmp_path: Path, deny: bool, name: str, tool: str, extra: dict[str, Any]
) -> None:
    server, _ = _sqlite_server(
        tmp_path, {"shop": _CATALOG_SCRIPT}, security=f"  default_deny_objects: {str(deny).lower()}\n"
    )
    text = _call_error(server, tool, {"connection_id": "shop", "object_name": name, **extra})
    assert "AUTHORIZATION_DENIED" in text and "catalog" in text, text
    assert _CATALOG_SECRET not in text


def test_sqlite_catalog_tables_are_refused_with_a_schema_argument(tmp_path: Path) -> None:
    server, _ = _sqlite_server(tmp_path, {"shop": _CATALOG_SCRIPT}, security="  default_deny_objects: false\n")
    text = _call_error(server, "db_sample_table", {"connection_id": "shop", "schema": "main",
                                                   "object_name": "sqlite_schema"})
    assert "AUTHORIZATION_DENIED" in text, text
    # the table beside them stays readable
    env = _call(server, "db_get_table", {"connection_id": "shop", "object_name": "users"})
    assert env["data"]["name"] == "users"


def test_sqlite_catalog_tables_are_never_listed(tmp_path: Path, monkeypatch: Any) -> None:
    """Even a connector (or a cached listing) that still reports them."""
    real = SQLiteConnector.list_tables

    def with_catalog(self: Any, schema: str | None, kinds: set[str], search: str | None) -> list[TableSummary]:
        extra = [TableSummary("main", n, "table") for n in ("sqlite_schema", "sqlite_sequence", "SQLITE_STAT1")]
        return [*real(self, schema, kinds, search), *extra]

    monkeypatch.setattr(SQLiteConnector, "list_tables", with_catalog)
    server, _ = _sqlite_server(tmp_path, {"shop": _CATALOG_SCRIPT})
    envs = [
        _call(server, "db_list_tables", {"connection_id": "shop"}),
        _call(server, "db_list_tables", {"connection_id": "shop", "schema": "main"}),
        _call(server, "db_get_catalog", {"connection_id": "shop", "include_system": True}),
        _call(server, "db_list_indexes", {"connection_id": "shop", "include_system": True}),
        _call(server, "db_search_metadata", {"query": "sqlite"}),
        _call(server, "db_search_values", {"query": "changeme", "include_system": True}),
    ]
    assert [t["name"] for t in envs[0]["data"]["tables"]] == ["users"]
    for env in envs:
        text = json.dumps(env).lower()
        assert "sqlite_schema" not in text and "sqlite_sequence" not in text and "sqlite_stat1" not in text, text[:600]
        assert _CATALOG_SECRET not in text


def test_the_sqlite_prefix_is_an_ordinary_name_on_other_engines(tmp_path: Path, monkeypatch: Any) -> None:
    fake = _FakeConnector([TableSummary("app", "sqlite_exports", "table")])
    server = _fake_server(tmp_path, monkeypatch, fake, engine="postgres", allowed=["app"], deny=True)
    env = _call(server, "db_list_tables", {"connection_id": "remote"})
    assert [t["name"] for t in env["data"]["tables"]] == ["sqlite_exports"]
    _call(server, "db_list_columns", {"connection_id": "remote", "object_name": "sqlite_exports"})
    assert fake.calls[-1] == ("app", "sqlite_exports")


def _keyless_search_script(table: str, columns: int, rows: list[dict[str, str]]) -> str:
    """A table with neither a primary key nor a unique index."""
    cols = ", ".join(f"c{i} TEXT" for i in range(1, columns + 1))
    script = f"CREATE TABLE {table} ({cols});"
    for row in rows:
        values = ", ".join(f"'{row.get(f'c{i}', 'x')}'" for i in range(1, columns + 1))
        script += f"INSERT INTO {table} VALUES ({values});"
    return script


def test_a_keyless_row_matching_in_two_chunks_is_reported_once(tmp_path: Path, monkeypatch: Any) -> None:
    server, _ = _sqlite_server(tmp_path, {"shop": _keyless_search_script("wide", 10, [{"c1": "twice", "c9": "twice"}])})
    monkeypatch.setattr(srv, "_SEARCH_CHUNK_COLUMNS", 4)
    hits = _call(server, "db_search_values", {"query": "twice"})["data"]["hits"]
    assert [h["matched_columns"] for h in hits] == [["c1", "c9"]]
    assert hits[0]["row"]["c1"] == hits[0]["row"]["c9"] == "twice"


@pytest.mark.parametrize(("columns", "late"), [(20, "c18"), (40, "c33")])
def test_a_wide_keyless_row_matching_in_two_full_chunks_is_reported_once(
    tmp_path: Path, columns: int, late: str
) -> None:
    """The reviewer's shape (c1 and c18 of 20) and one where both chunks are
    full, so no context column is shared between the two statements."""
    rows = [{"c1": "needle-2x", late: "needle-2x"}]
    server, _ = _sqlite_server(tmp_path, {"shop": _keyless_search_script("wide_nopk", columns, rows)})
    hits = _call(server, "db_search_values", {"query": "needle-2x"})["data"]["hits"]
    assert [h["matched_columns"] for h in hits] == [["c1", late]]


def test_distinct_keyless_rows_matching_in_different_chunks_are_both_reported(tmp_path: Path, monkeypatch: Any) -> None:
    """Rows alike in every column the later statement shares with the earlier
    one, except the column the earlier hit matched in, are two rows."""
    rows = [{"c7": "needle-k"}, {"c9": "needle-k"}]
    server, _ = _sqlite_server(tmp_path, {"shop": _keyless_search_script("wide", 10, rows)})
    monkeypatch.setattr(srv, "_SEARCH_CHUNK_COLUMNS", 4)
    hits = _call(server, "db_search_values", {"query": "needle-k"})["data"]["hits"]
    assert sorted(h["matched_columns"] for h in hits) == [["c7"], ["c9"]]


@pytest.mark.parametrize("keyed", [True, False])
def test_a_row_reported_by_an_earlier_chunk_does_not_spend_the_per_table_limit(
    tmp_path: Path, monkeypatch: Any, keyed: bool
) -> None:
    rows = [{"c1": "zz-both", "c9": "zz-both"}, {"c9": "zz-both"}]
    script = (_wide_search_script if keyed else _keyless_search_script)("wide", 10, rows)
    server, _ = _sqlite_server(tmp_path, {"shop": script})
    monkeypatch.setattr(srv, "_SEARCH_CHUNK_COLUMNS", 4)
    hits = _call(server, "db_search_values", {"query": "zz-both", "max_hits_per_table": 2})["data"]["hits"]
    assert sorted(h["matched_columns"] for h in hits) == [["c1", "c9"], ["c9"]]


def test_a_primary_key_with_a_masked_column_does_not_identify_a_row(tmp_path: Path, monkeypatch: Any) -> None:
    """Rows sharing the visible part of a key are different rows."""
    cols = ", ".join(f"c{i} TEXT" for i in range(1, 11))
    script = f"CREATE TABLE t (tenant INTEGER, ssn TEXT, {cols}, PRIMARY KEY (tenant, ssn));"
    script += "INSERT INTO t (tenant, ssn, c1) VALUES (1, '999-90-1111', 'pk-needle');"
    script += "INSERT INTO t (tenant, ssn, c9) VALUES (1, '999-90-2222', 'pk-needle');"
    server, _ = _sqlite_server(tmp_path, {"shop": script})
    monkeypatch.setattr(srv, "_SEARCH_CHUNK_COLUMNS", 4)
    env = _call(server, "db_search_values", {"query": "pk-needle"})
    assert sorted(h["matched_columns"] for h in env["data"]["hits"]) == [["c1"], ["c9"]]
    _assert_no_secret(env)


def _timed_out_by_the_executor(*_a: Any, **_k: Any) -> Any:
    raise ToolFailure(srv.ErrorCategory.TIMEOUT, "query on 'crm' exceeded its deadline; the connection was discarded")


def _timed_out_by_the_engine(*_a: Any, **_k: Any) -> Any:
    raise _from_driver(
        "the statement exceeded its time limit and the database cancelled it (QueryCanceled: canceling statement "
        "due to statement timeout)", category="TIMEOUT",
    )


def test_a_statement_timeout_is_audited_like_the_executor_deadline(tmp_path: Path, monkeypatch: Any) -> None:
    server, _ = _server(tmp_path, names=("crm", "erp"))
    audit = tmp_path / "audit.jsonl"
    seen: dict[str, list[tuple[str, str]]] = {}
    for label, patch in (("executor", ("run_query", _timed_out_by_the_executor)),
                         ("engine", ("execute_query", _timed_out_by_the_engine))):
        with monkeypatch.context() as m:
            if label == "executor":
                m.setattr(srv, *patch)
            else:
                m.setattr(SQLiteConnector, *patch)
            text = _call_error(server, "db_query", {"connection_id": "crm", "sql": "SELECT 1"})
            assert "TIMEOUT: " in text, text
            _call(server, "db_federated_query", {"sql": "SELECT 1"})
        records = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines()]
        audit.write_text("", encoding="utf-8")
        seen[label] = [(r["outcome"], r.get("category")) for r in records
                       if r["action"] in ("db_query", "db_federated_query:statement")]
    assert seen["executor"] == seen["engine"] == [("error", "TIMEOUT")] * 3, seen


def test_a_connection_failure_the_server_raises_is_audited_as_an_error(tmp_path: Path, monkeypatch: Any) -> None:
    def cannot_build(*_a: Any, **_k: Any) -> Any:
        raise OSError(24, "Too many open files")

    server, _ = _server(tmp_path)
    monkeypatch.setattr(registry, "build_connector", cannot_build)
    _call_error(server, "db_query", {"connection_id": "shop", "sql": "SELECT 1"})
    record = _audit_lines(tmp_path)[-1]
    assert (record["outcome"], record["category"]) == ("error", "CONNECTION_ERROR")


_OWN_REFUSAL = (
    "the result would need more than 8 MiB per block even on 1-row blocks (max_block_size=1, "
    "preferred_block_size_bytes=65536); select fewer or narrower columns"
)


def test_a_connectors_own_refusal_keeps_its_numbers(tmp_path: Path, monkeypatch: Any) -> None:
    def refuse(*_a: Any, **_k: Any) -> Any:
        raise ConnectorError(_OWN_REFUSAL, category="LIMIT_EXCEEDED")

    server, _ = _server(tmp_path)
    monkeypatch.setattr(SQLiteConnector, "execute_query", refuse)
    text = _call_error(server, "db_query", {"connection_id": "shop", "sql": "SELECT 1"})
    assert _OWN_REFUSAL in text and "<redacted>" not in text, text


def _refuse_from_a_suppressed_driver_error(*_a: Any, **_k: Any) -> Any:
    try:
        raise ValueError("driver state")
    except ValueError:
        raise ConnectorError(_OWN_REFUSAL, category="LIMIT_EXCEEDED") from None


def _wrap_a_driver_error(*_a: Any, **_k: Any) -> Any:
    try:
        raise ValueError(f"invalid input syntax for type integer: '{SECRETS[0]}' (77000000)")
    except ValueError as exc:
        raise ConnectorError(f"InvalidTextRepresentation: {exc}", category="QUERY_ERROR") from exc


def _wrap_implicitly(*_a: Any, **_k: Any) -> Any:
    try:
        raise ValueError("x")
    except ValueError as exc:
        raise ConnectorError(f"the engine said: '{SECRETS[1]}' 77000000 ({exc})")  # noqa: B904 - the shape under test


@pytest.mark.parametrize(
    ("raiser", "kept", "gone"),
    [
        (_refuse_from_a_suppressed_driver_error, [_OWN_REFUSAL], ["<redacted>"]),
        (_wrap_a_driver_error, ["InvalidTextRepresentation", "<redacted>"], [SECRETS[0], "77000000"]),
        (_wrap_implicitly, ["<redacted>"], [SECRETS[1], "77000000"]),
    ],
)
def test_only_text_the_connector_wrote_itself_escapes_the_sanitizer(
    tmp_path: Path, monkeypatch: Any, raiser: Any, kept: list[str], gone: list[str]
) -> None:
    server, app = _server(tmp_path)
    monkeypatch.setattr(SQLiteConnector, "execute_query", raiser)
    text = _call_error(server, "db_query", {"connection_id": "shop", "sql": "SELECT 1"})
    record = json.dumps(_audit_lines(tmp_path)[-1]) + json.dumps(list(app.history), default=str)
    for part in kept:
        assert part in text, text
    for part in gone:
        assert part not in text and part not in record, text


_INSTALL = "/opt/private-install/lib/python3.12/site-packages/universal_db_mcp/connectors"


@pytest.mark.parametrize(
    ("exc", "kept"),
    [
        (OSError(24, "Too many open files", f"{_INSTALL}/sqlite.py"), ["OSError", "Too many open files"]),
        (ImportError(f"cannot import name 'SQLiteConnector' from 'universal_db_mcp.connectors.sqlite' "
                     f"({_INSTALL}/sqlite.py)"), ["ImportError", "cannot import name"]),
        (PermissionError(13, "Permission denied", "C:\\Program Files\\UniversalDB MCP\\lib\\sqlite.py"),
         ["PermissionError", "Permission denied"]),
        # a Windows host running from a network share (UNC)
        (ImportError("DLL load failed while importing _pyodbc: "
                     "\\\\fileserver\\share\\Program Files\\udbmcp\\site-packages\\pyodbc.pyd"),
         ["ImportError", "DLL load failed while importing _pyodbc"]),
        (OSError(2, "No such file or directory", "\\\\fileserver\\share\\private-install\\sqlite.py"),
         ["FileNotFoundError", "No such file or directory"]),
    ],
)
def test_a_connector_that_cannot_be_built_does_not_echo_the_install_path(
    tmp_path: Path, monkeypatch: Any, exc: BaseException, kept: list[str]
) -> None:
    def cannot_build(*_a: Any, **_k: Any) -> Any:
        raise exc

    server, _ = _server(tmp_path)
    monkeypatch.setattr(registry, "build_connector", cannot_build)
    text = _call_error(server, "db_list_tables", {"connection_id": "shop"})
    assert "CONNECTION_ERROR" in text, text
    for part in kept:
        assert part in text, text
    assert "private-install" not in text and "site-packages" not in text and "Program Files" not in text, text
    assert "fileserver" not in text, text


def test_a_connectors_own_construction_refusal_is_kept_as_written(tmp_path: Path, monkeypatch: Any) -> None:
    refusal = ("mssql password contains '}', which an ODBC connection string cannot carry in any quoting form; "
               "change that value")

    def cannot_build(*_a: Any, **_k: Any) -> Any:
        raise ConnectorError(refusal)

    server, _ = _server(tmp_path)
    monkeypatch.setattr(registry, "build_connector", cannot_build)
    text = _call_error(server, "db_list_tables", {"connection_id": "shop"})
    assert refusal in text, text


@pytest.mark.parametrize(
    ("cell", "needle", "match", "expected"),
    [
        (b"Z\xc3\x9cRI", "züri", "contains", True),
        (b"Z\xc3\x9cRI", "züri", "exact", True),
        (b"Z\xc3\x9cRI\x00\x00", "züri", "exact", True),  # FixedString(7) pads with NULs
        (bytearray(b"Z\xc3\x9cRICH"), "zür", "prefix", True),
        (b"12\x00", "12", "exact", True),
        (b"ZURICH", "züri", "contains", False),
        ("ZÜRI", "züri", "exact", True),
        # what the connectors hand over (driver_helpers: a binary cell as base64, cut to the cell limit)
        ({"$binary_b64": base64.b64encode(b"Z\xc3\x9cRI\x00\x00\x00").decode()}, "züri", "exact", True),
        ({"$binary_b64": base64.b64encode(b"Z\xc3\x9cRICH").decode(), "$truncated": True}, "zür", "prefix", True),
        ({"$binary_b64": "not base64!"}, "züri", "contains", False),
        ({"name": "ZÜRI"}, "züri", "exact", False),
    ],
)
def test_bytes_cells_are_matched_as_text(cell: Any, needle: str, match: str, expected: bool) -> None:
    numeric = 12 if needle == "12" else None
    assert srv._value_matches(cell, needle, numeric, match) is expected


@pytest.mark.parametrize(
    "cell", [b"Z\xc3\x9cRI\x00\x00", {"$binary_b64": base64.b64encode(b"Z\xc3\x9cRI\x00\x00").decode()}]
)
def test_a_clickhouse_fixedstring_match_is_reported(tmp_path: Path, monkeypatch: Any, cell: Any) -> None:
    fake = _CatalogFake(
        [TableSummary("s", "cities", "table")],
        columns=[ColumnInfo("s", "cities", "code", "FixedString(7)"), ColumnInfo("s", "cities", "name", "String")],
        rows={"cities": [{"code": cell, "name": "Zurich"}]},
    )
    server = _fake_server(tmp_path, monkeypatch, fake, engine="clickhouse", allowed=["s"], deny=True)
    for query, match in (("züri", "contains"), ("ZÜRI", "exact")):
        hits = _call(server, "db_search_values", {"query": query, "match": match})["data"]["hits"]
        assert [h["matched_columns"] for h in hits] == [["code"]], (query, match)


def test_db_test_connection_reports_lost_audit_records(tmp_path: Path, monkeypatch: Any, capsys: Any) -> None:
    server, app = _sqlite_server(tmp_path, {"shop": _CATALOG_SCRIPT}, application="  audit_fail_closed: false\n")
    env = _call(server, "db_test_connection", {"connection_id": "shop"})
    assert env["data"]["audit"] == {
        "path": str(tmp_path / "audit.jsonl"), "fail_closed": False, "dropped_records": 0,
    }
    assert not any("audit" in w for w in env.get("warnings", [])), env.get("warnings")

    def disk_full(*_a: Any, **_k: Any) -> None:
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(app.audit, "_append", disk_full)
    _call(server, "db_list_connections", {})
    env = _call(server, "db_test_connection", {"connection_id": "shop"})
    assert env["data"]["audit"]["dropped_records"] == 1
    assert any("1 audit record(s)" in w and "audit_fail_closed" in w for w in env["warnings"]), env["warnings"]
    capsys.readouterr()  # the AuditLog's own stderr notice


def test_db_test_connection_says_when_nothing_is_audited(tmp_path: Path) -> None:
    _, app = _sqlite_server(tmp_path, {"shop": _CATALOG_SCRIPT})
    application = app.cfg.application.model_copy(update={"audit_path": None})
    app.cfg = app.cfg.model_copy(update={"application": application})
    app.audit = srv.AuditLog(path=None)
    env = _call(build_server(app), "db_test_connection", {"connection_id": "shop"})
    assert env["data"]["audit"]["path"] is None
    assert any("not audited" in w for w in env["warnings"]), env.get("warnings")


@pytest.mark.parametrize(
    ("engine", "session", "expected"),
    [
        ("sqlite", "", True),
        # the connector opens the file mode=ro with query_only on, whatever the setting says
        ("sqlite", "    session:\n      enforce_read_only: false\n", True),
        ("postgres", "", True),
        ("postgres", "    session:\n      enforce_read_only: false\n", False),
        ("oracle", "", False),  # no session-level read-only switch: the SQL guard alone refuses writes
        ("db2", "", False),
        ("mssql", "", False),
    ],
)
def test_db_list_connections_reports_the_server_side_read_only_session(
    tmp_path: Path, monkeypatch: Any, engine: str, session: str, expected: bool
) -> None:
    monkeypatch.setenv("UDBMCP_T_USER", "tester")
    db = tmp_path / "shop.db"
    _seed(db)
    target = (f"    database: {db}\n" if engine == "sqlite"
              else "    host: 127.0.0.1\n    port: 5999\n    database: testdb\n    username_env: UDBMCP_T_USER\n")
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "application:\n  transport: stdio\n"
        f"  audit_path: {tmp_path / 'audit.jsonl'}\n"
        f"  metadata_cache_path: {tmp_path / 'cache.sqlite'}\n"
        "security:\n  require_remote_tls: false\n"
        f"connections:\n  c:\n    type: {engine}\n{target}{session}",
        encoding="utf-8",
    )
    app_cfg, resolved = load_resolved(cfg)
    env = _call(build_server(AppContext(app_cfg, resolved)), "db_list_connections", {})
    conn = env["data"]["connections"][0]
    assert conn["read_only"] is True  # the v1 contract: the server never writes
    assert conn["server_read_only_session"] is expected


# I12: the columns of app.customers as the catalog reports them
_PG_CUSTOMERS = [
    ColumnInfo("app", "customers", "customer_id", "integer"),
    ColumnInfo("app", "customers", "full_name", "text"),
    ColumnInfo("app", "customers", "ssn", "text"),
]


def _pg_policy(demo_policy: Any) -> Any:
    return dataclasses.replace(demo_policy, engine="postgres")


def _known_columns(ast: exp.Expression, names: set[str]) -> dict[int, frozenset[str]]:
    # sqlglot reads (TABLE customers) as a table named TABLE aliased customers
    return {
        id(t): frozenset(names) for t in ast.find_all(exp.Table)
        if "customers" in (t.name.lower(), t.alias_or_name.lower())
    }


@pytest.mark.parametrize(
    ("sql", "expected"),
    [
        ("SELECT b.site_row_fn FROM customers b", {0}),
        ("SELECT customers.site_row_fn FROM customers", {0}),
        ("SELECT app.customers.site_row_fn FROM app.customers", {0}),
        ("SELECT upper(b.site_row_fn) AS full_name FROM customers b", {0}),
        ("SELECT x.full_name FROM customers b, LATERAL (SELECT b.site_row_fn AS full_name) x", {0}),
        # PostgreSQL folds an unquoted name, never a quoted one
        ('SELECT b."FULL_NAME" FROM customers b', {0}),
        # controls: real columns in any unquoted spelling, and the renamed ones
        ("SELECT b.full_name FROM customers b", set()),
        ("SELECT b.FULL_NAME FROM customers b", set()),
        ('SELECT b."full_name" FROM customers b', set()),
        ("SELECT count(*) FROM customers b WHERE b.site_row_fn IS NOT NULL", set()),
    ],
)
def test_a_site_row_function_over_a_base_table_is_masked(demo_policy: Any, sql: str, expected: set[int]) -> None:
    policy = _pg_policy(demo_policy)
    ast = sqlglot.parse_one(sql, read="postgres")
    known = _known_columns(ast, {"customer_id", "full_name", "ssn"})
    assert srv._query_mask_positions(policy, ast, [("c0", "t")], None, known) == expected


def test_without_the_tables_columns_only_the_known_row_functions_are_masked(demo_policy: Any) -> None:
    policy = _pg_policy(demo_policy)
    for sql, expected in (("SELECT b.site_row_fn FROM customers b", set()),
                          ("SELECT b.row_to_json FROM customers b", {0})):
        ast = sqlglot.parse_one(sql, read="postgres")
        assert srv._query_mask_positions(policy, ast, [("c0", "t")]) == expected, sql


class _PgRowFake(_FakeConnector):
    """app.customers on a PostgreSQL that answers every statement with one
    row: what attribute notation over a site function would return."""

    def __init__(self) -> None:
        super().__init__([TableSummary("app", "customers", "table")], columns=_PG_CUSTOMERS)
        self.statements: list[str] = []

    def execute_query(self, spec: Any) -> QueryOutcome:
        self.statements.append(spec.sql)
        return QueryOutcome(columns=[("site_row_fn", "text"), ("full_name", "text")],
                            rows=[[f"(1,Jane,{SECRETS[0]})", "Jane"]], truncated=False, rows_seen=1, elapsed_ms=0)


@pytest.mark.parametrize("security", ["", "  mask_action: omit\n"])
def test_db_query_masks_a_site_row_function_over_a_base_table(tmp_path: Path, monkeypatch: Any, security: str) -> None:
    fake = _PgRowFake()
    server, _ = _fake_app_server(tmp_path, monkeypatch, fake, engine="postgres", allowed=["app"], deny=True,
                                 security=security)
    sql = "SELECT b.site_row_fn, b.full_name FROM app.customers b"
    for _ in range(2):
        env = _call(server, "db_query", {"connection_id": "remote", "sql": sql})
        _assert_no_secret(env)
        assert "Jane" in json.dumps(env["data"]["rows"])
    assert fake.calls == [("app", "customers")], "the table's columns are read once and then cached"
    fed = _call(server, "db_federated_query", {"sql": "SELECT b.site_row_fn, b.full_name FROM app.customers b"})
    _assert_no_secret(fed)
    assert fed["data"]["connections_run"] == 1, fed


def test_a_catalog_failure_leaves_a_warning_not_a_failed_query(tmp_path: Path, monkeypatch: Any) -> None:
    fake = _PgRowFake()

    def broken(_schema: str | None, _table: str) -> list[ColumnInfo]:
        driver = ValueError(f"permission denied '{SECRETS[1]}'")
        raise ConnectorError(f"InsufficientPrivilege: {driver}") from driver

    fake.list_columns = broken  # type: ignore[method-assign]
    server, _ = _fake_app_server(tmp_path, monkeypatch, fake, engine="postgres", allowed=["app"], deny=True)
    sql = "SELECT b.site_row_fn, b.full_name FROM app.customers b"
    env = _call(server, "db_query", {"connection_id": "remote", "sql": sql})
    assert env["data"]["rows"] == [["<masked>", "<masked>"]], "fail closed: no name is proven a column"
    assert any("site-defined" in w and "'customers'" in w for w in env["warnings"]), env["warnings"]
    assert SECRETS[1] not in json.dumps(env)


def test_rows_of_one_statement_are_never_folded_into_one_earlier_hit(tmp_path: Path, monkeypatch: Any) -> None:
    """Two keyless rows alike in every column the search reads are two rows:
    when a later chunk returns both, each may join one earlier hit at most."""
    rows = [{"c1": "twin", "c9": "twin"}, {"c1": "twin", "c9": "twin"}]
    server, _ = _sqlite_server(tmp_path, {"shop": _keyless_search_script("wide", 10, rows)})
    monkeypatch.setattr(srv, "_SEARCH_CHUNK_COLUMNS", 4)
    real = srv._earlier_hit
    merged: list[int] = []

    def spy(*args: Any, **kwargs: Any) -> Any:
        hit = real(*args, **kwargs)
        if hit is not None:
            merged.append(id(hit))
        return hit

    monkeypatch.setattr(srv, "_earlier_hit", spy)
    hits = _call(server, "db_search_values", {"query": "twin"})["data"]["hits"]
    assert [h["matched_columns"] for h in hits] == [["c1", "c9"], ["c1", "c9"]]
    assert len(merged) == len(set(merged)) == 2


def test_a_failed_catalog_listing_masks_a_bare_tables_qualified_columns(tmp_path: Path, monkeypatch: Any) -> None:
    """The statement already ran: a listing that fails afterwards (no metadata
    cache, a flaky catalog) masks, it does not fail the call."""
    fake = _PgRowFake()
    server, app = _fake_app_server(tmp_path, monkeypatch, fake, engine="postgres", allowed=[], deny=True)
    real = AppContext.tables_for
    calls = {"n": 0}

    async def flaky(self: Any, policy: Any, connector: Any) -> list[Any]:
        calls["n"] += 1
        if calls["n"] > 1:  # the guard's own listing succeeds; the masking one does not
            raise ConnectorError("OperationalError: server closed the connection") from OSError("reset")
        return await real(self, policy, connector)

    monkeypatch.setattr(AppContext, "tables_for", flaky)
    fake.tables.append(TableSummary("app", "orders", "table"))
    env = _call(server, "db_query", {"connection_id": "remote", "sql": "SELECT b.site_row_fn, b.full_name "
                                     "FROM customers b, orders o WHERE o.customer_id = b.customer_id"})
    assert env["data"]["rows"] == [["<masked>", "<masked>"]]
    assert any("site-defined" in w and "could not be read" in w for w in env["warnings"]), env["warnings"]
    assert calls["n"] == 2, "a failed listing is not asked again for the next bare name"


def test_tables_past_the_lookup_budget_are_masked_not_trusted(tmp_path: Path, monkeypatch: Any) -> None:
    """Decoy tables ahead of the one read through a site function cannot use
    up the lookups and leave it to the built-in list."""
    fake = _PgRowFake()
    fake.tables += [TableSummary("app", f"d{i}", "table") for i in range(3)]
    server, _ = _fake_app_server(tmp_path, monkeypatch, fake, engine="postgres", allowed=["app"], deny=True)
    monkeypatch.setattr(srv, "_ROW_FUNCTION_TABLES", 2)
    decoys = ", ".join(f"app.d{i} x{i}" for i in range(3))
    sql = f"SELECT x0.id, x1.id, x2.id, b.site_row_fn, b.full_name FROM {decoys}, app.customers b"
    fake.execute_query = lambda spec: QueryOutcome(  # type: ignore[method-assign]
        columns=[("id", "t"), ("id", "t"), ("id", "t"), ("site_row_fn", "text"), ("full_name", "text")],
        rows=[[1, 2, 3, f"(1,Jane,{SECRETS[0]})", "Jane"]], truncated=False, rows_seen=1, elapsed_ms=0)
    env = _call(server, "db_query", {"connection_id": "remote", "sql": sql})
    _assert_no_secret(env)
    assert any("lookup" in w and "fail closed" in w for w in env["warnings"]), env["warnings"]


# ================================================================ fix-up round 1
# I12: whether a FROM item names a CTE is its scope's call, and a derived
# table, CTE or parenthesized TABLE that selects * hands its base table's row
# on, so x.site_fn through it is masked too. I06: a row is folded into an
# earlier hit only when it is certainly that row (a unique key, or earlier
# hits alike in everything both statements read that show the same values,
# after statements that returned every row they matched); every column the
# earlier hits matched in is read again. I05: on SQLite a name resolves only
# against the listing, and a cached listing is filtered too. I10:
# db_list_connections reports lost audit records without touching a database.
# I08: a UNC path is scrubbed.

_THROUGH_ANOTHER_SCOPE = [
    # a CTE of the base table's name in another scope leaves it a base table
    "SELECT b.site_row_fn, b.full_name FROM customers b "
    "WHERE EXISTS (WITH customers AS (SELECT 1 AS one) SELECT one FROM customers)",
    "SELECT b.site_row_fn, (WITH customers AS (SELECT 1 AS one) SELECT one FROM customers) AS full_name "
    "FROM customers b",
    # the base table's row handed on by a star
    "SELECT x.site_row_fn, x.full_name FROM (SELECT * FROM app.customers) x",
    "WITH x AS (SELECT * FROM app.customers) SELECT x.site_row_fn, x.full_name FROM x",
    "SELECT x.site_row_fn, x.full_name FROM (SELECT b.* FROM app.customers b) x",
    "SELECT x.site_row_fn, x.full_name FROM (SELECT * FROM (SELECT * FROM app.customers) y) x",
    "SELECT x.site_row_fn, x.full_name FROM (SELECT * FROM app.customers JOIN app.customers c USING (customer_id)) x",
]


@pytest.mark.parametrize("security", ["", "  mask_action: omit\n"])
@pytest.mark.parametrize("sql", _THROUGH_ANOTHER_SCOPE)
def test_a_site_row_function_reached_through_another_scope_is_masked(
    tmp_path: Path, monkeypatch: Any, security: str, sql: str
) -> None:
    fake = _PgRowFake()
    server, _ = _fake_app_server(tmp_path, monkeypatch, fake, engine="postgres", allowed=[], deny=True,
                                 security=security)
    env = _call(server, "db_query", {"connection_id": "remote", "sql": sql})
    _assert_no_secret(env)
    assert "Jane" in json.dumps(env["data"]["rows"]), "a real column through the star stays readable"
    assert ("app", "customers") in fake.calls


def test_a_site_row_function_through_a_star_is_masked_in_a_federated_query(tmp_path: Path, monkeypatch: Any) -> None:
    fake = _PgRowFake()
    server, _ = _fake_app_server(tmp_path, monkeypatch, fake, engine="postgres", allowed=["app"], deny=True)
    fed = _call(server, "db_federated_query",
                {"sql": "SELECT x.site_row_fn, x.full_name FROM (SELECT * FROM app.customers) x"})
    _assert_no_secret(fed)
    assert fed["data"]["connections_run"] == 1, fed


def test_a_site_row_function_over_a_parenthesized_table_is_masked(tmp_path: Path, monkeypatch: Any) -> None:
    """(TABLE customers) is SELECT * FROM customers; with nothing restricting
    names the guard lets the bare name through."""
    fake = _PgRowFake()
    server, _ = _fake_app_server(tmp_path, monkeypatch, fake, engine="postgres", allowed=[], deny=False)
    env = _call(server, "db_query", {"connection_id": "remote",
                                     "sql": "SELECT q.site_row_fn, q.full_name FROM (TABLE customers) q"})
    _assert_no_secret(env)
    assert "Jane" in json.dumps(env["data"]["rows"]) and fake.calls == [("app", "customers")]


def test_a_cte_named_like_a_table_is_not_looked_up(tmp_path: Path, monkeypatch: Any) -> None:
    """The walk knows a CTE's columns: no catalog lookup is spent on it."""
    fake = _PgRowFake()
    server, _ = _fake_app_server(tmp_path, monkeypatch, fake, engine="postgres", allowed=["app"], deny=True)
    _call(server, "db_query", {"connection_id": "remote",
                               "sql": "WITH customers AS (SELECT 1 AS one) SELECT customers.one FROM customers"})
    assert fake.calls == []


@pytest.mark.parametrize(
    ("sql", "expected"),
    [
        ("SELECT x.full_name FROM (SELECT * FROM customers) x", set()),
        ("SELECT x.FULL_NAME FROM (SELECT * FROM customers) x", set()),
        ("SELECT x.site_row_fn FROM (SELECT * FROM customers) x", {0}),
        ('SELECT x."FULL_NAME" FROM (SELECT * FROM customers) x', {0}),
        ("SELECT x.ssn FROM (SELECT * FROM customers) x", {0}),
        ("SELECT x.site_row_fn FROM (SELECT customers.* FROM customers) x", {0}),
        ("WITH x AS (SELECT * FROM customers) SELECT x.full_name FROM x", set()),
        ("WITH x AS (SELECT * FROM customers) SELECT x.site_row_fn FROM x", {0}),
        ("SELECT x.site_row_fn FROM (SELECT * FROM (SELECT * FROM customers) y) x", {0}),
        ("SELECT q.full_name FROM (TABLE customers) q", set()),
        ("SELECT q.site_row_fn FROM (TABLE customers) q", {0}),
        # an explicit column beside the star is still a column
        ("SELECT x.extra FROM (SELECT *, 1 AS extra FROM customers) x", set()),
        # USING merges columns, and their names are still the table's
        ("SELECT x.full_name FROM (SELECT * FROM customers JOIN customers c USING (customer_id)) x", set()),
        ("SELECT x.site_row_fn FROM (SELECT * FROM customers JOIN customers c USING (customer_id)) x", {0}),
    ],
)
def test_a_star_over_a_base_table_hands_its_row_on(demo_policy: Any, sql: str, expected: set[int]) -> None:
    policy = _pg_policy(demo_policy)
    ast = sqlglot.parse_one(sql, read="postgres")
    known = _known_columns(ast, {"customer_id", "full_name", "ssn"})
    assert srv._query_mask_positions(policy, ast, [("c0", "t")], None, known) == expected


def test_without_the_tables_columns_a_star_leaves_only_the_known_row_functions(demo_policy: Any) -> None:
    policy = _pg_policy(demo_policy)
    for sql, expected in (("SELECT x.site_row_fn FROM (SELECT * FROM customers) x", set()),
                          ("SELECT x.row_to_json FROM (SELECT * FROM customers) x", {0})):
        ast = sqlglot.parse_one(sql, read="postgres")
        assert srv._query_mask_positions(policy, ast, [("c0", "t")]) == expected, sql


def test_a_keyless_row_is_never_shown_with_another_rows_values(tmp_path: Path) -> None:
    """Two keyless rows share the value the first chunk matched; only the
    second matches again in the third. The leading columns every statement
    reads tell the two apart, so it joins its own hit."""
    rows = [
        {"c1": "Smith", "c2": "r1", "c33": "r1-other"},
        {"c1": "Smith", "c2": "r2", "c33": "smith notes of r2"},
    ]
    server, _ = _sqlite_server(tmp_path, {"shop": _keyless_search_script("wide", 40, rows)})
    hits = _call(server, "db_search_values", {"query": "smith"})["data"]["hits"]
    assert [(h["row"]["c2"], h["matched_columns"]) for h in hits] == [("r1", ["c1"]), ("r2", ["c1", "c33"])]
    assert hits[0]["row"].get("c33") is None and hits[1]["row"]["c33"] == "smith notes of r2"


def test_keyless_rows_a_later_statement_cannot_tell_apart_are_not_mixed(tmp_path: Path) -> None:
    """Rows alike in everything the later statement reads, differing only in
    a column the earlier one read: the later row is reported on its own, not
    folded into a hit that may be the other row."""
    rows = [
        {"c1": "Smith", "c10": "r1"},
        {"c1": "Smith", "c10": "r2", "c33": "smith notes of r2"},
    ]
    server, _ = _sqlite_server(tmp_path, {"shop": _keyless_search_script("wide", 40, rows)})
    hits = _call(server, "db_search_values", {"query": "smith"})["data"]["hits"]
    assert [h["matched_columns"] for h in hits] == [["c1"], ["c1"], ["c33"]]
    assert [h["row"].get("c10") for h in hits] == ["r1", "r2", None]
    assert [h["row"].get("c33") for h in hits] == [None, None, "smith notes of r2"]


def test_a_row_matching_again_past_the_eighth_matched_column_is_one_hit(tmp_path: Path) -> None:
    rows: list[dict[str, str]] = [{f"c{i}": "needle-9"} for i in range(1, 10)]
    rows[8]["c33"] = "needle-9"  # the ninth row matches again in the third chunk
    server, _ = _sqlite_server(tmp_path, {"shop": _keyless_search_script("wide", 40, rows)})
    hits = _call(server, "db_search_values", {"query": "needle-9", "max_hits_per_table": 10})["data"]["hits"]
    assert [h["matched_columns"] for h in hits] == [[f"c{i}"] for i in range(1, 9)] + [["c9", "c33"]]


def test_a_clickhouse_sorting_key_does_not_identify_a_row(tmp_path: Path, monkeypatch: Any) -> None:
    """ClickHouse lists its sorting key as the primary key, and any number of
    rows may share it."""
    fake = _CatalogFake(
        [TableSummary("s", "events", "table")],
        columns=[ColumnInfo("s", "events", "k", "String"),
                 *(ColumnInfo("s", "events", f"c{i}", "String") for i in range(1, 21))],
        indexes=[IndexInfo(name="(sorting key)", columns=["k"], unique=False, primary=True, kind="sorting_key",
                           schema="s", table="events")],
        rows={"events": [{"k": "tenant-a", "c1": "smith-1", "c2": "row-one"},
                         {"k": "tenant-a", "c2": "row-two", "c18": "smith-2"}]},
    )
    server = _fake_server(tmp_path, monkeypatch, fake, engine="clickhouse", allowed=["s"], deny=True)
    hits = _call(server, "db_search_values", {"query": "smith"})["data"]["hits"]
    assert [(h["row"].get("c2"), h["matched_columns"]) for h in hits] == [("row-one", ["c1"]), ("row-two", ["c18"])]
    assert hits[0]["row"].get("c18") is None


class _ScriptedSearchFake(_CatalogFake):
    """Each statement returns the next scripted batch of rows, projected onto
    the columns it selects, whatever its WHERE says: an engine whose
    collation matches more than the text does."""

    batches: list[list[dict[str, Any]]]

    def execute_query(self, spec: Any) -> QueryOutcome:
        self.statements.append(spec.sql)
        found = re.match(r"SELECT (.*) FROM", spec.sql)
        assert found, spec.sql
        select = re.findall(r'"([^"]*)"', found.group(1))
        batch = self.batches.pop(0) if self.batches else []
        rows = [[r.get(n) for n in select] for r in batch]
        return QueryOutcome(columns=[(n, "text") for n in select], rows=rows, truncated=False, rows_seen=len(rows),
                            elapsed_ms=0)


def test_a_keyless_row_is_not_joined_after_a_statement_stopped_at_its_limit(tmp_path: Path, monkeypatch: Any) -> None:
    """The first statement filled its LIMIT with a row the engine matched and
    the text does not, so a row it matched may be unreported: a later row
    alike to an earlier hit may be that one, and is reported on its own."""
    fake = _ScriptedSearchFake(
        [TableSummary("s", "wide", "table")],
        columns=[ColumnInfo("s", "wide", f"c{i}", "text") for i in range(1, 21)],
    )
    fake.batches = [
        [{"c1": "zurich"}, {"c1": "needle", "c2": "a"}],  # 2 rows: the LIMIT of max_hits_per_table=2
        [{"c1": "needle", "c2": "a", "c18": "needle", "c19": "b-only"}],
    ]
    server = _fake_server(tmp_path, monkeypatch, fake, engine="postgres", allowed=["s"], deny=True)
    hits = _call(server, "db_search_values", {"query": "needle", "max_hits_per_table": 2})["data"]["hits"]
    assert [h["matched_columns"] for h in hits] == [["c1"], ["c18"]]
    assert hits[0]["row"].get("c19") is None


def test_the_earlier_hit_of_a_keyless_row_needs_complete_earlier_statements() -> None:
    hit = {"matched_columns": ["c1"], "row": {"c1": "needle", "c2": "a"}}
    values = {"c1": "needle", "c2": "a", "c9": "needle"}
    assert srv._earlier_hit([(0, hit)], 8, values, [], set(), complete=True) is hit
    assert srv._earlier_hit([(0, hit)], 8, values, [], set(), complete=False) is None
    # a unique key names the row whatever the earlier statements returned
    keyed = {"matched_columns": ["c1"], "row": {"id": 1, "c1": "needle"}}
    assert srv._earlier_hit([(0, keyed)], 8, {"id": 1, "c9": "needle"}, ["id"], set(), complete=False) is keyed
    # several alike hits that show different values: which one it is cannot be known
    other = {"matched_columns": ["c1"], "row": {"c1": "needle", "c2": "b"}}
    assert srv._earlier_hit([(0, hit), (0, other)], 8, {"c1": "needle", "c9": "needle"}, [], set(),
                            complete=True) is None


@pytest.mark.parametrize("name", ["pragma_database_list", "pragma_table_list", "pragma_compile_options", "dbstat",
                                  "main.pragma_database_list", "json_each"])
@pytest.mark.parametrize("tool", ["db_sample_table", "db_list_columns", "db_get_statistics", "db_get_table"])
def test_sqlite_eponymous_tables_are_not_objects_without_default_deny(tmp_path: Path, name: str, tool: str) -> None:
    """They read the database file's path and the catalog's own names."""
    server, _ = _sqlite_server(tmp_path, {"shop": _CATALOG_SCRIPT}, security="  default_deny_objects: false\n")
    text = _call_error(server, tool, {"connection_id": "shop", "object_name": name})
    assert "AUTHORIZATION_DENIED" in text, text
    assert str(tmp_path) not in text and "sqlite_schema" not in text


def test_sqlite_tables_still_resolve_without_default_deny(tmp_path: Path) -> None:
    server, _ = _sqlite_server(tmp_path, {"shop": _CATALOG_SCRIPT}, security="  default_deny_objects: false\n")
    for name in ("users", "USERS", "main.users"):
        env = _call(server, "db_sample_table", {"connection_id": "shop", "object_name": name})
        assert env["data"]["rows"], name


def test_a_cached_listing_naming_sqlites_catalog_is_filtered(tmp_path: Path) -> None:
    """A metadata cache an earlier release wrote, when sqlite_schema was listed."""
    from universal_db_mcp.security.cursors import policy_fingerprint

    server, app = _sqlite_server(tmp_path, {"shop": _CATALOG_SCRIPT})
    app.cache.put_tables("shop", policy_fingerprint(app._policy_for("shop")), [
        TableSummary("main", "users", "table"), TableSummary("main", "sqlite_schema", "table"),
        TableSummary("main", "sqlite_sequence", "table"),
    ])
    envs = [
        _call(server, "db_list_tables", {"connection_id": "shop"}),
        _call(server, "db_get_catalog", {"connection_id": "shop", "include_system": True}),
    ]
    assert [t["name"] for t in envs[0]["data"]["tables"]] == ["users"]
    for env in envs:
        text = json.dumps(env).lower()
        assert "sqlite_schema" not in text and "sqlite_sequence" not in text, text[:600]


# I05, the statement route: the guard refuses SQLite's catalog by name only
# under default-deny, and without it resolves no name against the listing;
# with default_deny_objects: false, db_query returned sqlite_schema.sql and
# pragma_table_info's dflt_value, a sensitive column's DEFAULT literal each.
_SQLITE_CATALOG_STATEMENTS = [
    "SELECT sql FROM sqlite_schema",
    "SELECT sql FROM main.sqlite_master",
    'SELECT sql FROM "sqlite_schema"',
    "SELECT sql FROM SQLITE_MASTER",
    "SELECT * FROM sqlite_temp_schema",
    "SELECT * FROM sqlite_stat1",
    "SELECT (SELECT group_concat(sql) FROM sqlite_master) AS s",
    "WITH x AS (SELECT sql FROM main.sqlite_schema) SELECT * FROM x",
    "SELECT u.id, s.sql FROM users u JOIN sqlite_schema s ON 1 = 1",
    # A CTE of the same name that the reference cannot see: declared inside
    # EXISTS, a scalar subquery, a derived table, another UNION branch
    "SELECT sql FROM sqlite_schema WHERE EXISTS (WITH sqlite_schema AS (SELECT 1 AS a) SELECT a FROM sqlite_schema)",
    "SELECT (SELECT group_concat(sql) FROM sqlite_master) AS s,"
    " (WITH sqlite_master AS (SELECT 1 AS a) SELECT a FROM sqlite_master) AS t",
    "SELECT s.sql FROM sqlite_schema s, (WITH sqlite_schema AS (SELECT 1 AS a) SELECT a FROM sqlite_schema) z",
    "SELECT sql FROM sqlite_schema UNION ALL"
    " SELECT a FROM (WITH sqlite_schema AS (SELECT 'x' AS a) SELECT a FROM sqlite_schema)",
    "SELECT * FROM users WHERE id IN (SELECT 1 FROM sqlite_schema WHERE sql LIKE '%changeme%')"
    " AND EXISTS (WITH sqlite_schema AS (SELECT 1 AS a) SELECT a FROM sqlite_schema)",
]
_SQLITE_EPONYMOUS_STATEMENTS = [
    "SELECT name, dflt_value FROM pragma_table_info WHERE arg = 'users'",
    "SELECT * FROM main.pragma_table_xinfo WHERE arg = 'users'",
    "SELECT * FROM pragma_database_list",
    "SELECT * FROM pragma_table_list",
    "SELECT name FROM dbstat",
    "SELECT u.id FROM users u WHERE u.id IN (SELECT cid FROM pragma_table_info WHERE arg = 'users')",
    "SELECT name, dflt_value FROM pragma_table_info WHERE arg = 'users'"
    " AND EXISTS (WITH pragma_table_info AS (SELECT 1 AS a) SELECT a FROM pragma_table_info)",
    "SELECT file FROM pragma_database_list"
    " WHERE EXISTS (WITH pragma_database_list AS (SELECT 1 AS a) SELECT a FROM pragma_database_list)",
    "SELECT (SELECT file FROM pragma_database_list) AS f,"
    " (WITH pragma_database_list AS (SELECT 1 AS a) SELECT a FROM pragma_database_list) AS g",
    "SELECT p.file FROM pragma_database_list p,"
    " (WITH pragma_database_list AS (SELECT 1 AS a) SELECT a FROM pragma_database_list) z",
]


_STATEMENT_TOOLS = ["db_query", "db_validate_query", "db_explain", "db_federated_query", "db_federated_join"]


def _statement_call(tool: str, sql: str) -> dict[str, Any]:
    if tool == "db_federated_query":
        return {"sql": sql, "connections": ["shop"]}
    if tool == "db_explain":
        return {"connection_id": "shop", "sql": f"EXPLAIN QUERY PLAN {sql}"}
    if tool == "db_federated_join":
        return {"left": {"connection": "shop", "sql": sql}, "on": [["id", "id"]], "join": "left",
                "right": {"connection": "shop", "sql": "SELECT id FROM users"}}
    return {"connection_id": "shop", "sql": sql}


def _statement_refusal(server: Any, tool: str, sql: str) -> str:
    if tool != "db_federated_query":
        return _call_error(server, tool, _statement_call(tool, sql))
    env = _call(server, tool, _statement_call(tool, sql))
    [result] = env["data"]["results"]
    assert not result.get("rows"), result
    return json.dumps(env)


@pytest.mark.parametrize("deny", [True, False])
@pytest.mark.parametrize("sql", _SQLITE_CATALOG_STATEMENTS)
@pytest.mark.parametrize("tool", _STATEMENT_TOOLS)
def test_sqlite_catalog_tables_are_refused_in_a_statement(tmp_path: Path, deny: bool, sql: str, tool: str) -> None:
    server, _ = _sqlite_server(
        tmp_path, {"shop": _CATALOG_SCRIPT + "CREATE INDEX ix_pw ON users (password); ANALYZE;"},
        security=f"  default_deny_objects: {str(deny).lower()}\n",
    )
    text = _statement_refusal(server, tool, sql)
    assert "POLICY_VIOLATION" in text and "SQLite catalog table" in text, text
    assert _CATALOG_SECRET not in text


@pytest.mark.parametrize("deny", [True, False])
@pytest.mark.parametrize("sql", _SQLITE_EPONYMOUS_STATEMENTS)
@pytest.mark.parametrize("tool", _STATEMENT_TOOLS)
def test_sqlite_eponymous_tables_are_refused_in_a_statement(tmp_path: Path, deny: bool, sql: str, tool: str) -> None:
    """pragma_table_info WHERE arg = 't' is the table-function call the guard
    refuses, spelled as a table: it reads the same DEFAULT literals;
    pragma_database_list reads the file's path."""
    server, _ = _sqlite_server(
        tmp_path, {"shop": _CATALOG_SCRIPT}, security=f"  default_deny_objects: {str(deny).lower()}\n"
    )
    text = _statement_refusal(server, tool, sql)
    assert "POLICY_VIOLATION" in text and "could not be resolved to a permitted object" in text, text
    assert _CATALOG_SECRET not in text and str(tmp_path) not in text


@pytest.mark.parametrize("sql", [
    "SELECT id FROM users",
    "SELECT id FROM USERS",
    "SELECT id FROM main.users",
    'SELECT id FROM "users"',
    "SELECT id FROM recent",
    "WITH sqlite_like AS (SELECT id FROM users) SELECT id FROM sqlite_like",
    "WITH u AS (SELECT id FROM users) SELECT u.id FROM u JOIN recent r ON r.id = u.id",
])
@pytest.mark.parametrize("tool", _STATEMENT_TOOLS)
def test_sqlite_tables_views_and_ctes_still_read_in_a_statement_without_default_deny(
    tmp_path: Path, sql: str, tool: str
) -> None:
    server, _ = _sqlite_server(
        tmp_path, {"shop": _CATALOG_SCRIPT + "CREATE VIEW recent AS SELECT id FROM users;"},
        security="  default_deny_objects: false\n",
    )
    env = _call(server, tool, _statement_call(tool, sql))
    if tool == "db_query":
        assert env["data"]["rows"] == [[1]], env
    if tool == "db_federated_query":
        assert env["data"]["results"][0]["rows"] == [[1]], env
    if tool == "db_federated_join":
        assert env["data"]["rows"] == [[1, 1]], env


# I05 round 3: the guard left out of its checks (and of GuardResult.tables)
# every bare name some CTE of the statement declares, in whatever scope, so a
# CTE inside EXISTS hid the outer reference to the real table. A reference is
# a CTE's only where a WITH it can see declares that name.
@pytest.mark.parametrize("deny", [True, False])
@pytest.mark.parametrize("sql", [
    "SELECT id FROM users WHERE EXISTS (WITH u AS (SELECT 1 AS a) SELECT a FROM u)",
    "WITH u AS (SELECT id FROM users) SELECT id FROM u WHERE EXISTS (SELECT 1 FROM u)",
    "WITH u AS (SELECT id FROM users) SELECT id FROM (SELECT id FROM u) d",
    "WITH U AS (SELECT id FROM users) SELECT id FROM u",  # SQLite: names fold, quoted or not
    'WITH "U" AS (SELECT id FROM users) SELECT id FROM u',
    "WITH RECURSIVE n(id) AS (SELECT 1 UNION ALL SELECT id + 1 FROM n WHERE id < 1) SELECT id FROM n",
    "SELECT id FROM (WITH users AS (SELECT 1 AS id) SELECT id FROM users)",
])
@pytest.mark.parametrize("tool", _STATEMENT_TOOLS)
def test_sqlite_ctes_in_scope_still_read(tmp_path: Path, deny: bool, sql: str, tool: str) -> None:
    server, _ = _sqlite_server(
        tmp_path, {"shop": _CATALOG_SCRIPT}, security=f"  default_deny_objects: {str(deny).lower()}\n"
    )
    env = _call(server, tool, _statement_call(tool, sql))
    if tool == "db_query":
        assert env["data"]["rows"] == [[1]], env
    if tool == "db_federated_query":
        assert env["data"]["results"][0]["rows"] == [[1]], env


@pytest.mark.parametrize("deny", [True, False])
def test_sqlite_a_cte_naming_a_later_one_reads_but_is_masked_whole(tmp_path: Path, deny: bool) -> None:
    """SQLite's CTEs see each other in any order; the taint walk (sqlglot)
    sees only the ones before, so it cannot trace the output (fail closed)."""
    server, _ = _sqlite_server(
        tmp_path, {"shop": _CATALOG_SCRIPT}, security=f"  default_deny_objects: {str(deny).lower()}\n"
    )
    sql = "WITH a AS (SELECT id FROM b), b AS (SELECT id FROM users) SELECT id FROM a"
    env = _call(server, "db_query", {"connection_id": "shop", "sql": sql})
    assert env["data"]["rows"] == [["<masked>"]], env
    assert any("could not all be traced" in w for w in env["warnings"]), env["warnings"]


class _StatementFake(_FakeConnector):
    """app.customers on a remote engine; a statement that reaches it is
    recorded and answers one row. Oracle and Db2 catalogs spell an unquoted
    schema in upper case, as they look it up."""

    def __init__(self, engine: str = "postgres") -> None:
        upper = engine in ("oracle", "db2")
        super().__init__([TableSummary("APP" if upper else "app", "CUSTOMERS" if upper else "customers", "table")])
        self.statements: list[str] = []

    def execute_query(self, spec: Any) -> QueryOutcome:
        self.statements.append(spec.sql)
        return QueryOutcome(columns=[("id", "integer")], rows=[[1]], truncated=False, rows_seen=1, elapsed_ms=0)


# payroll is not a permitted object; a CTE of that name the reference cannot see
_HIDDEN_BY_A_CTE = [
    "SELECT * FROM payroll WHERE EXISTS (WITH payroll AS (SELECT 1 AS a) SELECT a FROM payroll)",
    "SELECT (SELECT COUNT(*) FROM payroll) AS n, (WITH payroll AS (SELECT 1 AS a) SELECT a FROM payroll) AS z",
    "SELECT p.* FROM payroll p, (WITH payroll AS (SELECT 1 AS a) SELECT a FROM payroll) z",
    "SELECT id FROM customers WHERE id IN (SELECT id FROM payroll)"
    " AND EXISTS (WITH payroll AS (SELECT 1 AS a) SELECT a FROM payroll)",
    "SELECT a FROM (WITH payroll AS (SELECT 1 AS a) SELECT a FROM payroll) z UNION ALL SELECT id FROM payroll",
    "SELECT id FROM customers WHERE EXISTS (WITH payroll AS (SELECT 1 AS a) SELECT a FROM payroll)"
    " AND EXISTS (SELECT 1 FROM payroll)",
]
# engine by engine, a name only a CTE out of reach, or not a CTE at all, declares
_HIDDEN_ON_THE_ENGINE = [
    # PostgreSQL: without RECURSIVE a CTE sees neither itself nor the CTEs after it
    ("postgres", "WITH payroll AS (SELECT * FROM payroll) SELECT * FROM payroll"),
    ("postgres", "WITH a AS (SELECT * FROM payroll), payroll AS (SELECT 1 AS x) SELECT * FROM a"),
    ("postgres", '(WITH payroll AS (SELECT 1 AS a) SELECT a FROM payroll) UNION ALL SELECT a FROM payroll'),
    # an unquoted name folds to lower case, a quoted one does not
    ("postgres", 'WITH "PAYROLL" AS (SELECT 1 AS a) SELECT * FROM payroll'),
    ("postgres", 'WITH payroll AS (SELECT 1 AS a) SELECT * FROM "PAYROLL"'),
    ("mysql", "WITH payroll AS (SELECT * FROM payroll) SELECT * FROM payroll"),
    ("mysql", "WITH a AS (SELECT * FROM payroll), payroll AS (SELECT 1 AS x) SELECT * FROM a"),
    # Oracle and Db2 fold an unquoted name to upper case
    ("oracle", 'WITH "payroll" AS (SELECT 1 AS a FROM customers) SELECT * FROM payroll'),
    ("oracle", "WITH a AS (SELECT * FROM payroll), payroll AS (SELECT 1 AS x FROM customers) SELECT * FROM a"),
    ("db2", 'WITH "payroll" AS (SELECT 1 AS a FROM customers) SELECT * FROM payroll'),
    # a collation may make SQL Server's names case-sensitive: only the same spelling is the CTE
    ("mssql", "WITH Payroll AS (SELECT 1 AS a) SELECT * FROM payroll"),
    # ClickHouse: WITH <expression> AS name names a value, never a table
    ("clickhouse", "WITH 1 AS payroll SELECT * FROM payroll"),
]
_REMOTE_ENGINES = ["postgres", "mysql", "oracle", "mssql", "clickhouse", "db2"]


@pytest.mark.parametrize(("deny", "allowed"), [(True, []), (True, ["app"]), (False, ["app"])])
@pytest.mark.parametrize(("engine", "sql"), [
    *((engine, sql) for engine in _REMOTE_ENGINES for sql in _HIDDEN_BY_A_CTE), *_HIDDEN_ON_THE_ENGINE,
])
def test_a_cte_out_of_scope_does_not_hide_the_table(
    tmp_path: Path, monkeypatch: Any, deny: bool, allowed: list[str], engine: str, sql: str
) -> None:
    """Live on PostgreSQL under default-deny, the same shapes over
    pg_stat_activity and pg_roles returned other sessions' statements and
    the role names. Under an allowlist the permitted table is written
    qualified (a bare name is refused there, owner decision 2026-09-27), and
    the bare payroll is refused as unqualified."""
    if allowed:
        sql = re.sub(r"\bFROM customers\b", "FROM app.customers", sql)
    category = "AUTHORIZATION_DENIED" if allowed else "POLICY_VIOLATION"
    fake = _StatementFake(engine)
    server, _ = _fake_app_server(tmp_path, monkeypatch, fake, engine=engine, allowed=allowed, deny=deny)
    for tool in ("db_query", "db_validate_query"):
        text = _call_error(server, tool, {"connection_id": "remote", "sql": sql})
        assert category in text and "'payroll'" in text.lower(), text
    env = _call(server, "db_federated_query", {"sql": sql, "connections": ["remote"]})
    assert category in env["data"]["results"][0]["error"], env
    assert fake.statements == []


_CTES_IN_SCOPE = [
    "WITH c AS (SELECT id FROM customers) SELECT id FROM c WHERE EXISTS (SELECT 1 FROM c)",
    "SELECT id FROM customers WHERE EXISTS (WITH c AS (SELECT id FROM customers) SELECT id FROM c)",
    "WITH a AS (SELECT id FROM customers), b AS (SELECT id FROM a) SELECT id FROM b",
    "WITH c AS (SELECT id FROM customers) SELECT id FROM (SELECT id FROM c) d",
    "SELECT id FROM (WITH customers AS (SELECT 1 AS id) SELECT id FROM customers) d",
    "WITH c AS (SELECT id FROM customers) SELECT id FROM (SELECT id FROM c UNION ALL SELECT id FROM c) d",
]
_CTES_ON_THE_ENGINE = [
    ("postgres", "WITH RECURSIVE t AS (SELECT id FROM customers UNION ALL SELECT id FROM t) SELECT id FROM t"),
    ("postgres", "WITH RECURSIVE a AS (SELECT id FROM b), b AS (SELECT id FROM customers) SELECT id FROM a"),
    ("postgres", "WITH C AS (SELECT id FROM customers) SELECT id FROM c"),
    ("postgres", 'WITH c AS (SELECT id FROM customers) SELECT id FROM "c"'),
    ("mysql", "WITH RECURSIVE t AS (SELECT id FROM customers UNION ALL SELECT id FROM t) SELECT id FROM t"),
    # a CTE naming itself is recursive on SQL Server, Oracle and Db2, which have no RECURSIVE keyword
    ("mssql", "WITH t (id) AS (SELECT id FROM customers UNION ALL SELECT id FROM t) SELECT id FROM t"),
    ("oracle", "WITH t (id) AS (SELECT id FROM customers UNION ALL SELECT id FROM t) SELECT id FROM t"),
    ("db2", "WITH t (id) AS (SELECT id FROM customers UNION ALL SELECT id FROM t) SELECT id FROM t"),
    ("oracle", 'WITH c AS (SELECT id FROM customers) SELECT id FROM "C"'),
    ("db2", "WITH c AS (SELECT id FROM customers) SELECT id FROM C"),
]


@pytest.mark.parametrize("allowed", [[], ["app"]])
@pytest.mark.parametrize(("engine", "sql"), [
    *((engine, sql) for engine in _REMOTE_ENGINES for sql in _CTES_IN_SCOPE), *_CTES_ON_THE_ENGINE,
])
def test_a_cte_in_scope_is_still_a_cte_under_default_deny(
    tmp_path: Path, monkeypatch: Any, engine: str, sql: str, allowed: list[str]
) -> None:
    if allowed and "WITH customers" not in sql:
        # under an allowlist the table is written qualified; a CTE's name stays bare
        sql = re.sub(r"\bFROM customers\b", "FROM app.customers", sql)
    fake = _StatementFake(engine)
    server, _ = _fake_app_server(tmp_path, monkeypatch, fake, engine=engine, allowed=allowed, deny=True)
    env = _call(server, "db_validate_query", {"connection_id": "remote", "sql": sql})
    assert env["data"]["valid"] is True
    assert {r["name"] for r in env["data"]["referenced_objects"]} <= {"customers"}, env["data"]


@pytest.mark.parametrize("shape", ["chain", "wide", "union"])
def test_the_cte_reach_check_is_linear_at_the_size_ceiling(monkeypatch: Any, shape: str) -> None:
    """Thousands of CTEs, each named by the next (or all by one FROM, or one
    CTE by every branch of a long UNION): each WITH's names are read once,
    and a walk up the tree is shared, not repeated per reference."""
    from universal_db_mcp.security.sql_guard import _MAX_SQL_BYTES

    n = 1500
    if shape == "chain":
        body = ", ".join(["c0 AS (SELECT 1 AS a)", *(f"c{i} AS (SELECT a FROM c{i - 1})" for i in range(1, n))])
        sql = f"WITH {body} SELECT a FROM c{n - 1}"
    elif shape == "wide":
        sql = "WITH " + ", ".join(f"c{i} AS (SELECT 1 AS a)" for i in range(n))
        sql += " SELECT a FROM " + ", ".join(f"c{i}" for i in range(n))
    else:
        sql = "WITH c AS (SELECT 1 AS a) " + " UNION ALL ".join(["SELECT a FROM c"] * n)
    assert len(sql) <= _MAX_SQL_BYTES
    ast = sqlglot.parse_one(sql, read="postgres")
    folds = 0
    fold = srv._folded_name

    def counted(engine: str, ident: exp.Identifier, *folding: Any) -> str:
        nonlocal folds
        folds += 1
        return fold(engine, ident, *folding)

    class Steps(dict[tuple[int, str], bool]):
        """The walk's memo, counting what the walk asks of it and records."""

        count = 0

        def __contains__(self, key: object) -> bool:
            self.count += 1
            return super().__contains__(key)

        def __setitem__(self, key: tuple[int, str], value: bool) -> None:
            self.count += 1
            super().__setitem__(key, value)

    steps = Steps()
    reach = srv._cte_in_reach

    def walked(
        engine: str, table: exp.Table, name: str, declared: Any, position: Any, recursive: Any, _memo: Any
    ) -> bool:
        return reach(engine, table, name, declared, position, recursive, steps)

    monkeypatch.setattr(srv, "_folded_name", counted)
    monkeypatch.setattr(srv, "_cte_in_reach", walked)
    assert srv._cte_hidden_tables("postgres", ast) == []
    nodes = sum(1 for _ in ast.walk())
    assert folds <= 3 * n, folds
    assert steps.count <= 4 * nodes, (steps.count, nodes)


def test_a_reference_a_cte_out_of_scope_hid_is_reported(tmp_path: Path, monkeypatch: Any) -> None:
    """Nothing restricting names, the table is read, and named as read."""
    fake = _StatementFake()
    server, _ = _fake_app_server(tmp_path, monkeypatch, fake, engine="postgres", allowed=[], deny=False)
    sql = "SELECT id FROM payroll WHERE EXISTS (WITH payroll AS (SELECT 1 AS a) SELECT a FROM payroll)"
    env = _call(server, "db_validate_query", {"connection_id": "remote", "sql": sql})
    assert env["data"]["referenced_objects"] == [{"schema": None, "name": "payroll", "catalog": None}]


class _AnswerFake(_FakeConnector):
    """app.customers (customer_id, full_name, ssn) on a remote engine that
    answers every statement with the given columns and one row. Oracle and
    Db2 catalogs spell an unquoted name in upper case, as they look it up."""

    def __init__(self, columns: list[str], row: list[Any], engine: str = "postgres") -> None:
        if engine in ("oracle", "db2"):
            super().__init__([TableSummary("APP", "CUSTOMERS", "table")],
                             columns=[dataclasses.replace(c, schema="APP", table="CUSTOMERS") for c in _PG_CUSTOMERS])
        else:
            super().__init__([TableSummary("app", "customers", "table")], columns=_PG_CUSTOMERS)
        self.answer = QueryOutcome(columns=[(c, "text") for c in columns], rows=[row], truncated=False, rows_seen=1,
                                   elapsed_ms=0)

    def execute_query(self, spec: Any) -> QueryOutcome:
        return self.answer


# The taint walk read a FROM item as sqlglot binds it, by the exact name:
# where the engine folds the name and binds it to the table instead, the walk
# traced the CTE's clean literals over the table's row; and on engines with no
# RECURSIVE keyword a CTE naming itself was a base table to it, so a value the
# recursion moves to another column went unmasked.
@pytest.mark.parametrize(("engine", "sql", "columns", "row"), [
    ("postgres", 'WITH "CUSTOMERS" AS (SELECT 1 AS a, 2 AS b, 3 AS c) SELECT * FROM CUSTOMERS AS t(a, b, c)',
     ["a", "b", "c"], [1, "Jane", SECRETS[0]]),
    ("postgres", 'WITH "CUSTOMERS" AS (SELECT 1 AS x, 2 AS y, 3 AS z)'
     " SELECT t.x AS a, t.y AS b, t.z AS c FROM CUSTOMERS AS t(x, y, z)", ["a", "b", "c"], [1, "Jane", SECRETS[0]]),
    ("oracle", 'WITH "customers" AS (SELECT 1 AS a, 2 AS b, 3 AS c FROM customers) SELECT * FROM customers',
     ["CUSTOMER_ID", "FULL_NAME", "SSN"], [1, "Jane", SECRETS[0]]),
    ("db2", 'WITH "customers" AS (SELECT 1 AS a, 2 AS b, 3 AS c FROM customers) SELECT * FROM customers',
     ["CUSTOMER_ID", "FULL_NAME", "SSN"], [1, "Jane", SECRETS[0]]),
    *((engine, "WITH t (a, b, n) AS (SELECT ssn, full_name, 0 FROM customers"
       " UNION ALL SELECT b, a, n + 1 FROM t WHERE n < 1) SELECT b FROM t", ["b"], [SECRETS[0]])
      for engine in ("mssql", "oracle", "db2")),
    # a case-insensitive collation binds customers to the CTE Customers (live on SQL Server)
    *((engine, sql, ["a", "b"], [1, SECRETS[0]])
      for engine in ("mssql", "mysql")
      for sql in ("WITH Customers (a, b) AS (SELECT customer_id, ssn FROM customers) SELECT a, b FROM customers",
                  "WITH Customers (a, b) AS (SELECT customer_id, ssn FROM customers) SELECT * FROM customers")),
])
def test_a_from_item_the_engine_binds_otherwise_is_masked(
    tmp_path: Path, monkeypatch: Any, engine: str, sql: str, columns: list[str], row: list[Any]
) -> None:
    fake = _AnswerFake(columns, row, engine)
    server, _ = _fake_app_server(tmp_path, monkeypatch, fake, engine=engine, allowed=[], deny=True)
    env = _call(server, "db_query", {"connection_id": "remote", "sql": sql})
    _assert_no_secret(env)


@pytest.mark.parametrize(("engine", "sql"), [
    (engine, "WITH t (a, n) AS (SELECT full_name, 0 FROM customers UNION ALL SELECT a, n + 1 FROM t WHERE n < 1)"
             " SELECT a FROM t")
    for engine in ("mssql", "oracle", "db2")
] + [
    ("postgres", "WITH RECURSIVE t (a, n) AS (SELECT full_name, 0 FROM customers"
                 " UNION ALL SELECT a, n + 1 FROM t WHERE n < 1) SELECT a FROM t"),
    ("postgres", 'WITH c AS (SELECT full_name AS a FROM customers) SELECT a FROM "c"'),
    ("postgres", "WITH C AS (SELECT full_name AS a FROM customers) SELECT a FROM c"),
    ("oracle", 'WITH "C" AS (SELECT full_name AS a FROM customers) SELECT a FROM C'),
    ("oracle", 'WITH c AS (SELECT full_name AS a FROM customers) SELECT a FROM "C"'),
    ("db2", "WITH c AS (SELECT full_name AS a FROM customers) SELECT a FROM C"),
    ("mssql", "WITH c AS (SELECT full_name AS a FROM customers) SELECT a FROM [c]"),
])
def test_a_cte_the_engine_binds_like_the_walk_stays_readable(
    tmp_path: Path, monkeypatch: Any, engine: str, sql: str
) -> None:
    fake = _AnswerFake(["a"], ["Jane"], engine)
    server, _ = _fake_app_server(tmp_path, monkeypatch, fake, engine=engine, allowed=[], deny=True)
    env = _call(server, "db_query", {"connection_id": "remote", "sql": sql})
    assert env["data"]["rows"] == [["Jane"]], env


@pytest.mark.parametrize(("engine", "sql"), [
    ("postgres", "WITH RECURSIVE b AS (SELECT a FROM c), c AS (SELECT full_name AS a FROM customers) SELECT a FROM b"),
    ("mssql", "WITH Customers (a) AS (SELECT full_name FROM customers) SELECT a FROM customers"),
    ("mysql", "WITH Customers (a) AS (SELECT full_name FROM customers) SELECT a FROM customers"),
])
def test_a_cte_the_walk_cannot_bind_like_the_engine_is_masked_whole(
    tmp_path: Path, monkeypatch: Any, engine: str, sql: str
) -> None:
    """A later CTE PostgreSQL's RECURSIVE lets a CTE name, or a name a
    collation may compare case-insensitively: the output cannot be traced,
    and every column is masked (fail closed)."""
    fake = _AnswerFake(["a"], ["Jane"], engine)
    server, _ = _fake_app_server(tmp_path, monkeypatch, fake, engine=engine, allowed=[], deny=True)
    env = _call(server, "db_query", {"connection_id": "remote", "sql": sql})
    assert env["data"]["rows"] == [["<masked>"]], env
    assert any("could not all be traced" in w for w in env["warnings"]), env["warnings"]


_RECURSIVE_SCRIPT = (
    "CREATE TABLE people (id INTEGER PRIMARY KEY, name TEXT, ssn TEXT);"
    f"INSERT INTO people VALUES (1, 'Jane', '{SECRETS[0]}');"
)


@pytest.mark.parametrize("keyword", ["", "RECURSIVE "])
def test_sqlite_a_recursion_moving_a_value_to_another_column_is_masked(tmp_path: Path, keyword: str) -> None:
    """SQLite makes a CTE naming itself recursive with or without the keyword."""
    server, _ = _sqlite_server(tmp_path, {"shop": _RECURSIVE_SCRIPT})
    moved = (f"WITH {keyword}t (a, b, n) AS (SELECT ssn, name, 0 FROM people"
             " UNION ALL SELECT b, a, n + 1 FROM t WHERE n < 1) SELECT b FROM t")
    env = _call(server, "db_query", {"connection_id": "shop", "sql": moved})
    _assert_no_secret(env)
    assert env["data"]["rows"] == [["<masked>"], ["<masked>"]], env
    clean = (f"WITH {keyword}t (a, n) AS (SELECT name, 0 FROM people"
             " UNION ALL SELECT a, n + 1 FROM t WHERE n < 1) SELECT a FROM t")
    env = _call(server, "db_query", {"connection_id": "shop", "sql": clean})
    assert env["data"]["rows"] == [["Jane"], ["Jane"]], env


def test_db_list_connections_reports_lost_audit_records_without_a_database(
    tmp_path: Path, monkeypatch: Any, capsys: Any
) -> None:
    """db_test_connection needs the database up; this listing touches none."""
    server, app = _sqlite_server(tmp_path, {"shop": _CATALOG_SCRIPT}, application="  audit_fail_closed: false\n")

    def cannot_build(*_a: Any, **_k: Any) -> Any:
        raise OSError(errno.ECONNREFUSED, "Connection refused")

    def disk_full(*_a: Any, **_k: Any) -> None:
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(registry, "build_connector", cannot_build)
    env = _call(server, "db_list_connections", {})
    assert env["data"]["audit"] == {"path": str(tmp_path / "audit.jsonl"), "fail_closed": False, "dropped_records": 0}
    assert not env.get("warnings"), env.get("warnings")
    monkeypatch.setattr(app.audit, "_append", disk_full)
    _call(server, "db_list_connections", {})
    env = _call(server, "db_list_connections", {})
    assert env["data"]["audit"]["dropped_records"] == 1
    assert any("audit record(s)" in w and "audit_fail_closed" in w for w in env["warnings"]), env["warnings"]
    capsys.readouterr()  # the AuditLog's own stderr notice


# ================================================================ fix-up round 2
# I12: with nothing restricting names the guard lets PostgreSQL bind a bare
# name, and one the catalog listing leaves out (a partitioned parent, a
# foreign table, a table created after the listing was cached) has no columns
# to tell a column from a site function over its row: every name qualified
# through it is masked. The listing is read once per statement, and a table
# named again is not resolved again. A bare name listed in several schemas is
# a column only in every one of them, and a cached column list expires.
# I06: a later chunk's merge into an earlier hit is charged to the byte ceiling.

_UNLISTED_BARE = [
    "SELECT b.site_row_fn, b.full_name FROM customers b",
    "SELECT customers.site_row_fn, customers.full_name FROM customers",
    "SELECT x.site_row_fn, x.full_name FROM (SELECT * FROM customers) x",
    "SELECT q.site_row_fn, q.full_name FROM (TABLE customers) q",
]


@pytest.mark.parametrize("security", ["", "  mask_action: omit\n"])
@pytest.mark.parametrize("kind", ["partitioned_table", "foreign_table", None])
@pytest.mark.parametrize("sql", _UNLISTED_BARE)
def test_a_bare_table_the_listing_does_not_name_is_masked(
    tmp_path: Path, monkeypatch: Any, sql: str, kind: str | None, security: str
) -> None:
    """The reviewer's live case: a partitioned parent (relkind p, never
    listed), a foreign table (not among the listed kinds) or a table created
    after the listing was cached (None)."""
    fake = _PgRowFake()
    fake.tables = [] if kind is None else [TableSummary("app", "customers", kind)]
    server, _ = _fake_app_server(tmp_path, monkeypatch, fake, engine="postgres", allowed=[], deny=False,
                                 security=security)
    env = _call(server, "db_query", {"connection_id": "remote", "sql": sql})
    _assert_no_secret(env)
    assert "Jane" not in json.dumps(env["data"]["rows"]), "fail closed: no name is proven a column"
    assert any("'customers'" in w and "catalog listing" in w and "schema" in w for w in env["warnings"]), \
        env["warnings"]
    assert fake.calls == []


def test_a_qualified_name_the_listing_does_not_name_keeps_its_columns(tmp_path: Path, monkeypatch: Any) -> None:
    """The remedy the warning names: the schema-qualified name's columns are
    read, so its real columns stay readable and the site function is masked."""
    fake = _PgRowFake()
    fake.tables = [TableSummary("app", "customers", "partitioned_table")]
    server, _ = _fake_app_server(tmp_path, monkeypatch, fake, engine="postgres", allowed=[], deny=False)
    env = _call(server, "db_query", {"connection_id": "remote",
                                     "sql": "SELECT b.site_row_fn, b.full_name FROM app.customers b"})
    _assert_no_secret(env)
    assert env["data"]["rows"] == [["<masked>", "Jane"]] and fake.calls == [("app", "customers")]


@pytest.mark.parametrize("qualified", [False, True])
@pytest.mark.parametrize("distinct", [False, True])
def test_the_listing_is_read_once_per_statement(
    tmp_path: Path, monkeypatch: Any, qualified: bool, distinct: bool
) -> None:
    """The reviewer's amplification: a listing read (and two passes over it)
    for every bare FROM item of a long UNION, of one table or of many."""
    fake = _PgRowFake()
    fake.tables += [TableSummary("app", f"filler_{i}", "table") for i in range(50)]
    server, _ = _fake_app_server(tmp_path, monkeypatch, fake, engine="postgres", allowed=[], deny=True)
    real = AppContext.tables_for
    calls = {"n": 0}

    async def counting(self: Any, policy: Any, connector: Any) -> list[Any]:
        calls["n"] += 1
        return await real(self, policy, connector)

    monkeypatch.setattr(AppContext, "tables_for", counting)
    seen: list[int] = []
    for branches in (1, 40):
        calls["n"] = 0
        tables = [f"filler_{i}" if distinct and i else "customers" for i in range(branches)]
        sql = " UNION ALL ".join(
            f"SELECT b{i}.site_row_fn, b{i}.full_name FROM {'app.' if qualified else ''}{t} b{i}"
            for i, t in enumerate(tables)
        )
        env = _call(server, "db_query", {"connection_id": "remote", "sql": sql})
        _assert_no_secret(env)
        seen.append(calls["n"])
    assert seen[0] == seen[1], seen
    assert fake.calls[0] == ("app", "customers") and len(fake.calls) == len(set(fake.calls))


def test_a_table_whose_columns_cannot_be_read_is_asked_once_per_statement(tmp_path: Path, monkeypatch: Any) -> None:
    fake = _PgRowFake()

    def broken(schema: str | None, table: str) -> list[ColumnInfo]:
        fake.calls.append((schema, table))
        raise ConnectorError("InsufficientPrivilege: permission denied for table customers")

    fake.list_columns = broken  # type: ignore[method-assign]
    server, _ = _fake_app_server(tmp_path, monkeypatch, fake, engine="postgres", allowed=[], deny=True)
    for table in ("customers", "app.customers"):
        fake.calls.clear()
        sql = " UNION ALL ".join(f"SELECT b{i}.site_row_fn, b{i}.full_name FROM {table} b{i}" for i in range(40))
        env = _call(server, "db_query", {"connection_id": "remote", "sql": sql})
        assert env["data"]["rows"] == [["<masked>", "<masked>"]], table
        assert fake.calls == [("app", "customers")], table
        assert len([w for w in env["warnings"] if "could not be read" in w]) == 1, env["warnings"]


class _TwoSchemaFake(_PgRowFake):
    """customers in app and in app2, where only app2's has a column named
    site_row_fn: a bare customers may bind to either."""

    def __init__(self) -> None:
        super().__init__()
        self.tables = [TableSummary("app", "customers", "table"), TableSummary("app2", "customers", "table")]
        self.columns = [*_PG_CUSTOMERS, *(dataclasses.replace(c, schema="app2") for c in _PG_CUSTOMERS),
                        ColumnInfo("app2", "customers", "site_row_fn", "text")]

    def list_columns(self, schema: str | None, table: str) -> list[ColumnInfo]:
        self.calls.append((schema, table))
        return [c for c in self.columns if c.schema == schema and c.table == table]


def test_a_bare_name_in_two_schemas_is_a_column_only_in_both(tmp_path: Path, monkeypatch: Any) -> None:
    """search_path may bind customers to app.customers, where site_row_fn is a
    site function over the row, although app2.customers has such a column."""
    fake = _TwoSchemaFake()
    server, _ = _fake_app_server(tmp_path, monkeypatch, fake, engine="postgres", allowed=[], deny=False)
    env = _call(server, "db_query", {"connection_id": "remote",
                                     "sql": "SELECT b.site_row_fn, b.full_name FROM customers b"})
    _assert_no_secret(env)
    assert env["data"]["rows"] == [["<masked>", "Jane"]]
    assert sorted(fake.calls) == [("app", "customers"), ("app2", "customers")]


def test_a_cached_column_list_expires(tmp_path: Path, monkeypatch: Any) -> None:
    """A column dropped (and a site function of its name created) after the
    table's columns were read: past _ROW_COLUMNS_TTL they are read again."""
    fake = _PgRowFake()
    server, app = _fake_app_server(tmp_path, monkeypatch, fake, engine="postgres", allowed=["app"], deny=True)
    stale = frozenset({"customer_id", "full_name", "ssn", "site_row_fn"})
    key = ("remote", "app", "customers")
    sql = "SELECT b.site_row_fn, b.full_name FROM app.customers b"
    app.row_columns[key] = (time.monotonic() - srv._ROW_COLUMNS_TTL / 2, stale)
    env = _call(server, "db_query", {"connection_id": "remote", "sql": sql})
    assert fake.calls == [] and SECRETS[0] in json.dumps(env), "a fresh entry is used as it is"
    app.row_columns[key] = (time.monotonic() - srv._ROW_COLUMNS_TTL - 1, stale)
    env = _call(server, "db_query", {"connection_id": "remote", "sql": sql})
    _assert_no_secret(env)
    assert fake.calls == [("app", "customers")] and app.row_columns[key][1] == frozenset(
        {"customer_id", "full_name", "ssn"}
    )


class _MatviewFake(_PgRowFake):
    """app.customers is a materialized view: information_schema.columns,
    which list_columns reads, has no row for its columns."""

    def __init__(self) -> None:
        super().__init__()
        self.tables = [TableSummary("app", "customers", "materialized_view")]

    def list_columns(self, schema: str | None, table: str) -> list[ColumnInfo]:
        self.calls.append((schema, table))
        return []


@pytest.mark.parametrize("security", ["", "  mask_action: omit\n"])
@pytest.mark.parametrize(("sql", "allowed"), [
    ("SELECT b.site_row_fn, b.full_name FROM app.customers b", ["app"]),
    # a bare name is refused under an allowlist (owner decision 2026-09-27)
    ("SELECT b.site_row_fn, b.full_name FROM customers b", []),
    ("SELECT x.site_row_fn, x.full_name FROM (SELECT * FROM app.customers) x", ["app"]),
])
def test_a_relation_the_catalog_lists_no_columns_of_is_masked(
    tmp_path: Path, monkeypatch: Any, sql: str, allowed: list[str], security: str
) -> None:
    """Live on PostgreSQL 17: a site function over a materialized view's row
    (information_schema does not list its columns) returned the masked value
    in every configuration, default-deny with a schema allowlist included."""
    fake = _MatviewFake()
    server, _ = _fake_app_server(tmp_path, monkeypatch, fake, engine="postgres", allowed=allowed, deny=True,
                                 security=security)
    env = _call(server, "db_query", {"connection_id": "remote", "sql": sql})
    _assert_no_secret(env)
    assert "Jane" not in json.dumps(env["data"]["rows"]), "fail closed: no name is proven a column"
    assert any("'customers'" in w and "lists no columns" in w and "qualifier" in w for w in env["warnings"]), \
        env["warnings"]


def test_a_bare_name_that_may_bind_to_a_relation_without_listed_columns_is_masked(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """customers is a table in app and a materialized view in app2: search_path
    may bind the bare name to the one whose columns are unknown."""
    fake = _TwoSchemaFake()
    fake.tables[1] = TableSummary("app2", "customers", "materialized_view")
    fake.columns = list(_PG_CUSTOMERS)
    server, _ = _fake_app_server(tmp_path, monkeypatch, fake, engine="postgres", allowed=[], deny=False)
    env = _call(server, "db_query", {"connection_id": "remote",
                                     "sql": "SELECT b.site_row_fn, b.full_name FROM customers b"})
    _assert_no_secret(env)
    assert env["data"]["rows"] == [["<masked>", "<masked>"]]


@pytest.mark.parametrize("keyed", [True, False])
def test_a_merge_into_an_earlier_hit_is_charged_to_the_byte_ceiling(
    tmp_path: Path, monkeypatch: Any, keyed: bool
) -> None:
    """Every hit fits when the first chunk reports it; the later chunk's
    columns merged into them cross the ceiling."""
    ceiling = 3000
    late = "needle-" + "y" * 290
    rows = [{"c1": f"needle-{n}", "c9": late} for n in range(10)]
    build = _wide_search_script if keyed else _keyless_search_script
    script = build("wide", 10, rows) + build("wide_too", 10, rows)  # whichever comes second is not reached
    server, _ = _sqlite_server(tmp_path, {"shop": script}, security=f"  max_response_bytes: {ceiling}\n")
    monkeypatch.setattr(srv, "_SEARCH_CHUNK_COLUMNS", 4)
    env = _call(server, "db_search_values", {"query": "needle", "max_hits_per_table": 20})
    hits = env["data"]["hits"]
    assert len(hits) == 10 and len({h["table"] for h in hits}) == 1
    assert all(h["matched_columns"][0] == "c1" for h in hits) and len(json.dumps(hits)) <= ceiling
    assert any(h["matched_columns"] == ["c1", "c9"] for h in hits), "some merges fit"
    assert any("response byte ceiling reached" in w for w in env["warnings"]), env["warnings"]
    assert not any("time budget" in w for w in env["warnings"]), "the byte ceiling ended it, not the clock"
    assert any("1 permitted table(s)" in w and "byte ceiling" in w for w in env["warnings"]), env["warnings"]
