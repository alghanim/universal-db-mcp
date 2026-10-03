"""Regressions for the second /code-review max pass over server.py (review of
33a8477, fixed 2026-10-03): the server's CTE pre-filter against the guard's
Unicode folding (V1-a), composite and table-function widths (M1 class),
MySQL backtick identifiers in the DDL tokenizer (S3), SQLite double-quoted
words in view definitions (R6), correlated qualifiers and unused CTEs (M2
class), SQLite's renamed aliases (P2 class), the bounded case tables, the
federated tool's per-statement parameters and the catalog work of the
discovery tools.

Engines that run in-process (SQLite) or on a loopback fixture (PostgreSQL
127.0.0.1:5433, MySQL 3307, ClickHouse 8124) are exercised end to end, and
skipped where the fixture is not running."""

from __future__ import annotations

import dataclasses
import itertools
import unicodedata
from functools import cache
from pathlib import Path
from typing import Any

import pytest
import sqlglot
from test_cr_fix_server import _call, _Fake, _fake_server, _final_mask, _no_secret, _on, _server

from universal_db_mcp import server as srv
from universal_db_mcp.connectors.base import ColumnInfo, QueryOutcome, TableSummary
from universal_db_mcp.errors import ToolFailure
from universal_db_mcp.security.sql_guard import SqlGuard, sqlglot_dialect

# ------------------------------- V1-a: the guard's folding is the server's


def _one(fold: Any, ch: str) -> str:
    mapped = fold(ch)
    return mapped if len(mapped) == 1 else ch


@cache
def _disagreeing_pairs() -> list[tuple[str, str]]:
    """Every pair of distinct code points that one of Unicode's case mappings
    (upper, lower, casefold) takes to one string, where at least one of them
    is a code point whose mappings disagree with each other (upper then lower
    is not lower, casefold is not lower, ...): σ/ς, θ/ϑ, μ/µ, с/ᲃ and the
    like."""
    cased = [
        ch for ch in map(chr, range(0x110000))
        if not 0xD800 <= ord(ch) < 0xE000 and (ch.upper() != ch or ch.lower() != ch or ch.casefold() != ch)
    ]
    disagreeing = {
        ch for ch in cased
        if _one(str.lower, _one(str.upper, ch)) != _one(str.lower, ch)
        or _one(str.upper, _one(str.lower, ch)) != _one(str.upper, ch)
        or ch.casefold() != ch.lower()
    }
    groups: dict[tuple[str, str], set[str]] = {}
    for ch in cased:
        for kind, fold in (("upper", str.upper), ("lower", str.lower), ("casefold", str.casefold)):
            groups.setdefault((kind, fold(ch)), set()).add(ch)
    pairs = {
        (a, b) for group in groups.values() for a, b in itertools.permutations(sorted(group), 2)
        if a in disagreeing or b in disagreeing
    }
    return sorted(pairs)


def test_v1a_the_pairs_cover_the_reported_letters() -> None:
    pairs = set(_disagreeing_pairs())
    for a, b in (("σ", "ς"), ("θ", "ϑ"), ("μ", "µ"), ("с", "ᲃ"), ("о", "ᲂ"), ("т", "ᲄ")):
        assert (a, b) in pairs and (b, a) in pairs, (a, b, unicodedata.name(b))


_GUARDS: dict[str, Any] = {}


def _guard(demo_policy: Any, engine: str) -> SqlGuard:
    policy = dataclasses.replace(demo_policy, engine=engine, default_deny_objects=True)
    from types import SimpleNamespace

    listed = srv._LiveResolver([SimpleNamespace(schema="HR", name="EMPLOYEES", kind="table")])
    return SqlGuard(engine, policy, listed)


@pytest.mark.parametrize("engine", ["oracle", "postgres", "db2", "mysql", "mssql", "sqlite"])
def test_v1a_the_server_considers_every_from_item_the_guard_takes_for_a_cte(demo_policy: Any, engine: str) -> None:
    """Property over every disagreeing pair: a bare FROM item the guard
    skips as a CTE's reference (its _cte_key matches a CTE's) is one the
    server's backstop decides on (_cte_bindings)."""
    guard = _guard(demo_policy, engine)
    dialect = sqlglot_dialect(engine)
    missed = []
    for a, b in _disagreeing_pairs():
        for quoted in (False, True):
            cte = sqlglot.exp.to_identifier(f"t{a}", quoted=quoted)
            ref = sqlglot.exp.Identifier(this=f"t{b}", quoted=False)
            if guard._cte_key(cte) != guard._cte_key(ref):
                continue
            sql = _out_of_reach("", cte.sql(dialect=dialect), ref.sql(dialect=dialect))
            try:
                ast = sqlglot.parse_one(sql, read=dialect)
            except sqlglot.errors.ParseError:
                continue  # refused by the guard as unparsable
            refs = [t for t in ast.find_all(sqlglot.exp.Table) if t.name == ref.name]
            if not refs or guard._cte_key(refs[0].this) != guard._cte_key(cte):
                continue
            considered = {id(t) for t, _bound in srv._cte_bindings(engine, ast)}
            if id(refs[0]) not in considered:
                missed.append((a, b, quoted, sql))
    assert not missed, missed[:10]


def _out_of_reach(engine: str, cte: str, ref: str) -> str:
    dual = {"oracle": " FROM DUAL", "db2": " FROM SYSIBM.SYSDUMMY1"}.get(engine, "")
    return f"SELECT * FROM {ref} WHERE EXISTS (WITH {cte} AS (SELECT 1 AS x{dual}) SELECT x FROM {cte})"


@pytest.mark.parametrize("engine", ["oracle", "postgres", "db2"])
def test_v1a_a_cte_out_of_reach_never_hides_a_table_whatever_its_case_mapping(
    demo_policy: Any, engine: str
) -> None:
    """End to end through the guard and the server's backstop: the outer
    FROM item is out of the CTE's reach, so it names a table no policy lists
    and the statement is refused, for every disagreeing pair."""
    guard = _guard(demo_policy, engine)
    passed = []
    for a, b in _disagreeing_pairs():
        for cte in (f"t{a}", f'"t{a}"'):
            sql = _out_of_reach(engine, cte, f"t{b}")
            try:
                srv._validate_in_scope(guard, engine, lambda g, sql=sql: g.validate_select(sql))
            except ToolFailure:
                continue
            passed.append(sql)
    assert not passed, passed[:10]


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT * FROM ΠΕΛΑΤΕΣ WHERE EXISTS (WITH πελατεσ AS (SELECT 1 AS x FROM DUAL) SELECT x FROM πελατεσ)",
        "SELECT * FROM ϑx WHERE EXISTS (WITH θx AS (SELECT 1 AS x FROM DUAL) SELECT x FROM θx)",
        "SELECT * FROM µx WHERE EXISTS (WITH μx AS (SELECT 1 AS x FROM DUAL) SELECT x FROM μx)",
        "SELECT * FROM сотрудники WHERE EXISTS (WITH ᲃᲂᲄрудники AS (SELECT 1 AS x FROM DUAL) SELECT 1 FROM ᲃᲂᲄрудники)",
    ],
)
def test_v1a_oracle_end_to_end_refuses_the_hidden_table(tmp_path: Path, monkeypatch: Any, sql: str) -> None:
    fake = _Fake([TableSummary("HR", "EMPLOYEES", "table", row_estimate=10),
                  TableSummary("APP", "ΠΕΛΑΤΕΣ", "table", row_estimate=10)],
                 schemas=["HR", "APP"], columns=[ColumnInfo("HR", "EMPLOYEES", "ID", "NUMBER")])
    server = _fake_server(tmp_path, monkeypatch, fake, engine="oracle", allowed=["hr"], system=["information_schema"])
    with pytest.raises(Exception, match="AUTHORIZATION_DENIED"):
        _call(server, "db_query", {"connection_id": "remote", "sql": sql})
    assert fake.statements == []


class _Rows(_Fake):
    def __init__(self, *args: Any, outcome: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.outcome = outcome

    def execute_query(self, spec: Any) -> Any:
        self.statements.append(spec.sql)
        return self.outcome


@pytest.mark.parametrize(("cte", "ref"), [("σ", "ς"), ("ς", "σ"), ("θ", "ϑ"), ("μ", "µ"), ("ᲃ", "с")])
def test_v1a_oracle_a_cte_bound_by_unicode_upper_case_is_traced(
    tmp_path: Path, monkeypatch: Any, cte: str, ref: str
) -> None:
    fake = _Rows(
        [TableSummary("HR", "PEOPLE", "table", row_estimate=10)], schemas=["HR"],
        columns=[ColumnInfo("HR", "PEOPLE", "SSN", "VARCHAR2(20)")],
        outcome=QueryOutcome(columns=[("X", "VARCHAR2")], rows=[["a"], ["999-90-1111"]], truncated=False,
                             rows_seen=2, elapsed_ms=1),
    )
    server = _fake_server(tmp_path, monkeypatch, fake, engine="oracle", allowed=["hr"], system=["information_schema"])
    sql = f"WITH {cte} AS (SELECT 'a' AS x FROM DUAL UNION ALL SELECT ssn FROM hr.people) SELECT * FROM {ref}"
    env = _call(server, "db_query", {"connection_id": "remote", "sql": sql})
    assert fake.statements, env
    _no_secret(env["data"])


def test_v6b_the_case_tables_stay_bounded() -> None:
    """A table shared by every statement remembers at most the code points
    below its bound, whatever names callers send (review V6-b)."""
    for table in (srv._NAME_FOLDING["oracle"][0], srv._UNICODE_FOLDING["postgres"][0]):
        assert isinstance(table, srv._UnicodeCase)
        "".join(map(chr, range(0x800, 0x30000))).translate(table)
        assert len(table) <= srv._UNICODE_CASE_CACHED
    assert "straße_é_ς".translate(srv._NAME_FOLDING["oracle"][0]) == "STRAßE_É_Σ"


# ------------------- M1 class: composite and table-function output widths

CUSTOMERS = ["customer_id", "full_name", "email", "ssn", "country", "created_at"]


@pytest.mark.parametrize(
    ("engine", "sql", "columns", "leaking"),
    [
        ("postgres", "SELECT ((c).*), upper(c.ssn), c.* FROM customers c", [*CUSTOMERS, "upper", *CUSTOMERS], 6),
        ("postgres", "SELECT (((c).*)), upper(c.ssn), c.* FROM customers c", [*CUSTOMERS, "upper", *CUSTOMERS], 6),
        ("postgres", "SELECT (c.*), upper(c.ssn), c.* FROM customers c", [*CUSTOMERS, "upper", *CUSTOMERS], 6),
        ("postgres", "SELECT c.* AS customer_id, upper(c.ssn), c.* FROM customers c",
         [*CUSTOMERS, "upper", *CUSTOMERS], 6),
        ("clickhouse", "SELECT (c.*), concat(c.ssn, ''), c.* FROM customers c",
         [*CUSTOMERS, "concat(ssn, '')", *CUSTOMERS], 6),
        # WITH ORDINALITY adds a column the alias list does not name
        ("postgres", "SELECT u.*, upper(c.ssn), c.* FROM unnest(ARRAY[1]) WITH ORDINALITY AS u(x), customers c",
         ["x", "ordinality", "upper", *CUSTOMERS], 2),
        # unnest of two arrays is two columns, one of them named by the list
        ("postgres", "SELECT u.*, upper(c.ssn), c.* FROM unnest(ARRAY[1], ARRAY[2]) AS u(x), customers c",
         ["x", "unnest", "upper", *CUSTOMERS], 2),
        ("postgres", "SELECT *, upper(c.ssn) FROM unnest(ARRAY[1]) WITH ORDINALITY AS u(x), customers c",
         ["x", "ordinality", *CUSTOMERS, "upper"], 8),
    ],
)
def test_m1_widths_the_analysis_cannot_prove_never_shift_a_mask(
    demo_policy: Any, engine: str, sql: str, columns: list[str], leaking: int
) -> None:
    assert leaking in _final_mask(_on(demo_policy, engine), sql, columns)


@pytest.mark.parametrize(
    ("sql", "columns", "masked"),
    [
        # a VALUES list's width is its rows': the positions stay exact
        ("SELECT v.*, upper(c.ssn), c.full_name FROM (VALUES (1, 2)) AS v(a, b), customers c",
         ["a", "b", "upper", "full_name"], {2}),
        ("SELECT u.x, upper(c.ssn), c.full_name FROM unnest(ARRAY[1]) WITH ORDINALITY AS u(x), customers c",
         ["x", "upper", "full_name"], {1}),
        ("SELECT * FROM unnest(ARRAY[1]) AS u(x)", ["x"], set()),
        ("SELECT c.*, 1 AS one FROM customers c", [*CUSTOMERS, "one"], {3}),
    ],
)
def test_m1_widths_the_analysis_proves_stay_exact(
    demo_policy: Any, sql: str, columns: list[str], masked: set[int]
) -> None:
    assert _final_mask(_on(demo_policy, "postgres"), sql, columns) == masked


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT ((b).*), upper(b.callsign), b.* FROM ocean.buoys b",
        "SELECT (b.*), upper(b.callsign), b.* FROM ocean.buoys b",
        "SELECT b.* AS buoy_id, upper(b.callsign), b.* FROM ocean.buoys b",
        "SELECT u.*, upper(b.callsign), b.* FROM unnest(ARRAY[1]) WITH ORDINALITY AS u(x), ocean.buoys b",
        "SELECT u.*, upper(b.callsign), b.* FROM unnest(ARRAY[1], ARRAY[2]) AS u(x), ocean.buoys b",
    ],
)
def test_m1_live_postgres(tmp_path: Path, sql: str) -> None:
    from test_cr_fix_server import _callsigns, _pg_live

    server = _pg_live(tmp_path)
    _conn, callsigns = _callsigns(tmp_path)
    env = _call(server, "db_query", {"connection_id": "pg", "sql": sql})
    assert env["data"]["rows"], env
    _no_secret(env["data"], callsigns)


def test_m1_unnest_of_scalar_array_literals_keeps_exact_positions(demo_policy: Any) -> None:
    sql = "SELECT u.*, upper(c.ssn), c.* FROM unnest(ARRAY[1, 2]) AS u(x), customers c"
    assert _final_mask(_on(demo_policy, "postgres"), sql, ["x", "upper", *CUSTOMERS]) == {1, 5}
    sql = "SELECT u.*, upper(c.ssn), c.* FROM unnest(ARRAY[1], ARRAY['a']) AS u(x, y), customers c"
    assert _final_mask(_on(demo_policy, "postgres"), sql, ["x", "y", "upper", *CUSTOMERS]) == {2, 6}


# --------------------------- S3: MySQL never escapes inside a backtick name

_MYSQL_CANONICAL = (
    "select 'O\\'Brien' AS `O'Brien`,'C:\\\\' AS `C:\\`,'it\\'s `x`' AS `it's ``x``` from `d`.`u` "
    "where ((`d`.`u`.`password` = 'hunter2') and (`d`.`u`.`note` <> 'O\\'Neil'))"
)


def _pw_policy(demo_policy: Any, engine: str) -> Any:
    import re

    return dataclasses.replace(demo_policy, engine=engine, sensitive_patterns=[re.compile(r"(?i)password")])


def test_s3_a_backtick_name_ending_in_a_backslash_keeps_mysql_in_step(demo_policy: Any) -> None:
    """MySQL's canonical VIEW_DEFINITION names an auto alias `C:\\`; a
    backslash inside backticks is the character itself."""
    assert srv._literal_beside_sensitive(_pw_policy(demo_policy, "mysql"), _MYSQL_CANONICAL)
    tokens = srv._ddl_tokens(_MYSQL_CANONICAL, "mysql", backslash=True, nested=False)
    assert tokens is not None and ("ident", "C:\\") in tokens and ("lit", "hunter2") in tokens


@pytest.mark.parametrize(
    ("engine", "definition"),
    [
        # a backslash-ending backtick name with nothing secret beside it
        ("mysql", "select `a\\` AS `b` from `d`.`u` where (`d`.`u`.`id` = 1)"),
        ("mysql", "select 'x\\'y' AS `C:\\` from `d`.`u` where (`d`.`u`.`password_set` = 1)"),
    ],
)
def test_s3_backtick_controls(demo_policy: Any, engine: str, definition: str) -> None:
    policy = _pw_policy(demo_policy, engine)
    tokens = srv._ddl_tokens(definition, engine, backslash=True, nested=False)
    assert tokens is not None
    if "password" not in definition:
        assert not srv._literal_beside_sensitive(policy, definition)


def test_s3_clickhouse_still_escapes_inside_quoted_names(demo_policy: Any) -> None:
    tokens = srv._ddl_tokens("SELECT 1 AS `a\\`b` FROM t", "clickhouse", backslash=True, nested=False)
    assert tokens is not None and ("ident", "a\\`b") in tokens


# ------------- R6: a double-quoted word is a name only in its query's scope


def _sqlite_views(tmp_path: Path, ddl: str) -> Any:
    import sqlite3

    server, app = _server(tmp_path)
    c = sqlite3.connect(tmp_path / "shop.db")
    c.executescript(ddl)
    c.commit()
    c.close()
    return server, app


def _view_defs(server: Any) -> dict[str, Any]:
    env = _call(server, "db_list_views", {"connection_id": "shop"})
    return {v["name"]: v["definition"] for v in env["data"]["views"]}


def _get_def(server: Any, name: str) -> Any:
    return _call(server, "db_get_table", {"connection_id": "shop", "object_name": name})["data"].get("definition")


_R6_DDL = """
CREATE TABLE users (id INTEGER PRIMARY KEY, password TEXT);
CREATE TABLE guest (gid INTEGER PRIMARY KEY);
CREATE TABLE roles (rid INTEGER PRIMARY KEY, admin TEXT);
INSERT INTO users VALUES (1, 'guest'), (2, 'admin');
CREATE VIEW v_guest AS SELECT id FROM users WHERE password = "guest";
CREATE VIEW v_admin AS SELECT id FROM users WHERE password = "admin";
CREATE VIEW v_outer AS SELECT id FROM users WHERE password = "admin" AND EXISTS (SELECT 1 FROM roles);
CREATE VIEW v_named AS SELECT "full_name" FROM "customers" WHERE ssn IS NOT NULL;
CREATE VIEW v_alias AS SELECT c."full_name" AS "who" FROM "customers" c WHERE "ssn" IS NOT NULL ORDER BY "who";
CREATE VIEW v_corr AS SELECT id FROM users u
    WHERE EXISTS (SELECT 1 FROM roles r WHERE r.rid = "id" AND "password" <> '');
CREATE VIEW v_plain AS SELECT full_name FROM customers WHERE ssn IS NOT NULL;
"""


def test_r6_a_double_quoted_password_literal_equal_to_another_tables_name_is_withheld(tmp_path: Path) -> None:
    server, _app = _sqlite_views(tmp_path, _R6_DDL)
    defs = _view_defs(server)
    for name in ("v_guest", "v_admin", "v_outer"):
        assert defs[name] is None, (name, defs[name])
        assert _get_def(server, name) is None, name
    # names in scope stay names: the definitions are shown, by both tools
    for name in ("v_named", "v_alias", "v_plain"):
        assert defs[name] is not None, (name, defs)
        assert _get_def(server, name) == defs[name], name
    # 'password' <> '' beside the sensitive name is a literal either way
    assert defs["v_corr"] is None and _get_def(server, "v_corr") is None


def test_r6_db_list_views_never_lists_every_column_of_the_schema(tmp_path: Path) -> None:
    from universal_db_mcp.connectors.sqlite import SQLiteConnector

    server, _app = _sqlite_views(tmp_path, _R6_DDL)
    calls: list[tuple[str, Any]] = []
    original = SQLiteConnector.list_columns

    def all_columns(self: Any, schema: Any) -> Any:
        raise AssertionError("db_list_views listed every column of the schema")

    def columns(self: Any, schema: Any, table: str) -> Any:
        calls.append((schema, table))
        return original(self, schema, table)

    mp = pytest.MonkeyPatch()
    mp.setattr(SQLiteConnector, "list_all_columns", all_columns)
    mp.setattr(SQLiteConnector, "list_columns", columns)
    try:
        defs = _view_defs(server)
    finally:
        mp.undo()
    assert defs["v_named"] is not None
    # one listing per distinct table the quoted definitions read
    assert len(calls) == len(set(calls)) <= 4, calls


# ------------- M2 class: a qualifier binds to a FROM item, never a spare CTE


@pytest.mark.parametrize(
    ("engine", "sql"),
    [
        ("postgres", "WITH w AS (SELECT 1 AS k) SELECT (SELECT w.k) AS out FROM (SELECT ssn FROM customers) w(k)"),
        ("postgres", "WITH w AS (SELECT 1 AS k) SELECT x.out FROM (SELECT ssn FROM customers) w(k), "
                     "LATERAL (SELECT w.k AS out) x"),
        ("mysql", "WITH w AS (SELECT 1 AS k), t(k) AS (SELECT ssn FROM customers) SELECT (SELECT w.k) AS out "
                  "FROM t AS w"),
        ("mysql", "WITH w AS (SELECT 1 AS k) SELECT (SELECT w.k) AS out FROM (SELECT ssn AS k FROM customers) AS w"),
        ("sqlite", "WITH w AS (SELECT 1 AS k), t(k) AS (SELECT ssn FROM customers) SELECT (SELECT w.k) AS out "
                   "FROM t AS w"),
        ("sqlite", "WITH w AS (SELECT 1 AS k) SELECT (SELECT w.k) AS out FROM (SELECT ssn AS k FROM customers) AS w"),
        # the spare CTE in the subquery's own WITH is not a FROM item either
        ("postgres", "SELECT (WITH w AS (SELECT 1 AS k) SELECT w.k) AS out FROM (SELECT ssn AS k FROM customers) w"),
    ],
)
def test_m2_a_correlated_qualifier_never_binds_to_an_unused_cte(demo_policy: Any, engine: str, sql: str) -> None:
    assert _final_mask(_on(demo_policy, engine), sql, ["out"]) == {0}


@pytest.mark.parametrize(
    ("engine", "sql"),
    [
        ("postgres", "WITH w AS (SELECT ssn AS k FROM customers) SELECT (SELECT 1 FROM w x WHERE x.k IS NULL) AS out "
                     "FROM customers c"),
        ("postgres", "WITH w AS (SELECT full_name AS k FROM customers) SELECT w.k AS out FROM w"),
        ("sqlite", "WITH w AS (SELECT full_name AS k FROM customers) SELECT (SELECT w.k) AS out FROM w"),
    ],
)
def test_m2_a_cte_in_a_from_still_binds(demo_policy: Any, engine: str, sql: str) -> None:
    masked = _final_mask(_on(demo_policy, engine), sql, ["out"])
    assert masked == ({0} if "ssn" in sql else set()), masked


# ------------------------- P2 class: aliases SQLite renames in a subquery


@pytest.mark.parametrize(
    "sql",
    [
        'SELECT q."x:1" AS y FROM (SELECT full_name AS x, ssn AS x, email AS "x:1" FROM customers) q',
        'SELECT "x:1" AS y FROM (SELECT full_name AS x, ssn AS x, email AS "x:1" FROM customers) q',
        'SELECT column1 AS y FROM (SELECT ssn AS "true", c.* FROM customers c) q',
        'SELECT q.column1 AS y FROM (SELECT ssn AS "true", c.* FROM customers c) q',
        'SELECT q.column1 AS y FROM (SELECT ssn AS "false", full_name AS column1 FROM customers c) q',
        'SELECT column2 AS y FROM (SELECT full_name AS "column2", ssn AS "TRUE" FROM customers) q',
        'WITH t("true", n) AS (SELECT ssn, full_name FROM customers) SELECT column1 AS y FROM t',
    ],
)
def test_p2_aliases_sqlite_renames_end_to_end(tmp_path: Path, sql: str) -> None:
    server, _app = _server(tmp_path)
    env = _call(server, "db_query", {"connection_id": "shop", "sql": sql})
    assert env["data"]["rows"], env
    _no_secret(env["data"])


def test_p2_ordinary_sqlite_aliases_stay_exact(demo_policy: Any) -> None:
    policy = _on(demo_policy, "sqlite")
    sql = "SELECT q.n, q.s FROM (SELECT full_name AS n, ssn AS s FROM customers) q"
    assert _final_mask(policy, sql, ["n", "s"]) == {1}
    # at the top level SQLite reports the alias as written
    assert _final_mask(policy, 'SELECT full_name AS "true", ssn AS s FROM customers', ["true", "s"]) == {1}


# ------------------- federated: each statement gets the names it uses


def test_federated_parameters_are_filtered_per_statement() -> None:
    params = {"region": "eu", "since": "2026-01-01"}
    assert srv._statement_parameters("SELECT :region AS region", "postgres", params) == {"region": "eu"}
    assert srv._statement_parameters("SELECT %(region)s AS region", "clickhouse", params) == {"region": "eu"}
    assert srv._statement_parameters("SELECT :region AS r, :since AS s", "mysql", params) == params
    # a name inside a literal or a comment is text, not a placeholder
    assert srv._statement_parameters("SELECT ':since' AS s, :region AS r -- :since", "postgres", params) == {
        "region": "eu"
    }
    # a statement naming none gets no mapping; a positional list is passed whole
    assert srv._statement_parameters("SELECT 1", "mysql", params) is None
    assert srv._statement_parameters("SELECT %s", "mysql", ["x"]) == ["x"]
    assert srv._statement_parameters("SELECT 1", "mysql", None) is None
    # PostgreSQL's cast and an array slice name no parameter
    assert srv._statement_parameters("SELECT a::date, b[1:since] FROM t WHERE r = :region", "postgres", params) == {
        "region": "eu"
    }


def _live_three(tmp_path: Path) -> Any:
    import os
    import socket

    from test_cr_fix_server import REPO

    from universal_db_mcp.config import load_resolved
    from universal_db_mcp.server import AppContext, build_server

    secrets = REPO / "out" / "mockdb-secrets"
    for port in (5433, 3307, 8124):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                pass
        except OSError:
            pytest.skip(f"the loopback fixture on 127.0.0.1:{port} is not running")
    for name in ("pg.pw", "mysql.pw", "clickhouse.pw"):
        if not (secrets / name).is_file():
            pytest.skip(f"the fixture's {name} is not there")
    os.environ.setdefault("UDBMCP_DEMO_PG_USER", "udbmcp_ro")
    os.environ.setdefault("UDBMCP_DEMO_MYSQL_USER", "udbmcp_ro")
    os.environ.setdefault("UDBMCP_DEMO_CH_USER", "default")
    conns = ""
    for cid, engine, port, db, user, pw in (
        ("pg", "postgres", 5433, "postgres", "UDBMCP_DEMO_PG_USER", "pg.pw"),
        ("mysql", "mysql", 3307, "testdb", "UDBMCP_DEMO_MYSQL_USER", "mysql.pw"),
        ("ch", "clickhouse", 8124, "default", "UDBMCP_DEMO_CH_USER", "clickhouse.pw"),
    ):
        conns += (
            f"  {cid}:\n    type: {engine}\n    host: 127.0.0.1\n    port: {port}\n    database: {db}\n"
            f"    username_env: {user}\n    password_file: {secrets / pw}\n    read_only: true\n"
        )
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "application:\n  transport: stdio\n"
        f"  audit_path: {tmp_path / 'audit.jsonl'}\n  metadata_cache_path: {tmp_path / 'cache.sqlite'}\n"
        "security:\n  require_remote_tls: false\n"
        f"connections:\n{conns}",
        encoding="utf-8",
    )
    app_cfg, resolved = load_resolved(cfg)
    return build_server(AppContext(app_cfg, resolved))


def test_federated_named_parameters_live(tmp_path: Path) -> None:
    server = _live_three(tmp_path)
    env = _call(server, "db_federated_query", {
        "queries": {
            "pg": "SELECT :region AS region",
            "mysql": "SELECT :region AS region, :since AS since",
            "ch": "SELECT %(region)s AS region",
        },
        "parameters": {"region": "eu", "since": "2026-01-01"},
    })
    results = {r["connection"]: r for r in env["data"]["results"]}
    assert all("error" not in r for r in results.values()), env
    assert results["pg"]["rows"] == [["eu"]] and results["ch"]["rows"] == [["eu"]], env
    assert results["mysql"]["rows"] == [["eu", "2026-01-01"]], env
    # a name no statement uses is still the caller's mistake, refused before any I/O
    with pytest.raises(Exception, match=r"VALIDATION.*'typo'"):
        _call(server, "db_federated_query", {
            "queries": {"pg": "SELECT :region AS region"}, "parameters": {"region": "eu", "typo": 1},
        })
    # the same statement on every connection keeps the shared mapping
    env = _call(server, "db_federated_query", {
        "sql": "SELECT :region AS region", "connections": ["pg", "mysql"], "parameters": {"region": "eu"},
    })
    assert [r["rows"] for r in env["data"]["results"]] == [[["eu"]], [["eu"]]], env


# ----------------------------- catalog work of the discovery tools (V8, SW-2)


def _uncached_sqlite(tmp_path: Path, names: tuple[str, ...] = ("shop",)) -> Any:
    from test_cr_fix_server import _seed

    from universal_db_mcp.config import load_resolved
    from universal_db_mcp.server import AppContext, build_server

    conns = ""
    for name in names:
        db = tmp_path / f"{name}.db"
        _seed(db)
        conns += f"  {name}:\n    type: sqlite\n    database: {db}\n    allowed_schemas: [main]\n"
    cfg = tmp_path / "config.yaml"
    # no metadata_cache_path: every listing reads the live catalog
    cfg.write_text(
        f"application:\n  transport: stdio\n  audit_path: {tmp_path / 'audit.jsonl'}\n"
        f"connections:\n{conns}",
        encoding="utf-8",
    )
    app_cfg, resolved = load_resolved(cfg)
    app = AppContext(app_cfg, resolved)
    return build_server(app), app


def _count_listings(mp: Any) -> list[Any]:
    from universal_db_mcp.connectors.sqlite import SQLiteConnector

    calls: list[Any] = []
    original = SQLiteConnector.list_tables

    def list_tables(self: Any, *args: Any) -> Any:
        if args[0] is None:  # the whole catalog (AppContext.tables_for); per-schema reads are the connector's
            calls.append(args)
        return original(self, *args)

    mp.setattr(SQLiteConnector, "list_tables", list_tables)
    return calls


@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("db_infer_relationships", {}),
        ("db_get_catalog", {"connection_id": "shop"}),
        ("db_review_schema", {"connection_id": "shop", "schema": "main"}),
        ("db_list_views", {"connection_id": "shop", "schema": "main"}),
    ],
)
def test_one_catalog_listing_per_call_without_the_metadata_cache(
    tmp_path: Path, monkeypatch: Any, tool: str, args: dict[str, Any]
) -> None:
    server, _app = _uncached_sqlite(tmp_path)
    calls = _count_listings(monkeypatch)
    _call(server, tool, args)
    assert len(calls) <= 1, calls
    calls.clear()
    _call(server, tool, args)  # the next call lists again: nothing is kept between calls
    assert len(calls) <= 1, calls


def test_infer_relationships_one_failing_connection_does_not_end_the_call(
    tmp_path: Path, monkeypatch: Any
) -> None:
    server, app = _uncached_sqlite(tmp_path, ("shop", "broken"))
    original = srv._schema_view

    async def schema_view(app_: Any, connector: Any, policy: Any, *a: Any, **kw: Any) -> Any:
        if policy.connection_id == "broken":
            raise RuntimeError("catalog unavailable")
        return await original(app_, connector, policy, *a, **kw)

    monkeypatch.setattr(srv, "_schema_view", schema_view)
    env = _call(server, "db_infer_relationships", {})
    assert env["data"]["tables_considered"] >= 1, env
    assert any("broken" in w for w in env["warnings"]), env


def test_readable_filter_of_a_long_listing_runs_off_the_event_loop(demo_policy: Any, monkeypatch: Any) -> None:
    import asyncio
    import threading
    from types import SimpleNamespace

    seen: set[str] = set()
    original = srv._readable

    def readable(policy: Any, table: Any) -> bool:
        seen.add(threading.current_thread().name)
        return original(policy, table)

    monkeypatch.setattr(srv, "_readable", readable)
    tables = [SimpleNamespace(schema="main", name=f"t{i}", kind="table") for i in range(2000)]
    main = threading.current_thread().name
    out = asyncio.run(srv._readable_tables(demo_policy, tables))
    assert [t.name for t in out] == [t.name for t in tables]
    assert main not in seen, seen
    seen.clear()
    asyncio.run(srv._readable_tables(demo_policy, tables[:10]))
    assert seen == {main}


def test_a_postgres_alias_cut_to_63_bytes_keeps_the_layout(demo_policy: Any) -> None:
    alias = "a" * 70
    sql = f"SELECT c.*, 1 AS {alias} FROM customers c"
    masked = _final_mask(_on(demo_policy, "postgres"), sql, [*CUSTOMERS, "a" * 63])
    assert masked == {3}, masked
    # a name that is not the alias, cut or not, still fails closed
    masked = _final_mask(_on(demo_policy, "postgres"), sql, [*CUSTOMERS, "b" * 63])
    assert masked == set(range(7)), masked


@pytest.mark.parametrize(
    ("sql", "columns", "leaking"),
    [
        ("SELECT * FROM (customers r CROSS JOIN (SELECT ssn FROM customers) b(j)) x", [*CUSTOMERS, "j"], 6),
        ("SELECT x.* FROM (customers r CROSS JOIN (SELECT ssn FROM customers) b(j)) x", [*CUSTOMERS, "j"], 6),
        ("SELECT x.j FROM (customers r CROSS JOIN (SELECT ssn FROM customers) b(j)) x", ["j"], 0),
        ("SELECT * FROM (customers r JOIN (SELECT ssn AS customer_id FROM customers) b USING (customer_id)) x",
         CUSTOMERS, 0),
    ],
)
def test_v11e_a_parenthesized_join_keeps_its_joined_columns(
    demo_policy: Any, sql: str, columns: list[str], leaking: int
) -> None:
    assert leaking in _final_mask(_on(demo_policy, "postgres"), sql, columns)
