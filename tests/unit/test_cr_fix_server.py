"""Regressions for the /code-review findings fixed in server.py and discovery
(2026-10-02): positional masking (M1-M4, P1-P4, R4, R5), DDL literal
withholding (S3, R6), dictionary reads in the discovery tools (S4), object
names with an empty qualifier (S2), the federated join's key list (X6),
namesake schemas (X7/R1), the connectors' own diagnostics (T3) and
relationship inference (A8).

The masking tests go through build_server / db_query where an engine runs
in-process (SQLite) or on the loopback PostgreSQL fixture (127.0.0.1:5433,
skipped where it is not running); the others drive the positional analysis
directly with the engine's dialect, as the server does after the statement
ran."""

from __future__ import annotations

import asyncio
import dataclasses
import json
import os
import re
import socket
import sqlite3
from pathlib import Path
from typing import Any

import pytest
import sqlglot

from universal_db_mcp import server as srv
from universal_db_mcp.config import load_resolved
from universal_db_mcp.connectors.base import ColumnInfo, ConnectorError, IndexInfo, KeyInfo
from universal_db_mcp.discovery.inference import TableFacts, TableRef, infer_relationships
from universal_db_mcp.errors import ToolFailure
from universal_db_mcp.security.sql_guard import sqlglot_dialect
from universal_db_mcp.server import AppContext, build_server

SECRETS = ("999-90-1111", "999-90-2222", "999-90-3333")
REPO = Path(__file__).resolve().parents[2]


def _seed(db: Path) -> None:
    c = sqlite3.connect(db)
    c.executescript(
        """
        CREATE TABLE customers (
            customer_id INTEGER PRIMARY KEY, full_name TEXT, email TEXT, ssn TEXT);
        """
    )
    c.executemany(
        "INSERT INTO customers VALUES (?,?,?,?)",
        [(i + 1, f"User {i}", f"u{i}@example.invalid", s) for i, s in enumerate(SECRETS)],
    )
    c.commit()
    c.close()


def _server(tmp_path: Path, security: str = "") -> tuple[Any, AppContext]:
    db = tmp_path / "shop.db"
    _seed(db)
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "application:\n  transport: stdio\n"
        f"  audit_path: {tmp_path / 'audit.jsonl'}\n"
        f"  metadata_cache_path: {tmp_path / 'cache.sqlite'}\n"
        f"security:\n  max_concurrent_queries: 4\n{security}"
        f"connections:\n  shop:\n    type: sqlite\n    database: {db}\n",
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


def _no_secret(payload: Any, secrets: tuple[str, ...] = SECRETS) -> None:
    text = json.dumps(payload, default=str)
    for secret in secrets:
        assert secret not in text, (secret, text[:800])


def _final_mask(policy: Any, sql: str, columns: list[str], table_columns: Any = None) -> set[int]:
    """The columns db_query masks for ``sql`` on ``policy``'s engine, given
    the names the driver reported: the traced positions plus the name
    heuristics, exactly as the tool combines them."""
    ast = sqlglot.parse_one(sql, read=sqlglot_dialect(policy.engine))
    cols = [(c, "t") for c in columns]
    positions = srv._query_mask_positions(policy, ast, cols, [], table_columns)
    names = srv._sensitive_output_names(policy, ast)
    return srv._mask_columns(policy, cols, names, positions)


def _on(policy: Any, engine: str) -> Any:
    return dataclasses.replace(policy, engine=engine)


CUSTOMERS = ["customer_id", "full_name", "email", "ssn", "country", "created_at"]


# --------------------------------------------- M1: PostgreSQL (expr).* widths


@pytest.mark.parametrize(
    ("sql", "columns", "leaking"),
    [
        # the composite expansion is six columns, not one: upper(ssn) sits at 6
        (
            "SELECT (CAST('(1,a,b,c,d,e)' AS customers)).*, upper(c.ssn), c.* FROM customers c",
            [*CUSTOMERS, "upper", *CUSTOMERS],
            6,
        ),
        # the SSN is spliced into the composite's second field (full_name, at 7)
        (
            "SELECT c.*, (CAST('(1,' || c.ssn || ',,,,)' AS customers)).* FROM customers c",
            [*CUSTOMERS, *CUSTOMERS],
            7,
        ),
        ("SELECT a.*, (q).* FROM accounts a, (SELECT ssn, ssn FROM customers) AS q(x, y)", ["id", "x", "y"], 1),
        ("SELECT (q).*, upper(c.ssn) FROM customers c, (SELECT 1 AS k, 2 AS j) q", ["k", "j", "upper"], 2),
    ],
)
def test_m1_a_composite_expansion_is_a_run_of_columns(
    demo_policy: Any, sql: str, columns: list[str], leaking: int
) -> None:
    assert leaking in _final_mask(_on(demo_policy, "postgres"), sql, columns)


def test_m1_a_width_the_trace_does_not_explain_never_shifts_a_mask(demo_policy: Any) -> None:
    """Whatever expands to more columns than the trace counted, a named
    output the trace placed must sit where the driver reports its name:
    otherwise the layout is wrong and every unproven column is masked."""
    policy = _on(demo_policy, "postgres")
    # f(1) stands for any construct the walk counts as one column and the
    # engine expands into two; to_json(c) carries the SSN under a name no
    # pattern matches, so only its position protects it
    sql = "SELECT f(1) AS w, to_json(c) AS u, c.* FROM customers c"
    columns = ["w", "w2", "u", *CUSTOMERS]
    assert 2 in _final_mask(policy, sql, columns)


# ------------------------------------- M2: aliases that differ only in case


@pytest.mark.parametrize(
    ("engine", "sql", "columns"),
    [
        ("postgres", 'SELECT "A".k FROM (SELECT 1 AS k) a, (SELECT ssn FROM customers) "A"(k)', ["k"]),
        ("postgres", 'SELECT "A".* FROM (SELECT 1 AS k) a, (SELECT ssn FROM customers) "A"(k)', ["k"]),
        ("postgres", 'SELECT to_json("A".*) FROM (SELECT 1 AS k) a, (SELECT ssn FROM customers) "A"(k)', ["to_json"]),
        (
            "postgres",
            'SELECT "A".k FROM (SELECT 1 AS k) a, (SELECT ssn FROM customers) "A"(k) UNION ALL SELECT 1',
            ["k"],
        ),
        # a correlated reference to the outer "A" from a scope that has its own a
        (
            "postgres",
            'SELECT (SELECT "A".k FROM (SELECT 1 AS k) a) FROM (SELECT ssn FROM customers) "A"(k)',
            ["k"],
        ),
        ("mysql", "SELECT `A`.k FROM (SELECT 1 AS k) a, (SELECT ssn AS k FROM customers) `A`", ["k"]),
        ("clickhouse", "SELECT A.k FROM (SELECT 1 AS k) AS a, (SELECT ssn AS k FROM customers) AS A", ["k"]),
    ],
)
def test_m2_case_variant_aliases_never_resolve_to_the_clean_source(
    demo_policy: Any, engine: str, sql: str, columns: list[str]
) -> None:
    assert _final_mask(_on(demo_policy, engine), sql, columns) == set(range(len(columns)))


def test_m2_a_reference_spelled_as_its_alias_folds_stays_clean(demo_policy: Any) -> None:
    """PostgreSQL folds the unquoted C to c: no over-masking of the
    everyday spelling."""
    policy = _on(demo_policy, "postgres")
    sql = "SELECT C.full_name FROM customers c"
    assert _final_mask(policy, sql, ["full_name"]) == set()
    sql = "SELECT Q.x FROM (SELECT full_name AS x, ssn FROM customers) q"
    assert _final_mask(policy, sql, ["x"]) == set()


# ------------------------- M3 / R5: attribute notation over a row function


def test_m3_a_row_function_over_a_star_mixing_a_table_with_another_run(demo_policy: Any) -> None:
    policy = _on(demo_policy, "postgres")
    sql = "SELECT x.row_text FROM (SELECT * FROM customers, unnest(ARRAY[1]) u) x"
    ast = sqlglot.parse_one(sql, read="postgres")
    known = {id(t): frozenset(CUSTOMERS) for t in ast.find_all(sqlglot.exp.Table) if t.name == "customers"}
    positions = srv._query_mask_positions(policy, ast, [("row_text", "t")], [], known)
    assert positions == {0}


def test_r5_a_decoy_cte_whose_name_postgres_folds_away_leaves_the_table_a_table(
    demo_policy: Any, tmp_path: Path
) -> None:
    """WITH "CUSTOMERS" ... FROM CUSTOMERS x reads the table customers (the
    unquoted name folds): its catalog columns are looked up, so x.row_text is
    known to be no column of it - a function of the whole row."""
    policy = _on(demo_policy, "postgres")
    sql = 'WITH "CUSTOMERS" AS (SELECT 1 AS k) SELECT x.row_text FROM CUSTOMERS x'
    ast = sqlglot.parse_one(sql, read="postgres")

    class _App:
        row_columns: dict[Any, Any] = {}

        async def tables_for(self, _policy: Any, _connector: Any) -> list[Any]:
            return [type("T", (), {"schema": "public", "name": "customers"})()]

    async def fake_meta(_app: Any, _cid: str, _fn: Any) -> list[Any]:
        return [ColumnInfo(name=n, data_type="text", nullable=True) for n in CUSTOMERS]

    original = srv.run_meta
    srv.run_meta = fake_meta  # type: ignore[assignment]
    try:
        warnings: list[str] = []
        known = asyncio.run(srv._row_function_columns(_App(), None, policy, ast, warnings))  # type: ignore[arg-type]
    finally:
        srv.run_meta = original  # type: ignore[assignment]
    assert known, "the folded FROM item names the table: its columns are read"
    assert srv._query_mask_positions(policy, ast, [("row_text", "t")], [], known) == {0}


def test_r4_postgres_folds_only_ascii_letters(demo_policy: Any) -> None:
    """PostgreSQL (UTF-8) folds an unquoted name's ASCII letters only: Ä
    stays Ä, so a column named "Äb" is the unquoted Äb, and a column "äb"
    is not - x.Äb over a table listing only äb is a function of the row."""
    assert srv._pg_identifier(sqlglot.exp.Identifier(this="ÄB", quoted=False)) == "Äb"
    policy = _on(demo_policy, "postgres")
    sql = "SELECT x.ÄB FROM customers x"
    ast = sqlglot.parse_one(sql, read="postgres")
    known = {id(t): frozenset([*CUSTOMERS, "äb"]) for t in ast.find_all(sqlglot.exp.Table)}
    assert srv._query_mask_positions(policy, ast, [("äb", "t")], [], known) == {0}


# ------------------------------------------------------ P1: PIVOT / UNPIVOT


@pytest.mark.parametrize(
    ("engine", "sql", "columns"),
    [
        ("mssql", "SELECT p.QA FROM dbo.customers PIVOT (MAX(ssn) FOR country IN ([QA])) AS p", ["QA"]),
        ("mssql", "SELECT u.val FROM dbo.customers UNPIVOT (val FOR col IN (full_name, ssn)) AS u", ["val"]),
        ("oracle", "SELECT p.x FROM customers PIVOT (MAX(ssn) FOR country IN ('QA' AS x)) p", ["X"]),
        ("oracle", "SELECT u.val FROM customers UNPIVOT (val FOR col IN (full_name, ssn)) u", ["VAL"]),
    ],
)
def test_p1_a_column_qualified_by_a_pivot_alias_is_never_traced_clean(
    demo_policy: Any, engine: str, sql: str, columns: list[str]
) -> None:
    assert _final_mask(_on(demo_policy, engine), sql, columns) == {0}


# ---------------------------------------- P2: SQLite's engine-made names


@pytest.mark.parametrize(
    "sql",
    [
        'SELECT "x:1" AS y FROM (SELECT full_name AS x, ssn AS x FROM customers) q',
        'SELECT q."x:1" AS y FROM (SELECT full_name AS x, ssn AS x FROM customers) q',
        'SELECT "upper(x)" AS y FROM (SELECT upper(x), full_name AS "upper(x)" FROM '
        "(SELECT ssn AS x, full_name FROM customers) a) b",
        'SELECT b."upper(x)" AS y FROM (SELECT upper(x), full_name AS "upper(x)" FROM '
        "(SELECT ssn AS x, full_name FROM customers) a) b",
        'SELECT "full_name:1" AS y FROM (SELECT a.full_name, b.ssn AS full_name FROM customers a, customers b) q',
        'SELECT x AS y FROM (SELECT (x), full_name AS x FROM (SELECT ssn AS x, full_name FROM customers) a) b',
    ],
)
def test_p2_sqlite_engine_made_names_end_to_end(tmp_path: Path, sql: str) -> None:
    server, _app = _server(tmp_path)
    env = _call(server, "db_query", {"connection_id": "shop", "sql": sql})
    assert env["data"]["rows"], env
    _no_secret(env["data"])


def test_p2_plain_derived_table_names_stay_readable(tmp_path: Path) -> None:
    server, _app = _server(tmp_path)
    env = _call(
        server, "db_query",
        {"connection_id": "shop", "sql": "SELECT n FROM (SELECT full_name AS n, upper(ssn) FROM customers) q"},
    )
    assert env["data"]["rows"][0] == ["User 0"], env


# ------------------------------------------- P3: Oracle MATCH_RECOGNIZE


@pytest.mark.parametrize(
    ("sql", "columns"),
    [
        (
            "SELECT * FROM customers MATCH_RECOGNIZE (PARTITION BY country ORDER BY customer_id "
            "MEASURES FIRST(ssn) AS x ONE ROW PER MATCH PATTERN (a) DEFINE a AS 1 = 1)",
            ["COUNTRY", "X"],
        ),
        (
            "SELECT m.x FROM customers MATCH_RECOGNIZE (PARTITION BY country ORDER BY customer_id "
            "MEASURES FIRST(ssn) AS x ONE ROW PER MATCH PATTERN (a) DEFINE a AS 1 = 1) m",
            ["X"],
        ),
        (
            "SELECT x FROM customers MATCH_RECOGNIZE (PARTITION BY country ORDER BY customer_id "
            "MEASURES FIRST(ssn) AS x ONE ROW PER MATCH PATTERN (a) DEFINE a AS 1 = 1)",
            ["X"],
        ),
    ],
)
def test_p3_match_recognize_measures_are_masked(demo_policy: Any, sql: str, columns: list[str]) -> None:
    mask = _final_mask(_on(demo_policy, "oracle"), sql, columns)
    assert len(columns) - 1 in mask


# ------------------------------------------ P4: PostgreSQL SEARCH / CYCLE


@pytest.mark.parametrize(
    ("sql", "columns"),
    [
        (
            "WITH RECURSIVE t(a) AS (SELECT ssn FROM customers UNION ALL SELECT a FROM t) "
            "CYCLE a SET is_cycle USING path SELECT path FROM t",
            ["path"],
        ),
        (
            "WITH RECURSIVE t(a) AS (SELECT ssn FROM customers UNION ALL SELECT a FROM t) "
            "SEARCH DEPTH FIRST BY a SET ord SELECT ord FROM t",
            ["ord"],
        ),
    ],
)
def test_p4_search_and_cycle_columns_are_masked(demo_policy: Any, sql: str, columns: list[str]) -> None:
    assert _final_mask(_on(demo_policy, "postgres"), sql, columns) == {0}


# ------------------------------------- live PostgreSQL (loopback fixture)


def _pg_live(tmp_path: Path) -> Any:
    secret = REPO / "out" / "mockdb-secrets" / "pg.pw"
    try:
        with socket.create_connection(("127.0.0.1", 5433), timeout=1):
            pass
    except OSError:
        pytest.skip("the loopback PostgreSQL fixture (127.0.0.1:5433) is not running")
    if not secret.is_file():
        pytest.skip("the PostgreSQL fixture's password file is not there")
    os.environ.setdefault("UDBMCP_DEMO_PG_USER", "udbmcp_ro")
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "application:\n  transport: stdio\n"
        f"  audit_path: {tmp_path / 'audit.jsonl'}\n"
        f"  metadata_cache_path: {tmp_path / 'cache.sqlite'}\n"
        "security:\n  max_concurrent_queries: 4\n  require_remote_tls: false\n"
        "  default_deny_objects: true\n  allowed_system_schemas: [information_schema]\n"
        "  mask_columns: ['(?i)^callsign$']\n"
        "connections:\n  pg:\n    type: postgres\n    host: 127.0.0.1\n    port: 5433\n"
        "    database: postgres\n    username_env: UDBMCP_DEMO_PG_USER\n"
        f"    password_file: {secret}\n    read_only: true\n",
        encoding="utf-8",
    )
    app_cfg, resolved = load_resolved(cfg)
    return build_server(AppContext(app_cfg, resolved))


def _callsigns(tmp_path: Path) -> tuple[Any, tuple[str, ...]]:
    """The live server and the fixture's callsigns, read with masking off."""
    import psycopg

    secret = (REPO / "out" / "mockdb-secrets" / "pg.pw").read_text(encoding="utf-8").strip()
    with psycopg.connect(
        host="127.0.0.1", port=5433, dbname="postgres", user=os.environ.get("UDBMCP_DEMO_PG_USER", "udbmcp_ro"),
        password=secret,
    ) as conn:
        values = tuple(str(r[0]) for r in conn.execute("SELECT callsign FROM ocean.buoys").fetchall())
    assert values
    return conn, values


@pytest.mark.parametrize(
    "sql",
    [
        # M1: the composite is two columns; upper(callsign) sits at 2
        "SELECT (q).*, upper(b.callsign), b.* FROM ocean.buoys b, (SELECT 1 AS k, 2 AS j) q",
        # M2: "A" is the callsign source, a the clean one
        'SELECT "A".k FROM (SELECT 1 AS k) a, (SELECT callsign FROM ocean.buoys) "A"(k)',
        # P4: CYCLE's path carries the callsign
        "WITH RECURSIVE t(a) AS (SELECT callsign FROM ocean.buoys UNION ALL SELECT a FROM t WHERE false) "
        "CYCLE a SET is_cycle USING path SELECT path FROM t",
        "WITH RECURSIVE t(a) AS (SELECT callsign FROM ocean.buoys UNION ALL SELECT a FROM t WHERE false) "
        "SEARCH DEPTH FIRST BY a SET ord SELECT ord FROM t",
    ],
)
def test_live_postgres_masking(tmp_path: Path, sql: str) -> None:
    server = _pg_live(tmp_path)
    _conn, callsigns = _callsigns(tmp_path)
    env = _call(server, "db_query", {"connection_id": "pg", "sql": sql})
    assert env["data"]["rows"], env
    _no_secret(env["data"], callsigns)


# ----------------------------------- S3 / R6: DDL literals beside a name


def _policy_for(demo_policy: Any, engine: str, pattern: str = r"(?i)password") -> Any:
    return dataclasses.replace(demo_policy, engine=engine, sensitive_patterns=[re.compile(pattern)])


@pytest.mark.parametrize(
    ("engine", "definition"),
    [
        # an apostrophe in a quoted name opened a "literal" that swallowed the real one
        ("postgres", "SELECT u.id AS \"user's id\" FROM users u WHERE u.password = 'hunter2'"),
        ("postgres", "SELECT u.id FROM users u WHERE u.note <> 'it''s' AND u.password = 'hunter2'"),
        # MySQL prints an embedded quote as \' in information_schema.views
        ("mysql", "select `u`.`id` AS `id` from `shop`.`users` `u` where ((`u`.`note` <> 'it\\'s') "
                  "and (`u`.`password` = 'hunter2'))"),
        ("mysql", "select `o'k` AS `x` from `users` where (`password` = 'hunter2')"),
        # a comment's apostrophe
        ("postgres", "SELECT id FROM users -- it's here\nWHERE password = 'hunter2'"),
        ("postgres", "SELECT id FROM users /* it's */ WHERE password = 'hunter2'"),
        ("mssql", "CREATE VIEW v AS SELECT [o'k] FROM users WHERE password = 'hunter2'"),
        ("sqlite", "CREATE VIEW v AS SELECT [o'k] FROM users WHERE password = 'hunter2'"),
        # a partial index whose name holds an apostrophe
        ("postgres", "CREATE INDEX \"o'k_idx\" ON public.users USING btree (id) WHERE (password = 'changeme'::text)"),
        # PostgreSQL's E'' string and a dollar-quoted literal
        ("postgres", "SELECT id FROM users WHERE note <> E'it\\'s' AND password = 'x'"),
        ("postgres", "SELECT id FROM users WHERE password = $q$it's$q$"),
        # a text no reading can finish is withheld where it names a sensitive word
        ("postgres", "SELECT id FROM users WHERE password = 'unterminated"),
    ],
)
def test_s3_a_literal_beside_a_sensitive_name_is_found_whatever_quotes_precede_it(
    demo_policy: Any, engine: str, definition: str
) -> None:
    assert srv._literal_beside_sensitive(_policy_for(demo_policy, engine), definition, ["v"])


@pytest.mark.parametrize(
    ("engine", "definition"),
    [
        ("postgres", "SELECT u.id AS \"user's id\" FROM users u WHERE u.kind = 'admin'"),
        ("postgres", "SELECT u.password_hash IS NULL AS no_password FROM users u"),
        ("mysql", "select `u`.`id` AS `id` from `users` `u` where (`u`.`note` <> 'it\\'s')"),
        # another column's DEFAULT literal in a table is harmless
        ("sqlite", "CREATE TABLE t (\"o'k\" TEXT DEFAULT 'x', password TEXT)"),
    ],
)
def test_s3_controls_stay_readable(demo_policy: Any, engine: str, definition: str) -> None:
    policy = _policy_for(demo_policy, engine, r"(?i)^password$")
    assert not srv._literal_beside_sensitive(policy, definition, ["v", "t", "o'k", "password"])


def test_s3_sqlite_table_ddl_with_an_apostrophe_in_a_name_end_to_end(tmp_path: Path) -> None:
    server, _app = _server(tmp_path)
    c = sqlite3.connect(tmp_path / "shop.db")
    c.execute("CREATE TABLE creds (id INTEGER PRIMARY KEY, [o'k] TEXT, "
              "password TEXT CHECK (password <> 'hunter2'))")
    c.commit()
    c.close()
    env = _call(server, "db_get_table", {"connection_id": "shop", "object_name": "creds"})
    assert "hunter2" not in json.dumps(env), env
    assert any("withheld" in w for w in env["warnings"]), env["warnings"]


def test_r6_a_sqlite_view_naming_columns_in_double_quotes_is_not_withheld(tmp_path: Path) -> None:
    server, _app = _server(tmp_path)
    c = sqlite3.connect(tmp_path / "shop.db")
    c.execute('CREATE VIEW v_named AS SELECT "full_name" FROM "customers" WHERE ssn IS NOT NULL')
    # a double-quoted word that names no column is a string to SQLite: a value
    c.execute('CREATE VIEW v_value AS SELECT full_name FROM customers WHERE ssn <> "999-90-1111"')
    c.commit()
    c.close()
    env = _call(server, "db_list_views", {"connection_id": "shop"})
    views = {v["name"]: v["definition"] for v in env["data"]["views"]}
    assert views["v_named"] is not None and '"full_name"' in views["v_named"], env
    assert views["v_value"] is None, env
    _no_secret(env)


# -------------------------- S4: listed dictionary objects the policy refuses


class _Caps:
    def get(self, _name: str) -> Any:
        from universal_db_mcp.models.capabilities import CapabilityState

        return CapabilityState.SUPPORTED


class _Fake:
    """A duck-typed remote connector over fixed catalog lists; it records
    every statement it is asked to run."""

    from universal_db_mcp.connectors.base import DatabaseConnector as _Base

    get_table = _Base.get_table
    synonym_chains = _Base.synonym_chains
    name_binding = _Base.name_binding

    def __init__(self, tables: list[Any], *, schemas: list[str], columns: list[Any] | None = None,
                 fks: list[Any] | None = None, views: list[Any] | None = None) -> None:
        self.tables, self.schemas = tables, schemas
        self.columns, self.fks, self.views = columns or [], fks or [], views or []
        self.statements: list[str] = []

    def capabilities(self) -> _Caps:
        return _Caps()

    def list_schemas(self, _catalog: str | None, _search: str | None) -> list[str]:
        return list(self.schemas)

    def list_tables(self, _schema: str | None, kinds: set[str], _search: str | None) -> list[Any]:
        return [t for t in self.tables if t.kind in kinds]

    def list_columns(self, schema: str | None, table: str) -> list[Any]:
        return [c for c in self.columns if c.table == table and c.schema == schema]

    def list_all_columns(self, schema: str | None) -> list[Any]:
        return [c for c in self.columns if c.schema == schema]

    def list_indexes(self, _schema: str | None, _table: str | None) -> list[Any]:
        return []

    def get_foreign_keys(self, schema: str | None, table: str | None) -> list[Any]:
        return [k for k in self.fks if k.source_schema == schema and (table is None or k.source_table == table)]

    def list_views(self, _schema: str | None) -> list[Any]:
        return list(self.views)

    def list_synonyms(self, _schema: str | None) -> list[Any]:
        return []

    def list_routines(self, _schema: str | None) -> list[Any]:
        return []

    def get_statistics(self, _schema: str | None, _name: str) -> dict[str, Any]:
        return {}

    def execute_query(self, spec: Any) -> Any:
        self.statements.append(spec.sql)
        raise AssertionError(f"no statement may run: {spec.sql}")


def _fake_server(tmp_path: Path, monkeypatch: Any, fake: Any, *, engine: str, allowed: list[str],
                 system: list[str]) -> Any:
    monkeypatch.setenv("UDBMCP_T_USER", "tester")
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "application:\n  transport: stdio\n"
        f"  audit_path: {tmp_path / 'audit.jsonl'}\n"
        f"  metadata_cache_path: {tmp_path / 'cache.sqlite'}\n"
        "security:\n  require_remote_tls: false\n  default_deny_objects: true\n"
        f"  allowed_system_schemas: {json.dumps(system)}\n"
        "connections:\n  remote:\n"
        f"    type: {engine}\n    host: 127.0.0.1\n    port: 5999\n    database: testdb\n"
        f"    username_env: UDBMCP_T_USER\n    allowed_schemas: {json.dumps(allowed)}\n",
        encoding="utf-8",
    )
    app_cfg, resolved = load_resolved(cfg)
    app = AppContext(app_cfg, resolved)
    app.connectors["remote"] = fake
    return build_server(app)


def _db2_dictionary(tmp_path: Path, monkeypatch: Any) -> tuple[Any, _Fake]:
    from universal_db_mcp.connectors.base import TableSummary

    fake = _Fake(
        [TableSummary("SYSIBM", "SYSCOLUMNS", "table", row_estimate=10)],
        schemas=["SYSIBM", "APP"],
        columns=[ColumnInfo("SYSIBM", "SYSCOLUMNS", "HIGH2KEY", "VARCHAR(254)"),
                 ColumnInfo("SYSIBM", "SYSCOLUMNS", "LOW2KEY", "VARCHAR(254)")],
    )
    server = _fake_server(tmp_path, monkeypatch, fake, engine="db2", allowed=["app"],
                          system=["information_schema", "sysibm"])
    return server, fake


def test_s4_value_search_never_reads_a_dictionary_table_the_policy_refuses(tmp_path: Path, monkeypatch: Any) -> None:
    server, fake = _db2_dictionary(tmp_path, monkeypatch)
    env = _call(server, "db_search_values", {"query": "a", "schemas": ["SYSIBM"], "include_system": True})
    assert fake.statements == [] and env["data"]["hits"] == [], env


def test_s4_schema_review_never_profiles_a_dictionary_table_the_policy_refuses(
    tmp_path: Path, monkeypatch: Any
) -> None:
    server, fake = _db2_dictionary(tmp_path, monkeypatch)
    env = _call(server, "db_review_schema",
                {"connection_id": "remote", "schema": "SYSIBM", "include_system": True, "include_top_values": True})
    assert fake.statements == [] and env["data"]["tables"] == [], env
    assert env["data"]["summary"]["tables_in_scope"] == 0, env


# ------------------------------------------- S2: an empty quoted qualifier


@pytest.mark.parametrize("name", ['"".ALL_USERS', "[].syslogins", "``.t", '"".customers', '""', "customers.\"\""])
def test_s2_an_empty_quoted_part_is_no_name(name: str) -> None:
    with pytest.raises(ToolFailure) as info:
        srv._split_qualified_name(None, name)
    assert "VALIDATION" in str(info.value), info.value


def test_s2_an_empty_quoted_qualifier_end_to_end(tmp_path: Path) -> None:
    server, _app = _server(tmp_path)
    text = _call_error(server, "db_sample_table", {"connection_id": "shop", "object_name": '"".customers'})
    assert "VALIDATION" in text, text
    assert _call(server, "db_sample_table", {"connection_id": "shop", "object_name": '"main".customers'})["data"]


# ------------------------- M4: an Oracle CTE name outside ASCII (server side)


@pytest.mark.parametrize(
    "sql",
    [
        'WITH "é" AS (SELECT 1 AS x FROM DUAL) SELECT * FROM é',
        'WITH "зарплаты" AS (SELECT 1 AS x FROM DUAL) SELECT * FROM зарплаты',
    ],
)
def test_m4_oracle_folds_a_non_ascii_name_by_unicode_rules(demo_policy: Any, sql: str) -> None:
    from types import SimpleNamespace

    from universal_db_mcp.security.sql_guard import SqlGuard

    policy = dataclasses.replace(demo_policy, engine="oracle", default_deny_objects=True)
    listed = srv._LiveResolver([SimpleNamespace(schema="HR", name="EMPLOYEES", kind="table")])
    with pytest.raises(ToolFailure):
        srv._validate_in_scope(SqlGuard("oracle", policy, listed), "oracle", lambda g: g.validate_select(sql))
    # a CTE the name binds to under every reading is still one
    ok = 'WITH "É" AS (SELECT 1 AS x FROM DUAL) SELECT * FROM é'
    srv._validate_in_scope(SqlGuard("oracle", policy, listed), "oracle", lambda g: g.validate_select(ok))


def test_m4_folding_is_one_character_for_one(demo_policy: Any) -> None:
    """Oracle folds é to É and keeps ß (no SS expansion); PostgreSQL and Db2
    bind a name to a CTE only where the ASCII and the Unicode readings agree."""
    assert srv._folded_name("oracle", sqlglot.exp.Identifier(this="straße_é", quoted=False)) == "STRAßE_É"
    assert srv._folded_name("oracle", sqlglot.exp.Identifier(this="é", quoted=True)) == "é"
    for engine, sql in (
        ("oracle", 'WITH "STRAßE" AS (SELECT 1 AS x FROM DUAL) SELECT * FROM straße'),
        ("postgres", "WITH straße AS (SELECT 1 AS x) SELECT * FROM straße"),
        ("db2", "WITH é AS (SELECT 1 AS x FROM SYSIBM.SYSDUMMY1) SELECT * FROM é"),
    ):
        ast = sqlglot.parse_one(sql, read=sqlglot_dialect(engine))
        assert srv._cte_hidden_tables(engine, ast) == [], (engine, sql)
    for engine, sql in (
        ("postgres", 'WITH "é" AS (SELECT 1 AS x) SELECT * FROM É'),
        ("db2", 'WITH "é" AS (SELECT 1 AS x FROM SYSIBM.SYSDUMMY1) SELECT * FROM é'),
        ("oracle", 'WITH "é" AS (SELECT 1 AS x FROM DUAL) SELECT * FROM é'),
    ):
        ast = sqlglot.parse_one(sql, read=sqlglot_dialect(engine))
        assert [t.name for t in srv._cte_hidden_tables(engine, ast)], (engine, sql)


def test_m4_the_taint_walk_does_not_trace_a_binding_the_readings_disagree_on(demo_policy: Any) -> None:
    """Db2 may fold é to É or keep it: the walk cannot tell the CTE from the
    table, so nothing of the result is traced as clean."""
    policy = _on(demo_policy, "db2")
    sql = 'WITH "é" AS (SELECT 1 AS x FROM SYSIBM.SYSDUMMY1) SELECT * FROM é'
    assert srv._output_items(policy, sqlglot.parse_one(sql, read="postgres")) is None
    # PostgreSQL keeps É on UTF-8 (a table) and folds it to é on LATIN1 (the CTE)
    sql = 'WITH "é" AS (SELECT 1 AS x) SELECT * FROM É'
    assert srv._output_items(_on(demo_policy, "postgres"), sqlglot.parse_one(sql, read="postgres")) is None


# ------------------------------------------- X6: the federated join's keys


def test_x6_the_key_list_is_bounded_before_any_read(tmp_path: Path, monkeypatch: Any) -> None:
    server, _app = _server(tmp_path)
    reads: list[Any] = []
    original = srv._guarded_read

    async def counting(*args: Any, **kwargs: Any) -> Any:
        reads.append(args)
        return await original(*args, **kwargs)

    monkeypatch.setattr(srv, "_guarded_read", counting)
    side = {"connection": "shop", "sql": "SELECT customer_id FROM customers"}
    text = _call_error(server, "db_federated_join",
                       {"left": side, "right": side, "on": [["customer_id", "customer_id"]] * 20000})
    assert "on" in text and reads == [], text
    text = _call_error(server, "db_federated_join",
                       {"left": side, "right": side, "on": [["customer_id", "customer_id"]] * 17})
    assert reads == [], text
    env = _call(server, "db_federated_join", {"left": side, "right": side, "on": [["customer_id", "customer_id"]] * 16})
    assert env["data"]["on"] == [["customer_id", "customer_id"]] and env["data"]["matched_left_rows"] == 3, env


# -------------------- X7 / R1: a namesake schema is never named to the caller


def _namesake_fake(tmp_path: Path, monkeypatch: Any) -> Any:
    from universal_db_mcp.connectors.base import TableSummary, ViewInfo

    fake = _Fake(
        [TableSummary("ocean", "orders", "table"), TableSummary("Ocean", "payroll", "table")],
        schemas=["ocean", "Ocean"],
        columns=[ColumnInfo("ocean", "orders", "id", "integer"), ColumnInfo("ocean", "orders", "pay_ref", "integer"),
                 ColumnInfo("Ocean", "payroll", "id", "integer")],
        fks=[KeyInfo(kind="foreign_key", name="fk_pay", columns=["pay_ref"], ref_schema="Ocean",
                     ref_table="payroll", ref_columns=["id"], source_schema="ocean", source_table="orders")],
        views=[ViewInfo("Ocean", "v_pay", "view", "SELECT id, salary FROM \"Ocean\".payroll", "available"),
               ViewInfo("ocean", "v_ok", "view", "SELECT id FROM ocean.orders", "available")],
    )
    return _fake_server(tmp_path, monkeypatch, fake, engine="postgres", allowed=["ocean"],
                        system=["information_schema"])


def _no_namesake(payload: Any) -> None:
    text = json.dumps(payload, default=str)
    assert "payroll" not in text and "Ocean" not in text and "v_pay" not in text, text[:800]


def test_x7_foreign_key_targets_in_a_namesake_schema_are_redacted(tmp_path: Path, monkeypatch: Any) -> None:
    server = _namesake_fake(tmp_path, monkeypatch)
    table = _call(server, "db_get_table", {"connection_id": "remote", "object_name": "ocean.orders"})
    assert table["data"]["foreign_keys"], table
    _no_namesake(table["data"]["foreign_keys"])
    rels = _call(server, "db_get_relationships", {"connection_id": "remote", "object_name": "ocean.orders"})
    assert rels["data"]["declared"] and rels["data"]["declared"][0]["to_table"] == "<not permitted>", rels
    _no_namesake(rels["data"])
    catalog = _call(server, "db_get_catalog", {"connection_id": "remote"})
    _no_namesake(catalog["data"])
    inferred = _call(server, "db_infer_relationships", {"connections": ["remote"]})
    _no_namesake(inferred["data"])


def test_r1_listings_without_a_schema_leave_the_namesake_out(tmp_path: Path, monkeypatch: Any) -> None:
    server = _namesake_fake(tmp_path, monkeypatch)
    views = _call(server, "db_list_views", {"connection_id": "remote"})
    assert [v["name"] for v in views["data"]["views"]] == ["v_ok"], views
    _no_namesake(views["data"])
    schemas = _call(server, "db_list_schemas", {"connection_id": "remote"})
    assert schemas["data"]["schemas"] == ["ocean"], schemas


# -------------------------- T3: a connector's own diagnostic is not redacted


def test_t3_the_sql_server_driver_diagnostic_keeps_the_driver_names(monkeypatch: Any) -> None:
    import types

    from universal_db_mcp.config import ConnectionConfig, ResolvedConnection, SecurityConfig
    from universal_db_mcp.connectors import mssql as mssql_module
    from universal_db_mcp.security.policy import EffectivePolicy

    fake = types.SimpleNamespace(pooling=True, drivers=lambda: ["ODBC Driver 17 for SQL Server"],
                                 connect=lambda *_a, **_k: None)
    monkeypatch.setattr(mssql_module, "open_module", lambda *_a, **_k: fake)
    cfg = ConnectionConfig.model_validate({"type": "mssql", "host": "h", "database": "d"})
    resolved = ResolvedConnection("m", cfg)
    connector = mssql_module.MssqlConnector(resolved, EffectivePolicy.build(SecurityConfig(), resolved))
    with pytest.raises(ConnectorError) as info:
        connector.list_schemas(None, None)
    text = srv._error_text(info.value)
    assert "ODBC Driver 18 for SQL Server" in text and "ODBC Driver 17 for SQL Server" in text, text
    assert "<redacted>" not in text, text


def test_t3_driver_text_wrapped_by_a_connector_is_still_sanitized() -> None:
    from universal_db_mcp.connectors.driver_helpers import translated_driver_errors

    class DriverError(Exception):
        pass

    def driver() -> None:
        raise DriverError("value '999-90-1111' out of range")

    with pytest.raises(ConnectorError) as info, translated_driver_errors():
        driver()
    assert "999-90-1111" not in srv._error_text(info.value)
    # a RuntimeError a driver raises from C (not a raise statement here) stays driver text
    with pytest.raises(ConnectorError) as info, translated_driver_errors():
        mapping = {1: "999-90-1111"}
        for key in mapping:
            mapping[key + 1] = "x"
    assert not srv._own_text(info.value)


# ------------------------------- A8: extension tables keyed by a derived name


def _facts(table: str, key: str) -> TableFacts:
    return TableFacts(
        ref=TableRef("c", "app", table), engine="postgres",
        columns=[ColumnInfo("app", table, key, "integer"), ColumnInfo("app", table, "note", "text")],
        indexes=[IndexInfo(name=f"pk_{table}", columns=[key], unique=True, primary=True)],
        foreign_keys=[],
    )


@pytest.mark.parametrize("key", ["customer_no", "customer_id", "customer_code"])
def test_a8_an_extension_table_sharing_a_derived_key_points_at_its_table(key: str) -> None:
    rels = infer_relationships([_facts("customers", key), _facts("customer_prefs", key)])
    pairs = {(r.source.table, r.target.table) for r in rels}
    assert ("customer_prefs", "customers") in pairs, pairs
    assert ("customers", "customer_prefs") not in pairs, pairs


def test_a8_sibling_surrogate_keys_stay_unrelated() -> None:
    rels = infer_relationships([_facts("customers", "rowguid"), _facts("orders", "rowguid")])
    assert rels == []
