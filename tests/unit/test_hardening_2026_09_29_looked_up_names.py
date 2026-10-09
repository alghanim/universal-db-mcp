"""Re-attack round 2, review of the fix (2026-09-29): a name is checked as
the engine looks it up.

1. Without default-deny a synonym (Db2: an alias) spelled in another case than
   a listed table of its schema was never looked up: the server compared the
   name with the listing ignoring case, and on Oracle, Db2 and SQL Server
   under a case-sensitive collation TRAVEL."Bookings" is another object than
   the listed TRAVEL.BOOKINGS (live: FOR R3RVOWN.PAYROLL, SYS.ALL_USERS, a
   table over a database link and ALL_TAB_COL_STATISTICS; Db2's MOI."citizens"
   FOR SYSCAT.DBAUTH; through every query, sample and profile tool). Now a
   name is compared with the listing, and looked up as a synonym, as the
   engine looks it up: a quoted one as written and an unquoted one folded,
   exactly; SQL Server binds it itself (OBJECT_ID, SCHEMA_ID), as its
   collation compares names.
2. With pg_catalog in allowed_system_schemas, default-deny refused a bare
   pg_tables as "looked up in public first": PostgreSQL searches pg_catalog
   first unless the search_path names it, which current_schemas(false) then
   shows; it holds only pg_ names.
3. PostgreSQL and Oracle read how a session binds names on the long-lived
   metadata session, which never saw an ALTER ROLE ... SET search_path (or a
   logon trigger's CURRENT_SCHEMA) made after it opened; every statement runs
   on a new session, and the binding is read on one now too.
"""

from __future__ import annotations

import re
import types
from pathlib import Path
from typing import Any

import pytest
from test_hardening_2026_09_27_qualified_names import _call, _call_error, _server
from test_hardening_2026_09_28_final_guard_server import _app_server

from universal_db_mcp.connectors.base import NameBinding, SynonymTarget, TableSummary

# ---- 1. a synonym beside a listed table, spelled in another case -------------

# engine, the statement's name for a synonym beside the listed OCEAN.BUOYS
# (SQL Server: ocean.buoys), that name as the engine looks it up, and what the
# synonym reads
_CASE_VARIANTS = [
    pytest.param("oracle", 'OCEAN."Buoys"', ("OCEAN", "Buoys"), SynonymTarget("SYS", "ALL_USERS"), id="oracle-sys"),
    pytest.param("oracle", '"OCEAN"."buoys"', ("OCEAN", "buoys"), SynonymTarget("R3OWN", "PAYROLL", "R3_LOOP"),
                 id="oracle-link"),
    pytest.param("db2", 'OCEAN."buoys"', ("OCEAN", "buoys"), SynonymTarget("SYSCAT", "DBAUTH"), id="db2"),
    # a case-sensitive collation: SQL Server keeps the synonym ocean.BUOYS beside the table (live, CS_AS)
    pytest.param("mssql", "ocean.BUOYS", ("ocean", "BUOYS"), SynonymTarget("sys", "objects"), id="mssql"),
]


def _looked_up_server(
    tmp_path: Path, monkeypatch: Any, engine: str, allowed: list[str], chains: dict[Any, list[Any]]
) -> tuple[Any, Any, list[tuple[str | None, str]]]:
    """_server without default-deny, its synonyms answered from ``chains``
    as the engine looks a name up (exactly), and every name asked recorded."""
    server, fake = _server(tmp_path, monkeypatch, engine, allowed, deny=False, second=True)
    asked: list[tuple[str | None, str]] = []

    def synonym_chains(names: list[tuple[str | None, str]]) -> dict[tuple[str | None, str], list[Any]]:
        asked.extend(names)
        return {n: chains[n] for n in names if n in chains}

    fake.synonym_chains = synonym_chains
    return server, fake, asked


@pytest.mark.parametrize(("engine", "written", "looked_up", "target"), _CASE_VARIANTS)
@pytest.mark.parametrize("allowed", [["ocean"], []], ids=["allowlist", "no-allowlist"])
def test_a_synonym_spelled_in_another_case_than_a_listed_table_is_looked_up(
    tmp_path: Path, monkeypatch: Any, engine: str, written: str, looked_up: Any, target: Any, allowed: list[str]
) -> None:
    server, fake, _asked = _looked_up_server(tmp_path, monkeypatch, engine, allowed, {looked_up: [target]})
    kind = "an alias" if engine == "db2" else "a synonym"
    sql = f"SELECT * FROM {written}"
    for tool, args in (
        ("db_query", {"connection_id": "remote", "sql": sql}),
        ("db_validate_query", {"connection_id": "remote", "sql": sql}),
        ("db_explain", {"connection_id": "remote", "sql": "EXPLAIN " + sql}),
        ("db_federated_join", {"left": {"connection": "remote", "sql": "SELECT buoy_id FROM ocean.buoys"},
                               "right": {"connection": "other", "sql": sql}, "on": [["buoy_id", "buoy_id"]]}),
        ("db_sample_table", {"connection_id": "remote", "schema": looked_up[0], "object_name": looked_up[1]}),
        ("db_profile_table", {"connection_id": "remote", "object_name": written}),
        ("db_get_table", {"connection_id": "remote", "schema": looked_up[0], "object_name": looked_up[1]}),
    ):
        text = _call_error(server, tool, args)
        assert f"'{looked_up[0]}.{looked_up[1]}' is {kind} that reads '{target.schema}.{target.name}'" in text, (
            tool, text,
        )
        assert "is a system schema" in text or "over the database link R3_LOOP" in text, (tool, text)
    env = _call(server, "db_federated_query", {"sql": sql, "connections": ["remote", "other"]})
    assert env["data"]["connections_run"] == 0
    assert all(f"is {kind} that reads" in r["error"] for r in env["data"]["results"]), env["data"]["results"]
    # the join's other side (the listed table) may have run; nothing read the synonym
    assert set(fake.statements) <= {"SELECT buoy_id FROM ocean.buoys"} and not fake.plans, (fake.statements, fake.plans)


# engine, spellings of the listed table the engine reads it by (never looked up as a synonym)
_LISTED_SPELLINGS = [
    ("oracle", ["OCEAN.buoys", "ocean.BUOYS", '"OCEAN"."BUOYS"', 'ocean."BUOYS"']),
    ("db2", ["ocean.buoys", 'OCEAN."BUOYS"']),
    ("mssql", ["ocean.buoys", "[ocean].[buoys]"]),
]


@pytest.mark.parametrize(("engine", "spellings"), _LISTED_SPELLINGS)
def test_the_listed_table_as_the_engine_looks_it_up_is_read_and_not_looked_up(
    tmp_path: Path, monkeypatch: Any, engine: str, spellings: list[str]
) -> None:
    ocean = "ocean" if engine == "mssql" else "OCEAN"
    buoys = "buoys" if engine == "mssql" else "BUOYS"
    # a namesake synonym in another case is no concern of the table's spellings
    server, fake, asked = _looked_up_server(
        tmp_path, monkeypatch, engine, ["ocean"], {(ocean, buoys.capitalize()): [SynonymTarget("SYS", "X")]}
    )
    for spelled in spellings:
        assert _call(server, "db_query", {"connection_id": "remote", "sql": f"SELECT buoy_id FROM {spelled}"})
    assert _call(server, "db_sample_table", {"connection_id": "remote", "schema": ocean, "object_name": buoys})
    assert asked == [], asked
    assert fake.statements


@pytest.mark.parametrize(
    ("engine", "sql", "looked_up"),
    [
        ("oracle", "SELECT * FROM ocean.r3_syn", ("OCEAN", "R3_SYN")),
        ("oracle", 'SELECT * FROM ocean."r3_Syn"', ("OCEAN", "r3_Syn")),
        ("oracle", "SELECT * FROM r3_syn", (None, "R3_SYN")),
        ("db2", 'SELECT * FROM "moi".r3_syn', ("moi", "R3_SYN")),
        ("mssql", "SELECT * FROM Ocean.R3_Syn", ("Ocean", "R3_Syn")),
    ],
)
def test_a_name_is_looked_up_as_a_synonym_as_the_engine_looks_it_up(
    tmp_path: Path, monkeypatch: Any, engine: str, sql: str, looked_up: Any
) -> None:
    server, _fake, asked = _looked_up_server(tmp_path, monkeypatch, engine, [], {})
    _call(server, "db_validate_query", {"connection_id": "remote", "sql": sql})
    assert asked == [looked_up], asked


def test_a_name_a_cte_leaves_to_the_catalog_is_looked_up_as_written(tmp_path: Path, monkeypatch: Any) -> None:
    """Oracle's "flights" in a scope no CTE flights covers is its own object,
    not FLIGHTS the statement reads elsewhere."""
    server, _fake, asked = _looked_up_server(
        tmp_path, monkeypatch, "oracle", [], {(None, "flights"): [SynonymTarget("SYS", "ALL_USERS")]}
    )
    sql = 'SELECT * FROM (WITH flights AS (SELECT 1 AS x FROM dual) SELECT x FROM flights), "flights", flights'
    text = _call_error(server, "db_query", {"connection_id": "remote", "sql": sql})
    assert "'flights' is a synonym that reads 'SYS.ALL_USERS'" in text, text
    assert (None, "flights") in asked and (None, "FLIGHTS") in asked, asked


# ---- the connectors look the names up exactly -----------------------------------


def test_oracle_looks_a_synonym_up_by_the_name_as_the_statement_looks_it_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from test_hardening_2026_09_28_credential_views import _oracle_synonyms

    rows = [
        ("TRAVEL", "Bookings", "R3OWN", "PAYROLL", None),
        ("TRAVEL", "FLIGHTS", "SYS", "ALL_USERS", None),
        ("PUBLIC", "Bookings", "TRAVEL", "Bookings", None),
    ]
    conn, session = _oracle_synonyms(tmp_path, monkeypatch, rows)
    names = [("TRAVEL", "Bookings"), ("TRAVEL", "BOOKINGS"), ("TRAVEL", "flights"), (None, "Bookings"),
             ("travel", "FLIGHTS")]
    assert conn.synonym_chains(names) == {
        ("TRAVEL", "Bookings"): [SynonymTarget("R3OWN", "PAYROLL")],
        (None, "Bookings"): [SynonymTarget("R3OWN", "PAYROLL"), SynonymTarget("TRAVEL", "Bookings")],
    }
    sql = next(s for s in session.statements if "all_synonyms" in s)
    assert "START WITH (synonym_name = :1 AND owner = :2) OR (synonym_name = :3 AND owner = :4)" in sql, sql
    assert session.binds == [["Bookings", "TRAVEL", "BOOKINGS", "TRAVEL", "flights", "TRAVEL", "Bookings", "FLIGHTS",
                              "travel"]]


def test_db2_looks_an_alias_up_by_the_name_as_the_statement_looks_it_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import sys

    from test_hardening_2026_09_28_converge_connectors import _connector, _Db2Rows

    from universal_db_mcp.connectors import db2 as db2_module

    rows = [("MOI     ", "citizens", "SYSCAT  ", "DBAUTH"), ("MOI", "VEHICLES", "SYSIBM", "SYSDBAUTH")]
    monkeypatch.setattr(db2_module, "open_module", lambda *_a, **_k: _Db2Rows(rows))
    monkeypatch.setitem(sys.modules, "ibm_db_dbi", types.ModuleType("ibm_db_dbi"))
    conn = _connector(db2_module.Db2Connector, "db2", tmp_path)
    names = [("MOI", "citizens"), ("MOI", "CITIZENS"), ("MOI ", "citizens "), ("MOI", "vehicles"), (None, "citizens")]
    assert conn.synonym_chains(names) == {
        ("MOI", "citizens"): [SynonymTarget("SYSCAT", "DBAUTH")],
        ("MOI ", "citizens "): [SynonymTarget("SYSCAT", "DBAUTH")],  # Db2 drops a delimited name's trailing blanks
        (None, "citizens"): [SynonymTarget("SYSCAT", "DBAUTH")],
    }


class _Params:
    """A pyodbc connection and cursor answering the synonym statement with
    ``rows``, each statement and its parameters recorded."""

    def __init__(self, rows: list[tuple[Any, ...]]) -> None:
        self.rows = rows
        self.calls: list[tuple[str, list[Any]]] = []
        self.closed = 0

    def cursor(self) -> _Params:
        return self

    def execute(self, sql: str, params: list[Any]) -> _Params:
        self.calls.append((sql, list(params)))
        return self

    def fetchall(self) -> list[tuple[Any, ...]]:
        return list(self.rows)

    def fetchone(self) -> None:
        return None

    def close(self) -> None:
        self.closed += 1


def test_mssql_binds_each_name_as_a_statement_does(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The database collation decides which synonym a name is: SQL Server
    binds it (live, 2022: under CS_AS ocean.BUOYS was the synonym beside the
    table ocean.buoys, under CI_AS and CI_AI OCEAN.SYN_X was ocean.syn_x, and
    no Python folding matches an accent- or width-insensitive collation)."""
    from test_hardening_2026_09_28_converge_connectors import _connector

    from universal_db_mcp.connectors import mssql as mssql_module

    # the name's index, the synonym's schema and name, its base object's server and other database, and the
    # schema and name OBJECT_ID binds that to in this database
    session = _Params([(0, "ocean", "BUOYS", None, None, "sys", "objects"),
                       (2, "ocean", "BUOYS", None, None, "sys", "objects"),
                       (2, "r3", "BUOYS", "srv1", "master", "dbo", "spt_values")])
    conn = _connector(mssql_module.MssqlConnector, "mssql", tmp_path)
    monkeypatch.setattr(conn, "_connect", lambda: session)
    names = [("ocean", "BUOYS"), ("ocean", "buoys"), (None, "BUOYS")]
    assert conn.synonym_chains(names) == {
        ("ocean", "BUOYS"): [SynonymTarget("sys", "objects")],
        (None, "BUOYS"): [SynonymTarget("sys", "objects"), SynonymTarget("dbo", "spt_values", "srv1.master")],
    }
    ((sql, params),) = session.calls
    assert params == ["ocean", "BUOYS", "ocean", "buoys", None, "BUOYS"], params
    assert "FROM (VALUES (0, CAST(? AS nvarchar(128)), CAST(? AS nvarchar(128))), (1, " in sql, sql
    assert "JOIN sys.synonyms AS s ON (v.sch IS NULL OR s.schema_id = SCHEMA_ID(v.sch)) AND s.object_id = " \
           "OBJECT_ID(QUOTENAME(SCHEMA_NAME(s.schema_id)) + N'.' + QUOTENAME(v.n))" in sql, sql
    assert session.closed == 1


def test_mssql_looks_many_names_up_in_batches(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from test_hardening_2026_09_28_converge_connectors import _connector

    from universal_db_mcp.connectors import mssql as mssql_module

    session = _Params([])
    conn = _connector(mssql_module.MssqlConnector, "mssql", tmp_path)
    monkeypatch.setattr(conn, "_connect", lambda: session)
    assert conn.synonym_chains([("dbo", f"t{n}") for n in range(1200)]) == {}
    assert [len(params) for _sql, params in session.calls] == [1000, 1000, 400]  # SQL Server takes 2100


# ---- 2. PostgreSQL: a bare pg_ name ----------------------------------------------

_PG_OPEN = "  allowed_system_schemas: [information_schema, pg_catalog]\n"


@pytest.mark.parametrize(
    ("path", "first"),
    [
        (("ocean",), None),  # pg_catalog implicit: searched first
        (("pg_catalog", "ocean"), None),
        (("ocean", "pg_catalog"), "ocean"),  # the path names it later
        ((), None),
    ],
)
def test_a_bare_pg_name_is_pg_catalog_s_where_the_session_searches_it_first(
    tmp_path: Path, monkeypatch: Any, path: tuple[str, ...], first: str | None
) -> None:
    catalog = [TableSummary("pg_catalog", "pg_tables", "view"), TableSummary("ocean", "buoys", "table")]
    server, fake = _app_server(tmp_path, monkeypatch, "postgres", [], catalog, security=_PG_OPEN)
    fake.binding = NameBinding(path)
    sql = "SELECT count(*) AS n FROM pg_tables"
    for tool in ("db_query", "db_validate_query"):
        if first is None:
            assert _call(server, tool, {"connection_id": "remote", "sql": sql}), tool
        else:
            text = _call_error(server, tool, {"connection_id": "remote", "sql": sql})
            assert f"a bare name is looked up in {first} first" in text and "write pg_catalog.pg_tables" in text, text
    qualified = "SELECT count(*) AS n FROM pg_catalog.pg_tables"
    assert _call(server, "db_query", {"connection_id": "remote", "sql": qualified})


@pytest.mark.parametrize("path", [("pg_catalog", "ocean"), ("ocean",)])
def test_postgres_looks_any_other_bare_name_up_past_pg_catalog(
    tmp_path: Path, monkeypatch: Any, path: tuple[str, ...]
) -> None:
    """pg_catalog holds only pg_ names (live, 17: 142 relations), so a path
    that names it first still binds a bare buoys to ocean's."""
    catalog = [TableSummary("ocean", "buoys", "table")]
    server, fake = _app_server(tmp_path, monkeypatch, "postgres", [], catalog, security=_PG_OPEN)
    fake.binding = NameBinding(path)
    assert _call(server, "db_query", {"connection_id": "remote", "sql": "SELECT buoy_id FROM buoys"})["data"]["rows"]


# ---- 3. the binding is read on a new session ----------------------------------------


class _Fresh:
    """A new session (psycopg's and oracledb's shapes) answering ``row``."""

    def __init__(self, row: tuple[Any, ...]) -> None:
        self.row = row
        self.statements: list[str] = []
        self.closed = False

    def execute(self, sql: str, *_a: Any) -> _Fresh:
        self.statements.append(sql)
        return self

    def fetchone(self) -> tuple[Any, ...]:
        return self.row

    def cursor(self) -> _Fresh:
        return self

    def __enter__(self) -> _Fresh:
        return self

    def __exit__(self, *_a: Any) -> None:
        return None

    def close(self) -> None:
        self.closed = True


@pytest.mark.parametrize(
    ("engine", "row", "statement", "binding"),
    [
        ("postgres", (["app", "public"],), "SELECT current_schemas(false)", NameBinding(("app", "public"))),
        ("oracle", ("TRAVEL",), "SELECT sys_context('USERENV', 'CURRENT_SCHEMA') FROM sys.dual",
         NameBinding(("TRAVEL",))),
    ],
)
def test_the_binding_is_read_on_a_new_session_as_each_statement_runs_on_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, engine: str, row: Any, statement: str, binding: NameBinding
) -> None:
    from test_hardening_2026_09_28_converge_connectors import _connector

    from universal_db_mcp.connectors import oracle as oracle_module
    from universal_db_mcp.connectors import postgres as pg_module

    cls = {"postgres": pg_module.PostgresConnector, "oracle": oracle_module.OracleConnector}[engine]
    conn = _connector(cls, engine, tmp_path)
    sessions: list[_Fresh] = []

    def connect() -> _Fresh:
        sessions.append(_Fresh(row))
        return sessions[-1]

    def shared() -> Any:
        raise AssertionError("the long-lived metadata session binds names as it did when it opened")

    monkeypatch.setattr(conn, "_connect", connect)
    monkeypatch.setattr(conn, "_shared_meta_conn", shared)
    assert conn.name_binding() == binding
    assert conn.name_binding() == binding
    assert [s.statements for s in sessions] == [[statement], [statement]]
    assert all(s.closed for s in sessions)


# the INFORMATION_SCHEMA columns SQL Server's catalog names in upper case
_MSSQL_INFORMATION_SCHEMA_COLUMNS = re.compile(
    r"\b(schema_name|table_schema|table_name|table_type|column_name|data_type|is_nullable|column_default|"
    r"ordinal_position|character_maximum_length|numeric_precision|numeric_scale|routine_schema|routine_name|"
    r"routine_type)\b"
)


def test_mssql_names_the_information_schema_views_as_its_catalog_spells_them(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SQL Server compares a catalog view's name, and its columns', as the
    database collation does: on a CS_AS database information_schema.tables
    is no object (live, 2022: every listing, and so every tool, failed with
    "Invalid object name 'information_schema.schemata'"; the sys views, whose
    names are lower case, and the synonym statement answered)."""
    from test_hardening_2026_09_28_converge_connectors import _connector

    from universal_db_mcp.connectors import mssql as mssql_module

    session = _Params([])
    conn = _connector(mssql_module.MssqlConnector, "mssql", tmp_path)
    monkeypatch.setattr(conn, "_connect", lambda: session)
    conn.list_schemas(None, "oce")
    conn.list_tables("ocean", {"table", "view"}, "buo")
    conn.list_columns("ocean", "buoys")
    conn.list_columns(None, "buoys")
    conn.list_all_columns("ocean")
    conn.list_views("ocean")
    conn.list_routines("ocean")
    assert len(session.calls) == 7
    for sql, _params in session.calls:
        assert "INFORMATION_SCHEMA." in sql and "information_schema" not in sql, sql
        assert not _MSSQL_INFORMATION_SCHEMA_COLUMNS.search(sql), sql
