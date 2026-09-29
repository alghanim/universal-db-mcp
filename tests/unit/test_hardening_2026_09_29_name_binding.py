"""Re-attack, round 2 (2026-09-29): the object a statement is authorized for
is the object the engine reads.

1. Default-deny matched a table name to the listing ignoring case and, for a
   bare name, in any listed schema, and the engine then bound the name its own
   way (live, every object dropped after): with an empty ocean.pg_settings
   listed, a bare pg_settings read pg_catalog's; with an empty
   R2OWN.DATABASE_PROPERTIES, a bare DATABASE_PROPERTIES Oracle's PUBLIC
   synonym (the RECO login blobs with it); with an empty r2own.syslogins, a
   bare syslogins SQL Server's compatibility view; and TRAVEL."travellers", a
   synonym of ALL_TAB_COL_STATISTICS beside the listed TRAVEL.TRAVELLERS,
   returned a masked column's low and high values. Now a name reads a listed
   object only as the catalog spells it (as the engine folds an unquoted name;
   on SQL Server in another case too where the database collation ignores
   case), and a bare one only in the first schema the session looks bare
   names up in, which the server asks the database once per 300 s
   (DatabaseConnector.name_binding). A bare pg_ name is pg_catalog's, which
   PostgreSQL searches first.
2. Without default-deny, what a synonym (Db2: an alias) names was checked
   against the never-readable views only: TRAVEL synonyms read another
   schema, SYS.ALL_USERS and a table over a database link, SQL Server ones
   master.dbo.spt_values and sys.objects, a Db2 alias SYSCAT.DBAUTH, and
   dbo.syslogins, no synonym at all, the server's logins (live). Each target
   now goes through every check a written reference does, one in another
   database or over a link is refused, and SQL Server's compatibility views
   are the sys views they are however a statement or a tool names them.
"""

from __future__ import annotations

import types
from pathlib import Path
from typing import Any

import pytest
from test_hardening_2026_09_27_qualified_names import _OCEAN, _call, _call_error, _entries, _refused, _server
from test_hardening_2026_09_28_final_guard_server import _app_server, _listed_guard

from universal_db_mcp.connectors.base import NameBinding, SynonymTarget, TableSummary
from universal_db_mcp.connectors.driver_helpers import synonym_chains
from universal_db_mcp.models.responses import ErrorCategory

# ---- 1. default-deny: the catalog's spelling ---------------------------------

# engine, listing, refused (-> the spelling the refusal offers), accepted
_SPELLINGS = [
    ("oracle", [("TRAVEL", "TRAVELLERS")],
     {'SELECT table_name FROM TRAVEL."travellers"': "TRAVEL.TRAVELLERS",
      'SELECT table_name FROM "travellers"': "TRAVEL.TRAVELLERS",
      'SELECT table_name FROM "Travel".travellers': "TRAVEL.TRAVELLERS"},
     ["SELECT * FROM TRAVEL.travellers", "SELECT * FROM travel.TRAVELLERS", 'SELECT * FROM "TRAVEL"."TRAVELLERS"',
      "SELECT * FROM travellers"]),
    ("postgres", [("ocean", "readings"), ("ocean", "Buoys")],
     {'SELECT * FROM ocean."Readings"': "ocean.readings", 'SELECT * FROM "OCEAN".readings': "ocean.readings",
      "SELECT * FROM ocean.buoys": 'ocean."Buoys"', "SELECT * FROM buoys": 'ocean."Buoys"'},
     ["SELECT * FROM ocean.READINGS", 'SELECT * FROM "ocean"."readings"', "SELECT * FROM OCEAN.readings",
      'SELECT * FROM ocean."Buoys"', 'SELECT * FROM "Buoys"', "SELECT * FROM readings"]),
    ("db2", [("MOI", "CITIZENS")],
     {'SELECT * FROM MOI."citizens"': "MOI.CITIZENS", 'SELECT * FROM "moi".CITIZENS': "MOI.CITIZENS"},
     ["SELECT * FROM moi.citizens", 'SELECT * FROM "MOI"."CITIZENS"']),
    ("clickhouse", [("telecom", "subscribers")],
     {"SELECT * FROM telecom.Subscribers": "telecom.subscribers",
      "SELECT * FROM Telecom.subscribers": "telecom.subscribers"},
     ["SELECT * FROM telecom.subscribers"]),
]


@pytest.mark.parametrize(("engine", "listing", "refused", "accepted"), _SPELLINGS)
def test_default_deny_reads_a_listed_object_only_as_the_catalog_spells_it(
    engine: str, listing: list[tuple[str, str]], refused: dict[str, str], accepted: list[str]
) -> None:
    guard = _listed_guard(engine, [], listing, deny=True)
    for sql, spelling in refused.items():
        for label, validate, prefix in _entries(guard):
            exc = _refused(validate, prefix + sql)
            text = str(exc)
            assert exc.category == ErrorCategory.POLICY, (label, sql, text)
            assert "is not spelled as the catalog lists it" in text and text.endswith(f"write {spelling}"), (
                label, sql, text,
            )
    for sql in accepted:
        for label, validate, prefix in _entries(guard):
            assert validate(prefix + sql).kind in ("select", "explain"), (label, sql)


def test_without_default_deny_the_spelling_is_the_engines_business() -> None:
    guard = _listed_guard("oracle", [], [("TRAVEL", "TRAVELLERS")], deny=False)
    assert guard.validate_select('SELECT * FROM TRAVEL."travellers"').kind == "select"


def test_postgres_reads_a_bare_pg_name_from_pg_catalog_first() -> None:
    """pg_catalog is searched before the search_path, and every relation it
    holds is named pg_... (live, 17): an ocean.pg_settings in the listing
    does not make a bare pg_settings ocean's."""
    guard = _listed_guard("postgres", [], [("ocean", "pg_settings"), ("ocean", "readings")], deny=True)
    for label, validate, prefix in _entries(guard):
        exc = _refused(validate, prefix + "SELECT name, setting FROM pg_settings")
        text = str(exc)
        assert exc.category == ErrorCategory.POLICY and "pg_catalog first" in text, (label, text)
        assert text.endswith("write ocean.pg_settings"), (label, text)
        assert validate(prefix + "SELECT name FROM ocean.pg_settings").kind in ("select", "explain"), label
    # pg_catalog opened and listed: the bare name is its own
    guard = _listed_guard("postgres", [], [("pg_catalog", "pg_settings")], deny=True, system_schemas=["pg_catalog"])
    assert guard.validate_select("SELECT name FROM pg_settings").kind == "select"


# ---- SQL Server's compatibility views ------------------------------------------

_COMPAT_POLICIES = [
    pytest.param([], True, id="default-deny"),
    pytest.param([], False, id="neither"),
    pytest.param(["dbo"], False, id="allowlist"),
    pytest.param(["dbo"], True, id="allowlist-default-deny"),
]


@pytest.mark.parametrize(("allowed", "deny"), _COMPAT_POLICIES)
def test_sql_server_compatibility_views_are_sys_views_however_named(allowed: list[str], deny: bool) -> None:
    """SQL Server binds dbo.syslogins and a bare syslogins to sys.syslogins,
    ahead of a user table dbo.sysusers of the same name (live, 2022: 38
    views; CREATE TABLE dbo.sysusers, then FROM dbo.sysusers returned the
    compatibility view's columns)."""
    listing = [("dbo", "patients"), ("r2own", "syslogins"), ("dbo", "sysusers")]
    guard = _listed_guard("mssql", allowed, listing, deny=deny)
    named = ["SELECT name FROM dbo.syslogins", "SELECT name FROM DBO.SYSLOGINS", "SELECT name FROM [dbo].[sysusers]",
             "SELECT id FROM dbo.syscomments", "SELECT name FROM dbo.sysobjects"]
    if not allowed:
        named += ["SELECT name FROM syslogins", "SELECT name FROM SysObjects"]
    for sql in named:
        for label, validate, prefix in _entries(guard):
            exc = _refused(validate, prefix + sql)
            text = str(exc)
            assert exc.category == ErrorCategory.AUTHZ, (label, sql, text)
            assert "SQL Server's compatibility view sys." in text and "system schema" in text, (label, sql, text)
    if not allowed:
        # another schema's object of that name is its own
        assert guard.validate_select("SELECT * FROM r2own.syslogins").kind == "select"
    assert guard.validate_select("SELECT * FROM dbo.patients").kind == "select"


def test_sql_server_compatibility_views_open_with_sys() -> None:
    guard = _listed_guard("mssql", [], [("sys", "syslogins")], deny=True, system_schemas=["sys"])
    assert guard.validate_select("SELECT name FROM dbo.syslogins").kind == "select"
    assert guard.validate_select("SELECT name FROM syslogins").kind == "select"
    # the ones that hold credentials stay refused whatever opens
    exc = _refused(guard.validate_select, "SELECT srvname FROM dbo.sysservers")
    assert exc.category == ErrorCategory.POLICY and "stored credentials" in str(exc)


def test_a_table_the_engine_never_reads_by_its_name_is_not_listed(tmp_path: Path, monkeypatch: Any) -> None:
    """A user table dbo.sysusers is listed by information_schema but never
    read: FROM [dbo].[sysusers], the sample and value search's statements
    included, reads the compatibility view."""
    catalog = [TableSummary("dbo", "patients", "table"), TableSummary("dbo", "sysusers", "table"),
               TableSummary("r2own", "syslogins", "table")]
    server, fake = _app_server(tmp_path, monkeypatch, "mssql", [], catalog)
    listed = {(t["schema"], t["name"]) for t in _call(server, "db_list_tables", {"connection_id": "remote"})["data"][
        "tables"]}
    assert listed == {("dbo", "patients"), ("r2own", "syslogins")}, listed
    _call(server, "db_search_values", {"query": "north", "connections": ["remote"]})
    assert not [s for s in fake.statements if "sysusers" in s.lower()], fake.statements


# ---- 1. default-deny: a bare name's schema, asked of the session ---------------

_BINDING_ENGINES = ["postgres", "oracle", "mssql", "db2"]
_R2 = {"postgres": "r2own", "oracle": "R2OWN", "mssql": "r2own", "db2": "R2OWN"}


def _spelled(engine: str, name: str) -> str:
    return name.upper() if engine in ("oracle", "db2") else name


def _binding_server(tmp_path: Path, monkeypatch: Any, engine: str, first: str, *, ignores_case: bool = False) -> Any:
    catalog = [
        TableSummary(_OCEAN[engine], _spelled(engine, "buoys"), "table"),
        TableSummary(_R2[engine], _spelled(engine, "props"), "table"),
    ]
    server, fake = _app_server(tmp_path, monkeypatch, engine, [], catalog)
    fake.binding = NameBinding((first,), ignores_case=ignores_case)
    return server, fake


@pytest.mark.parametrize("engine", _BINDING_ENGINES)
def test_a_bare_name_reads_only_the_first_schema_the_session_looks_in(
    tmp_path: Path, monkeypatch: Any, engine: str
) -> None:
    """PostgreSQL's search_path, Oracle's CURRENT_SCHEMA (then its PUBLIC
    synonyms), SQL Server's default schema and Db2's CURRENT SCHEMA: a
    listed R2OWN.PROPS does not make a bare PROPS R2OWN's."""
    server, fake = _binding_server(tmp_path, monkeypatch, engine, _OCEAN[engine])
    sql = "SELECT buoy_id FROM props"
    for tool, args in (
        ("db_query", {"connection_id": "remote", "sql": sql}),
        ("db_validate_query", {"connection_id": "remote", "sql": sql}),
        ("db_explain", {"connection_id": "remote", "sql": "EXPLAIN " + sql}),
    ):
        text = _call_error(server, tool, args)
        assert "POLICY_VIOLATION" in text and f"a bare name is looked up in {_OCEAN[engine]} first" in text, text
        assert f"write {_R2[engine]}.{_spelled(engine, 'props')}" in text, text
    assert not [s for s in fake.statements + fake.plans if "props" in s.lower()]
    # the first schema's own table reads, and the answer is kept
    assert _call(server, "db_query", {"connection_id": "remote", "sql": "SELECT buoy_id FROM buoys"})["data"]["rows"]
    assert _call(server, "db_query", {"connection_id": "remote", "sql": f"SELECT buoy_id FROM {_R2[engine]}.props"})
    assert fake.binding_asked == 1


@pytest.mark.parametrize("engine", _BINDING_ENGINES)
def test_qualified_statements_never_ask_how_bare_names_bind(tmp_path: Path, monkeypatch: Any, engine: str) -> None:
    server, fake = _binding_server(tmp_path, monkeypatch, engine, "elsewhere")
    assert _call(server, "db_query", {"connection_id": "remote", "sql": f"SELECT buoy_id FROM {_R2[engine]}.props"})
    assert fake.binding_asked == 0


def test_a_session_that_cannot_say_how_it_binds_refuses_the_bare_name(tmp_path: Path, monkeypatch: Any) -> None:
    server, fake = _binding_server(tmp_path, monkeypatch, "oracle", "OCEAN")

    def broken() -> NameBinding:
        raise RuntimeError("ORA-03113: end-of-file on communication channel")

    fake.name_binding = broken
    _call_error(server, "db_query", {"connection_id": "remote", "sql": "SELECT buoy_id FROM buoys"})
    assert not fake.statements


@pytest.mark.parametrize("ignores_case", [True, False])
def test_sql_server_reads_another_case_only_where_its_collation_ignores_case(
    tmp_path: Path, monkeypatch: Any, ignores_case: bool
) -> None:
    """Under a case-sensitive collation dbo.Patients may be a synonym beside
    the table dbo.patients; the database collation says which."""
    server, fake = _binding_server(tmp_path, monkeypatch, "mssql", "ocean", ignores_case=ignores_case)
    for sql in ("SELECT buoy_id FROM ocean.BUOYS", "SELECT buoy_id FROM OCEAN.buoys", "SELECT buoy_id FROM Buoys"):
        if ignores_case:
            assert _call(server, "db_query", {"connection_id": "remote", "sql": sql})["data"]["rows"], sql
        else:
            text = _call_error(server, "db_query", {"connection_id": "remote", "sql": sql})
            assert "is not spelled as the catalog lists it" in text and "write ocean.buoys" in text, text
    assert _call(server, "db_query", {"connection_id": "remote", "sql": "SELECT buoy_id FROM ocean.buoys"})


@pytest.mark.parametrize("engine", ["mysql", "clickhouse"])
def test_engines_that_bind_a_bare_name_in_one_database_keep_the_listing_s_answer(
    tmp_path: Path, monkeypatch: Any, engine: str
) -> None:
    server, fake = _server(tmp_path, monkeypatch, engine, [])
    assert fake.binding is None  # as their connectors answer
    assert _call(server, "db_query", {"connection_id": "remote", "sql": "SELECT buoy_id FROM buoys"})["data"]["rows"]


# ---- 2. without default-deny: what a synonym names ------------------------------

# engine, what the synonym names, the refusal
_TARGETS = [
    ("oracle", ("R2OWN", "PAYROLL"), "schema 'R2OWN' is not permitted"),
    ("oracle", ("SYS", "ALL_USERS"), "schema 'SYS' is a system schema"),
    ("oracle", SynonymTarget("OCEAN", "BUOYS", "R2_LOOP"), "over the database link R2_LOOP"),
    ("oracle", SynonymTarget("SYS", "DUAL", "R2_LOOP"), "over the database link R2_LOOP"),
    ("mssql", ("r2own", "payroll"), "schema 'r2own' is not permitted"),
    ("mssql", ("sys", "objects"), "schema 'sys' is a system schema"),
    ("mssql", ("dbo", "syslogins"), "SQL Server's compatibility view sys.syslogins"),
    ("mssql", SynonymTarget("dbo", "spt_values", "master"), "in the database master"),
    ("mssql", SynonymTarget("dbo", "spt_values", "srv1.master"), "in the database srv1.master"),
    ("db2", ("R2OWN", "PAYROLL"), "schema 'R2OWN' is not permitted"),
    ("db2", ("SYSCAT", "DBAUTH"), "schema 'SYSCAT' is a system schema"),
]


def _synonyms(
    tmp_path: Path, monkeypatch: Any, engine: str, allowed: list[str], chains: dict[Any, list[Any]]
) -> tuple[Any, Any]:
    server, fake = _server(tmp_path, monkeypatch, engine, allowed, deny=False)
    fake.synonym_chains = lambda names: {n: chains[n] for n in names if n in chains}
    return server, fake


def _looked_up(engine: str, schema: str, name: str) -> tuple[str, str]:
    """An unquoted schema.name as the engine looks it up (Oracle and Db2 fold
    it to upper case), the spelling the tools name it by."""
    return (schema.upper(), name.upper()) if engine in ("oracle", "db2") else (schema, name)


@pytest.mark.parametrize(("engine", "target", "refusal"), _TARGETS)
def test_a_synonym_reads_only_what_the_policy_permits_by_name(
    tmp_path: Path, monkeypatch: Any, engine: str, target: Any, refusal: str
) -> None:
    syn = _looked_up(engine, "ocean", "r2_syn")
    server, fake = _synonyms(tmp_path, monkeypatch, engine, ["ocean"], {syn: [target]})
    kind = "an alias" if engine == "db2" else "a synonym"
    for tool, args in (
        ("db_query", {"connection_id": "remote", "sql": "SELECT * FROM ocean.r2_syn"}),
        ("db_validate_query", {"connection_id": "remote", "sql": "SELECT * FROM ocean.r2_syn"}),
        ("db_sample_table", {"connection_id": "remote", "schema": syn[0], "object_name": syn[1]}),
    ):
        text = _call_error(server, tool, args)
        assert f"'{'.'.join(syn)}' is {kind} that reads" in text and refusal in text, (tool, text)
    assert not [s for s in fake.statements + fake.plans if "r2_syn" in s.lower()]


@pytest.mark.parametrize("engine", ["oracle", "mssql", "db2"])
def test_without_an_allowlist_a_synonym_still_reads_no_system_schema(
    tmp_path: Path, monkeypatch: Any, engine: str
) -> None:
    system = {"oracle": ("SYS", "ALL_USERS"), "mssql": ("sys", "objects"), "db2": ("SYSCAT", "DBAUTH")}[engine]
    chains = {_looked_up(engine, "ocean", "r2_sys"): [system],
              _looked_up(engine, "ocean", "r2_other"): [(_R2[engine], "PAYROLL")]}
    server, fake = _synonyms(tmp_path, monkeypatch, engine, [], chains)
    text = _call_error(server, "db_query", {"connection_id": "remote", "sql": "SELECT * FROM ocean.r2_sys"})
    assert "AUTHORIZATION_DENIED" in text and "is a system schema" in text, text
    # no allowlist: another user schema is readable, through a synonym as by name
    assert _call(server, "db_query", {"connection_id": "remote", "sql": "SELECT * FROM ocean.r2_other"})


@pytest.mark.parametrize("allowed", [["dbo"], []], ids=["allowlist", "no-allowlist"])
def test_sql_server_dbo_compatibility_views_are_refused_by_every_tool(
    tmp_path: Path, monkeypatch: Any, allowed: list[str]
) -> None:
    server, fake = _server(tmp_path, monkeypatch, "mssql", allowed, deny=False)
    for sql in ("SELECT TOP 3 name, sysadmin FROM dbo.syslogins", "SELECT id, text FROM dbo.syscomments"):
        text = _call_error(server, "db_query", {"connection_id": "remote", "sql": sql})
        assert "AUTHORIZATION_DENIED" in text and "SQL Server's compatibility view sys.sys" in text, text
    for args in ({"schema": "dbo", "object_name": "syslogins"}, {"object_name": "dbo.sysobjects"}):
        text = _call_error(server, "db_sample_table", {"connection_id": "remote", **args})
        assert "SQL Server's compatibility view sys.sys" in text, text
    if not allowed:
        text = _call_error(server, "db_query", {"connection_id": "remote", "sql": "SELECT name FROM syslogins"})
        assert "SQL Server's compatibility view sys.syslogins" in text, text
    assert not [s for s in fake.statements if "sys" in s.lower()]


# ---- the connectors ------------------------------------------------------------


def test_the_chain_walk_stops_at_a_target_in_another_database() -> None:
    targets = {
        ("TRAVEL", "REMOTE"): SynonymTarget("R2OWN", "PAYROLL", "R2_LOOP"),
        ("R2OWN", "PAYROLL"): SynonymTarget("SYS", "USER$"),  # a local namesake the link does not read
        ("TRAVEL", "LOCAL"): SynonymTarget("TRAVEL", "HOP"),
        ("TRAVEL", "HOP"): SynonymTarget("SYS", "DUAL", "R2_LOOP"),
    }
    chains = synonym_chains([("TRAVEL", "REMOTE"), ("TRAVEL", "LOCAL")], targets, str.upper, "PUBLIC")
    assert chains == {
        ("TRAVEL", "REMOTE"): [SynonymTarget("R2OWN", "PAYROLL", "R2_LOOP")],
        ("TRAVEL", "LOCAL"): [SynonymTarget("TRAVEL", "HOP"), SynonymTarget("SYS", "DUAL", "R2_LOOP")],
    }


def test_oracle_reports_a_synonyms_database_link(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from test_hardening_2026_09_28_credential_views import _oracle_synonyms

    rows = [("TRAVEL", "R2_REMOTE", "R2OWN", "PAYROLL", "R2_LOOP"), ("TRAVEL", "R2_PAY", "R2OWN", "PAYROLL", None)]
    conn, session = _oracle_synonyms(tmp_path, monkeypatch, rows)
    chains = conn.synonym_chains([("TRAVEL", "R2_REMOTE"), ("TRAVEL", "R2_PAY")])
    assert chains == {
        ("TRAVEL", "R2_REMOTE"): [SynonymTarget("R2OWN", "PAYROLL", "R2_LOOP")],
        ("TRAVEL", "R2_PAY"): [SynonymTarget("R2OWN", "PAYROLL")],
    }
    sql = next(s for s in session.statements if "all_synonyms" in s)
    assert sql.startswith("SELECT owner, synonym_name, table_owner, table_name, db_link FROM sys.all_synonyms"), sql


def test_mssql_reports_where_a_synonym_reads_as_the_engine_binds_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from test_hardening_2026_09_28_converge_connectors import _connector, _Session

    from universal_db_mcp.connectors import mssql as mssql_module

    # the index of the name bound to the synonym, its schema and name; the base object's server, its
    # database unless it is this one (NULLIF DB_NAME()), and its schema and name as OBJECT_ID binds them in
    # this database, else as written
    rows = [
        (0, "dbo", "r2_one", None, None, "sys", "syslogins"),  # FOR syslogins (live: bound to the view)
        (1, "dbo", "r2_same", None, None, "sys", "syslogins"),  # FOR HospitalDB.dbo.syslogins
        (2, "dbo", "r2_cross", None, "master", "dbo", "spt_values"),
        (3, "dbo", "r2_srv", "srv1", "master", "dbo", "spt_values"),
    ]
    session = _Session(rows=rows)
    conn = _connector(mssql_module.MssqlConnector, "mssql", tmp_path)
    monkeypatch.setattr(conn, "_connect", lambda: types.SimpleNamespace(cursor=lambda: session, close=lambda: None))
    chains = conn.synonym_chains([("dbo", "r2_one"), ("DBO", "R2_SAME"), (None, "r2_cross"), ("dbo", "r2_srv")])
    assert chains == {
        ("dbo", "r2_one"): [SynonymTarget("sys", "syslogins")],
        ("DBO", "R2_SAME"): [SynonymTarget("sys", "syslogins")],
        (None, "r2_cross"): [SynonymTarget("dbo", "spt_values", "master")],
        ("dbo", "r2_srv"): [SynonymTarget("dbo", "spt_values", "srv1.master")],
    }
    (sql,) = session.statements
    assert "PARSENAME(s.base_object_name, 4)" in sql and "NULLIF(PARSENAME(s.base_object_name, 3), DB_NAME())" in sql
    assert "OBJECT_SCHEMA_NAME(b.id)" in sql and "OBJECT_ID(s.base_object_name)" in sql, sql


def test_each_engine_says_how_its_sessions_bind_a_bare_name(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from test_hardening_2026_09_28_converge_connectors import _connector, _Session

    from universal_db_mcp.connectors import db2 as db2_module
    from universal_db_mcp.connectors import mssql as mssql_module
    from universal_db_mcp.connectors import mysql as mysql_module
    from universal_db_mcp.connectors import oracle as oracle_module
    from universal_db_mcp.connectors import postgres as pg_module

    # a new session each, as a statement runs on (test_hardening_2026_09_29_looked_up_names)
    pg = _connector(pg_module.PostgresConnector, "postgres", tmp_path)
    pg_session = _Session(answer=lambda sql: (["app", "public"],) if "current_schemas(false)" in sql else None)
    pg_session.close = lambda: None  # type: ignore[attr-defined]
    monkeypatch.setattr(pg, "_connect", lambda: pg_session)
    assert pg.name_binding() == NameBinding(("app", "public"))
    assert pg_session.statements == ["SELECT current_schemas(false)"]

    ora = _connector(oracle_module.OracleConnector, "oracle", tmp_path)
    ora_session = _Session(answer=lambda sql: ("TRAVEL",) if "CURRENT_SCHEMA" in sql else None)
    ora_session.close = lambda: None  # type: ignore[attr-defined]
    monkeypatch.setattr(ora, "_connect", lambda: ora_session)
    assert ora.name_binding() == NameBinding(("TRAVEL",))
    assert ora_session.statements == ["SELECT sys_context('USERENV', 'CURRENT_SCHEMA') FROM sys.dual"]

    for default, style, expected in (
        ("dbo", 196609, NameBinding(("dbo",), ignores_case=True)),  # SQL_Latin1_General_CP1_CI_AS
        ("ocean", 0, NameBinding(("ocean", "dbo"))),  # a _CS_ / _BIN collation, a user's own default schema
    ):
        ms_session = _Session(answer=lambda _sql, _r=(default, style): _r)
        ms = _connector(mssql_module.MssqlConnector, "mssql", tmp_path)
        monkeypatch.setattr(ms, "_connect", lambda _s=ms_session: types.SimpleNamespace(cursor=lambda: _s,
                                                                                         close=lambda: None))
        assert ms.name_binding() == expected
        (sql,) = ms_session.statements
        assert sql.startswith("SELECT SCHEMA_NAME(), ") and "'ComparisonStyle'" in sql, sql

    statements: list[str] = []

    class _Module:
        def exec_immediate(self, _conn: Any, sql: str) -> str:
            statements.append(sql)
            return "stmt"

        def fetch_tuple(self, _stmt: Any) -> Any:
            return ("DB2INST1 ",)

        def close(self, _conn: Any) -> bool:
            return True

    import sys

    monkeypatch.setattr(db2_module, "open_module", lambda *_a, **_k: _Module())
    monkeypatch.setitem(sys.modules, "ibm_db_dbi", types.ModuleType("ibm_db_dbi"))
    d = _connector(db2_module.Db2Connector, "db2", tmp_path)
    monkeypatch.setattr(d, "_connect", lambda: "handle")
    monkeypatch.setattr(d, "_module", _Module(), raising=False)
    assert d.name_binding() == NameBinding(("DB2INST1",))
    assert statements == ["SELECT CURRENT SCHEMA FROM SYSIBM.SYSDUMMY1"]

    my = _connector(mysql_module.MySQLConnector, "mysql", tmp_path)
    assert my.name_binding() is None
