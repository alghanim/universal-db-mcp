"""Re-attack, round 1 (2026-09-28): catalog objects that hold credentials.

Under the production default security.allowed_system_schemas:
[information_schema], db_query read PostgreSQL's
information_schema.user_mapping_options and handed back a postgres_fdw user
mapping's remote password in clear, with the remote host and database from
foreign_server_options (live, udbmcp-postgres-db): a credential for another
database, not the names of tables and columns the opened catalog is for. A
per-connection allowlist did not help, since information_schema is opened
for every connection, and masking did not either: the secret sits in a
generic option_value column.

The class is every catalog object that stores authentication material, or
the stored connections to other servers made with it, on every engine: the
FDW option views and their catalogs, password hashes and verifiers,
database links, linked and federated servers, replication source settings
and named collections. Each is refused to every tool, whatever
allowed_system_schemas or allowed_schemas opens, and left out of listings,
as the views of other sessions' SQL are.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from sqlglot import exp, parse_one
from test_hardening_2026_09_27_qualified_names import _call, _call_error, _entries, _policy, _refused, _server

from universal_db_mcp.connectors.base import TableSummary
from universal_db_mcp.discovery.system_schemas import is_credential_view, is_session_sql_view
from universal_db_mcp.errors import ToolFailure
from universal_db_mcp.models.responses import ErrorCategory
from universal_db_mcp.security.sql_guard import SqlGuard, StaticResolver, sqlglot_dialect

# (engine, the schema that holds it, a statement reading it)
_CREDENTIALS = [
    # PostgreSQL: the FDW option views (a user mapping's password, a server's host and database),
    # readable by the mapped login itself, and the catalogs under them
    ("postgres", "information_schema",
     "SELECT option_name, option_value FROM information_schema.user_mapping_options"),
    ("postgres", "information_schema", "SELECT option_value FROM INFORMATION_SCHEMA.USER_MAPPING_OPTIONS"),
    ("postgres", "information_schema",
     "SELECT foreign_server_name, option_value FROM information_schema.foreign_server_options"),
    ("postgres", "information_schema", "SELECT option_value FROM information_schema.foreign_data_wrapper_options"),
    ("postgres", "information_schema", "SELECT umoptions FROM information_schema._pg_user_mappings"),
    ("postgres", "information_schema", "SELECT srvoptions FROM information_schema._pg_foreign_servers"),
    ("postgres", "information_schema", "SELECT fdwoptions FROM information_schema._pg_foreign_data_wrappers"),
    ("postgres", "pg_catalog", "SELECT srvname, umoptions FROM pg_catalog.pg_user_mappings"),
    ("postgres", "pg_catalog", "SELECT srvname, umoptions FROM pg_user_mappings"),  # pg_catalog is searched first
    ("postgres", "pg_catalog", "SELECT umoptions FROM pg_catalog.pg_user_mapping"),
    ("postgres", "pg_catalog", "SELECT srvoptions FROM pg_catalog.pg_foreign_server"),
    ("postgres", "pg_catalog", "SELECT fdwoptions FROM pg_foreign_data_wrapper"),
    # a foreign table's own options, and its columns': file_fdw's program, a Multicorn db_url
    # (re-attack, round 2: user:password in clear, readable with a grant on the table, and
    # pg_foreign_table with none)
    ("postgres", "information_schema",
     "SELECT foreign_table_name, option_name, option_value FROM information_schema.foreign_table_options"),
    ("postgres", "information_schema", "SELECT option_value FROM information_schema.column_options"),
    ("postgres", "information_schema", "SELECT ftoptions FROM information_schema._pg_foreign_tables"),
    ("postgres", "information_schema", "SELECT attfdwoptions FROM information_schema._pg_foreign_table_columns"),
    ("postgres", "pg_catalog", "SELECT ftrelid, ftoptions FROM pg_catalog.pg_foreign_table"),
    ("postgres", "pg_catalog", "SELECT ftoptions FROM pg_foreign_table"),
    # pg_hba.conf's authentication options: an LDAP bind password, RADIUS secrets (live, 17)
    ("postgres", "pg_catalog", "SELECT options FROM pg_catalog.pg_hba_file_rules"),
    # to a superuser login: every role's password verifier, a subscription's connection string
    ("postgres", "pg_catalog", "SELECT rolname, rolpassword FROM pg_catalog.pg_authid"),
    ("postgres", "pg_catalog", "SELECT usename, passwd FROM pg_shadow"),
    ("postgres", "pg_catalog", "SELECT subconninfo FROM pg_catalog.pg_subscription"),
    # MySQL and MariaDB: account hashes, FEDERATED servers' and a replica's source passwords in clear
    ("mysql", "mysql", "SELECT user, authentication_string FROM mysql.user"),
    ("mysql", "mysql", "SELECT Priv FROM mysql.global_priv"),
    ("mysql", "mysql", "SELECT Password FROM mysql.password_history"),
    ("mysql", "mysql", "SELECT Host, Username, Password FROM mysql.servers"),
    ("mysql", "mysql", "SELECT User_name, User_password FROM mysql.slave_master_info"),
    # the same source's host and account, as a database link's
    ("mysql", "performance_schema",
     "SELECT host, port, user FROM performance_schema.replication_connection_configuration"),
    # SQL Server: login hashes (live: sa's, to the sa login), linked servers' provider strings
    # and remote logins, the compatibility views of them (bound bare too) and their base tables
    ("mssql", "sys", "SELECT name, password_hash FROM sys.sql_logins"),
    ("mssql", "sys", "SELECT name, data_source, provider_string FROM sys.servers"),
    ("mssql", "sys", "SELECT srvname, providerstring FROM sys.sysservers"),
    ("mssql", "sys", "SELECT srvname, providerstring FROM sysservers"),
    ("mssql", "sys", "SELECT rmtpassword FROM dbo.sysoledbusers"),
    ("mssql", "sys", "SELECT remote_name FROM sys.linked_logins"),
    ("mssql", "sys", "SELECT remote_name FROM sys.remote_logins"),
    ("mssql", "sys", "SELECT pwdhash FROM sys.syslnklgns"),
    ("mssql", "sys", "SELECT pwdhash FROM sys.sysxlgns"),
    # Oracle: verifiers, link and scheduler passwords, and the export and Data Pump views of them
    # (EXU8USRU and EXU*LNKU are readable by PUBLIC: the account's own hash, its links' passwords)
    ("oracle", "sys", "SELECT name, password, spare4 FROM SYS.USER$"),
    ("oracle", "sys", "SELECT password FROM SYS.USER_HISTORY$"),
    ("oracle", "sys", "SELECT passwordx, authpwdx FROM SYS.LINK$"),
    ("oracle", "sys", "SELECT password FROM SYS.SCHEDULER$_CREDENTIAL"),
    ("oracle", "sys", "SELECT verifier FROM SYS.XS$VERIFIERS"),
    ("oracle", "sys", "SELECT name, passwd FROM SYS.EXU8USRU"),
    ("oracle", "sys", "SELECT name, passwd FROM SYS.EXU10LNKU"),
    ("oracle", "sys", "SELECT password, spare4 FROM SYS.KU$_USER_VIEW"),
    ("oracle", "sys", "SELECT passwordx FROM SYS.KU$_DBLINK_VIEW"),
    ("oracle", "sys", "SELECT db_link, host, username FROM ALL_DB_LINKS"),
    ("oracle", "sys", "SELECT db_link, password FROM USER_DB_LINKS"),
    ("oracle", "sys", "SELECT host FROM SYS.DBA_DB_LINKS"),
    # 23ai: every link's host and remote user again, to the catalog role
    ("oracle", "sys", 'SELECT owner, name, "USER", host FROM V$DATABASE_LINK'),
    ("oracle", "sys", 'SELECT host FROM SYS.V_$DATABASE_LINK'),
    ("oracle", "sys", 'SELECT host FROM GV$DATABASE_LINK'),
    ("oracle", "sys", 'SELECT host FROM SYS.GV_$DATABASE_LINK'),
    # Db2: federated user mappings, server and wrapper options, and z/OS outbound passwords
    ("db2", "syscat", "SELECT servername, option, setting FROM SYSCAT.USEROPTIONS"),
    ("db2", "syscat", "SELECT servername, setting FROM SYSCAT.SERVEROPTIONS"),
    ("db2", "syscat", "SELECT setting FROM SYSCAT.WRAPOPTIONS"),
    ("db2", "sysibm", "SELECT setting FROM SYSIBM.SYSUSEROPTIONS"),
    ("db2", "sysibm", "SELECT newauthid, password FROM SYSIBM.USERNAMES"),
    # ClickHouse: named collections, the stored connections (user, password, keys) of engines
    ("clickhouse", "system", "SELECT name, collection FROM system.named_collections"),
]


def _opened(engine: str, schema: str, sql: str, allowed: list[str], deny: bool) -> SqlGuard:
    """A guard whose policy opens the object's schema and whose resolver
    lists every table the statement names, in that schema: nothing but the
    new rule stands between the caller and the object."""
    tables = {(schema, t.name.lower()) for t in parse_one(sql, read=sqlglot_dialect(engine)).find_all(exp.Table)}
    policy = _policy(engine, allowed, deny=deny, system_schemas=[schema])
    return SqlGuard(engine, policy, StaticResolver(tables | {("app", "t")}))


@pytest.mark.parametrize(
    ("allowed", "deny"),
    [(["app"], True), (["app"], False), ([], True), ([], False)],
    ids=["allowlist-default-deny", "allowlist", "default-deny", "neither"],
)
@pytest.mark.parametrize(("engine", "schema", "sql"), _CREDENTIALS)
def test_catalog_objects_holding_credentials_are_always_refused(
    engine: str, schema: str, sql: str, allowed: list[str], deny: bool
) -> None:
    guard = _opened(engine, schema, sql, allowed, deny)
    for label, validate, prefix in _entries(guard):
        exc = _refused(validate, prefix + sql)
        assert exc.category == ErrorCategory.POLICY, (label, str(exc))
        assert "stored credentials" in str(exc) and "allowed_system_schemas" in str(exc), (label, str(exc))


@pytest.mark.parametrize(("engine", "schema", "sql"), _CREDENTIALS)
def test_the_policy_refuses_them_to_every_tool_and_the_listings_leave_them_out(
    engine: str, schema: str, sql: str
) -> None:
    table = next(parse_one(sql, read=sqlglot_dialect(engine)).find_all(exp.Table))
    policy = _policy(engine, [], system_schemas=[schema])
    for written in {table.db or schema, schema}:
        assert is_credential_view(engine, written, table.name), (written, table.name)
        assert is_session_sql_view(engine, written, table.name), (written, table.name)  # the listings' filter
        with pytest.raises(ToolFailure) as info:
            policy.check_object(written, table.name)
        assert info.value.category == ErrorCategory.POLICY
        assert "stored credentials" in str(info.value), str(info.value)


@pytest.mark.parametrize(
    ("engine", "schema", "sql"),
    [
        # the definitions without their options, and the catalogs' other views, stay readable
        ("postgres", "information_schema", "SELECT foreign_server_name FROM information_schema.foreign_servers"),
        ("postgres", "information_schema", "SELECT foreign_server_name FROM information_schema.user_mappings"),
        ("postgres", "information_schema", "SELECT foreign_table_name FROM information_schema.foreign_tables"),
        ("postgres", "information_schema", "SELECT table_name FROM information_schema.tables"),
        ("postgres", "pg_catalog", "SELECT rolname FROM pg_catalog.pg_roles"),  # rolpassword is always ********
        # a residual: attfdwoptions, a foreign table column's options, sits in the core catalog
        ("postgres", "pg_catalog", "SELECT attname, attnum FROM pg_catalog.pg_attribute"),
        ("mysql", "performance_schema", "SELECT channel_name FROM performance_schema.replication_connection_status"),
        ("oracle", "sys", "SELECT db_link, logged_on FROM SYS.V_$DBLINK"),  # the session's open links: no host or user
        ("mysql", "mysql", "SELECT name FROM mysql.help_topic"),
        ("mssql", "sys", "SELECT name FROM sys.server_principals"),
        ("oracle", "sys", "SELECT username FROM SYS.ALL_USERS"),
        ("db2", "syscat", "SELECT servername FROM SYSCAT.SERVERS"),
        ("clickhouse", "system", "SELECT name, auth_type FROM system.users"),  # no hash (live, 26.3)
    ],
)
def test_the_rest_of_an_opened_catalog_stays_readable(engine: str, schema: str, sql: str) -> None:
    guard = _opened(engine, schema, sql, ["app"], True)
    assert guard.validate_select(sql).kind == "select"


@pytest.mark.parametrize(
    ("engine", "schema", "name"),
    [
        ("postgres", "app", "user_mapping_options"),
        ("postgres", None, "user_mapping_options"),  # information_schema is not on the search path
        ("mysql", "app", "user"),
        ("mysql", None, "servers"),
        ("mssql", "dbo", "sql_logins"),
        ("mssql", "app", "servers"),
        ("oracle", "TRAVEL", "DBA_DB_LINKS"),
        ("oracle", "TRAVEL", "USER$"),
        ("db2", "APP", "USEROPTIONS"),
        ("clickhouse", "app", "named_collections"),
        ("sqlite", None, "pg_authid"),
    ],
)
def test_namesakes_elsewhere_are_ordinary_tables(engine: str, schema: str | None, name: str) -> None:
    assert not is_credential_view(engine, schema, name)
    assert not is_session_sql_view(engine, schema, name)


_FDW_CATALOG = [
    TableSummary("ocean", "buoys", "table"),
    TableSummary("information_schema", "tables", "table"),
    TableSummary("information_schema", "foreign_tables", "table"),
    TableSummary("information_schema", "user_mapping_options", "table"),
    TableSummary("information_schema", "foreign_server_options", "table"),
    TableSummary("information_schema", "foreign_data_wrapper_options", "table"),
    TableSummary("information_schema", "foreign_table_options", "table"),
    TableSummary("information_schema", "column_options", "table"),
]


@pytest.mark.parametrize("allowed", [[], ["ocean"]], ids=["production-default", "allowlist"])
def test_the_reattack_repro_under_production_defaults(tmp_path: Path, monkeypatch: Any, allowed: list[str]) -> None:
    """The finding as reported: no allowed_system_schemas in the config (the
    default opens information_schema), and db_query on the FDW option views.
    Refused before any statement reaches the database, and left out of the
    information_schema listing."""
    server, fake = _server(tmp_path, monkeypatch, "postgres", allowed, catalog=_FDW_CATALOG)
    for sql in (
        "SELECT authorization_identifier, foreign_server_name, option_name, option_value "
        "FROM information_schema.user_mapping_options",
        "SELECT foreign_server_name, option_name, option_value FROM information_schema.foreign_server_options",
        "SELECT * FROM information_schema.foreign_data_wrapper_options",
        # re-attack, round 2: a file_fdw table's program with the feed's password in it (live)
        "SELECT foreign_table_name, option_name, option_value FROM information_schema.foreign_table_options",
        "SELECT column_name, option_name, option_value FROM information_schema.column_options",
    ):
        text = _call_error(server, "db_query", {"connection_id": "remote", "sql": sql})
        assert "POLICY_VIOLATION" in text and "stored credentials" in text, (sql, text)
    for tool, args in (
        ("db_sample_table", {"connection_id": "remote", "object_name": "information_schema.user_mapping_options"}),
        ("db_profile_table",
         {"connection_id": "remote", "schema": "information_schema", "object_name": "foreign_server_options"}),
        ("db_sample_table", {"connection_id": "remote", "object_name": "information_schema.foreign_table_options"}),
        ("db_get_table",
         {"connection_id": "remote", "schema": "information_schema", "object_name": "column_options"}),
    ):
        text = _call_error(server, tool, args)
        assert "POLICY_VIOLATION" in text and "stored credentials" in text, (tool, text)
    tables = _call(server, "db_list_tables", {"connection_id": "remote", "schema": "information_schema"})
    assert sorted(t["name"] for t in tables["data"]["tables"]) == ["foreign_tables", "tables"]
    assert not [s for s in fake.statements if "option" in s.lower()], fake.statements
    # the opened catalog's other views still answer, the foreign tables' names too
    _call(server, "db_query", {"connection_id": "remote", "sql": "SELECT table_name FROM information_schema.tables"})
    _call(server, "db_query",
          {"connection_id": "remote", "sql": "SELECT foreign_table_name FROM information_schema.foreign_tables"})


@pytest.mark.parametrize("engine", ["postgres", "mysql"])
def test_the_connectors_leave_them_out_of_an_opened_catalog(monkeypatch: pytest.MonkeyPatch, engine: str) -> None:
    """The catalog listing itself (the connectors' list_tables over the engine's catalog): with the system
    schemas opened, their credential objects are not listed, and the rest is."""
    from test_hardening_2026_09_27_connectors_sql import _catalog_connector

    from universal_db_mcp.config import SecurityConfig

    if engine == "postgres":
        opened = ["information_schema", "pg_catalog"]
        rows = [("information_schema", "tables", "v", None), ("information_schema", "user_mapping_options", "v", None),
                ("information_schema", "foreign_server_options", "v", None), ("pg_catalog", "pg_class", "r", 400),
                ("information_schema", "foreign_table_options", "v", None),
                ("information_schema", "column_options", "v", None), ("pg_catalog", "pg_foreign_table", "r", 1),
                ("pg_catalog", "pg_hba_file_rules", "v", None),
                ("pg_catalog", "pg_authid", "r", 3), ("pg_catalog", "pg_user_mappings", "v", None),
                ("public", "orders", "r", 10)]
        kept = {("information_schema", "tables"), ("pg_catalog", "pg_class"), ("public", "orders")}
    else:
        opened = ["information_schema", "mysql"]
        rows = [("information_schema", "TABLES", "SYSTEM VIEW", None), ("mysql", "help_topic", "BASE TABLE", 3),
                ("mysql", "user", "BASE TABLE", 3), ("mysql", "servers", "BASE TABLE", 1),
                ("mysql", "slave_master_info", "BASE TABLE", 1), ("testdb", "orders", "BASE TABLE", 10)]
        kept = {("information_schema", "tables"), ("mysql", "help_topic"), ("testdb", "orders")}
    conn, _ = _catalog_connector(monkeypatch, engine, rows, SecurityConfig(allowed_system_schemas=opened))
    listed = {(t.schema, t.name.lower()) for t in conn.list_tables(None, {"table", "view"}, None)}
    assert listed == kept, listed


# ---- a synonym in a readable schema (re-attack, round 2) ---------------------
#
# The lists above match the name a statement writes. Without default-deny a
# name in a permitted schema was admitted as written, and a synonym there read
# what it names: SQL Server's dbo.w4rv_logins FOR sys.sql_logins handed back
# the login hashes, Oracle's TRAVEL.W4RV_LINKS FOR SYS.ALL_DB_LINKS every
# link's host and remote user (live), while db_list_synonyms left the same
# synonym out. Now each name a tool reads that the listing does not hold is
# looked up as a synonym (Db2: an alias), and what it names, to the end of its
# chain, is refused like the view itself.

# (engine, what the synonym names in turn: the refused view last)
_SYNONYM_CHAINS = [
    ("oracle", [("SYS", "ALL_DB_LINKS")], "stored credentials"),
    ("oracle", [("OCEAN", "HOP"), ("PUBLIC", "W4_LINKS"), ("SYS", "ALL_DB_LINKS")], "stored credentials"),
    ("oracle", [("SYS", "V_$SQL")], "other sessions' SQL"),
    ("oracle", [("SYS", "ALL_TAB_HISTOGRAMS")], "column statistics"),
    ("oracle", [("SYS", "ALL_TAB_COLUMNS")], "low and high values"),  # its columns are not checked through one
    ("mssql", [("sys", "sql_logins")], "stored credentials"),
    ("mssql", [(None, "sysservers")], "stored credentials"),  # master..sysservers
    ("mssql", [("sys", "dm_exec_requests")], "other sessions' SQL"),
    ("db2", [("SYSCAT", "USEROPTIONS")], "stored credentials"),
    ("db2", [("OCEAN", "B"), ("SYSCAT", "COLDIST")], "column statistics"),
]


def _synonym_server(
    tmp_path: Path, monkeypatch: Any, engine: str, chains: dict[tuple[str | None, str], list[Any]], *, deny: bool
) -> tuple[Any, Any, list[list[tuple[str | None, str]]]]:
    """The recording connector of _server under allowed_schemas [ocean], its
    synonyms answered from ``chains`` (keyed by the name as the engine looks
    it up), and every lookup recorded."""
    server, fake = _server(tmp_path, monkeypatch, engine, ["ocean"], deny=deny, second=True)
    asked: list[list[tuple[str | None, str]]] = []

    def synonym_chains(names: list[tuple[str | None, str]]) -> dict[tuple[str | None, str], list[Any]]:
        asked.append(list(names))
        return {n: chains[n] for n in names if n in chains}

    fake.synonym_chains = synonym_chains
    return server, fake, asked


def _w4_syn(engine: str) -> tuple[str, str]:
    """ocean.w4_syn as the engine looks it up, the tools' spelling of it:
    Oracle and Db2 fold the unquoted name to upper case."""
    return ("OCEAN", "W4_SYN") if engine in ("oracle", "db2") else ("ocean", "w4_syn")


@pytest.mark.parametrize(("engine", "chain", "refusal"), _SYNONYM_CHAINS)
def test_a_synonym_does_not_read_a_refused_view_without_default_deny(
    tmp_path: Path, monkeypatch: Any, engine: str, chain: list[Any], refusal: str
) -> None:
    syn = _w4_syn(engine)
    server, fake, asked = _synonym_server(tmp_path, monkeypatch, engine, {syn: chain}, deny=False)
    sql = "SELECT * FROM ocean.w4_syn"
    for tool, args in (
        ("db_query", {"connection_id": "remote", "sql": sql}),
        ("db_validate_query", {"connection_id": "remote", "sql": sql}),
        ("db_explain", {"connection_id": "remote", "sql": "EXPLAIN " + sql}),
        ("db_federated_join", {"left": {"connection": "remote", "sql": "SELECT buoy_id FROM ocean.buoys"},
                               "right": {"connection": "other", "sql": sql}, "on": [["buoy_id", "buoy_id"]]}),
        ("db_sample_table", {"connection_id": "remote", "schema": syn[0], "object_name": syn[1]}),
        ("db_profile_table", {"connection_id": "remote", "object_name": ".".join(syn)}),
        ("db_get_table", {"connection_id": "remote", "schema": syn[0], "object_name": syn[1]}),
    ):
        text = _call_error(server, tool, args)
        assert "POLICY_VIOLATION" in text and refusal in text, (tool, text)
        assert f"'{'.'.join(syn)}' is {'an alias' if engine == 'db2' else 'a synonym'} that reads" in text, text
        assert f"'{'.'.join(filter(None, chain[-1]))}'" in text, text
    env = _call(server, "db_federated_query", {"sql": sql, "connections": ["remote", "other"]})
    assert env["data"]["connections_run"] == 0
    assert all(refusal in r["error"] for r in env["data"]["results"])
    assert not [s for s in fake.statements + fake.plans if "w4_syn" in s.lower()]
    assert syn in {n for names in asked for n in names}


@pytest.mark.parametrize("engine", ["oracle", "mssql", "db2"])
def test_a_synonym_of_an_ordinary_table_still_reads_and_a_listed_table_is_not_looked_up(
    tmp_path: Path, monkeypatch: Any, engine: str
) -> None:
    syn = _w4_syn(engine)
    ocean, buoys = (syn[0], "BUOYS") if engine in ("oracle", "db2") else (syn[0], "buoys")
    server, fake, asked = _synonym_server(tmp_path, monkeypatch, engine, {syn: [(ocean, buoys)]}, deny=False)
    _call(server, "db_query", {"connection_id": "remote", "sql": "SELECT buoy_id FROM ocean.w4_syn"})
    _call(server, "db_sample_table", {"connection_id": "remote", "schema": syn[0], "object_name": syn[1]})
    assert [s for s in fake.statements if "w4_syn" in s.lower()], fake.statements
    asked.clear()
    # the listed table as the engine looks it up (the tools quote a name as given)
    _call(server, "db_query", {"connection_id": "remote", "sql": "SELECT buoy_id FROM ocean.buoys"})
    _call(server, "db_sample_table", {"connection_id": "remote", "schema": ocean, "object_name": buoys})
    assert asked == [], "a listed table is a table or a view: synonyms share its namespace"


@pytest.mark.parametrize("engine", ["oracle", "mssql", "db2"])
def test_with_default_deny_a_synonym_is_refused_as_unlisted_and_never_looked_up(
    tmp_path: Path, monkeypatch: Any, engine: str
) -> None:
    server, _fake, asked = _synonym_server(
        tmp_path, monkeypatch, engine, {("ocean", "w4_syn"): [("sys", "x")]}, deny=True
    )
    text = _call_error(server, "db_query", {"connection_id": "remote", "sql": "SELECT * FROM ocean.w4_syn"})
    assert "could not be resolved" in text, text
    text = _call_error(
        server, "db_sample_table", {"connection_id": "remote", "schema": "ocean", "object_name": "w4_syn"}
    )
    assert "not a permitted object" in text, text
    assert asked == []


@pytest.mark.parametrize("engine", ["postgres", "mysql", "clickhouse"])
def test_engines_without_synonyms_are_not_asked(tmp_path: Path, monkeypatch: Any, engine: str) -> None:
    server, _fake, asked = _synonym_server(tmp_path, monkeypatch, engine, {}, deny=False)
    # a table whose columns the catalog does not list may hold a masked
    # column: masking refuses the statement (owner decision, 2026-10-03)
    text = _call_error(server, "db_query", {"connection_id": "remote", "sql": "SELECT buoy_id FROM ocean.somewhere"})
    assert "columns of 'somewhere' are not known" in text, text
    assert asked == []


def test_the_chain_walk_follows_synonyms_by_folded_names_and_stops_at_a_cycle() -> None:
    from universal_db_mcp.connectors.driver_helpers import synonym_chains

    targets = {
        ("TRAVEL", "S2"): ("TRAVEL", "S1"),
        ("TRAVEL", "S1"): ("TRAVEL", "ALL_DB_LINKS"),  # no object: Oracle reads PUBLIC.ALL_DB_LINKS (live)
        ("PUBLIC", "ALL_DB_LINKS"): ("SYS", "ALL_DB_LINKS"),
        ("TRAVEL", "LOOP_A"): ("TRAVEL", "LOOP_B"),
        ("TRAVEL", "LOOP_B"): ("TRAVEL", "LOOP_A"),
        ("OTHER", "BARE"): ("SYS", "USER$"),
        ("TRAVEL", "REMOTE"): (None, "T"),  # a synonym of another database's object keeps no owner
        ("TRAVEL", "Quoted"): ("SYS", "LINK$"),
        ("TRAVEL", "TWIN"): ("SYS", "USER$"),  # namesakes once folded: each is followed
        ("TRAVEL", "twin"): ("TRAVEL", "FLIGHTS"),
    }
    chains = synonym_chains(
        [("travel", "s2"), ("TRAVEL", "LOOP_A"), (None, "bare"), ("TRAVEL", "REMOTE"), ("TRAVEL", "BUOYS"),
         ("TRAVEL", "quoted"), ("OTHER", "S2"), ("TRAVEL", "twin")],
        targets, str.upper, "PUBLIC",
    )
    assert _local(chains) == {
        ("travel", "s2"): [("TRAVEL", "S1"), ("TRAVEL", "ALL_DB_LINKS"), ("SYS", "ALL_DB_LINKS")],
        ("TRAVEL", "LOOP_A"): [("TRAVEL", "LOOP_B"), ("TRAVEL", "LOOP_A")],
        (None, "bare"): [("SYS", "USER$")],  # a bare name, of any schema
        ("TRAVEL", "REMOTE"): [(None, "T")],
        ("TRAVEL", "quoted"): [("SYS", "LINK$")],  # more spellings than the engine reads, never fewer
        ("TRAVEL", "twin"): [("SYS", "USER$"), ("TRAVEL", "FLIGHTS")],
    }


def _local(chains: dict[Any, list[Any]]) -> dict[Any, list[tuple[Any, str]]]:
    """``chains`` as (schema, name) pairs, each target this database's
    (SynonymTarget.elsewhere None)."""
    assert all(t.elsewhere is None for chain in chains.values() for t in chain), chains
    return {name: [(t.schema, t.name) for t in chain] for name, chain in chains.items()}


def _oracle_synonyms(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, rows: list[tuple[Any, ...]]) -> Any:
    from test_hardening_2026_09_28_converge_connectors import _connector, _Session

    from universal_db_mcp.connectors import oracle as oracle_module

    class _Synonyms(_Session):
        """sys.all_synonyms, every row: the Python walk picks the chain."""

        def __init__(self) -> None:
            super().__init__(rows=rows)
            self.binds: list[list[Any]] = []

        def execute(self, sql: str, *args: Any, **_k: Any) -> _Session:
            if "all_synonyms" in sql:
                self.binds.append(list(args[0]))
            return super().execute(sql)

    conn = _connector(oracle_module.OracleConnector, "oracle", tmp_path)
    session = _Synonyms()
    monkeypatch.setattr(conn, "_connect", lambda: session)
    return conn, session


def test_oracle_looks_synonyms_up_through_the_public_ones(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rows = [  # owner, synonym_name, table_owner, table_name, db_link
        ("TRAVEL", "W4_LINKS", "SYS", "ALL_DB_LINKS", None),
        ("TRAVEL", "W4_T2", "TRAVEL", "ALL_DB_LINKS", None),  # CREATE SYNONYM ... FOR ALL_DB_LINKS, by TRAVEL (live)
        ("PUBLIC", "ALL_DB_LINKS", "SYS", "ALL_DB_LINKS", None),
        ("PUBLIC", "W4_PUB", "SYS", "V_$SQL", None),
    ]
    conn, session = _oracle_synonyms(tmp_path, monkeypatch, rows)
    chains = conn.synonym_chains([("TRAVEL", "W4_LINKS"), ("TRAVEL", "W4_T2"), (None, "W4_PUB"), ("TRAVEL", "T")])
    assert _local(chains) == {
        ("TRAVEL", "W4_LINKS"): [("SYS", "ALL_DB_LINKS")],
        ("TRAVEL", "W4_T2"): [("TRAVEL", "ALL_DB_LINKS"), ("SYS", "ALL_DB_LINKS")],
        (None, "W4_PUB"): [("SYS", "V_$SQL")],
    }
    sql = next(s for s in session.statements if "all_synonyms" in s)
    assert "FROM sys.all_synonyms START WITH" in sql, sql
    assert "CONNECT BY NOCYCLE owner IN (PRIOR table_owner, 'PUBLIC') AND synonym_name = PRIOR table_name" in sql
    assert "PRIOR db_link IS NULL" in sql
    # each name as the statement looks it up, exactly; a bare one of any owner
    assert session.binds == [["W4_LINKS", "TRAVEL", "W4_T2", "TRAVEL", "W4_PUB", "T", "TRAVEL"]]
    assert sql.count("owner = :") == 3 and sql.count("owner IN (") == 1, sql  # three qualified starts, the walk


def test_oracle_looks_many_names_up_in_batches(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    conn, session = _oracle_synonyms(tmp_path, monkeypatch, [])
    assert conn.synonym_chains([("APP", f"T{n}") for n in range(450)]) == {}
    assert [len(b) for b in session.binds] == [400, 400, 100]


def test_db2_looks_aliases_up_public_ones_included(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import sys
    import types

    from test_hardening_2026_09_28_converge_connectors import _connector, _Db2Rows

    from universal_db_mcp.connectors import db2 as db2_module

    rows = [
        ("MOI     ", "W4_OPTS", "SYSCAT  ", "USEROPTIONS"),  # CHAR-padded, as SYSCAT returns them
        ("MOI", "A", "MOI", "B"),
        ("MOI", "B", "SYSCAT", "COLDIST"),
        ("SYSPUBLIC", "W4_PUB", "SYSIBM", "SYSUSEROPTIONS"),
    ]
    server = _Db2Rows(rows)
    monkeypatch.setattr(db2_module, "open_module", lambda *_a, **_k: server)
    monkeypatch.setitem(sys.modules, "ibm_db_dbi", types.ModuleType("ibm_db_dbi"))
    conn = _connector(db2_module.Db2Connector, "db2", tmp_path)
    chains = conn.synonym_chains([("MOI", "W4_OPTS"), ("MOI", "A"), (None, "W4_PUB"), ('MOI ', "B "), ("MOI", "T")])
    assert _local(chains) == {
        ("MOI", "W4_OPTS"): [("SYSCAT", "USEROPTIONS")],
        ("MOI", "A"): [("MOI", "B"), ("SYSCAT", "COLDIST")],
        (None, "W4_PUB"): [("SYSIBM", "SYSUSEROPTIONS")],
        ("MOI ", "B "): [("SYSCAT", "COLDIST")],  # Db2 drops a delimited name's trailing blanks
    }
    assert server.statements[-1] == (
        "SELECT TABSCHEMA, TABNAME, BASE_TABSCHEMA, BASE_TABNAME FROM SYSCAT.TABLES WHERE TYPE = 'A'"
    )


def test_mssql_looks_synonyms_up_by_their_base_objects_parts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import types

    from test_hardening_2026_09_28_converge_connectors import _connector, _Session

    from universal_db_mcp.connectors import mssql as mssql_module

    # the index of the name SQL Server binds to the synonym, SCHEMA_NAME(schema_id), name, the base object's
    # server and other database, and its schema and name (as OBJECT_ID binds them in this database, else
    # PARSENAME's), live; connected to master here
    rows = [
        (0, "dbo", "w4_logins", None, None, "sys", "sql_logins"),  # the collation ignores case
        (1, "dbo", "w4_servers", None, None, "sys", "sysservers"),  # [master]..[sysservers]
        (2, "dbo", "w4_upper", None, None, "sys", "SQL_LOGINS"),  # [master].[sys].[SQL_LOGINS]
    ]
    session = _Session(rows=rows)
    conn = _connector(mssql_module.MssqlConnector, "mssql", tmp_path)
    monkeypatch.setattr(conn, "_connect", lambda: types.SimpleNamespace(cursor=lambda: session, close=lambda: None))
    chains = conn.synonym_chains([("DBO", "W4_Logins"), ("dbo", "w4_servers"), (None, "w4_upper"), ("dbo", "t")])
    assert _local(chains) == {
        ("DBO", "W4_Logins"): [("sys", "sql_logins")],
        ("dbo", "w4_servers"): [("sys", "sysservers")],
        (None, "w4_upper"): [("sys", "SQL_LOGINS")],
    }
    (sql,) = session.statements
    assert sql.startswith("SELECT v.i, SCHEMA_NAME(s.schema_id), s.name, PARSENAME(s.base_object_name, 4), ") and (
        sql.endswith("CROSS APPLY (SELECT CASE WHEN PARSENAME(s.base_object_name, 4) IS "
                     "NULL AND NULLIF(PARSENAME(s.base_object_name, 3), DB_NAME()) IS NULL THEN "
                     "OBJECT_ID(s.base_object_name) END AS id) AS b")
    ), sql
    for chain in chains.values():
        with pytest.raises(ToolFailure, match="stored credentials"):
            from universal_db_mcp.security.policy import check_not_session_sql

            check_not_session_sql("mssql", chain[-1].schema, chain[-1].name)


def test_oracle_synonym_listing_follows_a_target_that_is_no_object_to_the_public_synonym(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TRAVEL's CREATE SYNONYM W4FX_T2 FOR ALL_DB_LINKS keeps TRAVEL.ALL_DB_LINKS
    as its target, which Oracle reads as the PUBLIC synonym (live): the
    listing leaves it out as the query tools refuse it."""
    rows = [
        ("TRAVEL", "W4FX_T2", "TRAVEL", "ALL_DB_LINKS", None),
        ("TRAVEL", "W4FX_OK", "TRAVEL", "FLIGHTS", None),
        ("PUBLIC", "ALL_DB_LINKS", "SYS", "ALL_DB_LINKS", None),
    ]
    conn, session = _oracle_synonyms(tmp_path, monkeypatch, rows)
    for schema in ("TRAVEL", None):
        assert [(s.schema, s.name) for s in conn.list_synonyms(schema)] == [("TRAVEL", "W4FX_OK")], schema
    listing = next(s for s in session.statements if "START WITH owner = :1" in s)
    assert "CONNECT BY NOCYCLE owner IN (PRIOR table_owner, 'PUBLIC')" in listing, listing
