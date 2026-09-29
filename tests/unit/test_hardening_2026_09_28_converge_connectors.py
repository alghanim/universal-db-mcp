"""Connector convergence (wave 4, 2026-09-28): classes of defects, not repros.

1. What changes how a server reads statement text is held, on every
   connection, at what the SQL guard parses under, and checked there: a
   connection where it cannot be held is refused, naming its own cause.
   MySQL/MariaDB sql_mode and client character set, PostgreSQL
   standard_conforming_strings and client_encoding, SQL Server
   QUOTED_IDENTIFIER, Db2's SQL_COMPAT and ClickHouse's dialect and
   name-binding settings. Oracle and SQLite have no such session setting.
2. Oracle never reads through a database link (a q'...' literal, which
   sqlglot does not read, makes any '@' count), never vouches for a DUAL
   named with one, and names the SYS object of every dictionary view it reads.
3. No catalog listing names a view the policy refuses whatever the allowlists
   open: other sessions' SQL, and column statistics (a column's values), not
   through a chain of synonyms or aliases either.

The fakes model what the server does with each statement where that is the
question (a site's sql_mode, a proxy that drops a SET); the live checks on
the loopback fixtures are in the wave report.
"""

from __future__ import annotations

import re
import sys
import types
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import sqlglot
from sqlglot import exp

from universal_db_mcp.config import ConnectionConfig, ResolvedConnection, SecurityConfig
from universal_db_mcp.connectors import clickhouse as ch_module
from universal_db_mcp.connectors import db2 as db2_module
from universal_db_mcp.connectors import mssql as mssql_module
from universal_db_mcp.connectors import mysql as mysql_module
from universal_db_mcp.connectors import oracle as oracle_module
from universal_db_mcp.connectors import postgres as pg_module
from universal_db_mcp.connectors.base import ConnectorError, QuerySpec
from universal_db_mcp.discovery.system_schemas import is_session_sql_view
from universal_db_mcp.security.policy import EffectivePolicy


def _resolved(engine: str, tmp_path: Path, **extra: Any) -> ResolvedConnection:
    body: dict[str, Any] = {"type": engine, "host": "h", "database": "d"}
    for field, value in (("username_file", "app_ro"), ("password_file", "s3cret")):
        p = tmp_path / f"{engine}.{field}"
        p.write_text(value + "\n", encoding="utf-8")
        p.chmod(0o600)
        body[field] = str(p)
    body.update(extra)
    return ResolvedConnection("c", ConnectionConfig.model_validate(body))


def _connector(cls: Any, engine: str, tmp_path: Path, security: SecurityConfig | None = None, **extra: Any) -> Any:
    resolved = _resolved(engine, tmp_path, **extra)
    return cls(resolved, EffectivePolicy.build(security or SecurityConfig(), resolved))


class _Session:
    """A connection and cursor in one (PyMySQL, psycopg and pyodbc shapes):
    ``on(sql)`` runs each statement (it may raise, or change the state);
    ``answer(sql)`` is its one row."""

    def __init__(
        self,
        on: Callable[[str], None] = lambda _sql: None,
        answer: Callable[[str], Any] = lambda _sql: None,
        rows: list[tuple[Any, ...]] | None = None,
    ) -> None:
        self.statements: list[str] = []
        self._on = on
        self._answer = answer
        self._rows = rows or []
        self._last = ""
        self.description: list[Any] = []
        self.version = "19.3.0.0.0"

    def execute(self, sql: str, *_a: Any, **_k: Any) -> _Session:
        self.statements.append(sql)
        self._on(sql)
        self._last = sql
        return self

    def fetchone(self) -> Any:
        return self._answer(self._last)

    def fetchall(self) -> list[Any]:
        row = self._answer(self._last)
        return [row] if row is not None else list(self._rows)

    def cursor(self, *_a: Any, **_k: Any) -> _Session:
        return self

    def __enter__(self) -> _Session:
        return self

    def __exit__(self, *_a: Any) -> None:
        return None

    def close(self) -> None:
        return None

    def rollback(self) -> None:
        return None


# ------------------------------------------------------------ 1. MySQL sql_mode


def _mysql_eval(node: exp.Expression, state: dict[str, str]) -> Any:
    """The value MySQL gives the connector's sql_mode expressions (the
    functions they use, as MySQL defines them)."""
    if isinstance(node, exp.Literal):
        return node.this
    if isinstance(node, exp.Null):
        return None
    if isinstance(node, exp.SessionParameter):
        return state[node.name.lower()]
    if isinstance(node, exp.Concat):
        return "".join(str(_mysql_eval(e, state)) for e in node.expressions)
    if isinstance(node, exp.Replace):
        return str(_mysql_eval(node.this, state)).replace(
            str(_mysql_eval(node.expression, state)), str(_mysql_eval(node.args["replacement"], state))
        )
    if isinstance(node, exp.Trim):
        assert str(node.args.get("position")).upper() == "BOTH"
        return str(_mysql_eval(node.this, state)).strip(str(_mysql_eval(node.expression, state)))
    if isinstance(node, exp.Anonymous) and node.name.upper() == "FIND_IN_SET":
        needle, haystack = (str(_mysql_eval(e, state)) for e in node.expressions)
        items = haystack.split(",") if haystack else []
        return items.index(needle) + 1 if needle in items else 0
    if isinstance(node, exp.Or):
        return bool(_mysql_eval(node.this, state)) or bool(_mysql_eval(node.expression, state))
    if isinstance(node, exp.NEQ):
        return _mysql_eval(node.this, state) != _mysql_eval(node.expression, state)
    if isinstance(node, exp.If):
        branch = node.args["true"] if _mysql_eval(node.this, state) else node.args["false"]
        return _mysql_eval(branch, state)
    raise AssertionError(f"the fake does not evaluate {type(node).__name__}")


class _MySQLServer:
    """A MySQL session: ``SET SESSION sql_mode = <expr>`` is evaluated
    against the session's variables, and a NULL is refused as MySQL refuses
    it (ER_WRONG_VALUE_FOR_VAR); ``honours_set`` False models a proxy that
    answers OK and changes nothing, ``honours_names`` False the same for SET
    NAMES."""

    def __init__(
        self, sql_mode: str, charset: str = "utf8mb4", honours_set: bool = True, honours_names: bool = True
    ) -> None:
        self.state = {"sql_mode": sql_mode, "character_set_client": charset}
        self.honours_set = honours_set
        self.honours_names = honours_names

    def on(self, sql: str) -> None:
        if sql == "SET NAMES utf8mb4":
            if self.honours_names:
                self.state["character_set_client"] = "utf8mb4"
            return
        match = re.fullmatch(r"SET SESSION sql_mode = (.+)", sql, flags=re.DOTALL)
        if match is None:
            return
        value = _mysql_eval(sqlglot.parse_one("SELECT " + match.group(1), read="mysql").expressions[0], self.state)
        if value is None:
            raise RuntimeError("(1231, \"Variable 'sql_mode' can't be set to the value of 'NULL'\")")
        if self.honours_set:
            self.state["sql_mode"] = value


def _mysql(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, server: _MySQLServer) -> tuple[Any, _Session]:
    session = _Session(on=server.on)
    fake = types.SimpleNamespace(connect=lambda **_kw: session, cursors=types.SimpleNamespace(SSCursor=object))
    monkeypatch.setattr(mysql_module, "open_module", lambda *_a, **_k: fake)
    return _connector(mysql_module.MySQLConnector, "mysql", tmp_path), session


_SITE_MODES = [
    # MySQL 9.7 spells SET sql_mode = 'ANSI' this way (live, 2026-09-28)
    "REAL_AS_FLOAT,PIPES_AS_CONCAT,ANSI_QUOTES,IGNORE_SPACE,ONLY_FULL_GROUP_BY,ANSI",
    "ANSI_QUOTES",
    "NO_BACKSLASH_ESCAPES",
    "STRICT_TRANS_TABLES,NO_BACKSLASH_ESCAPES,NO_ENGINE_SUBSTITUTION",
    "PIPES_AS_CONCAT,HIGH_NOT_PRECEDENCE",
    # MariaDB's SET sql_mode = 'ORACLE'
    "PIPES_AS_CONCAT,ANSI_QUOTES,IGNORE_SPACE,ORACLE,NO_KEY_OPTIONS,NO_TABLE_OPTIONS,NO_FIELD_OPTIONS",
]


@pytest.mark.parametrize("site_mode", _SITE_MODES)
def test_mysql_session_drops_the_sql_mode_flags_that_change_how_text_is_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, site_mode: str
) -> None:
    """Live (review, 2026-09-28): under NO_BACKSLASH_ESCAPES, 'a\\', INFO
    FROM information_schema.PROCESSLIST #' read one string to the guard and
    ran as a read of PROCESSLIST; under ANSI_QUOTES "taster" was a masked
    column the guard read as a string."""
    server = _MySQLServer(site_mode)
    conn, session = _mysql(tmp_path, monkeypatch, server)
    conn._connect()
    kept = server.state["sql_mode"].split(",") if server.state["sql_mode"] else []
    lexing = {"ANSI", "ANSI_QUOTES", "NO_BACKSLASH_ESCAPES", "PIPES_AS_CONCAT", "HIGH_NOT_PRECEDENCE", "ORACLE"}
    assert not lexing & set(kept), kept
    assert kept == [f for f in site_mode.split(",") if f not in lexing], "the site's other flags stay"
    assert session.statements[0].startswith("SET SESSION sql_mode"), "held before anything else runs"
    assert any(a.startswith("sql_mode") for a in conn.session_status["applied"])


def test_mysql_session_keeps_a_default_sql_mode_as_it_is(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    default = "ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO"
    server = _MySQLServer(default)
    conn, _ = _mysql(tmp_path, monkeypatch, server)
    conn._connect()
    assert server.state["sql_mode"] == default


@pytest.mark.parametrize(
    ("server", "cause", "not_cause"),
    [
        # a proxy that answers OK and changes nothing
        (_MySQLServer("ANSI_QUOTES", honours_set=False), "an sql_mode without ANSI", "character set"),
        # a backslash can be a GBK character's second byte
        (_MySQLServer("", charset="gbk", honours_names=False), "the utf8mb4 client character set", "sql_mode"),
    ],
    ids=["set-not-held", "client-charset"],
)
def test_mysql_session_that_does_not_read_text_as_the_guard_does_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, server: _MySQLServer, cause: str, not_cause: str
) -> None:
    """Each refusal names its own cause (review, 2026-09-28: a character
    set refusal sent the operator to sql_mode)."""
    conn, session = _mysql(tmp_path, monkeypatch, server)
    with pytest.raises(ConnectorError) as err:
        conn._connect()
    assert "read statements differently from the SQL guard" in str(err.value), str(err.value)
    head = str(err.value).split(" for the session")[0]
    assert cause in head and not_cause not in head, str(err.value)
    assert not any("READ ONLY" in s for s in session.statements), "refused before the session is used"


@pytest.mark.parametrize("charset", ["latin1", "utf8mb3", "gbk", "sjis"])
def test_mysql_session_reads_text_in_utf8mb4(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, charset: str) -> None:
    """A session left in another client character set (init_command; live,
    MySQL 9.7: SET NAMES utf8mb3 and latin1 were refused as an sql_mode
    fault) is put back in utf8mb4, the character set PyMySQL encodes in."""
    server = _MySQLServer("", charset=charset)
    conn, session = _mysql(tmp_path, monkeypatch, server)
    conn._connect()
    assert server.state["character_set_client"] == "utf8mb4"
    assert "character_set_client=utf8mb4" in conn.session_status["applied"]
    names = session.statements.index("SET NAMES utf8mb4")
    assert names < next(i for i, s in enumerate(session.statements) if "READ ONLY" in s)


def test_mysql_session_whose_server_refuses_the_sql_mode_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(sql: str) -> None:
        if "sql_mode" in sql:
            raise RuntimeError("(1227, 'Access denied')")

    session = _Session(on=refuse)
    fake = types.SimpleNamespace(connect=lambda **_kw: session, cursors=types.SimpleNamespace(SSCursor=object))
    monkeypatch.setattr(mysql_module, "open_module", lambda *_a, **_k: fake)
    conn = _connector(mysql_module.MySQLConnector, "mysql", tmp_path)
    with pytest.raises(ConnectorError, match="sql_mode"):
        conn._connect()


def test_mysql_session_readback_reports_the_sql_mode(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    answers = {"sql_mode": ("STRICT_TRANS_TABLES",), "character_set_client": ("utf8mb4",)}
    session = _Session(answer=lambda sql: next((v for k, v in answers.items() if k in sql), ("x",)))
    conn = _connector(mysql_module.MySQLConnector, "mysql", tmp_path)
    readback = conn._session_readback(session)
    assert readback["sql_mode"] == "STRICT_TRANS_TABLES"
    assert readback["character_set_client"] == "utf8mb4"


# --------------------------------------------- 1. PostgreSQL standard_conforming_strings


class _PgServer:
    """A PostgreSQL session: SET changes the session's settings, a
    backslash before a string's closing quote is an unterminated string
    unless standard_conforming_strings is on, and CAST(NULLIF(
    current_setting('client_encoding'), 'UTF8') AS integer) fails unless the
    session decodes statements as UTF-8. ``honours_encoding`` False models a
    session whose client_encoding does not change (a pooler)."""

    def __init__(
        self,
        conforming: str = "off",
        honours_set: bool = True,
        refuse_set: bool = False,
        encoding: str = "UTF8",
        honours_encoding: bool = True,
    ) -> None:
        self.settings = {
            "standard_conforming_strings": conforming,
            "backslash_quote": "on",
            "client_encoding": encoding,
        }
        self.honours_set = honours_set
        self.refuse_set = refuse_set
        self.honours_encoding = honours_encoding

    def on(self, sql: str) -> None:
        for name, value in re.findall(r"SET (\w+) = '?(\w+)'?", sql):
            if name in self.settings:
                if self.refuse_set:
                    raise RuntimeError(f'permission denied to set parameter "{name}"')
                if self.honours_set and (name != "client_encoding" or self.honours_encoding):
                    self.settings[name] = value
        if "\\'" in sql and self.settings["standard_conforming_strings"] != "on":
            raise RuntimeError("unterminated quoted string at or near \"'udbmcp\\'\"")
        encoding = self.settings["client_encoding"]
        if "NULLIF(current_setting('client_encoding'), 'UTF8')" in sql and encoding != "UTF8":
            raise RuntimeError(f'invalid input syntax for type integer: "{encoding}"')


def _pg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, server: _PgServer) -> tuple[Any, _Session]:
    session = _Session(on=server.on)
    fake = types.SimpleNamespace(connect=lambda **_kw: session)
    monkeypatch.setattr(pg_module, "open_module", lambda *_a, **_k: fake)
    return _connector(pg_module.PostgresConnector, "postgres", tmp_path), session


def test_postgres_session_reads_backslashes_as_the_guard_does(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """With standard_conforming_strings off (a role's or database's setting),
    'x\\', ' , secret FROM t --' is one string to the server where the guard
    reads two literals and nothing else (live, PostgreSQL 17)."""
    server = _PgServer(conforming="off")
    conn, session = _pg(tmp_path, monkeypatch, server)
    conn._connect()
    assert server.settings == {
        "standard_conforming_strings": "on",
        "backslash_quote": "safe_encoding",
        "client_encoding": "UTF8",
    }
    assert "SET standard_conforming_strings = on" in session.statements[0], "held before anything else runs"
    assert any(a.startswith("standard_conforming_strings") for a in conn.session_status["applied"])


def test_postgres_session_decodes_statements_as_utf8(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """With client_encoding SJIS (a role's or database's setting), psycopg
    encodes the guard's '¥' as the byte 0x5C, a backslash to the server
    (review, live, PostgreSQL 17: SELECT '¥' returned '\\', and
    length(E'¥n') was 1, a newline escape)."""
    server = _PgServer(encoding="SJIS")
    conn, session = _pg(tmp_path, monkeypatch, server)
    conn._connect()
    assert server.settings["client_encoding"] == "UTF8"
    assert "client_encoding=UTF8" in conn.session_status["applied"]
    pinned = next(i for i, s in enumerate(session.statements) if "client_encoding = 'UTF8'" in s)
    assert pinned < next(i for i, s in enumerate(session.statements) if "read_only" in s)


@pytest.mark.parametrize(
    ("server", "cause"),
    [
        (_PgServer(honours_set=False), "standard_conforming_strings"),
        (_PgServer(refuse_set=True), "standard_conforming_strings"),
        (_PgServer(conforming="on", encoding="SJIS", honours_encoding=False), "the UTF8 client encoding"),
    ],
    ids=["set-not-held", "set-refused", "encoding-not-held"],
)
def test_postgres_session_that_does_not_read_text_as_the_guard_does_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, server: _PgServer, cause: str
) -> None:
    conn, session = _pg(tmp_path, monkeypatch, server)
    with pytest.raises(ConnectorError) as err:
        conn._connect()
    assert cause in str(err.value).split(" for the session")[0], str(err.value)
    assert "read statements differently from the SQL guard" in str(err.value)
    assert not any("read_only" in s for s in session.statements), "refused before the session is used"


def test_postgres_session_whose_driver_encodes_in_another_codec_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """psycopg encodes each statement in the codec of the client_encoding
    the server last reported; one that is not UTF-8 there (a proxy that does
    not pass the report on) writes other bytes than the guard read."""
    conn, session = _pg(tmp_path, monkeypatch, _PgServer(conforming="on"))
    session.info = types.SimpleNamespace(encoding="shift_jis")  # type: ignore[attr-defined]
    with pytest.raises(ConnectorError) as err:
        conn._connect()
    assert "the UTF8 client encoding" in str(err.value) and "shift_jis" in str(err.value)
    session.info = types.SimpleNamespace(encoding="utf-8")  # type: ignore[attr-defined]
    conn._connect()


def test_postgres_session_readback_reports_the_client_encoding(tmp_path: Path) -> None:
    row = ("on", "60s", "5s", "udbmcp:c", "read committed", "on", "UTF8")
    conn = _connector(pg_module.PostgresConnector, "postgres", tmp_path)
    readback = conn._session_readback(_Session(answer=lambda _sql: row))
    assert readback["standard_conforming_strings"] == "on" and readback["client_encoding"] == "UTF8"


# ---------------------------------------------------- 1. SQL Server QUOTED_IDENTIFIER


class _MssqlServer:
    """QUOTED_IDENTIFIER as the session holds it: OFF under a DSN's
    QuotedId=No (live: "name" was then the string 'name')."""

    def __init__(self, quoted_identifier: bool, honours_set: bool = True) -> None:
        self.quoted_identifier = quoted_identifier
        self.honours_set = honours_set

    def on(self, sql: str) -> None:
        for statement in sql.split(";"):
            statement = statement.strip()
            if statement == "SET QUOTED_IDENTIFIER ON" and self.honours_set:
                self.quoted_identifier = True
            if statement.startswith("IF SESSIONPROPERTY('QUOTED_IDENTIFIER') <> 1") and not self.quoted_identifier:
                raise RuntimeError("[42000] QUOTED_IDENTIFIER is OFF (50000) (SQLExecDirectW)")


def _mssql(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, server: _MssqlServer) -> tuple[Any, _Session]:
    session = _Session(on=server.on)
    fake = types.SimpleNamespace(
        connect=lambda *_a, **_k: session, drivers=lambda: ["ODBC Driver 18 for SQL Server"], pooling=True
    )
    monkeypatch.setattr(mssql_module, "open_module", lambda *_a, **_k: fake)
    return _connector(mssql_module.MssqlConnector, "mssql", tmp_path), session


def test_mssql_session_reads_double_quotes_as_identifiers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    server = _MssqlServer(quoted_identifier=False)
    conn, _ = _mssql(tmp_path, monkeypatch, server)
    conn._connect()
    assert server.quoted_identifier is True
    assert any(a.startswith("quoted_identifier") for a in conn.session_status["applied"])


def test_mssql_session_that_does_not_hold_quoted_identifier_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    conn, _ = _mssql(tmp_path, monkeypatch, _MssqlServer(quoted_identifier=False, honours_set=False))
    with pytest.raises(ConnectorError) as err:
        conn._connect()
    assert "QUOTED_IDENTIFIER" in str(err.value) and "read statements differently" in str(err.value)


# ------------------------------------------------------------------- 1. Db2 SQL_COMPAT


class _Db2Server:
    """ibm_db stand-in holding SYSIBM.SQL_COMPAT: 'NPS' (a connect procedure
    set it) makes '#' an operator and lets an expression name a select-list
    alias (live, Db2 11.5.9); ``absent`` is a release before 11.1."""

    def __init__(self, compat: str | None = "NPS", absent: bool = False, refuse: bool = False) -> None:
        self.compat = compat
        self.absent = absent
        self.refuse = refuse
        self.statements: list[str] = []

    def connect(self, *_a: Any, **_k: Any) -> str:
        return "handle"

    def exec_immediate(self, _conn: Any, sql: str) -> str:
        self.statements.append(sql)
        if "SQL_COMPAT" in sql:
            if self.absent:
                raise RuntimeError(
                    '[IBM][CLI Driver][DB2/LINUXX8664] SQL0206N  "SYSIBM.SQL_COMPAT" is not valid in the '
                    "context where it is used.  SQLSTATE=42703 SQLCODE=-206"
                )
            if self.refuse:
                raise RuntimeError("SQL0551N  The statement failed: no WRITE privilege.  SQLSTATE=42501 SQLCODE=-551")
            self.compat = re.search(r"'(\w+)'", sql).group(1)  # type: ignore[union-attr]
        return "stmt"

    def close(self, _conn: Any) -> bool:
        return True


def _db2(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, server: _Db2Server) -> Any:
    monkeypatch.setattr(db2_module, "open_module", lambda *_a, **_k: server)
    monkeypatch.setitem(sys.modules, "ibm_db_dbi", types.ModuleType("ibm_db_dbi"))
    return _connector(db2_module.Db2Connector, "db2", tmp_path)


def test_db2_session_leaves_netezza_compatibility(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    server = _Db2Server(compat="NPS")
    conn = _db2(tmp_path, monkeypatch, server)
    conn._connect()
    assert server.compat == "DB2"
    assert "SET SYSIBM.SQL_COMPAT = 'DB2'" in server.statements, "qualified: a user variable cannot stand in"
    assert any(a.startswith("sql_compat") for a in conn.session_status["applied"])


def test_db2_release_without_sql_compat_has_nothing_to_leave(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    conn = _db2(tmp_path, monkeypatch, _Db2Server(absent=True))
    assert conn._connect() == "handle"
    assert any(s.startswith("sql_compat") for s in conn.session_status["skipped"])


def test_db2_session_that_cannot_leave_netezza_compatibility_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    conn = _db2(tmp_path, monkeypatch, _Db2Server(refuse=True))
    with pytest.raises(ConnectorError) as err:
        conn._connect()
    assert "SQL_COMPAT" in str(err.value) and "read statements differently" in str(err.value)


# ------------------------------------------------- 1. ClickHouse dialect and friends


class _Setting:
    def __init__(self, value: str, readonly: int = 0) -> None:
        self.value = value
        self.readonly = readonly


class _CHClient:
    """server_settings as system.settings reports the account's profile;
    set_client_setting keeps a setting for every request (``drops`` models
    a driver that drops it, as clickhouse-connect does for a readonly one
    under invalid_setting_action 'drop')."""

    def __init__(self, settings: dict[str, _Setting], drops: bool = False) -> None:
        self.server_settings = settings
        self.params: dict[str, str] = {}
        self.drops = drops

    def set_client_setting(self, name: str, value: Any) -> None:
        setting = self.server_settings.get(name)
        if setting is not None and setting.readonly and not self.drops:
            raise RuntimeError(f"Setting {name} is readonly")
        if not self.drops:
            self.params[name] = str(value)

    def get_client_setting(self, name: str) -> str | None:
        return self.params.get(name)

    def close(self) -> None:
        return None


def _ch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, client: _CHClient) -> Any:
    fake = types.SimpleNamespace(get_client=lambda **_kw: client)
    monkeypatch.setattr(ch_module, "open_module", lambda *_a, **_k: fake)
    return _connector(ch_module.ClickHouseConnector, "clickhouse", tmp_path, port=8123)


@pytest.mark.parametrize(
    ("name", "profile", "default"),
    [
        ("dialect", "prql", "clickhouse"),
        ("dialect", "kusto", "clickhouse"),
        ("dialect", "polyglot", "clickhouse"),
        ("implicit_select", "1", "0"),
        ("prefer_column_name_to_alias", "1", "0"),
        ("enable_global_with_statement", "0", "1"),
        ("enable_global_with_statement", "false", "1"),
        ("analyzer_compatibility_join_using_top_level_identifier", "1", "0"),
    ],
)
def test_clickhouse_holds_the_settings_that_decide_how_text_is_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, profile: str, default: str
) -> None:
    """dialect reads the text as another language; implicit_select runs a
    bare expression; prefer_column_name_to_alias binds a name the select list
    aliases to the table's column (live, 26.3: SELECT dummy + 1 AS dummy,
    dummy AS d gave d = 0 instead of 1); enable_global_with_statement=0 binds
    a subquery's name to the table, not the CTE the guard reads (review,
    live, 26.3: WITH subscribers AS (...) SELECT * FROM (SELECT * FROM
    subscribers) read telecom.subscribers, tables [] to the guard); the
    analyzer_compatibility setting binds JOIN USING names to select-list
    aliases."""
    client = _CHClient({"readonly": _Setting("0"), name: _Setting(profile)})
    conn = _ch(tmp_path, monkeypatch, client)
    conn._connect()
    assert client.params[name] == default
    assert f"{name}={default}" in conn.session_status["applied"]


def test_clickhouse_sends_nothing_for_a_profile_already_at_the_defaults(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A readonly=1 profile (the documented account) takes no setting at all."""
    client = _CHClient(
        {
            "readonly": _Setting("1", readonly=1),
            "dialect": _Setting("clickhouse", readonly=1),
            "implicit_select": _Setting("0", readonly=1),
            "prefer_column_name_to_alias": _Setting("0", readonly=1),
            "enable_global_with_statement": _Setting("1", readonly=1),
            "analyzer_compatibility_join_using_top_level_identifier": _Setting("0", readonly=1),
        }
    )
    _ch(tmp_path, monkeypatch, client)._connect()
    assert client.params == {}


def test_clickhouse_server_without_the_settings_reads_text_the_default_way(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _CHClient({"readonly": _Setting("0")})
    _ch(tmp_path, monkeypatch, client)._connect()
    assert set(client.params) == {"readonly", "max_execution_time"}


@pytest.mark.parametrize(
    ("client", "name"),
    [
        (_CHClient({"readonly": _Setting("1", readonly=1), "dialect": _Setting("kusto", readonly=1)}), "dialect"),
        (_CHClient({"readonly": _Setting("0"), "dialect": _Setting("prql")}, drops=True), "dialect"),
        # also what a readonly profile's compatibility <= 21.x reports (live, 26.3)
        (
            _CHClient(
                {"readonly": _Setting("1", readonly=1), "enable_global_with_statement": _Setting("0", readonly=1)}
            ),
            "enable_global_with_statement",
        ),
    ],
    ids=["readonly-profile", "driver-drops-it", "readonly-global-with"],
)
def test_clickhouse_profile_whose_reading_settings_cannot_be_held_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, client: _CHClient, name: str
) -> None:
    with pytest.raises(ConnectorError) as err:
        _ch(tmp_path, monkeypatch, client)._connect()
    assert name in str(err.value) and "read statements differently" in str(err.value)


# ------------------------------------------------------ 2. Oracle database links


_LINKED = [
    'SELECT dummy FROM "DUAL"@lnk',
    'SELECT dummy FROM "SYS"."DUAL"@lnk',
    "SELECT dummy FROM dual @lnk",
    "SELECT dummy FROM sys.dual/**/@lnk",
    "SELECT dummy FROM DUAL@lnk",
    'SELECT * FROM travel."BOOKINGS"@lnk',
    'SELECT * FROM travel."BOOKINGS"@"LNK"',
    "SELECT * FROM travel.bookings @lnk",
    "SELECT * FROM travel.bookings@ lnk",
    "SELECT * FROM travel.bookings@lnk.example.com",
    "SELECT n FROM t WHERE n IN (SELECT n FROM u@lnk)",
    "SELECT * FROM t PARTITION (p1)@lnk",
    # q'...' literals, which sqlglot reads as the name q and ordinary strings:
    # Oracle's literal is q'{'}', and FROM t@lnk is outside it (review, 2026-09-28)
    "SELECT q'{'}', n FROM t@lnk --'",
    "SELECT nq'!'!', n FROM t@lnk --'",
    "SELECT Q'<'>' , n FROM t@lnk --'",
    "SELECT NQ'#'#', n FROM t@lnk --'",
]


@pytest.mark.parametrize("sql", _LINKED)
def test_oracle_refuses_a_database_link_before_connecting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sql: str
) -> None:
    """Live (review, 2026-09-28): the quoted, spaced and commented forms
    passed the guard and reached Oracle as DB-link reads (ORA-02019); with a
    link, the same-named object of another database is read."""
    dialed: list[Any] = []
    monkeypatch.setattr(oracle_module, "open_module", lambda *_a, **_k: dialed.append(1))
    conn = _connector(oracle_module.OracleConnector, "oracle", tmp_path)
    for run in (lambda: conn.execute_query(QuerySpec(sql=sql)), lambda: conn.explain(sql, False)):
        with pytest.raises(ConnectorError) as err:
            run()
        assert err.value.category == "POLICY_VIOLATION", str(err.value)
        assert "database link" in str(err.value)
    assert dialed == [], "refused before a session is opened"


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT 'ops@example.com' AS mail FROM t",
        "SELECT n FROM t WHERE mail = N'a@b'",
        'SELECT "odd@name" FROM t',
        "SELECT /*+ FULL(@sel$2 t) INDEX(t@sel$1 i) */ n FROM t",
        "SELECT n FROM t -- @lnk\n",
        "SELECT n FROM t /* t@lnk */",
        "SELECT n FROM t WHERE n = :1",
        # a string 'Q', and a name q apart from the string after it, are no q'...' literal
        "SELECT n FROM t WHERE code = 'Q' AND mail = 'a@b'",
        "SELECT q '[x]' FROM t WHERE mail = 'a@b'",
    ],
)
def test_oracle_an_at_sign_in_data_is_not_a_link(sql: str) -> None:
    assert oracle_module._db_link(sql) is None


def test_oracle_statement_the_tokenizer_cannot_read_is_treated_as_linked() -> None:
    assert oracle_module._db_link("SELECT q'[it's @ x]' FROM t@lnk") is not None


@pytest.mark.parametrize(
    "sql", ['SELECT dummy FROM "DUAL"@lnk', "SELECT dummy FROM dual @lnk", "SELECT dummy FROM dual/**/@lnk"]
)
def test_oracle_never_vouches_for_a_dual_named_with_a_link(sql: str) -> None:
    """The local-session check says nothing about the DUAL of another
    database: a DUAL with a link is never the bare DUAL it checks."""
    assert oracle_module._names_bare_dual(sql) is False


def test_oracle_shadow_check_reads_the_sys_dictionary_view() -> None:
    """Live (review, 2026-09-28): with TRAVEL.ALL_OBJECTS (0 rows) beside
    TRAVEL.DUAL, the bare all_objects of the check read the schema's own
    view, saw no DUAL, and the passport data leaked through FROM DUAL."""
    tables = list(sqlglot.parse_one(oracle_module._SHADOWED_DUAL, read="oracle").find_all(exp.Table))
    assert tables and all(t.db.upper() == "SYS" for t in tables), [t.sql("oracle") for t in tables]


# -------------------------------------------- 2. every dictionary name is qualified

# What Oracle resolves in the session's current schema before a PUBLIC
# synonym: a login schema holding an ALL_TABLES view answers in its place.
_ORACLE_DICTIONARY = re.compile(r"(?i)(?<![\w$.])(?:(?:all|dba|user|cdb)_\w+|g?v\$\w+|dbms_\w+)")


def _qualified_tables(sql: str, dialect: str, allowed_bare: set[str]) -> list[str]:
    text = re.sub(r"(?<!:):\d+", "NULL", sql.replace("%%", "%").replace("%s", "NULL"))  # binds sqlglot cannot read
    tree = sqlglot.parse_one(text, read=dialect)
    ctes = {c.alias_or_name.lower() for c in tree.find_all(exp.CTE)}
    return [
        t.sql(dialect)
        for t in tree.find_all(exp.Table)
        if isinstance(t.this, exp.Identifier) and not t.db and t.name.lower() not in ctes | allowed_bare
    ]


def test_oracle_catalog_reads_name_the_sys_objects(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A login schema's own ALL_OBJECTS, V$VERSION or DBMS_XPLAN would be
    read in place of the dictionary's. PLAN_TABLE alone stays bare: it must
    name what EXPLAIN PLAN writes into (a login schema's own PLAN_TABLE
    when it has one)."""
    session = _Session()
    fake = types.SimpleNamespace(connect=lambda **_kw: session)
    monkeypatch.setattr(oracle_module, "open_module", lambda *_a, **_k: fake)
    for version in ("19.3.0.0.0", "11.2.0.4.0"):
        session.version = version
        conn = _connector(oracle_module.OracleConnector, "oracle", tmp_path)
        conn.list_schemas(None, "A")
        conn.list_tables("APP", {"table", "view"}, "T")
        conn.list_columns("APP", "T")
        conn.list_all_columns("APP")
        conn.list_indexes("APP", "T")
        conn.list_views("APP")
        conn.list_synonyms("APP")
        conn.list_routines("APP")
        conn.get_foreign_keys("APP", "T")
        conn.get_statistics("APP", "T")
        conn.health_check()
        conn.explain("SELECT n FROM app.t", False)
    issued = [s for s in session.statements if not s.startswith("EXPLAIN PLAN")]
    assert len(issued) > 15, issued
    issued.append(oracle_module._SHADOWED_DUAL)
    for sql in issued:
        assert _qualified_tables(sql, "oracle", {"plan_table"}) == [], sql
        bare = [m.group(0) for m in _ORACLE_DICTIONARY.finditer(sql)]
        assert bare == [], (bare, sql)


def test_postgres_catalog_reads_name_pg_catalog(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """pg_catalog is searched first unless search_path names it later (a
    role's ALTER ROLE ... SET search_path = app, pg_catalog): then app's own
    pg_class is read in its place."""
    session = _Session()
    fake = types.SimpleNamespace(connect=lambda **_kw: session)
    monkeypatch.setattr(pg_module, "open_module", lambda *_a, **_k: fake)
    conn = _connector(pg_module.PostgresConnector, "postgres", tmp_path)
    conn.list_schemas(None, "a")
    conn.list_tables("app", {"table", "view", "materialized_view", "foreign_table"}, "t")
    conn.list_columns("app", "t")
    conn.list_all_columns("app")
    conn.list_indexes("app", "t")
    conn.list_views("app")
    conn.list_routines("app")
    conn.get_foreign_keys("app", "t")
    conn.get_statistics("app", "t")
    catalog = [s for s in session.statements if " FROM " in s.upper() and "'udbmcp" not in s]
    assert len(catalog) >= 9, catalog
    for sql in catalog:
        assert _qualified_tables(sql, "postgres", set()) == [], sql
        assert not re.search(r"(?<![\w.])pg_get_\w+\(", sql), sql


# --------------------------------------------------------- 3. listings leave them out

_REFUSED_VIEWS = {
    "mysql": [
        ("information_schema", "COLUMN_STATISTICS"),
        ("mysql", "column_stats"),
        ("information_schema", "PROCESSLIST"),
    ],
    "postgres": [
        ("pg_catalog", "pg_stats"),
        ("pg_catalog", "pg_stats_ext"),
        ("pg_catalog", "pg_stats_ext_exprs"),
        ("pg_catalog", "pg_statistic"),
        ("pg_catalog", "pg_stat_activity"),
    ],
    "oracle": [
        ("SYS", "ALL_TAB_HISTOGRAMS"),
        ("SYS", "DBA_TAB_COL_STATISTICS"),
        ("SYS", "USER_PART_HISTOGRAMS"),
        ("SYS", "HISTGRM$"),
        ("SYS", "V_$SQL"),
    ],
    "db2": [
        ("SYSCAT", "COLDIST"),
        ("SYSSTAT", "COLDIST"),
        ("SYSSTAT", "COLUMNS"),
        ("SYSIBM", "SYSCOLDIST"),
        ("SYSIBMADM", "MON_CURRENT_SQL"),
    ],
    "mssql": [("sys", "column_store_segments"), ("sys", "dm_exec_requests")],
    "clickhouse": [("system", "processes"), ("system", "query_log")],
}
_KEPT = {
    "mysql": ("information_schema", "COLUMNS"),
    "postgres": ("pg_catalog", "pg_class"),
    "oracle": ("SYS", "ALL_TAB_COLUMNS"),  # its low and high values are refused by column, not listed away
    "db2": ("SYSCAT", "COLUMNS"),
    "mssql": ("sys", "objects"),
    "clickhouse": ("system", "columns"),
}


def test_the_rows_the_listings_are_given_are_the_policys_always_refused_set() -> None:
    """The listings drop what is_session_sql_view names: what the policy
    refuses whatever the allowlists open (the guard's set: other sessions'
    SQL and column statistics). The rows below are in it; _KEPT is not."""
    for engine, names in _REFUSED_VIEWS.items():
        assert all(is_session_sql_view(engine, schema, name) for schema, name in names), engine
        assert not is_session_sql_view(engine, *_KEPT[engine]), engine


_OPEN_EVERYTHING = SecurityConfig(
    allowed_system_schemas=[
        "information_schema",
        "mysql",
        "pg_catalog",
        "sys",
        "syscat",
        "sysstat",
        "sysibm",
        "sysibmadm",
        "system",
    ]
)


def _listed(tables: list[Any]) -> set[tuple[str, str]]:
    return {(str(t.schema), str(t.name)) for t in tables}


def test_mysql_listing_leaves_out_the_refused_views(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rows = [(s, n, "SYSTEM VIEW", None) for s, n in [*_REFUSED_VIEWS["mysql"], _KEPT["mysql"]]]
    conn = _connector(mysql_module.MySQLConnector, "mysql", tmp_path, _OPEN_EVERYTHING)
    monkeypatch.setattr(conn, "_connect", lambda: _Session(rows=rows))
    assert _listed(conn.list_tables(None, {"table", "view"}, None)) == {_KEPT["mysql"]}


def test_postgres_listings_leave_out_the_refused_views(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    names = [*_REFUSED_VIEWS["postgres"], _KEPT["postgres"]]
    conn = _connector(pg_module.PostgresConnector, "postgres", tmp_path, _OPEN_EVERYTHING)
    monkeypatch.setattr(conn, "_connect", lambda: _Session(rows=[(s, n, "v", None) for s, n in names]))
    assert _listed(conn.list_tables(None, {"table", "view"}, None)) == {_KEPT["postgres"]}
    monkeypatch.setattr(conn, "_connect", lambda: _Session(rows=[(s, n, "SELECT 1") for s, n in names]))
    assert _listed(conn.list_views(None)) == {_KEPT["postgres"]}


def test_oracle_listings_leave_out_the_refused_views(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    names = [*_REFUSED_VIEWS["oracle"], _KEPT["oracle"]]
    conn = _connector(oracle_module.OracleConnector, "oracle", tmp_path, _OPEN_EVERYTHING)
    monkeypatch.setattr(conn, "_connect", lambda: _Session(rows=[(s, n, "VIEW") for s, n in names]))
    assert _listed(conn.list_tables(None, {"table", "view"}, None)) == {_KEPT["oracle"]}
    conn.close()
    monkeypatch.setattr(conn, "_connect", lambda: _Session(rows=[(s, n, "text") for s, n in names]))
    assert _listed(conn.list_views(None)) == {_KEPT["oracle"]}
    conn.close()
    # PUBLIC synonyms name the SYS views: V$SQL -> SYS.V_$SQL, ALL_TAB_HISTOGRAMS -> SYS.ALL_TAB_HISTOGRAMS
    synonyms = [
        ("PUBLIC", "ALL_TAB_HISTOGRAMS", "SYS", "ALL_TAB_HISTOGRAMS", None),
        ("PUBLIC", "V$SQL", "SYS", "V_$SQL", None),
        ("PUBLIC", "ALL_TAB_COLUMNS", "SYS", "ALL_TAB_COLUMNS", None),
    ]
    monkeypatch.setattr(conn, "_connect", lambda: _Session(rows=synonyms))
    assert _listed(conn.list_synonyms(None)) == {("PUBLIC", "ALL_TAB_COLUMNS")}


class _OracleSynonyms(_Session):
    """sys.all_synonyms as Oracle answers the listing: every row; the
    owner's (WHERE owner = :1); or the owner's and, in turn, each local
    synonym a row names (START WITH owner = :1 CONNECT BY ... PRIOR)."""

    def __init__(self, rows: list[tuple[Any, ...]]) -> None:
        super().__init__()
        self.everything = rows
        self.params: list[Any] = []

    def execute(self, sql: str, *args: Any, **_k: Any) -> _Session:
        self.params = list(args[0]) if args else []
        return super().execute(sql)

    def fetchall(self) -> list[Any]:
        if not self.params:
            return list(self.everything)
        found = [r for r in self.everything if r[0] == self.params[0]]
        frontier = found if "CONNECT BY" in self._last else []
        while frontier:
            frontier = [s for r in frontier if not r[4] for s in self.everything if s[:2] == r[2:4] and s not in found]
            found += frontier
        return found


def test_oracle_synonym_listing_follows_a_chain_to_the_refused_view(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A synonym that names a synonym that names a refused view is left out
    too, wherever the synonyms in between are (review, 2026-09-28: APP.S2 ->
    APP.S1 -> PUBLIC.V$SQL was listed)."""
    rows = [
        ("APP", "S2", "APP", "S1", None),
        ("APP", "S1", "PUBLIC", "V$SQL", None),
        ("APP", "S3", "PUBLIC", "HOP", None),  # through another owner's synonym
        ("PUBLIC", "HOP", "SYS", "ALL_TAB_HISTOGRAMS", None),
        ("PUBLIC", "V$SQL", "SYS", "V_$SQL", None),
        ("APP", "H", "SYS", "ALL_TAB_HISTOGRAMS", None),
        ("APP", "LOOP_A", "APP", "LOOP_B", None),  # a cycle names nothing refused
        ("APP", "LOOP_B", "APP", "LOOP_A", None),
        ("APP", "K", "APP", "KEPT", None),
        ("APP", "R", "SYS", "V_$SQL", "LNK"),  # another database's V$SQL, by name
    ]
    conn = _connector(oracle_module.OracleConnector, "oracle", tmp_path, _OPEN_EVERYTHING)
    session = _OracleSynonyms(rows)
    monkeypatch.setattr(conn, "_connect", lambda: session)
    kept = {("APP", "K"), ("APP", "LOOP_A"), ("APP", "LOOP_B")}
    assert _listed(conn.list_synonyms("APP")) == kept, "the other owners' synonyms are read, not listed"
    conn.close()
    assert _listed(conn.list_synonyms(None)) == kept


class _Db2Rows(_Db2Server):
    def __init__(self, rows: list[tuple[Any, ...]]) -> None:
        super().__init__(compat=None)
        self.rows = rows
        self._pending: list[tuple[Any, ...]] = []

    def prepare(self, _conn: Any, sql: str) -> str:
        self.statements.append(sql)
        return "stmt"

    def execute(self, _stmt: Any, params: Any) -> bool:
        schema = params[0] if self.statements[-1].endswith("TABSCHEMA = ?") else None
        self._pending = [r for r in self.rows if schema is None or r[0] == schema]
        return True

    def fetch_tuple(self, _stmt: Any) -> Any:
        return self._pending.pop(0) if self._pending else False


def test_db2_listings_leave_out_the_refused_views(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    names = [*_REFUSED_VIEWS["db2"], _KEPT["db2"]]
    for method, rows, expected in (
        ("list_tables", [(s, n, "V", -1) for s, n in names], {_KEPT["db2"]}),
        ("list_views", [(s, n, "text") for s, n in names], {_KEPT["db2"]}),
        (
            "list_synonyms",
            [("APP", "HIST", "SYSCAT", "COLDIST"), ("APP", "COLS", "SYSCAT", "COLUMNS")],
            {("APP", "COLS")},
        ),
    ):
        monkeypatch.setattr(db2_module, "open_module", lambda *_a, _r=rows, **_k: _Db2Rows(_r))
        monkeypatch.setitem(sys.modules, "ibm_db_dbi", types.ModuleType("ibm_db_dbi"))
        conn = _connector(db2_module.Db2Connector, "db2", tmp_path, _OPEN_EVERYTHING)
        out = getattr(conn, method)(*((None, {"table", "view"}, None) if method == "list_tables" else (None,)))
        assert _listed(out) == expected, method


def test_db2_alias_listing_follows_a_chain_to_the_refused_view(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An alias of an alias of a refused view is left out too, wherever the
    aliases in between are, and so is an alias named like one (review,
    2026-09-28: APP.A -> APP.B -> SYSCAT.COLDIST was listed)."""
    rows = [
        ("APP", "A", "APP", "B"),
        ("APP", "B", "SYSCAT", "COLDIST"),
        ("APP", "C", "OTHER", "HOP"),  # through another schema's alias
        ("OTHER", "HOP", "SYSIBMADM", "MON_CURRENT_SQL"),
        ("APP", "EXPLAIN_STATEMENT", "APP", "T"),  # its own name is a refused one
        ("APP", "LOOP_A", "APP", "LOOP_B"),
        ("APP", "LOOP_B", "APP", "LOOP_A"),
        ("APP", "COLS", "SYSCAT", "COLUMNS"),
    ]
    monkeypatch.setattr(db2_module, "open_module", lambda *_a, **_k: _Db2Rows(rows))
    monkeypatch.setitem(sys.modules, "ibm_db_dbi", types.ModuleType("ibm_db_dbi"))
    conn = _connector(db2_module.Db2Connector, "db2", tmp_path, _OPEN_EVERYTHING)
    kept = {("APP", "COLS"), ("APP", "LOOP_A"), ("APP", "LOOP_B")}
    assert _listed(conn.list_synonyms("APP")) == kept, "the other schemas' aliases are read, not listed"
    assert _listed(conn.list_synonyms(None)) == kept


def test_mssql_listing_leaves_out_the_refused_views(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rows = [(s, n, "VIEW") for s, n in [*_REFUSED_VIEWS["mssql"], _KEPT["mssql"]]]
    conn = _connector(mssql_module.MssqlConnector, "mssql", tmp_path, _OPEN_EVERYTHING)
    monkeypatch.setattr(conn, "_connect", lambda: _Session(rows=rows))
    assert _listed(conn.list_tables(None, {"table", "view"}, None)) == {_KEPT["mssql"]}


def test_clickhouse_listing_leaves_out_the_refused_views(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rows = [(s, n, "SystemProcesses", None) for s, n in [*_REFUSED_VIEWS["clickhouse"], _KEPT["clickhouse"]]]
    conn = _connector(ch_module.ClickHouseConnector, "clickhouse", tmp_path, _OPEN_EVERYTHING, port=8123)
    monkeypatch.setattr(
        conn,
        "_shared_meta_client",
        lambda: types.SimpleNamespace(query=lambda *_a, **_k: types.SimpleNamespace(result_rows=rows)),
    )
    assert _listed(conn.list_tables(None, {"table", "view"}, None)) == {_KEPT["clickhouse"]}
