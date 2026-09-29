"""IBM Db2 connector (ibm_db manylinux wheel with bundled clidriver).

Per spec §5:
- LUW only in this build; z/OS and Db2 for i are explicitly NOT implemented
  (different catalog semantics, licensing, and native-client requirements).
- The wheel bundles clidriver; the target never fetches it and IBM_DB_HOME
  is not relied upon.
- Db2 Connect licensing for z/OS/i gateways is an administrator prerequisite
  reported by doctor, never auto-accepted.
- EXPLAIN tables are NOT auto-created with the read-only identity; explain
  stays unsupported until an administrator provisions them (policy §10).
- Package binding is an administrator step; the read-only identity never
  binds packages automatically.
"""

from __future__ import annotations

import functools
import math
import re
import secrets
import socket
import ssl
import threading
import time
from collections.abc import Callable, Sequence
from decimal import Decimal
from typing import Any

import sqlglot

from universal_db_mcp.config import ResolvedConnection
from universal_db_mcp.connectors.base import (
    EXPLAIN_ANALYZE_UNSUPPORTED,
    ColumnInfo,
    ConnectorError,
    DatabaseConnector,
    HealthInfo,
    IndexInfo,
    KeyInfo,
    NameBinding,
    QueryOutcome,
    QuerySpec,
    RoutineInfo,
    SynonymInfo,
    SynonymTarget,
    TableSummary,
    ViewInfo,
    own_objects_first,
)
from universal_db_mcp.connectors.driver_helpers import (
    adapt_row,
    cell_truncation_warning,
    column_names_at,
    ibm_db_sqlstate,
    next_fetch_size,
    open_module,
    statement_body,
    synonym_chains,
    synonym_names_refused_view,
    translated_driver_errors,
)
from universal_db_mcp.discovery.system_schemas import SYSTEM_SCHEMAS, is_session_sql_view
from universal_db_mcp.models.capabilities import Cap, CapabilityMatrix, CapabilityState, Limitation
from universal_db_mcp.security.policy import EffectivePolicy
from universal_db_mcp.security.redact import scrub_exception

# Catalog, internal and package schemas list_tables leaves out (bound as
# parameters): the discovery set plus Db2's internal schemas.
_DB2_SYSTEM_SCHEMAS = tuple(
    sorted({s.upper() for s in SYSTEM_SCHEMAS["db2"]} | {"SYSIBMINTERNAL", "SYSIBMTS", "NULLID", "SQLJ"})
)
# Db2 11.1+ reads statements as Netezza does under SQL_COMPAT 'NPS' (a
# connect procedure can set it for every session): '#' becomes an operator
# and an expression can name a select-list alias (live, 11.5.9: SELECT 1 AS
# a, a FROM SYSIBM.SYSDUMMY1 ran). The variable is qualified so that no user
# variable of that name stands in; PUBLIC may write it. String literals and
# delimited identifiers read the same in both modes.
_DB2_PIN_READING = "SET SYSIBM.SQL_COMPAT = 'DB2'"
# A release before 11.1 has no SQL_COMPAT, and no Netezza mode to leave.
_DB2_NO_SQL_COMPAT = ("SQL0206N", "SQL0204N")


# ibm_db result types whose values can be gigabytes: the driver reads each
# such value whole, so they are cut on the server.
_DB2_LOB_TYPES = frozenset({"clob", "dbclob", "blob", "xml"})
# The first request of every DRDA conversation, the liveness question of the
# TLS probe: one request DSS (length 10, 0xD0, RQSDSS, correlator 1) carrying
# EXCSAT (code point 0x1041) with no parameters. A Db2 server answers with its
# attributes (EXCSATRD) and asks for nothing: no credentials are sent.
_DRDA_EXCSAT = bytes.fromhex("000ad001000100041041")
# Database code pages in which Db2 casts graphic strings to character: UTF-8
# and UTF-16. Elsewhere CAST(<GRAPHIC> AS VARCHAR) is SQL0461N.
_UNICODE_CODEPAGES = frozenset({1208, 1200})


def _db2_read_tail(body: str) -> tuple[str, str]:
    """``body`` without the clauses at its end that Db2 takes only at the
    end of the outermost statement (FOR READ ONLY, FOR FETCH ONLY, OPTIMIZE
    FOR n ROWS, an isolation clause), and those clauses. Read from tokens,
    so neither a quoted name nor a comment is taken for one."""
    try:
        tokens = sqlglot.Dialect.get_or_raise("postgres").tokenize(body)  # the guard's dialect for Db2
    except Exception:  # noqa: BLE001 - sqlglot's TokenError, and whatever else a tokenizer raises
        return body, ""
    words = [body[t.start : t.end + 1].upper() for t in tokens]
    cut = len(words)
    while cut:
        tail = words[:cut]
        if tail[-3:] in (["FOR", "READ", "ONLY"], ["FOR", "FETCH", "ONLY"]):
            cut -= 3
        elif tail[-2:-1] == ["WITH"] and tail[-1] in ("UR", "CS", "RS", "RR"):
            cut -= 2
        elif tail[-4:-2] == ["OPTIMIZE", "FOR"] and tail[-2].isdigit() and tail[-1] in ("ROW", "ROWS"):
            cut -= 4
        else:
            break
    if cut in (0, len(words)):
        return body, ""
    start = tokens[cut].start
    return body[:start].rstrip(), body[start:]


def _db2_capped_select(sql: str, described: list[tuple[str, str]], max_cell_bytes: int) -> str | None:
    """The statement as a nested table expression whose CLOB, DBCLOB, BLOB
    and XML columns the server cuts to ``max_cell_bytes + 1`` characters or
    bytes (so a cut is still detected here), or None when it has none.

    Columns are referenced by position and keep the statement's own names,
    so masking by name still applies. ORDER BY ORDER OF keeps the
    statement's row order. SUBSTRING (unlike SUBSTR) takes a length past the
    value's end, and counts CODEUNITS32 so no character is split."""
    if not any(kind in _DB2_LOB_TYPES for _name, kind in described):
        return None
    keep = max_cell_bytes + 1
    items: list[str] = []
    for i, (name, kind) in enumerate(described, start=1):
        ref = f"udbmcp_q.c{i}"
        if kind == "blob":
            expr = f"SUBSTRING({ref}, 1, {keep}, OCTETS)"
        elif kind == "xml":
            expr = f"SUBSTRING(XMLSERIALIZE({ref} AS CLOB(2G)), 1, {keep}, CODEUNITS32)"
        elif kind in _DB2_LOB_TYPES:
            expr = f"SUBSTRING({ref}, 1, {keep}, CODEUNITS32)"
        else:
            expr = ref
        quoted = '"' + name.replace('"', '""') + '"'
        items.append(f"{expr} AS {quoted}")
    body, tail = _db2_read_tail(statement_body(sql, "postgres"))
    positions = ", ".join(f"c{i}" for i in range(1, len(described) + 1))
    capped = f"SELECT {', '.join(items)} FROM (\n{body}\n) AS udbmcp_q({positions}) ORDER BY ORDER OF udbmcp_q"
    return f"{capped} {tail}" if tail else capped


def _meta_translated(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Metadata/catalog methods surface driver failures as ``ConnectorError``.

    ibm_db raises its own exception type for connect/SQL failures; without
    this wrapping a raw driver exception escaped the server's per-connection
    degradation in db_search_metadata and aborted the whole tool call as
    INTERNAL_ERROR instead of a per-connection warning."""

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        with translated_driver_errors():
            return fn(*args, **kwargs)

    return wrapper


def _s(value: Any) -> Any:
    """SYSCAT identifier columns come back CHAR-padded ('MOI     '); every
    name comparison downstream (object resolution, search, quoting) needs
    the trimmed value."""
    return value.rstrip() if isinstance(value, str) else value



def _db2_type(typename: str, length: Any, scale: Any) -> str:
    """SYSCAT.COLUMNS.TYPENAME with LENGTH/SCALE folded back in for the
    parameterised types only: VARCHAR(200), DECIMAL(12,2). INTEGER's LENGTH
    is its byte width and stays out."""
    up = typename.upper()
    if up in ("CHARACTER", "CHAR", "VARCHAR", "GRAPHIC", "VARGRAPHIC", "BINARY", "VARBINARY") and length:
        return f"{typename}({int(length)})"
    if up in ("DECIMAL", "NUMERIC") and length:
        return f"{typename}({int(length)},{int(scale or 0)})"
    return typename


class Db2Connector(DatabaseConnector):
    engine = "db2"

    def __init__(self, connection: ResolvedConnection, policy: EffectivePolicy) -> None:
        super().__init__(connection, policy)
        self._module: Any = None
        self._conn: Any = None
        self._exec_lock = threading.Lock()  # serializes queries
        self._unicode_db: bool | None = None  # the database's code page is Unicode (read at connect)
        if connection.config.family not in (None, "luw"):
            raise ValueError(
                f"db2 family '{connection.config.family}' is not implemented in this "
                f"build; LUW catalogs and licensing differ from z/OS and Db2 for i"
            )

    def _connect(self) -> Any:
        """Connect, bounded by connect_timeout_seconds. A connection opened for
        one query (``_query_connect``) gets that query's timeout as its CLI
        statement ceiling, so the server stops the statement when the
        caller's deadline does (cancel_current has no path to it)."""
        self._module = open_module(
            "ibm_db",
            "ibm_db (manylinux cp312 wheel with bundled clidriver)",
        )
        import ibm_db_dbi  # type: ignore[import-not-found,import-untyped,unused-ignore] # noqa: F401 - ships with ibm_db

        cfg = self.connection.config
        fields: list[tuple[str, str]] = [
            ("DATABASE", f"{cfg.database}"),
            ("HOSTNAME", f"{cfg.host}"),
            ("PORT", f"{cfg.port or 50000}"),
            ("PROTOCOL", "TCPIP"),
            # What DBAs see in LIST APPLICATIONS / MON_GET_CONNECTION.
            ("CLIENTAPPLNAME", self.session_profile.application_name),
            # Without it a connect waits for the OS SYN timeout (75 s on
            # macOS, about 127 s on Linux), or forever on a listener that
            # accepts and never answers.
            ("CONNECTTIMEOUT", str(max(1, math.ceil(cfg.connect_timeout_seconds)))),
        ]
        if ceiling := self._statement_ceiling():
            # CLI-level statement ceiling: SQL0952N (SQLSTATE 57014) at the limit.
            fields.append(("QUERYTIMEOUT", str(ceiling)))
        if auth := cfg.options.get("authentication"):
            # Servers that demand a specific mechanism (Kerberos, TOKEN, AES)
            # otherwise answer SQL30082N reason 17, which reads exactly like
            # the credential bug fixed in 854b50d.
            fields.append(("AUTHENTICATION", str(auth).upper()))
        if cfg.tls.enabled:
            fields.append(("SECURITY", "SSL"))
            if cfg.tls.ca_file:
                fields.append(("SSLServerCertificate", cfg.tls.ca_file))
            # The Linux clidriver (11.5.9) does not check the certificate's
            # host name by default: any certificate the CA issued, for any
            # host, was accepted. Basic matches HOSTNAME against the SAN (an
            # IP literal needs an IP SAN) on every platform.
            fields.append(("SSLClientHostnameValidation", "Basic"))
        # Credentials MUST travel inside the connection string. For a
        # connection-string DSN, ibm_db ignores connect()'s positional
        # user/password arguments, so passing them there sends NO credentials:
        # the server answers SQL30082N reason 17 (UNSUPPORTED FUNCTION) under
        # default negotiation and reason 3 (PASSWORD MISSING) under SERVER auth.
        # Reproduced live 2026-09-15; long misdiagnosed as a server/TLS block.
        if self.connection.username:
            fields.append(("UID", self.connection.username.value))
        if self.connection.password:
            fields.append(("PWD", self.connection.password.value))
        for key, value in fields:
            # No quoting form carries ';' in a CLI connection-string value
            # (raw, braces, doubled braces and quotes were all rejected live);
            # unrefused it would split into extra connection keywords. The
            # message names the keyword only, never the value.
            if ";" in value:
                raise ConnectorError(
                    f"db2 connection value for {key} contains ';', which a Db2 CLI "
                    "connection string cannot carry in any quoting form; change that value"
                )
        dsn = "".join(f"{key}={value};" for key, value in fields)
        if cfg.tls.enabled:
            self._require_tls_answer()
        conn = self._module.connect(dsn, "", "")
        self._configure_session(conn)
        if self._unicode_db is None:
            self._unicode_db = self._database_is_unicode(conn)
        return conn

    def _database_is_unicode(self, conn: Any) -> bool | None:
        """Whether the database's code page is Unicode, from the CLI's
        connection information (no statement); None when the driver does not
        say."""
        try:
            codepage = int(self._module.server_info(conn).DB_CODEPAGE)
        except Exception:  # noqa: BLE001 - optional knowledge; text_expression then compares as declared
            return None
        return codepage in _UNICODE_CODEPAGES

    def _require_tls_answer(self) -> None:
        """Refuse a TLS connect whose listener accepts and never answers.

        CONNECTTIMEOUT bounds a plain connect, but ibm_db's connect over TLS
        to such a listener never returned: the worker thread and its
        executor tokens were held for good. So did a peer that completes the
        handshake and then never answers DRDA (a TLS-terminating proxy in
        front of a down Db2, a hung instance whose listener still
        handshakes). A TCP connect, a TLS handshake and an answer to EXCSAT
        within connect_timeout_seconds show the server answers, and a
        timeout is reported at the step that did not complete; any other
        failure (refused, reset, a handshake alert, a peer that hangs up) is
        left to the Db2 client, which reports it in its own words. Liveness
        only: the probe sends no credentials, and the certificate is
        verified by the Db2 client on the real connect (SSLServerCertificate
        plus host-name validation). A second verifier here could refuse what
        GSKit accepts."""
        cfg = self.connection.config
        host, port = str(cfg.host), int(cfg.port or 50000)
        budget = max(1.0, float(cfg.connect_timeout_seconds))
        deadline = time.monotonic() + budget
        probe = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        probe.check_hostname = False
        probe.verify_mode = ssl.CERT_NONE
        stage = "tcp"  # what the peer has yet to do: accept, handshake, answer
        try:
            with socket.create_connection((host, port), timeout=budget) as raw:
                stage = "tls"
                raw.settimeout(max(0.05, deadline - time.monotonic()))
                with probe.wrap_socket(raw, server_hostname=host) as tls:
                    stage = "drda"
                    tls.settimeout(max(0.05, deadline - time.monotonic()))
                    tls.sendall(_DRDA_EXCSAT)
                    tls.recv(1)  # any answer, or the peer hanging up
        except TimeoutError:
            if stage == "tcp":  # a dropped SYN or a wrong address: no TLS was tried
                raise ConnectorError(
                    f"db2 connection '{self.connection.name}': {host}:{port} did not accept a TCP connection within "
                    f"{budget:g} s (connect_timeout_seconds). Check the host and port, and any firewall between "
                    "this server and it"
                ) from None
            what = (
                "did not answer DRDA after its TLS handshake" if stage == "drda" else "did not complete a TLS handshake"
            )
            raise ConnectorError(
                f"db2 connection '{self.connection.name}': {host}:{port} {what} within {budget:g} s "
                "(connect_timeout_seconds), so the connect was not handed to the Db2 client, which would wait "
                "on it without a bound. Check that the port is the server's SSL port (SSL_SVCENAME) and that "
                "the server, and any TLS proxy in front of it, is responsive"
            ) from None
        except OSError:
            return

    def _configure_session(self, conn: Any) -> None:
        """Apply the session safety profile.

        The isolation level is the production-safety promise on Db2: an
        ordinary SELECT at the default CS takes share locks and queues behind
        writers, so read-only connections run at UR unless configured
        otherwise, and it is REQUIRED (a refusal fails the connection rather
        than running at CS silently). The agent no longer has to remember
        WITH UR - though the clause still works. The lock ceiling is
        best-effort. Db2 has no session-wide read-only; the guard enforces it.
        SQL_COMPAT 'DB2' (_DB2_PIN_READING) is required where the server has it.
        """
        prof = self.session_profile
        self._session_reset()
        try:
            self._module.exec_immediate(conn, _DB2_PIN_READING)
            self._session_applied("sql_compat=DB2")
        except Exception as exc:  # noqa: BLE001
            if not any(code in str(exc) for code in _DB2_NO_SQL_COMPAT):
                raise self._reading_required("SQL_COMPAT 'DB2'", exc) from exc
            self._session_skipped("sql_compat (no Netezza mode before Db2 11.1)", exc)
        if prof.isolation:
            try:
                self._module.exec_immediate(conn, f"SET CURRENT ISOLATION = {prof.isolation.upper()}")
                self._session_applied(f"isolation={prof.isolation}")
            except Exception as exc:  # noqa: BLE001
                raise self._session_required(f"isolation {prof.isolation}", exc) from exc
        if prof.lock_timeout_seconds is not None:
            secs = int(math.ceil(prof.lock_timeout_seconds))
            try:
                self._module.exec_immediate(conn, f"SET CURRENT LOCK TIMEOUT = {secs}")
                self._session_applied(f"lock_timeout={secs}s")
            except Exception as exc:  # noqa: BLE001
                self._session_skipped("lock_timeout", exc)

    def _session_readback(self, conn: Any) -> dict[str, Any]:
        try:
            stmt = self._module.exec_immediate(
                conn, "VALUES (CURRENT ISOLATION, CURRENT LOCK TIMEOUT, CURRENT CLIENT_APPLNAME)"
            )
            row = self._module.fetch_tuple(stmt)
        except Exception:  # noqa: BLE001 - reporting only
            return {}
        if not row or len(row) < 3:
            return {}
        return {
            "isolation": str(row[0]).strip().lower() or "server default",
            "lock_timeout_seconds": str(row[1]),
            "application_name": str(row[2]),
        }

    def _dbi_conn(self) -> Any:
        """ibm_db_dbi wrapper for DB-API access."""
        import ibm_db_dbi

        return ibm_db_dbi.Connection(self._conn) if self._conn else None

    def _fetch_all(self, stmt: Any) -> list[tuple[Any, ...]]:
        """Drain a statement handle into a list of row tuples.

        ibm_db.fetch_tuple returns ``False`` (not ``None``) once the result set
        is exhausted, so the loop stops on any falsy sentinel. A real row is a
        non-empty tuple and therefore always truthy, even when every cell is
        NULL, so no data row can be mistaken for end-of-set.
        """
        rows: list[tuple[Any, ...]] = []
        while row := self._module.fetch_tuple(stmt):
            rows.append(row)
        return rows

    def cancel_current(self) -> bool:
        # ibm_db has no safe out-of-band cancel in this API surface; reported
        # truthfully as unsupported. A SET CLIENT INTERRUPT session option or
        # FORCE APPLICATION path is a documented future option.
        return False

    def build_sample_query(self, schema: str | None, table: str, columns: list[str] | None, limit: int) -> str:
        cols = ", ".join(self.quote_identifier(c) for c in columns) if columns else "*"
        qualified = (
            f"{self.quote_identifier(schema)}.{self.quote_identifier(table)}"
            if schema
            else self.quote_identifier(table)
        )
        return f"SELECT {cols} FROM {qualified} FETCH FIRST {int(limit)} ROWS ONLY"

    def capabilities(self) -> CapabilityMatrix:
        return CapabilityMatrix(
            engine="db2",
            engine_family="db2-luw",
            driver="ibm_db (bundled clidriver)",
            capabilities={
                Cap.CONNECT: CapabilityState.UNVERIFIED,
                Cap.HEALTH: CapabilityState.UNVERIFIED,
                Cap.LIST_SCHEMAS: CapabilityState.UNVERIFIED,
                Cap.LIST_TABLES: CapabilityState.UNVERIFIED,
                Cap.GET_TABLE: CapabilityState.UNVERIFIED,
                Cap.LIST_COLUMNS: CapabilityState.UNVERIFIED,
                Cap.LIST_VIEWS: CapabilityState.UNVERIFIED,
                Cap.LIST_SYNONYMS: CapabilityState.UNVERIFIED,
                Cap.LIST_ROUTINES: CapabilityState.UNVERIFIED,
                Cap.RELATIONSHIPS: CapabilityState.UNVERIFIED,
                Cap.STATISTICS: CapabilityState.UNVERIFIED,
                Cap.QUERY: CapabilityState.UNVERIFIED,
                Cap.PARAMETERS: CapabilityState.UNVERIFIED,
                Cap.CANCEL: CapabilityState.UNSUPPORTED,
                Cap.SERVER_SIDE_CANCEL: CapabilityState.UNSUPPORTED,
                Cap.EXPLAIN: CapabilityState.UNSUPPORTED,
                Cap.EXPLAIN_ANALYZE: CapabilityState.UNSUPPORTED,
                Cap.SAMPLE: CapabilityState.UNVERIFIED,
                Cap.TLS: CapabilityState.UNVERIFIED,
            },
            limitations=[
                Limitation(
                    scope="explain",
                    detail="EXPLAIN PLAN needs administrator-provisioned explain tables "
                    "(session schema or SYSTOOLS.EXPLAIN_*, created once with "
                    "SYSPROC.SYSINSTALLOBJECTS('EXPLAIN','C',NULL,NULL)); never created here. "
                    "Refused with that instruction until provisioned; the plan rows written for "
                    "a call are deleted again.",
                ),
                Limitation(
                    scope="licensing",
                    detail="Db2 Connect licensing applies when the target is z/OS "
                    "or Db2 for i through a gateway; the read-only identity never "
                    "runs bind/grant steps.",
                ),
                Limitation(scope="families", detail="z/OS and Db2 for i are not implemented in this build."),
                Limitation(
                    scope="cancel",
                    detail="No out-of-band cancel in this driver surface. Each query's own timeout "
                    "is its CLI QUERYTIMEOUT, so the server stops the statement at that deadline; the "
                    "connection is discarded on timeout.",
                ),
                Limitation(
                    scope="query",
                    detail="CLOB, DBCLOB, BLOB and XML result columns are cut to the cell limit by the "
                    "server: the statement, described first by a prepare (which runs nothing), runs as a "
                    "nested table expression. A statement Db2 refuses in that form is refused.",
                ),
            ],
            required_privileges=[
                "CONNECT to the database",
                "SELECT on permitted tables/views",
                "catalog visibility (SYSCAT views) for permitted schemas",
            ],
            unverified_items=[
                "bundled-clidriver wheel operation on target (import alone is not a connectivity test)",
                "SSL via SSLServerCertificate file",
                "package binding state for the read-only identity",
            ],
        )

    def health_check(self) -> HealthInfo:
        start = time.monotonic()
        try:
            conn = self._connect()
            try:
                # SYSIBMADM.ENV_INST_INFO needs EXECUTE on an admin table
                # function that a bare CONNECT+SELECT identity does not have.
                # Version reporting is best-effort; liveness uses SYSDUMMY1,
                # which every connectable account can read.
                row = None
                try:
                    stmt = self._module.exec_immediate(
                        conn, "SELECT service_level FROM SYSIBMADM.ENV_INST_INFO"
                    )
                    row = self._module.fetch_tuple(stmt)
                except Exception:  # noqa: BLE001 - version is optional
                    stmt = self._module.exec_immediate(conn, "SELECT 1 FROM SYSIBM.SYSDUMMY1")
                    self._module.fetch_tuple(stmt)
                session = self.session_report(self._session_readback(conn))
            finally:
                self._module.close(conn)
            return HealthInfo(
                healthy=True,
                server_version=str(row[0]) if row else None,
                latency_ms=int((time.monotonic() - start) * 1000),
                session=session,
            )
        except Exception as exc:  # noqa: BLE001, S110
            return HealthInfo(healthy=False, detail=scrub_exception(exc)[:300])

    @_meta_translated
    def list_schemas(self, catalog: str | None, search: str | None) -> list[str]:
        conn = self._connect()
        try:
            sql = "SELECT SCHEMANAME FROM SYSCAT.SCHEMATA"
            if search:
                sql += " WHERE SCHEMANAME LIKE ?"
            sql += " ORDER BY 1"
            stmt = self._module.exec_immediate(conn, sql) if not search else self._module.prepare(conn, sql)
            if search:
                self._module.execute(stmt, (f"%{search}%",))
            rows = []
            while row := self._module.fetch_tuple(stmt):
                rows.append(_s(row[0]))
            return rows
        finally:
            self._module.close(conn)

    @_meta_translated
    def list_tables(self, schema: str | None, kinds: set[str], search: str | None) -> list[TableSummary]:
        conn = self._connect()
        try:
            types: list[str] = []
            if "table" in kinds:
                types.append("T")
            if "view" in kinds:
                types.append("V")
            if not types:
                return []
            sql = (
                "SELECT TABSCHEMA, TABNAME, TYPE, CARD FROM SYSCAT.TABLES WHERE TYPE IN ("
                + ", ".join(["?"] * len(types))
                + ")"
            )
            params: list[Any] = [*types]
            # System schemas are not data unless the administrator allowed
            # them: returning them would turn them into resolver entries under
            # the default config. Named one by one, since a 'SYS%' prefix
            # also matches user schemas.
            opened = self._opened_schemas()
            if hidden := [s for s in _DB2_SYSTEM_SCHEMAS if s.lower() not in opened]:
                sql += " AND TABSCHEMA NOT IN (" + ", ".join(["?"] * len(hidden)) + ")"
                params.extend(hidden)
            if schema:
                sql += " AND TABSCHEMA = ?"
                params.append(schema)
            if search:
                sql += " AND TABNAME LIKE ?"
                params.append(f"%{search}%")
            sql += " ORDER BY 1, 2"
            stmt = self._module.prepare(conn, sql)
            self._module.execute(stmt, tuple(params))
            out = []
            while row := self._module.fetch_tuple(stmt):
                kind = "table" if row[2] == "T" else "view"
                if kind not in kinds or is_session_sql_view(self.engine, _s(row[0]), _s(row[1])):
                    continue
                out.append(
                    TableSummary(
                        schema=_s(row[0]),
                        name=_s(row[1]),
                        kind=kind,
                        row_estimate=int(row[3]) if row[3] is not None and row[3] >= 0 else None,
                        row_estimate_source="catalog_estimate(SYSCAT.TABLES.CARD)"
                        if row[3] is not None and row[3] >= 0
                        else None,
                    )
                )
            return own_objects_first(out, _DB2_SYSTEM_SCHEMAS)
        finally:
            self._module.close(conn)

    @_meta_translated
    def list_columns(self, schema: str | None, table: str) -> list[ColumnInfo]:
        conn = self._connect()
        try:
            sql = (
                "SELECT COLNAME, TYPENAME, NULLS, DEFAULT, COLNO, LENGTH, SCALE FROM SYSCAT.COLUMNS "
                "WHERE TABSCHEMA = ? AND TABNAME = ? ORDER BY COLNO"
            )
            stmt = self._module.prepare(conn, sql)
            self._module.execute(stmt, (schema, table))
            rows = []
            while row := self._module.fetch_tuple(stmt):
                rows.append(row)
            return [
                ColumnInfo(
                    schema=schema,
                    table=table,
                    name=_s(r[0]),
                    data_type=_db2_type(_s(r[1]), r[5] if len(r) > 5 else None, r[6] if len(r) > 6 else None),
                    nullable=r[2] == "Y",
                    default=r[3],
                    ordinal=r[4],
                )
                for r in rows
            ]
        finally:
            self._module.close(conn)

    def length_expression(self, quoted_column: str) -> str:
        return f"CHARACTER_LENGTH({quoted_column}, CODEUNITS32)"  # LENGTH() is bytes on Db2

    def text_expression(self, quoted_column: str, portable_name: str, declared_type: str | None = None) -> str:
        # ibm_db types a parameter marker from the value it is compared with,
        # so a value-search needle longer than a CHAR(n)/VARCHAR(n) column
        # raised CLI0109E and the whole table went unsearched. Compared as the
        # widest VARCHAR, a longer needle simply does not match. A GRAPHIC or
        # VARGRAPHIC column is widened as graphic: outside a Unicode database
        # Db2 refuses to cast graphic to character (SQL0461N). Without the
        # declared type only a Unicode database takes the VARCHAR cast for
        # every string column; elsewhere the column is compared as declared.
        declared = (declared_type or "").strip().upper()
        if declared.startswith(("GRAPHIC", "VARGRAPHIC", "LONG VARGRAPHIC")):
            return f"CAST({quoted_column} AS VARGRAPHIC(16336))"
        if declared or self._unicode_db:
            return f"CAST({quoted_column} AS VARCHAR(32672))"
        return quoted_column

    def substring_expression(self, quoted_column: str, chars: int) -> str:
        # Db2 raises SQL0138N when SUBSTR asks for more than the value holds
        # (every other engine just returns the shorter string), so the length
        # argument is clamped per row.
        n = int(chars)
        return (
            f"SUBSTR({quoted_column}, 1, CASE WHEN LENGTH({quoted_column}) < {n} "
            f"THEN LENGTH({quoted_column}) ELSE {n} END)"
        )

    def build_search_query(
        self, schema: str | None, table: str, select_columns: list[str], where_sql: str, limit: int
    ) -> str:
        cols = ", ".join(self.quote_identifier(c) for c in select_columns) if select_columns else "*"
        qualified = (
            f"{self.quote_identifier(schema)}.{self.quote_identifier(table)}"
            if schema
            else self.quote_identifier(table)
        )
        return f"SELECT {cols} FROM {qualified} WHERE {where_sql} FETCH FIRST {int(limit)} ROWS ONLY"

    def build_top_values_query(self, sample_sql: str, column: str, limit: int) -> str:
        q = self.quote_identifier(column)
        return (
            f"SELECT {q} AS v, COUNT(*) AS cnt FROM ({sample_sql}) s "
            f"WHERE {q} IS NOT NULL GROUP BY {q} ORDER BY cnt DESC FETCH FIRST {int(limit)} ROWS ONLY"
        )

    @_meta_translated
    def list_all_columns(self, schema: str | None) -> list[ColumnInfo]:
        conn = self._connect()
        try:
            sql = (
                "SELECT TABNAME, COLNAME, TYPENAME, NULLS, DEFAULT, COLNO, LENGTH, SCALE FROM SYSCAT.COLUMNS "
                "WHERE TABSCHEMA = ? ORDER BY TABNAME, COLNO"
            )
            stmt = self._module.prepare(conn, sql)
            self._module.execute(stmt, (schema,))
            rows = self._fetch_all(stmt)
            return [
                ColumnInfo(schema=schema, table=_s(r[0]), name=_s(r[1]),
                           data_type=_db2_type(_s(r[2]), r[6] if len(r) > 6 else None, r[7] if len(r) > 7 else None),
                           nullable=r[3] == "Y", default=r[4], ordinal=r[5])
                for r in rows
            ]
        finally:
            self._module.close(conn)

    @_meta_translated
    def list_indexes(self, schema: str | None, table: str | None) -> list[IndexInfo]:
        conn = self._connect()
        try:
            sql = (
                "SELECT i.TABNAME, i.INDNAME, i.UNIQUERULE, ic.COLNAME, ic.COLSEQ, i.INDEXTYPE "
                "FROM SYSCAT.INDEXES i JOIN SYSCAT.INDEXCOLUSE ic "
                "ON ic.INDSCHEMA = i.INDSCHEMA AND ic.INDNAME = i.INDNAME "
                "WHERE i.TABSCHEMA = ?"
            )
            params: list[Any] = [schema]
            if table:
                sql += " AND i.TABNAME = ?"
                params.append(table)
            sql += " ORDER BY i.TABNAME, i.INDNAME, ic.COLSEQ"
            stmt = self._module.prepare(conn, sql)
            self._module.execute(stmt, tuple(params))
            rows = self._fetch_all(stmt)
        finally:
            self._module.close(conn)
        grouped: dict[tuple[str, str], IndexInfo] = {}
        for tname, iname, rule, col, _seq, itype in rows:
            key = (_s(tname), _s(iname))
            info = grouped.get(key)
            if info is None:
                # UNIQUERULE: P = primary key, U = unique, D = duplicates allowed
                info = IndexInfo(name=key[1], columns=[], unique=(_s(rule) in ("P", "U")),
                                 primary=(_s(rule) == "P"), kind=str(_s(itype)).lower(),
                                 schema=schema, table=key[0])
                grouped[key] = info
            info.columns.append(str(_s(col)))
        return list(grouped.values())

    @_meta_translated
    def list_views(self, schema: str | None) -> list[ViewInfo]:
        conn = self._connect()
        try:
            sql = "SELECT VIEWSCHEMA, VIEWNAME, TEXT FROM SYSCAT.VIEWS"
            params: list[Any] = []
            if schema:
                sql += " WHERE VIEWSCHEMA = ?"
                params.append(schema)
            sql += " ORDER BY 1, 2"
            stmt = self._module.prepare(conn, sql)
            self._module.execute(stmt, tuple(params))
            rows = []
            while row := self._module.fetch_tuple(stmt):
                rows.append(row)
            return [
                ViewInfo(schema=_s(r[0]), name=_s(r[1]), kind="view", definition_state="unavailable")
                for r in rows
                if not is_session_sql_view(self.engine, _s(r[0]), _s(r[1]))
            ]
        finally:
            self._module.close(conn)

    @_meta_translated
    def list_synonyms(self, schema: str | None) -> list[SynonymInfo]:
        conn = self._connect()
        try:
            # every alias, of any schema: an alias may name another schema's
            # alias in turn, which is read to follow the chain, not listed
            sql = "SELECT TABSCHEMA, TABNAME, BASE_TABSCHEMA, BASE_TABNAME FROM SYSCAT.TABLES WHERE TYPE = 'A'"
            stmt = self._module.prepare(conn, sql)
            self._module.execute(stmt, ())
            rows = []
            while row := self._module.fetch_tuple(stmt):
                rows.append(tuple(_s(v) for v in row[:4]))
            targets = {(r[0], r[1]): (r[2], r[3]) for r in rows}
            wanted = schema.rstrip(" ") if schema else None  # Db2 compares names blank-padded
            # an alias names what its target holds, and may name it through others
            return [
                SynonymInfo(schema=r[0], name=r[1], target_schema=r[2], target_name=r[3])
                for r in rows
                if (wanted is None or r[0] == wanted)
                and not synonym_names_refused_view(self.engine, (r[0], r[1]), (r[2], r[3]), targets)
            ]
        finally:
            self._module.close(conn)

    @_meta_translated
    def synonym_chains(
        self, names: Sequence[tuple[str | None, str]]
    ) -> dict[tuple[str | None, str], list[SynonymTarget]]:
        conn = self._connect()
        try:
            # every alias, public ones (SYSPUBLIC) included, as the listing reads them
            stmt = self._module.prepare(
                conn, "SELECT TABSCHEMA, TABNAME, BASE_TABSCHEMA, BASE_TABNAME FROM SYSCAT.TABLES WHERE TYPE = 'A'"
            )
            self._module.execute(stmt, ())
            targets = {}
            while row := self._module.fetch_tuple(stmt):
                targets[(_s(row[0]), _s(row[1]))] = (_s(row[2]), _s(row[3]))
        finally:
            self._module.close(conn)
        # the names as the statement looks them up, exactly (MOI."citizens" is
        # not MOI.CITIZENS), but for a delimited name's trailing blanks,
        # which Db2 drops
        return synonym_chains(names, targets, lambda n: n.rstrip(" "))

    @_meta_translated
    def name_binding(self) -> NameBinding:
        # a bare name is CURRENT SCHEMA's object, else a public alias's (SYSPUBLIC)
        conn = self._connect()
        try:
            stmt = self._module.exec_immediate(conn, "SELECT CURRENT SCHEMA FROM SYSIBM.SYSDUMMY1")
            row = self._module.fetch_tuple(stmt)
        finally:
            self._module.close(conn)
        return NameBinding((_s(row[0]),))

    @_meta_translated
    def list_routines(self, schema: str | None) -> list[RoutineInfo]:
        conn = self._connect()
        try:
            sql = "SELECT ROUTINESCHEMA, ROUTINENAME, ROUTINETYPE FROM SYSCAT.ROUTINES"
            params: list[Any] = []
            if schema:
                sql += " WHERE ROUTINESCHEMA = ?"
                params.append(schema)
            stmt = self._module.prepare(conn, sql)
            self._module.execute(stmt, tuple(params))
            rows = []
            while row := self._module.fetch_tuple(stmt):
                rows.append(row)
            kinds = {"F": "function", "P": "procedure"}
            return [RoutineInfo(schema=_s(r[0]), name=_s(r[1]), kind=kinds.get(_s(r[2]), _s(r[2]))) for r in rows]
        finally:
            self._module.close(conn)

    @_meta_translated
    def get_foreign_keys(self, schema: str | None, table: str | None) -> list[KeyInfo]:
        conn = self._connect()
        try:
            # SYSCAT.REFERENCES names the constraint and both tables;
            # SYSCAT.KEYCOLUSE supplies the column lists on both sides
            # (joined by COLSEQ, so composite keys line up). Verified live on
            # Db2 11.5.9 (2026-09-16).
            sql = (
                "SELECT r.CONSTNAME, r.TABSCHEMA, r.TABNAME, r.REFTABSCHEMA, r.REFTABNAME, "
                "k.COLNAME, k.COLSEQ, rk.COLNAME "
                "FROM SYSCAT.REFERENCES r "
                "JOIN SYSCAT.KEYCOLUSE k ON k.CONSTNAME = r.CONSTNAME "
                "AND k.TABSCHEMA = r.TABSCHEMA AND k.TABNAME = r.TABNAME "
                "JOIN SYSCAT.KEYCOLUSE rk ON rk.CONSTNAME = r.REFKEYNAME "
                "AND rk.TABSCHEMA = r.REFTABSCHEMA AND rk.TABNAME = r.REFTABNAME AND rk.COLSEQ = k.COLSEQ"
            )
            params: list[Any] = []
            predicates: list[str] = []
            if schema:
                predicates.append("r.TABSCHEMA = ?")
                params.append(schema)
            if table:
                predicates.append("r.TABNAME = ?")
                params.append(table)
            if predicates:
                sql += " WHERE " + " AND ".join(predicates)
            sql += " ORDER BY r.CONSTNAME, k.COLSEQ"
            stmt = self._module.prepare(conn, sql)
            self._module.execute(stmt, tuple(params))
            rows = self._fetch_all(stmt)
        finally:
            self._module.close(conn)
        grouped: dict[tuple[str, str, str], KeyInfo] = {}
        for name, src_schema, src_table, ref_schema, ref_table, col, _seq, ref_col in rows:
            key = (_s(name), _s(src_schema), _s(src_table))
            info = grouped.get(key)
            if info is None:
                info = KeyInfo(
                    kind="foreign_key", name=key[0], columns=[], ref_schema=_s(ref_schema), ref_table=_s(ref_table),
                    ref_columns=[], source_schema=key[1], source_table=key[2],
                )
                grouped[key] = info
            info.columns.append(str(_s(col)))
            info.ref_columns.append(str(_s(ref_col)))
        return list(grouped.values())

    @_meta_translated
    def get_statistics(self, schema: str | None, table: str) -> dict[str, Any]:
        conn = self._connect()
        try:
            sql = "SELECT CARD, STATS_TIME FROM SYSCAT.TABLES WHERE TABSCHEMA = ? AND TABNAME = ?"
            stmt = self._module.prepare(conn, sql)
            self._module.execute(stmt, (schema, table))
            row = self._module.fetch_tuple(stmt)
            if not row:
                return {"schema": schema, "table": table, "row_estimate": None, "row_estimate_source": "unavailable"}
            return {
                "schema": schema,
                "table": table,
                "row_estimate": int(row[0]) if row[0] is not None and row[0] >= 0 else None,
                "row_estimate_source": "catalog_estimate(SYSCAT.TABLES.CARD)",
                "stats_time": str(row[1]) if row[1] else None,
            }
        finally:
            self._module.close(conn)

    def execute_query(self, spec: QuerySpec) -> QueryOutcome:
        with self._exec_lock:
            return self._execute(spec)

    def _execute(self, spec: QuerySpec) -> QueryOutcome:
        import ibm_db_dbi

        with translated_driver_errors(), self._query_connect(spec.timeout_seconds):
            raw = self._connect()
        start = time.monotonic()
        truncated = False
        cell_truncated_cols: list[str] = []
        rows: list[list[Any]] = []
        approx_bytes = 0
        cur: Any = None
        import json

        try:
            # From here on a failure is the statement's (a value that does
            # not fit a column, SQL0952N at the time limit), not a connection
            # failure; ibm_db_dbi reports some as a SystemError from fetchmany.
            with translated_driver_errors(phase="execute"):
                conn = ibm_db_dbi.Connection(raw)
                # ibm_db_dbi's per-row type fix-up formats the whole row into
                # a debug message even with logging off: a 10 MB CLOB cost
                # 17 MB of memory per row that was never given back. Its one
                # conversion that matters (DECIMAL text, possibly with a
                # locale's ',', to Decimal) is done below; BLOB bytes need none.
                no_fix = getattr(conn, "set_fix_return_type", None)
                if callable(no_fix):
                    no_fix(False)
                cur = conn.cursor()
                params = tuple(spec.parameters) if isinstance(spec.parameters, list) else spec.parameters
                described = self._described(raw, spec.sql)
                capped = _db2_capped_select(spec.sql, described, spec.max_cell_bytes) if described else None
                if capped is None:
                    cur.execute(spec.sql, params)
                else:
                    self._execute_capped(cur, capped, params, described or [])
                cols = [(d[0], "unknown") for d in cur.description or []]
                col_labels = [
                    getattr(d[1], "__name__", "unknown").lower() if d[1] is not None else "unknown"
                    for d in (cur.description or [])
                ]
                # ibm_db reads every CLOB, DBCLOB, BLOB and XML value of the
                # rows it fetches whole (cut on the server above, to a few
                # times the cell limit): such a result is fetched one row at
                # a time, and a row is let go before the next is read.
                lob_types = [t for t in (getattr(ibm_db_dbi, n, None) for n in ("TEXT", "BINARY", "XML")) if t]
                one_by_one = any(any(d[1] is t for t in lob_types) for d in cur.description or [])
                decimal_type = getattr(ibm_db_dbi, "DECIMAL", None)
                decimals = [i for i, d in enumerate(cur.description or []) if decimal_type and d[1] is decimal_type]
                while True:
                    batch = cur.fetchmany(1 if one_by_one else next_fetch_size(spec.max_rows, len(rows)))
                    if not batch:
                        break
                    for r in batch:
                        if decimals:
                            r = [
                                Decimal(str(v).replace(",", ".")) if i in decimals and v is not None else v
                                for i, v in enumerate(r)
                            ]
                        vals, labels, cut = adapt_row(r, spec.max_cell_bytes)
                        if not col_labels:
                            col_labels = labels
                        cell_truncated_cols.extend(column_names_at(cols, cut))
                        approx_bytes += len(json.dumps(vals, default=str).encode("utf-8"))
                        if len(rows) >= spec.max_rows or approx_bytes > spec.max_response_bytes:
                            truncated = True
                            break
                        rows.append(vals)
                    del batch, r
                    if truncated:
                        break
            warnings = ["result truncated by limits"] if truncated else []
            if cell_truncated_cols:
                truncated = True
                warnings.append(cell_truncation_warning(cell_truncated_cols, spec.max_cell_bytes))
            return QueryOutcome(
                columns=[(c[0], t) for c, t in zip(cols, col_labels or ["unknown"] * len(cols), strict=True)],
                rows=rows,
                truncated=truncated,
                rows_seen=len(rows),
                elapsed_ms=int((time.monotonic() - start) * 1000),
                warnings=warnings,
            )
        finally:
            # The statement handle goes before the connection: one freed
            # later, by the garbage collector after the connection closed,
            # left an error set that failed the next query's fetch
            # ('Fetch Failure: ' after any failed statement, live).
            if cur is not None:
                try:
                    cur.close()
                except Exception:  # noqa: BLE001, S110
                    pass
            try:
                self._module.close(raw)
            except Exception:  # noqa: BLE001, S110
                pass

    def _described(self, raw: Any, sql: str) -> list[tuple[str, str]] | None:
        """The statement's result columns as (name, ibm_db type name), from
        a prepare: Db2 describes the statement and runs nothing. None from a
        driver module without ibm_db's describe calls."""
        num_fields = getattr(self._module, "num_fields", None)
        if not callable(num_fields):
            return None
        stmt = self._module.prepare(raw, sql)
        try:
            count = num_fields(stmt)
            return [
                (str(self._module.field_name(stmt, i)), str(self._module.field_type(stmt, i)).lower())
                for i in range(count or 0)
            ]
        finally:
            self._module.free_stmt(stmt)

    @staticmethod
    def _execute_capped(cur: Any, capped: str, params: Any, described: list[tuple[str, str]]) -> None:
        """Run the value-capped rewrite of the statement. Fails closed: a
        rewrite Db2 refuses (SQLSTATE class 42: its syntax or its names) is
        the query's failure, never a reason to run the statement with its
        values read whole."""
        try:
            cur.execute(capped, params)
        except Exception as exc:
            if not (ibm_db_sqlstate(exc) or "").startswith("42"):
                raise
            lobs = ", ".join(repr(name) for name, kind in described if kind in _DB2_LOB_TYPES)
            raise ConnectorError(
                f"the statement returns CLOB, DBCLOB, BLOB or XML column(s) {lobs}, and Db2 refused it with "
                f"those values cut to the cell limit on the server ({scrub_exception(exc)}); select "
                "SUBSTRING(<column>, 1, <n>, CODEUNITS32) (XMLSERIALIZE an XML column first) instead",
                category="QUERY_ERROR",
            ) from exc

    def explain(self, sql: str, analyze: bool) -> dict[str, Any]:
        """EXPLAIN PLAN into the explain tables, read back as operators.

        Db2 writes the plan into EXPLAIN_* tables that a DBA provisions once
        (`CALL SYSPROC.SYSINSTALLOBJECTS('EXPLAIN','C',NULL,NULL)`, usually
        into SYSTOOLS); they are looked up in the session authorization id's
        schema first, then SYSTOOLS, exactly as the engine does. Without them
        the call fails with that instruction: nothing is created here. The
        rows written for this call are deleted again; the statement is never
        executed.
        """
        if analyze:
            raise NotImplementedError(EXPLAIN_ANALYZE_UNSUPPORTED)
        queryno = secrets.randbelow(2_000_000_000) + 1
        cleanup_warning: str | None = None
        with translated_driver_errors():
            conn = self._connect()
            try:
                schema = self._explain_schema(conn)
            except BaseException:
                self._module.close(conn)
                raise
            if schema is None:
                self._module.close(conn)
        if schema is None:
            # outside the driver-error translation: "unsupported here" is a
            # capability statement, not a driver failure
            raise NotImplementedError(
                "Db2 explain tables are not provisioned for this account (no EXPLAIN_STATEMENT in the "
                "session schema or SYSTOOLS); a DBA creates them once with "
                "CALL SYSPROC.SYSINSTALLOBJECTS('EXPLAIN','C',NULL,NULL)"
            )
        with translated_driver_errors():
            try:
                q = self.quote_identifier(schema)
                self._module.exec_immediate(conn, f"EXPLAIN PLAN SET QUERYNO = {int(queryno)} FOR {sql}")  # noqa: S608
                stmt = self._module.prepare(
                    conn,
                    f"SELECT EXPLAIN_REQUESTER, EXPLAIN_TIME, SOURCE_NAME, SOURCE_SCHEMA, SOURCE_VERSION, "
                    f"EXPLAIN_LEVEL, STMTNO, SECTNO, TOTAL_COST FROM {q}.EXPLAIN_STATEMENT "
                    f"WHERE QUERYNO = ? AND EXPLAIN_LEVEL = 'P' ORDER BY EXPLAIN_TIME DESC",  # noqa: S608
                )
                self._module.execute(stmt, (queryno,))
                heads = self._fetch_all(stmt)
                if not heads:
                    raise ConnectorError("Db2 EXPLAIN PLAN wrote no plan statement (explain tables present but empty)")
                head = heads[0]
                keys = tuple(head[:8])
                stmt = self._module.prepare(
                    conn,
                    f"SELECT o.OPERATOR_ID, o.OPERATOR_TYPE, o.TOTAL_COST, o.IO_COST, o.CPU_COST, "
                    f"s.OBJECT_SCHEMA, s.OBJECT_NAME, s.STREAM_COUNT "
                    f"FROM {q}.EXPLAIN_OPERATOR o LEFT JOIN {q}.EXPLAIN_STREAM s "
                    f"ON s.EXPLAIN_REQUESTER = o.EXPLAIN_REQUESTER AND s.EXPLAIN_TIME = o.EXPLAIN_TIME "
                    f"AND s.SOURCE_NAME = o.SOURCE_NAME AND s.SOURCE_SCHEMA = o.SOURCE_SCHEMA "
                    f"AND s.SOURCE_VERSION = o.SOURCE_VERSION AND s.EXPLAIN_LEVEL = o.EXPLAIN_LEVEL "
                    f"AND s.STMTNO = o.STMTNO AND s.SECTNO = o.SECTNO AND s.TARGET_ID = o.OPERATOR_ID "
                    f"AND s.OBJECT_NAME IS NOT NULL "
                    f"WHERE o.EXPLAIN_REQUESTER = ? AND o.EXPLAIN_TIME = ? AND o.SOURCE_NAME = ? "
                    f"AND o.SOURCE_SCHEMA = ? AND o.SOURCE_VERSION = ? AND o.EXPLAIN_LEVEL = ? "
                    f"AND o.STMTNO = ? AND o.SECTNO = ? ORDER BY o.OPERATOR_ID",  # noqa: S608
                )
                self._module.execute(stmt, keys)
                ops = self._fetch_all(stmt)
                try:
                    stmt = self._module.prepare(
                        conn, f"DELETE FROM {q}.EXPLAIN_INSTANCE WHERE EXPLAIN_REQUESTER = ? AND EXPLAIN_TIME = ?"  # noqa: S608
                    )
                    self._module.execute(stmt, (keys[0], keys[1]))
                except Exception as exc:  # noqa: BLE001 - scratch rows stay behind: reported, never hidden
                    code = re.search(r"SQL\d{4,5}[NWC]|SQLSTATE[= ]*\w{5}", str(exc))
                    cleanup_warning = (
                        f"the explain rows written for this call could not be deleted from {schema}.EXPLAIN_INSTANCE"
                        + (f" ({code.group(0)})" if code else "")
                        + "; the account needs DELETE on the explain tables (INSERT is needed to write them); "
                        "a DBA can prune EXPLAIN_INSTANCE"
                    )
            finally:
                self._module.close(conn)
        rows = [
            {
                "operator_id": r[0], "operator": _s(r[1]), "total_cost": r[2], "io_cost": r[3], "cpu_cost": r[4],
                "object_schema": _s(r[5]) if r[5] else None, "object_name": _s(r[6]) if r[6] else None,
                "stream_count": r[7],
            }
            for r in ops
        ]
        text = "\n".join(
            f"{r['operator_id']:>3} {r['operator']:<8} cost={r['total_cost']}"
            + (f" {r['object_schema']}.{r['object_name']}" if r["object_name"] else "")
            for r in rows
        )
        return {
            "raw": text or None, "rows": rows, "total_cost": head[8],
            "method": f"EXPLAIN PLAN into {schema}.EXPLAIN_* (timerons), not executed",
            **({"cleanup_warning": cleanup_warning} if cleanup_warning else {}),
        }

    def _explain_schema(self, conn: Any) -> str | None:
        """The schema whose explain tables Db2 would use for this session:
        the session authorization id's, then SYSTOOLS."""
        stmt = self._module.exec_immediate(
            conn,
            "SELECT TABSCHEMA FROM SYSCAT.TABLES WHERE TABNAME = 'EXPLAIN_STATEMENT' "
            "AND TABSCHEMA IN (SESSION_USER, 'SYSTOOLS')",
        )
        found = {_s(r[0]) for r in self._fetch_all(stmt)}
        stmt = self._module.exec_immediate(conn, "VALUES (SESSION_USER)")
        me = str(_s(self._fetch_all(stmt)[0][0]))
        if me in found:
            return me
        if "SYSTOOLS" in found:
            return "SYSTOOLS"
        return None
