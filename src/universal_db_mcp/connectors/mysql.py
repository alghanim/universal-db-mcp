"""MySQL / MariaDB connector (PyMySQL, pure Python).

Integration status: implemented against PyMySQL documented APIs; live
behaviors are marked ``unverified`` until Gate C proves them. TLS uses the
explicit CA file; verification is never disabled. Metadata calls reuse a
lock-guarded pooled connection (spec §7) — PyMySQL connections are not
thread-safe, so the lock is held for the *entire* use of the shared
connection, not just the checkout probe; queries run serialized on fresh
connections so cancellation/discards are well-defined.
"""

from __future__ import annotations

import math
import struct
import threading
import time
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

import sqlglot
from sqlglot import TokenType, exp

from universal_db_mcp.config import ResolvedConnection
from universal_db_mcp.connectors.base import (
    EXPLAIN_ANALYZE_UNSUPPORTED,
    ColumnInfo,
    ConnectorError,
    DatabaseConnector,
    HealthInfo,
    IndexInfo,
    KeyInfo,
    QueryOutcome,
    QuerySpec,
    RoutineInfo,
    SynonymInfo,
    TableSummary,
    ViewInfo,
    own_objects_first,
)
from universal_db_mcp.connectors.driver_helpers import (
    SelectList,
    adapt_row,
    cell_truncation_warning,
    column_names_at,
    next_fetch_size,
    open_module,
    statement_body,
    translated_driver_errors,
)
from universal_db_mcp.discovery.system_schemas import is_session_sql_view
from universal_db_mcp.models.capabilities import Cap, CapabilityMatrix, CapabilityState, Limitation
from universal_db_mcp.security.policy import EffectivePolicy
from universal_db_mcp.security.redact import scrub_exception
from universal_db_mcp.security.sql_guard import mask_pyformat_placeholders, translate_paramstyle

# PyMySQL FIELD_TYPE codes -> stable column labels (driver-derived, not
# data-derived).
_MYSQL_TYPE_LABELS = {
    0: "decimal",
    1: "integer",
    2: "integer",
    3: "integer",
    4: "real",
    5: "real",
    8: "bigint",
    9: "bigint",
    10: "date",
    12: "datetime",
    13: "time",
    15: "text",
    16: "integer",
    245: "text",
    246: "decimal",
    249: "blob",
    250: "blob",
    251: "blob",
    252: "blob",
    253: "text",
    254: "text",
}

# Result types that can hold gigabytes (the TEXT/BLOB family, JSON,
# GEOMETRY; MySQL also reports long string expressions such as REPEAT() as
# BLOB types) and the VARCHAR family, which a row can hold at most 64 KiB of.
_MYSQL_LOB_TYPES = frozenset({245, 249, 250, 251, 252, 255})
_MYSQL_STRING_TYPES = frozenset({15, 253, 254})


# MySQL errors that refuse a rewrite the statement itself did not have: a
# syntax or placement error, a name MySQL will not take as an alias, and a
# derived table's column it names differently or twice.
_REWRITE_REFUSED = frozenset({1054, 1059, 1060, 1064, 1166, 1234})
# The prepared-statement protocol does not take the statement (some SHOW
# forms): it is not described.
_PREPARE_UNSUPPORTED = 1295
# Longest name MySQL takes as an identifier.
_MYSQL_NAME_MAX = 64
# The server's own schemas, which list_tables leaves out unless allowed.
_MYSQL_SYSTEM_SCHEMAS = ("mysql", "information_schema", "performance_schema", "sys")
# information_schema views of the statements other sessions are running, with
# their literals: PROCESSLIST shows every session of the account this server
# shares between callers (every account's with PROCESS), and INNODB_TRX's
# trx_query needs PROCESS. information_schema is open by default
# (security.allowed_system_schemas), so list_tables never lists these, and the
# resolver never finds them. sys's lock-wait views show the waiting and
# blocking sessions' statements the same way (INNODB_TRX.trx_query,
# threads.PROCESSLIST_INFO), and the one allowed_system_schemas list opens
# MySQL's sys wherever 'sys' is named for SQL Server's or Oracle's
# dictionary. INNODB_FT_INDEX_CACHE and _TABLE hold the indexed words of
# whichever table innodb_ft_aux_table names, allowlisted or not, and
# INNODB_LOCKS (MySQL 5.7, MariaDB) the key values of the rows other
# transactions have locked in any table (LOCK_DATA, with PROCESS); MariaDB's
# query_cache_info plugin adds QUERY_CACHE_INFO, the text of every cached
# SELECT. performance_schema's processlist, threads and events_statements_*,
# and the column statistics, are left out too wherever they are opened
# (is_session_sql_view: the policy refuses them whatever is opened).
_MYSQL_NEVER_LISTED = frozenset({
    ("information_schema", "processlist"),
    ("information_schema", "innodb_trx"),
    ("information_schema", "innodb_locks"),
    ("information_schema", "query_cache_info"),
    ("information_schema", "innodb_ft_index_cache"),
    ("information_schema", "innodb_ft_index_table"),
    ("sys", "innodb_lock_waits"),
    ("sys", "x$innodb_lock_waits"),
    ("sys", "schema_table_lock_waits"),
    ("sys", "x$schema_table_lock_waits"),
})

# sql_mode flags under which MySQL or MariaDB reads a statement differently
# from the guard, which parses the default mode: ANSI_QUOTES makes "x" an
# identifier (a string to the guard), NO_BACKSLASH_ESCAPES ends 'a\' at the
# backslash (live: 'a\', INFO FROM information_schema.PROCESSLIST #' read
# PROCESSLIST where the guard saw one string), PIPES_AS_CONCAT makes || a
# concatenation (OR to the guard), HIGH_NOT_PRECEDENCE binds NOT tighter than
# BETWEEN, and the combination modes that set them (ANSI; ORACLE, MSSQL, DB2,
# POSTGRESQL and MAXDB on MariaDB and MySQL 5.7, where MariaDB's ORACLE also
# switches the parser). A site sets them globally or through init_connect;
# the session keeps the site's other flags.
_MYSQL_LEXING_MODES = (
    "ANSI", "ANSI_QUOTES", "NO_BACKSLASH_ESCAPES", "PIPES_AS_CONCAT", "HIGH_NOT_PRECEDENCE",
    "ORACLE", "MSSQL", "DB2", "POSTGRESQL", "MAXDB",
)


def _mysql_sql_mode_statements() -> tuple[str, str]:
    """The session's sql_mode without _MYSQL_LEXING_MODES, computed by the
    server from its own value (each flag cut out of ',<mode>,' in turn); and
    the check that fails the connect (a NULL sql_mode is refused,
    ER_WRONG_VALUE_FOR_VAR) unless none of those flags is left."""
    mode = "CONCAT(',', @@session.sql_mode, ',')"
    for flag in _MYSQL_LEXING_MODES:
        mode = f"REPLACE({mode}, ',{flag},', ',')"
    lexing = " OR ".join(f"FIND_IN_SET('{flag}', @@session.sql_mode)" for flag in _MYSQL_LEXING_MODES)
    return (
        f"SET SESSION sql_mode = TRIM(BOTH ',' FROM {mode})",
        f"SET SESSION sql_mode = IF({lexing}, NULL, @@session.sql_mode)",
    )


_MYSQL_PIN_SQL_MODE, _MYSQL_CHECK_SQL_MODE = _mysql_sql_mode_statements()
# The client character set PyMySQL encodes in (charset utf8mb4), held where
# a client init_command or a proxy left another: in GBK or SJIS a backslash
# can be a character's second byte, which ends a string the guard reads on.
# The check fails the connect the same way unless it holds.
_MYSQL_PIN_CHARSET = "SET NAMES utf8mb4"
_MYSQL_CHECK_CHARSET = (
    "SET SESSION sql_mode = IF(@@session.character_set_client <> 'utf8mb4', NULL, @@session.sql_mode)"
)


def _mysql_select(sql: str, tree: exp.Expr | None = None) -> SelectList | None:
    """The select list of ``sql`` when MySQL can describe it under a
    top-level LIMIT 0 without running it; None otherwise. ``tree`` is
    ``_mysql_parse(sql)`` when the caller has it.

    MySQL does not execute a statement whose own LIMIT is 0 (measured on
    MySQL 9.7: a primary-key lookup, LIMIT 1 over a sorted join and SLEEP()
    all return in 0.00 s), except a CTE it materializes. Only SELECTs that
    read tables, return rows and contain no subquery or CTE are described:
    the optimizer evaluates what yields at most one row while planning on
    releases this was not measured on (MariaDB). The rest are described
    through the prepared-statement protocol instead.
    """
    select = SelectList.locate(statement_body(sql, "mysql"), "mysql", mask=mask_pyformat_placeholders, tree=tree)
    if select is None:
        return None
    tree = select.tree
    if (
        not tree.args.get("from_")
        or tree.args.get("into")
        or tree.args.get("locks")
        or tree.find(exp.With) is not None
        or len(list(tree.find_all(exp.Select))) != 1
        or (not tree.args.get("group") and any(a.find_ancestor(exp.Window) is None for a in tree.find_all(exp.AggFunc)))
    ):
        return None
    return select


def _mysql_describe_probe(select: SelectList) -> str | None:
    """The statement under a top-level ``LIMIT 0``: its own LIMIT (always its
    last clause here) replaced, or one appended; None for a bound LIMIT,
    which would leave a parameter without its marker."""
    if select.tree.args.get("limit") is None:
        return select.sql + "\nLIMIT 0"
    outer = select.outer_tokens()
    at = max((i for i, t in enumerate(outer) if t.token_type == TokenType.LIMIT), default=None)
    if at is None or any(
        t.token_type not in (TokenType.NUMBER, TokenType.COMMA, TokenType.OFFSET) for t in outer[at + 1:]
    ):
        return None
    return select.sql[: outer[at].start] + "LIMIT 0"


def _mysql_compared_outputs(tree: exp.Select, names: list[str]) -> set[int]:
    """Output columns the statement orders, groups or filters by, under
    their output name or position. MySQL resolves such a reference to the
    output column, so cutting it there would order, group or compare by its
    first max_cell_bytes characters."""
    lowered = [n.lower() for n in names]
    out: set[int] = set()
    for key in ("order", "group", "having"):
        clause = tree.args.get(key)
        if clause is None:
            continue
        for column in clause.find_all(exp.Column):
            if not column.table:
                out.update(i for i, n in enumerate(lowered) if n == column.name.lower())
        for item in clause.expressions if key != "having" else []:
            key_expr = item.this if isinstance(item, exp.Ordered) else item
            if isinstance(key_expr, exp.Literal) and not key_expr.is_string and key_expr.this.isdigit():
                out.add(int(key_expr.this) - 1)
    return out


def _mysql_cut_columns(description: Sequence[Any], max_cell_bytes: int) -> set[int]:
    """Output columns whose values can exceed the cell limit."""
    cut: set[int] = set()
    for i, d in enumerate(description):
        size = d[3] if len(d) > 3 else None  # PEP 249 internal_size: the declared maximum length
        if (d[1] in _MYSQL_LOB_TYPES and (size is None or size > max_cell_bytes)) or (
            d[1] in _MYSQL_STRING_TYPES and size is not None and size > max_cell_bytes
        ):
            cut.add(i)
    return cut


def _mysql_quote(name: str, *, bound: bool) -> str:
    """A backtick-quoted name; '%' doubled when parameters are bound
    (PyMySQL formats the text then)."""
    quoted = "`" + name.replace("`", "``") + "`"
    return quoted.replace("%", "%%") if bound else quoted


def _mysql_capped_select(
    select: SelectList, description: Sequence[Any], cut: set[int], max_cell_bytes: int, *, bound: bool
) -> str | None:
    """The statement with the output columns at ``cut`` cut by the server
    to ``max_cell_bytes + 1`` (so a cut is still detected here) and kept
    under their own names, so masking by name still applies; None when the
    rewrite cannot be exact. Only the select list changes, so MySQL plans
    and streams the statement as written. LEFT() keeps binary values
    binary. A column the statement orders, groups or filters by, or a
    DISTINCT, cannot be cut in the select list."""
    names = [str(d[0]) for d in description]
    if cut & _mysql_compared_outputs(select.tree, names) or select.tree.args.get("distinct"):
        return None
    keep = max_cell_bytes + 1
    return select.rewrite(
        names, cut, lambda text: f"LEFT({text}, {keep})", lambda name: _mysql_quote(name, bound=bound)
    )


def _mysql_derived_selects(
    sql: str, description: Sequence[Any], cut: set[int], max_cell_bytes: int, *, bound: bool
) -> list[str]:
    """The statement as a derived table whose columns at ``cut`` the server
    cuts to ``max_cell_bytes + 1``, each output under its own name: first
    with the columns referenced by name (unique names MySQL can quote; any
    release), then by position through a derived column list (MySQL 8.0).

    The statement stays whole inside, so what it orders, groups or compares
    it does on the full values. MySQL merges such a derived table into the
    outer query and keeps its ORDER BY, or materializes it (a UNION, DISTINCT
    or GROUP BY, which mostly do so already) in that order."""
    keep = max_cell_bytes + 1
    names = [str(d[0]) for d in description]
    body = statement_body(sql, "mysql")
    forms: list[tuple[list[str], str]] = []
    if all(0 < len(n) <= _MYSQL_NAME_MAX for n in names) and len({n.lower() for n in names}) == len(names):
        forms.append(([f"udbmcp_q.{_mysql_quote(n, bound=bound)}" for n in names], ""))
    positions = [f"c{i}" for i in range(1, len(names) + 1)]
    forms.append(([f"udbmcp_q.{p}" for p in positions], f"({', '.join(positions)})"))
    out: list[str] = []
    for refs, column_list in forms:
        items = [
            f"{f'LEFT({ref}, {keep})' if i in cut else ref} AS {_mysql_quote(name, bound=bound)}"
            for i, (ref, name) in enumerate(zip(refs, names, strict=True))
        ]
        out.append(f"SELECT {', '.join(items)} FROM (\n{body}\n) AS udbmcp_q{column_list}")
    return out


def _mysql_parse(sql: str) -> exp.Expr | None:
    """The statement's parse; None when sqlglot cannot read it."""
    try:
        return sqlglot.parse_one(mask_pyformat_placeholders(statement_body(sql, "mysql")), read="mysql")
    except Exception:  # noqa: BLE001 - sqlglot's errors, and whatever else a parser raises
        return None


def _mysql_orders_rows(tree: exp.Expr | None) -> bool:
    """Whether the statement orders its own rows (an ORDER BY of its
    outermost query); True when that cannot be told."""
    while isinstance(tree, exp.Subquery) and isinstance(tree.this, exp.Query):
        tree = tree.this
    return tree is None or tree.args.get("order") is not None


@dataclass(frozen=True)
class _CapPlan:
    """How a statement runs with its values cut on the server: the
    rewrites to try, most preferred first; the column labels of the
    statement as written; the names of the columns that are cut."""

    rewrites: list[str]
    labels: list[str]
    columns: list[str]


def _uncut_refusal(columns: list[str], reason: str) -> ConnectorError:
    return ConnectorError(
        f"the statement returns TEXT, BLOB, JSON or GEOMETRY column(s) {', '.join(repr(c) for c in columns)} "
        f"whose values could not be cut to the cell limit on the server ({reason}); select "
        "LEFT(<column>, <n>) for them instead",
        category="QUERY_ERROR",
    )


class MySQLConnector(DatabaseConnector):
    engine = "mysql"

    def __init__(self, connection: ResolvedConnection, policy: EffectivePolicy) -> None:
        super().__init__(connection, policy)
        self._module: Any = None
        self._exec_lock = threading.Lock()  # serializes queries
        self._kill_lock = threading.Lock()  # guards _running_thread
        self._running_thread: int | None = None  # server thread id of the executing query
        self._pool_lock = threading.Lock()
        self._meta_conn: Any = None  # reused metadata connection (ping on checkout)

    @contextmanager
    def _shared_meta_conn(self) -> Iterator[Any]:
        """Reusable metadata connection with ping-on-checkout (spec §7
        connection pooling; one connection per connector).

        A PyMySQL connection is a single socket with an unbuffered
        (``SSCursor``) protocol stream and is not thread-safe, so
        ``_pool_lock`` is held for the whole ``with`` block — checkout,
        cursor use and fetch — mirroring how ``_exec_lock`` serializes
        queries. If the block raises, the connection is discarded (closed and
        dropped) rather than reused with a possibly half-read result stream;
        the next caller reconnects.
        """
        with self._pool_lock:
            if self._meta_conn is not None:
                try:
                    self._meta_conn.ping(reconnect=False)
                except Exception:  # noqa: BLE001 - stale connection, rebuild
                    self._discard_meta_conn()
            if self._meta_conn is None:
                self._meta_conn = self._connect()
            try:
                yield self._meta_conn
            except BaseException:
                self._discard_meta_conn()
                raise

    def _discard_meta_conn(self) -> None:
        """Close and forget the shared metadata connection (caller holds
        ``_pool_lock``). Close errors are irrelevant: the object is dropped."""
        conn, self._meta_conn = self._meta_conn, None
        if conn is not None:
            try:
                conn.close()
            except Exception:  # noqa: BLE001, S110
                pass

    def close(self) -> None:
        with self._pool_lock:
            self._discard_meta_conn()

    def quote_identifier(self, name: str) -> str:
        """MySQL/MariaDB identifier quoting. Double quotes are string
        literals under the default ``sql_mode`` (only ``ANSI_QUOTES`` makes
        them identifiers), so the ANSI default from the base class would turn
        ``SELECT "col" FROM "t"`` into a constant-string select or a syntax
        error. Backticks are always identifiers; an embedded backtick is
        escaped by doubling it."""
        return "`" + name.replace("`", "``") + "`"

    def _connect(self) -> Any:
        kw = self._connect_kwargs()
        try:
            conn = self._module.connect(**kw)
        except AttributeError as exc:
            # PyMySQL dispatches mysql_old_password (pre-4.1 hashes, removed in
            # MySQL 5.7.5) to a helper it no longer ships, so the driver raises
            # AttributeError and the operator sees what looks like our internal
            # defect rather than an unsupported authentication plugin.
            if "scramble_old_password" in str(exc):
                raise ConnectorError(
                    "the MySQL account uses the legacy mysql_old_password authentication plugin, "
                    "which this client cannot perform. Have the DBA move the account to "
                    "mysql_native_password or caching_sha2_password "
                    "(ALTER USER ... IDENTIFIED WITH caching_sha2_password BY '<password>')"
                ) from exc
            raise
        self._configure_session(conn)
        # The handshake and the session setup were bounded by the connect
        # timeout; statements may read for the policy's hard timeout plus a
        # margin. PyMySQL has no public setter for its read timeout.
        conn._read_timeout = int(self.policy.hard_query_timeout_seconds) + 5
        return conn

    def _connect_kwargs(self) -> dict[str, Any]:
        self._module = open_module("pymysql", "PyMySQL (pure-Python wheel from the bundle wheelhouse)")
        cfg = self.connection.config
        # rounded up: PyMySQL refuses 0, which int(0.5) was
        bound = max(1, math.ceil(cfg.connect_timeout_seconds))
        kw: dict[str, Any] = {
            "host": cfg.host,
            "port": cfg.port or 3306,
            "database": cfg.database,
            "connect_timeout": bound,
            "charset": "utf8mb4",
            # the handshake is a read too: without this bound a listener that
            # accepts and never answers held the connect for the query timeout
            "read_timeout": bound,
            "cursorclass": self._module.cursors.SSCursor,  # streaming; bounded fetch below
            "autocommit": True,  # reads only; no transaction state to leak
        }
        if socket_path := cfg.options.get("unix_socket"):
            # A co-located server with no TCP listener: PyMySQL ignores host
            # entirely when unix_socket is given, so do not send a bogus one.
            kw.pop("host", None)
            kw["unix_socket"] = socket_path
        if self.connection.username:
            kw["user"] = self.connection.username.value
        if self.connection.password:
            kw["password"] = self.connection.password.value
        if cfg.tls.enabled:
            kw["ssl"] = {
                "ca": cfg.tls.ca_file,
                "check_hostname": cfg.tls.verify_server,
            }
            if cfg.tls.client_cert_file:
                kw["ssl"]["cert"] = cfg.tls.client_cert_file
            if cfg.tls.client_key_file:
                kw["ssl"]["key"] = cfg.tls.client_key_file
        kw["program_name"] = self.session_profile.application_name
        return kw

    def _configure_session(self, conn: Any) -> None:
        """Apply the session safety profile. READ ONLY is required when
        requested (MySQL 5.6.5+, MariaDB 10.0+); the ceilings are
        best-effort because their names differ across versions and forks
        (max_execution_time on MySQL 5.7.8+, max_statement_time on MariaDB).
        The sql_mode the guard parses under (_MYSQL_LEXING_MODES) and the
        utf8mb4 client character set are required on every connection,
        first, and each refusal names its own cause."""
        prof = self.session_profile
        self._session_reset()
        with conn.cursor() as cur:
            try:
                cur.execute(_MYSQL_PIN_SQL_MODE)
                cur.execute(_MYSQL_CHECK_SQL_MODE)
                self._session_applied("sql_mode without " + ", ".join(_MYSQL_LEXING_MODES))
            except Exception as exc:  # noqa: BLE001
                raise self._reading_required("an sql_mode without " + ", ".join(_MYSQL_LEXING_MODES), exc) from exc
            try:
                cur.execute(_MYSQL_PIN_CHARSET)
                cur.execute(_MYSQL_CHECK_CHARSET)
                self._session_applied("character_set_client=utf8mb4")
            except Exception as exc:  # noqa: BLE001
                raise self._reading_required("the utf8mb4 client character set", exc) from exc
            if prof.enforce_read_only:
                try:
                    cur.execute("SET SESSION TRANSACTION READ ONLY")
                    self._session_applied("read_only")
                except Exception as exc:  # noqa: BLE001
                    raise self._session_required("read-only mode", exc) from exc
            if prof.isolation:
                level = prof.isolation.replace("_", " ").upper()
                try:
                    cur.execute(f"SET SESSION TRANSACTION ISOLATION LEVEL {level}")
                    self._session_applied(f"isolation={prof.isolation}")
                except Exception as exc:  # noqa: BLE001
                    raise self._session_required(f"isolation {prof.isolation}", exc) from exc
            if prof.statement_timeout_seconds:
                ms = int(math.ceil(prof.statement_timeout_seconds * 1000))
                try:
                    cur.execute(f"SET SESSION max_execution_time = {ms}")
                    self._session_applied(f"statement_timeout={ms}ms")
                except Exception as exc:  # noqa: BLE001
                    try:  # MariaDB spells it differently and takes seconds
                        cur.execute(f"SET SESSION max_statement_time = {math.ceil(prof.statement_timeout_seconds)}")
                        self._session_applied(f"statement_timeout(mariadb)={math.ceil(prof.statement_timeout_seconds)}s")
                    except Exception:  # noqa: BLE001
                        self._session_skipped("statement_timeout", exc)
            if prof.lock_timeout_seconds is not None:
                secs = max(1, int(math.ceil(prof.lock_timeout_seconds)))
                for var in ("innodb_lock_wait_timeout", "lock_wait_timeout"):
                    try:
                        cur.execute(f"SET SESSION {var} = {secs}")
                        self._session_applied(f"{var}={secs}s")
                    except Exception as exc:  # noqa: BLE001
                        self._session_skipped(var, exc)

    def _session_readback(self, conn: Any) -> dict[str, Any]:
        out: dict[str, Any] = {}
        with conn.cursor() as cur:
            for key, exprs in (
                ("read_only", ("@@session.transaction_read_only", "@@session.tx_read_only")),
                ("isolation", ("@@session.transaction_isolation", "@@session.tx_isolation")),
                ("statement_timeout_ms", ("@@session.max_execution_time",)),
                ("statement_timeout_s", ("@@session.max_statement_time",)),  # MariaDB
                ("innodb_lock_wait_timeout", ("@@session.innodb_lock_wait_timeout",)),
                ("sql_mode", ("@@session.sql_mode",)),
                ("character_set_client", ("@@session.character_set_client",)),
            ):
                for expr in exprs:
                    try:
                        cur.execute(f"SELECT {expr}")
                        rows = cur.fetchall()
                        if rows:
                            out[key] = str(rows[0][0])
                            break
                    except Exception:  # noqa: BLE001, S112 - the other spelling may exist
                        continue
        return out

    def cancel_current(self) -> bool:
        """Stop the executing query with KILL QUERY <thread id> from a
        short-lived second connection (PyMySQL has no out-of-band cancel).
        The server ends the statement, so an abandoned worker stops reading
        instead of streaming the rest of the result. An account may always
        kill its own threads."""
        with self._kill_lock:
            thread_id = self._running_thread
        if thread_id is None:
            return False
        try:
            kw = self._connect_kwargs()
            del kw["cursorclass"]
            killer = self._module.connect(**kw)
            try:
                with killer.cursor() as cur:
                    cur.execute(f"KILL QUERY {int(thread_id)}")
            finally:
                killer.close()
            return True
        except Exception:  # noqa: BLE001 - best effort: the executor discards the connection anyway
            return False

    def capabilities(self) -> CapabilityMatrix:
        return CapabilityMatrix(
            engine="mysql",
            engine_family="mysql/mariadb",
            driver="PyMySQL",
            capabilities={
                Cap.CONNECT: CapabilityState.UNVERIFIED,
                Cap.HEALTH: CapabilityState.UNVERIFIED,
                Cap.LIST_SCHEMAS: CapabilityState.UNVERIFIED,
                Cap.LIST_TABLES: CapabilityState.UNVERIFIED,
                Cap.GET_TABLE: CapabilityState.UNVERIFIED,
                Cap.LIST_COLUMNS: CapabilityState.UNVERIFIED,
                Cap.LIST_VIEWS: CapabilityState.UNVERIFIED,
                Cap.LIST_SYNONYMS: CapabilityState.UNSUPPORTED,
                Cap.LIST_ROUTINES: CapabilityState.UNVERIFIED,
                Cap.RELATIONSHIPS: CapabilityState.UNVERIFIED,
                Cap.STATISTICS: CapabilityState.UNVERIFIED,
                Cap.QUERY: CapabilityState.UNVERIFIED,
                Cap.PARAMETERS: CapabilityState.UNVERIFIED,
                Cap.CANCEL: CapabilityState.UNVERIFIED,
                Cap.SERVER_SIDE_CANCEL: CapabilityState.UNVERIFIED,
                Cap.EXPLAIN: CapabilityState.UNVERIFIED,
                Cap.EXPLAIN_ANALYZE: CapabilityState.UNSUPPORTED,
                Cap.SAMPLE: CapabilityState.UNVERIFIED,
                Cap.TLS: CapabilityState.UNVERIFIED,
            },
            limitations=[
                Limitation(
                    scope="cancel",
                    detail="PyMySQL exposes no out-of-band cancellation; on timeout the "
                    "query is stopped with KILL QUERY from a short-lived second connection "
                    "and the connection is discarded.",
                ),
                Limitation(scope="explain", detail=f"{EXPLAIN_ANALYZE_UNSUPPORTED}."),
                Limitation(
                    scope="query",
                    detail="Values that can exceed the cell limit (TEXT, BLOB, JSON, GEOMETRY, long VARCHAR) "
                    "are cut by the server: in the select list of a plain SELECT, otherwise with the statement "
                    "as a derived table, described first through the prepared-statement protocol (which runs "
                    "nothing). Such a derived table with a UNION, DISTINCT or GROUP BY is materialized before "
                    "its first row. A statement MySQL takes in neither form is refused, and so is, on MariaDB, "
                    "one whose ORDER BY the derived table would drop.",
                ),
            ],
            required_privileges=[
                "SELECT on permitted tables (read-only account)",
                "SHOW VIEW / metadata visibility on permitted schemas",
            ],
            unverified_items=["TLS with internal CA", "streaming cursor truncation behavior"],
        )

    def health_check(self) -> HealthInfo:
        start = time.monotonic()
        try:
            conn = self._connect()
            try:
                with conn.cursor() as cur:
                    cur.execute("SELECT VERSION()")
                    row = cur.fetchone()
                session = self.session_report(self._session_readback(conn))
            finally:
                conn.close()
            ver = row[0] if row else None
            return HealthInfo(
                healthy=True,
                server_version=str(ver),
                latency_ms=int((time.monotonic() - start) * 1000),
                session=session,
            )
        except Exception as exc:  # noqa: BLE001, S110
            return HealthInfo(healthy=False, detail=scrub_exception(exc)[:300])

    def list_schemas(self, catalog: str | None, search: str | None) -> list[str]:
        sql = "SELECT schema_name FROM information_schema.schemata"
        params: list[Any] = []
        if search:
            sql += " WHERE schema_name LIKE %s"
            params.append(f"%{search}%")
        sql += " ORDER BY 1"
        with translated_driver_errors():
            with self._shared_meta_conn() as conn, conn.cursor() as cur:
                cur.execute(sql, params or None)
                return [r[0] for r in cur.fetchall()]

    def list_tables(self, schema: str | None, kinds: set[str], search: str | None) -> list[TableSummary]:
        types: list[str] = []
        if "table" in kinds:
            types.append("BASE TABLE")
        if "view" in kinds:
            types += ["VIEW", "SYSTEM VIEW"]  # information_schema's own tables are SYSTEM VIEWs
        if not types:
            return []
        sql = (
            "SELECT table_schema, table_name, table_type, table_rows "
            "FROM information_schema.tables WHERE table_type IN (" + ", ".join(["%s"] * len(types)) + ")"
        )
        params: list[Any] = list(types)
        # System schemas are not data unless the administrator allowed them
        # (security.allowed_system_schemas lists information_schema by
        # default): the resolver permits only what is listed here.
        opened = self._opened_schemas()
        if hidden := [s for s in _MYSQL_SYSTEM_SCHEMAS if s not in opened]:
            sql += " AND table_schema NOT IN (" + ", ".join(["%s"] * len(hidden)) + ")"
            params.extend(hidden)
        if schema:
            sql += " AND table_schema = %s"
            params.append(schema)
        if search:
            sql += " AND table_name LIKE %s"
            params.append(f"%{search}%")
        sql += " ORDER BY 1, 2"
        with translated_driver_errors():
            with self._shared_meta_conn() as conn, conn.cursor() as cur:
                cur.execute(sql, params or None)
                rows = cur.fetchall()
        tables = [
            TableSummary(
                schema=r[0],
                name=r[1],
                kind="view" if r[2] in ("VIEW", "SYSTEM VIEW") else "table",
                row_estimate=int(r[3]) if r[3] is not None else None,
                row_estimate_source="catalog_estimate(information_schema.tables.table_rows)"
                if r[3] is not None
                else None,
            )
            for r in rows
            if (str(r[0]).lower(), str(r[1]).lower()) not in _MYSQL_NEVER_LISTED
            and not is_session_sql_view(self.engine, str(r[0]), str(r[1]))
        ]
        return own_objects_first(tables, _MYSQL_SYSTEM_SCHEMAS)

    def list_columns(self, schema: str | None, table: str) -> list[ColumnInfo]:
        schema = schema or self.connection.config.database or ""
        sql = (
            "SELECT column_name, column_type, is_nullable, column_default, ordinal_position "
            "FROM information_schema.columns WHERE table_schema = %s AND table_name = %s "
            "ORDER BY ordinal_position"
        )
        with translated_driver_errors():
            with self._shared_meta_conn() as conn, conn.cursor() as cur:
                cur.execute(sql, (schema, table))
                rows = cur.fetchall()
        return [
            ColumnInfo(
                schema=schema,
                table=table,
                name=r[0],
                data_type=r[1],
                nullable=r[2] == "YES",
                default=r[3],
                ordinal=r[4],
            )
            for r in rows
        ]

    def placeholder(self, index: int) -> str:
        return "%s"

    def length_expression(self, quoted_column: str) -> str:
        return f"CHAR_LENGTH({quoted_column})"  # LENGTH() is bytes on MySQL

    def list_all_columns(self, schema: str | None) -> list[ColumnInfo]:
        schema = schema or self.connection.config.database or ""
        sql = (
            "SELECT table_name, column_name, column_type, is_nullable, column_default, ordinal_position "
            "FROM information_schema.columns WHERE table_schema = %s ORDER BY table_name, ordinal_position"
        )
        with translated_driver_errors():
            with self._shared_meta_conn() as conn, conn.cursor() as cur:
                cur.execute(sql, (schema,))
                rows = cur.fetchall()
        return [
            ColumnInfo(schema=schema, table=r[0], name=r[1], data_type=r[2], nullable=r[3] == "YES",
                       default=r[4], ordinal=r[5])
            for r in rows
        ]

    def list_indexes(self, schema: str | None, table: str | None) -> list[IndexInfo]:
        schema = schema or self.connection.config.database or ""
        sql = (
            "SELECT table_name, index_name, non_unique, column_name, seq_in_index, index_type "
            "FROM information_schema.statistics WHERE table_schema = %s"
        )
        params: list[Any] = [schema]
        if table:
            sql += " AND table_name = %s"
            params.append(table)
        sql += " ORDER BY table_name, index_name, seq_in_index"
        with translated_driver_errors():
            with self._shared_meta_conn() as conn, conn.cursor() as cur:
                cur.execute(sql, params)
                rows = cur.fetchall()
        grouped: dict[tuple[str, str], IndexInfo] = {}
        for tname, iname, non_unique, col, _seq, itype in rows:
            info = grouped.get((tname, iname))
            if info is None:
                info = IndexInfo(name=iname, columns=[], unique=not bool(int(non_unique or 0)),
                                 primary=(str(iname).upper() == "PRIMARY"), kind=str(itype).lower(),
                                 schema=schema, table=tname)
                grouped[(tname, iname)] = info
            info.columns.append(str(col) if col is not None else "(expression)")
        return list(grouped.values())

    def list_views(self, schema: str | None) -> list[ViewInfo]:
        sql = (
            "SELECT table_schema, table_name, view_definition FROM information_schema.views "
            "WHERE table_schema NOT IN ('mysql','information_schema','performance_schema','sys')"
        )
        params: list[Any] = []
        if schema:
            sql += " AND table_schema = %s"
            params.append(schema)
        sql += " ORDER BY 1, 2"
        with translated_driver_errors():
            with self._shared_meta_conn() as conn, conn.cursor() as cur:
                cur.execute(sql, params or None)
                rows = cur.fetchall()
        return [
            ViewInfo(schema=r[0], name=r[1], kind="view", definition=r[2], definition_state="available") for r in rows
        ]

    def list_synonyms(self, schema: str | None) -> list[SynonymInfo]:
        return []  # MySQL/MariaDB has no synonyms.

    def list_routines(self, schema: str | None) -> list[RoutineInfo]:
        sql = (
            "SELECT routine_schema, routine_name, routine_type FROM information_schema.routines "
            "WHERE routine_schema NOT IN ('mysql','information_schema','performance_schema','sys')"
        )
        params: list[Any] = []
        if schema:
            sql += " AND routine_schema = %s"
            params.append(schema)
        with translated_driver_errors():
            with self._shared_meta_conn() as conn, conn.cursor() as cur:
                cur.execute(sql, params or None)
                rows = cur.fetchall()
        return [RoutineInfo(schema=r[0], name=r[1], kind=r[2].lower()) for r in rows]

    def get_foreign_keys(self, schema: str | None, table: str | None) -> list[KeyInfo]:
        sql = (
            "SELECT constraint_name, table_schema, table_name, referenced_table_name, "
            "column_name, referenced_column_name, referenced_table_schema "
            "FROM information_schema.key_column_usage "
            "WHERE referenced_table_name IS NOT NULL"
        )
        params: list[Any] = []
        if schema:
            sql += " AND table_schema = %s"
            params.append(schema)
        if table:
            sql += " AND table_name = %s"
            params.append(table)
        with translated_driver_errors():
            with self._shared_meta_conn() as conn, conn.cursor() as cur:
                cur.execute(sql, params or None)
                rows = cur.fetchall()
        merged: dict[str, KeyInfo] = {}
        for name, tschema, tname, rname, col, rcol, rschema in rows:
            k = merged.get(name)
            if k:
                k.columns.append(col)
                k.ref_columns.append(rcol)
            else:
                merged[name] = KeyInfo(
                    kind="foreign_key",
                    name=name,
                    columns=[col],
                    ref_schema=rschema or tschema,
                    ref_table=rname,
                    ref_columns=[rcol],
                    source_schema=tschema,
                    source_table=tname,
                )
        return list(merged.values())

    def get_statistics(self, schema: str | None, table: str) -> dict[str, Any]:
        schema = schema or self.connection.config.database or ""
        sql = (
            "SELECT table_rows, data_length, index_length, update_time "
            "FROM information_schema.tables WHERE table_schema = %s AND table_name = %s"
        )
        with translated_driver_errors():
            with self._shared_meta_conn() as conn, conn.cursor() as cur:
                cur.execute(sql, (schema, table))
                row = cur.fetchone()
        if not row:
            return {"schema": schema, "table": table, "row_estimate": None, "row_estimate_source": "unavailable"}
        return {
            "schema": schema,
            "table": table,
            "row_estimate": int(row[0]) if row[0] is not None else None,
            "row_estimate_source": "catalog_estimate(information_schema; InnoDB estimates vary)",
            "data_bytes": int(row[1]) if row[1] else None,
            "index_bytes": int(row[2]) if row[2] else None,
            "last_update": str(row[3]) if row[3] else None,
        }

    def execute_query(self, spec: QuerySpec) -> QueryOutcome:
        with self._exec_lock:
            return self._execute(spec)

    def _execute(self, spec: QuerySpec) -> QueryOutcome:
        # The guard accepts qmark/named placeholders as opaque markers;
        # PyMySQL only understands format/pyformat (%s, %(name)s), so rewrite
        # them onto the driver's spelling after validation. Raised outside
        # translated_driver_errors() so a parameter-style mismatch keeps its
        # VALIDATION category instead of becoming a CONNECTION error.
        sql, parameters = translate_paramstyle(spec.sql, spec.parameters, backslash_escapes=True)
        # PyMySQL runs ``query % args`` whenever args is not None — an empty
        # tuple included — so an unparameterised statement with a literal '%'
        # (LIKE 'a%') would fail client-side. Pass None when nothing is bound
        # so the SQL is sent verbatim.
        args = parameters or None
        with translated_driver_errors():
            conn = self._connect()
        try:
            thread_id: int | None = int(conn.thread_id())
        except Exception:  # noqa: BLE001 - no id, nothing to KILL: cancel reports False
            thread_id = None
        with self._kill_lock:
            self._running_thread = thread_id
        start = time.monotonic()
        truncated = False
        truncation_cause = "row limit"
        cell_truncated_cols: list[str] = []
        rows: list[list[Any]] = []
        approx_bytes = 0
        conn_closed = False
        cur: Any = None
        import json

        try:
            with translated_driver_errors(phase="execute"):
                plan = self._value_capped(conn, sql, args, spec)
                # Not a context manager: on truncation Cursor.close() MUST NOT
                # run against a live connection (see below), and the explicit
                # close is easier to make idempotent.
                cur = conn.cursor()
                if plan is None:
                    cur.execute(sql, args)
                else:
                    self._execute_capped(cur, plan, args)
                cols = [(d[0], "unknown") for d in cur.description or []]
                col_labels = plan.labels if plan is not None else [
                    _MYSQL_TYPE_LABELS.get(d[1], "unknown") for d in (cur.description or [])
                ]
                # SSCursor reads rows one by one anyway: while a column that
                # can hold megabytes arrives (a statement that could not be
                # described), hold one row at a time (and let it go before
                # the next is read).
                one_by_one = any(d[1] in _MYSQL_LOB_TYPES for d in (cur.description or []))
                while True:
                    batch = cur.fetchmany(1 if one_by_one else next_fetch_size(spec.max_rows, len(rows)))
                    if not batch:
                        break
                    for raw in batch:
                        vals, _labels, cut = adapt_row(raw, spec.max_cell_bytes)
                        cell_truncated_cols.extend(column_names_at(cols, cut))
                        approx_bytes += len(json.dumps(vals, default=str).encode("utf-8"))
                        if len(rows) >= spec.max_rows or approx_bytes > spec.max_response_bytes:
                            truncated = True
                            truncation_cause = "row limit" if len(rows) >= spec.max_rows else "byte limit"
                            break
                        rows.append(vals)
                    del batch, raw
                    if truncated:
                        # Sever the cursor from the connection BEFORE closing:
                        # SSCursor.close() would otherwise drain the entire
                        # remaining streaming result (there is no way to stop
                        # the server sending it once the cursor stays bound),
                        # turning a bounded fetch into a full transfer. Closing
                        # the connection sends COM_QUIT without draining.
                        cur.connection = None
                        # The unread result must not try to drain the closed
                        # socket when it is collected (PyMySQL's __del__).
                        result = getattr(cur, "_result", None)
                        if result is not None:
                            result.unbuffered_active = False
                        conn.close()
                        conn_closed = True
                        break
            warnings: list[str] = []
            if truncated:
                warnings.append(f"result truncated by {truncation_cause}")
            if cell_truncated_cols:
                # A cell cut to the byte limit must never be reported as
                # an intact result: name the columns (live test
                # 2026-09-11 found this path reporting truncated=false
                # after a silent cut).
                warnings.append(cell_truncation_warning(cell_truncated_cols, spec.max_cell_bytes))
            return QueryOutcome(
                columns=[(c[0], t) for c, t in zip(cols, col_labels or ["unknown"] * len(cols), strict=True)],
                rows=rows,
                truncated=truncated or bool(cell_truncated_cols),
                rows_seen=len(rows),
                elapsed_ms=int((time.monotonic() - start) * 1000),
                warnings=warnings,
            )
        finally:
            with self._kill_lock:
                self._running_thread = None
            if cur is not None:
                try:
                    cur.close()  # no-op on the truncation path: cursor severed above
                except Exception:  # noqa: BLE001, S110
                    pass
            if not conn_closed:
                try:
                    conn.close()
                except Exception:  # noqa: BLE001, S110
                    pass

    def _value_capped(self, conn: Any, sql: str, args: Any, spec: QuerySpec) -> _CapPlan | None:
        """How the statement runs with every value that could exceed the
        cell limit cut by the server; None to run it as written (nothing
        needs cutting, it is a catalog statement such as SHOW, or it could
        not be described).

        A plain SELECT is described under a top-level LIMIT 0, which MySQL
        plans without running (``_mysql_select``), and has its select list
        rewritten. Every other statement is described through the
        prepared-statement protocol, which runs nothing, and becomes a
        derived table; so does a plain SELECT whose select list cannot be
        cut exactly. MariaDB drops the ORDER BY of a derived table that has
        no LIMIT, so there a statement that orders its rows is refused
        rather than returned in another order.
        """
        tree = _mysql_parse(sql)
        if tree is not None and not isinstance(tree, exp.Query):
            return None  # SHOW, DESCRIBE: the server's own catalog text
        select = _mysql_select(sql, tree) if tree is not None else None
        probe_sql = _mysql_describe_probe(select) if select is not None else None
        description = self._limit0_description(conn, probe_sql, args) if probe_sql is not None else None
        if description is None:
            description = self._prepared_description(conn, sql, args)
        if description is None:
            return None
        cut = _mysql_cut_columns(description, spec.max_cell_bytes)
        if not cut:
            return None
        bound = args is not None
        columns = [str(description[i][0]) for i in sorted(cut)]
        rewrites: list[str] = []
        if select is not None and (
            in_place := _mysql_capped_select(select, description, cut, spec.max_cell_bytes, bound=bound)
        ):
            rewrites.append(in_place)
        if "mariadb" not in str(getattr(conn, "server_version", "")).lower() or not _mysql_orders_rows(tree):
            rewrites.extend(_mysql_derived_selects(sql, description, cut, spec.max_cell_bytes, bound=bound))
        elif not rewrites:
            raise _uncut_refusal(
                columns, "MariaDB does not keep the ORDER BY of the derived table that would cut them"
            )
        return _CapPlan(rewrites, [_MYSQL_TYPE_LABELS.get(d[1], "unknown") for d in description], columns)

    def _limit0_description(self, conn: Any, probe_sql: str, args: Any) -> list[Any] | None:
        """The columns of the statement under its top-level LIMIT 0. A
        describe MySQL refuses (its syntax) is None; any other failure (the
        statement's own error, a KILL) is the statement's."""
        probe = conn.cursor()
        try:
            probe.execute(probe_sql, args)
            return list(probe.description or [])
        except getattr(self._module, "MySQLError", ()) as exc:
            if exc.args and exc.args[0] in _REWRITE_REFUSED:
                return None
            raise
        finally:
            close = getattr(probe, "close", None)
            if callable(close):
                close()  # reads the (empty) result to its end: the connection is free again

    def _prepared_description(self, conn: Any, sql: str, args: Any) -> list[Any] | None:
        """The statement's result columns as MySQL's prepared-statement
        protocol describes them: COM_STMT_PREPARE resolves the statement and
        runs nothing (a SLEEP(), a subquery or a CTE included), and the
        prepared statement is closed again at once. The bound values are
        inlined first, as PyMySQL would send them. PyMySQL has no public
        call for this. None for a statement the protocol does not take, and
        for a connection that is not PyMySQL's."""
        pymysql = self._module
        connection_type = getattr(getattr(pymysql, "connections", None), "Connection", None)
        if connection_type is None or not isinstance(conn, connection_type):
            return None
        text = conn.cursor().mogrify(sql, args)
        conn._execute_command(pymysql.constants.COMMAND.COM_STMT_PREPARE, text)
        try:
            head = conn._read_packet()  # an error packet raises here
        except pymysql.MySQLError as exc:
            if exc.args and exc.args[0] == _PREPARE_UNSUPPORTED:
                return None
            raise
        head.read_uint8()  # OK
        statement_id = head.read_uint32()
        columns = head.read_uint16()
        params = head.read_uint16()
        for _ in range(params + (1 if params else 0)):  # parameter definitions, then EOF
            conn._read_packet()
        described = [conn._read_packet(pymysql.protocol.FieldDescriptorPacket).description() for _ in range(columns)]
        if columns:
            conn._read_packet()  # EOF
        conn._execute_command(pymysql.constants.COMMAND.COM_STMT_CLOSE, struct.pack("<I", statement_id))  # no reply
        return described

    def _execute_capped(self, cur: Any, plan: _CapPlan, args: Any) -> None:
        """Run the first rewrite MySQL takes. Fails closed: when it refuses
        them all, the statement never runs with its values uncut."""
        for i, text in enumerate(plan.rewrites):
            try:
                cur.execute(text, args)
                return
            except getattr(self._module, "MySQLError", ()) as exc:
                if not (exc.args and exc.args[0] in _REWRITE_REFUSED):
                    raise
                if i == len(plan.rewrites) - 1:
                    raise _uncut_refusal(plan.columns, f"MySQL refused it: {scrub_exception(exc)}") from exc

    def explain(self, sql: str, analyze: bool) -> dict[str, Any]:
        if analyze:
            raise NotImplementedError(EXPLAIN_ANALYZE_UNSUPPORTED)
        with translated_driver_errors():
            conn = self._connect()
            try:
                with conn.cursor() as cur:
                    cur.execute("EXPLAIN " + sql)  # noqa: S608 - validated upstream
                    return {"raw": [[str(c) for c in row] for row in cur.fetchall()]}
            finally:
                conn.close()
