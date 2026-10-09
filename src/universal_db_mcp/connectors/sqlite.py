"""SQLite connector — the always-available local reference implementation.

Safety posture:
- Data files are opened with URI ``mode=ro`` (read-only) and extension
  loading is explicitly disabled.
- ATTACH is impossible (read-only handle) and additionally denied by the
  SQL guard.
- A sqlite3 authorizer is installed on every handle as a runtime backstop:
  only SELECT-style reads on schema objects are authorized, everything else
  (writes, pragmas other than a small introspection allowlist, transactions,
  functions marked SQLITE_FUNCTION) is denied at the engine API level.
- Each query gets a fresh handle, so cancellation is a hard ``interrupt()``
  and there is no cross-query state to leak.
"""

from __future__ import annotations

import math
import re
import sqlite3
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
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
    ObjectNotFound,
    QueryOutcome,
    QuerySpec,
    RoutineInfo,
    SynonymInfo,
    TableSummary,
    ViewInfo,
)
from universal_db_mcp.connectors.driver_helpers import (
    SelectList,
    capped_text,
    statement_body,
    translated_driver_errors,
)
from universal_db_mcp.models.capabilities import Cap, CapabilityMatrix, CapabilityState, Limitation
from universal_db_mcp.models.responses import ErrorCategory
from universal_db_mcp.security.policy import EffectivePolicy

_SYSTEM_SCHEMAS = {"temp", "temp_main"}


def _is_catalog_table(name: str) -> bool:
    """sqlite_schema, sqlite_sequence, sqlite_stat1...: the engine's own
    catalog. SQLite reserves the prefix, so no user table carries it."""
    return name.lower().startswith("sqlite_")


# PRAGMAs the authorizer may permit (read-only introspection). Everything
# else, including PRAGMA settings, is denied at the engine level.
_ALLOWED_PRAGMAS = {
    "table_list",
    "table_info",
    "table_xinfo",
    "index_list",
    "index_info",
    "index_xinfo",
    "foreign_key_list",
    "database_list",
    "schema_version",
    "user_version",
    "application_id",
    "page_count",
    "page_size",
    "encoding",
    "integrity_check",
    "quick_check",
    "compile_options",
    "function_list",
    "module_list",
    "collation_list",
    "journal_mode",  # read returns mode
    "data_version",  # read-only; FTS5 reads it on every query
}

# The internal (shadow) tables of a virtual table are named after it: its
# own name, "_", then a suffix its module's xShadowName accepts. They hold
# the indexed values under generic column names (c0, c1ssn), past any
# masking by name. SQLite marks them itself (PRAGMA table_list type
# 'shadow') when the build has the module; these suffixes stand in for a
# module the build lacks.
_FTS3_SHADOWS = frozenset({"content", "segments", "segdir", "docsize", "stat"})
_RTREE_SHADOWS = frozenset({"node", "rowid", "parent"})
_MODULE_SHADOWS: dict[str, frozenset[str]] = {
    "fts3": _FTS3_SHADOWS,
    "fts4": _FTS3_SHADOWS,
    "fts5": frozenset({"content", "data", "idx", "docsize", "config"}),
    "rtree": _RTREE_SHADOWS,
    "rtree_i32": _RTREE_SHADOWS,
    "geopoly": _RTREE_SHADOWS,
}
# SQLite stores a virtual table's definition as "CREATE VIRTUAL TABLE "
# followed by the statement as written from the table's name on (no IF NOT
# EXISTS, no schema), comments included; they are blanked first
# (_without_comments). A quoted name or module needs no space next to USING
# ('"posts"USING', 'USING"fts5"'). Each name alternative is an unrolled loop,
# linear on any input; the match reads at most the first _MODULE_SCAN
# characters.
_NAME = r"""(?:"[^"]*(?:""[^"]*)*"|\[[^\]]*\]|`[^`]*(?:``[^`]*)*`|'[^']*(?:''[^']*)*'|[^\s."'`\[(]+)"""
_AFTER_NAME = r"""(?:\s+|(?<=["\]`'])\s*)"""
_BEFORE_NAME = r"""(?:\s+|\s*(?=["\[`']))"""
_VTAB_MODULE = re.compile(
    rf"CREATE\s+VIRTUAL\s+TABLE\s+(?:{_NAME}\s*\.\s*)?{_NAME}{_AFTER_NAME}USING{_BEFORE_NAME}({_NAME})",
    re.IGNORECASE,
)
_MODULE_SCAN = 4096


_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


def _fold(name: str) -> str:
    """A name as SQLite compares names: ASCII letters folded, nothing else."""
    return name.translate(_ASCII_LOWER)


def _without_comments(text: str) -> str:
    """``text`` with each SQL comment ('--' to the end of its line, '/* */')
    replaced by one space, outside quoted names and strings. One pass:
    linear on any input."""
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch in "\"'`[":
            close = "]" if ch == "[" else ch
            end = text.find(close, i + 1)
            # a doubled quote inside a quoted name or string is two quoted runs
            end = n if end < 0 else end + 1
            out.append(text[i:end])
            i = end
        elif text.startswith("--", i):
            end = text.find("\n", i)
            out.append(" ")
            i = n if end < 0 else end
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            out.append(" ")
            i = n if end < 0 else end + 2
        else:
            j = i
            while j < n and text[j] not in "\"'`[-/":
                j += 1
            if j == i:
                j += 1
            out.append(text[i:j])
            i = j
    return "".join(out)


def _module_of(sql: str | None) -> str | None:
    """The module of a virtual table's stored definition, lowercased; ''
    for one this cannot read; None for a definition that is not a virtual
    table's."""
    if not sql or not sql[:21].upper().startswith("CREATE VIRTUAL TABLE"):
        return None
    found = _VTAB_MODULE.match(_without_comments(sql[:_MODULE_SCAN]))
    if found is None:
        return ""
    module = found.group(1)
    if module[0] in "\"[`'":
        module = module[1:-1]
    return _fold(module)


def _unmarked_shadow(name: str, owner_module: str | None, registered: frozenset[str]) -> bool:
    """Whether a table SQLite reports as a plain one is the internal table of
    a virtual table whose module this build lacks: SQLite marks only the
    shadow tables of a module it has. ``owner_module`` is the module of the
    virtual table the name points at (the part before its last "_"), None
    when there is no such virtual table. A module this cannot read or does
    not know keeps every such table back (fail closed)."""
    if owner_module is None or owner_module in registered:
        return False
    known = _MODULE_SHADOWS.get(owner_module)
    return known is None or _fold(name).rpartition("_")[2] in known


def _parsed(sql: str) -> list[exp.Expr | None] | None:
    """The statement's parse; None when sqlglot cannot read it."""
    try:
        return list(sqlglot.parse(sql, read="sqlite"))
    except Exception:  # noqa: BLE001 - sqlglot's ParseError/TokenError, and whatever else a parser raises
        return None


def _name_text(node: exp.Expression) -> str | None:
    """The name a part of ``x IN <schema>.<table>`` spells: an identifier,
    or a string, which SQLite reads as a name there."""
    if isinstance(node, exp.Identifier) or (isinstance(node, exp.Literal) and node.is_string):
        return str(node.this)
    return None


def _in_table(field: exp.Expression) -> tuple[str | None, str] | None:
    """The (schema, name) of the table ``x IN <field>`` reads: 't', "t",
    [t], t, main.'t', 'main'.'t'; None for anything else (a table-valued
    function's call)."""
    if isinstance(field, exp.Literal) and field.is_string:
        return None, str(field.this)
    if isinstance(field, exp.Column) and (name := _name_text(field.this)) is not None:
        schema = field.args.get("table")
        return (_name_text(schema) if schema is not None else None), name
    if isinstance(field, exp.Table) and field.name:
        return field.db or None, field.name
    if isinstance(field, exp.Dot):
        schema, name = _name_text(field.this), _name_text(field.expression)
        if schema is not None and name is not None:
            return schema, name
    return None


def _table_references(trees: list[exp.Expr | None]) -> set[tuple[str | None, str]] | None:
    """The (schema, name) of every table the statement (``trees``, its
    parse) reads, as SQLite reads a name: a FROM or JOIN item (a quoted
    string included: FROM 't'), a subquery's, and the table of ``x IN
    table`` (a string too: x IN 't'). An alias, a column or a literal is no
    table. None when the right side of an IN is neither a list, a subquery,
    a table nor a table-valued function."""
    out: set[tuple[str | None, str]] = set()
    for tree in trees:
        if tree is None:
            continue
        for table in tree.find_all(exp.Table):
            if table.name:
                out.add((table.db or None, table.name))
        for test in tree.find_all(exp.In):
            field = test.args.get("field")
            if field is None or isinstance(field, (exp.Anonymous, exp.Func)):
                continue
            found = _in_table(field)
            if found is None:
                return None
            out.add(found)
    return out


_MIN_VALUE_LENGTH_LIMIT = 16 * 1024 * 1024
# SQLite never sets SQLITE_LIMIT_LENGTH above its compile-time
# SQLITE_MAX_LENGTH, 1,000,000,000 bytes in its default build (953 MiB,
# reached at a max_response_bytes of about 59.6 MiB).
_SQLITE_MAX_LENGTH = 1_000_000_000
# SQLite's own heap, in values of the largest length a handle accepts (512
# MiB by default). The limit is process-wide and the server's metadata cache
# is SQLite too: writing and reading back its largest entry (64 MiB of JSON)
# takes about 160 MiB of it, and a 64 MiB limit failed every other
# connection's large catalog listing (review round 5). Output values are cut
# inside SQLite (_sql_cut, so a row or a sort holds cut values; live, review
# round 4: 16 columns of one 8 MiB value grew the server by 327 MB, ORDER BY
# over 30 rows of 4 MiB by 194 MB), so this only bounds what that cannot
# reach: a sort, group or DISTINCT over long values, a wide row inside a
# subquery.
_HEAP_LIMIT_VALUES = 32
_heap_limit_enforced: bool | None = None  # this SQLite library counts its heap (decided once)
# How often a cancelled connector interrupts its open handles again until
# they close: Connection.interrupt() reaches only a statement already
# running, and SQLite forgets it when a statement starts on an idle handle.
# A progress handler would look at the cancel flag instead, but it calls
# into Python, and takes the GIL, every few thousand steps of every
# statement: next to any busy Python thread a statement ran 25-250x slower.
_REINTERRUPT_SECONDS = 0.02
# Up to this many virtual tables, a statement whose text contains none of
# their names followed by "_" is not parsed for the tables it reads.
_VTAB_PREFILTER = 256


def _value_length_limit(max_response_bytes: int) -> int:
    """SQLITE_LIMIT_LENGTH for this connection's handles: well above anything
    a response can carry, never under 16 MiB, never above SQLite's own
    ceiling."""
    return min(max(max_response_bytes * 16, _MIN_VALUE_LENGTH_LIMIT), _SQLITE_MAX_LENGTH)


def _heap_limit(max_response_bytes: int) -> int:
    """PRAGMA hard_heap_limit for this connection's handles (512 MiB by
    default). SQLite has one heap limit per process, and the pragma only
    ever lowers it: the smallest any SQLite connection asks for applies to
    every SQLite handle in the server, the metadata cache's included."""
    return _HEAP_LIMIT_VALUES * _value_length_limit(max_response_bytes)


def _heap_limit_takes(conn: sqlite3.Connection) -> bool:
    """False for a SQLite library built without memory statistics
    (SQLITE_DEFAULT_MEMSTATUS=0), which ignores its heap limit, or one older
    than the pragma (3.31)."""
    global _heap_limit_enforced
    if _heap_limit_enforced is None:
        options = {row[0] for row in conn.execute("PRAGMA compile_options").fetchall()}
        _heap_limit_enforced = "DEFAULT_MEMSTATUS=0" not in options and sqlite3.sqlite_version_info >= (3, 31)
    return _heap_limit_enforced


def _sql_cut(expression: str, keep: int) -> str:
    """``expression`` cut in SQL to ``keep`` characters (text) or bytes (a
    blob); any other value as it is (an integer stays an integer). A Python
    function here took the GIL once per input row of a sort (13-20x slower
    next to a busy thread, review round 3); this runs in C. substr()'s
    bounds are not constants ('random() & 0' is always 0): SQLite gives a
    function call with a constant argument registers of its own that it never
    reuses, so each output column kept its whole value until the statement
    ended (64 columns of an 8 MiB value: 586 MB, against 80 MB this way)."""
    zero = "(random() & 0)"
    cut = f"substr({expression}, {zero} + 1, {zero} + {keep})"
    return f"CASE typeof({expression}) WHEN 'text' THEN {cut} WHEN 'blob' THEN {cut} ELSE {expression} END"


def _spellings(name: str) -> set[str]:
    """``name`` (folded) as a statement may spell it inside quotes: as is,
    and with the quote character of a quoted name or string doubled (a
    virtual table named customer's notes is read from 'customer''s notes')."""
    return {name} | {name.replace(q, q + q) for q in "\"'`" if q in name}


def _describe_probe(select: SelectList) -> str | None:
    """The statement under a top-level ``LIMIT 0``, which SQLite answers
    with the statement's column names before it computes anything (a
    materialized CTE or a sort included): its own LIMIT replaced, or one
    appended. None for a LIMIT with a parameter, which would lose its
    marker."""
    if select.tree.args.get("limit") is None:
        return select.sql + "\nLIMIT 0"
    outer = select.outer_tokens()
    at = max((i for i, t in enumerate(outer) if t.token_type == TokenType.LIMIT), default=None)
    if at is None or any(
        t.token_type not in (TokenType.NUMBER, TokenType.COMMA, TokenType.OFFSET, TokenType.DASH)
        for t in outer[at + 1:]
    ):
        return None
    return select.sql[: outer[at].start] + "LIMIT 0"


def _compared_outputs(tree: exp.Select, names: list[str]) -> set[int]:
    """Output columns the statement compares: named in a join condition,
    WHERE, GROUP BY, HAVING or ORDER BY (subqueries included), where SQLite
    resolves a result alias (ORDER BY before a column of the same name), or
    named by position in GROUP BY or ORDER BY. Cut in the select list, such
    a column would be compared by its first characters.

    SQLite reads a GROUP BY or ORDER BY term as a position under any
    spelling of an integer literal (_position). Any other term that names
    no column (random(), NULL, a bound parameter, '2', 2.0) compares no
    output: SQLite sorts or groups by its value."""
    named: set[str] = set()
    for key in ("joins", "where", "group", "having", "order"):
        value = tree.args.get(key)
        for node in value if isinstance(value, list) else [value]:
            if isinstance(node, exp.Expression):
                named.update(c.name.lower() for c in node.find_all(exp.Column) if not c.table)
    out = {i for i, name in enumerate(names) if name.lower() in named}
    for key in ("group", "order"):
        clause = tree.args.get(key)
        for item in clause.expressions if clause is not None else []:
            position = _position(item.this if isinstance(item, exp.Ordered) else item)
            if position is not None and 1 <= position <= len(names):
                out.add(position - 1)
    return out


def _position(term: exp.Expression) -> int | None:
    """The output a GROUP BY or ORDER BY term names by position (1-based),
    as SQLite reads one (sqlite3ExprIsInteger): an integer literal, decimal
    or hex, under any parentheses, COLLATE, unary plus (which the parse
    drops) and unary minus: 2, (2), +2, 0x2, -(-2), 2 COLLATE x. None for
    any other term; a bound parameter, '2', 2.0 or CAST(2 AS INT) is a value
    (SQLite 3.50, live)."""
    sign = 1
    while isinstance(term, (exp.Paren, exp.Collate, exp.Neg)):
        if isinstance(term, exp.Neg):
            sign = -sign
        term = term.this
    if isinstance(term, exp.HexString):
        try:
            return sign * int(term.this, 16)
        except ValueError:
            return None
    if isinstance(term, exp.Literal) and not term.is_string and term.this.isascii() and term.this.isdigit():
        return sign * int(term.this)
    return None


def _adapt(value: Any, max_cell_bytes: int) -> tuple[Any, str, bool]:
    """Return (json-safe value, type label, cell_truncated)."""
    if value is None or isinstance(value, (bool,)):
        return value, ("boolean" if isinstance(value, bool) else "null"), False
    if isinstance(value, int):
        if abs(value) < 2**53:
            return value, "integer", False
        return str(value), "bigint", False  # exact, out of JSON-safe range
    if isinstance(value, float):
        if not math.isfinite(value):
            # inf/NaN are invalid JSON (RFC 8259); emit an exact sentinel
            # string instead, mirroring the bigint-as-string strategy.
            return ("$nan" if math.isnan(value) else ("$inf" if value > 0 else "-$inf")), "real", False
        return value, "real", False
    if isinstance(value, str):
        text, cut = capped_text(value, max_cell_bytes)  # never encodes the whole value
        return text, "text", cut
    if isinstance(value, (bytes, memoryview)):
        size = len(value) if isinstance(value, bytes) else value.nbytes
        raw = bytes(value[:max_cell_bytes])
        import base64

        if size > max_cell_bytes:
            return {"$binary_b64": base64.b64encode(raw).decode(), "$truncated": True}, "blob", True
        return {"$binary_b64": base64.b64encode(raw).decode()}, "blob", False
    return str(value), "text", False


class SQLiteConnector(DatabaseConnector):
    engine = "sqlite"

    def __init__(self, connection: ResolvedConnection, policy: EffectivePolicy) -> None:
        super().__init__(connection, policy)
        path = connection.config.database
        if not path:
            raise ValueError("sqlite connection requires 'database' path")
        # Resolve relative paths against the service working directory NOW:
        # config validation stores the value unresolved, and Path.as_uri()
        # raises ValueError for relative paths, which would crash every later
        # operation as INTERNAL instead of failing fast with a clear message.
        try:
            expanded = Path(path).expanduser()
        except RuntimeError:
            # pathlib's answer for a ~user that names no account here, or a
            # bare ~ without a home directory (an INTERNAL_ERROR otherwise).
            head = str(path).replace("\\", "/").split("/", 1)[0]
            raise ConnectorError(
                f"the SQLite database path of connection '{connection.name}' starts with '{head}', which names "
                "no account on this machine (or one without a home directory); give the full path instead",
                category=ErrorCategory.CONNECTION,
            ) from None
        self._path = expanded.resolve()
        self._conn_lock = threading.Lock()
        # Every open handle, for cancel_current to interrupt; at most one per
        # call in flight. Changed only under _handles_lock, which a handle's
        # opening and closing take with the cancel.
        self._handles: set[sqlite3.Connection] = set()
        self._handles_lock = threading.Lock()
        self._reinterrupting = False
        # Set by cancel_current, never cleared: the executor discards a
        # connector it cut off, and every handle and statement here looks.
        self._cancelled = threading.Event()
        # The main schema's virtual tables (lowercased name -> module) under
        # the file and schema version they were read at: one entry, replaced
        # when either changes.
        self._vtabs: tuple[tuple[int, int, int], dict[str, str]] | None = None
        self._modules: frozenset[str] | None = None  # the modules this SQLite library has
        self._dbstat_available: bool | None = None  # probed once per connector
        self._heap_cap: int | None = None  # SQLite's heap limit as the last handle read it back

    # ---- connection management -------------------------------------------

    @contextmanager
    def _heap_refusals(self, what: str, advice: str = "") -> Iterator[None]:
        """SQLITE_NOMEM at the heap limit reaches Python as a MemoryError:
        ``what`` needs more memory than the server lets SQLite use. Raised as
        this connector's own refusal (from None), so the caller reads the
        limit's size."""
        try:
            yield
        except MemoryError:
            cap = self._heap_cap
            size = f" ({cap >> 20} MiB, shared by every SQLite handle in the process)" if cap else ""
            raise ConnectorError(
                f"{what} needs more memory than this server lets SQLite use{size}{advice}",
                category=ErrorCategory.LIMIT,
            ) from None

    @contextmanager
    def _length_refusals(self, conn: sqlite3.Connection) -> Iterator[None]:
        """SQLITE_TOOBIG: the statement built or read a value longer than
        SQLITE_LIMIT_LENGTH, which SQLite reports only as 'string or blob too
        big'. Raised as this connector's own refusal (from None), so the
        caller reads the limit in force on ``conn`` and what raises it."""
        try:
            yield
        except sqlite3.Error as exc:
            if getattr(exc, "sqlite_errorcode", None) != sqlite3.SQLITE_TOOBIG:
                raise
            limit = conn.getlimit(sqlite3.SQLITE_LIMIT_LENGTH)
            if limit < max(self.policy.max_response_bytes * 16, _MIN_VALUE_LENGTH_LIMIT):
                basis, remedy = "SQLite's own ceiling, which no setting of this server raises", ""
            else:
                basis = "16 x security.max_response_bytes, at least 16 MiB"
                remedy = "; raising security.max_response_bytes raises the limit"
            raise ConnectorError(
                "string or blob too big: the statement builds or reads a value longer than this server lets "
                f"SQLite handle ({limit >> 20} MiB: {basis}). A stored value that long cannot be read at all, "
                f"not even through length() or substr(){remedy}",
                category=ErrorCategory.QUERY,
            ) from None

    @contextmanager
    def _handle(self, what: str = "reading the database's schema") -> Iterator[sqlite3.Connection]:
        """A fresh handle for one metadata call, closed when it returns."""
        with self._heap_refusals(what):
            conn = self._open()
            try:
                yield conn
            finally:
                self._close(conn)

    def _close(self, conn: sqlite3.Connection) -> None:
        """Close a handle _open returned, under the lock a cancel interrupts
        it under: never an interrupt on a handle being closed."""
        with self._handles_lock:
            self._handles.discard(conn)
            conn.close()

    def _open(self) -> sqlite3.Connection:
        """A fresh read-only handle. The caller closes it with _close: 'with
        conn' only ends a transaction, and a Connection sits in a reference
        cycle, so an unclosed one kept its parsed schema, under SQLite's
        process-wide heap cap, until the cyclic GC ran."""
        self._stop_if_cancelled()  # a connector the executor cut off opens nothing more
        if not self._path.is_file():
            raise FileNotFoundError(
                f"configured SQLite data file '{self._path}' does not exist or is not a "
                f"regular file (connection '{self.connection.name}')"
            )
        uri = f"file:{self._path.as_uri()[7:]}?mode=ro"
        conn = sqlite3.connect(
            uri,
            uri=True,
            timeout=self.connection.config.connect_timeout_seconds,
            isolation_level=None,  # autocommit; we never open transactions
        )
        try:
            conn.enable_load_extension(False)
            # The engine runs inside this process, so a statement that builds
            # a huge value (a string-doubling recursive CTE) would allocate it
            # in the server's own memory. Past this length SQLite stops with
            # SQLITE_TOOBIG instead; a stored value above it can no longer be
            # read either.
            conn.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, _value_length_limit(self.policy.max_response_bytes))
            # Read the header now: some builds (Ubuntu 24.04's 3.45) run
            # 'SELECT sqlite_version()' without it, so an encrypted or
            # non-SQLite file would pass for a healthy database.
            conn.execute("PRAGMA schema_version").fetchone()
            # Session safety profile: the read-only URI + query_only IS the
            # server-side read-only here; the lock ceiling is SQLite's busy
            # timeout. Both PRAGMAs run BEFORE the authorizer is installed,
            # because the authorizer denies PRAGMA to everything that follows.
            # No setting changes how SQLite splits a statement into tokens (a
            # double-quoted name that matches no column is read as a string
            # afterwards, the same token the guard read), so there is no
            # reading to hold here.
            self._session_reset()
            conn.execute("PRAGMA query_only = ON")
            qo = conn.execute("PRAGMA query_only").fetchone()
            self._last_query_only = str(qo[0]) if qo else "?"
            self._session_applied("read_only")
            # What the output cut cannot reach (a sort, group or DISTINCT
            # over long values) builds past SQLITE_LIMIT_LENGTH inside this
            # process: cap SQLite's heap, well above what the metadata
            # cache, SQLite too, needs of it.
            heap = _heap_limit(self.policy.max_response_bytes)
            if _heap_limit_takes(conn):
                conn.execute(f"PRAGMA hard_heap_limit = {heap}")
                self._heap_cap = int(conn.execute("PRAGMA hard_heap_limit").fetchone()[0])
                self._session_applied(f"hard_heap_limit={self._heap_cap >> 20}MiB (process-wide)")
            else:
                self._session_skipped(
                    "hard_heap_limit",
                    RuntimeError(f"SQLite {sqlite3.sqlite_version} was built without heap accounting"),
                )
            lock = self.session_profile.lock_timeout_seconds
            if lock is not None:
                conn.execute(f"PRAGMA busy_timeout = {int(lock * 1000)}")
                self._session_applied(f"busy_timeout={int(lock * 1000)}ms")
            conn.set_authorizer(self._authorizer)
            with self._handles_lock:
                # Under the cancel's lock: either the cancel finds this
                # handle and interrupts it, or this finds the cancel's flag.
                self._stop_if_cancelled()
                self._handles.add(conn)
        except BaseException:
            conn.close()
            raise
        return conn

    def _authorizer(
        self, action: int, arg1: str | None, arg2: str | None, db_name: str | None, trigger: str | None
    ) -> int:
        import sqlite3 as _sq

        if action == _sq.SQLITE_SELECT:
            return _sq.SQLITE_OK
        if action == _sq.SQLITE_READ:
            return _sq.SQLITE_OK
        if action == _sq.SQLITE_FUNCTION:
            # Built-in scalar/aggregate functions are fine; the SQL guard
            # denies unknown/dangerous ones by name before they reach here.
            return _sq.SQLITE_OK
        if action == _sq.SQLITE_RECURSIVE:
            # Fired when preparing statements with recursive CTEs; recursion
            # itself is a read, not a write.
            return _sq.SQLITE_OK
        if action == _sq.SQLITE_PRAGMA:
            name = (arg1 or "").lower()
            if name in _ALLOWED_PRAGMAS:
                return _sq.SQLITE_OK
            return _sq.SQLITE_DENY
        if action in (_sq.SQLITE_ANALYZE,):
            return _sq.SQLITE_DENY
        return _sq.SQLITE_DENY

    # ---- capabilities ------------------------------------------------------

    def capabilities(self) -> CapabilityMatrix:
        return CapabilityMatrix(
            engine="sqlite",
            engine_family="sqlite",
            driver=f"python sqlite3 (SQLite {sqlite3.sqlite_version})",
            capabilities={
                Cap.CONNECT: CapabilityState.SUPPORTED,
                Cap.HEALTH: CapabilityState.SUPPORTED,
                Cap.LIST_SCHEMAS: CapabilityState.SUPPORTED,
                Cap.LIST_TABLES: CapabilityState.SUPPORTED,
                Cap.GET_TABLE: CapabilityState.SUPPORTED,
                Cap.LIST_COLUMNS: CapabilityState.SUPPORTED,
                Cap.LIST_VIEWS: CapabilityState.SUPPORTED,
                Cap.LIST_SYNONYMS: CapabilityState.UNSUPPORTED,
                Cap.LIST_ROUTINES: CapabilityState.UNSUPPORTED,
                Cap.SEARCH_METADATA: CapabilityState.SUPPORTED,
                Cap.RELATIONSHIPS: CapabilityState.SUPPORTED,
                Cap.STATISTICS: CapabilityState.SUPPORTED,
                Cap.QUERY: CapabilityState.SUPPORTED,
                Cap.PARAMETERS: CapabilityState.SUPPORTED,
                Cap.CANCEL: CapabilityState.SUPPORTED,
                Cap.SERVER_SIDE_CANCEL: CapabilityState.SUPPORTED,
                Cap.EXPLAIN: CapabilityState.SUPPORTED,
                Cap.EXPLAIN_ANALYZE: CapabilityState.UNSUPPORTED,
                Cap.SAMPLE: CapabilityState.SUPPORTED,
                Cap.TLS: CapabilityState.UNSUPPORTED,
            },
            limitations=[
                Limitation(
                    scope="explain",
                    detail="EXPLAIN ANALYZE executes the statement and is never offered "
                    "for SQLite in this build; EXPLAIN and EXPLAIN QUERY PLAN are "
                    "non-executing.",
                ),
                Limitation(
                    scope="metadata",
                    detail="No synonyms or stored routines exist in SQLite. The internal tables of full-text "
                    "(FTS3/4/5) and R*Tree indexes are not listed and a statement reading one is refused: they "
                    "hold the indexed values under generic column names, where masking by name cannot apply.",
                ),
                Limitation(
                    scope="query",
                    detail="SQLite runs inside the server process. Each output value is cut to the cell "
                    "limit inside SQLite, except in a statement that is not one SELECT, uses DISTINCT or a "
                    "bound LIMIT, or selects * over a join, and except a column the statement compares "
                    "(WHERE, GROUP BY, HAVING, ORDER BY, a join condition, a position in GROUP BY or ORDER BY "
                    "under any spelling of an integer). SQLite's heap is capped at "
                    f"{_HEAP_LIMIT_VALUES}x the longest value a handle accepts "
                    f"({_heap_limit(self.policy.max_response_bytes) >> 20} MiB here). The cap is "
                    "process-wide: every SQLite handle in the server shares it, the metadata cache's "
                    "included, and the smallest cap any SQLite connection asks for applies. A statement "
                    "that needs more (a sort, group or DISTINCT over long values) is refused with "
                    "LIMIT_EXCEEDED.",
                ),
            ],
            required_privileges=[
                "filesystem read access to the configured database file (applied "
                "by the OS service identity, not by this connector)"
            ],
            unverified_items=[],
        )

    # ---- health ------------------------------------------------------------

    def health_check(self) -> HealthInfo:
        start = time.monotonic()
        try:
            with self._handle() as conn:
                row = conn.execute("SELECT sqlite_version()").fetchone()
            session = self.session_report({"uri_mode": "ro", "query_only": getattr(self, "_last_query_only", "?")})
            return HealthInfo(
                healthy=True,
                server_version=row[0] if row else sqlite3.sqlite_version,
                latency_ms=int((time.monotonic() - start) * 1000),
                session=session,
            )
        except Exception as exc:  # noqa: BLE001 - health reports failures
            detail = str(exc)
            if "file is not a database" in detail.lower():
                # The stdlib driver reports the same text for an encrypted file
                # and for a corrupt one, and operators read it as corruption.
                detail = (
                    f"{detail} - the file is not readable as plain SQLite: it may be ENCRYPTED "
                    "(SQLCipher or SQLite SEE, which the standard-library driver cannot open; "
                    "this build ships no encryption extension), truncated, or not a database"
                )
            return HealthInfo(healthy=False, detail=detail[:300], latency_ms=int((time.monotonic() - start) * 1000))

    # ---- metadata ----------------------------------------------------------

    def _quote(self, name: str) -> str:
        return '"' + name.replace('"', '""') + '"'

    # ---- the internal tables of virtual tables ------------------------------

    def _virtual_tables(self, conn: sqlite3.Connection) -> dict[str, str]:
        """The main schema's virtual tables, lowercased name -> module (''
        for one whose definition this cannot read). Read once per file and
        schema version: SQLite bumps the version with every schema change,
        and reading it is one header read."""
        stat = self._path.stat()
        key = (stat.st_dev, stat.st_ino, int(conn.execute("PRAGMA schema_version").fetchone()[0]))
        cached = self._vtabs
        if cached is not None and cached[0] == key:
            return cached[1]
        vtabs: dict[str, str] = {}
        for name, sql in conn.execute(
            "SELECT name, sql FROM main.sqlite_schema WHERE type = 'table' AND sql LIKE 'CREATE VIRTUAL TABLE%'"
        ).fetchall():
            vtabs[_fold(str(name))] = _module_of(str(sql)) or ""
        self._vtabs = (key, vtabs)
        return vtabs

    def _registered_modules(self, conn: sqlite3.Connection) -> frozenset[str]:
        """The virtual-table modules this SQLite library has. Unreadable: none,
        so every shadow-like name of a virtual table is kept back."""
        if self._modules is None:
            try:
                self._modules = frozenset(_fold(str(r[0])) for r in conn.execute("PRAGMA module_list").fetchall())
            except sqlite3.Error:
                return frozenset()
        return self._modules

    def _is_shadow(
        self, conn: sqlite3.Connection, vtabs: dict[str, str], schema: str, name: str, kind: str
    ) -> bool:
        """Whether a ``PRAGMA table_list`` row is an internal table of a
        full-text or R*Tree index: one SQLite marks so, or a plain table
        named after a virtual table (``vtabs``) whose module this build
        lacks, with a suffix of that module."""
        if kind == "shadow":
            return True
        if kind != "table" or _fold(schema) != "main":
            return False
        module = vtabs.get(_fold(name).rpartition("_")[0])
        return module is not None and _unmarked_shadow(name, module, self._registered_modules(conn))

    def _shadow_named(self, conn: sqlite3.Connection, schema: str | None, name: str) -> str | None:
        """The internal table of a full-text or R*Tree index that ``name``
        (in ``schema``, any when None) names, if any. Costs one header read
        unless the part of the name before its last "_" is a virtual table:
        PRAGMA table_list builds the columns of every view and virtual table
        it meets, so it is asked about such a name only."""
        owner, sep, _suffix = _fold(name).rpartition("_")
        if not sep or (schema is not None and _fold(schema) != "main"):
            return None  # SQLite names a shadow table <virtual table>_<suffix>; temp holds none here
        vtabs = self._virtual_tables(conn)
        if owner not in vtabs:
            return None
        for row in conn.execute(f"PRAGMA main.table_list({self._quote(name)})").fetchall():  # noqa: S608
            if self._is_shadow(conn, vtabs, str(row[0]), str(row[1]), str(row[2])):
                return str(row[1])
        return None

    def list_schemas(self, catalog: str | None, search: str | None) -> list[str]:
        # One attached database (main); read-only mode means temp is empty.
        with self._handle() as conn:
            rows = conn.execute("PRAGMA database_list").fetchall()
        names = [r[1] for r in rows if r[1] != "temp"]
        if search:
            names = [n for n in names if search.lower() in n.lower()]
        return names

    def list_tables(self, schema: str | None, kinds: set[str], search: str | None) -> list[TableSummary]:
        want_kinds = kinds or {"table", "view", "materialized_view"}
        out: list[TableSummary] = []
        # The estimates read dbstat, so the handle stays open for the loop.
        with self._handle() as conn:
            rows = conn.execute("PRAGMA table_list").fetchall()
            vtabs = self._virtual_tables(conn)
            # PRAGMA table_list columns: schema, name, type, ncol, wr, strict
            for schema_name, name, kind, _ncol, _wr, _strict in rows:
                if schema_name == "temp" or _is_catalog_table(name):
                    continue
                if self._is_shadow(conn, vtabs, schema_name, name, kind):
                    continue
                if schema and schema_name.lower() != schema.lower():
                    continue
                if kind == "view" and "view" not in want_kinds:
                    continue
                if kind == "table" and not ({"table"} & want_kinds):
                    continue
                if kind == "virtual" and not ({"table"} & want_kinds):
                    continue
                if search and search.lower() not in name.lower():
                    continue
                est = self._row_estimate(conn, schema_name, name) if kind != "view" else None
                out.append(
                    TableSummary(
                        schema=schema_name,
                        name=name,
                        kind="view" if kind == "view" else "table",
                        row_estimate=est,
                        row_estimate_source="catalog_estimate" if est is not None else None,
                    )
                )
        return out

    def _row_estimate(self, conn: sqlite3.Connection, schema: str, name: str) -> int | None:
        # sqlite_master has no per-table row count; use the dbstat virtual
        # table when compiled in (read-only, no side effects). No COUNT(*)
        # on user tables — that is a full scan, disallowed by default.
        if not self._dbstat_ok(conn):
            return None
        try:
            row = conn.execute(
                "SELECT SUM(ncell) FROM dbstat WHERE name = ?",  # noqa: S608 - parameterized
                (name,),
            ).fetchone()
            return int(row[0]) if row and row[0] is not None else None
        except sqlite3.Error:
            return None

    def _dbstat_ok(self, conn: sqlite3.Connection) -> bool:
        if self._dbstat_available is not None:
            return self._dbstat_available
        try:
            conn.execute("SELECT 1 FROM dbstat LIMIT 1")
            self._dbstat_available = True
        except sqlite3.OperationalError as exc:
            if "no such table" not in str(exc).lower():
                return False  # this handle failed, not the build: ask again next time
            self._dbstat_available = False  # built without SQLITE_ENABLE_DBSTAT_VTAB
        except sqlite3.Error:
            return False
        return self._dbstat_available

    def get_table(self, schema: str | None, name: str) -> dict[str, Any]:
        schema = schema or "main"
        with self._handle() as conn:
            rows = conn.execute(f"PRAGMA table_list({self._quote(name)})").fetchall()  # noqa: S608
            found = next(
                (r for r in rows if r[0].lower() == schema.lower() and r[1].lower() == name.lower()),
                None,
            )
            if found is None or self._is_shadow(conn, self._virtual_tables(conn), found[0], found[1], found[2]):
                raise ObjectNotFound(f"table '{schema}.{name}' not found")
            kind = "view" if found[2] == "view" else "table"
            cols = self.list_columns(schema, name)
            fks = self.get_foreign_keys(schema, name)
            pk = [c.name for c in self._pk_columns(conn, schema, name)]
            idx = self._indexes(conn, schema, name)
            ddl = self._definition(conn, schema, name)
            est = self._row_estimate(conn, schema, name) if kind == "table" else None
            return {
                "schema": schema,
                "name": name,
                "kind": kind,
                "row_estimate": est,
                "row_estimate_source": "catalog_estimate" if est is not None else None,
                "columns": [c.__dict__ for c in cols],
                "primary_key": pk,
                "foreign_keys": [fk.__dict__ for fk in fks],
                "indexes": [i.__dict__ for i in idx],
                "definition": ddl,
            }

    def _pk_columns(self, conn: sqlite3.Connection, schema: str, name: str) -> list[ColumnInfo]:
        rows = conn.execute(f"PRAGMA table_info({self._quote(name)})").fetchall()  # noqa: S608
        cols = [
            ColumnInfo(
                schema=schema,
                table=name,
                name=r[1],
                data_type=r[2] or "ANY",
                nullable=not bool(r[3]) and not bool(r[5]),
                default=r[4],
                ordinal=r[0],
            )
            for r in rows
        ]
        keyed = [(r[5], c) for c, r in zip(cols, rows, strict=True) if r[5] > 0]
        return [c for _pos, c in sorted(keyed, key=lambda kc: kc[0])]  # pk column order, not table order

    def list_indexes(self, schema: str | None, table: str | None) -> list[IndexInfo]:
        with self._handle() as conn:
            names = [table] if table else [t.name for t in self.list_tables(schema, {"table"}, None)]
            out: list[IndexInfo] = []
            for name in names:
                pk = [c.name for c in self._pk_columns(conn, schema or "main", name)]
                if pk:
                    out.append(IndexInfo(name="(primary key)", columns=pk, unique=True, primary=True,
                                         kind="primary_key", schema=schema or "main", table=name))
                for idx in self._indexes(conn, schema or "main", name):
                    idx.schema = schema or "main"
                    idx.table = name
                    idx.kind = "btree"
                    out.append(idx)
        return out

    def _indexes(self, conn: sqlite3.Connection, schema: str, name: str) -> list[IndexInfo]:
        out = []
        for row in conn.execute(f"PRAGMA index_list({self._quote(name)})").fetchall():  # noqa: S608
            _, idx_name, unique, _origin, _partial = row[:5]
            cols = [
                r[2]
                for r in conn.execute(
                    f"PRAGMA index_info({self._quote(str(idx_name))})"  # noqa: S608
                ).fetchall()
            ]
            out.append(IndexInfo(name=idx_name, columns=cols, unique=bool(unique)))
        return out

    def _definition(self, conn: sqlite3.Connection, schema: str, name: str) -> str | None:
        row = conn.execute(
            f"SELECT sql FROM {self._quote(schema)}.sqlite_schema "  # noqa: S608
            f"WHERE lower(name) = lower(?)",
            (name,),
        ).fetchone()
        return row[0] if row else None

    def list_columns(self, schema: str | None, table: str) -> list[ColumnInfo]:
        schema = schema or "main"
        with self._handle() as conn:
            if self._shadow_named(conn, schema, table):
                return []  # an internal table of an index: not a table here
            rows = conn.execute(f"PRAGMA table_info({self._quote(table)})").fetchall()  # noqa: S608
        return [
            ColumnInfo(
                schema=schema,
                table=table,
                name=r[1],
                data_type=r[2] or "ANY",
                nullable=not bool(r[3]) and not bool(r[5]),
                default=r[4],
                ordinal=r[0],
            )
            for r in rows
        ]

    def list_views(self, schema: str | None) -> list[ViewInfo]:
        schema = schema or "main"
        with self._handle() as conn:
            rows = conn.execute("SELECT name, sql FROM main.sqlite_schema WHERE type = 'view' ORDER BY name").fetchall()
        return [
            ViewInfo(schema=schema, name=r[0], kind="view", definition=r[1], definition_state="available") for r in rows
        ]

    def list_synonyms(self, schema: str | None) -> list[SynonymInfo]:
        return []  # SQLite has no synonyms; capability reports unsupported.

    def list_routines(self, schema: str | None) -> list[RoutineInfo]:
        return []  # SQLite has no stored routines; capability reports unsupported.

    def get_foreign_keys(self, schema: str | None, table: str | None) -> list[KeyInfo]:
        with self._handle() as conn:
            tables = [
                r[1]
                for r in conn.execute("PRAGMA table_list").fetchall()
                if r[0] == "main" and r[2] != "view" and not _is_catalog_table(r[1])
            ]
            if table:
                tables = [t for t in tables if t.lower() == table.lower()]
            fks: list[KeyInfo] = []
            for t in tables:
                # PRAGMA foreign_key_list row: (id, seq, table, from, to, ...).
                # Composite constraints share `id` with increasing seq; merge
                # on (id, ref_table) per source table so distinct constraints
                # are never conflated.
                merged: dict[tuple[int, str], KeyInfo] = {}
                order: list[tuple[int, str]] = []
                for row in conn.execute(f"PRAGMA foreign_key_list({self._quote(t)})").fetchall():  # noqa: S608
                    fid, seq, ref_table, from_col, to_col = row[:5]
                    if to_col is None:
                        # "REFERENCES parent" without a column list: the parent
                        # columns are its declared primary key, in key order.
                        to_col = self._parent_pk_column(conn, ref_table, int(seq))
                    key = (int(fid), ref_table)
                    if key not in merged:
                        merged[key] = KeyInfo(
                            kind="foreign_key",
                            name=None,
                            columns=[from_col],
                            ref_schema="main",
                            ref_table=ref_table,
                            ref_columns=[to_col],
                            source_schema="main",
                            source_table=t,
                        )
                        order.append(key)
                    else:
                        merged[key].columns.append(from_col)
                        merged[key].ref_columns.append(to_col)
                fks.extend(merged[k] for k in order)
        return fks

    def _parent_pk_column(self, conn: sqlite3.Connection, ref_table: str, seq: int) -> str:
        """seq-th column of the referenced table's declared primary key."""
        pk = [
            r[1]
            for r in conn.execute(f"PRAGMA table_info({self._quote(ref_table)})").fetchall()  # noqa: S608
            if r[5] > 0
        ]
        info = conn.execute(f"PRAGMA table_info({self._quote(ref_table)})").fetchall()  # noqa: S608
        pk.sort(key=lambda name: next(int(r[5]) for r in info if r[1] == name))
        return str(pk[seq]) if seq < len(pk) else str(pk[0])

    def get_statistics(self, schema: str | None, table: str) -> dict[str, Any]:
        schema = schema or "main"
        est = None
        with self._handle() as conn:
            if self._dbstat_ok(conn):
                est = self._row_estimate(conn, schema, table)
        return {
            "schema": schema,
            "table": table,
            "row_estimate": est,
            "row_estimate_source": "catalog_estimate(dbstat)" if est is not None else "unavailable",
            "note": "Exact counts require an explicit COUNT(*) query, which is "
            "disallowed by default to avoid full scans.",
        }

    # ---- query execution ----------------------------------------------------

    def cancel_current(self) -> bool:
        """Engine-level cancellation, called from a different thread by the
        executor on timeout: sqlite3.Connection.interrupt() on every open
        handle, again every _REINTERRUPT_SECONDS until they are all closed,
        and a flag every handle opening and every step of a query looks at.
        interrupt() alone reaches only a statement already running: one
        that lands while the statement is still being described, rewritten
        or prepared would be forgotten, and the statement would run
        unstopped. Always True: whatever this connector runs next stops."""
        self._cancelled.set()
        with self._handles_lock:
            self._interrupt_handles()
            start = bool(self._handles) and not self._reinterrupting
            self._reinterrupting = self._reinterrupting or start
        if start:
            threading.Thread(
                target=self._keep_interrupting, name=f"udbmcp-sqlite-cancel-{self.connection.name}", daemon=True
            ).start()
        return True

    def _interrupt_handles(self) -> None:
        """Interrupt every open handle; the caller holds _handles_lock."""
        for conn in list(self._handles):
            try:
                conn.interrupt()
            except sqlite3.Error:
                self._handles.discard(conn)  # closed outside _close: nothing runs on it

    def _keep_interrupting(self) -> None:
        """A cancelled connector's open handles, interrupted until closed:
        no statement starts on one and runs. Ends with the last of them;
        the connector opens no more."""
        while True:
            time.sleep(_REINTERRUPT_SECONDS)
            with self._handles_lock:
                self._interrupt_handles()
                if not self._handles:
                    self._reinterrupting = False
                    return

    def _stop_if_cancelled(self) -> None:
        """SQLite's own error for an interrupted statement, once cancelled."""
        if self._cancelled.is_set():
            raise sqlite3.OperationalError("interrupted")

    def execute_query(self, spec: QuerySpec) -> QueryOutcome:
        # Serialized per connector: the cancel slot must always reference the
        # one running query, and a local file database is not a scalability
        # boundary worth racing for (docs/driver-matrix.md).
        with self._conn_lock:
            return self._execute(spec)

    def _execute(self, spec: QuerySpec) -> QueryOutcome:
        with translated_driver_errors():
            conn = self._open()  # interrupted by a cancel from here on (see cancel_current)
        try:
            start = time.monotonic()
            parameters = spec.parameters or ()  # qmark/named params
            # A statement or value the engine rejects (a denied write, an
            # integer parameter past 64 bits) is the statement's error.
            with translated_driver_errors(phase="execute"), self._heap_refusals(
                "the statement", ": sort, group or compare shorter values (substr() cuts a long one), or fewer rows"
            ), self._length_refusals(conn):
                self._stop_if_cancelled()
                trees = self._refuse_shadow_tables(conn, spec.sql)
                capped = self._value_capped(conn, spec.sql, parameters, spec.max_cell_bytes, trees)
                self._stop_if_cancelled()
                return self._stream(conn, capped or spec.sql, parameters, spec, start)
        finally:
            self._close(conn)

    def _refuse_shadow_tables(self, conn: sqlite3.Connection, sql: str) -> list[exp.Expr | None] | None:
        """Refuse a statement that reads an internal table of a full-text or
        R*Tree index: it holds the indexed values under generic names (c0,
        c1ssn), so masking by column name would not apply. The engine's own
        reads of them, for a query on the index, are not affected (the
        authorizer cannot tell those apart). Only a table the statement
        reads counts, not a literal, alias or column of that name; a
        statement that cannot be parsed has every word of its read as one.
        Nothing to look for, and no parse, without a virtual table whose
        name, then "_", the statement's text contains, under any quoting
        (_spellings). Returns the statement's parse when it made one."""
        vtabs = self._virtual_tables(conn)
        if not vtabs:
            return None
        lowered = _fold(sql)
        if len(vtabs) <= _VTAB_PREFILTER and not any(
            f"{spelled}_" in lowered for name in vtabs for spelled in _spellings(name)
        ):
            return None
        trees = _parsed(sql)
        references = _table_references(trees) if trees is not None else None
        if references is None:
            try:
                tokens = sqlglot.Dialect.get_or_raise("sqlite").tokenize(sql)
            except Exception:  # noqa: BLE001 - sqlglot's TokenError, and whatever else a tokenizer raises
                raise ConnectorError(
                    "the statement could not be read to check it reads no internal table of a full-text or "
                    "R*Tree index",
                    category=ErrorCategory.QUERY,
                ) from None
            references = {(None, t.text) for t in tokens if "_" in t.text}
        name = next(
            (hit for schema, table in sorted(references, key=str) if (hit := self._shadow_named(conn, schema, table))),
            None,
        )
        if name is not None:
            raise ConnectorError(
                f"'{name}' is an internal table of a full-text or R*Tree index, which holds the indexed values "
                "outside the column names masking applies to; query the index's own table instead",
                category=ErrorCategory.QUERY,
            )
        return trees

    def _value_capped(
        self,
        conn: sqlite3.Connection,
        sql: str,
        parameters: Any,
        max_cell_bytes: int,
        trees: list[exp.Expr | None] | None = None,
    ) -> str | None:
        """The statement with each output column cut where SQLite computes
        it (_sql_cut, in SQL: no Python call per row), under the name the
        statement gives it (masking by name still applies), so a row, and the
        rows a sort holds, carry cut values; None when that cannot be exact:
        a statement that is not one SELECT (a UNION, VALUES), a DISTINCT, a
        LIMIT with a parameter, a star over a join, a select list with a
        '?' parameter (the cut repeats its expression, which would number
        the parameters after it anew). An output the statement compares
        keeps its whole value. ``trees`` is the statement's parse, when
        _refuse_shadow_tables made one."""
        parsed = [t for t in trees or () if t is not None]
        tree = parsed[0] if len(parsed) == 1 else None
        select = SelectList.locate(statement_body(sql, "sqlite"), "sqlite", tree=tree)
        if select is None or select.tree.args.get("distinct") or (probe := _describe_probe(select)) is None:
            return None
        if any(p.this is None for e in select.tree.expressions for p in e.find_all(exp.Placeholder)):
            return None
        try:
            names = [str(d[0]) for d in conn.execute(probe, parameters).description or []]
        except sqlite3.Error:
            return None  # the statement as written reports its own error
        cut = set(range(len(names))) - _compared_outputs(select.tree, names)
        if not cut:
            return None
        keep = max_cell_bytes + 1
        return select.rewrite(names, cut, lambda text: _sql_cut(text, keep), self._quote)

    def _stream(
        self, conn: sqlite3.Connection, sql: str, parameters: Any, spec: QuerySpec, start: float
    ) -> QueryOutcome:
        import json

        rows: list[list[Any]] = []
        truncated = False
        truncation_cause = "row limit"
        cell_trunc = False
        rows_seen = 0
        approx_bytes = 0
        col_labels: list[str] = []
        cur = conn.execute(sql, parameters)
        cols = [(d[0], "unknown") for d in cur.description or []]
        # One row at a time: a row costs no round trip in-process, and a
        # batch held whole rows here before their cells were cut (40 rows of
        # a 4 MB blob: 160 MB, live).
        while (raw := cur.fetchone()) is not None:
            self._stop_if_cancelled()
            rows_seen += 1
            adapted = [_adapt(v, spec.max_cell_bytes) for v in raw]
            del raw  # not alive while the next row is fetched
            for i, a in enumerate(adapted):
                if i >= len(col_labels):
                    col_labels.append(a[1])
                elif col_labels[i] in ("unknown", "null") and a[0] is not None:
                    col_labels[i] = a[1]
            row_vals = [a[0] for a in adapted]
            cell_trunc = cell_trunc or any(a[2] for a in adapted)
            approx_bytes += len(json.dumps(row_vals, default=str).encode("utf-8"))
            if len(rows) >= spec.max_rows or approx_bytes > spec.max_response_bytes:
                truncated = True
                truncation_cause = "row limit" if len(rows) >= spec.max_rows else "byte limit"
                conn.interrupt()  # stop the cursor at the engine level
                break
            rows.append(row_vals)
        final_types = col_labels or ["unknown"] * len(cols)
        warnings: list[str] = []
        if truncated:
            warnings.append(f"result truncated by {truncation_cause}")
        if cell_trunc:
            warnings.append(
                f"one or more cell values exceeded the {spec.max_cell_bytes} byte cell limit and were truncated"
            )
        return QueryOutcome(
            columns=[(c[0], t) for c, t in zip(cols, final_types, strict=True)],
            rows=rows,
            # A cut cell is its warning only, unlike the other engines: SQLite
            # keeps any text in a column declared DATE or NUMERIC, whose
            # MIN/MAX the profile does not cut, and the server refuses a
            # truncated aggregate row as a whole (db_profile_table).
            truncated=truncated,
            rows_seen=rows_seen,
            elapsed_ms=int((time.monotonic() - start) * 1000),
            warnings=warnings,
        )

    def explain(self, sql: str, analyze: bool) -> dict[str, Any]:
        if analyze:
            raise NotImplementedError(EXPLAIN_ANALYZE_UNSUPPORTED)
        # EXPLAIN QUERY PLAN is non-executing; run it for real and preserve
        # the engine's plan rows verbatim.
        with self._handle("planning the statement") as conn:
            rows = conn.execute("EXPLAIN QUERY PLAN " + sql).fetchall()  # noqa: S608 - validated upstream
        return {
            "engine": "sqlite",
            "raw": [list(r) for r in rows],
            "note": "EXPLAIN QUERY PLAN output preserved verbatim; no optimization findings are invented",
        }
