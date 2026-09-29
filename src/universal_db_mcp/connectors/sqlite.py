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
import sqlite3
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Any

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
}


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
# inside SQLite (_CUT_FUNCTION), so this only bounds what that cannot reach:
# a sort, group or DISTINCT over long values, a wide row inside a subquery.
_HEAP_LIMIT_VALUES = 32
_heap_limit_enforced: bool | None = None  # this SQLite library counts its heap (decided once)
# The SQL function that cuts each output value where SQLite computes it, so
# a row or a sort holds cut values (live, review round 4: 16 columns of one
# 8 MiB value grew the server by 327 MB, ORDER BY over 30 rows of 4 MiB by
# 194 MB). CPython reports any failure of such a function, its arguments'
# conversion included (text that is not UTF-8), in these words.
_CUT_FUNCTION = "udbmcp_cut"
_CUT_FAILED = "user-defined function raised exception"


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


def _value_cut(keep: int) -> Callable[[Any], Any]:
    """The _CUT_FUNCTION: a text or blob value cut to ``keep`` characters
    or bytes, any other value as it is (an integer stays an integer)."""

    def cut(value: Any) -> Any:
        if isinstance(value, (str, bytes)) and len(value) > keep:
            return value[:keep]
        return value

    return cut


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
    a column would be compared by its first characters."""
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
            term = item.this if isinstance(item, exp.Ordered) else item
            if isinstance(term, exp.Literal) and not term.is_string and term.this.isdigit():
                out.add(int(term.this) - 1)
    return out


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
        self._path = Path(path).expanduser().resolve()
        self._conn_lock = threading.Lock()
        self._current_conn: sqlite3.Connection | None = None
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
    def _handle(self) -> Iterator[sqlite3.Connection]:
        """A fresh handle for one metadata call, closed when it returns."""
        with self._heap_refusals("reading the database's schema"), closing(self._open()) as conn:
            yield conn

    def _open(self) -> sqlite3.Connection:
        """A fresh read-only handle. The caller closes it (contextlib.closing):
        'with conn' only ends a transaction, and a Connection sits in a
        reference cycle, so an unclosed one kept its parsed schema, under
        SQLite's process-wide heap cap, until the cyclic GC ran."""
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
                    detail="No synonyms or stored routines exist in SQLite.",
                ),
                Limitation(
                    scope="query",
                    detail="SQLite runs inside the server process. Each output value is cut to the cell "
                    "limit inside SQLite, except in a statement that is not one SELECT, uses DISTINCT or a "
                    "bound LIMIT, or selects * over a join, and except a column the statement compares "
                    "(WHERE, GROUP BY, HAVING, ORDER BY, a join condition). SQLite's heap is capped at "
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
            # PRAGMA table_list columns: schema, name, type, ncol, wr, strict
            for schema_name, name, kind, _ncol, _wr, _strict in rows:
                if schema_name == "temp" or _is_catalog_table(name):
                    continue
                if schema and schema_name.lower() != schema.lower():
                    continue
                if kind == "view" and "view" not in want_kinds:
                    continue
                if kind in ("table", "shadow") and not ({"table"} & want_kinds):
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
            rows = conn.execute("PRAGMA table_list").fetchall()
            found = next(
                (r for r in rows if r[0].lower() == schema.lower() and r[1].lower() == name.lower()),
                None,
            )
            if found is None:
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
        """Engine-level cancellation: sqlite3.Connection.interrupt(). Called
        from a different thread by the executor on timeout. Executions are
        serialized per connector (see execute_query), so the registered
        handle is always the running query."""
        conn = self._current_conn
        if conn is not None:
            try:
                conn.interrupt()
                return True
            except sqlite3.Error:
                return False
        return False

    def execute_query(self, spec: QuerySpec) -> QueryOutcome:
        # Serialized per connector: the cancel slot must always reference the
        # one running query, and a local file database is not a scalability
        # boundary worth racing for (docs/driver-matrix.md).
        with self._conn_lock:
            return self._execute(spec)

    def _execute(self, spec: QuerySpec) -> QueryOutcome:
        with translated_driver_errors():
            conn = self._open()
        try:
            start = time.monotonic()
            parameters = spec.parameters or ()  # qmark/named params
            # A statement or value the engine rejects (a denied write, an
            # integer parameter past 64 bits) is the statement's error.
            with translated_driver_errors(phase="execute"), self._heap_refusals(
                "the statement", ": sort, group or compare shorter values (substr() cuts a long one), or fewer rows"
            ), self._length_refusals(conn):
                conn.create_function(_CUT_FUNCTION, 1, _value_cut(spec.max_cell_bytes + 1), deterministic=True)
                capped = self._value_capped(conn, spec.sql, parameters)
                self._current_conn = conn
                try:
                    return self._stream(conn, capped or spec.sql, parameters, spec, start)
                except sqlite3.OperationalError as exc:
                    if capped is None or str(exc) != _CUT_FAILED:
                        raise
                # The cut could not take a value (text that is not UTF-8
                # reaches no Python function), perhaps in a row the statement
                # then leaves out: the statement as written decides.
                return self._stream(conn, spec.sql, parameters, spec, start)
        finally:
            self._current_conn = None
            conn.close()

    def _value_capped(self, conn: sqlite3.Connection, sql: str, parameters: Any) -> str | None:
        """The statement with each output column cut by _CUT_FUNCTION where
        SQLite computes it, under the name the statement gives it (masking by
        name still applies), so a row, and the rows a sort holds, carry cut
        values; None when that cannot be exact: a statement that is not one SELECT
        (a UNION, VALUES), a DISTINCT, a LIMIT with a parameter, a star over
        a join. An output the statement compares keeps its whole value."""
        select = SelectList.locate(statement_body(sql, "sqlite"), "sqlite")
        if select is None or select.tree.args.get("distinct") or (probe := _describe_probe(select)) is None:
            return None
        try:
            names = [str(d[0]) for d in conn.execute(probe, parameters).description or []]
        except sqlite3.Error:
            return None  # the statement as written reports its own error
        cut = set(range(len(names))) - _compared_outputs(select.tree, names)
        if not cut:
            return None
        return select.rewrite(names, cut, lambda text: f"{_CUT_FUNCTION}({text})", self._quote)

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
        with self._heap_refusals("planning the statement"), closing(self._open()) as conn:
            rows = conn.execute("EXPLAIN QUERY PLAN " + sql).fetchall()  # noqa: S608 - validated upstream
        return {
            "engine": "sqlite",
            "raw": [list(r) for r in rows],
            "note": "EXPLAIN QUERY PLAN output preserved verbatim; no optimization findings are invented",
        }
