"""PostgreSQL connector (psycopg 3, binary wheel).

Integration status: implemented against psycopg 3 documented APIs; marked
``unverified`` in capabilities until a real instance proves each item (Gate
C). TLS uses the explicit CA file; verification is never disabled.
"""

from __future__ import annotations

import codecs
import functools
import math
import struct
import threading
import time
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from typing import Any

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
    TableSummary,
    ViewInfo,
    own_objects_first,
)
from universal_db_mcp.connectors.driver_helpers import (
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
from universal_db_mcp.security.sql_guard import translate_paramstyle

# Result types whose text form has a small bound (booleans, numbers, dates
# and times, network addresses, uuid, geometric points and boxes, reg* and
# ranges of bounded types). A query's other columns are cut server-side.
_PG_BOUNDED_TYPES = frozenset({
    16, 18, 19, 20, 21, 23, 24, 26, 27, 28, 29, 600, 601, 603, 628, 650, 700, 701, 718, 774, 790, 829, 869,
    1082, 1083, 1114, 1184, 1186, 1266, 1700, 2202, 2203, 2204, 2205, 2206, 2950, 3220, 3734, 3769,
    3904, 3906, 3908, 3910, 3912, 3926, 4089, 4096, 4191, 5069,
})
_PG_BYTEA = 17
_PG_DECLARED_LENGTH_TYPES = frozenset({1042, 1043})  # char(n), varchar(n): n characters, 4 bytes at most each
# Types psycopg loads into Python values (json, jsonb, an anonymous record)
# that the cap keeps typed unless the value is too long, and the expression
# that carries a cut value in the same type (a JSON string, a one-field row).
_PG_TYPED_CUTS = {114: "to_json", 3802: "to_jsonb", 2249: "ROW"}
_PG_SYSTEM_SCHEMAS = ("pg_toast", "pg_catalog", "information_schema")
# How the server reads a string literal, held where the guard parses it. With
# standard_conforming_strings off (a role's or database's setting, or libpq's
# options=-c), a backslash in '...' escapes the next character: 'x\', ' ,
# secret FROM t --' is then one string and a read of t to the server, where
# the guard reads two literals (live, PostgreSQL 17). backslash_quote keeps
# its default; it only decides whether E'\'' is refused.
_PG_PIN_READING = "SET standard_conforming_strings = on; SET backslash_quote = safe_encoding"
# Parses only where the server reads the backslash as the character it is.
_PG_READING_PROBE = "SELECT 'udbmcp\\'"
# The encoding psycopg writes each statement in and the server decodes it
# from, held at the UTF-8 the guard read. Under a role's or database's
# client_encoding SJIS, the guard's '¥' is the byte 0x5C, a backslash to the
# server (review, live, PostgreSQL 17: SELECT '¥' returned '\', and
# length(E'¥n') was 1). The probe fails (invalid input syntax for type
# integer) unless the server decodes statements as UTF-8.
_PG_PIN_ENCODING = "SET client_encoding = 'UTF8'"
_PG_ENCODING_PROBE = "SELECT CAST(NULLIF(current_setting('client_encoding'), 'UTF8') AS integer)"
# How long cancel_current waits for the server to take a cancel request;
# under the executor's cancel-hook budget (2 s).
_CANCEL_TIMEOUT_SECONDS = 1.5


def _cancel_waits_without_the_gil() -> bool:
    """psycopg's cancel_safe() waits without the GIL only on libpq 17 or
    later; on an older libpq it quietly calls cancel() (PQcancel), which
    holds the GIL until the host answers."""
    try:
        import psycopg

        return bool(psycopg.capabilities.has_cancel_safe())
    except Exception:  # noqa: BLE001 - no psycopg, or one without the capability probe
        return False


def _pg_is_array(conn: Any, oid: int) -> bool:
    """psycopg loads the array types it knows into lists; their JSON form
    is what a caller saw before the cap."""
    types = getattr(getattr(conn, "adapters", None), "types", None)
    info = types.get(oid) if types is not None else None
    return info is not None and getattr(info, "array_oid", None) == oid


def _pg_capped_select(
    conn: Any, sql: str, description: Sequence[Any], max_cell_bytes: int, *, bound: bool
) -> str | None:
    """The statement as a derived table whose unbounded columns the server
    cuts to ``max_cell_bytes + 1`` (so a cut is still detected here), or
    None when no column needs it.

    Columns are referenced by position (duplicate or odd names cannot
    collide) and keep the statement's own names, so masking by name still
    applies. PostgreSQL never pulls a subquery with ORDER BY into the outer
    query, so the rows keep their order. A '%' in a name is doubled when
    parameters are bound (psycopg formats the text then). json, jsonb and
    record values within the limit keep their type, so psycopg still loads
    them (a JSON number stays a number); only a longer one arrives as its
    cut text. An array has no such form and is cut as its JSON text. Such a
    typed cut reads its column up to three times, so the statement is then
    fenced (OFFSET 0) to compute each value once instead of PostgreSQL
    pulling it up into the CASE.
    """
    keep = max_cell_bytes + 1
    items: list[str] = []
    capped = fenced = False
    for i, d in enumerate(description, start=1):
        ref = f"udbmcp_q.c{i}"
        width = getattr(d, "display_size", None)
        if d.type_code in _PG_BOUNDED_TYPES or (
            d.type_code in _PG_DECLARED_LENGTH_TYPES and width and width * 4 <= max_cell_bytes
        ):
            expr = ref
        elif d.type_code == _PG_BYTEA:
            expr = f"substring({ref} FROM 1 FOR {keep})"
        elif cut := _PG_TYPED_CUTS.get(d.type_code):
            # A NULL's length is NULL too: it keeps its own branch, or
            # ROW(left(NULL, n)) would make a NULL record a one-field row.
            expr = (
                f"CASE WHEN COALESCE(octet_length({ref}::text), 0) <= {max_cell_bytes} THEN {ref} "
                f"ELSE {cut}(left({ref}::text, {keep})) END"
            )
            fenced = True
        elif _pg_is_array(conn, d.type_code):
            expr = f"left(to_json({ref})::text, {keep})"
        else:
            expr = f"left({ref}::text, {keep})"
        capped = capped or expr != ref
        name = '"' + str(d[0]).replace('"', '""') + '"'
        items.append(f"{expr} AS {name.replace('%', '%%') if bound else name}")
    if not capped:
        return None
    # The statement ends at its last token: ';' (or several), whitespace and
    # comments after it are a syntax error inside the parentheses.
    source = f"(\n{statement_body(sql, 'postgres')}\n)"
    if fenced:
        source = f"(SELECT * FROM {source} AS udbmcp_s OFFSET 0)"
    positions = ", ".join(f"c{i}" for i in range(1, len(description) + 1))
    return f"SELECT {', '.join(items)} FROM {source} AS udbmcp_q({positions})"


_PG_EPOCH_JDATE = 2451545  # 2000-01-01, PostgreSQL's date epoch, as a Julian day
_INT32_INFINITY = 2**31 - 1
_INT64_INFINITY = 2**63 - 1


def _pg_date_text(days: int) -> str:
    """PostgreSQL's own spelling of a date (days since 2000-01-01) that
    Python's date cannot hold; PostgreSQL's j2date."""
    julian = days + _PG_EPOCH_JDATE + 32044
    quad, rest = divmod(julian, 146097)
    julian += 60 + quad * 3 + (rest * 4 + 3) // 146097
    quad, julian = divmod(julian, 1461)
    y = julian * 4 // 1461
    julian = ((julian + 305) % 365 if y else (julian + 306) % 366) + 123
    year = y + quad * 4 - 4800
    quad = julian * 2141 // 65536
    day = julian - 7834 * quad // 256
    month = (quad + 10) % 12 + 1
    return f"{year:04d}-{month:02d}-{day:02d}" if year > 0 else f"{1 - year:04d}-{month:02d}-{day:02d} BC"


def _pg_clock_text(micros: int) -> str:
    """HH:MM:SS[.ffffff] of a non-negative number of microseconds (hours
    past 23 included: '24:00:00' is a valid PostgreSQL time)."""
    seconds, fraction = divmod(micros, 1_000_000)
    clock = f"{seconds // 3600:02d}:{seconds // 60 % 60:02d}:{seconds % 60:02d}"
    return clock + (f".{fraction:06d}" if fraction else "")


def _pg_timestamp_text(micros: int, tz: bool) -> str:
    days, rest = divmod(micros, 86_400_000_000)
    date_text = _pg_date_text(days)
    date_part, bc = (date_text[:-3], " BC") if date_text.endswith(" BC") else (date_text, "")
    return f"{date_part} {_pg_clock_text(rest)}{'+00' if tz else ''}{bc}"


def _pg_utc_offset_text(west: int) -> str:
    """PostgreSQL's spelling of a timetz offset, which it stores as seconds
    west of UTC: +00, +05:30, -08."""
    hours, rest = divmod(abs(west), 3600)
    minutes, seconds = divmod(rest, 60)
    text = f"{'-' if west > 0 else '+'}{hours:02d}"
    if minutes or seconds:
        text += f":{minutes:02d}"
    return text + (f":{seconds:02d}" if seconds else "")


def _pg_interval_text(micros: int, days: int, months: int) -> str:
    """PostgreSQL's spelling (IntervalStyle postgres) of an interval Python's
    timedelta cannot hold."""
    if (micros, days, months) == (_INT64_INFINITY, _INT32_INFINITY, _INT32_INFINITY):
        return "infinity"
    if (micros, days, months) == (-_INT64_INFINITY - 1, -_INT32_INFINITY - 1, -_INT32_INFINITY - 1):
        return "-infinity"
    years = abs(months) // 12 * (1 if months >= 0 else -1)
    parts = [
        f"{n} {unit}{'' if abs(n) == 1 else 's'}"
        for n, unit in ((years, "year"), (months - 12 * years, "mon"), (days, "day"))
        if n
    ]
    if micros or not parts:
        sign = "-" if micros < 0 else ("+" if parts and parts[-1].startswith("-") else "")
        parts.append(sign + _pg_clock_text(abs(micros)))
    return " ".join(parts)


@functools.cache
def _tolerant_datetime_loaders() -> tuple[tuple[str, type[Any]], ...]:
    """psycopg's date/time loaders refuse or misread what Python's datetime
    cannot hold, all valid in PostgreSQL: dates and timestamps at 'infinity'
    or '-infinity' (SCD2 tables close rows with valid_to = 'infinity'), BC
    or after year 9999; times at '24:00:00' (end of day); intervals at
    'infinity' (read as 0) or past timedelta's range (psycopg's C loader
    wraps them around). One such value failed the whole query, or was
    silently wrong. These return the server's own text instead; binary
    values are spelled the way the server would (UTC for timestamptz).
    Never clamped to date.max: that would be a different date.
    """
    from psycopg import DataError
    from psycopg.types import datetime as pg_datetime

    def text_form(base: type[Any]) -> type[Any]:
        class Tolerant(base):  # type: ignore[misc]
            def load(self, data: Any) -> Any:
                try:
                    return super().load(data)
                except DataError:
                    return bytes(data).decode()

        return Tolerant

    class Date(pg_datetime.DateBinaryLoader):
        def load(self, data: Any) -> Any:
            try:
                return super().load(data)
            except DataError:
                days = struct.unpack("!i", bytes(data))[0]
                if abs(days) >= _INT32_INFINITY:
                    return "infinity" if days > 0 else "-infinity"
                return _pg_date_text(days)

    def binary_timestamp(base: type[Any], tz: bool) -> type[Any]:
        class Timestamp(base):  # type: ignore[misc]
            def load(self, data: Any) -> Any:
                try:
                    return super().load(data)
                except DataError:
                    micros = struct.unpack("!q", bytes(data))[0]
                    if abs(micros) >= _INT64_INFINITY:
                        return "infinity" if micros > 0 else "-infinity"
                    return _pg_timestamp_text(micros, tz)

        return Timestamp

    class TimeBinary(pg_datetime.TimeBinaryLoader):
        def load(self, data: Any) -> Any:
            try:
                return super().load(data)
            except DataError:
                return _pg_clock_text(struct.unpack("!q", bytes(data))[0])

    class TimetzBinary(pg_datetime.TimetzBinaryLoader):
        def load(self, data: Any) -> Any:
            try:
                return super().load(data)
            except DataError:
                micros, west = struct.unpack("!qi", bytes(data))
                return _pg_clock_text(micros) + _pg_utc_offset_text(west)

    class Interval(pg_datetime.IntervalLoader):
        def load(self, data: Any) -> Any:
            text = bytes(data).decode()
            if text.lstrip("-") == "infinity":  # psycopg reads it as 0
                return text
            try:
                return super().load(data)
            except (DataError, NotImplementedError):  # out of range; an IntervalStyle psycopg cannot read
                return text

    class IntervalBinary(pg_datetime.IntervalBinaryLoader):
        def load(self, data: Any) -> Any:
            try:
                return super().load(data)
            except DataError:
                return _pg_interval_text(*struct.unpack("!qii", bytes(data)))

    return (
        ("date", text_form(pg_datetime.DateLoader)),
        ("timestamp", text_form(pg_datetime.TimestampLoader)),
        ("timestamptz", text_form(pg_datetime.TimestamptzLoader)),
        ("time", text_form(pg_datetime.TimeLoader)),
        ("timetz", text_form(pg_datetime.TimetzLoader)),
        ("interval", Interval),
        ("date", Date),
        ("timestamp", binary_timestamp(pg_datetime.TimestampBinaryLoader, False)),
        ("timestamptz", binary_timestamp(pg_datetime.TimestamptzBinaryLoader, True)),
        ("time", TimeBinary),
        ("timetz", TimetzBinary),
        ("interval", IntervalBinary),
    )


def _register_tolerant_datetime_loaders(conn: Any) -> None:
    adapters = getattr(conn, "adapters", None)
    if adapters is None:
        return
    for name, loader in _tolerant_datetime_loaders():
        adapters.register_loader(name, loader)


def _pg_type(data_type: Any, char_len: Any, precision: Any, scale: Any) -> str:
    """information_schema.data_type with the declared length/precision folded
    back in ("character varying(200)", "numeric(12,2)"), so the profiler's
    oversized_string / integer_range findings have something to compare."""
    base = str(data_type or "")
    low = base.lower()
    if low in ("character varying", "character", "varchar", "char", "bpchar", "bit", "bit varying") and char_len:
        return f"{base}({int(char_len)})"
    if low in ("numeric", "decimal") and precision:
        return f"{base}({int(precision)},{int(scale or 0)})"
    return base


class PostgresConnector(DatabaseConnector):
    engine = "postgres"

    def __init__(self, connection: ResolvedConnection, policy: EffectivePolicy) -> None:
        super().__init__(connection, policy)
        self._module: Any = None
        self._cancel_target: Any = None
        self._exec_lock = threading.Lock()  # serializes queries: cancel slot correctness
        self._exec_state_lock = threading.Lock()  # guards _exec_waiters
        self._exec_waiters = 0  # requests queued on _exec_lock, not yet executing
        self._pool_lock = threading.Lock()
        self._meta_conn: Any = None  # reused metadata connection (probe on checkout)

    @contextmanager
    def _shared_meta_conn(self) -> Iterator[Any]:
        """Reusable metadata connection with probe-on-checkout (spec §7
        connection pooling; bounded to one connection per connector).

        A psycopg connection must never be used as a context manager here:
        ``Connection.__exit__`` *closes* the connection, which would defeat
        pooling. The pool lock is held for the whole ``with`` block — checkout
        probe, execute and fetch — mirroring how ``_exec_lock`` serializes
        queries, so two concurrent metadata callers can never share (and one
        close) the same connection. If the block raises, the connection is
        discarded (closed and dropped, fail closed) rather than reused in an
        uncertain state; the next caller transparently reconnects.
        """
        # Driver errors of the connect and of the catalog query run in the
        # caller's block are translated here, after the discard below: an
        # unreachable server must be a per-connection failure, not a crash of
        # a cross-connection tool.
        with self._pool_lock, translated_driver_errors():
            if self._meta_conn is not None:
                try:
                    self._meta_conn.execute("SELECT 1")
                except Exception:  # noqa: BLE001 - stale connection, rebuild
                    self._discard_meta_conn()
            if self._meta_conn is None:
                conn = self._connect()
                conn.autocommit = True
                self._meta_conn = conn
            try:
                yield self._meta_conn
            except BaseException:
                self._discard_meta_conn()
                raise
            finally:
                try:
                    self._meta_conn.rollback()  # release any implicit transaction state
                except Exception:  # noqa: BLE001, S110
                    pass

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

    def _connect(self) -> Any:
        self._module = open_module(
            "psycopg",
            "psycopg[binary] (manylinux cp312 wheel from the bundle wheelhouse)",
        )
        cfg = self.connection.config
        kw: dict[str, Any] = {
            "host": cfg.host,
            "port": cfg.port or 5432,
            "dbname": cfg.database,
            # rounded up: int(0.5) == 0 means "wait forever" to libpq
            "connect_timeout": max(1, math.ceil(cfg.connect_timeout_seconds)),
        }
        if self.connection.username:
            kw["user"] = self.connection.username.value
        if self.connection.password:
            kw["password"] = self.connection.password.value
        if cfg.tls.enabled:
            kw["sslmode"] = "verify-full" if cfg.tls.verify_server else "require"
            kw["sslrootcert"] = cfg.tls.ca_file
            if cfg.tls.client_cert_file:
                kw["sslcert"] = cfg.tls.client_cert_file
            if cfg.tls.client_key_file:
                kw["sslkey"] = cfg.tls.client_key_file
        # Pass-through options for deployments libpq can reach but our schema
        # cannot describe: Kerberos/GSSAPI, service files, and an explicit
        # sslmode when TLS is deliberately off (config refuses one that could
        # weaken an enabled tls block).
        for key in ("gssencmode", "krbsrvname", "service", "passfile", "sslmode"):
            value = cfg.options.get(key)
            if value:
                kw[key] = value
        kw["application_name"] = self.session_profile.application_name
        conn = self._module.connect(**kw)
        _register_tolerant_datetime_loaders(conn)
        self._configure_session(conn)
        return conn

    def _configure_session(self, conn: Any) -> None:
        """Apply the session safety profile (see security/session.py).

        SET inside psycopg's implicit transaction would be rolled back with
        it, so the statements run with autocommit on and the previous mode is
        restored. Server-side read-only is REQUIRED when requested: it is the
        promise this profile makes. The ceilings are best-effort and recorded.
        How string literals are read (_PG_PIN_READING) and the encoding
        statements travel in (_PG_PIN_ENCODING) are required on every
        connection, first, and each checked by a statement that runs only
        then; psycopg's own codec is checked too.
        """
        prof = self.session_profile
        self._session_reset()
        previous = getattr(conn, "autocommit", None)
        try:
            if previous is False:
                conn.autocommit = True
            try:
                conn.execute(_PG_PIN_READING)
                conn.execute(_PG_READING_PROBE)
                self._session_applied("standard_conforming_strings=on")
            except Exception as exc:  # noqa: BLE001
                raise self._reading_required("standard_conforming_strings on", exc) from exc
            try:
                conn.execute(_PG_PIN_ENCODING)
                conn.execute(_PG_ENCODING_PROBE)
                # psycopg follows the client_encoding the server reports; a
                # connection object without `info` is not psycopg's
                info = getattr(conn, "info", None)
                if info is not None and codecs.lookup(info.encoding).name != "utf-8":
                    raise RuntimeError(f"psycopg encodes statements as {info.encoding}")
                self._session_applied("client_encoding=UTF8")
            except Exception as exc:  # noqa: BLE001
                raise self._reading_required("the UTF8 client encoding", exc) from exc
            if prof.enforce_read_only:
                try:
                    conn.execute("SET default_transaction_read_only = on")
                    self._session_applied("read_only")
                except Exception as exc:  # noqa: BLE001
                    raise self._session_required("read-only mode", exc) from exc
            if prof.statement_timeout_seconds:
                ms = int(math.ceil(prof.statement_timeout_seconds * 1000))
                try:
                    conn.execute(f"SET statement_timeout = '{ms}ms'")
                    self._session_applied(f"statement_timeout={ms}ms")
                except Exception as exc:  # noqa: BLE001
                    self._session_skipped("statement_timeout", exc)
            if prof.lock_timeout_seconds is not None:
                ms = max(1, int(math.ceil(prof.lock_timeout_seconds * 1000)))  # 0 would DISABLE the ceiling
                try:
                    conn.execute(f"SET lock_timeout = '{ms}ms'")
                    self._session_applied(f"lock_timeout={ms}ms")
                except Exception as exc:  # noqa: BLE001
                    self._session_skipped("lock_timeout", exc)
            if prof.isolation:
                level = prof.isolation.replace("_", " ")
                try:
                    conn.execute(f"SET default_transaction_isolation = '{level}'")
                    self._session_applied(f"isolation={prof.isolation}")
                except Exception as exc:  # noqa: BLE001
                    raise self._session_required(f"isolation {prof.isolation}", exc) from exc
        finally:
            if previous is False:
                conn.autocommit = previous

    def _session_readback(self, conn: Any) -> dict[str, Any]:
        try:
            row = conn.execute(
                "SELECT current_setting('default_transaction_read_only'), "
                "current_setting('statement_timeout'), current_setting('lock_timeout'), "
                "current_setting('application_name'), current_setting('default_transaction_isolation'), "
                "current_setting('standard_conforming_strings'), current_setting('client_encoding')"
            ).fetchone()
        except Exception:  # noqa: BLE001 - reporting only
            return {}
        if not row or len(row) < 5:
            return {}
        keys = (
            "read_only", "statement_timeout", "lock_timeout", "application_name", "isolation",
            "standard_conforming_strings", "client_encoding",
        )
        return {k: str(v) for k, v in zip(keys, row, strict=False)}

    def cancel_current(self) -> bool:
        """Request-scoped best-effort cancel of the executing query.

        The executor's deadline hook calls this from a separate thread with no
        request identity, so the only safe discriminator is execution state:
        if another request is still queued on ``_exec_lock``, the deadline that
        fired belongs to the *queued* request, and cancelling the registered
        target would kill an unrelated in-flight query. In that case the hook
        refuses (fail closed): the cancel is lost, but the executor still
        discards the timed-out request's connection and poisons the connector.
        """
        with self._exec_state_lock:
            if self._exec_waiters > 0:
                return False
        target = self._cancel_target
        if target is not None:
            if not _cancel_waits_without_the_gil():
                # Not sent: the server's statement_timeout still ends the
                # query, and the executor discards the connection.
                return False
            try:
                # Server-side cancel on a separate connection. Not cancel():
                # libpq's PQcancel blocks holding the GIL, so a host that
                # stopped answering froze every thread. cancel_safe waits
                # without it and gives up inside the executor's hook budget.
                target.cancel_safe(timeout=_CANCEL_TIMEOUT_SECONDS)
                return True
            except Exception:  # noqa: BLE001, S110
                return False
        return False

    def capabilities(self) -> CapabilityMatrix:
        limitations = [
            Limitation(scope="explain", detail=f"{EXPLAIN_ANALYZE_UNSUPPORTED}."),
            Limitation(
                scope="cancel",
                detail="psycopg cancel() requests server-side cancellation; the "
                "executor still discards the connection after a deadline. "
                "Cancel is skipped while another request is queued, so a "
                "queued request's deadline can never cancel a running query.",
            ),
        ]
        if not _cancel_waits_without_the_gil():
            limitations.append(
                Limitation(
                    scope="cancel",
                    detail="this psycopg's libpq predates 17, so its only cancel (PQcancel) holds the "
                    "interpreter lock until the host answers, freezing the whole server behind an "
                    "unresponsive host: no cancel is sent. The server-side statement_timeout still ends "
                    "the query; install a psycopg-binary that bundles libpq 17 or later.",
                )
            )
        return CapabilityMatrix(
            engine="postgres",
            engine_family="postgresql",
            driver="psycopg 3 (binary)",
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
            limitations=limitations,
            required_privileges=[
                "CONNECT on the database",
                "USAGE on allowed schemas",
                "SELECT on permitted tables/views",
                "read access to catalog views for metadata (pg_catalog)",
            ],
            unverified_items=[
                "live TLS verify-full against internal CA",
                "server-side cancel under load",
                "row estimates via pg_class.reltuples freshness",
            ],
        )

    def health_check(self) -> HealthInfo:
        start = time.monotonic()
        try:
            with self._connect() as conn:
                row = conn.execute("SELECT version()").fetchone()
                session = self.session_report(self._session_readback(conn))
            return HealthInfo(
                healthy=True,
                server_version=(row[0] if row else "")[:40],
                latency_ms=int((time.monotonic() - start) * 1000),
                session=session,
            )
        except Exception as exc:  # noqa: BLE001, S110
            return HealthInfo(healthy=False, detail=scrub_exception(exc)[:300])

    def list_schemas(self, catalog: str | None, search: str | None) -> list[str]:
        sql = "SELECT schema_name FROM information_schema.schemata"
        params: list[Any] = []
        if search:
            sql += " WHERE schema_name ILIKE %s"
            params.append(f"%{search}%")
        sql += " ORDER BY 1"
        with self._shared_meta_conn() as conn:
            return [r[0] for r in conn.execute(sql, params).fetchall()]

    def name_binding(self) -> NameBinding:
        # the search_path as this login's sessions have it (schemas that do
        # not exist or that it may not use left out; pg_catalog only where
        # the path names it, else it is searched first: server._first_schema),
        # asked of a new session as each statement runs on one: the shared
        # metadata session keeps the path it opened with (live: after ALTER
        # ROLE ... SET search_path it still answered the old one)
        with translated_driver_errors():
            conn = self._connect()
            try:
                row = conn.execute("SELECT current_schemas(false)").fetchone()
            finally:
                conn.close()
        return NameBinding(tuple(str(s) for s in row[0]))

    def list_tables(self, schema: str | None, kinds: set[str], search: str | None) -> list[TableSummary]:
        types: list[str] = []
        if "table" in kinds:
            types.append("r")
        if "view" in kinds:
            types.append("v")
        if "materialized_view" in kinds:
            types.append("m")
        if "foreign_table" in kinds:
            types.append("f")
        if not types:
            return []
        sql = (
            "SELECT n.nspname, c.relname, c.relkind, "
            "CASE WHEN c.reltuples < 0 THEN NULL ELSE c.reltuples::bigint END "
            "FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
            "WHERE c.relkind = ANY(%s) AND n.nspname NOT LIKE 'pg_temp%%'"
        )
        params: list[Any] = [types]
        # System schemas are not data unless the administrator allowed them
        # (security.allowed_system_schemas lists information_schema by
        # default): the resolver permits only what is listed here.
        opened = self._opened_schemas()
        if hidden := [s for s in _PG_SYSTEM_SCHEMAS if s not in opened]:
            sql += " AND n.nspname <> ALL(%s)"
            params.append(hidden)
        if schema:
            sql += " AND n.nspname = %s"
            params.append(schema)
        if search:
            sql += " AND c.relname ILIKE %s"
            params.append(f"%{search}%")
        kind_map = {"r": "table", "v": "view", "m": "materialized_view", "f": "foreign_table"}
        with self._shared_meta_conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        tables = [
            TableSummary(
                schema=r[0],
                name=r[1],
                kind=kind_map.get(r[2], r[2]),
                row_estimate=int(r[3]) if r[3] else None,
                row_estimate_source="catalog_estimate(pg_class.reltuples)" if r[3] else None,
            )
            for r in rows
            if not is_session_sql_view(self.engine, r[0], r[1])
        ]
        return own_objects_first(tables, _PG_SYSTEM_SCHEMAS)

    def list_columns(self, schema: str | None, table: str) -> list[ColumnInfo]:
        schema = schema or "public"
        sql = (
            "SELECT column_name, data_type, is_nullable, column_default, ordinal_position, "
            "character_maximum_length, numeric_precision, numeric_scale "
            "FROM information_schema.columns WHERE table_schema = %s AND table_name = %s "
            "ORDER BY ordinal_position"
        )
        with self._shared_meta_conn() as conn:
            rows = conn.execute(sql, (schema, table)).fetchall()
        return [
            ColumnInfo(
                schema=schema,
                table=table,
                name=r[0],
                data_type=_pg_type(r[1], r[5], r[6], r[7]),
                nullable=r[2] == "YES",
                default=r[3],
                ordinal=r[4],
            )
            for r in rows
        ]

    def list_views(self, schema: str | None) -> list[ViewInfo]:
        sql = (
            "SELECT schemaname, viewname, definition FROM pg_catalog.pg_views"
            + (" WHERE schemaname = %s" if schema else "")
            + " ORDER BY 1, 2"
        )
        params: tuple[Any, ...] = (schema,) if schema else ()
        with self._shared_meta_conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [
            ViewInfo(schema=r[0], name=r[1], kind="view", definition=r[2], definition_state="available")
            for r in rows
            if not is_session_sql_view(self.engine, r[0], r[1])
        ]

    def list_synonyms(self, schema: str | None) -> list[SynonymInfo]:
        return []  # PostgreSQL has no synonyms.

    def list_routines(self, schema: str | None) -> list[RoutineInfo]:
        sql = (
            "SELECT n.nspname, p.proname, CASE WHEN p.prokind = 'p' THEN 'procedure' ELSE 'function' END "
            "FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "
            "WHERE n.nspname NOT IN ('pg_catalog','information_schema')"
            + (" AND n.nspname = %s" if schema else "")
            + " ORDER BY 1, 2"
        )
        # pg_proc.prokind is PostgreSQL 11+, while psycopg 3 supports servers
        # from 10. Without a fallback, db_list_routines is the single tool that
        # dies on an older server while everything else keeps working.
        legacy_sql = (
            "SELECT n.nspname, p.proname, CASE WHEN p.proisagg THEN 'aggregate' ELSE 'function' END "
            "FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "
            "WHERE n.nspname NOT IN ('pg_catalog','information_schema')"
            + (" AND n.nspname = %s" if schema else "")
            + " ORDER BY 1, 2"
        )
        params: tuple[Any, ...] = (schema,) if schema else ()
        with translated_driver_errors(), self._connect() as conn:
            try:
                rows = conn.execute(sql, params).fetchall()
            except Exception:  # noqa: BLE001 - pre-11 servers lack prokind
                rows = conn.execute(legacy_sql, params).fetchall()
        return [RoutineInfo(schema=r[0], name=r[1], kind=r[2]) for r in rows]

    def text_expression(self, quoted_column: str, portable_name: str, declared_type: str | None = None) -> str:
        return f"CAST({quoted_column} AS text)" if portable_name == "uuid" else quoted_column

    def placeholder(self, index: int) -> str:
        return "%s"

    def list_all_columns(self, schema: str | None) -> list[ColumnInfo]:
        schema = schema or "public"
        sql = (
            "SELECT table_name, column_name, data_type, is_nullable, column_default, ordinal_position, "
            "character_maximum_length, numeric_precision, numeric_scale "
            "FROM information_schema.columns WHERE table_schema = %s ORDER BY table_name, ordinal_position"
        )
        with self._shared_meta_conn() as conn:
            rows = conn.execute(sql, (schema,)).fetchall()
        return [
            ColumnInfo(schema=schema, table=r[0], name=r[1], data_type=_pg_type(r[2], r[6], r[7], r[8]),
                       nullable=r[3] == "YES", default=r[4], ordinal=r[5])
            for r in rows
        ]

    def list_indexes(self, schema: str | None, table: str | None) -> list[IndexInfo]:
        schema = schema or "public"
        sql = (
            "SELECT t.relname, i.relname, ix.indisunique, ix.indisprimary, a.attname, k.ord, am.amname, "
            "pg_catalog.pg_get_indexdef(ix.indexrelid) "
            "FROM pg_catalog.pg_index ix JOIN pg_catalog.pg_class t ON t.oid = ix.indrelid "
            "JOIN pg_catalog.pg_namespace n ON n.oid = t.relnamespace "
            "JOIN pg_catalog.pg_class i ON i.oid = ix.indexrelid JOIN pg_catalog.pg_am am ON am.oid = i.relam "
            "CROSS JOIN LATERAL unnest(ix.indkey) WITH ORDINALITY AS k(attnum, ord) "
            "LEFT JOIN pg_catalog.pg_attribute a ON a.attrelid = t.oid AND a.attnum = k.attnum "
            "WHERE n.nspname = %s"
        )
        params: list[Any] = [schema]
        if table:
            sql += " AND t.relname = %s"
            params.append(table)
        sql += " ORDER BY t.relname, i.relname, k.ord"
        with self._shared_meta_conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        grouped: dict[tuple[str, str], IndexInfo] = {}
        for tname, iname, unique, primary, col, _ord, am, definition in rows:
            info = grouped.get((tname, iname))
            if info is None:
                info = IndexInfo(name=iname, columns=[], unique=bool(unique), primary=bool(primary),
                                 kind=str(am), definition=definition, schema=schema, table=tname)
                grouped[(tname, iname)] = info
            info.columns.append(str(col) if col is not None else "(expression)")
        return list(grouped.values())

    def get_foreign_keys(self, schema: str | None, table: str | None) -> list[KeyInfo]:
        # Query the catalog directly with the schema/table as bound parameters:
        # the previous regclass::text rendering was search_path-dependent
        # (unqualified names for search_path schemas made ref_schema collapse
        # into the table name), ignored the schema argument entirely, and never
        # populated the FK column lists.
        sql = (
            "SELECT con.conname, ns.nspname, cl.relname, rns.nspname, rcl.relname, "
            "a.attname, ra.attname, k.ord "
            "FROM pg_catalog.pg_constraint con "
            "JOIN pg_catalog.pg_class cl ON cl.oid = con.conrelid "
            "JOIN pg_catalog.pg_namespace ns ON ns.oid = cl.relnamespace "
            "JOIN pg_catalog.pg_class rcl ON rcl.oid = con.confrelid "
            "JOIN pg_catalog.pg_namespace rns ON rns.oid = rcl.relnamespace "
            "CROSS JOIN LATERAL unnest(con.conkey, con.confkey) "
            "WITH ORDINALITY AS k(att, ratt, ord) "
            "JOIN pg_catalog.pg_attribute a ON a.attrelid = cl.oid AND a.attnum = k.att "
            "JOIN pg_catalog.pg_attribute ra ON ra.attrelid = rcl.oid AND ra.attnum = k.ratt "
            "WHERE con.contype = 'f'"
        )
        params: list[Any] = []
        if schema:
            sql += " AND ns.nspname = %s"
            params.append(schema)
        if table:
            sql += " AND cl.relname = %s"
            params.append(table)
        sql += " ORDER BY con.conname, k.ord"
        with self._shared_meta_conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        # Constraint names are unique per (namespace, table) only, so group by
        # the full constraint identity.
        grouped: dict[tuple[str, str, str, str, str], KeyInfo] = {}
        out: list[KeyInfo] = []
        for name, src_schema, src_table, ref_schema, ref_table, col, ref_col, _ord in rows:
            key = (str(name), str(src_schema), str(src_table), str(ref_schema), str(ref_table))
            info = grouped.get(key)
            if info is None:
                info = KeyInfo(
                    kind="foreign_key",
                    name=name,
                    columns=[],
                    ref_schema=ref_schema,
                    ref_table=ref_table,
                    ref_columns=[],
                    source_schema=src_schema,
                    source_table=src_table,
                )
                grouped[key] = info
                out.append(info)
            info.columns.append(col)
            info.ref_columns.append(ref_col)
        return out

    def get_statistics(self, schema: str | None, table: str) -> dict[str, Any]:
        schema = schema or "public"
        with self._shared_meta_conn() as conn:
            row = conn.execute(
                "SELECT CASE WHEN c.reltuples < 0 THEN NULL ELSE c.reltuples::bigint END, s.n_live_tup, s.last_analyze "
                "FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
                "LEFT JOIN pg_catalog.pg_stat_user_tables s ON s.relid = c.oid "
                "WHERE n.nspname = %s AND c.relname = %s",
                (schema, table),
            ).fetchone()
        if not row:
            return {"schema": schema, "table": table, "row_estimate": None, "row_estimate_source": "unavailable"}
        return {
            "schema": schema,
            "table": table,
            "row_estimate": int(row[0]) if row[0] is not None else None,
            "row_estimate_source": "catalog_estimate(pg_class.reltuples / pg_stat_user_tables)",
            "last_analyze": str(row[2]) if row[2] else None,
            "note": "estimates; freshness depends on the last ANALYZE",
        }

    # Common PostgreSQL type OIDs -> stable labels (driver-derived, not
    # data-derived).
    _PG_OID_TYPES = {
        16: "boolean",
        17: "blob",
        20: "bigint",
        21: "integer",
        23: "integer",
        25: "text",
        700: "real",
        701: "real",
        1700: "decimal",
        1082: "date",
        1083: "time",
        1114: "datetime",
        1184: "datetime",
        2950: "text",
        114: "text",
        3802: "text",
        1043: "text",
        1042: "text",
        18: "text",
    }

    def execute_query(self, spec: QuerySpec) -> QueryOutcome:
        with self._exec_state_lock:
            self._exec_waiters += 1
        try:
            self._exec_lock.acquire()
        finally:
            # The request is no longer queued once it holds the lock: from
            # here on a firing deadline belongs to THIS request, so it must
            # not suppress cancellation any more.
            with self._exec_state_lock:
                self._exec_waiters -= 1
        try:
            return self._execute(spec)
        finally:
            self._exec_lock.release()

    def _execute(self, spec: QuerySpec) -> QueryOutcome:
        start = time.monotonic()
        # psycopg's paramstyle is format/pyformat (%s / %(name)s); the guard
        # also admits :name markers, so rewrite those onto the driver's
        # spelling after validation. A bare '?' reaches the server untouched
        # (JSONB key-exists operator), so qmark is not translated here.
        # Raised before the ConnectorError boundary so a parameter-style
        # mismatch keeps its VALIDATION category.
        sql, parameters = spec.sql, spec.parameters
        if isinstance(parameters, dict):
            sql, parameters = translate_paramstyle(sql, parameters, backslash_escapes=False)
        args: Any = tuple(parameters) if isinstance(parameters, (list, tuple)) else parameters
        with translated_driver_errors():
            conn = self._connect()
        self._cancel_target = conn
        try:
            with translated_driver_errors(phase="execute"):
                # Server-side (named) cursor: rows stream from the engine and
                # the row/byte ceilings stop the transfer early. DECLARE plans
                # the statement and describes its columns; nothing runs before
                # the first FETCH, so the description decides whether the
                # values must be cut server-side first.
                with conn.cursor(name="udbmcp_query") as cur:
                    cur.execute(sql, args)
                    description = list(cur.description or [])
                    cols = [(d[0], self._PG_OID_TYPES.get(d.type_code, "unknown")) for d in description]
                    capped = _pg_capped_select(conn, sql, description, spec.max_cell_bytes, bound=args is not None)
                    if capped is None:
                        rows, cell_truncated_cols, truncated = self._stream(cur, cols, spec)
                if capped is not None:
                    rows, cell_truncated_cols, truncated = self._stream_capped(conn, capped, args, cols, spec)
            warnings: list[str] = []
            if truncated:
                warnings.append("result truncated by limits")
            if cell_truncated_cols:
                # A cell cut to the byte limit must never be reported as an
                # intact result: name the columns (live test 2026-09-11 found
                # this path reporting truncated=false after a silent cut).
                warnings.append(cell_truncation_warning(cell_truncated_cols, spec.max_cell_bytes))
            return QueryOutcome(
                columns=cols,
                rows=rows,
                truncated=truncated or bool(cell_truncated_cols),
                rows_seen=len(rows),
                elapsed_ms=int((time.monotonic() - start) * 1000),
                warnings=warnings,
            )
        finally:
            self._cancel_target = None
            try:
                conn.rollback()  # release the cursor's read transaction
            except Exception:  # noqa: BLE001, S110
                pass
            conn.close()

    def _stream_capped(
        self, conn: Any, capped: str, args: Any, cols: list[tuple[str, str]], spec: QuerySpec
    ) -> tuple[list[list[Any]], list[str], bool]:
        """Stream the value-capped rewrite of the statement. Fails closed: a
        rewrite the server refuses, or a cancel while it is declared, is the
        query's failure, never a reason to run the statement with its values
        uncut."""
        with conn.cursor(name="udbmcp_query") as cur:
            try:
                cur.execute(capped, args)
            except Exception as exc:
                if getattr(exc, "sqlstate", None) == "42601":
                    raise ConnectorError(
                        "the statement could not be run with its values cut to the cell limit on the server "
                        f"({scrub_exception(exc)})",
                        category="QUERY_ERROR",
                    ) from exc
                raise
            return self._stream(cur, cols, spec)

    def _stream(
        self, cur: Any, cols: list[tuple[str, str]], spec: QuerySpec
    ) -> tuple[list[list[Any]], list[str], bool]:
        """FETCH up to the row and byte ceilings, never more rows at a time
        than decide truncation. A truncated result sends no cancel: the
        server does no work between a named cursor's FETCHes, closing the
        cursor and the rollback end the statement, and psycopg's cancel()
        (PQcancel) holds the GIL until the host answers."""
        import json

        rows: list[list[Any]] = []
        cell_truncated_cols: list[str] = []
        approx_bytes = 0
        truncated = False
        while not truncated:
            batch = cur.fetchmany(next_fetch_size(spec.max_rows, len(rows)))
            if not batch:
                break
            for raw in batch:
                vals, _labels, cut = adapt_row(raw, spec.max_cell_bytes)
                cell_truncated_cols.extend(column_names_at(cols, cut))
                approx_bytes += len(json.dumps(vals, default=str).encode("utf-8"))
                if len(rows) >= spec.max_rows or approx_bytes > spec.max_response_bytes:
                    truncated = True
                    break
                rows.append(vals)
        return rows, cell_truncated_cols, truncated

    def explain(self, sql: str, analyze: bool) -> dict[str, Any]:
        if analyze:
            raise NotImplementedError(EXPLAIN_ANALYZE_UNSUPPORTED)
        with translated_driver_errors(), self._connect() as conn:
            rows = conn.execute("EXPLAIN " + sql).fetchall()
        return {"raw": "\n".join(r[0] for r in rows)}
