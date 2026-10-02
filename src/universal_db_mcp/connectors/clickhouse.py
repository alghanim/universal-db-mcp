"""ClickHouse connector (clickhouse-connect).

Implemented against the documented HTTP-native client APIs; live behaviors
marked ``unverified`` until Gate C proves them. TLS via explicit CA. Agent SQL
never carries settings (the guard refuses SETTINGS), and the per-query
settings this connector sends only ever tighten the account's own profile,
or hold how a statement is read at the defaults the guard parses under.
Results stream block by block under a byte budget on the response itself:
the row/byte ceilings stop the fetch and KILL the query instead of applying
after the whole response was buffered.
"""

from __future__ import annotations

import array
import functools
import importlib
import math
import re
import sys
import threading
import time
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import replace
from typing import Any, NoReturn

import sqlglot
from sqlglot import exp

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
    adapt_row,
    cell_truncation_warning,
    column_names_at,
    open_module,
    translated_driver_errors,
)
from universal_db_mcp.discovery.system_schemas import is_session_sql_view
from universal_db_mcp.models.capabilities import Cap, CapabilityMatrix, CapabilityState, Limitation
from universal_db_mcp.models.responses import ErrorCategory
from universal_db_mcp.security.policy import EffectivePolicy
from universal_db_mcp.security.redact import scrub_exception
from universal_db_mcp.security.sql_guard import bind_text, code_view, mask_pyformat_placeholders

# What one db_query may pull off the wire, in decoded bytes. The driver decodes
# a whole server block before the first of its rows reaches the row/byte
# ceilings, and max_block_size bounds only blocks read from a table: JOIN
# output (live 2026-09-27: a first block of 65417 rows, 785 MB), arrayJoin()
# and aggregate blocks arrive whole. At the budget the query is KILLed and the
# connection dropped, whatever the block.
# Decoding many short strings costs up to ~20x their wire size in Python
# objects, so the budget stays small (live: an arrayJoin() of 12-byte strings
# grew the process by 75 MB at 8 MiB, 113 MB at 16 MiB).
_STREAM_BUDGET_FACTOR = 4  # x max_response_bytes: Native rows run near their JSON size
_STREAM_BUDGET_FLOOR = 8 * 1024 * 1024  # room for wide rows whose cells are cut only after decoding
# What the driver may build in Python objects while it decodes one block,
# charged before each column read (_StreamBudget.admit): a value costs 1 to
# 112 bytes of objects per wire byte, so the wire budget alone let one
# 116-character statement (7.9M empty strings, 8 MB on the wire) grow the
# server by 190 MB (live, review round 4). A multiple of the stream budget:
# a readonly=1 profile (the documented account) takes no max_block_size, and
# one 65409-row block of the fixture's 9-column cdr table builds 28 MB.
_OBJECT_BUDGET_FACTOR = 4
# Rows per block for a table read, JOIN output blocks included. The floor
# keeps scans fast: on the 250k-row fixture (2026-09-27) filtered and
# aggregate scans took 13-50x the default time with 11-row blocks, 1.3-3x with
# 256 and 1x with 1024. A first block too wide for the stream budget is
# fetched again on blocks 1/32 the size, down to one row: rows of unknown
# width need a block sized from the budget, not from max_rows (a CROSS JOIN
# on 1-row blocks took 84 s, live, so the steps stay few).
_MIN_BLOCK_ROWS = 256
_MAX_BLOCK_ROWS = 1024
_BLOCK_NARROWING = 32
# ClickHouse evaluates scalar subqueries while planning, even under plain
# EXPLAIN: this is what planning may read before the EXPLAIN is refused.
_EXPLAIN_MAX_ROWS_TO_READ = 1000
_TOO_MANY_ROWS = 158  # ClickHouse error code for an exceeded max_rows_to_read
# Join reordering checks max_rows_to_read against its row estimates (26.3:
# a plain JOIN over 250k rows was refused, reading nothing).
_JOIN_ORDER = "query_plan_optimize_join_order_limit"
_TIMEOUT_EXCEEDED = 159  # max_execution_time
# READONLY, SETTING_CONSTRAINT_VIOLATION: the profile refused a per-query
# setting (a <min>/<max> constraint is not visible in system.settings.readonly)
_SETTING_REFUSED = (164, 452)
_READ_TIMEOUT_MARGIN_SECONDS = 5
# Settings that decide how the server reads a statement, held at the defaults
# the guard parses under wherever the account's profile sets another value:
# dialect reads the text as another language (prql, kusto, promql, polyglot),
# implicit_select runs a bare expression as a SELECT,
# prefer_column_name_to_alias binds a name the select list aliases to the
# table's column (live, 26.3: SELECT dummy + 1 AS dummy, dummy AS d gave
# d = 0, not 1), enable_global_with_statement=0 binds a subquery's name to
# the table where the guard reads the CTE of that name (live, 26.3: WITH
# subscribers AS (...) SELECT * FROM (SELECT * FROM subscribers) read
# telecom.subscribers; a profile's compatibility <= 21.x reports it 0), and
# analyzer_compatibility_join_using_top_level_identifier binds JOIN USING
# names to select-list aliases. The old analyzer (compatibility < 24.3, or
# enable_analyzer=0) reads that CTE either way (live). A server without one
# reads text the default way. String literals read the same everywhere
# (backslash escapes are always on).
_CH_READING_SETTINGS = {
    "dialect": "clickhouse",
    "implicit_select": "0",
    "prefer_column_name_to_alias": "0",
    "enable_global_with_statement": "1",
    "analyzer_compatibility_join_using_top_level_identifier": "0",
}
# The server's own databases (names are case-sensitive: both spellings exist).
_CH_SYSTEM_DATABASES = ("system", "INFORMATION_SCHEMA", "information_schema")
# clickhouse-connect sends a statement whose text ends in LIMIT 0 (its own
# comment regex applied, which keeps '#' comments) as a columns-only FORMAT
# JSON request, read whole into memory outside the stream budget, the
# row/byte ceilings and KILL: a UNION whose last branch ends in LIMIT 0, or a
# '# LIMIT 0' comment, downloaded everything before it (p03L-2). A bound
# value at the end can be that 0.
_COLUMNS_ONLY = re.compile(r"LIMIT\s+(?:0|%s|%\(\w+\)s)\s*(?:;\s*)*$", re.IGNORECASE)
_OWN_LIMIT_0 = re.compile(r"\bLIMIT\s+0[\s;]*$", re.IGNORECASE)
# A '#!' comment that ends in a quoted string: the server skips it to the end
# of the text, while the driver's comment regex keeps the string, so the text
# no longer ends in LIMIT 0 for the driver and streams like any other.
_NO_COLUMNS_PROBE = "\n#!''"


def _server_setting(client: Any, name: str) -> tuple[str, bool]:
    """``(value, changeable)`` of one setting as the account's server profile
    reports it (system.settings, read by the driver at connect). A setting
    the profile does not list reads as ``('', True)``."""
    server = getattr(client, "server_settings", None) or {}
    setting = server.get(name)
    if setting is None:
        return "", True
    return str(getattr(setting, "value", setting)).strip(), not getattr(setting, "readonly", 0)


def _tightens(client: Any, name: str, value: int) -> bool:
    """True when sending ``value`` for the numeric ceiling ``name`` cannot
    relax the profile's own: changeable, and unset (0) or larger."""
    current, changeable = _server_setting(client, name)
    if not changeable:
        return False
    try:
        profile = int(current or 0)
    except ValueError:
        return False
    return profile == 0 or value < profile


def _is_off(value: str) -> bool:
    return value.lower() in ("", "0", "false")


def _server_error_code(exc: BaseException | None) -> int | None:
    """The ClickHouse error code of a driver exception: its ``code``
    attribute, else the 'code: N' text of the server response."""
    code = getattr(exc, "code", None)
    if isinstance(code, int):
        return code
    match = re.search(r"\bcode: (\d+)", str(exc or ""), re.IGNORECASE)
    return int(match.group(1)) if match else None


@contextmanager
def _statement_errors() -> Iterator[None]:
    """A failure ClickHouse reports with an error code is the statement's:
    QUERY_ERROR, or TIMEOUT at its time limit. A failed request carries no
    code and passes through to translated_driver_errors, a connection error."""
    try:
        yield
    except ConnectorError:
        raise
    except Exception as exc:  # noqa: BLE001 - deliberately broad: driver boundary
        code = _server_error_code(exc)
        if code is None:
            raise
        text = scrub_exception(exc)
        if code == _TIMEOUT_EXCEEDED:
            raise ConnectorError(
                f"the statement exceeded its time limit and the database cancelled it ({text})",
                category=ErrorCategory.TIMEOUT,
            ) from exc
        raise ConnectorError(text, category=ErrorCategory.QUERY) from exc


def _driver_module(name: str) -> Any:
    """A clickhouse-connect module; None without the driver."""
    try:
        return importlib.import_module(name)
    except ImportError:
        return None


def _server_bound(sql: str, params: Any) -> bool:
    """Whether the driver sends ``params`` as server-side parameters (a
    mapping, and a {name:Type} placeholder in the text, as its own regex
    finds one): it formats nothing into the text then."""
    binding = _driver_module("clickhouse_connect.driver.binding")
    pattern = getattr(binding, "external_bind_re", None)
    return isinstance(params, dict) and pattern is not None and pattern.search(sql) is not None


def _returns_no_rows(sql: str) -> bool:
    """Whether the statement is one SELECT whose own top-level LIMIT 0 ends
    its code: the driver's columns-only request then reads a header."""
    if not _OWN_LIMIT_0.search(code_view(sql, "clickhouse").rstrip()):
        return False
    try:
        tree = sqlglot.parse_one(mask_pyformat_placeholders(sql), read="clickhouse")
    except Exception:  # noqa: BLE001 - sqlglot's errors, and whatever else a parser raises
        return False
    limit = tree.args.get("limit") if isinstance(tree, exp.Select) else None
    value = limit.args.get("expression") if isinstance(limit, exp.Limit) else None
    return isinstance(value, exp.Literal) and value.this == "0" and not tree.args.get("offset")


def _streamed(sql: str, *, probe_ok: bool) -> str:
    """``sql`` as the driver must receive it to stream it (_COLUMNS_ONLY):
    unchanged unless the driver would send a columns-only request for it,
    and ``probe_ok`` and the statement really returns no rows."""
    query = _driver_module("clickhouse_connect.driver.query")
    remove_comments = getattr(query, "remove_sql_comments", None)
    uncommented = str(remove_comments(sql)) if callable(remove_comments) else sql
    if not _COLUMNS_ONLY.search(uncommented) or (probe_ok and _returns_no_rows(sql)):
        return sql
    return re.sub(r"[\s;]*\Z", "", sql) + _NO_COLUMNS_PROBE


def _driver_sql(sql: str, params: Any) -> str:
    """The text the driver gets for ``sql`` with ``params``. Bound
    client-side, the driver %-formats the values into the whole text, string
    literals and comments included, after the guard validated it: bind_text
    doubles every '%' that is not a placeholder in code and refuses
    placeholders that do not match the values (p03L-1)."""
    if params and not _server_bound(sql, params):
        sql = bind_text(sql, params, engine="clickhouse")
    return _streamed(sql, probe_ok=True)


class _StreamBudgetExceeded(Exception):
    """The response passed the stream budget; the query is KILLed already."""


class _BlockTooWide(ConnectorError):
    """The first block alone passed the stream budget, and the fetch can run
    again on blocks of ``block`` rows."""

    def __init__(self, block: int) -> None:
        super().__init__("first block over the stream budget")
        self.block = block


class _PlanningReadLimit(ConnectorError):
    """Planning an EXPLAIN hit its read ceiling (ClickHouse code 158)."""

    def __init__(self, ceiling: int | None) -> None:
        super().__init__("EXPLAIN planning exceeded max_rows_to_read")
        self.ceiling = ceiling


class _StreamBudget:
    """Counts the decoded response bytes of one query and stops the read at
    the budget, before the driver finishes decoding the block being read.

    clickhouse-connect 1.8 builds its byte buffer over ``source.gen`` of the
    ResponseSource its backend's ``execute_query`` returns, so the meter goes
    there. The query client reads uncompressed (``_connect``), so each chunk
    is at most the driver's 1 MiB read size (its read-ahead, 10 MiB by
    default, comes on top).
    """

    def __init__(self, budget: int, on_exceeded: Callable[[], object]) -> None:
        self.budget = budget
        self.object_budget = _OBJECT_BUDGET_FACTOR * budget
        self.exceeded = False
        self.objects_exceeded = False  # the block's objects, not its wire bytes, stopped the read
        self._on_exceeded = on_exceeded
        self._consumed = 0
        self._last_chunk = 0
        self._objects = 0  # charged for the block being decoded
        self._response: Any = None

    @staticmethod
    def seam(client: Any) -> Any:
        """The backend whose ``execute_query`` the meter wraps; None when this
        driver has no such seam."""
        backend = getattr(client, "_backend", None)
        return backend if callable(getattr(backend, "execute_query", None)) else None

    def install(self, client: Any) -> bool:
        """Meter the client's responses. False when the seam is missing: then
        a result block is decoded whole before the row/byte ceilings see it,
        and the caller says so."""
        backend = self.seam(client)
        if backend is None:
            return False
        execute = backend.execute_query

        def execute_query(*args: Any, **kwargs: Any) -> Any:
            execution = execute(*args, **kwargs)
            source = getattr(execution, "source", None)
            if source is not None and hasattr(source, "gen"):
                self._response = getattr(source, "response", None)
                source.gen = self._metered(source.gen)
                source.udbmcp_budget = self  # what the guarded response buffer asks (_guard_column_reads)
            return execution

        backend.execute_query = execute_query
        return True

    def _metered(self, chunks: Iterator[bytes]) -> Iterator[bytes]:
        for chunk in chunks:
            self._consumed += len(chunk)
            self._last_chunk = len(chunk)
            if self._consumed > self.budget:
                self._stop()
            yield chunk

    def _stop(self) -> NoReturn:
        self.exceeded = True
        self._on_exceeded()
        self.drop()
        raise _StreamBudgetExceeded

    def admit(self, wire_bytes: int, objects: int = 0) -> None:
        """Stop before the driver allocates for a column read that takes at
        least ``wire_bytes`` off the wire, when the budget cannot let that
        many arrive: what it still allows plus the chunk already buffered
        (the driver's buffer holds at most the last chunk unread). Such a
        read would pass the budget anyway, after the allocation. Stop as
        well when the ``objects`` bytes the read builds would take the
        block's objects past the object budget."""
        self._objects += objects
        if self._objects > self.object_budget:
            self.objects_exceeded = True
            self._stop()
        if wire_bytes > self.budget - self._consumed + self._last_chunk:
            self._stop()

    def next_block(self) -> None:
        """The block decoded last was handed over: what the driver builds
        from here on belongs to the next one."""
        self._objects = 0

    def drop(self) -> None:
        """Close the connection without reading the rest of the response: the
        driver's close drains it first, in one unbounded read."""
        if self._response is None:
            return
        try:
            self._response.close()
        except Exception:  # noqa: BLE001, S110 - the client is closed right after
            pass


# clickhouse-connect allocates for the element count a block declares before
# it reads one element: 8 bytes a String, 43 a UUID, a whole offsets array for
# each level of Array(Array(...)). A 110-character statement grew the server
# by 398 MB behind an 8-byte offset (arrayMap/splitByChar/repeat, live), so
# the byte meter alone is too late. What the read builds counts as well: the
# Python objects of a value weigh 1 to 112 times its wire bytes.


@functools.cache
def _item_size(array_type: str) -> int:
    return array.array(array_type).itemsize


# Bytes of Python objects per decoded value (CPython 3.12, 64-bit): the slot
# of the list that holds it, and the object when one is built for it.
_SLOT = 8
_NUMBER = _SLOT + 36  # an int or float taken out of a compact array
_STR = _SLOT + 41  # an empty str; its characters are counted on the wire
_LIST = _SLOT + 56  # an Array row, built for each entry of its offsets
_DICT = _SLOT + 224  # a Map row, likewise
# The least each of the driver's C column readers takes off the wire, and
# what it builds: ``(wire bytes, object bytes)``.
_DATA_CONV_READS: dict[str, Callable[..., tuple[int, int]]] = {
    "read_date_col": lambda num_rows, *_a: (2 * num_rows, num_rows * (_SLOT + 32)),
    "read_date32_col": lambda num_rows, *_a: (4 * num_rows, num_rows * (_SLOT + 32)),
    "read_datetime_col": lambda num_rows, *_a: (4 * num_rows, num_rows * (_SLOT + 48)),
    "read_ipv4_col": lambda num_rows, *_a: (4 * num_rows, num_rows * (_SLOT + 56 + 28)),
    "read_uuid_col": lambda num_rows, *_a: (16 * num_rows, num_rows * (_SLOT + 64 + 44)),
    "read_nullable_array": lambda array_type, num_rows, *_a: (
        num_rows * (1 + _item_size(array_type)),
        num_rows * _NUMBER,
    ),
}
# What a type's own Python code builds per value on top of the readers above,
# found by the first class of its MRO listed here; any other type is charged
# _OTHER. A compact numeric array (ArrayType) builds nothing until a container
# takes its values out.
_BUILT_BY_TYPE: dict[str, int] = {
    "Decimal": _SLOT + 104,
    "BigInt": _SLOT + 60,
    "IPv6": _SLOT + 64 + 44,
    "DateTime64": _SLOT + 48,
    "TimeBase": _SLOT + 48,
    "BFloat16": _SLOT + 24,
    "Bool": _SLOT,
    "Enum": _SLOT,
    "String": 0,
    "FixedString": 0,
    "Date": 0,
    "DateTime": 0,
    "IPv4": 0,
    "UUID": 0,
    "ArrayType": 0,
    "Array": 0,  # its rows are charged with its offsets (_LIST)
    "Map": 0,
    "Nested": 0,
}
_OTHER = _SLOT + 56
# Types that hand their whole read to another type: what they contain is not
# taken out of them.
_DELEGATING = frozenset({"Point", "Ring", "Polygon", "MultiPolygon", "SimpleAggregateFunction"})
_READ_GUARD_LOCK = threading.Lock()
_read_guarded: bool | None = None  # decided once per process (_guard_column_reads)


def _admit(source: Any, wire_bytes: int, objects: int = 0) -> None:
    budget = getattr(source, "_udbmcp_budget", None)
    if budget is not None:
        budget.admit(wire_bytes, objects)


def _class_names(ch_type: Any) -> list[str]:
    return [cls.__name__ for cls in type(ch_type).__mro__]


def _built_per_value(ch_type: Any, container: Any) -> int:
    """The object bytes one value of ``ch_type`` costs beyond what the
    driver's C readers charge themselves, read inside ``container`` (the
    type whose read takes its values out: a slot there each, and an object
    for each value of a compact array), or at the top level (None)."""
    kind = next((name for name in _class_names(ch_type) if name in _BUILT_BY_TYPE or name == "Tuple"), None)
    cost = _SLOT if container is not None else 0
    low_card, nullable = getattr(ch_type, "low_card", False), getattr(ch_type, "nullable", False)
    if kind == "ArrayType":
        if low_card:
            return cost + _NUMBER  # [index[key] for key in keys]: an int each
        return cost + (_NUMBER if container is not None and not nullable else 0)
    if low_card:
        return cost + _SLOT
    if nullable:
        cost += _SLOT  # the column is copied once with its NULLs in
    if kind == "Tuple":
        width = len(getattr(ch_type, "element_types", ()))
        named = bool(getattr(ch_type, "element_names", ()))  # read as a dict, not a tuple
        return cost + _SLOT + (_container_size(width, named) if width else 0)
    return cost + (_OTHER if kind is None else _BUILT_BY_TYPE[kind])


@functools.cache
def _container_size(width: int, named: bool) -> int:
    return sys.getsizeof(dict.fromkeys(range(width)) if named else tuple(range(width)))


def _guard_column_reads() -> bool:
    """Make every column read of a budgeted stream ask the query's stream
    budget first (``_StreamBudget.admit``), once per process: the driver's
    response buffer class is swapped for a subclass, its C column readers
    that take the buffer are wrapped, and so is each data type's
    ``read_column_data``, which knows what the values become. A stream
    without a budget (a metadata client) reads exactly as before. False when
    this clickhouse-connect has no such seam."""
    global _read_guarded
    with _READ_GUARD_LOCK:
        if _read_guarded is None:
            _read_guarded = _install_read_guard()
        return _read_guarded


def _install_read_guard() -> bool:
    try:
        from clickhouse_connect.datatypes.base import ClickHouseType
        from clickhouse_connect.driver import _backendclient
        from clickhouse_connect.driver import ctypes as driver_ctypes
    except ImportError:
        return False
    buffer_type = getattr(_backendclient, "RespBuffCls", None)
    data_conv = getattr(driver_ctypes, "data_conv", None)
    if not isinstance(buffer_type, type) or data_conv is None:
        return False

    class _AdmittingBuffer(buffer_type):  # type: ignore[misc, valid-type]
        def __init__(self, source: Any) -> None:
            super().__init__(source)
            self._udbmcp_budget = getattr(source, "udbmcp_budget", None)
            self._udbmcp_reading: Any = None  # the data type whose read is under way

        def read_array(self, array_type: str, num: int) -> Any:
            if self._udbmcp_budget is not None:
                # read by an Array or a Map itself: its offsets, a row each
                names = _class_names(self._udbmcp_reading)
                rows = _LIST if "Array" in names else _DICT if "Map" in names else 0
                self._udbmcp_budget.admit(num * _item_size(array_type), num * rows)
            return super().read_array(array_type, num)

        def read_bytes(self, sz: int) -> Any:
            _admit(self, sz)
            return super().read_bytes(sz)

        def read_str_col(self, num_rows: int, *args: Any, **kwargs: Any) -> Any:
            _admit(self, num_rows, num_rows * _STR)  # a length byte each at least
            return super().read_str_col(num_rows, *args, **kwargs)

        def read_fixed_str_col(self, size: int, num_rows: int, *args: Any, **kwargs: Any) -> Any:
            _admit(self, size * num_rows, num_rows * _STR)
            return super().read_fixed_str_col(size, num_rows, *args, **kwargs)

        def read_bytes_col(self, size: int, num_rows: int, *args: Any, **kwargs: Any) -> Any:
            _admit(self, size * num_rows, num_rows * (_SLOT + 33))
            return super().read_bytes_col(size, num_rows, *args, **kwargs)

    for name, costs in _DATA_CONV_READS.items():
        read = getattr(data_conv, name, None)
        if callable(read):
            setattr(data_conv, name, _admitting(read, costs))
    pending: list[type] = [ClickHouseType]
    while pending:
        cls = pending.pop()
        pending.extend(cls.__subclasses__())
        if "read_column_data" in vars(cls):
            cls.read_column_data = _decoding(cls.read_column_data)  # type: ignore[attr-defined]
    _backendclient.RespBuffCls = _AdmittingBuffer  # type: ignore[attr-defined]
    return True


def _admitting(read: Callable[..., Any], costs: Callable[..., tuple[int, int]]) -> Callable[..., Any]:
    """A C column reader that asks the stream budget of its buffer first."""

    @functools.wraps(read)
    def admitted(source: Any, *args: Any) -> Any:
        _admit(source, *costs(*args))
        return read(source, *args)

    return admitted


def _decoding(read: Callable[..., Any]) -> Callable[..., Any]:
    """A data type's ``read_column_data`` that charges what its values
    become before it reads them, and tells the reads inside it whose they
    are."""

    @functools.wraps(read)
    def read_column_data(self: Any, source: Any, num_rows: int, ctx: Any, read_state: Any) -> Any:
        if getattr(source, "_udbmcp_budget", None) is None:
            return read(self, source, num_rows, ctx, read_state)
        container = source._udbmcp_reading
        _admit(source, 0, num_rows * _built_per_value(self, container))
        source._udbmcp_reading = container if _DELEGATING.intersection(_class_names(self)) else self
        try:
            return read(self, source, num_rows, ctx, read_state)
        finally:
            source._udbmcp_reading = container

    return read_column_data


def _split_key_expressions(key: str) -> list[str]:
    """Split a ClickHouse sorting/primary key on top-level commas only:
    "toYYYYMM(ts), tuple(a, b), id" -> 3 expressions, not 4."""
    out: list[str] = []
    depth = 0
    cur: list[str] = []
    for ch in key:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth = max(0, depth - 1)
        if ch == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    tail = "".join(cur).strip()
    if tail:
        out.append(tail)
    return [c for c in out if c]


class ClickHouseConnector(DatabaseConnector):
    engine = "clickhouse"

    def __init__(self, connection: ResolvedConnection, policy: EffectivePolicy) -> None:
        super().__init__(connection, policy)
        self._module: Any = None
        self._cancel_query_id: str | None = None  # query_id of the executing query
        self._cancel_event: threading.Event | None = None  # polled by the executing fetch loop
        self._exec_lock = threading.Lock()  # serializes queries: cancel slot correctness
        self._pool_lock = threading.Lock()
        self._meta_client: Any = None  # reused metadata client (probe on checkout)
        self._ceilings_refused: str | None = None  # why the profile refused the per-query ceilings

    def _session_settings(self) -> dict[str, Any]:
        prof = self.session_profile
        self._session_reset()
        settings: dict[str, Any] = {}
        if prof.enforce_read_only:
            settings["readonly"] = 1  # applied/skipped is decided against the server profile
        if prof.statement_timeout_seconds:
            settings["max_execution_time"] = int(math.ceil(prof.statement_timeout_seconds))
            self._session_applied(f"max_execution_time={settings['max_execution_time']}s")
        return settings

    def _session_readback(self, client: Any) -> dict[str, Any]:
        try:
            row = client.query("SELECT getSetting('readonly'), getSetting('max_execution_time')").result_rows
        except Exception:  # noqa: BLE001 - reporting only
            return {}
        if not row or len(row[0]) < 2:
            return {}
        return {"readonly": str(row[0][0]), "max_execution_time": str(row[0][1])}

    def _shared_meta_client(self) -> Any:
        """Lock-guarded reusable metadata client with probe-on-checkout
        (spec §7 connection pooling; one client per connector)."""
        with self._pool_lock:
            if self._meta_client is not None:
                try:
                    self._meta_client.query("SELECT 1")
                    return self._meta_client
                except Exception:  # noqa: BLE001, S110 - stale client, rebuild
                    self._discard_meta_client()
            self._meta_client = self._connect()
            return self._meta_client

    def _discard_meta_client(self) -> None:
        """Close and forget the shared metadata client (caller holds
        ``_pool_lock``). Close errors are irrelevant: the object is dropped."""
        client, self._meta_client = self._meta_client, None
        if client is not None:
            try:
                client.close()
            except Exception:  # noqa: BLE001, S110
                pass

    def close(self) -> None:
        with self._pool_lock:
            self._discard_meta_client()

    def _connect(self, *, uncompressed: bool = False) -> Any:
        self._module = open_module(
            "clickhouse_connect",
            "clickhouse-connect (wheel from the bundle wheelhouse)",
        )
        cfg = self.connection.config
        kw: dict[str, Any] = {
            "host": cfg.host,
            "port": cfg.port or (8443 if cfg.tls.enabled else 8123),
            "database": cfg.database,
            "connect_timeout": max(1, math.ceil(cfg.connect_timeout_seconds)),
            # Socket read bound (the driver default is 300 s): a response that
            # stalls past the policy's hard query ceiling is dead, not slow.
            "send_receive_timeout": math.ceil(self.policy.hard_query_timeout_seconds) + _READ_TIMEOUT_MARGIN_SECONDS,
            # The driver appends "LIMIT <query_limit>" only to SELECT-looking
            # text with no LIMIT anywhere in it, so this is a backstop for the
            # catalog queries, not a ceiling. db_query and EXPLAIN switch it
            # off and bound the result themselves (_execute, _explain).
            "query_limit": self.policy.hard_max_rows,
            # Session safety profile, applied to EVERY request this client
            # sends: readonly=1 makes the server refuse writes and any
            # SETTINGS override inside agent SQL; max_execution_time is the
            # policy ceiling server-side. client_name is what shows up in
            # system.query_log / system.processes.
            "client_name": self.session_profile.application_name,
        }
        if uncompressed:
            # An LZ4/zstd frame holds a whole server block, and the driver
            # decompresses it in one call (live 2026-09-27: one 785 MB chunk)
            # before the stream budget could count a byte of it.
            kw["compress"] = False
        wanted = self._session_settings()
        if self.connection.username:
            kw["username"] = self.connection.username.value
        if self.connection.password:
            kw["password"] = self.connection.password.value
        if cfg.tls.enabled:
            kw["secure"] = True
            kw["verify"] = bool(cfg.tls.verify_server)
            kw["ca_cert"] = cfg.tls.ca_file
            if cfg.tls.client_cert_file:
                kw["client_cert"] = cfg.tls.client_cert_file
                if self.connection.password:
                    # clickhouse-connect skips Basic auth entirely when a client
                    # certificate is present and tls_mode is unset (mutual-TLS
                    # branch), so a configured password would never be sent.
                    # Asking for 'strict' keeps the certificate for transport
                    # and still sends the credentials.
                    kw["tls_mode"] = "strict"
            if cfg.tls.client_key_file:
                kw["client_cert_key"] = cfg.tls.client_key_file
        client = self._module.get_client(**kw)
        self._apply_session_settings(client, wanted)
        self._hold_reading_settings(client)
        if _StreamBudget.seam(client) is None:
            self._session_skipped(
                "stream byte budget",
                RuntimeError("this clickhouse-connect has no backend execute_query seam to meter"),
            )
        return client

    def _apply_session_settings(self, client: Any, wanted: dict[str, Any]) -> None:
        """Pin the session profile on the client AFTER looking at the server
        profile the account already carries.

        readonly=1 forbids changing any setting and readonly=2 forbids
        changing readonly itself, so sending our own readonly=1 to such an
        account would fail every query. A profile that is already read-only
        is stronger than ours: keep it and report it verbatim.
        """
        ro_value = _server_setting(client, "readonly")[0]
        for name, value in wanted.items():
            if name == "readonly" and ro_value not in ("", "0"):
                self._session_applied(f"read_only (server profile readonly={ro_value})")
                continue
            if name == "readonly":
                try:
                    client.set_client_setting(name, value)
                    self._session_applied("read_only")
                except Exception as exc:  # noqa: BLE001 - the promise did not take: fail closed
                    raise self._session_required("read-only mode", exc) from exc
                continue
            if name != "readonly" and ro_value == "1":
                # readonly=1 rejects every SET; the server's own ceilings apply
                self._session_skipped(name, RuntimeError(f"server profile readonly={ro_value} rejects SET"))
                continue
            try:
                client.set_client_setting(name, value)
            except Exception as exc:  # noqa: BLE001 - reported, and fail-closed below
                self._session_skipped(name, exc)
        if ro_value == "1":
            # The same refusal reaches db_query's per-query result ceilings
            # (_result_ceilings): the fetch is bounded by streaming and KILL
            # QUERY alone on this account.
            self._session_skipped(
                "per-query result ceilings",
                RuntimeError("server profile readonly=1 rejects SET; streamed and KILLed at the ceiling"),
            )
        elif self._ceilings_refused:
            self._session_skipped("per-query result ceilings", RuntimeError(self._ceilings_refused))

    def _hold_reading_settings(self, client: Any) -> None:
        """Send _CH_READING_SETTINGS with every request where the account's
        profile sets another value. A profile that does not let one be
        changed (readonly=1, a constraint), or a driver that drops it, fails
        the connection: the server would not read statements as the guard
        did."""
        for name, default in _CH_READING_SETTINGS.items():
            current, changeable = _server_setting(client, name)
            if not current or current.lower() == default:
                continue
            if default in ("0", "1") and _is_off(current) == _is_off(default):  # a boolean, spelled another way
                continue
            try:
                if not changeable:
                    raise RuntimeError(f"the account's profile sets {name}={current} and does not allow changing it")
                client.set_client_setting(name, default)
                if client.get_client_setting(name) != default:
                    raise RuntimeError(f"the driver did not keep {name} for its requests")
            except Exception as exc:  # noqa: BLE001
                raise self._reading_required(f"{name}={default}", exc) from exc
            self._session_applied(f"{name}={default}")

    def cancel_current(self) -> bool:
        """Best-effort server-side cancel via ``KILL QUERY`` on a separate
        short-lived client.

        clickhouse-connect 1.8.0 exposes no client-side handle (and no
        ``cancel_query`` method) for an in-flight HTTP request, so ``_execute``
        pins a generated ``query_id`` on the executing client and the deadline
        hook kills that exact query out of band. Returns False — cancelling
        nothing — when no query is executing or the KILL itself fails; it
        never guesses. The executing fetch loop is flagged as well, so a
        worker the executor abandoned stops reading at its next row.
        """
        event = self._cancel_event
        if event is not None:
            event.set()
        return self._kill_current()

    def _kill_current(self) -> bool:
        """``KILL QUERY`` the pinned query_id; False when nothing is pinned or
        the KILL failed."""
        qid = self._cancel_query_id
        if qid is None:
            return False
        try:
            killer = self._connect()
        except Exception:  # noqa: BLE001 - cancel must never raise
            return False
        try:
            killer.command("KILL QUERY WHERE query_id = %(qid)s", parameters={"qid": qid})
            return True
        except Exception:  # noqa: BLE001 - best effort; the executor still discards
            return False
        finally:
            try:
                killer.close()
            except Exception:  # noqa: BLE001, S110
                pass

    def capabilities(self) -> CapabilityMatrix:
        return CapabilityMatrix(
            engine="clickhouse",
            engine_family="clickhouse",
            driver="clickhouse-connect",
            capabilities={
                Cap.CONNECT: CapabilityState.UNVERIFIED,
                Cap.HEALTH: CapabilityState.UNVERIFIED,
                Cap.LIST_SCHEMAS: CapabilityState.UNVERIFIED,
                Cap.LIST_TABLES: CapabilityState.UNVERIFIED,
                Cap.GET_TABLE: CapabilityState.UNVERIFIED,
                Cap.LIST_COLUMNS: CapabilityState.UNVERIFIED,
                Cap.LIST_VIEWS: CapabilityState.UNVERIFIED,
                Cap.LIST_SYNONYMS: CapabilityState.UNSUPPORTED,
                Cap.LIST_ROUTINES: CapabilityState.UNSUPPORTED,
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
                Limitation(scope="explain", detail=f"{EXPLAIN_ANALYZE_UNSUPPORTED}."),
                Limitation(
                    scope="explain",
                    detail="ClickHouse evaluates scalar and IN subqueries while planning, even under "
                    "plain EXPLAIN, including those inside a view's definition. Where the account "
                    f"profile accepts per-query settings, every EXPLAIN is planned under a "
                    f"{_EXPLAIN_MAX_ROWS_TO_READ}-row read ceiling (or the profile's own lower "
                    "max_rows_to_read), which ClickHouse checks against its row estimate for the tables "
                    "a subquery reads: such a statement over more rows is refused (run it with db_query "
                    "instead). Join reordering checks that ceiling against its estimates too, so a JOIN "
                    "refused that way is planned again with query_plan_optimize_join_order_limit=0 and "
                    "comes back in its written order, with a warning. On a readonly=1 profile, or one "
                    "that refuses the ceiling, the plan comes back with a warning that planning may have "
                    "read table data.",
                ),
                Limitation(
                    scope="metadata",
                    detail="ClickHouse dictionaries/projections are not surfaced in v1.",
                ),
                Limitation(
                    scope="column_types",
                    detail="Column type labels are derived from the first returned row "
                    "when the driver does not expose per-column types on streaming "
                    "results; treat them as hints, not guarantees.",
                ),
            ],
            required_privileges=["SELECT on permitted databases/tables (read-only profile)"],
            unverified_items=[
                "KILL QUERY cancellation by query_id over native transport",
                "TLS verify with internal CA",
            ],
        )

    def health_check(self) -> HealthInfo:
        start = time.monotonic()
        try:
            client = self._connect()
            row = client.query("SELECT version()").result_rows
            session = self.session_report(self._session_readback(client))
            return HealthInfo(
                healthy=True,
                server_version=str(row[0][0]) if row else None,
                latency_ms=int((time.monotonic() - start) * 1000),
                session=session,
            )
        except Exception as exc:  # noqa: BLE001, S110
            return HealthInfo(healthy=False, detail=scrub_exception(exc)[:300])

    def list_schemas(self, catalog: str | None, search: str | None) -> list[str]:
        sql = "SELECT name FROM system.databases"
        params: dict[str, Any] = {}
        if search:
            sql += " WHERE name ILIKE %(s)s"
            params["s"] = f"%{search}%"
        sql += " ORDER BY name"
        with translated_driver_errors():
            client = self._shared_meta_client()
            return [r[0] for r in client.query(sql, parameters=params).result_rows]

    def list_tables(self, schema: str | None, kinds: set[str], search: str | None) -> list[TableSummary]:
        conds: list[str] = []
        # System databases are not data unless the administrator allowed them
        # (security.allowed_system_schemas lists information_schema by
        # default): the resolver permits only what is listed here.
        opened = self._opened_schemas()
        if hidden := [db for db in _CH_SYSTEM_DATABASES if db.lower() not in opened]:
            conds.append("database NOT IN (" + ", ".join(f"'{db}'" for db in hidden) + ")")
        params: dict[str, Any] = {}
        if schema:
            conds.append("database = %(db)s")
            params["db"] = schema
        if search:
            conds.append("name ILIKE %(s)s")
            params["s"] = f"%{search}%"
        sql = (
            "SELECT database, name, engine, total_rows FROM system.tables"
            + (" WHERE " + " AND ".join(conds) if conds else "")
            + " ORDER BY database, name"
        )
        with translated_driver_errors():
            client = self._shared_meta_client()
            rows = client.query(sql, parameters=params).result_rows
        out = []
        for db, name, eng, total in rows:
            kind = "view" if str(eng).lower().startswith("view") else "table"
            if kind not in kinds or is_session_sql_view(self.engine, db, name):
                continue
            out.append(
                TableSummary(
                    schema=db,
                    name=name,
                    kind=kind,
                    row_estimate=int(total) if total is not None else None,
                    row_estimate_source="catalog_estimate(system.tables.total_rows)" if total is not None else None,
                )
            )
        return own_objects_first(out, _CH_SYSTEM_DATABASES)

    def list_columns(self, schema: str | None, table: str) -> list[ColumnInfo]:
        with translated_driver_errors():
            client = self._shared_meta_client()
            rows = client.query(
                "SELECT name, type, is_in_primary_key, comment "
                "FROM system.columns WHERE database = %(db)s AND table = %(t)s "
                "ORDER BY position",
                parameters={"db": schema or self.connection.config.database, "t": table},
            ).result_rows
        return [
            ColumnInfo(
                schema=schema,
                table=table,
                name=r[0],
                data_type=r[1],
                # ClickHouse marks nullable columns as Nullable(T) (and
                # Nullable(Nothing) for the untyped NULL); everything else is
                # NOT NULL. The previous negation reported exactly the inverse.
                nullable=str(r[1]).startswith("Nullable("),
                comment=r[3] or None,
                ordinal=i,
            )
            for i, r in enumerate(rows)
        ]

    def length_expression(self, quoted_column: str) -> str:
        return f"lengthUTF8({quoted_column})"

    def substring_expression(self, quoted_column: str, chars: int) -> str:
        return f"substringUTF8({quoted_column}, 1, {int(chars)})"

    def escape_like(self, needle: str) -> str:
        # ClickHouse LIKE has no ESCAPE clause; backslash is its (only) escape
        return needle.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

    def like_predicate(self, expression: str, placeholder: str) -> str:
        return f"{expression} LIKE {placeholder}"

    def quote_identifier(self, name: str) -> str:
        # ClickHouse reads a backslash inside a quoted identifier as an escape,
        # so the inherited ANSI doubling let a catalog name ending in '\' close
        # the identifier early and the rest parse as SQL. Backslash first, then
        # backtick: the order clickhouse-connect's own _format_identifier uses.
        return "`" + name.replace("\\", "\\\\").replace("`", "\\`") + "`"

    def text_expression(self, quoted_column: str, portable_name: str, declared_type: str | None = None) -> str:
        # lowerUTF8: lower() folds ASCII only ('ZÜRICH' -> 'zÜrich') while
        # the value search folds the needle in full Unicode. lowerUTF8 takes
        # String alone ('text'): FixedString ('string'), UUID, Enum and IP
        # arguments are refused, so they go through toString(), which also
        # drops a FixedString's trailing zero bytes.
        text = quoted_column if portable_name == "text" else f"toString({quoted_column})"
        return f"lowerUTF8({text})"

    def placeholder(self, index: int) -> str:
        # A '%' in a catalog name ('pct_%') is doubled with the rest of the
        # text when the statement runs with its values bound (_driver_sql).
        return f"%(p{index})s"

    def pack_parameters(self, values: list[Any]) -> Any:
        return {f"p{i}": v for i, v in enumerate(values, start=1)}

    def list_all_columns(self, schema: str | None) -> list[ColumnInfo]:
        db = schema or self.connection.config.database
        with translated_driver_errors():
            client = self._shared_meta_client()
            rows = client.query(
                "SELECT table, name, type, comment, position FROM system.columns "
                "WHERE database = %(db)s ORDER BY table, position",
                parameters={"db": db},
            ).result_rows
        return [
            ColumnInfo(schema=db, table=r[0], name=r[1], data_type=r[2],
                       nullable=str(r[2]).startswith("Nullable("), comment=r[3] or None, ordinal=int(r[4]))
            for r in rows
        ]

    def list_indexes(self, schema: str | None, table: str | None) -> list[IndexInfo]:
        """ClickHouse has no secondary B-tree indexes: the MergeTree sorting
        key is what the engine reads by (reported as the primary key), and
        data-skipping indices are the rest."""
        db = schema or self.connection.config.database
        out: list[IndexInfo] = []
        with translated_driver_errors():
            client = self._shared_meta_client()
            sql = "SELECT name, sorting_key, primary_key, engine FROM system.tables WHERE database = %(db)s"
            params: dict[str, Any] = {"db": db}
            if table:
                sql += " AND name = %(t)s"
                params["t"] = table
            for tname, sorting, primary, engine in client.query(sql, parameters=params).result_rows:
                key = primary or sorting
                if key:
                    out.append(IndexInfo(name="(sorting key)", columns=_split_key_expressions(str(key)),
                                         unique=False, primary=True, kind="sorting_key",
                                         definition=f"{engine} ORDER BY ({sorting})", schema=db, table=tname))
            sql = (
                "SELECT table, name, type, expr, granularity FROM system.data_skipping_indices "
                "WHERE database = %(db)s"
            )
            if table:
                sql += " AND table = %(t)s"
            for tname, iname, itype, expr, gran in client.query(sql, parameters=params).result_rows:
                out.append(IndexInfo(name=iname, columns=[str(expr)], unique=False, primary=False,
                                     kind=f"skipping:{itype}", definition=f"GRANULARITY {gran}",
                                     schema=db, table=tname))
        return out

    def list_views(self, schema: str | None) -> list[ViewInfo]:
        tables = self.list_tables(schema, {"view"}, None)
        return [ViewInfo(schema=t.schema, name=t.name, kind="view", definition_state="not_supported") for t in tables]

    def list_synonyms(self, schema: str | None) -> list[SynonymInfo]:
        return []

    def list_routines(self, schema: str | None) -> list[RoutineInfo]:
        return []  # user-defined functions exist but are not surfaced in v1

    def get_foreign_keys(self, schema: str | None, table: str | None) -> list[KeyInfo]:
        return []  # ClickHouse does not enforce FKs; report empty, not guessed

    def get_statistics(self, schema: str | None, table: str) -> dict[str, Any]:
        with translated_driver_errors():
            client = self._shared_meta_client()
            rows = client.query(
                "SELECT total_rows, formatReadableSize(total_bytes) FROM system.tables "
                "WHERE database = %(db)s AND name = %(t)s",
                parameters={"db": schema or "", "t": table},
            ).result_rows
        if not rows:
            return {"schema": schema, "table": table, "row_estimate": None, "row_estimate_source": "unavailable"}
        return {
            "schema": schema,
            "table": table,
            "row_estimate": int(rows[0][0]) if rows[0][0] is not None else None,
            "row_estimate_source": "catalog_estimate(system.tables)",
            "total_bytes": rows[0][1],
        }

    def execute_query(self, spec: QuerySpec) -> QueryOutcome:
        with self._exec_lock:
            return self._execute(spec)

    def _pin_query_id(self, client: Any) -> None:
        """Pin a per-query query_id on a dedicated client so cancel_current()
        can KILL exactly this query: clickhouse-connect shares this params
        dict by reference into every HTTP request, and each query runs on its
        own client under _exec_lock. If the driver surface ever changes,
        cancellation becomes unavailable — reported truthfully as False —
        rather than guessed."""
        qid = str(uuid.uuid4())
        try:
            client.params["query_id"] = qid
        except AttributeError:
            self._cancel_query_id = None
        else:
            self._cancel_query_id = qid

    def _result_ceilings(self, client: Any, max_rows: int, block: int) -> dict[str, Any]:
        """Per-query settings bounding what the server produces for one fetch,
        sent only where they tighten the account's own profile: blocks of
        ``block`` rows, JOIN output blocks included.

        readonly=1 rejects every SET, so nothing is sent there; the stream
        budget and KILL QUERY still bound the fetch (session_report says so). A row
        'break' always delivers the overflow row the fetch loop needs to
        report truncation. max_result_bytes is never sent: under 'break' a
        byte cut is silent, and rows whose native size dwarfs their JSON
        (UInt256, the JSON type) end before the client's byte ceiling sees an
        overflow (live 2026-09-27: 2048 of 20000 rows, untruncated, at 4x
        max_response_bytes). The byte ceiling is enforced per row instead.
        """
        if _server_setting(client, "readonly")[0] == "1" or self._ceilings_refused:
            return {}
        settings: dict[str, Any] = {}
        if _tightens(client, "max_block_size", block):
            settings["max_block_size"] = block
        # A JOIN's output block ignores max_block_size (live: 65536 rows, 9.3 s
        # to a first row; 512 rows, 0.17 s, with this). Only a server that
        # lists the setting takes it: an unknown one fails the query.
        if _server_setting(client, "max_joined_block_size_rows")[0] and _tightens(
            client, "max_joined_block_size_rows", block
        ):
            settings["max_joined_block_size_rows"] = block
        if (
            _server_setting(client, "result_overflow_mode")[1]
            and _tightens(client, "max_result_rows", max_rows + 1)
            # 'break' would also make the profile's own byte ceiling a silent cut
            and _is_off(_server_setting(client, "max_result_bytes")[0])
            # the server refuses every non-throw overflow mode with the query cache
            and _is_off(_server_setting(client, "use_query_cache")[0])
        ):
            settings["max_result_rows"] = max_rows + 1
            settings["result_overflow_mode"] = "break"
        return settings

    def _open_stream(self, client: Any, spec: QuerySpec, settings: dict[str, Any]) -> Any:
        """The column-block stream under the per-query ceilings, or without
        them when the account's profile refuses one (a settings constraint the
        driver cannot see): the stream budget and KILL QUERY still bound the
        fetch. ``settings`` is emptied then, so no 'break' is assumed, and the
        refusal is remembered for later queries and session reports once the
        statement ran without them."""
        params = spec.parameters or None
        try:
            return client.query_column_block_stream(spec.sql, parameters=params, settings=settings)
        except Exception as exc:
            refused = _server_error_code(exc)
            if not settings or refused not in _SETTING_REFUSED:
                raise
        settings.clear()
        own_error = False
        try:
            return client.query_column_block_stream(spec.sql, parameters=params, settings=settings)
        except Exception as exc:
            # refused without the ceilings too: the statement's own error
            own_error = _server_error_code(exc) is not None
            raise
        finally:
            if not own_error:
                self._ceilings_refused = (
                    f"server profile refused them (code {refused}); streamed and KILLed at the ceiling"
                )
                self._session_skipped("per-query result ceilings", RuntimeError(self._ceilings_refused))

    def _execute(self, spec: QuerySpec) -> QueryOutcome:
        # outside translated_driver_errors: a placeholder/value mismatch stays a VALIDATION error
        params = spec.parameters or None
        spec = replace(spec, sql=_driver_sql(spec.sql, params), parameters=params)
        cancel = threading.Event()
        self._cancel_event = cancel
        start = time.monotonic()
        block = min(max(spec.max_rows + 1, _MIN_BLOCK_ROWS), _MAX_BLOCK_ROWS)
        try:
            while True:
                try:
                    return self._fetch(spec, cancel, start, block)
                except _BlockTooWide as exc:
                    # The first block alone passed the stream budget: wide
                    # computed rows, or an arrayJoin() multiplying a
                    # table-read block. Run it again on narrower blocks.
                    block = exc.block
        finally:
            self._cancel_event = None

    def _fetch(self, spec: QuerySpec, cancel: threading.Event, start: float, block: int) -> QueryOutcome:
        with translated_driver_errors():
            if cancel.is_set():
                raise ConnectorError("query cancelled after its deadline")
            client = self._connect(uncompressed=True)
            # The driver's LIMIT is no ceiling: it is appended only when a
            # whole-statement regex finds no LIMIT anywhere (a subquery's or a
            # string literal's counts; 'SELECT*FROM' is not seen as a SELECT),
            # and at max_rows == hard_max_rows it cut the result to exactly
            # max_rows, hiding the overflow row that proves truncation.
            client.query_limit = 0
            budget = _StreamBudget(
                max(_STREAM_BUDGET_FLOOR, _STREAM_BUDGET_FACTOR * spec.max_response_bytes), self._kill_current
            )
            metered = budget.install(client)
            guarded = _guard_column_reads()
            truncated = False
            truncation_cause = "row limit"
            cell_truncated_cols: list[str] = []
            rows: list[list[Any]] = []
            cols: list[tuple[str, str]] = []
            labels: list[str] = []
            approx_bytes = 0
            import json

            try:
                self._pin_query_id(client)
                settings = self._result_ceilings(client, spec.max_rows, block)
                try:
                    # Rows stream block by block and the ceilings below stop
                    # the fetch; result_rows would buffer the whole response.
                    # Blocks come column-oriented and rows are built one at a
                    # time: the driver's row blocks turn a whole decoded block
                    # into row tuples first (live: 424 MB for one 7.7 MB
                    # arrayJoin() block of 7.68M rows).
                    with _statement_errors(), self._open_stream(client, spec, settings) as stream:
                        cols = [(n, "unknown") for n in stream.source.column_names]
                        exhausted = False
                        try:
                            for columns in stream:
                                budget.next_block()
                                for i in range(len(columns[0]) if columns else 0):
                                    if cancel.is_set():
                                        raise ConnectorError("query cancelled after its deadline")
                                    vals, lab, cut = adapt_row([col[i] for col in columns], spec.max_cell_bytes)
                                    if not labels:
                                        labels = lab
                                    if cut:
                                        cell_truncated_cols.extend(column_names_at(cols, cut))
                                    approx_bytes += len(json.dumps(vals, default=str).encode("utf-8"))
                                    if len(rows) >= spec.max_rows or approx_bytes > spec.max_response_bytes:
                                        truncated = True
                                        truncation_cause = (
                                            "row limit" if len(rows) >= spec.max_rows else "byte limit"
                                        )
                                        break
                                    rows.append(vals)
                                if truncated:
                                    break
                            else:
                                exhausted = True
                        finally:
                            if not exhausted:
                                # Leaving the stream drains the rest of the
                                # response in one read while the server keeps
                                # producing it: stop the query, then drop the
                                # connection. A 'break' ends the query itself
                                # once max_rows+1 rows were produced.
                                broke = truncation_cause == "row limit" and "result_overflow_mode" in settings
                                if not ((truncated and broke) or cancel.is_set() or budget.exceeded):
                                    self._kill_current()
                                budget.drop()
                except _StreamBudgetExceeded:
                    if not rows:
                        narrower = block
                        while narrower > 1:
                            narrower = max(1, narrower // _BLOCK_NARROWING)
                            if self._result_ceilings(client, spec.max_rows, narrower) != settings:
                                raise _BlockTooWide(narrower) from None
                        raise ConnectorError(
                            self._block_too_wide(budget, settings), category=ErrorCategory.LIMIT
                        ) from None
                    truncated, truncation_cause = True, "byte limit"
                warnings = [f"result truncated by {truncation_cause}"] if truncated else []
                if not metered:
                    warnings.append(
                        "this clickhouse-connect version offers no seam for the stream byte budget: each "
                        "result block was decoded whole before the row and byte ceilings applied"
                    )
                elif not guarded:
                    warnings.append(
                        "this clickhouse-connect version offers no seam for the column read guard: a column "
                        "was allocated at the size its block declared before the stream byte budget applied"
                    )
                if cell_truncated_cols:
                    truncated = True
                    warnings.append(cell_truncation_warning(cell_truncated_cols, spec.max_cell_bytes))
                return QueryOutcome(
                    columns=[(c[0], t) for c, t in zip(cols, labels or ["unknown"] * len(cols), strict=True)],
                    rows=rows,
                    truncated=truncated,
                    rows_seen=len(rows),
                    elapsed_ms=int((time.monotonic() - start) * 1000),
                    warnings=warnings,
                )
            finally:
                self._cancel_query_id = None
                client.close()

    @staticmethod
    def _block_too_wide(budget: _StreamBudget, settings: dict[str, Any]) -> str:
        """The refusal for a first block over the stream budget (its wire
        bytes, or what it decodes to) that no narrower block can fix."""
        if settings.get("max_block_size") == 1:
            why = (
                "even on 1-row blocks: one row, or the rows one input row expands to (arrayJoin(), a JOIN), "
                "is wider than that. Select fewer or narrower columns (substring() cuts a wide value), or cut "
                "the expanded rows with a smaller LIMIT"
            )
        else:
            why = (
                "and this account's profile does not accept a smaller block size (max_block_size). Select "
                "fewer or narrower columns (substring() cuts a wide value), or add a LIMIT small enough for "
                "its rows to fit"
            )
        if budget.objects_exceeded:
            size = f"that decodes to more than {budget.object_budget >> 20} MiB in memory"
        else:
            size = f"of more than {budget.budget >> 20} MiB"
        return f"ClickHouse sent a result block {size} before its first row was read, {why}"

    def explain(self, sql: str, analyze: bool) -> dict[str, Any]:
        if analyze:
            raise NotImplementedError(EXPLAIN_ANALYZE_UNSUPPORTED)
        # ClickHouse evaluates scalar subqueries while planning, even under
        # plain EXPLAIN, so an EXPLAIN reads data and can run long: it takes
        # the same cancel slot as db_query (serialized, pinned query_id the
        # deadline hook can KILL) and a read ceiling.
        with self._exec_lock:
            try:
                return self._explain(sql)
            except _PlanningReadLimit as exc:
                ceiling = exc.ceiling
        limit = f"more than {ceiling} rows" if ceiling else "more rows than this account may read"
        raise NotImplementedError(
            f"ClickHouse evaluates scalar subqueries (and IN subqueries) while planning; this EXPLAIN "
            f"would read {limit} of data to produce a plan, by reading them or by the planner's row "
            "estimate. Use db_query to run it under the query limits"
        )

    def _explain(self, sql: str) -> dict[str, Any]:
        with translated_driver_errors():
            client = self._connect()
            try:
                # The driver would append "LIMIT <query_limit>" to an
                # "EXPLAIN SELECT ..." that has no LIMIT and return the plan
                # of a different statement (a top-N sort, not a full one).
                client.query_limit = 0
                # Every EXPLAIN gets the read ceiling: whether planning reads
                # is not visible in the statement text (a view's definition,
                # ClickHouse's '#' comments and heredocs hid the subquery from
                # a text heuristic, live, and the plan read 250k rows).
                sent = self._explain_ceiling(client)
                self._pin_query_id(client)
                try:
                    with _statement_errors():
                        try:
                            rows = self._plan(client, sql, sent)
                        except Exception as exc:
                            if _server_error_code(exc) == _TOO_MANY_ROWS:
                                raise _PlanningReadLimit(self._read_ceiling(client, sent)) from exc
                            raise
                finally:
                    self._cancel_query_id = None
            finally:
                client.close()
        notes: list[str] = []
        ceiling = self._read_ceiling(client, sent)
        if ceiling is None or ceiling > _EXPLAIN_MAX_ROWS_TO_READ:
            notes.append(
                "ClickHouse evaluates scalar subqueries while planning and this account's profile "
                "does not accept a read ceiling for EXPLAIN, so producing this plan may have read table data"
            )
        if _JOIN_ORDER in sent:
            notes.append(
                "ClickHouse's join reordering checks the read ceiling against its row estimates, so this "
                f"plan was made with {_JOIN_ORDER}=0: the joins appear in their written order, which the "
                "engine may change when the statement runs"
            )
        plan: dict[str, Any] = {"raw": rows}
        if notes:
            plan["cleanup_warning"] = "; ".join(notes)  # db_explain's channel for connector warnings
        return plan

    @staticmethod
    def _plan(client: Any, sql: str, sent: list[str]) -> Any:
        """The EXPLAIN rows under the settings ``sent`` put on the client. A
        plan refused at the read ceiling is tried once more with join
        reordering off (added to ``sent``): the refusal may be the reorder's
        row estimate, not a read. A profile constraint that refuses one of the
        settings (not visible in system.settings) plans without them and
        empties ``sent``."""
        # a plan is never a columns-only request (it came back empty)
        explain = _streamed("EXPLAIN " + sql, probe_ok=False)  # noqa: S608 - validated upstream
        try:
            return client.query(explain).result_rows
        except Exception as exc:
            code = _server_error_code(exc)
            join_order, changeable = _server_setting(client, _JOIN_ORDER)
            if code == _TOO_MANY_ROWS and join_order and changeable and _server_setting(client, "readonly")[0] != "1":
                client.set_client_setting(_JOIN_ORDER, 0)
                sent.append(_JOIN_ORDER)
            elif sent and code in _SETTING_REFUSED:
                for name in sent:
                    client.params.pop(name, None)
                sent.clear()
            else:
                raise
        return client.query(explain).result_rows

    @staticmethod
    def _explain_ceiling(client: Any) -> list[str]:
        """Cap what planning may read, sent the way the session profile is:
        max_rows_to_read where it tightens the profile, and read_overflow_mode
        'throw'. readonly=1 rejects every SET. Returns the names of the
        settings put on the client."""
        if _server_setting(client, "readonly")[0] == "1":
            return []
        wanted: dict[str, Any] = {"read_overflow_mode": "throw"}
        if _tightens(client, "max_rows_to_read", _EXPLAIN_MAX_ROWS_TO_READ):
            wanted["max_rows_to_read"] = _EXPLAIN_MAX_ROWS_TO_READ
        sent: list[str] = []
        for name, value in wanted.items():
            if not _server_setting(client, name)[1]:
                continue  # pinned by the profile: sending it would fail the query
            try:
                client.set_client_setting(name, value)
            except Exception:  # noqa: BLE001, S112 - reported by the caller when no ceiling took
                continue
            sent.append(name)
        return sent

    @staticmethod
    def _read_ceiling(client: Any, sent: list[str]) -> int | None:
        """The row ceiling planning runs under: ours, or the profile's own
        when it is lower or ours was not sent; None when there is none that
        throws (a 'break' ceiling lets planning read on, live)."""
        if "read_overflow_mode" not in sent and _server_setting(client, "read_overflow_mode")[0] not in ("", "throw"):
            return None
        ceilings = [_EXPLAIN_MAX_ROWS_TO_READ] if "max_rows_to_read" in sent else []
        profile = _server_setting(client, "max_rows_to_read")[0]
        if profile.isdigit() and int(profile) > 0:
            ceilings.append(int(profile))
        return min(ceilings) if ceilings else None
