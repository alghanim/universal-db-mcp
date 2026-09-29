"""Regression tests for the 2026-09-27 hardening review, ClickHouse group
(F07, F10, F38, F83, F88).

Every test names the finding it pins. The fakes mimic the clickhouse-connect
1.8 surface the connector uses: a shared-by-reference ``params`` dict,
``query_limit``, ``server_settings`` (system.settings rows with ``value`` and
``readonly``), ``query_column_block_stream`` (a context manager whose
``source`` carries ``column_names`` and which yields column-oriented blocks),
``query``, ``command`` and ``close``. The tests write their blocks as rows;
``_Stream`` hands them out as columns, the way the driver decodes them.
``_NativeClient`` goes one level lower for the stream byte budget: the real
driver decodes Native-format bytes that a fake backend's ResponseSource hands
out.
"""
from __future__ import annotations

import inspect
import math
import types
from collections.abc import Callable, Iterator
from typing import Any

import pytest
import sqlglot
from clickhouse_connect.driver import _backendclient
from clickhouse_connect.driver.query import QueryContext
from clickhouse_connect.driver.transform import NativeTransform
from mcp.server.mcpserver.exceptions import ToolError
from sqlglot import exp

from universal_db_mcp.config import ConnectionConfig, ResolvedConnection, SecurityConfig
from universal_db_mcp.connectors import clickhouse as ch_module
from universal_db_mcp.connectors.base import ConnectorError, QuerySpec
from universal_db_mcp.connectors.clickhouse import ClickHouseConnector
from universal_db_mcp.security.policy import EffectivePolicy

KILL_SQL = "KILL QUERY WHERE query_id = %(qid)s"


class _Setting:
    """One system.settings row as the driver keeps it (SettingDef)."""

    def __init__(self, value: str, readonly: int = 0) -> None:
        self.value = value
        self.readonly = readonly


class _ServerError(Exception):
    """A clickhouse-connect DatabaseError: the server's message and its code."""

    def __init__(self, message: str, code: int | None = None) -> None:
        super().__init__(message)
        self.code = code


class _Stream:
    def __init__(self, state: dict[str, Any], names: tuple[str, ...], blocks: Iterator[list[tuple[Any, ...]]]) -> None:
        self.source = types.SimpleNamespace(column_names=names)
        self._state = state
        self._blocks = blocks

    def __enter__(self) -> _Stream:
        return self

    def __exit__(self, *exc: object) -> None:
        # How many KILLs had been sent when the stream closed: the driver
        # drains the rest of the response here, so the KILL must come first.
        self._state["exits"].append(len(self._state["commands"]))

    def __iter__(self) -> Iterator[Any]:
        for block in self._blocks:
            # column-oriented, as query_column_block_stream yields them
            yield block if self._state.get("columnar") else [list(col) for col in zip(*block, strict=True)]


class _Client:
    def __init__(self, state: dict[str, Any]) -> None:
        self.params: dict[str, Any] = {}
        self.query_limit = state["get_client_kw"][-1].get("query_limit", 0)
        self.server_settings = dict(state["server"])
        # the seam the stream budget wraps (these fakes hand out decoded blocks)
        self._backend = types.SimpleNamespace(execute_query=lambda *_a, **_k: None)
        self._state = state

    def set_client_setting(self, name: str, value: Any) -> None:
        ro = self.server_settings.get("readonly")
        if ro is not None and ro.value == "1":
            raise RuntimeError("Cannot modify setting in readonly mode")
        self.params[name] = value

    def query_column_block_stream(self, query: str, parameters: Any = None, settings: Any = None) -> _Stream:
        st = self._state
        st["streams"].append(
            {
                "sql": query,
                "settings": dict(settings or {}),
                "query_id": self.params.get("query_id"),
                "query_limit": self.query_limit,
                "cancel_slot": st["conn"]._cancel_query_id,
            }
        )
        return _Stream(st, st["names"], st["blocks"](st))

    def query(self, query: str, parameters: Any = None, settings: Any = None) -> Any:
        self._state["queries"].append(query)
        return self._state["on_query"](self, query)

    def command(self, cmd: str, parameters: Any = None) -> str:
        self._state["commands"].append((cmd, parameters))
        return "ok"

    def close(self) -> None:
        self._state["closed"] += 1


def _leb128(n: int) -> bytes:
    out = bytearray()
    while True:
        low, n = n & 0x7F, n >> 7
        out.append(low | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _native_block(values: list[str], name: str = "v") -> bytes:
    """One Native-format block of a single String column, as ClickHouse sends it."""
    out = bytearray(_leb128(1) + _leb128(len(values)))
    for text in (name, "String"):
        out += _leb128(len(text)) + text.encode()
    for value in values:
        raw = value.encode()
        out += _leb128(len(raw)) + raw
    return bytes(out)


class _Wire:
    """The HTTP response under the driver's ResponseSource: hands out chunks
    and records what the driver's drain would read once the query stopped."""

    def __init__(self, state: dict[str, Any], body: bytes, chunk: int = 64 * 1024) -> None:
        self._state = state
        self.body = body
        self.chunk = chunk
        self.pulled = 0
        self.drained = 0
        self.closed = False

    def chunks(self) -> Iterator[bytes]:
        while self.pulled < len(self.body) and not self.closed:
            piece = self.body[self.pulled : self.pulled + self.chunk]
            self.pulled += len(piece)
            yield piece

    def drain_conn(self) -> None:
        if not self.closed:
            self.drained += len(self.body) - self.pulled
            self.pulled = len(self.body)

    def close(self) -> None:
        if not self.closed:
            self._state["kills_at_close"].append(len(self._state["commands"]))
        self.closed = True


class _WireSource:
    """clickhouse-connect's ResponseSource surface: ``gen``, ``response``, and
    a ``close`` that drains before it closes."""

    def __init__(self, wire: _Wire) -> None:
        self.response = wire
        self.gen = wire.chunks()

    def close(self) -> None:
        self.response.drain_conn()
        self.response.close()


class _Backend:
    def __init__(self, state: dict[str, Any]) -> None:
        self._state = state

    def execute_query(self, context: Any, runtime: Any, prepped_query: Any) -> Any:
        body = self._state["body"]
        if callable(body):  # what the server sends depends on the settings
            body = body(self._state["streams"][-1]["settings"])
        wire = _Wire(self._state, body)
        self._state["wires"].append(wire)
        return types.SimpleNamespace(source=_WireSource(wire), columns=None)


class _NativeClient:
    """A client whose stream the real driver decodes (its C response buffer
    and Native transform) from the backend's byte source, the way
    clickhouse-connect 1.8's ``_query_with_context`` does."""

    def __init__(self, state: dict[str, Any]) -> None:
        self.params: dict[str, Any] = {}
        self.query_limit = 0
        self.server_settings = dict(state["server"])
        self._backend = _Backend(state)
        self._state = state

    def set_client_setting(self, name: str, value: Any) -> None:
        self.params[name] = value

    def query_column_block_stream(self, query: str, parameters: Any = None, settings: Any = None) -> Any:
        self._state["streams"].append({"sql": query, "settings": dict(settings or {})})
        execution = self._backend.execute_query(None, None, query)
        # the driver's module global, looked up per query as _query_with_context does
        byte_source = _backendclient.RespBuffCls(execution.source)
        return NativeTransform.parse_response(byte_source, QueryContext()).column_block_stream

    def command(self, cmd: str, parameters: Any = None) -> str:
        self._state["commands"].append((cmd, parameters))
        return "ok"

    def close(self) -> None:
        self._state["closed"] += 1


def _no_query(client: _Client, sql: str) -> Any:
    raise AssertionError(f"client.query() must not run on this path: {sql}")


def _connector(tmp_path: Any, **cfg: Any) -> ClickHouseConnector:
    body: dict[str, Any] = {"type": "clickhouse", "host": "h", "database": "d", "options": {"os_authentication": True}}
    body.update(cfg)
    resolved = ResolvedConnection("ch", ConnectionConfig.model_validate(body))
    return ClickHouseConnector(resolved, EffectivePolicy.build(SecurityConfig(), resolved))


def _make(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
    *,
    server: dict[str, _Setting] | None = None,
    names: tuple[str, ...] = ("v",),
    blocks: Callable[[dict[str, Any]], Iterator[list[tuple[Any, ...]]]] | None = None,
    on_query: Callable[[_Client, str], Any] = _no_query,
    client_cls: Callable[[dict[str, Any]], Any] = _Client,
    body: bytes | Callable[[dict[str, Any]], bytes] = b"",
    **cfg: Any,
) -> tuple[ClickHouseConnector, dict[str, Any]]:
    conn = _connector(tmp_path, **cfg)
    state: dict[str, Any] = {
        "conn": conn, "server": server or {}, "names": names, "blocks": blocks or (lambda st: iter([[(1,)]])),
        "on_query": on_query, "streams": [], "queries": [], "commands": [], "exits": [], "closed": 0,
        "pulled": 0, "overpulled": False, "get_client_kw": [], "body": body, "wires": [], "kills_at_close": [],
    }

    def get_client(**kw: Any) -> Any:
        state["get_client_kw"].append(kw)
        return client_cls(state)

    monkeypatch.setattr(ch_module, "open_module", lambda *_a, **_k: types.SimpleNamespace(get_client=get_client))
    return conn, state


def _bounded_blocks(rows_per_block: int, allowed: int, row: Callable[[int], tuple[Any, ...]] = lambda i: (i,)) -> Any:
    """A block generator that records an over-pull past ``allowed`` blocks."""

    def gen(state: dict[str, Any]) -> Iterator[list[tuple[Any, ...]]]:
        i = 0
        while True:
            if state["pulled"] >= allowed:
                state["overpulled"] = True
                raise AssertionError("the fetch kept pulling blocks past the ceiling")
            state["pulled"] += 1
            yield [row(i + k) for k in range(rows_per_block)]
            i += rows_per_block

    return gen


# --- F07: streaming fetch, per-row ceilings, KILL on early stop ----------------


@pytest.mark.parametrize(
    ("server", "kills"),
    [
        # 'break' at max_result_rows = max_rows+1 has ended the query already
        ({}, 0),
        # no per-query settings on readonly=1: the KILL is what stops it
        ({"readonly": _Setting("1", 1)}, 1),
    ],
)
def test_f07_row_ceiling_stops_the_stream(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any, server: dict[str, _Setting], kills: int
) -> None:
    """The whole result used to be materialized (result_rows) before max_rows
    applied. Now rows stream block by block and the fetch stops at row
    max_rows+1. Where the server may still be producing, the pinned query is
    KILLed before the stream closes, because closing alone drains the rest of
    the response while the server keeps producing it."""
    conn, state = _make(monkeypatch, tmp_path, server=server, blocks=_bounded_blocks(6, allowed=2))
    out = conn._execute(QuerySpec(sql="SELECT v FROM t", max_rows=10))
    assert out.truncated is True
    assert len(out.rows) == 10
    assert any("row limit" in w for w in out.warnings), out.warnings
    assert state["pulled"] == 2 and not state["overpulled"]
    qid = state["streams"][0]["query_id"]
    assert qid and state["streams"][0]["cancel_slot"] == qid
    assert state["commands"] == [(KILL_SQL, {"qid": qid})] * kills
    assert state["exits"] == [kills], "KILL QUERY must be sent before the stream is closed (and drained)"
    assert conn._cancel_query_id is None


def test_f07_byte_budget_stops_on_wide_cells(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    conn, state = _make(
        monkeypatch, tmp_path, names=("big",), blocks=_bounded_blocks(1, allowed=3, row=lambda i: ("x" * 1_000_000,))
    )
    out = conn._execute(
        QuerySpec(sql="SELECT big FROM t", max_rows=1000, max_response_bytes=3_000_000, max_cell_bytes=2_000_000)
    )
    assert out.truncated is True
    assert len(out.rows) == 2
    assert any("byte limit" in w for w in out.warnings), out.warnings
    assert state["pulled"] == 3 and not state["overpulled"]
    assert [c for c, _p in state["commands"]] == [KILL_SQL]
    assert state["exits"] == [1]


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT a.x FROM t a CROSS JOIN t b LIMIT 1500000",
        "SELECT x FROM (SELECT a.x FROM t a CROSS JOIN t b LIMIT 3000000) s",
        "SELECT x, ' LIMIT ' AS note FROM t",
        "SELECT*FROM t",
    ],
)
def test_f07_server_side_ceilings_do_not_depend_on_the_statement_text(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any, sql: str
) -> None:
    """query_limit was the only server-side bound and clickhouse-connect adds
    it only when a whole-statement regex finds no LIMIT anywhere: a subquery's
    LIMIT, the text ' LIMIT ' in a literal, or 'SELECT*FROM' (not seen as a
    SELECT) disabled it. The per-query settings now apply to every shape."""
    conn, state = _make(monkeypatch, tmp_path)
    conn._execute(QuerySpec(sql=sql, max_rows=10))
    sent = state["streams"][0]
    settings = sent["settings"]
    assert 1 <= settings["max_block_size"] <= 1024
    assert settings["max_result_rows"] == 11
    assert settings["result_overflow_mode"] == "break"
    # 'break' also turns max_result_bytes into a SILENT cut: rows whose native
    # size dwarfs their JSON (UInt256, the JSON type) end early with no
    # overflow row for the client to see (live 2026-09-27: 20000-row result
    # returned 2048 rows, untruncated, at 4x max_response_bytes). The byte
    # ceiling is enforced per row client-side instead.
    assert "max_result_bytes" not in settings
    assert sent["query_limit"] == 0, "the driver's text-dependent LIMIT must not be relied on (or appended)"


def test_f07_query_limit_no_longer_cuts_the_overflow_row(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    """With query_limit == hard_max_rows the driver appended LIMIT 10000, so
    max_rows=10000 on a bigger table returned exactly 10000 rows and the
    overflow row that proves truncation never arrived: truncated=false."""
    from clickhouse_connect.driver.query import QueryContext

    def blocks(state: dict[str, Any]) -> Iterator[list[tuple[Any, ...]]]:
        sent = state["streams"][-1]
        ctx = QueryContext(query=sent["sql"])
        cap = sent["query_limit"] if ctx.is_select and not ctx.has_limit and sent["query_limit"] else None
        total = 25_000 if cap is None else min(cap, 25_000)
        for start in range(0, total, 1000):
            yield [(i,) for i in range(start, min(start + 1000, total))]

    conn, state = _make(monkeypatch, tmp_path, blocks=blocks)
    out = conn._execute(QuerySpec(sql="SELECT v FROM big", max_rows=conn.policy.hard_max_rows))
    assert len(out.rows) == conn.policy.hard_max_rows
    assert out.truncated is True


def test_f07_execute_path_never_buffers_through_query(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    conn, state = _make(monkeypatch, tmp_path, blocks=_bounded_blocks(3, allowed=1))
    with pytest.raises(ConnectorError):
        conn._execute(QuerySpec(sql="SELECT v FROM t", max_rows=100))  # over-pull guard fires after block 1
    state["blocks"] = lambda st: iter([[(1,), (2,)]])
    state["commands"].clear()
    clients = len(state["get_client_kw"])
    out = conn._execute(QuerySpec(sql="SELECT v FROM t", max_rows=100))
    assert out.rows == [[1], [2]] and out.truncated is False
    assert state["queries"] == [], "client.query()/result_rows materialize the whole result"
    assert len(state["streams"]) == 2
    # a query that ran to its end is not KILLed, and costs no second client
    assert state["commands"] == []
    assert len(state["get_client_kw"]) == clients + 1


def test_f07_readonly_1_profile_streams_without_settings_and_says_so(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    """readonly=1 rejects every SET: the fetch must still work (no settings
    sent, nothing raised), stay bounded by streaming + KILL QUERY, and the
    session report must say the per-query ceilings are not applied."""
    conn, state = _make(
        monkeypatch, tmp_path, server={"readonly": _Setting("1", 1)}, blocks=_bounded_blocks(6, allowed=2)
    )
    out = conn._execute(QuerySpec(sql="SELECT v FROM t", max_rows=10))
    assert state["streams"][0]["settings"] == {}
    assert out.truncated is True and len(out.rows) == 10
    assert [c for c, _p in state["commands"]] == [KILL_SQL]
    report = conn.session_report()
    assert any("per-query result ceilings" in s for s in report["skipped"]), report["skipped"]


@pytest.mark.parametrize(
    ("server", "absent"),
    [
        # the profile's own row ceiling is tighter: keep it (and its mode)
        ({"max_result_rows": _Setting("5")}, {"max_result_rows", "result_overflow_mode"}),
        # 'break' would silently apply to the profile's byte ceiling too
        ({"max_result_bytes": _Setting("5000000")}, {"max_result_rows", "result_overflow_mode"}),
        # the server refuses non-throw overflow modes with the query cache
        ({"use_query_cache": _Setting("1")}, {"max_result_rows", "result_overflow_mode"}),
        # a settings constraint pins the mode: sending the pair would fail
        ({"result_overflow_mode": _Setting("throw", 1)}, {"max_result_rows", "result_overflow_mode"}),
        ({"max_block_size": _Setting("100")}, {"max_block_size"}),
        ({"max_block_size": _Setting("65409", 1)}, {"max_block_size"}),
    ],
)
def test_f07_per_query_ceilings_never_relax_the_account_profile(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any, server: dict[str, _Setting], absent: set[str]
) -> None:
    conn, state = _make(monkeypatch, tmp_path, server=server)
    conn._execute(QuerySpec(sql="SELECT v FROM t", max_rows=10))
    sent = state["streams"][0]["settings"]
    assert not absent & set(sent), sent


def test_f07_unset_profile_ceilings_are_tightened(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    server = {"max_result_rows": _Setting("0"), "max_result_bytes": _Setting("0"), "use_query_cache": _Setting("0"),
              "result_overflow_mode": _Setting("throw"), "max_block_size": _Setting("65409")}
    conn, state = _make(monkeypatch, tmp_path, server=server)
    conn._execute(QuerySpec(sql="SELECT v FROM t", max_rows=10))
    sent = state["streams"][0]["settings"]
    assert sent["max_result_rows"] == 11 and sent["result_overflow_mode"] == "break"
    assert sent["max_block_size"] <= 1024


def test_f07_cancel_stops_an_abandoned_worker(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    """After the executor deadline the worker used to keep materializing the
    response. cancel_current() now also flags the fetch loop, which stops at
    the next row."""
    inner = _bounded_blocks(6, allowed=3)

    def blocks(state: dict[str, Any]) -> Iterator[list[tuple[Any, ...]]]:
        for n, block in enumerate(inner(state)):
            if n == 1:
                state["cancelled"] = state["conn"].cancel_current()  # the deadline hook, mid-fetch
            yield block

    conn, state = _make(monkeypatch, tmp_path, blocks=blocks)
    with pytest.raises(ConnectorError, match="cancel"):
        conn._execute(QuerySpec(sql="SELECT v FROM t", max_rows=1000))
    assert state["cancelled"] is True
    assert state["pulled"] == 2 and not state["overpulled"]
    qid = state["streams"][0]["query_id"]
    assert state["commands"] == [(KILL_SQL, {"qid": qid})], "one KILL: the hook's"
    assert conn._cancel_query_id is None
    assert conn.cancel_current() is False, "nothing executing: never KILL an unrelated query"


def _wide_blocks_budget(monkeypatch: pytest.MonkeyPatch) -> int:
    budget = 1 << 20
    monkeypatch.setattr(ch_module, "_STREAM_BUDGET_FLOOR", budget)
    return budget


def test_f07_a_block_wider_than_the_stream_budget_is_refused_undecoded(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    """max_block_size bounds only blocks read from a table: a JOIN's output
    block (live 2026-09-27: 65417 rows, 785 MB), an arrayJoin() block and an
    aggregate block come whole, and the driver decoded all of it before its
    first row reached the ceilings (2 GB at max_rows=10). The byte stream is
    metered now: at the budget the query is KILLed and the connection dropped
    without the driver's drain, which reads the rest in one unbounded call."""
    budget = _wide_blocks_budget(monkeypatch)
    body = _native_block(["x" * 100_000] * 200)  # one 20 MB block, whatever the block settings
    conn, state = _make(monkeypatch, tmp_path, client_cls=_NativeClient, body=body)
    with pytest.raises(ConnectorError, match="even on 1-row blocks") as info:
        conn._execute(QuerySpec(sql="SELECT big FROM t a CROSS JOIN t b", max_rows=10, max_response_bytes=100_000))
    assert getattr(info.value, "category", None) == "LIMIT_EXCEEDED"
    # the narrower attempts, down to one-row blocks, hit the budget too
    assert [s["settings"]["max_block_size"] for s in state["streams"]] == [256, 8, 1]
    for wire in state["wires"]:
        assert wire.pulled <= budget + wire.chunk
        assert wire.closed and wire.drained == 0, "the rest of the response must be dropped, not read"
    assert [c for c, _p in state["commands"]] == [KILL_SQL] * 3
    assert state["kills_at_close"] == [1, 2, 3], "KILL QUERY first, so the server stops sending"
    assert conn._cancel_query_id is None and conn._cancel_event is None


@pytest.mark.parametrize("server", [{}, {"max_joined_block_size_rows": _Setting("65409")}])
def test_f07_a_first_block_too_wide_is_fetched_again_on_narrow_blocks(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any, server: dict[str, _Setting]
) -> None:
    """Wide computed rows (repeat(), groupArray()) in 256-row blocks, or an
    arrayJoin() multiplying them, pass the budget before the first row: the
    statement runs once more on blocks 1/32 the size. The JOIN output block
    is bounded from the first attempt on (live, review 2: a first JOIN block
    of 65536 rows took 9.3 s, one of 512 rows 0.17 s), where the server
    lists the setting (an unknown one fails the query)."""
    budget = _wide_blocks_budget(monkeypatch)

    def server_blocks(settings: dict[str, Any]) -> bytes:
        rows = settings.get("max_block_size", 65409)
        return b"".join(_native_block(["w" * 50_000] * rows) for _ in range(3))

    conn, state = _make(monkeypatch, tmp_path, server=server, client_cls=_NativeClient, body=server_blocks)
    out = conn._execute(QuerySpec(sql="SELECT repeat(v, 5000) FROM t", max_rows=10, max_response_bytes=100_000))
    assert len(out.rows) == 10 and out.truncated is True
    sent = [s["settings"] for s in state["streams"]]
    assert [s["max_block_size"] for s in sent] == [256, 8]
    assert [s.get("max_joined_block_size_rows") for s in sent] == ([256, 8] if server else [None, None])
    assert state["wires"][0].pulled <= budget + state["wires"][0].chunk
    assert [c for c, _p in state["commands"]] == [KILL_SQL], "the first attempt is KILLed at the budget"


def _limited_blocks(total: int, cell: int) -> Callable[[dict[str, Any]], bytes]:
    """What the server sends for 'SELECT <cell-wide value> ... LIMIT total':
    ``total`` rows in blocks of the max_block_size the query asked for."""

    def body(settings: dict[str, Any]) -> bytes:
        block = settings.get("max_block_size", 65409)
        sizes = [min(block, total - start) for start in range(0, total, block)]
        return b"".join(_native_block(["w" * cell] * n) for n in sizes)

    return body


def test_f07_wide_rows_under_a_limit_stream_instead_of_failing(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    """Review 2: 'SELECT repeat(caller_msisdn, 30000) ... LIMIT 100' at
    max_rows=100 (360 KB rows) became LIMIT_EXCEEDED ('add a LIMIT'), because
    the second attempt still asked for max_rows+1 = 101-row blocks, 36 MB.
    Here scaled down 8x: 45 KB rows under a 1 MiB budget. The rows now stream
    and the result ends at the byte budget, truncated, instead of failing."""
    _wide_blocks_budget(monkeypatch)
    body = _limited_blocks(100, 45_000)
    conn, state = _make(monkeypatch, tmp_path, client_cls=_NativeClient, body=body)
    spec = QuerySpec(sql="SELECT repeat(v, 30000) AS big FROM t LIMIT 100", max_rows=100,
                     max_response_bytes=128 * 1024, max_cell_bytes=1024)
    out = conn._execute(spec)
    assert [s["settings"]["max_block_size"] for s in state["streams"]] == [256, 8]
    assert 8 <= len(out.rows) < 100 and out.truncated is True
    assert any("byte limit" in w for w in out.warnings), out.warnings
    assert any("cell limit" in w for w in out.warnings), out.warnings


def test_f07_narrowing_is_not_a_no_op_at_the_default_max_rows(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    """At the default max_rows (1000) the first attempt already used
    max_rows+1 = 1001-row blocks, so the 'narrow' retry was the same query:
    live, 'SELECT repeat(caller_msisdn, 1000) FROM telecom.cdr' (12 KB rows)
    failed with LIMIT_EXCEEDED. Scaled down 8x here."""
    _wide_blocks_budget(monkeypatch)
    conn, state = _make(monkeypatch, tmp_path, client_cls=_NativeClient, body=_limited_blocks(3000, 1_500))
    out = conn._execute(
        QuerySpec(sql="SELECT repeat(v, 1000) AS big FROM t", max_response_bytes=100_000, max_cell_bytes=1024)
    )
    assert [s["settings"]["max_block_size"] for s in state["streams"]] == [1001, 31]
    assert len(out.rows) > 0 and out.truncated is True


def test_f07_rows_too_wide_for_narrow_blocks_stream_on_one_row_blocks(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    _wide_blocks_budget(monkeypatch)
    conn, state = _make(monkeypatch, tmp_path, client_cls=_NativeClient, body=_limited_blocks(11, 200_000))
    out = conn._execute(QuerySpec(sql="SELECT big FROM t", max_rows=10, max_response_bytes=100_000))
    assert [s["settings"]["max_block_size"] for s in state["streams"]] == [256, 8, 1]
    assert 1 <= len(out.rows) < 10 and out.truncated is True
    assert any("byte limit" in w for w in out.warnings), out.warnings


def test_f07_narrowing_skips_steps_the_profile_already_takes(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    """A profile's own max_block_size of 4 makes 256- and 8-row blocks the
    same query: the next attempt is the first one that changes anything."""
    _wide_blocks_budget(monkeypatch)
    conn, state = _make(
        monkeypatch, tmp_path, server={"max_block_size": _Setting("4")}, client_cls=_NativeClient,
        body=_limited_blocks(11, 400_000),
    )
    out = conn._execute(QuerySpec(sql="SELECT big FROM t", max_rows=10, max_response_bytes=100_000))
    assert [s["settings"].get("max_block_size") for s in state["streams"]] == [None, 1]
    assert out.rows and out.truncated is True


def test_f07_column_blocks_are_never_transposed_whole(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    """Review 2: an arrayJoin() block under the stream budget (7.7 MB of
    UInt8 on the wire, 7.68M rows) grew the process by 424 MB, because the
    driver's row stream turns each decoded block into row tuples
    ('list(zip(*block))') before the first row is read. Rows are now built
    from the column block one at a time, only as many as the ceilings let
    through."""

    class _Column:
        def __init__(self, state: dict[str, Any], n: int) -> None:
            self._state = state
            self._n = n

        def __len__(self) -> int:
            return self._n

        def __getitem__(self, i: int) -> int:
            self._state["cells_read"] += 1
            return i % 2

        def __iter__(self) -> Iterator[int]:
            raise AssertionError("the whole block was turned into rows")

    def blocks(state: dict[str, Any]) -> Iterator[Any]:
        yield [_Column(state, 5_000_000), _Column(state, 5_000_000)]
        raise AssertionError("the fetch kept pulling blocks past the ceiling")

    conn, state = _make(monkeypatch, tmp_path, names=("x", "y"), blocks=blocks)
    state["columnar"] = True
    state["cells_read"] = 0
    out = conn._execute(QuerySpec(sql="SELECT x, y FROM t", max_rows=10))
    assert out.rows == [[i % 2, i % 2] for i in range(10)] and out.truncated is True
    assert state["cells_read"] <= 2 * 11


def test_f07_no_second_attempt_where_blocks_cannot_narrow(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    """readonly=1 takes no settings, so a second attempt would be the same."""
    _wide_blocks_budget(monkeypatch)
    body = _native_block(["x" * 100_000] * 200)
    conn, state = _make(
        monkeypatch, tmp_path, server={"readonly": _Setting("1", 1)}, client_cls=_NativeClient, body=body
    )
    with pytest.raises(ConnectorError, match="does not accept a smaller block size") as info:
        conn._execute(QuerySpec(sql="SELECT big FROM t", max_rows=10, max_response_bytes=100_000))
    assert "LIMIT" in str(info.value), "without per-query settings a LIMIT is what cuts the block"
    assert len(state["streams"]) == 1


def test_f07_a_deadline_between_attempts_stops_the_second(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    _wide_blocks_budget(monkeypatch)
    conn, state = _make(monkeypatch, tmp_path, client_cls=_NativeClient)

    def body(settings: dict[str, Any]) -> bytes:
        conn.cancel_current()  # the executor's deadline hook fires during the first attempt
        return _native_block(["x" * 100_000] * 200)

    state["body"] = body
    with pytest.raises(ConnectorError, match="cancel"):
        conn._execute(QuerySpec(sql="SELECT big FROM t", max_rows=10, max_response_bytes=100_000))
    assert len(state["streams"]) == 1


def test_f07_stream_budget_truncates_after_rows_were_read(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    budget = _wide_blocks_budget(monkeypatch)
    body = _native_block(["a", "b", "c"]) + _native_block(["x" * 100_000] * 200)
    conn, state = _make(monkeypatch, tmp_path, client_cls=_NativeClient, body=body)
    out = conn._execute(QuerySpec(sql="SELECT v FROM t", max_rows=10, max_response_bytes=100_000))
    assert out.truncated is True
    assert out.rows == [["a"], ["b"], ["c"]]
    assert any("byte limit" in w for w in out.warnings), out.warnings
    wire = state["wires"][0]
    assert wire.pulled <= budget + wire.chunk and wire.drained == 0
    assert [c for c, _p in state["commands"]] == [KILL_SQL]


@pytest.mark.parametrize(
    ("server", "kills"),
    [
        # result_overflow_mode='break' ends the query once max_rows+1 rows
        # were produced (live: 256 of 250000 rows read), so no KILL is needed
        ({}, []),
        # readonly=1 takes no per-query settings: the KILL stops the server
        ({"readonly": _Setting("1", 1)}, [KILL_SQL]),
    ],
)
def test_f07_leaving_at_the_row_limit_drops_the_rest_undrained(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any, server: dict[str, _Setting], kills: list[str]
) -> None:
    """Every truncated query used to open a second client to KILL, and then
    the driver drained the server's next block, however large, into memory."""
    body = _native_block([str(i) for i in range(11)]) + _native_block(["y" * 1000] * 5000)
    conn, state = _make(monkeypatch, tmp_path, server=server, client_cls=_NativeClient, body=body)
    out = conn._execute(QuerySpec(sql="SELECT v FROM t", max_rows=10))
    assert out.truncated is True and len(out.rows) == 10
    assert [c for c, _p in state["commands"]] == kills
    wire = state["wires"][0]
    assert wire.closed and wire.drained == 0
    assert len(state["get_client_kw"]) == 1 + len(kills)


def test_f07_query_client_reads_the_response_uncompressed(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    """An LZ4 frame holds a whole server block: the driver decompressed one
    785 MB chunk in a single call (live 2026-09-27), before any meter could
    count it. Metadata and KILL clients keep compression."""
    conn, state = _make(monkeypatch, tmp_path)
    conn._execute(QuerySpec(sql="SELECT v FROM t", max_rows=10))
    assert state["get_client_kw"][0]["compress"] is False
    conn._connect()
    assert "compress" not in state["get_client_kw"][-1]


def test_f07_the_driver_seam_the_meter_wraps_is_present() -> None:
    """The meter wraps ResponseSource.gen through the backend's
    execute_query, where clickhouse-connect 1.8 builds its byte buffer: a
    driver upgrade that moves either must fail here, not unbound the fetch."""
    from clickhouse_connect.driver._backend.http_sync import HttpSyncBackend
    from clickhouse_connect.driver._backendclient import SyncBackendClient
    from clickhouse_connect.driver.httpclient import HttpClient
    from clickhouse_connect.driver.httputil import ResponseSource

    assert callable(HttpSyncBackend.execute_query)
    source = ResponseSource(types.SimpleNamespace(headers={}, stream=lambda *_a: iter([b"x"])))
    assert source.response is not None and list(source.gen) == [b"x"]
    query_path = inspect.getsource(SyncBackendClient._query_with_context)
    assert "RespBuffCls(execution.source)" in query_path
    # the instance attribute _StreamBudget.install() reads
    assert "self._backend.execute_query(" in query_path
    assert "self._backend = " in inspect.getsource(HttpClient.__init__)


def test_f07_a_driver_without_the_meter_seam_says_so(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    """install() used to return silently when the seam was missing: the
    fetch then ran without its byte bound (2 GB for one JOIN block, round 1)
    and nothing said so."""

    class _NoSeam(_Client):
        def __init__(self, state: dict[str, Any]) -> None:
            super().__init__(state)
            del self._backend

    conn, _state = _make(monkeypatch, tmp_path, client_cls=_NoSeam)
    out = conn._execute(QuerySpec(sql="SELECT v FROM t", max_rows=10))
    assert out.rows == [[1]]
    assert any("stream byte budget" in w for w in out.warnings), out.warnings
    report = conn.session_report()
    assert any("stream byte budget" in s for s in report["skipped"]), report["skipped"]
    conn2, _state2 = _make(monkeypatch, tmp_path)
    out = conn2._execute(QuerySpec(sql="SELECT v FROM t", max_rows=10))
    assert not any("stream byte budget" in w for w in out.warnings)


@pytest.mark.parametrize(
    "error",
    [
        "Code: 452. DB::Exception: Setting max_block_size shouldn't be less than 8192. (SETTING_CONSTRAINT_VIOLATION)",
        "Code: 164. DB::Exception: Cannot modify 'max_result_rows' setting in readonly mode. (READONLY)",
    ],
)
def test_f07_ceilings_a_profile_constraint_refuses_are_dropped_not_fatal(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any, error: str
) -> None:
    """system.settings 'readonly' does not show min/max constraints, and a
    refused per-query setting failed every db_query on such an account."""

    class _Constrained(_Client):
        def query_column_block_stream(self, query: str, parameters: Any = None, settings: Any = None) -> _Stream:
            if settings:
                self._state["refused"] = dict(settings)
                raise _ServerError(error, code=int(error.split(".")[0].split()[1]))
            return super().query_column_block_stream(query, parameters, settings)

    conn, state = _make(monkeypatch, tmp_path, client_cls=_Constrained, blocks=_bounded_blocks(6, allowed=2))
    out = conn._execute(QuerySpec(sql="SELECT v FROM t", max_rows=10))
    assert state["refused"]["max_result_rows"] == 11
    assert [s["settings"] for s in state["streams"]] == [{}]
    assert out.truncated is True and len(out.rows) == 10
    assert [c for c, _p in state["commands"]] == [KILL_SQL], "without 'break' the KILL stops the server"
    report = conn.session_report()
    assert any("per-query result ceilings" in s for s in report["skipped"]), report["skipped"]
    # the refusal is remembered: later queries skip the failing round trip,
    # and every later connect still reports it
    state["pulled"] = 0
    del state["refused"]
    conn._execute(QuerySpec(sql="SELECT v FROM t", max_rows=10))
    assert "refused" not in state and [s["settings"] for s in state["streams"]] == [{}, {}]
    conn._connect()
    report = conn.session_report()
    assert any("per-query result ceilings" in s for s in report["skipped"]), report["skipped"]


def test_f07_other_stream_errors_still_fail(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    class _Broken(_Client):
        def query_column_block_stream(self, query: str, parameters: Any = None, settings: Any = None) -> _Stream:
            raise _ServerError("Code: 60. DB::Exception: Unknown table", code=60)

    conn, state = _make(monkeypatch, tmp_path, client_cls=_Broken)
    with pytest.raises(ConnectorError, match="Unknown table"):
        conn._execute(QuerySpec(sql="SELECT v FROM t", max_rows=10))
    assert conn._cancel_query_id is None


def test_f07_the_ceilings_are_not_blamed_for_the_statements_own_refusal(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    """Review 2: a statement the server refused with code 164 whatever the
    settings latched 'ceilings refused' for the connector's life, and every
    later db_query ran without max_block_size or 'break'."""

    class _RefusesTheStatement(_Client):
        def query_column_block_stream(self, query: str, parameters: Any = None, settings: Any = None) -> _Stream:
            if "bad" in query:
                raise _ServerError("Code: 164. DB::Exception: Cannot execute query in readonly mode. (READONLY)", 164)
            return super().query_column_block_stream(query, parameters, settings)

    conn, state = _make(monkeypatch, tmp_path, client_cls=_RefusesTheStatement, blocks=_bounded_blocks(6, allowed=2))
    with pytest.raises(ConnectorError, match="readonly mode"):
        conn._execute(QuerySpec(sql="SELECT bad FROM t", max_rows=10))
    assert conn._ceilings_refused is None
    assert not any("per-query result ceilings" in s for s in conn.session_report()["skipped"])
    conn._execute(QuerySpec(sql="SELECT v FROM t", max_rows=10))
    assert state["streams"][-1]["settings"]["result_overflow_mode"] == "break"


class _NetworkError(Exception):
    """clickhouse-connect's OperationalError for a failed HTTP request: no code."""


@pytest.mark.parametrize("where", ["open", "stream"])
@pytest.mark.parametrize(
    ("error", "category"),
    [
        (_ServerError("Code: 47. DB::Exception: Unknown expression identifier `nosuchcol`", code=47), "QUERY_ERROR"),
        # a server error in the middle of the stream (StreamFailureError: text only)
        (RuntimeError("Code: 241. DB::Exception: Memory limit (for query) exceeded"), "QUERY_ERROR"),
        (_ServerError("Code: 159. DB::Exception: Timeout exceeded: elapsed 5.0 seconds, maximum: 5", 159), "TIMEOUT"),
        (_NetworkError("Error HTTPConnectionPool(host='h', port=8123): Connection refused"), None),
    ],
)
def test_f07_statement_errors_are_query_errors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any, where: str, error: Exception, category: str | None
) -> None:
    """Review 2: ClickHouse statement errors (unknown identifier, syntax,
    types) reached the agent as CONNECTION_ERROR while every other SQL engine
    reports QUERY_ERROR; the server's own time limit (code 159) is TIMEOUT. A
    failed request keeps the connection category."""

    class _Failing(_Client):
        def query_column_block_stream(self, query: str, parameters: Any = None, settings: Any = None) -> _Stream:
            if where == "open":
                raise error
            return super().query_column_block_stream(query, parameters, settings)

    def blocks(state: dict[str, Any]) -> Iterator[list[tuple[Any, ...]]]:
        yield [(1,)]
        raise error

    conn, _state = _make(monkeypatch, tmp_path, client_cls=_Failing, blocks=blocks)
    with pytest.raises(ConnectorError) as info:
        conn._execute(QuerySpec(sql="SELECT v FROM t", max_rows=10))
    assert getattr(info.value, "category", None) == category
    assert conn._cancel_query_id is None


def test_f07_a_failed_connect_stays_a_connection_error(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    conn, _state = _make(monkeypatch, tmp_path)

    def refused(**_kw: Any) -> Any:
        raise _ServerError("Code: 516. DB::Exception: default: Authentication failed", code=516)

    monkeypatch.setattr(ch_module, "open_module", lambda *_a, **_k: types.SimpleNamespace(get_client=refused))
    with pytest.raises(ConnectorError) as info:
        conn._execute(QuerySpec(sql="SELECT v FROM t", max_rows=10))
    assert getattr(info.value, "category", None) is None


def test_f07_read_timeout_follows_the_hard_timeout(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    """send_receive_timeout was the driver's 300 s default, five times the
    policy's hard ceiling; a sub-second connect timeout truncated to 0."""
    conn, state = _make(monkeypatch, tmp_path, connect_timeout_seconds=0.5)
    conn._connect()
    kw = state["get_client_kw"][-1]
    assert kw["send_receive_timeout"] == math.ceil(conn.policy.hard_query_timeout_seconds) + 5
    assert kw["connect_timeout"] == 1


# --- F10: identifier quoting ---------------------------------------------------

_HOSTILE_NAMES = [
    "a\\",
    'a\\"b',
    "x`y",
    'a"b',
    "c\\` , y",
    "zürich straße",
    'x\\", (SELECT count() FROM telecom.subscribers) AS leaked, "y',
    "x\\`, (SELECT count() FROM telecom.subscribers) AS leaked, `y",
]


@pytest.mark.parametrize("name", _HOSTILE_NAMES)
def test_f10_quoted_identifier_is_exactly_one_alias(tmp_path: Any, name: str) -> None:
    """The ANSI quoting inherited from base only doubled '"'; ClickHouse also
    reads a backslash as an escape inside a quoted identifier, so a catalog
    name containing or ending in '\\' closed the identifier early and the rest
    was parsed as SQL."""
    quoted = _connector(tmp_path).quote_identifier(name)
    tree = sqlglot.parse_one(f"SELECT 1 AS {quoted}", read="clickhouse")
    assert [s.alias for s in tree.expressions] == [name]


def _shape(sql: str) -> tuple[set[tuple[str, str]], list[str]]:
    tree = sqlglot.parse_one(sql, read="clickhouse")
    tables = {(t.db, t.name) for t in tree.find_all(exp.Table)}
    return tables, [s.alias_or_name for s in tree.expressions]


@pytest.mark.parametrize("name", _HOSTILE_NAMES)
def test_f10_generated_discovery_sql_keeps_its_shape(tmp_path: Any, name: str) -> None:
    """Sample, top-values and value-search SQL go to run_query WITHOUT the
    guard; a hostile column/table name must not add columns or tables."""
    conn = _connector(tmp_path)
    cols = ["id", name]
    sample = conn.build_sample_query("telecom", name, cols, 20)
    assert _shape(sample) == ({("telecom", name)}, cols)
    search = conn.build_search_query("telecom", name, cols, "1 = 1", 5)
    assert _shape(search) == ({("telecom", name)}, cols)
    top = conn.build_top_values_query(sample, name, 5)
    tables, projected = _shape(top)
    assert tables == {("telecom", name)}
    assert projected == ["v", "cnt"]
    outer_col = sqlglot.parse_one(top, read="clickhouse").expressions[0].this
    assert isinstance(outer_col, exp.Column) and outer_col.name == name


@pytest.mark.parametrize("name", ["pct_%", "100%", "a%%b", "%(p1)s", "x%sy"])
def test_f10_percent_in_a_catalog_name_survives_client_side_binding(tmp_path: Any, name: str) -> None:
    """clickhouse-connect binds dict parameters client-side with Python
    %-formatting over the whole statement, quoted identifiers included: a
    column named 'pct_%' failed the value search of its table ('unsupported
    format character')."""
    from clickhouse_connect.driver.binding import bind_query

    conn = _connector(tmp_path)
    expr = f"LOWER({conn.text_expression(conn.quote_identifier(name), 'text')})"
    where = conn.like_predicate(expr, conn.placeholder(1))
    sql = conn.build_search_query("telecom", name, ["id", name], where, 5)
    final, server_params = bind_query(sql, conn.pack_parameters(["%zürich%"]))
    assert server_params == {}
    assert _shape(str(final)) == ({("telecom", name)}, ["id", name])
    like = sqlglot.parse_one(str(final), read="clickhouse").find(exp.Like)
    assert like is not None and like.expression.this == "%zürich%"
    column = like.this.find(exp.Column)
    assert column is not None and column.name == name


def test_f10_search_sql_without_placeholders_is_left_alone(tmp_path: Any) -> None:
    """No parameters, no %-formatting: a doubled '%' would reach the server."""
    conn = _connector(tmp_path)
    sql = conn.build_search_query("telecom", "t", ["pct_%"], "1 = 1", 5)
    assert "`pct_%`" in sql and "%%" not in sql


# --- F83: Unicode case folding in value search --------------------------------


def test_f83_text_expression_folds_unicode(tmp_path: Any) -> None:
    """ClickHouse lower() folds ASCII only ('ZÜRICH' -> 'zÜrich') while the
    needle is folded in Python with full Unicode, so the match never hit.
    lowerUTF8 refuses FixedString ('string'; 'text' is String) and UUID, Enum
    and IP arguments, so everything but String goes through toString(), which
    also drops a FixedString's trailing zero bytes (live 2026-09-27:
    lowerUTF8(toString(toFixedString('AB', 3))) = 'ab')."""
    conn = _connector(tmp_path)
    assert conn.text_expression("`c`", "text") == "lowerUTF8(`c`)"
    for portable in ("string", "uuid", "enum", "inet"):
        assert conn.text_expression("`c`", portable) == "lowerUTF8(toString(`c`))", portable


def test_f83_value_search_expression_never_folds_a_fixedstring_directly(tmp_path: Any) -> None:
    """The regression the first fix introduced: every portable 'string'
    column went to lowerUTF8(), which ClickHouse refuses for FixedString, so
    a table with a FixedString column (country codes, hashes) failed its
    whole value-search statement."""
    from universal_db_mcp.discovery.types import portable_type

    conn = _connector(tmp_path)
    for ch_type in ("FixedString(2)", "Nullable(FixedString(2))", "LowCardinality(Nullable(FixedString(3)))"):
        portable = portable_type("clickhouse", ch_type)
        assert portable.kind == "string"
        expr = conn.text_expression("`c`", portable.name)
        assert expr.startswith("lowerUTF8(toString("), (ch_type, expr)


# --- F38 / F88: db_explain -----------------------------------------------------


class _Plan:
    result_rows = [("Expression",), ("  ReadFromMergeTree (d.t)",)]


def test_f38_explain_is_serialized_killable_and_read_bounded(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    """EXPLAIN never pinned a query_id nor took the exec lock, so a timed-out
    EXPLAIN (ClickHouse runs scalar subqueries while planning) could not be
    KILLed and ran to max_execution_time."""
    seen: dict[str, Any] = {}

    def on_query(client: _Client, sql: str) -> Any:
        conn = state["conn"]
        seen["params"] = dict(client.params)
        seen["locked"] = conn._exec_lock.locked()
        seen["cancelled"] = conn.cancel_current()  # the deadline hook, mid-flight
        return _Plan()

    conn, state = _make(monkeypatch, tmp_path, on_query=on_query)
    plan = conn.explain("SELECT (SELECT max(a) FROM t) AS m", analyze=False)
    assert plan["raw"] == _Plan.result_rows
    assert "cleanup_warning" not in plan
    qid = seen["params"]["query_id"]
    assert qid and seen["cancelled"] is True
    assert state["commands"] == [(KILL_SQL, {"qid": qid})]
    assert seen["locked"] is True, "EXPLAIN shares the connector's cancel slot: it must hold _exec_lock"
    assert seen["params"]["max_rows_to_read"] == 1000
    assert seen["params"]["read_overflow_mode"] == "throw"
    assert conn._cancel_query_id is None
    assert state["closed"] >= 2  # the explain client and the KILL client


def test_f38_cancel_slot_is_cleared_when_explain_raises(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    def on_query(client: _Client, sql: str) -> Any:
        raise _ServerError("Code: 60. DB::Exception: Unknown table", code=60)

    conn, state = _make(monkeypatch, tmp_path, on_query=on_query)
    with pytest.raises(ConnectorError, match="Unknown table"):
        conn.explain("SELECT a FROM t", analyze=False)
    assert conn._cancel_query_id is None
    assert not conn._exec_lock.locked()


@pytest.mark.parametrize(
    "error",
    [
        _ServerError("Received ClickHouse exception, code: 158", code=158),
        _ServerError("Code: 158. DB::Exception: Limit for rows (controlled by 'max_rows_to_read' setting) exceeded"),
    ],
)
def test_f38_a_reading_explain_is_refused_clearly(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any, error: Exception
) -> None:
    def on_query(client: _Client, sql: str) -> Any:
        raise error

    conn, _state = _make(monkeypatch, tmp_path, on_query=on_query)
    with pytest.raises(NotImplementedError, match="scalar subqueries") as info:
        conn.explain("SELECT (SELECT sum(x) FROM t) AS s", analyze=False)
    assert "db_query" in str(info.value)
    assert conn._cancel_query_id is None


@pytest.mark.parametrize(
    ("server", "ceiling"),
    [
        ({}, 1000),
        # the account's own ceiling is tighter: that is the one that fired
        ({"max_rows_to_read": _Setting("500")}, 500),
        # readonly=1 takes no SET: only the profile's ceiling can fire
        ({"readonly": _Setting("1", 1), "max_rows_to_read": _Setting("200")}, 200),
    ],
)
def test_f38_refusal_names_the_read_ceiling_that_fired(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any, server: dict[str, _Setting], ceiling: int
) -> None:
    def on_query(client: _Client, sql: str) -> Any:
        raise _ServerError("Code: 158. DB::Exception: Limit for rows exceeded", code=158)

    conn, _state = _make(monkeypatch, tmp_path, server=server, on_query=on_query)
    with pytest.raises(NotImplementedError, match=f"more than {ceiling} rows"):
        conn.explain("SELECT (SELECT sum(x) FROM t) AS s", analyze=False)


def test_f38_capability_note_does_not_promise_a_ceiling_readonly_1_cannot_take(tmp_path: Any) -> None:
    notes = [lim.detail for lim in _connector(tmp_path).capabilities().limitations if lim.scope == "explain"]
    note = next(n for n in notes if "subqueries" in n and "planning" in n)
    assert "where the account profile accepts" in note.lower()
    assert "readonly=1" in note and "warning" in note
    # every EXPLAIN, not only one whose text shows a subquery (a view hides it)
    assert "every EXPLAIN" in note and "view" in note
    assert "query_plan_optimize_join_order_limit=0" in note and "written order" in note


def test_f38_readonly_1_profile_explains_with_a_warning(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    """readonly=1 rejects the read ceiling: say so instead of failing."""
    seen: dict[str, Any] = {}

    def on_query(client: _Client, sql: str) -> Any:
        seen["params"] = dict(client.params)
        return _Plan()

    conn, _state = _make(monkeypatch, tmp_path, server={"readonly": _Setting("1", 1)}, on_query=on_query)
    plan = conn.explain("SELECT (SELECT max(a) FROM t) AS m", analyze=False)
    assert plan["raw"] == _Plan.result_rows
    assert "max_rows_to_read" not in seen["params"]
    assert "scalar subqueries" in plan["cleanup_warning"]
    # the statement text cannot tell: a view may hold the subquery
    assert "scalar subqueries" in conn.explain("SELECT a FROM t ORDER BY a", analyze=False)["cleanup_warning"]
    # the profile's own ceiling, at or under ours, is a ceiling too
    conn, _state = _make(
        monkeypatch, tmp_path, on_query=on_query,
        server={"readonly": _Setting("1", 1), "max_rows_to_read": _Setting("500", 1)},
    )
    assert "cleanup_warning" not in conn.explain("SELECT a FROM t", analyze=False)


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT a.x FROM db.big a JOIN db.small b ON a.k = b.k",
        "SELECT x FROM db.big WHERE k IN (1, 2, 3) ORDER BY x",
        "SELECT k, count() FROM db.big GROUP BY k",
        "SELECT x FROM db.big WHERE note = 'IN t'",
        # review 2: the view's own definition holds the scalar subquery
        "SELECT s, 'tag' AS t FROM db.v_scalar",
        # review 2: ClickHouse '#' / '#!' comments and heredocs hid the
        # subquery from the literal-stripping regex, which then saw one SELECT
        "SELECT 1 AS a, # it's\n (SELECT sum(x) FROM db.big) AS s, 'x' AS t",
        "SELECT 1 AS a, #! it's\n (SELECT sum(x) FROM db.big) AS s, 'x' AS t",
        "SELECT $$'$$ AS q, (SELECT sum(x) FROM db.big) AS s, $$'$$ AS r",
        "SELECT $tag$'$tag$ AS q, (SELECT sum(x) FROM db.big) AS s, $tag$'$tag$ AS r",
    ],
)
def test_f38_every_explain_is_planned_under_the_read_ceiling(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any, sql: str
) -> None:
    """The fix-up applied the ceiling only where a regex over the statement
    text saw a subquery; ClickHouse's own lexer ('#' comments, heredocs) and
    views hid it, and those EXPLAINs read the whole table again (live, review
    2: read_rows 250002, no warning). No text heuristic decides it now."""
    seen: dict[str, Any] = {}

    def on_query(client: _Client, sql: str) -> Any:
        seen["params"] = dict(client.params)
        return _Plan()

    conn, _state = _make(monkeypatch, tmp_path, on_query=on_query)
    plan = conn.explain(sql, analyze=False)
    assert seen["params"]["max_rows_to_read"] == 1000
    assert seen["params"]["read_overflow_mode"] == "throw"
    assert "cleanup_warning" not in plan
    assert seen["params"]["query_id"], "still killable by the deadline hook"


_JOIN_REFUSED = "Code: 158. DB::Exception: Limit for rows (controlled by 'max_rows_to_read' setting) exceeded"


def test_f38_a_join_refused_on_its_row_estimate_is_planned_in_written_order(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    """ClickHouse 26.3 checks max_rows_to_read against its row estimates
    while reordering joins: under the read ceiling a plain JOIN EXPLAIN over
    250k rows was refused although planning read nothing (live). With
    reordering off it plans, and a scalar subquery is still refused (live,
    review 2). The plan says it shows the written join order."""
    sent: list[dict[str, Any]] = []

    def on_query(client: _Client, sql: str) -> Any:
        sent.append(dict(client.params))
        if "query_plan_optimize_join_order_limit" not in client.params:
            raise _ServerError(_JOIN_REFUSED, code=158)
        return _Plan()

    conn, _state = _make(
        monkeypatch, tmp_path, server={"query_plan_optimize_join_order_limit": _Setting("10")}, on_query=on_query
    )
    plan = conn.explain("SELECT a.x FROM db.big a JOIN db.small b ON a.k = b.k", analyze=False)
    assert plan["raw"] == _Plan.result_rows
    assert [p.get("query_plan_optimize_join_order_limit") for p in sent] == [None, 0]
    assert all(p["max_rows_to_read"] == 1000 and p["read_overflow_mode"] == "throw" for p in sent)
    assert "written order" in plan["cleanup_warning"]
    assert "may have read" not in plan["cleanup_warning"]


def test_f38_a_plan_the_ceiling_allows_keeps_join_reordering(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    seen: dict[str, Any] = {}

    def on_query(client: _Client, sql: str) -> Any:
        seen["params"] = dict(client.params)
        return _Plan()

    conn, _state = _make(
        monkeypatch, tmp_path, server={"query_plan_optimize_join_order_limit": _Setting("10")}, on_query=on_query
    )
    plan = conn.explain("SELECT a.x FROM db.small a JOIN db.small b ON a.k = b.k", analyze=False)
    assert "query_plan_optimize_join_order_limit" not in seen["params"] and "cleanup_warning" not in plan


@pytest.mark.parametrize(
    "server",
    [
        # a server without join reordering does not know the setting (it would fail the query)
        {},
        # pinned by the profile: sending it would fail the query
        {"query_plan_optimize_join_order_limit": _Setting("10", 1)},
    ],
)
def test_f38_a_read_refusal_with_no_reordering_to_turn_off_is_final(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any, server: dict[str, _Setting]
) -> None:
    calls: list[dict[str, Any]] = []

    def on_query(client: _Client, sql: str) -> Any:
        calls.append(dict(client.params))
        raise _ServerError(_JOIN_REFUSED, code=158)

    conn, _state = _make(monkeypatch, tmp_path, server=server, on_query=on_query)
    with pytest.raises(NotImplementedError, match="more than 1000 rows"):
        conn.explain("SELECT (SELECT sum(x) FROM db.big) AS s", analyze=False)
    assert len(calls) == 1


def test_f38_a_scalar_subquery_stays_refused_with_reordering_off(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    calls: list[dict[str, Any]] = []

    def on_query(client: _Client, sql: str) -> Any:
        calls.append(dict(client.params))
        raise _ServerError(_JOIN_REFUSED, code=158)

    conn, _state = _make(
        monkeypatch, tmp_path, server={"query_plan_optimize_join_order_limit": _Setting("10")}, on_query=on_query
    )
    with pytest.raises(NotImplementedError, match="more than 1000 rows"):
        conn.explain("SELECT (SELECT sum(x) FROM db.big) AS s", analyze=False)
    assert [c.get("query_plan_optimize_join_order_limit") for c in calls] == [None, 0]
    assert conn._cancel_query_id is None


@pytest.mark.parametrize(
    "error",
    [
        "Code: 452. DB::Exception: Setting max_rows_to_read shouldn't be less than 100000. "
        "(SETTING_CONSTRAINT_VIOLATION)",
        "Code: 164. DB::Exception: Cannot modify 'read_overflow_mode' setting in readonly mode. (READONLY)",
    ],
)
def test_f38_a_ceiling_the_profile_refuses_plans_with_a_warning(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any, error: str
) -> None:
    """Every EXPLAIN now carries the ceiling, so a profile constraint that
    refuses it (not visible in system.settings) would fail every EXPLAIN:
    plan without it and say planning may have read data, as on readonly=1."""
    sent: list[dict[str, Any]] = []

    def on_query(client: _Client, sql: str) -> Any:
        sent.append(dict(client.params))
        if "max_rows_to_read" in client.params:
            raise _ServerError(error, code=int(error.split(".")[0].split()[1]))
        return _Plan()

    conn, _state = _make(monkeypatch, tmp_path, on_query=on_query)
    plan = conn.explain("SELECT a FROM t", analyze=False)
    assert plan["raw"] == _Plan.result_rows
    assert "may have read table data" in plan["cleanup_warning"]
    assert len(sent) == 2 and not {"max_rows_to_read", "read_overflow_mode"} & set(sent[1])
    assert sent[1]["query_id"] and conn._cancel_query_id is None


def test_f38_a_break_ceiling_is_no_ceiling(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    """Under read_overflow_mode 'break' planning reads on (live, review 2: a
    scalar-subquery EXPLAIN at max_rows_to_read=1000 'break' read 249621
    rows): a profile that pins 'break' gets the warning."""
    seen: dict[str, Any] = {}

    def on_query(client: _Client, sql: str) -> Any:
        seen["params"] = dict(client.params)
        return _Plan()

    conn, _state = _make(
        monkeypatch, tmp_path, server={"read_overflow_mode": _Setting("break", 1)}, on_query=on_query
    )
    plan = conn.explain("SELECT a FROM t", analyze=False)
    assert "read_overflow_mode" not in seen["params"]
    assert "may have read table data" in plan["cleanup_warning"]


def test_f38_the_statements_own_refusal_is_reported_as_its_own(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    calls: list[str] = []

    def on_query(client: _Client, sql: str) -> Any:
        calls.append(sql)
        raise _ServerError("Code: 164. DB::Exception: Cannot execute query in readonly mode. (READONLY)", 164)

    conn, _state = _make(monkeypatch, tmp_path, on_query=on_query)
    with pytest.raises(ConnectorError, match="readonly mode") as info:
        conn.explain("SELECT a FROM t", analyze=False)
    assert len(calls) == 2, "one retry without the ceiling, then the statement's own error"
    assert getattr(info.value, "category", None) == "QUERY_ERROR"


def test_f38_explain_statement_errors_are_query_errors(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    def on_query(client: _Client, sql: str) -> Any:
        raise _ServerError("Code: 47. DB::Exception: Unknown expression identifier `nosuchcol`", code=47)

    conn, _state = _make(monkeypatch, tmp_path, on_query=on_query)
    with pytest.raises(ConnectorError, match="Unknown expression") as info:
        conn.explain("SELECT nosuchcol FROM t", analyze=False)
    assert getattr(info.value, "category", None) == "QUERY_ERROR"


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT (SELECT sum(x) FROM db.big) AS s",
        "SELECT x FROM db.big WHERE k IN (SELECT k FROM db.small)",
        "SELECT x FROM db.big WHERE k IN db.small",
        "WITH (SELECT avg(x) FROM db.big) AS m SELECT x FROM db.big WHERE x > m",
        "SELECT x FROM db.big WHERE k GLOBAL IN db.small",
    ],
)
def test_f38_statements_whose_planning_may_read_keep_the_ceiling(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any, sql: str
) -> None:
    seen: dict[str, Any] = {}

    def on_query(client: _Client, sql: str) -> Any:
        seen["params"] = dict(client.params)
        return _Plan()

    conn, _state = _make(monkeypatch, tmp_path, on_query=on_query)
    conn.explain(sql, analyze=False)
    assert seen["params"]["max_rows_to_read"] == 1000
    assert seen["params"]["read_overflow_mode"] == "throw"


def test_f88_explain_reaches_the_engine_as_written(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    """query_limit made the driver append 'LIMIT 10000' to 'EXPLAIN SELECT ...
    ORDER BY ...' (no LIMIT): the plan returned was a top-N sort."""
    from clickhouse_connect.driver.query import QueryContext

    sent: list[str] = []

    def on_query(client: _Client, sql: str) -> Any:
        ctx = QueryContext(query=sql)  # what the driver's _prep_query does
        limit = f"\n LIMIT {client.query_limit}" if ctx.is_select and not ctx.has_limit and client.query_limit else ""
        sent.append(ctx.final_query + limit)
        return _Plan()

    conn, _state = _make(monkeypatch, tmp_path, on_query=on_query)
    conn.explain("SELECT a FROM t ORDER BY a", analyze=False)
    assert sent == ["EXPLAIN SELECT a FROM t ORDER BY a"]


@pytest.mark.anyio
async def test_f38_db_explain_reports_the_refusal_as_a_capability(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End to end: the code-158 refusal reaches the agent as
    CAPABILITY_UNSUPPORTED with the reason, not as a connection error."""
    from universal_db_mcp.config import load_resolved
    from universal_db_mcp.server import AppContext, build_server

    class _Res:
        def __init__(self, rows: list[Any], names: list[str]) -> None:
            self.result_rows = rows
            self.column_names = names

    class _MetaClient:
        def __init__(self) -> None:
            self.params: dict[str, Any] = {}
            self.query_limit = 0

        def set_client_setting(self, name: str, value: object) -> None:
            self.params[name] = value

        def query(self, sql: str, parameters: object = None) -> _Res:
            if sql.startswith("SELECT database, name, engine"):
                return _Res([["main", "t", "MergeTree", 1]], ["database", "name", "engine", "total_rows"])
            if sql == "SELECT 1":
                return _Res([["1"]], ["v"])
            if sql.startswith("EXPLAIN"):
                raise _ServerError("Code: 158. DB::Exception: Limit for rows exceeded", code=158)
            raise AssertionError(sql)

        def command(self, cmd: str, parameters: object = None) -> str:
            return "ok"

        def close(self) -> None:
            pass

    monkeypatch.setattr(
        ch_module, "open_module", lambda *_a, **_k: types.SimpleNamespace(get_client=lambda **kw: _MetaClient())
    )
    monkeypatch.setenv("UDBMCP_TEST_U", "x")
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(
        f"""
application:
  airgapped: true
  transport: stdio
  metadata_cache_path: {tmp_path}/meta-cache.sqlite
  audit_path: {tmp_path}/audit.jsonl
  telemetry_enabled: false

security:
  read_only: true
  default_deny_objects: true
  require_remote_tls: false
  max_concurrent_queries: 4

connections:
  ch1:
    type: clickhouse
    host: 127.0.0.1
    port: 8124
    database: main
    username_env: UDBMCP_TEST_U
""",
        encoding="utf-8",
    )
    cfg, resolved = load_resolved(cfg_path)
    mcp = build_server(AppContext(cfg, resolved))
    with pytest.raises(ToolError) as info:
        await mcp.call_tool(
            "db_explain", {"connection_id": "ch1", "sql": "EXPLAIN SELECT (SELECT count() FROM t) AS s"}
        )
    msg = str(info.value)
    assert "CAPABILITY_UNSUPPORTED" in msg and "scalar subqueries" in msg, msg


# --- F07 residual: a column the block declares larger than the budget ---------


def _declared_block(type_name: str, declared: int, data: bytes = b"\x01" * (2 << 20)) -> bytes:
    """One row of an Array (or Map) column whose single offset declares
    ``declared`` elements, then the elements' bytes as they stream: what the
    server sends for 'SELECT arrayMap(x -> <value>, range(<declared>))'."""
    head = _leb128(1) + _leb128(1) + _leb128(1) + b"a" + _leb128(len(type_name)) + type_name.encode()
    return head + declared.to_bytes(8, "little") + data


@pytest.mark.parametrize(
    "type_name",
    [
        "Array(String)", "Array(Nullable(String))", "Array(FixedString(1))", "Array(Array(UInt8))",
        "Array(UInt8)", "Array(UUID)", "Array(DateTime)", "Array(Date)", "Array(IPv4)",
        "Array(Nullable(UInt32))", "Array(Tuple())", "Map(String, String)",
    ],
)
def test_f07_a_column_declared_past_the_budget_is_refused_before_the_driver_allocates_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any, type_name: str
) -> None:
    """Review round 3: clickhouse-connect allocates for the element count a
    block declares before it reads one element (8 bytes per String, 43 per
    UUID), while the stream budget meters wire bytes only. 'SELECT
    arrayMap(x -> splitByChar(',', repeat(',', 999999)), ...)' (110
    characters) grew the server by 398 MB at max_rows=10. Every element
    costs at least one byte on the wire, so a count the rest of the budget
    cannot carry is refused before the allocation."""
    import tracemalloc

    _wide_blocks_budget(monkeypatch)  # 1 MiB
    body = _declared_block(type_name, 5_000_000)
    conn, state = _make(monkeypatch, tmp_path, client_cls=_NativeClient, body=body)
    tracemalloc.start()
    try:
        with pytest.raises(ConnectorError, match="even on 1-row blocks") as info:
            conn._execute(QuerySpec(sql="SELECT a FROM t", max_rows=10, max_response_bytes=100_000))
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert getattr(info.value, "category", None) == "LIMIT_EXCEEDED"
    assert peak < 8 * 1024 * 1024, f"{peak / 1e6:.1f} MB traced for a 5M-element declaration"
    assert [c for c, _p in state["commands"]] == [KILL_SQL] * len(state["streams"]), "KILLed at each attempt"
    for wire in state["wires"]:
        assert wire.closed and wire.drained == 0


def test_f07_columns_within_the_budget_decode_as_before(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    body = _declared_block("Array(String)", 3, b"".join(_leb128(1) + b"x" for _ in range(3)))
    conn, _state = _make(monkeypatch, tmp_path, client_cls=_NativeClient, body=body)
    out = conn._execute(QuerySpec(sql="SELECT a FROM t", max_rows=10))
    assert out.rows == [['["x", "x", "x"]']] and out.truncated is False


def test_f07_the_read_guard_leaves_a_stream_without_a_budget_alone() -> None:
    """Metadata clients read through the same driver class and carry no
    budget: their reads pass straight through."""
    ch_module._guard_column_reads()
    source = types.SimpleNamespace(gen=iter([_native_block(["a", "b"])]), response=None, close=lambda: None)
    buffer = _backendclient.RespBuffCls(source)
    assert type(buffer).__name__ == "_AdmittingBuffer"
    with NativeTransform.parse_response(buffer, QueryContext()).column_block_stream as stream:
        blocks = list(stream)
    assert [list(column) for column in blocks[0]] == [["a", "b"]]


# --- F07 residual, round 2: values that decode far past their wire size -------


def _array_row_block(*columns: tuple[str, int, bytes]) -> bytes:
    """One Native block of one row, a column ``Array(<element>)`` for each
    ``(element, count, one element's bytes)``: the row holds ``count``
    copies of that element, the way the server sends an arrayMap() result."""
    out = bytearray(_leb128(len(columns)) + _leb128(1))
    for i, (element, count, value) in enumerate(columns):
        name, type_name = f"c{i}", f"Array({element})"
        out += _leb128(len(name)) + name.encode() + _leb128(len(type_name)) + type_name.encode()
        out += count.to_bytes(8, "little") + value * count
    return bytes(out)


@pytest.mark.parametrize(
    ("element", "count", "value"),
    [
        ("String", 1_000_000, b"\x00"),  # empty strings: a list slot each, for one wire byte
        ("Decimal(9, 2)", 250_000, (123).to_bytes(4, "little")),  # a Decimal object per 4 wire bytes
        ("Bool", 1_000_000, b"\x01"),
        ("Tuple()", 1_000_000, b"\x00"),
        ("Date", 500_000, (19_000).to_bytes(2, "little")),
        ("Array(UInt8)", 120_000, bytes(8)),  # 120k empty inner arrays: a list object per offset
    ],
)
def test_f07_values_that_decode_far_past_their_wire_size_are_refused_before_they_are_built(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any, element: str, count: int, value: bytes
) -> None:
    """Review round 4: admission compared a column read's wire bytes with the
    stream budget, but the driver builds 8 to 112 bytes of Python objects per
    wire byte. One ~116-character statement within the default 8 MiB budget
    ('SELECT arrayMap(o -> arrayMap(x -> x, splitByChar(...)), ...)', 7.9M
    empty strings) still grew the server by 190 MB, a Decimal32 variant by
    236 MB. Each read is now admitted on the objects it builds as well."""
    import tracemalloc

    _wide_blocks_budget(monkeypatch)  # 1 MiB: each column below fits it on the wire
    body = _array_row_block((element, count, value))
    assert len(body) < 1 << 20
    conn, state = _make(monkeypatch, tmp_path, client_cls=_NativeClient, body=body)
    tracemalloc.start()
    try:
        with pytest.raises(ConnectorError, match="even on 1-row blocks") as info:
            conn._execute(QuerySpec(sql="SELECT a FROM t", max_rows=1, max_response_bytes=100_000))
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert getattr(info.value, "category", None) == "LIMIT_EXCEEDED"
    assert "MiB" in str(info.value) and "decode" in str(info.value), str(info.value)
    assert peak < 3 * 1024 * 1024, f"{peak / 1e6:.1f} MB traced for {count} x {element}"
    for wire in state["wires"]:
        assert wire.closed and wire.drained == 0


def test_f07_the_object_budget_counts_every_column_of_a_block(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    """Ten columns that each build a quarter of the object budget are one
    block: all ten are alive when its first row is read."""
    _wide_blocks_budget(monkeypatch)
    column = ("Date", 20_000, (19_000).to_bytes(2, "little"))
    conn, _state = _make(monkeypatch, tmp_path, client_cls=_NativeClient, body=_array_row_block(*[column] * 10))
    with pytest.raises(ConnectorError, match="even on 1-row blocks"):
        conn._execute(QuerySpec(sql="SELECT a FROM t", max_rows=1, max_response_bytes=100_000))
    # three of them fit
    conn, _state = _make(monkeypatch, tmp_path, client_cls=_NativeClient, body=_array_row_block(*[column] * 3))
    out = conn._execute(QuerySpec(sql="SELECT a FROM t", max_rows=1, max_response_bytes=100_000, max_cell_bytes=64))
    assert len(out.rows) == 1 and len(out.rows[0]) == 3


def test_f07_the_object_budget_is_counted_per_block(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    """A block's objects are released once its rows were read: a result of
    many blocks that each fit streams whole, however much it builds in all."""
    _wide_blocks_budget(monkeypatch)
    block = _array_row_block(*[("Date", 20_000, (19_000).to_bytes(2, "little"))] * 3)
    conn, _state = _make(monkeypatch, tmp_path, client_cls=_NativeClient, body=block * 8)
    out = conn._execute(QuerySpec(sql="SELECT a FROM t", max_rows=10, max_response_bytes=100_000, max_cell_bytes=64))
    assert len(out.rows) == 8 and not any("byte limit" in w for w in out.warnings), out.warnings


def test_f07_plain_numeric_columns_are_not_charged_as_objects(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    """A top-level numeric column stays one compact array until its rows are
    read one at a time: a 1000-row block of 100 UInt64 columns (800 KB) is
    what it weighs on the wire, not 100k Python ints."""
    _wide_blocks_budget(monkeypatch)
    rows, cols = 1000, 100
    out_block = bytearray(_leb128(cols) + _leb128(rows))
    for i in range(cols):
        out_block += _leb128(len(f"c{i}")) + f"c{i}".encode() + _leb128(6) + b"UInt64" + bytes(8 * rows)
    conn, state = _make(monkeypatch, tmp_path, client_cls=_NativeClient, body=bytes(out_block))
    out = conn._execute(QuerySpec(sql="SELECT * FROM t", max_rows=5, max_response_bytes=100_000))
    assert len(out.rows) == 5 and len(state["streams"]) == 1


def test_f07_a_numeric_column_declared_past_the_wire_budget_is_refused_before_it_is_allocated(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    """Wave-3 review (I14): a top-level numeric column is charged no object
    bytes (above), so only the wire check in _StreamBudget.admit keeps the
    driver from allocating the size its block declares before the byte meter
    sees a chunk. 5M UInt64 rows declare 40 MB against a 1 MiB budget, and
    the driver's buffer reserves that much for the read before it takes a
    byte: with the check removed this test traced 174 MB, and live a nested
    arrayJoin grew the server by +25 MB instead of +9 MB."""
    import tracemalloc

    _wide_blocks_budget(monkeypatch)  # 1 MiB
    declared = 5_000_000
    body = _leb128(1) + _leb128(declared) + _leb128(1) + b"v" + _leb128(6) + b"UInt64" + bytes(2 << 20)
    conn, state = _make(monkeypatch, tmp_path, client_cls=_NativeClient, body=body)
    tracemalloc.start()
    try:
        with pytest.raises(ConnectorError, match="even on 1-row blocks") as info:
            conn._execute(QuerySpec(sql="SELECT v FROM t", max_rows=10, max_response_bytes=100_000))
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert getattr(info.value, "category", None) == "LIMIT_EXCEEDED"
    assert "decodes" not in str(info.value), "the wire check refused it, not the object budget"
    assert peak < 8 * 1024 * 1024, f"{peak / 1e6:.1f} MB traced for a {8 * declared / 1e6:.0f} MB declaration"
    for wire in state["wires"]:
        assert wire.closed and wire.drained == 0


# --- F26 on ClickHouse: an allowed system database must be listed -------------

_CH_CATALOG = [
    ("INFORMATION_SCHEMA", "TABLES", "View", None), ("information_schema", "tables", "View", None),
    ("system", "one", "SystemOne", None), ("system", "tables", "SystemTables", None),
    ("telecom", "cdr", "MergeTree", 250_000),
]


def _ch_catalog(_client: _Client, sql: str) -> Any:
    """system.tables as the server filters it: the quoted databases of the
    statement's NOT IN list are left out."""
    if sql == "SELECT 1":
        return types.SimpleNamespace(result_rows=[(1,)])
    hidden = sql.split("NOT IN (", 1)[1].split(")", 1)[0].replace("'", "").split(", ") if "NOT IN" in sql else []
    return types.SimpleNamespace(result_rows=[r for r in _CH_CATALOG if r[0] not in hidden])


@pytest.mark.parametrize(
    ("opened", "listed"),
    [
        # the default security.allowed_system_schemas: [information_schema]
        (None, {"INFORMATION_SCHEMA", "information_schema", "telecom"}),
        (["information_schema", "system"], {"INFORMATION_SCHEMA", "information_schema", "system", "telecom"}),
        ([], {"telecom"}),
    ],
)
def test_f26_clickhouse_lists_the_system_databases_the_administrator_allowed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any, opened: list[str] | None, listed: set[str]
) -> None:
    """Review round 4: list_tables always left out system, INFORMATION_SCHEMA
    and information_schema, and the resolver permits only listed objects:
    live, with allowed_system_schemas [information_schema, system], 'SELECT
    name FROM system.one' was 'could not be resolved to a permitted object'."""
    conn, _state = _make(monkeypatch, tmp_path, on_query=_ch_catalog)
    security = SecurityConfig() if opened is None else SecurityConfig(allowed_system_schemas=opened)
    conn.policy = EffectivePolicy.build(security, conn.connection)
    assert {t.schema for t in conn.list_tables(None, {"table", "view"}, None)} == listed


def test_f26_clickhouse_lists_the_system_databases_after_the_servers_own(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    """Review round 5: system.tables sorted by database puts both
    INFORMATION_SCHEMA spellings (and system) before telecom, so a default
    db_list_tables opened with 70 catalog views. They now follow the
    server's own databases, in the server's order."""
    conn, _state = _make(monkeypatch, tmp_path, on_query=_ch_catalog)
    conn.policy = EffectivePolicy.build(
        SecurityConfig(allowed_system_schemas=["information_schema", "system"]), conn.connection
    )
    assert [(t.schema, t.name) for t in conn.list_tables(None, {"table", "view"}, None)] == [
        ("telecom", "cdr"), ("INFORMATION_SCHEMA", "TABLES"), ("information_schema", "tables"),
        ("system", "one"), ("system", "tables"),
    ]
