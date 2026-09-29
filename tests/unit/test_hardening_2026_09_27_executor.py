"""Executor hardening regressions (2026-09-27 review: F11, F12, F39).

- F11: a request that fails, is cancelled or never reaches its worker thread
  must return its global concurrency token; leaked tokens used to take every
  connection offline with LIMIT_EXCEEDED until restart.
- F12: a connection whose driver call was abandoned past its deadline fails
  fast instead of stranding one more token per retry (AppContext rebuilds a
  new connector object for every retry of a poisoned connection).
- F39: requests queued behind a busy connection hold no global token, so an
  idle connection never waits behind them.
- Review round 1: the breaker clears on the worker thread even when the
  request's event loop has closed; a client cancel fires the cancel hook; a
  hung connect refuses every connection to that server; connector objects for
  one connection share one gate; a call that never started says so.
- Review round 2: only a connect still hanging past its connection's connect
  bound refuses the other connections to that server (a short caller-chosen
  deadline or an early client cancel that catches a normal connect does not);
  the connect-phase TIMEOUT blames the database only past that bound; a
  worker hands its token back without waiting on a stopped event loop.
- Review round 3: a connect hung past its bound gives its global token back
  and waits in a stuck-connect budget, so dead connections on several
  servers no longer take every connection offline; a full budget refuses
  connects to database servers; only abandoned workers count toward a
  server's share of the global tokens (since round 4, only at a limit of
  2); waiters wake when a connect crosses its bound; a call that gives up
  on the global limiter leaves its server open.
- Review round 4: from a limit of 3 up, every call to a server that holds
  a global token counts toward its share (checked again once the token is
  handed over), so a parallel fan-out of statements no cancel hook stops
  leaves a token for the other servers; a connect abandoned within its
  bound is parked at the bound even for requests that were already
  waiting; the stuck-connect budget has 10 slots whatever the limit, so a
  fan-out over a few dead servers does not refuse the healthy ones.
- Review round 5: at the default limit of 4, healthy calls to one server
  run three at a time (pinned); a connect bound the event loop acted on a
  clock tick early (Windows' 15.6 ms monotonic clock on Python 3.12) holds
  for every later check; one server spelled with and without its default
  port, or with a trailing dot, is one server; statements of parked
  connects that connected after all are bounded by the budget; a call woken
  for its server's share parks a connect past its bound when no alarm did.
- Integration round 2: the next request, on an event loop of its own,
  parks a connect abandoned within its bound on a loop that has closed
  since (site-check); a call in line for a global token, or waiting for its
  server's share, is refused once a connect to its server hangs even when
  the token that frees goes to another call; at-bound timings are measured
  from the bound.
- Integration round 3: a call that gives up after it took its global token
  (refused after the token wait, a deadline or client cancel before a
  worker thread starts, a token returned on a later event loop) leaves
  nothing counted against its server; a client cancel that lands while the
  timeout path waits on the cancel hook still parks a hung connect; a
  request on a later event loop is woken at the bound of a connect
  abandoned on a loop that closed since.
- Integration round 3 fix-up: a connect past its bound that completes while
  the cancel hook runs leaves the calls in line in their order; a request
  on a later event loop is woken when a token handed back to a loop that
  closed since comes back; the server's single loop schedules one at-bound
  alarm per connect however many requests come in.
- Integration round 3 fix-up 2: parking a connect wakes the calls waiting
  for its server's share, which run if it connected before they looked
  again; only a connection without a host has no database server (a
  PostgreSQL socket directory given as the host is one).
- Wave 4: an Oracle tns_alias connection is keyed on its alias, not on the
  placeholder host it never dials, and MySQL through a socket has no
  server whatever its host; a call to a hung server in line behind another
  server's call is refused at an alarm that runs a tick early.
"""

from __future__ import annotations

import asyncio
import gc
import importlib
import inspect
import math
import threading
import time
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any

import anyio
import pytest

from universal_db_mcp.connectors.base import DatabaseConnector, QuerySpec
from universal_db_mcp.errors import ToolFailure
from universal_db_mcp.models.responses import ErrorCategory
from universal_db_mcp.services import executor
from universal_db_mcp.services.executor import ExecutionService


def _open_gate() -> threading.Event:
    ev = threading.Event()
    ev.set()
    return ev


class _Fake(DatabaseConnector):
    """A driver stand-in whose calls block on ``threading.Event`` gates: the
    connect gate models a listener that accepts TCP and never answers, the
    query gate a long-running statement. ``cancel_current`` cancels nothing,
    as on Db2, MySQL and SQL Server."""

    engine = "fake"

    def __init__(
        self,
        name: str,
        *,
        connect: threading.Event | None = None,
        query: threading.Event | None = None,
        host: str | None = None,
        port: int | None = None,
        connect_timeout: float | None = None,
        engine: str | None = None,
    ) -> None:
        # DatabaseConnector.__init__ needs a resolved config; the executor only
        # reads connection.name, the id every rebuilt connector object shares,
        # and the database server address and connect bound in
        # connection.config.
        self.connection = SimpleNamespace(  # type: ignore[assignment]
            name=name,
            config=SimpleNamespace(
                type=engine or self.engine, host=host, port=port, connect_timeout_seconds=connect_timeout
            ),
        )
        self.connect_gate = connect if connect is not None else _open_gate()
        self.query_gate = query if query is not None else _open_gate()

    def _connect(self) -> object:
        self.connect_gate.wait(10)
        return object()

    def health_check(self):  # type: ignore[no-untyped-def]
        self._connect()
        return "healthy"

    def execute_query(self, spec: QuerySpec):  # type: ignore[no-untyped-def]
        self._connect()
        self.query_gate.wait(10)
        return spec.sql

    def cancel_current(self) -> bool:
        return False

    # unused abstract members
    def capabilities(self):  # type: ignore[no-untyped-def]
        raise NotImplementedError

    def list_schemas(self, *a: object, **k: object) -> list[str]:
        return []

    def list_tables(self, *a: object, **k: object) -> list[object]:
        return []

    def list_columns(self, *a: object, **k: object) -> list[object]:
        return []

    def list_views(self, *a: object, **k: object) -> list[object]:
        return []

    def list_synonyms(self, *a: object, **k: object) -> list[object]:
        return []

    def list_routines(self, *a: object, **k: object) -> list[object]:
        return []

    def get_foreign_keys(self, *a: object, **k: object) -> list[object]:
        return []

    def get_statistics(self, *a: object, **k: object) -> dict[str, object]:
        return {}

    def explain(self, *a: object, **k: object) -> dict[str, object]:
        return {}


def _borrowed(svc: ExecutionService) -> int:
    return int(svc._limiter.statistics().borrowed_tokens)


def _parked(svc: ExecutionService) -> int:
    """Connects hung past their bound that wait in the stuck-connect budget."""
    return sum(len(runs) for runs in svc._parked.values())


async def _until(predicate: Callable[[], bool], within: float = 3.0) -> bool:
    for _ in range(int(within / 0.01)):
        if predicate():
            return True
        await anyio.sleep(0.01)
    return predicate()


def _query(ran: list[str], tag: str) -> Callable[[DatabaseConnector], Any]:
    """A run_bounded fn that records that the driver call really started."""

    def fn(c: DatabaseConnector) -> Any:
        ran.append(tag)
        return c.execute_query(QuerySpec(sql=tag))

    return fn


async def _poisoned_while_queued(svc: ExecutionService, name: str) -> tuple[list[str], dict[str, ToolFailure]]:
    """F11 path A: two requests queue behind a query whose deadline fires and
    poisons the connector; both fail closed without running."""
    query = threading.Event()
    conn = _Fake(name, query=query)
    ran: list[str] = []
    failures: dict[str, ToolFailure] = {}

    async def call(tag: str, deadline: float) -> None:
        try:
            await svc.run_bounded(conn, _query(ran, tag), deadline, description=tag)
        except ToolFailure as exc:
            failures[tag] = exc

    try:
        async with anyio.create_task_group() as tg:
            tg.start_soon(call, "slow", 0.3)
            assert await _until(lambda: ran == ["slow"])
            tg.start_soon(call, "q1", 30.0)
            tg.start_soon(call, "q2", 30.0)
    finally:
        query.set()
    return ran, failures


async def _cancelled_while_queued(svc: ExecutionService, name: str) -> tuple[list[str], bool]:
    """F11 path B: a request queued behind a running query is cancelled
    (notifications/cancelled, client disconnect) while it waits."""
    query = threading.Event()
    conn = _Fake(name, query=query)
    ran: list[str] = []
    try:
        async with anyio.create_task_group() as tg:
            tg.start_soon(lambda: svc.run_bounded(conn, _query(ran, "running"), 30.0, description="running"))
            assert await _until(lambda: ran == ["running"])
            with anyio.move_on_after(0.1) as scope:
                await svc.run_bounded(conn, _query(ran, "queued"), 30.0, description="queued")
            query.set()
    finally:
        query.set()
    return ran, scope.cancelled_caught


# ------------------------------------------------------------------ F11


@pytest.mark.anyio
async def test_request_queued_while_its_connector_is_poisoned_returns_its_token(anyio_backend: str) -> None:
    svc = ExecutionService(max_concurrent=4)
    ran, failures = await _poisoned_while_queued(svc, "a")
    assert failures["slow"].category == ErrorCategory.TIMEOUT
    assert failures["q1"].category == ErrorCategory.CONNECTION
    assert failures["q2"].category == ErrorCategory.CONNECTION
    assert ran == ["slow"], "a request queued on a poisoned connector must never run"
    assert await _until(lambda: _borrowed(svc) == 0), f"leaked tokens: {_borrowed(svc)}"


@pytest.mark.anyio
async def test_request_cancelled_while_queued_on_the_gate_returns_its_token(anyio_backend: str) -> None:
    svc = ExecutionService(max_concurrent=4)
    ran, cancelled = await _cancelled_while_queued(svc, "a")
    assert cancelled
    assert ran == ["running"], "the cancelled request's fn must never run"
    assert await _until(lambda: _borrowed(svc) == 0), f"leaked tokens: {_borrowed(svc)}"


@pytest.mark.anyio
async def test_request_cancelled_before_its_worker_starts_returns_its_token(anyio_backend: str) -> None:
    svc = ExecutionService(max_concurrent=4)
    threads = anyio.to_thread.current_default_thread_limiter()
    saved = threads.total_tokens
    hold = threading.Event()
    ran: list[str] = []
    threads.total_tokens = 1
    try:
        async with anyio.create_task_group() as tg:
            # Occupy the only worker-thread slot: run_bounded's call then waits
            # inside anyio before any thread picks it up.
            tg.start_soon(anyio.to_thread.run_sync, lambda: hold.wait(10))
            assert await _until(lambda: threads.borrowed_tokens == 1)
            with anyio.move_on_after(0.2) as scope:
                await svc.run_bounded(_Fake("a"), _query(ran, "never"), 5.0, description="t")
            assert scope.cancelled_caught
            hold.set()
    finally:
        hold.set()
        threads.total_tokens = saved
    assert ran == [], "fn must never run for a request that already gave up"
    assert _borrowed(svc) == 0


@pytest.mark.anyio
async def test_worker_started_after_its_request_gave_up_skips_fn(anyio_backend: str) -> None:
    """anyio can still hand a call to a thread after the awaiting request was
    cancelled; the start handshake makes that thread skip the driver call,
    because the request side has already returned the token."""
    svc = ExecutionService(max_concurrent=4)
    run = executor._Run()
    await svc._limiter.acquire_on_behalf_of(run)
    svc._settle(run, _Fake("a"))  # the request side leaves first
    assert _borrowed(svc) == 0
    ran: list[str] = []
    result = await anyio.to_thread.run_sync(
        svc._run_worker, _Fake("a"), _query(ran, "late"), run, anyio.lowlevel.current_token()
    )
    assert result is None
    assert ran == []
    assert _borrowed(svc) == 0


@pytest.mark.anyio
async def test_executor_stays_live_after_repeated_queued_failures(anyio_backend: str) -> None:
    svc = ExecutionService(max_concurrent=4)
    for cycle in range(5):  # max_concurrent + 1 cycles of both leak paths
        await _poisoned_while_queued(svc, f"a{cycle}")
        await _cancelled_while_queued(svc, f"b{cycle}")
        assert await _until(lambda: _borrowed(svc) == 0), f"cycle {cycle}: leaked {_borrowed(svc)}"
    start = time.monotonic()
    with anyio.fail_after(3):
        assert await svc.run_bounded(_Fake("healthy"), lambda c: "ok", 1.0, description="healthy") == "ok"
    assert time.monotonic() - start < 0.5


# ------------------------------------------------------------------ F12


@pytest.mark.anyio
async def test_connection_with_an_abandoned_worker_fails_fast(anyio_backend: str) -> None:
    svc = ExecutionService(max_concurrent=4)
    hung = threading.Event()  # the "database" never answers until set
    calls: list[str] = []

    def health(c: DatabaseConnector) -> Any:
        calls.append("health")
        return c.health_check()

    try:
        with pytest.raises(ToolFailure) as first:
            await svc.run_bounded(_Fake("dead", connect=hung), health, 0.2, description="health check on 'dead'")
        assert first.value.category == ErrorCategory.TIMEOUT
        assert _borrowed(svc) == 1, "the abandoned worker keeps its token"
        for _ in range(4):
            # AppContext builds a fresh connector object for every retry of a
            # poisoned connection; the breaker follows the connection id.
            start = time.monotonic()
            with pytest.raises(ToolFailure) as retry:
                await svc.run_bounded(_Fake("dead", connect=hung), health, 0.2, description="health check on 'dead'")
            assert time.monotonic() - start < 0.05
            assert retry.value.category == ErrorCategory.CONNECTION
            assert "connection 'dead' is still recovering" in str(retry.value)
            assert "retry later" in str(retry.value)
            assert _borrowed(svc) <= 1
        assert calls == ["health"], "no retry may start another driver call"
        # Other connections are unaffected.
        assert await svc.run_bounded(_Fake("healthy"), lambda c: c.health_check(), 1.0, description="h") == "healthy"
    finally:
        hung.set()
    # The abandoned call returns: its token and the breaker clear together.
    assert await _until(lambda: _borrowed(svc) == 0)
    assert await svc.run_bounded(_Fake("dead", connect=hung), health, 1.0, description="t") == "healthy"
    assert calls == ["health", "health"]
    assert _borrowed(svc) == 0


@pytest.mark.anyio
async def test_cancelled_running_request_counts_as_abandoned(anyio_backend: str) -> None:
    """A client that cancels a running call the cancel hook cannot stop, and
    retries, strands tokens the same way a deadline does: the still-running
    worker trips the breaker."""
    svc = ExecutionService(max_concurrent=4)
    hung = threading.Event()
    ran: list[str] = []
    try:
        with anyio.move_on_after(0.2) as scope:
            await svc.run_bounded(_Fake("slow", query=hung), _query(ran, "first"), 30.0, description="q")
        assert scope.cancelled_caught
        assert _borrowed(svc) == 1
        with pytest.raises(ToolFailure) as retry:
            await svc.run_bounded(_Fake("slow", query=hung), _query(ran, "second"), 30.0, description="q")
        assert retry.value.category == ErrorCategory.CONNECTION
        assert ran == ["first"]
    finally:
        hung.set()
    assert await _until(lambda: _borrowed(svc) == 0)
    assert await svc.run_bounded(_Fake("slow"), _query(ran, "third"), 1.0, description="q") == "third"


@pytest.mark.anyio
async def test_connect_phase_timeout_does_not_claim_a_server_side_query(anyio_backend: str) -> None:
    svc = ExecutionService(max_concurrent=4)
    hung = threading.Event()
    try:
        with pytest.raises(ToolFailure) as exc:
            await svc.run_bounded(
                _Fake("dead", connect=hung), lambda c: c.health_check(), 0.2, description="health check on 'dead'"
            )
    finally:
        hung.set()
    assert exc.value.category == ErrorCategory.TIMEOUT
    assert "the connect had not completed when the deadline fired" in str(exc.value)
    assert "server-side" not in str(exc.value)
    # 0.2 s is well within a normal connect bound: nothing says the database
    # did not answer.
    assert "did not answer" not in str(exc.value)


@pytest.mark.anyio
async def test_query_phase_timeout_keeps_the_server_side_warning(anyio_backend: str) -> None:
    svc = ExecutionService(max_concurrent=4)
    hung = threading.Event()
    try:
        with pytest.raises(ToolFailure) as exc:
            await svc.run_bounded(_Fake("slow", query=hung), _query([], "q"), 0.2, description="query on 'slow'")
    finally:
        hung.set()
    assert exc.value.category == ErrorCategory.TIMEOUT
    assert "may still run server-side" in str(exc.value)
    assert "connect had not completed" not in str(exc.value)


# ------------------------------------------------------------------ F39


@pytest.mark.anyio
async def test_queued_requests_hold_no_token_and_an_idle_connection_runs(anyio_backend: str) -> None:
    svc = ExecutionService(max_concurrent=4)
    query = threading.Event()
    busy = _Fake("busy", query=query)
    ran: list[str] = []
    try:
        async with anyio.create_task_group() as tg:
            for i in range(8):
                tg.start_soon(lambda t=f"q{i}": svc.run_bounded(busy, _query(ran, t), 30.0, description=t))
            assert await _until(lambda: len(ran) == 1)
            await anyio.sleep(0.05)  # the other seven reach the gate
            assert _borrowed(svc) == 1, "queued requests must not hold global tokens"
            start = time.monotonic()
            assert await svc.run_bounded(_Fake("idle"), lambda c: "ok", 1.0, description="idle") == "ok"
            assert time.monotonic() - start < 0.5
            query.set()
    finally:
        query.set()
    assert len(ran) == 8
    assert _borrowed(svc) == 0


@pytest.mark.anyio
async def test_queue_budget_expiring_on_the_gate_raises_limit(anyio_backend: str, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(executor, "_QUEUE_TIMEOUT_FACTOR", 1.0)
    monkeypatch.setattr(executor, "_MIN_QUEUE_SECONDS", 0.2)
    svc = ExecutionService(max_concurrent=4)
    query = threading.Event()
    busy = _Fake("busy", query=query)
    ran: list[str] = []
    failures: dict[str, ToolFailure] = {}

    async def call(tag: str, deadline: float) -> None:
        try:
            await svc.run_bounded(busy, _query(ran, tag), deadline, description=tag)
        except ToolFailure as exc:
            failures[tag] = exc

    try:
        async with anyio.create_task_group() as tg:
            tg.start_soon(call, "running", 30.0)
            assert await _until(lambda: ran == ["running"])
            tg.start_soon(call, "expires", 0.1)  # queue budget max(0.1 x 1, 0.2) s
            tg.start_soon(call, "next", 30.0)
            assert await _until(lambda: "expires" in failures)
            query.set()
    finally:
        query.set()
    assert failures["expires"].category == ErrorCategory.LIMIT
    assert "connection 'busy' is busy" in str(failures["expires"])
    assert ran == ["running", "next"], "the expired request never runs; the next waiter still does"
    assert _borrowed(svc) == 0


@pytest.mark.anyio
async def test_request_timing_out_on_the_limiter_releases_the_gate(anyio_backend: str, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(executor, "_QUEUE_TIMEOUT_FACTOR", 1.0)
    monkeypatch.setattr(executor, "_MIN_QUEUE_SECONDS", 0.2)
    svc = ExecutionService(max_concurrent=1)
    holder = object()
    await svc._limiter.acquire_on_behalf_of(holder)
    conn = _Fake("a")
    with pytest.raises(ToolFailure) as exc:
        await svc.run_bounded(conn, lambda c: "never", 0.1, description="t")
    assert exc.value.category == ErrorCategory.LIMIT
    assert not svc._gate_for(conn).locked(), "the gate must be released on the LIMIT path"
    svc._limiter.release_on_behalf_of(holder)
    assert await svc.run_bounded(conn, lambda c: "ok", 0.1, description="t") == "ok"
    assert _borrowed(svc) == 0


@pytest.mark.anyio
async def test_connector_gates_stay_bounded_across_rebuilds(anyio_backend: str) -> None:
    svc = ExecutionService(max_concurrent=4)
    rebuilt = [_Fake("same-id") for _ in range(50)]  # AppContext rebuilds after each poisoning
    for conn in rebuilt:
        assert await svc.run_bounded(conn, lambda c: "ok", 1.0, description="t") == "ok"
    assert list(svc._connection_gates) == ["same-id"], "rebuilt connectors share their connection's gate"
    # A connector with no connection id gets a gate of its own, which goes
    # with the connector.
    bare = [_Fake.__new__(_Fake) for _ in range(50)]
    for conn in bare:
        assert await svc.run_bounded(conn, lambda c: "ok", 1.0, description="t") == "ok"
    del rebuilt, bare, conn

    def collected() -> bool:
        gc.collect()
        return len(svc._connector_gates) == 0

    assert await _until(collected), len(svc._connector_gates)


# ------------------------------------------------------------------ review round 1


class _Cancellable(_Fake):
    """``cancel_current`` stops the running statement, as the PostgreSQL,
    Oracle, ClickHouse and SQLite hooks do."""

    def __init__(self, name: str, **kw: Any) -> None:
        super().__init__(name, **kw)
        self.cancels = 0

    def execute_query(self, spec: QuerySpec):  # type: ignore[no-untyped-def]
        result = super().execute_query(spec)
        if self.cancels:
            time.sleep(0.05)  # the cancelled statement unwinds (a server round-trip)
        return result

    def cancel_current(self) -> bool:
        self.cancels += 1
        self.query_gate.set()
        return True


class _SlowHook(_Fake):
    """A cancel hook that takes a while (a network round-trip) and reports
    success without stopping anything."""

    def cancel_current(self) -> bool:
        time.sleep(1.0)
        return True


def test_breaker_and_token_clear_after_the_request_loop_closed() -> None:
    """site-check and scripts/live_evidence.py run every tool call under its
    own event loop on one shared AppContext. A worker abandoned in one call
    finishes after that loop closed; its connection must not stay refused,
    and its token must come back."""
    svc = ExecutionService(max_concurrent=4)
    hung = threading.Event()

    async def step(conn: DatabaseConnector, fn: Callable[[DatabaseConnector], Any], seconds: float) -> Any:
        return await svc.run_bounded(conn, fn, seconds, description="step")

    try:
        with pytest.raises(ToolFailure) as first:
            anyio.run(step, _Fake("site_db2", query=hung), _query([], "slow"), 0.3)
        assert first.value.category == ErrorCategory.TIMEOUT
    finally:
        hung.set()  # the database answers after the first loop has closed
    waited = time.monotonic() + 3.0
    while svc._abandoned and time.monotonic() < waited:
        time.sleep(0.01)
    assert svc._abandoned == {}, "the returned worker must clear its breaker entry"
    assert anyio.run(step, _Fake("site_db2"), lambda c: "ok", 5.0) == "ok"
    assert _borrowed(svc) == 0, "the orphaned token must be returned on the next loop"


@pytest.mark.anyio
async def test_client_cancel_fires_the_cancel_hook_and_frees_the_connection(anyio_backend: str) -> None:
    svc = ExecutionService(max_concurrent=4)
    first = _Cancellable("pg", query=threading.Event())
    ran: list[str] = []
    try:
        with anyio.move_on_after(0.2) as scope:
            await svc.run_bounded(first, _query(ran, "long"), 30.0, description="q")
        assert scope.cancelled_caught
        assert first.cancels == 1, "a client cancel must cancel the running statement"
        assert svc.is_poisoned(first), "a connector cancelled mid-call is discarded"
        # The retry (a freshly built connector, as AppContext does) runs at
        # once instead of finding the connection still recovering.
        start = time.monotonic()
        assert await svc.run_bounded(_Cancellable("pg"), _query(ran, "retry"), 5.0, description="q") == "retry"
        assert time.monotonic() - start < 0.5
        assert svc._abandoned == {}
        assert _borrowed(svc) == 0
    finally:
        first.query_gate.set()


@pytest.mark.anyio
async def test_timeout_with_a_working_cancel_hook_leaves_the_connection_usable(anyio_backend: str) -> None:
    svc = ExecutionService(max_concurrent=4)
    first = _Cancellable("pg", query=threading.Event())
    try:
        with pytest.raises(ToolFailure) as exc:
            await svc.run_bounded(first, _query([], "long"), 0.2, description="q")
        assert exc.value.category == ErrorCategory.TIMEOUT
        assert svc._abandoned == {}, "a cancelled statement that returned is not abandoned"
        assert await svc.run_bounded(_Cancellable("pg"), lambda c: "ok", 1.0, description="q") == "ok"
        assert _borrowed(svc) == 0
    finally:
        first.query_gate.set()


@pytest.mark.anyio
async def test_hung_connect_fails_fast_for_every_connection_to_that_server(anyio_backend: str, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Several connection ids often point at one database server (different
    schemas or users). A connect that hangs there, past its connection's
    connect bound, strands at most one token, not one per configured id."""
    monkeypatch.setattr(executor, "_HUNG_CONNECT_FLOOR", 0.1, raising=False)
    svc = ExecutionService(max_concurrent=4)
    hung = threading.Event()
    calls: list[str] = []

    def health(c: DatabaseConnector) -> Any:
        calls.append(c.connection.name)
        return c.health_check()

    try:
        failures: list[ToolFailure] = []
        for i in range(4):
            # The 0.4 s deadline is well past the 0.1 s connect bound: the
            # connect is hanging, not merely cut short.
            conn = _Fake(f"dead{i}", connect=hung, host="db2.example", port=50001, connect_timeout=0.1)
            start = time.monotonic()
            with pytest.raises(ToolFailure) as exc:
                await svc.run_bounded(conn, health, 0.4, description=f"health check on 'dead{i}'")
            failures.append(exc.value)
            assert _borrowed(svc) <= 1
            if i:
                assert time.monotonic() - start < 0.05
        assert failures[0].category == ErrorCategory.TIMEOUT
        for other in failures[1:]:
            assert other.category == ErrorCategory.CONNECTION
            assert "a connect to its database server did not complete" in str(other)
            assert "db2.example" not in str(other), "the refusal must not name the server"
        assert calls == ["dead0"], "no other connection may start a driver call against the hung server"
        # Another server, and a connection with no server address, still run.
        other_server = _Fake("other", host="db2b.example", port=50001)
        assert await svc.run_bounded(other_server, lambda c: c.health_check(), 1.0, description="h") == "healthy"
        assert await svc.run_bounded(_Fake("local"), lambda c: c.health_check(), 1.0, description="h") == "healthy"
    finally:
        hung.set()
    # The parked connect gave its token back already; wait for it to return.
    assert await _until(lambda: _borrowed(svc) == 0 and _parked(svc) == 0)
    conn = _Fake("dead1", connect=hung, host="db2.example", port=50001)
    assert await svc.run_bounded(conn, health, 1.0, description="h") == "healthy"


@pytest.mark.anyio
async def test_query_phase_abandonment_does_not_block_the_server(anyio_backend: str) -> None:
    """Only a connect that hangs speaks for the whole server; a slow statement
    on one connection says nothing about the others."""
    svc = ExecutionService(max_concurrent=4)
    hung = threading.Event()
    try:
        with pytest.raises(ToolFailure):
            await svc.run_bounded(_Fake("a", query=hung, host="pg.example"), _query([], "slow"), 0.2, description="q")
        assert await svc.run_bounded(_Fake("b", host="pg.example"), lambda c: "ok", 1.0, description="q") == "ok"
    finally:
        hung.set()


@pytest.mark.anyio
async def test_sibling_connectors_for_one_connection_run_one_driver_call(anyio_backend: str) -> None:
    """AppContext builds a new connector object once the old one is
    discarded, even while the old one's call is still in flight (the server
    discards a connector when a queued call on it is cancelled). Connector
    objects for one connection id share one queue, so they cannot put
    several calls in flight against a hung database."""
    svc = ExecutionService(max_concurrent=4)
    hung = threading.Event()
    calls: list[str] = []
    failures: list[ToolFailure] = []

    def health(c: DatabaseConnector) -> Any:
        calls.append(c.connection.name)
        return c.health_check()

    async def one(i: int) -> None:
        try:
            await svc.run_bounded(_Fake("dead", connect=hung), health, 1.0, description=f"h{i}")
        except ToolFailure as exc:
            failures.append(exc)

    try:
        async with anyio.create_task_group() as tg:
            for i in range(4):
                tg.start_soon(one, i)  # each on a freshly built connector object
                await anyio.sleep(0.05)
            await anyio.sleep(0.1)
            assert calls == ["dead"], "only one driver call may run for a connection"
            assert _borrowed(svc) == 1
        assert _borrowed(svc) == 1
        assert sorted(f.category for f in failures) == [ErrorCategory.CONNECTION] * 3 + [ErrorCategory.TIMEOUT]
        assert await svc.run_bounded(_Fake("healthy"), lambda c: "ok", 1.0, description="h") == "ok"
    finally:
        hung.set()
    assert await _until(lambda: _borrowed(svc) == 0)


@pytest.mark.anyio
async def test_deadline_before_the_worker_starts_reports_that_nothing_ran(anyio_backend: str) -> None:
    svc = ExecutionService(max_concurrent=4)
    threads = anyio.to_thread.current_default_thread_limiter()
    saved = threads.total_tokens
    hold = threading.Event()
    ran: list[str] = []
    conn = _Cancellable("a")
    threads.total_tokens = 1
    try:
        async with anyio.create_task_group() as tg:
            # Every worker thread is busy: the deadline fires before the
            # driver call can start.
            tg.start_soon(anyio.to_thread.run_sync, lambda: hold.wait(10))
            assert await _until(lambda: threads.borrowed_tokens == 1)
            with pytest.raises(ToolFailure) as exc:
                await svc.run_bounded(conn, _query(ran, "never"), 0.2, description="query on 'a'")
            hold.set()
    finally:
        hold.set()
        threads.total_tokens = saved
    assert exc.value.category == ErrorCategory.TIMEOUT
    assert "did not start within its deadline" in str(exc.value)
    assert "server-side" not in str(exc.value)
    assert ran == []
    assert conn.cancels == 0, "there is no statement to cancel"
    assert not svc.is_poisoned(conn), "a connector that was never used stays usable"
    assert _borrowed(svc) == 0


@pytest.mark.anyio
async def test_cancellation_during_the_cancel_hook_still_discards_the_connector(anyio_backend: str) -> None:
    svc = ExecutionService(max_concurrent=4)
    conn = _SlowHook("x", query=threading.Event())
    try:
        # The 0.2 s deadline fires; the outer cancellation lands while the
        # executor waits on the 1 s cancel hook.
        with anyio.move_on_after(0.5) as scope:
            await svc.run_bounded(conn, _query([], "q"), 0.2, description="q")
        assert scope.cancelled_caught
        assert svc.is_poisoned(conn), "the connector whose statement was cut off must be discarded"
    finally:
        conn.query_gate.set()
    assert await _until(lambda: _borrowed(svc) == 0 and not svc._abandoned)


@pytest.mark.anyio
async def test_a_driver_call_that_never_returns_hints_at_the_way_out(anyio_backend: str, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(executor, "_STUCK_AFTER_SECONDS", 0.3, raising=False)
    svc = ExecutionService(max_concurrent=4)
    hung = threading.Event()
    try:
        with pytest.raises(ToolFailure):
            await svc.run_bounded(_Fake("dead", connect=hung), lambda c: c.health_check(), 0.1, description="h")
        with pytest.raises(ToolFailure) as early:
            await svc.run_bounded(_Fake("dead", connect=hung), lambda c: c.health_check(), 0.1, description="h")
        assert "retry later" in str(early.value)
        assert "restart" not in str(early.value)
        await anyio.sleep(0.35)
        with pytest.raises(ToolFailure) as late:
            await svc.run_bounded(_Fake("dead", connect=hung), lambda c: c.health_check(), 0.1, description="h")
        assert late.value.category == ErrorCategory.CONNECTION
        assert "check the database and the network, or restart the server" in str(late.value)
    finally:
        hung.set()


@pytest.mark.anyio
async def test_has_live_worker_follows_an_abandoned_driver_call(anyio_backend: str) -> None:
    """The server closes a discarded connector only once no worker thread
    still uses it."""
    svc = ExecutionService(max_concurrent=4)
    hung = threading.Event()
    conn = _Fake("x", query=hung)
    try:
        assert not svc.has_live_worker(conn)
        with pytest.raises(ToolFailure):
            await svc.run_bounded(conn, _query([], "q"), 0.2, description="q")
        assert svc.has_live_worker(conn)
    finally:
        hung.set()
    assert await _until(lambda: not svc.has_live_worker(conn))
    assert await svc.run_bounded(_Fake("y"), lambda c: "ok", 1.0, description="q") == "ok"
    assert not svc.has_live_worker(conn)


# ------------------------------------------------------------------ review round 2


class _SlowConnect(_Fake):
    """A healthy database whose connect takes a moment (a remote TLS
    handshake and authentication) and always completes."""

    def _connect(self) -> object:
        time.sleep(0.3)
        return object()


def _health(calls: list[str]) -> Callable[[DatabaseConnector], Any]:
    def fn(c: DatabaseConnector) -> Any:
        calls.append(c.connection.name)
        return c.health_check()

    return fn


def _dead(name: str, host: str, hung: threading.Event) -> _Fake:
    """A connection whose server accepts TCP and never answers; its connect
    bound is the (patched) floor."""
    return _Fake(name, connect=hung, host=host, port=50001, connect_timeout=0.1)


async def _call_into(
    svc: ExecutionService,
    conn: _Fake,
    fn: Callable[[DatabaseConnector], Any],
    deadline: float,
    out: dict[str, Any],
    ended: dict[str, float],
    start: float,
) -> None:
    """Runs one call and records its result or failure, and when it ended."""
    name = conn.connection.name
    try:
        out[name] = await svc.run_bounded(conn, fn, deadline, description=name)
    except ToolFailure as exc:
        out[name] = exc
    ended[name] = time.monotonic() - start


def _first_bound(svc: ExecutionService, server: tuple[str, str, int | None], start: float) -> float:
    """When the first abandoned connect to the server reached its connect
    bound, in seconds after ``start``: its worker thread may have started a
    moment after its request, on a loaded host."""
    return min(run.hung_after for run in svc._hung_connects[server]) - start


@pytest.mark.anyio
@pytest.mark.parametrize("how", ["deadline", "cancel"])
async def test_cut_short_healthy_connect_does_not_refuse_the_other_connections_to_its_server(
    anyio_backend: str, how: str
) -> None:
    """timeout_seconds is caller-chosen and a client may cancel at any time:
    a deadline or cancel that catches a normal connect is no evidence of a
    hung server, so another connection id on that server keeps working."""
    svc = ExecutionService(max_concurrent=4)
    victim = _Fake("victim", host="db.example", port=5432)
    for _ in range(3):
        caller = _SlowConnect("caller", host="db.example", port=5432)  # rebuilt, as AppContext does
        if how == "deadline":
            with pytest.raises(ToolFailure) as cut:
                await svc.run_bounded(caller, lambda c: c.health_check(), 0.02, description="h")
            assert cut.value.category == ErrorCategory.TIMEOUT
        else:
            with anyio.move_on_after(0.02) as scope:
                await svc.run_bounded(caller, lambda c: c.health_check(), 30.0, description="h")
            assert scope.cancelled_caught
        assert await svc.run_bounded(victim, lambda c: "ok", 1.0, description="v") == "ok"
        assert await _until(lambda: not svc._abandoned)  # the cut-short connect returns
    assert await _until(lambda: _borrowed(svc) == 0)


@pytest.mark.anyio
async def test_connect_still_hanging_past_its_bound_then_refuses_the_other_connections(
    anyio_backend: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A short deadline that catches a connect which then keeps hanging trips
    the server-wide refusal once the connect has run past its bound."""
    monkeypatch.setattr(executor, "_HUNG_CONNECT_FLOOR", 0.3, raising=False)
    svc = ExecutionService(max_concurrent=4)
    hung = threading.Event()
    calls: list[str] = []
    try:
        with pytest.raises(ToolFailure):
            await svc.run_bounded(
                _Fake("a", connect=hung, host="db.example", connect_timeout=0.1), _health(calls), 0.05, description="h"
            )
        # 0.05 s into the connect: still within its bound.
        assert await svc.run_bounded(_Fake("b", host="db.example"), lambda c: "ok", 1.0, description="b") == "ok"
        await anyio.sleep(0.35)
        with pytest.raises(ToolFailure) as refused:
            await svc.run_bounded(_Fake("b", host="db.example"), _health(calls), 1.0, description="b")
        assert refused.value.category == ErrorCategory.CONNECTION
        assert "a connect to its database server did not complete" in str(refused.value)
        assert calls == ["a"]
    finally:
        hung.set()
    assert await _until(lambda: _borrowed(svc) == 0 and not svc._hung_connects)


@pytest.mark.anyio
async def test_cut_short_connect_that_then_connected_no_longer_speaks_for_its_server(
    anyio_backend: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A deadline caught the worker connecting; the connect then completed
    and the worker runs a long statement. That says nothing about the server:
    past the connect bound the other connections still run, while the
    connection itself waits for its abandoned call."""
    monkeypatch.setattr(executor, "_HUNG_CONNECT_FLOOR", 0.1, raising=False)
    svc = ExecutionService(max_concurrent=4)
    connect, query = threading.Event(), threading.Event()
    try:
        with pytest.raises(ToolFailure):
            conn = _Fake("a", connect=connect, query=query, host="db.example", connect_timeout=0.1)
            await svc.run_bounded(conn, _query([], "long"), 0.05, description="q")
        connect.set()  # connected; the statement runs on (no hook stops it)
        await anyio.sleep(0.2)
        assert await svc.run_bounded(_Fake("b", host="db.example"), lambda c: "ok", 1.0, description="b") == "ok"
        assert (_borrowed(svc), _parked(svc)) == (1, 0), "a running statement keeps its global token"
        with pytest.raises(ToolFailure) as own:
            await svc.run_bounded(_Fake("a", host="db.example"), lambda c: "ok", 1.0, description="a")
        assert "connection 'a' is still recovering" in str(own.value)
    finally:
        connect.set()
        query.set()
    assert await _until(lambda: _borrowed(svc) == 0)


@pytest.mark.anyio
async def test_call_queued_on_its_gate_looks_again_at_a_connect_that_completed_meanwhile(
    anyio_backend: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A request queued on its connection's gate checks the breaker again
    once it has the gate. A connect to its server that was cut short, and has
    completed since, no longer speaks for the server there either."""
    monkeypatch.setattr(executor, "_HUNG_CONNECT_FLOOR", 0.3, raising=False)
    svc = ExecutionService(max_concurrent=4)
    connect, query, busy = threading.Event(), threading.Event(), threading.Event()
    ran: list[str] = []
    results: dict[str, Any] = {}
    b = _Fake("b", query=busy, host="db.example")

    async def one(tag: str) -> None:
        results[tag] = await svc.run_bounded(b, _query(ran, tag), 5.0, description=tag)

    try:
        with pytest.raises(ToolFailure):
            conn = _Fake("a", connect=connect, query=query, host="db.example", connect_timeout=0.1)
            await svc.run_bounded(conn, _query([], "long"), 0.05, description="a")
        async with anyio.create_task_group() as tg:
            tg.start_soon(one, "b1")  # keeps b's gate
            assert await _until(lambda: ran == ["b1"])
            tg.start_soon(one, "b2")  # queues on the gate, a's connect still within its bound
            await anyio.sleep(0.05)
            connect.set()  # a connected; its statement runs on
            await anyio.sleep(0.4)  # past a's connect bound
            busy.set()
        assert results == {"b1": "b1", "b2": "b2"}
    finally:
        connect.set()
        query.set()
        busy.set()
    assert await _until(lambda: _borrowed(svc) == 0)


@pytest.mark.anyio
async def test_connect_running_past_its_bound_says_the_database_did_not_answer(
    anyio_backend: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(executor, "_HUNG_CONNECT_FLOOR", 0.1, raising=False)
    svc = ExecutionService(max_concurrent=4)
    hung = threading.Event()
    try:
        with pytest.raises(ToolFailure) as exc:
            conn = _Fake("dead", connect=hung, connect_timeout=0.1)
            await svc.run_bounded(conn, lambda c: c.health_check(), 0.4, description="health check on 'dead'")
    finally:
        hung.set()
    assert exc.value.category == ErrorCategory.TIMEOUT
    assert "the connect had not completed when the deadline fired" in str(exc.value)
    assert "(the database or network did not answer)" in str(exc.value)


@pytest.mark.anyio
async def test_one_database_server_never_takes_every_stuck_connect_slot(
    anyio_backend: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An agent fans out over several connection ids behind one hung server
    in parallel: the calls start together, as far as the server's share of
    the global tokens allows, before any breaker can trip. Their connects,
    hung past their bound, give their global tokens back and wait in the
    stuck-connect budget, of which one server may take every slot but one:
    the server's remaining connect keeps its global token instead, the call
    left waiting for the share is refused, and connections to other servers
    are not."""
    monkeypatch.setattr(executor, "_HUNG_CONNECT_FLOOR", 0.1, raising=False)
    monkeypatch.setattr(executor, "_STUCK_CONNECT_SLOTS", 3)
    svc = ExecutionService(max_concurrent=4)
    hung = threading.Event()
    calls: list[str] = []
    failures: dict[str, ToolFailure] = {}

    async def one(i: int) -> None:
        conn = _Fake(f"dead{i}", connect=hung, host="db2.example", port=50001, connect_timeout=0.1)
        try:
            await svc.run_bounded(conn, _health(calls), 0.3, description=f"health check on 'dead{i}'")
        except ToolFailure as exc:
            failures[f"dead{i}"] = exc

    try:
        async with anyio.create_task_group() as tg:
            for i in range(4):
                tg.start_soon(one, i)
        assert len(calls) == 3, "the server's share: every global token but one"
        assert sorted(f.category for f in failures.values()) == [ErrorCategory.CONNECTION] + [ErrorCategory.TIMEOUT] * 3
        assert _parked(svc) == 2
        assert _borrowed(svc) == 1, "the server's last hung connect keeps its global token"
        start = time.monotonic()
        other = _Fake("healthy", host="pg.example", port=5432)
        assert await svc.run_bounded(other, lambda c: "ok", 1.0, description="h") == "ok"
        assert await svc.run_bounded(_Fake("local"), lambda c: "ok", 1.0, description="h") == "ok"
        assert time.monotonic() - start < 0.3
        with pytest.raises(ToolFailure) as refused:
            await svc.run_bounded(_Fake("dead4", host="db2.example", port=50001), _health(calls), 1.0, description="h")
        assert refused.value.category == ErrorCategory.CONNECTION
        assert "a connect to its database server did not complete" in str(refused.value)
        # The slot left takes a connect hung on another server.
        with pytest.raises(ToolFailure):
            await svc.run_bounded(_dead("elsewhere", "db2b.example", hung), _health(calls), 0.3, description="e")
        assert (_parked(svc), _borrowed(svc)) == (3, 1)
    finally:
        hung.set()
    assert await _until(lambda: _borrowed(svc) == 0 and _parked(svc) == 0)
    back = _Fake("dead0", host="db2.example", port=50001)
    assert await svc.run_bounded(back, _health(calls), 1.0, description="h") == "healthy"


@pytest.mark.anyio
async def test_fan_out_over_a_dead_server_leaves_a_token_and_its_last_call_ends_at_the_bound(
    anyio_backend: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A fan-out over four connection ids on one dead server, whose deadline
    is shorter than the connect bound. Three connects hold the server's
    share of the global tokens until they cross their bound, and a call to
    another server runs at once on the fourth. The fourth call to the dead
    server waits for the share and is refused at the bound, when the
    connects are parked, well within its queue budget."""
    monkeypatch.setattr(executor, "_HUNG_CONNECT_FLOOR", 0.4, raising=False)
    monkeypatch.setattr(executor, "_MIN_QUEUE_SECONDS", 2.0)
    svc = ExecutionService(max_concurrent=4)
    hung = threading.Event()
    calls: list[str] = []
    out: dict[str, Any] = {}
    ended: dict[str, float] = {}
    start = time.monotonic()
    try:
        async with anyio.create_task_group() as tg:
            for i in range(4):
                conn = _dead(f"dead{i}", "db2.example", hung)
                # 0.25 s, within the 0.4 s bound, leaves a loaded host's
                # worker threads time to start: a call that never started
                # would hand its token to the call waiting for the share.
                tg.start_soon(_call_into, svc, conn, _health(calls), 0.25, out, ended, start)
            assert await _until(lambda: len(calls) == 3)
            assert _borrowed(svc) == 3
            began = time.monotonic()
            other = _Fake("healthy", host="pg.example", port=5432)
            assert await svc.run_bounded(other, lambda c: "ok", 1.0, description="h") == "ok"
            assert time.monotonic() - began < 0.2
        assert len(calls) == 3
        refused = [name for name, result in out.items() if result.category == ErrorCategory.CONNECTION]
        assert len(refused) == 1, out
        assert "a connect to its database server did not complete" in str(out[refused[0]])
        bound = _first_bound(svc, ("fake", "db2.example", 50001), start)
        assert ended[refused[0]] - bound < 0.25, (ended, bound)
        # The refusal comes at the first connect's bound; the others, whose
        # worker threads started a moment later, are parked at their own.
        assert await _until(lambda: (_parked(svc), _borrowed(svc)) == (3, 0))
    finally:
        hung.set()
    assert await _until(lambda: _borrowed(svc) == 0 and _parked(svc) == 0)


@pytest.mark.anyio
async def test_a_single_token_is_not_reserved(anyio_backend: str) -> None:
    """With max_concurrent_queries 1 there is no token to set aside."""
    svc = ExecutionService(max_concurrent=1)
    assert await svc.run_bounded(_Fake("a", host="db.example"), lambda c: "ok", 1.0, description="a") == "ok"
    assert _borrowed(svc) == 0


def test_token_returns_when_the_request_loop_stops_before_the_worker_hands_it_back() -> None:
    """asyncio.run stops its loop, then closes it. A worker whose driver call
    returns in between must not block on the stopped loop (its callback would
    be dropped at close, and its token lost for the life of the process):
    the next request returns the token on its own loop."""
    svc = ExecutionService(max_concurrent=1)
    hung = threading.Event()
    loop = asyncio.new_event_loop()

    async def slow() -> Any:
        return await svc.run_bounded(_Fake("site", query=hung), _query([], "slow"), 0.2, description="s")

    try:
        with pytest.raises(ToolFailure):
            loop.run_until_complete(slow())
        hung.set()  # the driver call returns while the loop is stopped
        time.sleep(0.3)
    finally:
        hung.set()
        loop.close()

    async def other() -> Any:
        with anyio.fail_after(3):
            return await svc.run_bounded(_Fake("other"), lambda c: "ok", 1.0, description="o")

    assert anyio.run(other) == "ok"
    assert _borrowed(svc) == 0


@pytest.mark.anyio
async def test_call_waiting_for_its_servers_share_fails_fast_once_that_server_hangs(
    anyio_backend: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A connect still running and two abandoned statements on a server hold
    its share of the global tokens, so a fourth call to it waits. Once the
    connect is abandoned past its bound, that call is refused like any later
    call instead of waiting out its whole queue budget."""
    monkeypatch.setattr(executor, "_HUNG_CONNECT_FLOOR", 0.1, raising=False)
    svc = ExecutionService(max_concurrent=4)
    connect, query = threading.Event(), threading.Event()
    calls: list[str] = []
    ended: dict[str, float] = {}
    failures: dict[str, ToolFailure] = {}
    start = time.monotonic()

    async def call(conn: _Fake, deadline: float) -> None:
        name = conn.connection.name
        try:
            await svc.run_bounded(conn, _query(calls, name), deadline, description=name)  # queue budget 10 s
        except ToolFailure as exc:
            failures[name] = exc
        ended[name] = time.monotonic() - start

    try:
        async with anyio.create_task_group() as tg:
            # A connect that hangs, with a deadline past its connect bound.
            tg.start_soon(call, _Fake("dead", connect=connect, host="db2.example", connect_timeout=0.1), 0.5)
            assert await _until(lambda: "dead" in calls)
            for i in range(2):  # statements no cancel hook stops (Db2, SQL Server)
                await call(_Fake(f"slow{i}", query=query, host="db2.example"), 0.05)
            tg.start_soon(call, _Fake("waiting", host="db2.example"), 1.0)
            await anyio.sleep(0.05)
            assert "dead" not in failures, "the connect's request is still waiting on its deadline"
            assert svc._server_waiters[("fake", "db2.example", None)], "waiting waits for its server's share"
    finally:
        connect.set()
        query.set()
    assert failures["dead"].category == ErrorCategory.TIMEOUT
    assert failures["waiting"].category == ErrorCategory.CONNECTION
    assert "a connect to its database server did not complete" in str(failures["waiting"])
    assert ended["waiting"] < 2.0, ended
    assert "waiting" not in calls
    assert await _until(lambda: _borrowed(svc) == 0)


# ------------------------------------------------------------------ review round 3


@pytest.mark.anyio
@pytest.mark.parametrize("how", ["limit", "cancel"])
async def test_call_that_gives_up_on_the_global_limiter_leaves_its_server_open(
    anyio_backend: str, how: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A call that fails (LIMIT_EXCEEDED) or is cancelled while it waits for
    a global token leaves nothing held against its database server: more
    such calls than the server's share would otherwise close the server for
    the life of the process."""
    monkeypatch.setattr(executor, "_QUEUE_TIMEOUT_FACTOR", 1.0)
    monkeypatch.setattr(executor, "_MIN_QUEUE_SECONDS", 0.2)
    svc = ExecutionService(max_concurrent=4)
    foreign = [object() for _ in range(4)]
    for holder in foreign:  # other servers' calls hold every global token
        await svc._limiter.acquire_on_behalf_of(holder)
    ran: list[str] = []
    for i in range(4):
        conn = _Fake(f"s{i}", host="s.example")
        if how == "limit":
            with pytest.raises(ToolFailure) as exc:
                await svc.run_bounded(conn, _query(ran, f"s{i}"), 0.1, description=f"s{i}")
            assert exc.value.category == ErrorCategory.LIMIT
        else:
            with anyio.move_on_after(0.1) as scope:
                await svc.run_bounded(conn, _query(ran, f"s{i}"), 30.0, description=f"s{i}")
            assert scope.cancelled_caught
        assert not svc._server_waiters.get(("fake", "s.example", None))
        assert _borrowed(svc) == 4
    for holder in foreign:
        svc._limiter.release_on_behalf_of(holder)
    assert await svc.run_bounded(_Fake("s9", host="s.example"), _query(ran, "s9"), 1.0, description="s9") == "s9"
    assert ran == ["s9"]
    assert _borrowed(svc) == 0


@pytest.mark.anyio
async def test_call_waiting_for_a_global_token_is_refused_once_its_server_hangs(
    anyio_backend: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """While a call waits for a global token, a connect to its database
    server runs past its connect bound. The call is refused like any later
    call to that server, and never starts another connect there."""
    monkeypatch.setattr(executor, "_HUNG_CONNECT_FLOOR", 0.3, raising=False)
    svc = ExecutionService(max_concurrent=4)
    hung = threading.Event()
    calls: list[str] = []
    failures: dict[str, ToolFailure] = {}
    foreign: list[object] = []

    async def waiting() -> None:
        conn = _Fake("a2", connect=hung, host="s.example", connect_timeout=0.1)
        try:
            await svc.run_bounded(conn, _health(calls), 1.0, description="a2")
        except ToolFailure as exc:
            failures["a2"] = exc

    try:
        # a1's 0.05 s deadline fires well within its connect bound: nothing
        # blames the server yet.
        with pytest.raises(ToolFailure):
            conn = _Fake("a1", connect=hung, host="s.example", connect_timeout=0.1)
            await svc.run_bounded(conn, _health(calls), 0.05, description="a1")
        for _ in range(3):  # other servers' calls take the other global tokens
            holder = object()
            await svc._limiter.acquire_on_behalf_of(holder)
            foreign.append(holder)
        async with anyio.create_task_group() as tg:
            tg.start_soon(waiting)
            await anyio.sleep(0.4)  # a1's connect runs past its bound
            svc._limiter.release_on_behalf_of(foreign.pop())
        assert failures["a2"].category == ErrorCategory.CONNECTION
        assert "a connect to its database server did not complete" in str(failures["a2"])
        assert calls == ["a1"], "the waiting call must not start a connect against the hung server"
    finally:
        hung.set()
        for holder in foreign:
            svc._limiter.release_on_behalf_of(holder)
    assert await _until(lambda: _borrowed(svc) == 0)


@pytest.mark.anyio
async def test_connects_hung_on_several_servers_hold_no_global_token(
    anyio_backend: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One db_search_metadata sweep over connections on different dead
    servers (several Db2 instances, a black-holed subnet). A connect still
    hanging past its connect bound holds no database session: it gives its
    global token back and waits in the stuck-connect budget, so the other
    connections keep running. Once that budget is full, a connect to any
    database server is refused rather than risk a global token."""
    monkeypatch.setattr(executor, "_HUNG_CONNECT_FLOOR", 0.1, raising=False)
    monkeypatch.setattr(executor, "_STUCK_CONNECT_SLOTS", 4)
    svc = ExecutionService(max_concurrent=4)
    hung = threading.Event()
    calls: list[str] = []
    other = _Fake("pg", host="pg.example", port=5432)
    try:
        for i in range(4):
            # The 0.5 s deadline leaves a loaded host's worker thread time to
            # start and cross the 0.1 s bound before the request leaves.
            with pytest.raises(ToolFailure) as exc:
                await svc.run_bounded(
                    _dead(f"dead{i}", f"db{i}.example", hung), _health(calls), 0.5, description=f"dead{i}"
                )
            assert exc.value.category == ErrorCategory.TIMEOUT
            assert await _until(lambda: _borrowed(svc) == 0), f"dead{i}: a connect hung past its bound holds a token"
            if i < 3:
                assert await svc.run_bounded(other, lambda c: "ok", 1.0, description="pg") == "ok"
        assert _parked(svc) == 4
        start = time.monotonic()
        with anyio.fail_after(2):
            assert await svc.run_bounded(_Fake("local"), lambda c: "ok", 1.0, description="local") == "ok"
        assert time.monotonic() - start < 0.2
        for i in range(4):  # the dead connections fail fast and start nothing
            with pytest.raises(ToolFailure) as retry:
                await svc.run_bounded(
                    _dead(f"dead{i}", f"db{i}.example", hung), _health(calls), 0.5, description=f"dead{i}"
                )
            assert retry.value.category == ErrorCategory.CONNECTION
        with pytest.raises(ToolFailure) as refused:
            await svc.run_bounded(other, _health(calls), 1.0, description="pg")
        assert refused.value.category == ErrorCategory.CONNECTION
        assert "the limit of 4 pending connects to database servers that did not answer" in str(refused.value)
        assert "example" not in str(refused.value), "the refusal must not name any server"
        assert calls == [f"dead{i}" for i in range(4)]
        assert _borrowed(svc) == 0
    finally:
        hung.set()
    assert await _until(lambda: _parked(svc) == 0 and _borrowed(svc) == 0)
    assert await svc.run_bounded(other, lambda c: "ok", 1.0, description="pg") == "ok"


@pytest.mark.anyio
@pytest.mark.parametrize("hosts", [["db0", "db1", "db2", "db3"], ["x", "x", "x", "y"]])
async def test_parallel_fan_out_over_several_hung_servers_leaves_the_global_tokens_free(
    anyio_backend: str, monkeypatch: pytest.MonkeyPatch, hosts: list[str]
) -> None:
    monkeypatch.setattr(executor, "_HUNG_CONNECT_FLOOR", 0.1, raising=False)
    svc = ExecutionService(max_concurrent=4)
    hung = threading.Event()
    calls: list[str] = []
    failures: list[ToolFailure] = []

    async def one(i: int) -> None:
        try:
            conn = _dead(f"dead{i}", f"{hosts[i]}.example", hung)
            await svc.run_bounded(conn, _health(calls), 0.5, description=f"dead{i}")
        except ToolFailure as exc:
            failures.append(exc)

    try:
        async with anyio.create_task_group() as tg:
            for i in range(4):
                tg.start_soon(one, i)
        assert [f.category for f in failures] == [ErrorCategory.TIMEOUT] * 4
        assert await _until(lambda: _borrowed(svc) == 0)
        start = time.monotonic()
        with anyio.fail_after(2):
            assert await svc.run_bounded(_Fake("local"), lambda c: "ok", 1.0, description="local") == "ok"
            # Four parked connects leave room in the stuck-connect budget: a
            # connection to another database server still runs.
            other = _Fake("pg", host="pg.example", port=5432)
            assert await svc.run_bounded(other, lambda c: "ok", 1.0, description="pg") == "ok"
        assert time.monotonic() - start < 0.2
    finally:
        hung.set()
    assert await _until(lambda: _parked(svc) == 0 and _borrowed(svc) == 0)


@pytest.mark.anyio
async def test_healthy_calls_to_one_server_run_in_parallel(anyio_backend: str) -> None:
    """Only abandoned workers count toward a database server's share of the
    global tokens: at max_concurrent_queries 2, two connections to one
    server still run side by side."""
    svc = ExecutionService(max_concurrent=2)
    both = threading.Barrier(2)
    results: list[str] = []

    def meet(c: DatabaseConnector) -> str:
        both.wait(timeout=3)  # BrokenBarrierError if the calls run one after the other
        return str(c.connection.name)

    async def one(name: str) -> None:
        conn = _Fake(name, host="pg.example", port=5432)
        results.append(await svc.run_bounded(conn, meet, 5.0, description=name))

    async with anyio.create_task_group() as tg:
        tg.start_soon(one, "sales")
        tg.start_soon(one, "hr")
    assert sorted(results) == ["hr", "sales"]
    assert _borrowed(svc) == 0


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("max_concurrent", "limit"), [(2, "1 abandoned call (calls that"), (4, "3 calls in flight, counting calls that")]
)
async def test_abandoned_calls_to_one_server_leave_a_global_token_for_the_others(
    anyio_backend: str, monkeypatch: pytest.MonkeyPatch, max_concurrent: int, limit: str
) -> None:
    """Statements no cancel hook stops (Db2, SQL Server) run on after their
    requests left, each holding its global token. A server's abandoned calls
    may hold every global token but one: another call to that server waits
    for its share and ends in LIMIT_EXCEEDED, while other servers run. From
    a limit of 3 up, the refusal counts every call in flight."""
    monkeypatch.setattr(executor, "_QUEUE_TIMEOUT_FACTOR", 1.0)
    monkeypatch.setattr(executor, "_MIN_QUEUE_SECONDS", 0.2)
    svc = ExecutionService(max_concurrent=max_concurrent)
    hung = threading.Event()
    try:
        for i in range(max_concurrent - 1):
            with pytest.raises(ToolFailure):
                conn = _Fake(f"s{i}", query=hung, host="s.example")
                await svc.run_bounded(conn, _query([], f"slow{i}"), 0.1, description=f"s{i}")
        assert _borrowed(svc) == max_concurrent - 1
        with pytest.raises(ToolFailure) as limited:
            await svc.run_bounded(_Fake("next", host="s.example"), lambda c: "ok", 0.1, description="next")
        other = _Fake("other", host="other.example")
        assert await svc.run_bounded(other, lambda c: "ok", 1.0, description="other") == "ok"
    finally:
        hung.set()
    assert limited.value.category == ErrorCategory.LIMIT
    assert f"this connection's database server is at its limit of {limit} timed out or were cancelled" in str(
        limited.value
    )
    assert "s.example" not in str(limited.value), "the refusal must not name the server"
    assert await _until(lambda: _borrowed(svc) == 0)
    assert await svc.run_bounded(_Fake("next", host="s.example"), lambda c: "ok", 1.0, description="next") == "ok"


@pytest.mark.anyio
async def test_call_waiting_for_its_servers_share_is_refused_once_a_connect_there_crosses_its_bound(
    anyio_backend: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """db_query's timeout_seconds may be shorter than the connect bound: three
    calls to a dead server are abandoned in connects that have not yet run
    past it, and hold the server's share of the global tokens. A fourth call
    to that server waits; once the connects cross their bound it is refused
    at once, instead of waiting out its queue budget."""
    monkeypatch.setattr(executor, "_HUNG_CONNECT_FLOOR", 0.4, raising=False)
    monkeypatch.setattr(executor, "_MIN_QUEUE_SECONDS", 3.0)
    svc = ExecutionService(max_concurrent=4)
    hung = threading.Event()
    calls: list[str] = []
    try:
        for i in range(3):
            with pytest.raises(ToolFailure) as exc:
                await svc.run_bounded(_dead(f"s{i}", "s.example", hung), _health(calls), 0.05, description=f"s{i}")
            assert exc.value.category == ErrorCategory.TIMEOUT
        start = time.monotonic()
        with pytest.raises(ToolFailure) as refused:
            await svc.run_bounded(_dead("s3", "s.example", hung), _health(calls), 0.5, description="s3")
        assert refused.value.category == ErrorCategory.CONNECTION
        assert "a connect to its database server did not complete" in str(refused.value)
        assert time.monotonic() - start < 1.0
        assert calls == ["s0", "s1", "s2"]
    finally:
        hung.set()
    assert await _until(lambda: _borrowed(svc) == 0 and _parked(svc) == 0)


@pytest.mark.anyio
async def test_call_handed_a_token_by_a_parked_connect_is_refused_when_that_fills_the_budget(
    anyio_backend: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A connect parked as its request leaves hands its global token to a
    call waiting for one, and fills the stuck-connect budget in doing so.
    The call is refused, since a connect it started could no longer be
    parked: the breaker is re-checked once the token is taken."""
    monkeypatch.setattr(executor, "_HUNG_CONNECT_FLOOR", 0.1, raising=False)
    monkeypatch.setattr(executor, "_STUCK_CONNECT_SLOTS", 4)
    svc = ExecutionService(max_concurrent=4)
    hung = threading.Event()
    calls: list[str] = []
    failures: dict[str, ToolFailure] = {}
    foreign: list[object] = []

    async def call(conn: _Fake, deadline: float) -> None:
        try:
            await svc.run_bounded(conn, _health(calls), deadline, description=conn.connection.name)
        except ToolFailure as exc:
            failures[conn.connection.name] = exc

    try:
        for i in range(3):  # three of the four stuck-connect slots
            await call(_dead(f"dead{i}", f"db{i}.example", hung), 0.5)
        assert await _until(lambda: (_parked(svc), _borrowed(svc)) == (3, 0))
        for _ in range(3):  # other calls hold three global tokens
            holder = object()
            await svc._limiter.acquire_on_behalf_of(holder)
            foreign.append(holder)
        async with anyio.create_task_group() as tg:
            # Takes the last global token; its deadline is past its bound.
            tg.start_soon(call, _dead("dead3", "db3.example", hung), 0.5)
            assert await _until(lambda: "dead3" in calls)
            tg.start_soon(call, _Fake("pg", host="pg.example"), 1.0)  # waits for a global token
        assert failures["dead3"].category == ErrorCategory.TIMEOUT
        assert failures["pg"].category == ErrorCategory.CONNECTION
        assert "the limit of 4 pending connects" in str(failures["pg"])
        assert "pg" not in calls
    finally:
        hung.set()
        for holder in foreign:
            svc._limiter.release_on_behalf_of(holder)
    assert await _until(lambda: _borrowed(svc) == 0 and _parked(svc) == 0)


@pytest.mark.anyio
async def test_call_waiting_for_its_servers_share_runs_once_an_abandoned_call_returns(
    anyio_backend: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A statement no cancel hook stops holds its server's share of the
    global tokens (max_concurrent_queries 2). Another call to that server
    waits, and runs as soon as the statement returns, not at the end of its
    queue budget."""
    monkeypatch.setattr(executor, "_MIN_QUEUE_SECONDS", 3.0)
    svc = ExecutionService(max_concurrent=2)
    hung = threading.Event()

    async def returns_later() -> None:
        await anyio.sleep(0.2)
        hung.set()

    try:
        with pytest.raises(ToolFailure):
            conn = _Fake("sales", query=hung, host="pg.example", port=5432)
            await svc.run_bounded(conn, _query([], "slow"), 0.1, description="sales")
        async with anyio.create_task_group() as tg:
            tg.start_soon(returns_later)
            start = time.monotonic()
            other = _Fake("hr", host="pg.example", port=5432)
            assert await svc.run_bounded(other, lambda c: "ok", 1.0, description="hr") == "ok"
            assert time.monotonic() - start < 1.0
    finally:
        hung.set()
    assert await _until(lambda: _borrowed(svc) == 0)


@pytest.mark.anyio
async def test_abandoned_call_that_returns_leaves_the_calls_in_line_in_their_order(
    anyio_backend: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """News about a server's share wakes only the calls waiting for that
    share: calls to the server that wait in line for a global token keep
    their places, behind and ahead of calls to other servers."""
    monkeypatch.setattr(executor, "_MIN_QUEUE_SECONDS", 3.0)
    svc = ExecutionService(max_concurrent=4)
    hung = threading.Event()
    foreign: list[object] = []
    order: list[str] = []

    async def one(conn: _Fake) -> None:
        await svc.run_bounded(conn, lambda c: order.append(c.connection.name), 1.0, description="c")

    try:
        with pytest.raises(ToolFailure):  # holds one global token, abandoned
            conn = _Fake("sales", query=hung, host="s.example")
            await svc.run_bounded(conn, _query([], "slow"), 0.1, description="sales")
        for _ in range(3):  # other calls hold the other global tokens
            holder = object()
            await svc._limiter.acquire_on_behalf_of(holder)
            foreign.append(holder)
        async with anyio.create_task_group() as tg:
            for name, host in [("hr", "s.example"), ("ops", "s.example"), ("pg", "pg.example")]:
                tg.start_soon(one, _Fake(name, host=host))
                await anyio.sleep(0.05)  # in this order
            hung.set()  # the abandoned statement returns its token; one token goes round
        assert order == ["hr", "ops", "pg"]
    finally:
        hung.set()
        for holder in foreign:
            svc._limiter.release_on_behalf_of(holder)
    assert await _until(lambda: _borrowed(svc) == 0)


@pytest.mark.anyio
async def test_freed_stuck_connect_slot_takes_a_connect_that_waited_for_one(
    anyio_backend: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A connect that crossed its bound while the stuck-connect budget was
    full keeps its global token; it moves into the budget, and gives the
    token back, as soon as a parked connect returns."""
    monkeypatch.setattr(executor, "_HUNG_CONNECT_FLOOR", 0.1, raising=False)
    monkeypatch.setattr(executor, "_STUCK_CONNECT_SLOTS", 4)
    svc = ExecutionService(max_concurrent=4)
    gates = [threading.Event() for _ in range(5)]
    calls: list[str] = []

    async def one(i: int, deadline: float) -> None:
        with pytest.raises(ToolFailure):
            await svc.run_bounded(
                _dead(f"dead{i}", f"db{i}.example", gates[i]), _health(calls), deadline, description="d"
            )

    try:
        for i in range(3):
            await one(i, 0.4)
        async with anyio.create_task_group() as tg:  # both start before the budget fills
            tg.start_soon(one, 3, 0.4)  # parked: the budget is full
            tg.start_soon(one, 4, 0.7)  # past its bound, no slot left
        assert (_parked(svc), _borrowed(svc)) == (4, 1)
        gates[0].set()  # a parked connect returns
        assert await _until(lambda: (_parked(svc), _borrowed(svc)) == (4, 0))
    finally:
        for gate in gates:
            gate.set()
    assert await _until(lambda: (_parked(svc), _borrowed(svc)) == (0, 0))


@pytest.mark.anyio
async def test_call_queued_on_a_connection_poisoned_meanwhile_does_not_wait_for_a_global_token(
    anyio_backend: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The breaker is checked again once a request has its gate, before it
    waits for a global token: a request queued behind a query whose deadline
    poisons the connection is refused at once, even with every global token
    taken."""
    monkeypatch.setattr(executor, "_QUEUE_TIMEOUT_FACTOR", 1.0)
    monkeypatch.setattr(executor, "_MIN_QUEUE_SECONDS", 1.0)
    svc = ExecutionService(max_concurrent=2)
    query = threading.Event()
    conn = _Fake("a", query=query)
    holder = object()
    ran: list[str] = []
    failures: dict[str, ToolFailure] = {}

    async def call(tag: str, deadline: float) -> None:
        try:
            await svc.run_bounded(conn, _query(ran, tag), deadline, description=tag)
        except ToolFailure as exc:
            failures[tag] = exc

    await svc._limiter.acquire_on_behalf_of(holder)  # another call holds the other token
    try:
        async with anyio.create_task_group() as tg:
            tg.start_soon(call, "slow", 0.3)  # abandoned, it keeps its token
            assert await _until(lambda: ran == ["slow"])
            tg.start_soon(call, "queued", 1.0)
        assert failures["slow"].category == ErrorCategory.TIMEOUT
        assert failures["queued"].category == ErrorCategory.CONNECTION
        assert ran == ["slow"]
    finally:
        query.set()
        svc._limiter.release_on_behalf_of(holder)
    assert await _until(lambda: _borrowed(svc) == 0)


@pytest.mark.anyio
async def test_refusal_does_not_wait_for_the_connections_gate(
    anyio_backend: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A connection whose server hangs is refused before it queues on its
    gate, even while an earlier, healthy call on it still runs."""
    monkeypatch.setattr(executor, "_HUNG_CONNECT_FLOOR", 0.1, raising=False)
    svc = ExecutionService(max_concurrent=4)
    hung, busy = threading.Event(), threading.Event()
    x = _Fake("x", query=busy, host="db.example", port=50001)
    ran: list[str] = []
    try:
        async with anyio.create_task_group() as tg:
            tg.start_soon(lambda: svc.run_bounded(x, _query(ran, "x1"), 5.0, description="x1"))  # keeps x's gate
            assert await _until(lambda: ran == ["x1"])
            with pytest.raises(ToolFailure):  # another connection's connect hangs past its bound
                await svc.run_bounded(_dead("dead", "db.example", hung), _health(ran), 0.4, description="dead")
            start = time.monotonic()
            with pytest.raises(ToolFailure) as refused:
                await svc.run_bounded(x, _query(ran, "x2"), 5.0, description="x2")
            assert time.monotonic() - start < 0.1
            assert refused.value.category == ErrorCategory.CONNECTION
            busy.set()
        assert ran == ["x1", "dead"]
    finally:
        hung.set()
        busy.set()
    assert await _until(lambda: _borrowed(svc) == 0 and _parked(svc) == 0)


# ------------------------------------------------------------------ review round 4


@pytest.mark.anyio
async def test_parallel_statements_no_hook_stops_on_one_server_leave_a_global_token(
    anyio_backend: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An agent fans out over four connection ids on one Db2 server in
    parallel. The statements run on past their deadline and no cancel hook
    stops them, until they return. A server's calls in flight may hold every
    global token but one, so the other servers, and SQLite, keep running."""
    monkeypatch.setattr(executor, "_QUEUE_TIMEOUT_FACTOR", 1.0)
    monkeypatch.setattr(executor, "_MIN_QUEUE_SECONDS", 0.3)
    svc = ExecutionService(max_concurrent=4)
    hung = threading.Event()
    ran: list[str] = []
    failures: dict[str, ToolFailure] = {}

    async def one(i: int) -> None:
        conn = _Fake(f"db2_{i}", query=hung, host="db2.example", port=50000)
        try:
            await svc.run_bounded(conn, _query(ran, f"db2_{i}"), 0.1, description=f"db2_{i}")
        except ToolFailure as exc:
            failures[f"db2_{i}"] = exc

    try:
        async with anyio.create_task_group() as tg:
            for i in range(4):
                tg.start_soon(one, i)
        assert len(ran) == 3, ran
        categories = [f.category for f in failures.values()]
        assert sorted(map(str, categories)) == sorted(map(str, [ErrorCategory.TIMEOUT] * 3 + [ErrorCategory.LIMIT]))
        limited = next(f for f in failures.values() if f.category == ErrorCategory.LIMIT)
        assert "this connection's database server is at its limit of 3 calls in flight" in str(limited)
        assert "db2.example" not in str(limited), "the refusal must not name the server"
        assert _borrowed(svc) == 3
        start = time.monotonic()
        other = _Fake("pg", host="pg.example", port=5432)
        assert await svc.run_bounded(other, lambda c: "ok", 0.1, description="pg") == "ok"
        assert await svc.run_bounded(_Fake("local"), lambda c: "ok", 0.1, description="local") == "ok"
        assert time.monotonic() - start < 0.2
    finally:
        hung.set()
    assert await _until(lambda: _borrowed(svc) == 0)


@pytest.mark.anyio
async def test_call_handed_a_token_once_its_server_has_its_share_passes_it_on(
    anyio_backend: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Four calls to one server wait in line for a global token, ahead of a
    call to another server. The first three take the server's whole share
    as tokens come free; the fourth, handed a token next, gives it to the
    call behind it and waits for its share, instead of running a fourth
    call on the server."""
    monkeypatch.setattr(executor, "_MIN_QUEUE_SECONDS", 3.0)
    svc = ExecutionService(max_concurrent=4)
    hold = threading.Event()
    foreign = [object() for _ in range(4)]
    for holder in foreign:  # other servers' calls hold every global token
        await svc._limiter.acquire_on_behalf_of(holder)
    ran: list[str] = []
    results: dict[str, Any] = {}

    async def one(conn: _Fake) -> None:
        name = conn.connection.name
        results[name] = await svc.run_bounded(conn, _query(ran, name), 5.0, description=name)

    try:
        async with anyio.create_task_group() as tg:
            for i in range(4):
                tg.start_soon(one, _Fake(f"s{i}", query=hold, host="s.example"))
                await anyio.sleep(0.02)  # in this order
            tg.start_soon(one, _Fake("pg", host="pg.example"))
            await anyio.sleep(0.02)
            while foreign:
                svc._limiter.release_on_behalf_of(foreign.pop())
            assert await _until(lambda: "pg" in results), ran
            assert sorted(ran) == ["pg", "s0", "s1", "s2"], "the fourth call to the server must wait for its share"
            hold.set()
        assert sorted(ran) == ["pg", "s0", "s1", "s2", "s3"]
    finally:
        hold.set()
        for holder in foreign:
            svc._limiter.release_on_behalf_of(holder)
    assert await _until(lambda: _borrowed(svc) == 0)


@pytest.mark.anyio
async def test_parked_connect_that_then_connected_leaves_its_servers_share(
    anyio_backend: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A connect parked past its bound gave its global token back. When it
    connects after all and its statement runs on, it holds a stuck-connect
    slot, not a global token, and does not count toward its server's share:
    three other calls to the server still run side by side (max 4), and a
    fourth waits for the share."""
    monkeypatch.setattr(executor, "_HUNG_CONNECT_FLOOR", 0.1, raising=False)
    monkeypatch.setattr(executor, "_QUEUE_TIMEOUT_FACTOR", 1.0)
    monkeypatch.setattr(executor, "_MIN_QUEUE_SECONDS", 0.3)
    svc = ExecutionService(max_concurrent=4)
    connect, query, hold = threading.Event(), threading.Event(), threading.Event()
    ran: list[str] = []

    async def one(name: str) -> None:
        await svc.run_bounded(_Fake(name, query=hold, host="s.example"), _query(ran, name), 5.0, description=name)

    try:
        with pytest.raises(ToolFailure):
            late = _Fake("late", connect=connect, query=query, host="s.example", connect_timeout=0.1)
            await svc.run_bounded(late, _query(ran, "late"), 0.4, description="late")
        assert await _until(lambda: (_parked(svc), _borrowed(svc)) == (1, 0))
        connect.set()  # it connects after all; its statement runs on
        await anyio.sleep(0.1)
        async with anyio.create_task_group() as tg:
            for name in ("a", "b", "c"):
                tg.start_soon(one, name)
            assert await _until(lambda: {"a", "b", "c"} <= set(ran)), ran
            with pytest.raises(ToolFailure) as limited:
                await svc.run_bounded(_Fake("d", host="s.example"), _query(ran, "d"), 0.1, description="d")
            hold.set()
        assert limited.value.category == ErrorCategory.LIMIT
        assert "at its limit of 3 calls in flight" in str(limited.value)
        assert "d" not in ran
        assert _parked(svc) == 1, "the connect that completed late still holds its stuck-connect slot"
    finally:
        connect.set()
        query.set()
        hold.set()
    assert await _until(lambda: _borrowed(svc) == 0 and _parked(svc) == 0)


@pytest.mark.anyio
@pytest.mark.parametrize("arrives", ["before the abandonment", "after the abandonment"])
async def test_call_waiting_for_a_token_held_by_connects_abandoned_within_their_bound_gets_one_at_the_bound(
    anyio_backend: str, monkeypatch: pytest.MonkeyPatch, arrives: str
) -> None:
    """Calls whose deadline is shorter than the connect bound abandon three
    connects to one dead server; with another call, they hold every global
    token. A call to another server that waits for a token gets one at the
    connects' bound, when they are parked, well within its queue budget,
    whether it began waiting before they were abandoned or after."""
    monkeypatch.setattr(executor, "_HUNG_CONNECT_FLOOR", 0.4, raising=False)
    monkeypatch.setattr(executor, "_MIN_QUEUE_SECONDS", 3.0)
    svc = ExecutionService(max_concurrent=4)
    hung = threading.Event()
    holder = object()
    await svc._limiter.acquire_on_behalf_of(holder)  # another server's call
    calls: list[str] = []
    out: dict[str, Any] = {}
    ended: dict[str, float] = {}
    start = time.monotonic()
    try:
        async with anyio.create_task_group() as tg:
            async with anyio.create_task_group() as fan_out:
                for i in range(3):
                    conn = _dead(f"dead{i}", "db2.example", hung)
                    fan_out.start_soon(_call_into, svc, conn, _health(calls), 0.25, out, ended, start)
                assert await _until(lambda: len(calls) == 3)
                if arrives == "before the abandonment":
                    pg = _Fake("pg", host="pg.example", port=5432)
                    tg.start_soon(_call_into, svc, pg, lambda c: "ok", 1.0, out, ended, start)
            assert [out[f"dead{i}"].category for i in range(3)] == [ErrorCategory.TIMEOUT] * 3
            if arrives == "after the abandonment":
                pg = _Fake("pg", host="pg.example", port=5432)
                tg.start_soon(_call_into, svc, pg, lambda c: "ok", 1.0, out, ended, start)
        assert out["pg"] == "ok", out["pg"]
        bound = _first_bound(svc, ("fake", "db2.example", 50001), start)
        assert ended["pg"] - bound < 0.25, (ended, bound)
        # pg's token comes at the first connect's bound; the others, whose
        # worker threads started a moment later, are parked at their own.
        assert await _until(lambda: (_parked(svc), _borrowed(svc)) == (3, 1))
    finally:
        hung.set()
        svc._limiter.release_on_behalf_of(holder)
    assert await _until(lambda: _borrowed(svc) == 0 and _parked(svc) == 0)


@pytest.mark.anyio
async def test_call_in_line_before_a_connect_to_its_server_is_abandoned_is_refused_at_the_bound(
    anyio_backend: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A call to a server waits in line for a global token while a connect
    to that server is still running; the connect's request is abandoned
    within its bound. At the bound the connect is parked and the call is
    refused, since the server hangs, instead of waiting out its queue
    budget or starting another connect there."""
    monkeypatch.setattr(executor, "_HUNG_CONNECT_FLOOR", 0.4, raising=False)
    monkeypatch.setattr(executor, "_MIN_QUEUE_SECONDS", 3.0)
    svc = ExecutionService(max_concurrent=4)
    hung = threading.Event()
    foreign = [object() for _ in range(3)]
    for holder in foreign:  # other servers' calls hold three global tokens
        await svc._limiter.acquire_on_behalf_of(holder)
    calls: list[str] = []
    out: dict[str, Any] = {}
    ended: dict[str, float] = {}
    start = time.monotonic()
    try:
        async with anyio.create_task_group() as tg:
            # a1 takes the last token and is abandoned at 0.1 s, within its bound.
            tg.start_soon(_call_into, svc, _dead("a1", "s.example", hung), _health(calls), 0.1, out, ended, start)
            assert await _until(lambda: "a1" in calls)
            tg.start_soon(_call_into, svc, _dead("a2", "s.example", hung), _health(calls), 0.5, out, ended, start)
        bound = _first_bound(svc, ("fake", "s.example", 50001), start)
    finally:
        hung.set()
        for holder in foreign:
            svc._limiter.release_on_behalf_of(holder)
    assert out["a1"].category == ErrorCategory.TIMEOUT
    assert isinstance(out["a2"], ToolFailure), out["a2"]
    assert out["a2"].category == ErrorCategory.CONNECTION, out["a2"]
    assert "a connect to its database server did not complete" in str(out["a2"])
    assert ended["a2"] - bound < 0.25, (ended, bound)
    assert calls == ["a1"]
    assert await _until(lambda: _borrowed(svc) == 0 and _parked(svc) == 0)


@pytest.mark.anyio
async def test_call_waiting_for_its_servers_share_is_refused_at_the_bound_of_a_connect_abandoned_after(
    anyio_backend: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two abandoned statements and a connect still running hold a server's
    share (max 4), so another call to the server waits for it. The connect's
    request is then abandoned within its bound: at the bound the waiting
    call is refused, since the server hangs, instead of waiting out its
    queue budget."""
    monkeypatch.setattr(executor, "_HUNG_CONNECT_FLOOR", 0.4, raising=False)
    monkeypatch.setattr(executor, "_MIN_QUEUE_SECONDS", 3.0)
    svc = ExecutionService(max_concurrent=4)
    hung, query = threading.Event(), threading.Event()
    calls: list[str] = []
    out: dict[str, Any] = {}
    ended: dict[str, float] = {}
    start = time.monotonic()
    try:
        for i in range(2):  # statements no cancel hook stops (Db2, SQL Server)
            with pytest.raises(ToolFailure):
                conn = _Fake(f"st{i}", query=query, host="s.example", port=50001)
                await svc.run_bounded(conn, _query(calls, f"st{i}"), 0.05, description=f"st{i}")
        async with anyio.create_task_group() as tg:
            tg.start_soon(_call_into, svc, _dead("c", "s.example", hung), _health(calls), 0.15, out, ended, start)
            assert await _until(lambda: "c" in calls)
            waiting = _Fake("w", host="s.example", port=50001)
            tg.start_soon(_call_into, svc, waiting, _health(calls), 1.0, out, ended, start)
            await anyio.sleep(0.02)
            assert svc._server_waiters[("fake", "s.example", 50001)], "w waits for its server's share"
        bound = _first_bound(svc, ("fake", "s.example", 50001), start)
    finally:
        hung.set()
        query.set()
    assert out["c"].category == ErrorCategory.TIMEOUT
    assert isinstance(out["w"], ToolFailure), out["w"]
    assert out["w"].category == ErrorCategory.CONNECTION, out["w"]
    assert "a connect to its database server did not complete" in str(out["w"])
    assert ended["w"] - bound < 0.25, (ended, bound)
    assert "w" not in calls
    assert await _until(lambda: _borrowed(svc) == 0 and _parked(svc) == 0)


@pytest.mark.anyio
@pytest.mark.parametrize("max_concurrent", [4, 64])
async def test_stuck_connect_budget_has_ten_slots_whatever_the_concurrency_limit(
    anyio_backend: str, monkeypatch: pytest.MonkeyPatch, max_concurrent: int
) -> None:
    """Threads parked in a hung connect cannot be reclaimed, so at most ten
    wait in the stuck-connect budget however high max_concurrent_queries is.
    At the default of 4 the budget still has ten slots: a fan-out over a few
    dead servers leaves the healthy ones running."""
    monkeypatch.setattr(executor, "_HUNG_CONNECT_FLOOR", 0.1, raising=False)
    svc = ExecutionService(max_concurrent=max_concurrent)
    hung = threading.Event()
    calls: list[str] = []

    async def one(i: int) -> None:
        with pytest.raises(ToolFailure) as exc:
            await svc.run_bounded(_dead(f"dead{i}", f"db{i}.example", hung), _health(calls), 0.4, description="d")
        assert exc.value.category == ErrorCategory.TIMEOUT

    try:
        async with anyio.create_task_group() as tg:
            for i in range(10):
                tg.start_soon(one, i)
        assert await _until(lambda: (_parked(svc), _borrowed(svc)) == (10, 0))
        with pytest.raises(ToolFailure) as refused:
            await svc.run_bounded(_dead("dead10", "db10.example", hung), _health(calls), 0.4, description="d")
        assert refused.value.category == ErrorCategory.CONNECTION
        assert "the limit of 10 pending connects to database servers that did not answer" in str(refused.value)
        assert len(calls) == 10, "the eleventh connect never starts"
        assert await svc.run_bounded(_Fake("local"), lambda c: "ok", 1.0, description="local") == "ok"
    finally:
        hung.set()
    assert await _until(lambda: _parked(svc) == 0 and _borrowed(svc) == 0)


@pytest.mark.anyio
async def test_a_full_budget_of_one_pending_connect_says_so(
    anyio_backend: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(executor, "_HUNG_CONNECT_FLOOR", 0.1, raising=False)
    monkeypatch.setattr(executor, "_STUCK_CONNECT_SLOTS", 1)
    svc = ExecutionService(max_concurrent=4)
    hung = threading.Event()
    try:
        with pytest.raises(ToolFailure):
            await svc.run_bounded(_dead("dead", "db.example", hung), _health([]), 0.4, description="dead")
        assert await _until(lambda: _parked(svc) == 1)
        with pytest.raises(ToolFailure) as refused:
            await svc.run_bounded(_Fake("pg", host="pg.example"), lambda c: "ok", 1.0, description="pg")
        assert "the limit of 1 pending connect to database servers that did not answer" in str(refused.value)
    finally:
        hung.set()
    assert await _until(lambda: _parked(svc) == 0)


@pytest.mark.anyio
async def test_connect_that_completed_within_its_bound_leaves_the_calls_in_line_in_their_order(
    anyio_backend: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A deadline caught a connect that then completed within its bound; its
    statement runs on. At the bound nothing says the server hangs, so the
    calls to that server waiting in line for a global token keep their
    places, behind and ahead of calls to other servers."""
    monkeypatch.setattr(executor, "_HUNG_CONNECT_FLOOR", 0.3, raising=False)
    monkeypatch.setattr(executor, "_MIN_QUEUE_SECONDS", 3.0)
    svc = ExecutionService(max_concurrent=4)
    connect, query = threading.Event(), threading.Event()
    foreign = [object() for _ in range(3)]
    for holder in foreign:  # other calls hold the other global tokens
        await svc._limiter.acquire_on_behalf_of(holder)
    order: list[str] = []

    async def one(conn: _Fake) -> None:
        await svc.run_bounded(conn, lambda c: order.append(c.connection.name), 1.0, description="c")

    try:
        with pytest.raises(ToolFailure):
            conn = _Fake("a", connect=connect, query=query, host="s.example", connect_timeout=0.1)
            await svc.run_bounded(conn, _query([], "long"), 0.05, description="a")
        connect.set()  # connected within its bound; the statement runs on
        async with anyio.create_task_group() as tg:
            for name, host in [("hr", "s.example"), ("pg", "pg.example"), ("ops", "s.example")]:
                tg.start_soon(one, _Fake(name, host=host))
                await anyio.sleep(0.05)  # in this order
            await anyio.sleep(0.3)  # past a's connect bound
            while foreign:  # one token at a time goes round the line
                svc._limiter.release_on_behalf_of(foreign.pop())
                await anyio.sleep(0.05)
        assert order == ["hr", "pg", "ops"]
    finally:
        connect.set()
        query.set()
        for holder in foreign:
            svc._limiter.release_on_behalf_of(holder)
    assert await _until(lambda: _borrowed(svc) == 0)


@pytest.mark.anyio
async def test_alarm_run_early_by_the_loop_clock_still_parks_the_connect(
    anyio_backend: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The event loop may run a timer up to one clock tick before it is due
    (15.6 ms with Windows' monotonic clock on Python 3.12): the alarm at a
    connect's bound treats its own firing as the bound."""
    monkeypatch.setattr(executor, "_HUNG_CONNECT_FLOOR", 0.4, raising=False)
    svc = ExecutionService(max_concurrent=4)
    hung = threading.Event()
    server = ("fake", "s.example", 50001)
    try:
        with pytest.raises(ToolFailure):
            await svc.run_bounded(_dead("a", "s.example", hung), _health([]), 0.05, description="a")
        (run,) = svc._hung_connects[server]
        assert run.hung_after > time.monotonic(), "the connect is still within its bound"
        svc._at_bound(server, run.hung_after)  # as if the loop ran the alarm early
        assert (_parked(svc), _borrowed(svc)) == (1, 0)
    finally:
        hung.set()
    assert await _until(lambda: _borrowed(svc) == 0 and _parked(svc) == 0)


# ------------------------------------------------------------------ review round 5


@pytest.mark.anyio
@pytest.mark.parametrize("max_concurrent", [3, 4, 8])
async def test_healthy_calls_to_one_server_hold_every_global_token_but_one(
    anyio_backend: str, max_concurrent: int
) -> None:
    """From a limit of 3 up, every call to a database server that holds a
    global token counts toward its share, healthy ones too: at the default
    of 4, three calls to one server run side by side and a fourth waits
    until one of them returns, while a call to another server runs at once.
    Only with a limit of 2 do healthy calls to one server use every token
    (test_healthy_calls_to_one_server_run_in_parallel)."""
    svc = ExecutionService(max_concurrent=max_concurrent)
    share = max_concurrent - 1
    side_by_side = threading.Barrier(share)
    hold = threading.Event()
    ran: list[str] = []
    results: dict[str, Any] = {}

    def fn(c: DatabaseConnector) -> str:
        name = str(c.connection.name)
        ran.append(name)
        if name != "extra":
            side_by_side.wait(timeout=3)  # BrokenBarrierError unless the share runs at once
        hold.wait(10)
        return name

    async def one(name: str) -> None:
        results[name] = await svc.run_bounded(_Fake(name, host="pg.example", port=5432), fn, 5.0, description=name)

    try:
        async with anyio.create_task_group() as tg:
            for i in range(share):
                tg.start_soon(one, f"s{i}")
            assert await _until(lambda: len(ran) == share)
            tg.start_soon(one, "extra")
            await anyio.sleep(0.1)
            assert "extra" not in ran, "the call past the server's share waits for one to return"
            other = _Fake("other", host="other.example", port=5432)
            assert await svc.run_bounded(other, lambda c: "ok", 1.0, description="other") == "ok"
            hold.set()
        assert sorted(results) == sorted([f"s{i}" for i in range(share)] + ["extra"])
    finally:
        hold.set()
    assert _borrowed(svc) == 0


def _coarse_monotonic(monkeypatch: pytest.MonkeyPatch) -> None:
    """time.monotonic() as CPython 3.12 reads it on Windows (GetTickCount64,
    15.625 ms ticks; the MSI installs 3.12), with the event loop's clock
    resolution to match: asyncio runs a timer once it is due within one
    resolution, so up to a tick before the clock reaches it."""
    tick = 0.015625
    precise = time.monotonic
    monkeypatch.setattr(time, "monotonic", lambda: math.floor(precise() / tick) * tick)
    monkeypatch.setattr(asyncio.get_running_loop(), "_clock_resolution", tick)


async def _traffic(stop: anyio.Event) -> None:
    """Other work on the server's event loop (HTTP requests, other calls),
    which wakes it every few milliseconds until stopped."""
    while not stop.is_set():
        with anyio.move_on_after(0.003):
            await stop.wait()


@pytest.mark.anyio
async def test_call_in_line_is_refused_at_the_bound_on_a_coarse_monotonic_clock(
    anyio_backend: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The at-bound alarm may act on a connect a clock tick before
    time.monotonic() shows it past its bound. The call it wakes, and every
    later check, must agree that the connect is past its bound: the call in
    line is refused, instead of taking the token the parking freed and
    starting a connect against the hung server."""
    monkeypatch.setattr(executor, "_HUNG_CONNECT_FLOOR", 0.4, raising=False)
    monkeypatch.setattr(executor, "_MIN_QUEUE_SECONDS", 3.0)
    _coarse_monotonic(monkeypatch)
    svc = ExecutionService(max_concurrent=4)
    hung = threading.Event()
    foreign = [object() for _ in range(3)]
    for holder in foreign:  # other servers' calls hold three global tokens
        await svc._limiter.acquire_on_behalf_of(holder)
    calls: list[str] = []
    out: dict[str, Any] = {}
    ended: dict[str, float] = {}
    start = time.monotonic()
    stop = anyio.Event()
    try:
        async with anyio.create_task_group() as tg:
            tg.start_soon(_traffic, stop)
            async with anyio.create_task_group() as in_line:
                # a1 takes the last token and is abandoned at 0.1 s, within its bound.
                a1 = _dead("a1", "s.example", hung)
                in_line.start_soon(_call_into, svc, a1, _health(calls), 0.1, out, ended, start)
                assert await _until(lambda: "a1" in calls)
                a2 = _dead("a2", "s.example", hung)
                in_line.start_soon(_call_into, svc, a2, _health(calls), 0.5, out, ended, start)
            stop.set()
    finally:
        hung.set()
        for holder in foreign:
            svc._limiter.release_on_behalf_of(holder)
    assert isinstance(out["a2"], ToolFailure), out["a2"]
    assert out["a2"].category == ErrorCategory.CONNECTION, out["a2"]
    assert "a connect to its database server did not complete" in str(out["a2"])
    assert calls == ["a1"], "a2 must not start a connect against the hung server"
    assert await _until(lambda: _borrowed(svc) == 0 and _parked(svc) == 0)


@pytest.mark.anyio
async def test_fan_out_over_a_dead_server_starts_no_fourth_connect_on_a_coarse_monotonic_clock(
    anyio_backend: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """test_fan_out_over_a_dead_server_leaves_a_token_and_its_last_call_ends_at_the_bound
    on Windows' clock: the call left waiting for the server's share is
    refused at the first connect's bound and never connects."""
    monkeypatch.setattr(executor, "_HUNG_CONNECT_FLOOR", 0.4, raising=False)
    monkeypatch.setattr(executor, "_MIN_QUEUE_SECONDS", 2.0)
    _coarse_monotonic(monkeypatch)
    svc = ExecutionService(max_concurrent=4)
    hung = threading.Event()
    calls: list[str] = []
    out: dict[str, Any] = {}
    ended: dict[str, float] = {}
    start = time.monotonic()
    stop = anyio.Event()
    try:
        async with anyio.create_task_group() as tg:
            tg.start_soon(_traffic, stop)
            async with anyio.create_task_group() as fan_out:
                for i in range(4):
                    conn = _dead(f"dead{i}", "db2.example", hung)
                    # Within the bound, with room for a worker thread to
                    # start under the traffic and the coarse clock.
                    fan_out.start_soon(_call_into, svc, conn, _health(calls), 0.25, out, ended, start)
            stop.set()
    finally:
        hung.set()
    assert len(calls) == 3, f"a fourth connect started against the dead server: {calls}"
    refused = [name for name, result in out.items() if result.category == ErrorCategory.CONNECTION]
    assert len(refused) == 1, out
    assert await _until(lambda: _borrowed(svc) == 0 and _parked(svc) == 0)


def _address(engine: str, host: str, port: int | None, *, tls: bool = False) -> Any:
    """The database server the executor keys a connection's config on."""
    conn = _Fake("x", host=host, port=port, engine=engine)
    conn.connection.config.tls = SimpleNamespace(enabled=tls)
    return executor._server(conn)


@pytest.mark.parametrize(
    ("engine", "one", "other"),
    [
        ("postgres", ("pg.example", None), ("pg.example", 5432)),
        ("mysql", ("my.example", None), ("my.example", 3306)),
        ("oracle", ("ora.example", None), ("ora.example", 1521)),
        ("mssql", ("sql.example", None), ("sql.example", 1433)),
        ("db2", ("db2.example", None), ("db2.example", 50000)),
        ("clickhouse", ("ch.example", None), ("ch.example", 8123)),
        ("db2", ("DB2.Example.", 50000), ("db2.example", None)),
        # With a port, the driver dials it and the instance name is not used.
        ("mssql", ("SQL.example\\SALES", 1433), ("sql.example", None)),
    ],
)
def test_one_database_server_spelled_several_ways_is_one_server(
    engine: str, one: tuple[str, int | None], other: tuple[str, int | None]
) -> None:
    assert _address(engine, *one) == _address(engine, *other)


@pytest.mark.parametrize(
    ("engine", "one", "other"),
    [
        ("postgres", ("pg.example", None), ("pg.example", 5433)),
        ("postgres", ("pg.example", 5432), ("pg2.example", 5432)),
        # A named instance listens on a port of its own, found through SQL
        # Server Browser: it is not the default instance.
        ("mssql", ("sql.example\\SALES", None), ("sql.example", 1433)),
        ("mssql", ("sql.example\\SALES", None), ("sql.example\\HR", None)),
    ],
)
def test_distinct_database_servers_stay_distinct(
    engine: str, one: tuple[str, int | None], other: tuple[str, int | None]
) -> None:
    assert _address(engine, *one) != _address(engine, *other)


def test_clickhouse_without_a_port_is_its_https_port_under_tls() -> None:
    assert _address("clickhouse", "ch.example", None, tls=True) == _address("clickhouse", "ch.example", 8443, tls=True)
    assert _address("clickhouse", "ch.example", None, tls=True) != _address("clickhouse", "ch.example", 8123)


@pytest.mark.parametrize(
    ("engine", "port", "dials"),
    [
        ("postgres", 5432, "cfg.port or 5432"),
        ("mysql", 3306, "cfg.port or 3306"),
        ("oracle", 1521, "cfg.port or 1521"),
        ("mssql", 1433, "cfg.port or 1433"),
        ("db2", 50000, "cfg.port or 50000"),
        ("clickhouse", 8123, "cfg.port or (8443 if cfg.tls.enabled else 8123)"),
    ],
)
def test_default_ports_are_the_ones_the_connectors_dial(engine: str, port: int, dials: str) -> None:
    """The connectors are the source of truth for the port a config without
    one reaches."""
    assert dials in inspect.getsource(importlib.import_module(f"universal_db_mcp.connectors.{engine}"))
    assert _address(engine, "h.example", None) == (engine, "h.example", port)


@pytest.mark.anyio
async def test_statement_fan_out_over_one_server_spelled_several_ways_leaves_a_global_token(
    anyio_backend: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Connection ids on one Db2 server may leave the port out (the driver
    dials 50000) or spell it out, and write the host in another case or with
    a trailing dot. They are one database server for its share of the global
    tokens, so a parallel fan-out of statements no cancel hook stops still
    leaves a token for the other servers and SQLite."""
    monkeypatch.setattr(executor, "_QUEUE_TIMEOUT_FACTOR", 1.0)
    monkeypatch.setattr(executor, "_MIN_QUEUE_SECONDS", 0.3)
    svc = ExecutionService(max_concurrent=4)
    hung = threading.Event()
    ran: list[str] = []
    failures: dict[str, ToolFailure] = {}
    spellings = [("DB2.example.", None), ("db2.example", 50000), ("Db2.Example", None), ("db2.example.", 50000)]

    async def one(i: int) -> None:
        host, port = spellings[i]
        conn = _Fake(f"db2_{i}", query=hung, host=host, port=port, engine="db2")
        try:
            await svc.run_bounded(conn, _query(ran, f"db2_{i}"), 0.1, description=f"db2_{i}")
        except ToolFailure as exc:
            failures[f"db2_{i}"] = exc

    try:
        async with anyio.create_task_group() as tg:
            for i in range(4):
                tg.start_soon(one, i)
        assert len(ran) == 3, ran
        categories = sorted(str(f.category) for f in failures.values())
        assert categories == sorted(map(str, [ErrorCategory.TIMEOUT] * 3 + [ErrorCategory.LIMIT]))
        assert _borrowed(svc) == 3
        assert await svc.run_bounded(_Fake("local"), lambda c: "ok", 0.1, description="local") == "ok"
    finally:
        hung.set()
    assert await _until(lambda: _borrowed(svc) == 0)


@pytest.mark.anyio
async def test_statements_of_parked_connects_that_connected_after_all_are_bounded_by_the_budget(
    anyio_backend: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A parked connect gave its global token back. If it connects after
    all, its statement runs outside the global limiter, still in its
    stuck-connect slot, until it returns. While those slots are taken,
    connections with a server address are refused, so at most
    max_concurrent_queries plus the budget's slots driver calls run at once
    (1 + 10 at a limit of 1)."""
    monkeypatch.setattr(executor, "_HUNG_CONNECT_FLOOR", 0.1, raising=False)
    monkeypatch.setattr(executor, "_STUCK_CONNECT_SLOTS", 3)
    svc = ExecutionService(max_concurrent=1)
    connect, query = threading.Event(), threading.Event()
    live, peak = [0], [0]
    counting = threading.Lock()

    def statement(c: DatabaseConnector) -> str:
        c._connect()
        with counting:
            live[0] += 1
            peak[0] = max(peak[0], live[0])
        try:
            query.wait(10)
        finally:
            with counting:
                live[0] -= 1
        return "done"

    out: dict[str, Any] = {}
    ended: dict[str, float] = {}
    start = time.monotonic()
    try:
        for i in range(3):
            late = _Fake(f"ora{i}", connect=connect, host=f"ora{i}.example", port=1521, connect_timeout=0.1)
            with pytest.raises(ToolFailure):
                await svc.run_bounded(late, statement, 0.4, description=f"ora{i}")
        assert await _until(lambda: (_parked(svc), _borrowed(svc)) == (3, 0))
        connect.set()  # the connects complete after all; their statements run on
        assert await _until(lambda: live[0] == 3)
        assert (_parked(svc), _borrowed(svc)) == (3, 0), "they keep their slots, and take no global token"
        # Their servers answer now, but the slots stay taken until the calls
        # return: another id on one of them, and any other server, are refused.
        for conn in (_Fake("ora_b", host="ora0.example", port=1521), _Fake("pg", host="pg.example")):
            with pytest.raises(ToolFailure) as refused:
                await svc.run_bounded(conn, statement, 1.0, description=conn.connection.name)
            assert "the limit of 3 pending connects" in str(refused.value)
        async with anyio.create_task_group() as tg:
            for i in range(2):
                tg.start_soon(_call_into, svc, _Fake(f"local{i}"), statement, 5.0, out, ended, start)
            assert await _until(lambda: live[0] == 4)
            await anyio.sleep(0.1)
            assert live[0] == 4, "the other SQLite call waits for the only global token"
            query.set()
        assert out == {"local0": "done", "local1": "done"}
        assert peak[0] == 4, "max_concurrent_queries 1 plus the budget's 3 slots"
    finally:
        connect.set()
        query.set()
    assert await _until(lambda: _borrowed(svc) == 0 and _parked(svc) == 0)


@pytest.mark.anyio
async def test_call_woken_for_its_servers_share_parks_a_connect_past_its_bound_itself(
    anyio_backend: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Without the at-bound alarm (another anyio backend, or a connect
    abandoned on an event loop that has closed since), a connect abandoned
    within its bound keeps its global token past the bound until something
    parks it. A call that wakes because its server's share has room parks it
    itself and takes the token that frees, instead of waiting behind it."""
    monkeypatch.setattr(executor, "_HUNG_CONNECT_FLOOR", 0.5, raising=False)
    monkeypatch.setattr(executor, "_MIN_QUEUE_SECONDS", 3.0)
    monkeypatch.setattr(ExecutionService, "_alarm_at_bound", lambda self, server, run: None)
    svc = ExecutionService(max_concurrent=2)
    hung, query, hold = threading.Event(), threading.Event(), threading.Event()
    out: dict[str, Any] = {}
    ended: dict[str, float] = {}
    start = time.monotonic()
    try:
        with pytest.raises(ToolFailure):  # abandoned within its bound, it keeps a token
            await svc.run_bounded(_dead("c", "t.example", hung), _health([]), 0.1, description="c")
        with pytest.raises(ToolFailure):  # a statement no hook stops: the other token, its server's share
            await svc.run_bounded(_Fake("st", query=query, host="s.example"), _query([], "st"), 0.1, description="st")
        async with anyio.create_task_group() as tg:
            x = _Fake("x", query=hold, host="u.example")
            tg.start_soon(_call_into, svc, x, _query([], "x"), 5.0, out, ended, start)  # in line for a token
            w = _Fake("w", host="s.example")
            tg.start_soon(_call_into, svc, w, lambda c: "ok", 1.0, out, ended, start)  # waits for its share
            await anyio.sleep(0.6)  # c's connect runs past its bound; nothing parks it
            assert (_parked(svc), _borrowed(svc)) == (0, 2)
            returned = time.monotonic() - start
            query.set()  # st returns: its token goes to x, and w wakes for its share
            assert await _until(lambda: "w" in out)
            hold.set()
        assert out["w"] == "ok", out["w"]
        assert ended["w"] - returned < 0.5, ended
        assert out["x"] == "x"
    finally:
        hung.set()
        query.set()
        hold.set()
    assert await _until(lambda: _borrowed(svc) == 0 and _parked(svc) == 0)


# ------------------------------------------------------------------ integration round 2


def test_connect_abandoned_within_its_bound_on_a_loop_that_closed_is_parked_by_the_next_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """site-check runs every tool call under an event loop of its own, and
    the at-bound alarm goes with its loop. A connect abandoned within its
    bound there is parked by the next request, on another loop, once past
    its bound: its global token (the only one here) goes to that request,
    instead of staying held until the driver returns."""
    monkeypatch.setattr(executor, "_HUNG_CONNECT_FLOOR", 0.4, raising=False)
    monkeypatch.setattr(executor, "_QUEUE_TIMEOUT_FACTOR", 1.0)
    monkeypatch.setattr(executor, "_MIN_QUEUE_SECONDS", 1.0)
    svc = ExecutionService(max_concurrent=1)
    hung = threading.Event()

    async def step(conn: DatabaseConnector, fn: Callable[[DatabaseConnector], Any], seconds: float) -> Any:
        return await svc.run_bounded(conn, fn, seconds, description="step")

    try:
        with pytest.raises(ToolFailure) as first:
            anyio.run(step, _dead("dead", "db.example", hung), _health([]), 0.2)
        assert "did not answer" not in str(first.value), "abandoned within its bound"
        assert (_parked(svc), _borrowed(svc)) == (0, 1)
        time.sleep(0.4)  # past the bound; the first loop, and its alarm, are gone
        assert anyio.run(step, _Fake("local"), lambda c: "ok", 0.5) == "ok"
        assert (_parked(svc), _borrowed(svc)) == (1, 0)
    finally:
        hung.set()
    waited = time.monotonic() + 3.0
    while svc._parked and time.monotonic() < waited:
        time.sleep(0.01)
    assert anyio.run(step, _Fake("pg", host="pg.example"), lambda c: "ok", 0.5) == "ok"
    assert (_parked(svc), _borrowed(svc)) == (0, 0)


@pytest.mark.anyio
@pytest.mark.parametrize("abandoned", ["within its bound", "past its bound"])
async def test_call_in_line_behind_another_server_is_refused_once_a_connect_to_its_server_hangs(
    anyio_backend: str, monkeypatch: pytest.MonkeyPatch, abandoned: str
) -> None:
    """Calls to other servers hold three global tokens and a connect to a
    dead server the fourth. A call to another server, then a call to the
    dead one, wait in line for a token. Once the connect is abandoned and
    past its bound (at the bound, for a request that left within it), its
    token goes to the first call in line. The call to the dead server,
    which waits for no share, is woken all the same and refused at once,
    instead of waiting out its queue budget for LIMIT_EXCEEDED."""
    monkeypatch.setattr(executor, "_HUNG_CONNECT_FLOOR", 0.4, raising=False)
    monkeypatch.setattr(executor, "_MIN_QUEUE_SECONDS", 3.0)
    svc = ExecutionService(max_concurrent=4)
    hung, hold = threading.Event(), threading.Event()
    foreign = [object() for _ in range(3)]
    for holder in foreign:  # other servers' calls hold three global tokens
        await svc._limiter.acquire_on_behalf_of(holder)
    calls: list[str] = []
    out: dict[str, Any] = {}
    ended: dict[str, float] = {}
    server = ("fake", "s.example", 50001)
    deadline = 0.2 if abandoned == "within its bound" else 0.6
    start = time.monotonic()
    try:
        async with anyio.create_task_group() as tg:
            tg.start_soon(_call_into, svc, _dead("c", "s.example", hung), _health(calls), deadline, out, ended, start)
            assert await _until(lambda: "c" in calls)
            if abandoned == "within its bound":
                assert await _until(lambda: "c" in out)
            t = _Fake("t", query=hold, host="t.example")
            tg.start_soon(_call_into, svc, t, _query(calls, "t"), 5.0, out, ended, start)
            await anyio.sleep(0.02)  # in this order
            w = _Fake("w", host="s.example", port=50001)
            tg.start_soon(_call_into, svc, w, _health(calls), 1.0, out, ended, start)
            await anyio.sleep(0.02)
            assert list(svc._server_waiters[server].values()) == [False], "w waits in line for a token"
            assert await _until(lambda: "w" in out, within=6.0)
            hold.set()
        bound = _first_bound(svc, server, start)
    finally:
        hung.set()
        hold.set()
        for holder in foreign:
            svc._limiter.release_on_behalf_of(holder)
    assert out["c"].category == ErrorCategory.TIMEOUT
    assert isinstance(out["w"], ToolFailure), out["w"]
    assert out["w"].category == ErrorCategory.CONNECTION, out["w"]
    assert "a connect to its database server did not complete" in str(out["w"])
    # Once the connect is both abandoned and past its bound.
    assert ended["w"] - max(bound, ended["c"]) < 0.25, (ended, bound)
    assert out["t"] == "t"
    assert calls == ["c", "t"]
    assert await _until(lambda: _borrowed(svc) == 0 and _parked(svc) == 0)


@pytest.mark.anyio
async def test_call_waiting_for_its_servers_share_is_refused_at_the_bound_when_the_freed_token_goes_elsewhere(
    anyio_backend: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two statements no cancel hook stops and a connect abandoned within
    its bound hold a server's share (max 4), and another server's call the
    fourth token. A call to a third server waits in line for a token; a call
    to the first server waits for its share. At the bound the connect is
    parked and its token goes to the call in line. The call waiting for the
    share is refused at once, since its server hangs, instead of waiting for
    a token until its queue budget runs out."""
    monkeypatch.setattr(executor, "_HUNG_CONNECT_FLOOR", 0.4, raising=False)
    monkeypatch.setattr(executor, "_MIN_QUEUE_SECONDS", 3.0)
    svc = ExecutionService(max_concurrent=4)
    hung, query, hold = threading.Event(), threading.Event(), threading.Event()
    holder = object()
    await svc._limiter.acquire_on_behalf_of(holder)  # another server's call
    calls: list[str] = []
    out: dict[str, Any] = {}
    ended: dict[str, float] = {}
    server = ("fake", "s.example", 50001)
    try:
        for i in range(2):  # statements no cancel hook stops (Db2, SQL Server)
            with pytest.raises(ToolFailure):
                conn = _Fake(f"st{i}", query=query, host="s.example", port=50001)
                await svc.run_bounded(conn, _query(calls, f"st{i}"), 0.2, description=f"st{i}")
        start = time.monotonic()
        with pytest.raises(ToolFailure):  # abandoned within its 0.4 s bound
            await svc.run_bounded(_dead("c", "s.example", hung), _health(calls), 0.2, description="c")
        assert _borrowed(svc) == 4
        async with anyio.create_task_group() as tg:
            t = _Fake("t", query=hold, host="t.example")
            tg.start_soon(_call_into, svc, t, _query(calls, "t"), 5.0, out, ended, start)
            await anyio.sleep(0.02)  # in this order
            w = _Fake("w", host="s.example", port=50001)
            tg.start_soon(_call_into, svc, w, _health(calls), 1.0, out, ended, start)
            await anyio.sleep(0.02)
            assert list(svc._server_waiters[server].values()) == [True], "w waits for its server's share"
            assert await _until(lambda: "w" in out, within=6.0)
            hold.set()
        bound = _first_bound(svc, server, start)
    finally:
        hung.set()
        query.set()
        hold.set()
        svc._limiter.release_on_behalf_of(holder)
    assert isinstance(out["w"], ToolFailure), out["w"]
    assert out["w"].category == ErrorCategory.CONNECTION, out["w"]
    assert "a connect to its database server did not complete" in str(out["w"])
    assert ended["w"] - bound < 0.25, (ended, bound)
    assert out["t"] == "t"
    assert calls == ["st0", "st1", "c", "t"]
    assert await _until(lambda: _borrowed(svc) == 0 and _parked(svc) == 0)


# ------------------------------------------------------------------ integration round 3


@pytest.mark.anyio
async def test_calls_refused_once_they_have_a_global_token_leave_their_server_open(
    anyio_backend: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A call counts toward its server's share from the moment it takes a
    global token. Calls refused right after (a connect parked as its request
    left filled the stuck-connect budget while they waited) leave nothing
    counted against their server: as many of them as its share would
    otherwise close it for the life of the process."""
    monkeypatch.setattr(executor, "_HUNG_CONNECT_FLOOR", 0.1, raising=False)
    monkeypatch.setattr(executor, "_STUCK_CONNECT_SLOTS", 4)
    svc = ExecutionService(max_concurrent=4)
    hung, last = threading.Event(), threading.Event()
    calls: list[str] = []
    failures: dict[str, ToolFailure] = {}
    foreign: list[object] = []

    async def call(conn: _Fake, deadline: float) -> None:
        try:
            await svc.run_bounded(conn, _health(calls), deadline, description=conn.connection.name)
        except ToolFailure as exc:
            failures[conn.connection.name] = exc

    try:
        for i in range(3):  # three of the four stuck-connect slots
            await call(_dead(f"dead{i}", f"db{i}.example", hung), 0.5)
        assert await _until(lambda: (_parked(svc), _borrowed(svc)) == (3, 0))
        for _ in range(3):  # other calls hold three global tokens
            holder = object()
            await svc._limiter.acquire_on_behalf_of(holder)
            foreign.append(holder)
        async with anyio.create_task_group() as tg:
            # Takes the last global token; parked as its request leaves past
            # its bound, it fills the budget.
            tg.start_soon(call, _dead("dead3", "db3.example", last), 0.5)
            assert await _until(lambda: "dead3" in calls)
            for i in range(3):  # in line for a global token, each refused once it has one
                tg.start_soon(call, _Fake(f"pg{i}", host="pg.example"), 1.0)
        assert [failures[f"pg{i}"].category for i in range(3)] == [ErrorCategory.CONNECTION] * 3
        assert "the limit of 4 pending connects" in str(failures["pg2"])
        assert not svc._holding.get(("fake", "pg.example", None)), "refused calls stay counted against their server"
        while foreign:
            svc._limiter.release_on_behalf_of(foreign.pop())
        last.set()  # dead3's connect returns: its slot frees
        assert await _until(lambda: _parked(svc) == 3)
        with anyio.fail_after(2):
            assert await svc.run_bounded(_Fake("pg", host="pg.example"), lambda c: "ok", 0.5, description="pg") == "ok"
        assert calls == [f"dead{i}" for i in range(4)]
    finally:
        hung.set()
        last.set()
        for holder in foreign:
            svc._limiter.release_on_behalf_of(holder)
    assert await _until(lambda: _borrowed(svc) == 0 and _parked(svc) == 0)


@pytest.mark.anyio
@pytest.mark.parametrize("how", ["deadline", "cancel"])
async def test_calls_that_give_up_before_a_worker_thread_starts_leave_their_server_open(
    anyio_backend: str, how: str
) -> None:
    """Every worker thread is busy. Calls to one server take a global token,
    and a place in the server's share with it, then their deadline fires or
    their client cancels before a thread picks them up. More such calls than
    the server's share leave it open."""
    svc = ExecutionService(max_concurrent=4)
    threads = anyio.to_thread.current_default_thread_limiter()
    saved = threads.total_tokens
    hold = threading.Event()
    ran: list[str] = []
    server = ("fake", "s.example", None)
    threads.total_tokens = 1
    try:
        async with anyio.create_task_group() as tg:
            tg.start_soon(anyio.to_thread.run_sync, lambda: hold.wait(10))  # the only worker thread
            assert await _until(lambda: threads.borrowed_tokens == 1)
            for i in range(4):
                conn = _Fake(f"s{i}", host="s.example")
                if how == "deadline":
                    with pytest.raises(ToolFailure) as exc:
                        await svc.run_bounded(conn, _query(ran, f"s{i}"), 0.05, description=f"s{i}")
                    assert "did not start within its deadline" in str(exc.value)
                else:
                    with anyio.move_on_after(0.05) as scope:
                        await svc.run_bounded(conn, _query(ran, f"s{i}"), 30.0, description=f"s{i}")
                    assert scope.cancelled_caught
                assert not svc._holding.get(server), f"s{i} stays counted against its server"
                assert _borrowed(svc) == 0
            hold.set()
        assert await svc.run_bounded(_Fake("s9", host="s.example"), _query(ran, "s9"), 1.0, description="s9") == "s9"
        assert ran == ["s9"]
    finally:
        hold.set()
        threads.total_tokens = saved
    assert _borrowed(svc) == 0


def test_calls_whose_tokens_come_back_on_a_later_event_loop_leave_their_server_open(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """site-check and scripts/live_evidence.py run every tool call under an
    event loop of its own. Three statements to one server that no cancel
    hook stops are abandoned and return after their loops closed: the next
    request returns their global tokens on its own loop, and their places in
    the server's share with them, or the server stays at its share for the
    life of the process."""
    monkeypatch.setattr(executor, "_QUEUE_TIMEOUT_FACTOR", 1.0)
    monkeypatch.setattr(executor, "_MIN_QUEUE_SECONDS", 0.5)
    svc = ExecutionService(max_concurrent=4)
    query = threading.Event()
    server = ("fake", "s.example", None)

    async def step(conn: DatabaseConnector, fn: Callable[[DatabaseConnector], Any], seconds: float) -> Any:
        return await svc.run_bounded(conn, fn, seconds, description="step")

    try:
        for i in range(3):
            with pytest.raises(ToolFailure) as exc:
                anyio.run(step, _Fake(f"s{i}", query=query, host="s.example"), _query([], f"s{i}"), 0.05)
            assert exc.value.category == ErrorCategory.TIMEOUT
        assert len(svc._holding[server]) == 3, "the three statements hold the server's share"
    finally:
        query.set()  # the statements return after their loops closed
    waited = time.monotonic() + 3.0
    while svc._abandoned and time.monotonic() < waited:
        time.sleep(0.01)
    assert svc._abandoned == {}
    assert anyio.run(step, _Fake("next", host="s.example"), lambda c: "ok", 0.5) == "ok"
    assert not svc._holding.get(server)
    assert _borrowed(svc) == 0


@pytest.mark.anyio
async def test_client_cancel_while_the_timeout_waits_on_the_cancel_hook_still_parks_a_hung_connect(
    anyio_backend: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The deadline fires on a connect hung past its bound, and the client's
    own cancel (notifications/cancelled, a client-side timeout as long as
    timeout_seconds) lands while the executor waits on the cancel hook. The
    connect is abandoned all the same as one that hangs: it gives its global
    token back and refuses the other connections to its server."""
    monkeypatch.setattr(executor, "_HUNG_CONNECT_FLOOR", 0.1, raising=False)
    svc = ExecutionService(max_concurrent=4)
    hung = threading.Event()
    calls: list[str] = []
    try:
        dead = _SlowHook("dead", connect=hung, host="db.example", port=50001, connect_timeout=0.1)
        with anyio.move_on_after(0.45) as scope:  # the deadline fires at 0.3 s; the hook takes 1 s
            await svc.run_bounded(dead, _health(calls), 0.3, description="dead")
        assert scope.cancelled_caught
        assert svc.is_poisoned(dead)
        assert (_parked(svc), _borrowed(svc)) == (1, 0), "the hung connect keeps its global token"
        with pytest.raises(ToolFailure) as refused:
            await svc.run_bounded(_dead("dead_b", "db.example", hung), _health(calls), 1.0, description="dead_b")
        assert refused.value.category == ErrorCategory.CONNECTION
        assert "a connect to its database server did not complete" in str(refused.value)
        assert calls == ["dead"]
    finally:
        hung.set()
    assert await _until(lambda: _borrowed(svc) == 0 and _parked(svc) == 0)


@pytest.mark.parametrize("waits", ["for its server's share", "in line for a global token"])
def test_call_on_a_later_event_loop_is_woken_at_the_bound_of_a_connect_abandoned_on_a_closed_one(
    monkeypatch: pytest.MonkeyPatch, waits: str
) -> None:
    """site-check runs every tool call under an event loop of its own, and
    the at-bound alarm of a connect abandoned within its bound was scheduled
    on a loop that is gone. A call on a later loop that waits for a token
    meanwhile is woken at the bound all the same: refused if it waits for
    the share of the server that hangs, handed the connect's token if it
    waits in line for one, instead of waiting out its queue budget."""
    monkeypatch.setattr(executor, "_HUNG_CONNECT_FLOOR", 0.5, raising=False)
    monkeypatch.setattr(executor, "_MIN_QUEUE_SECONDS", 3.0)
    svc = ExecutionService(max_concurrent=4)
    hung, query = threading.Event(), threading.Event()
    calls: list[str] = []
    server = ("fake", "s.example", 50001)

    async def step(conn: _Fake, fn: Callable[[DatabaseConnector], Any], seconds: float) -> Any:
        return await svc.run_bounded(conn, fn, seconds, description=conn.connection.name)

    statements = [_Fake(f"st{i}", query=query, host="s.example", port=50001) for i in range(2)]
    if waits == "in line for a global token":
        statements.append(_Fake("other", query=query, host="t.example"))  # the fourth token
    out: Any
    try:
        for conn in statements:  # statements no cancel hook stops (Db2, SQL Server)
            with pytest.raises(ToolFailure):
                anyio.run(step, conn, _query(calls, conn.connection.name), 0.05)
        start = time.monotonic()
        with pytest.raises(ToolFailure) as abandoned:
            anyio.run(step, _dead("c", "s.example", hung), _health(calls), 0.05)
        assert "did not answer" not in str(abandoned.value), "abandoned within its bound"
        assert _borrowed(svc) == len(statements) + 1
        waiting = _Fake("w", host="s.example", port=50001) if waits == "for its server's share" else _Fake("local")
        try:
            out = anyio.run(step, waiting, lambda c: "ok", 0.2)
        except ToolFailure as exc:
            out = exc
        ended = time.monotonic() - start
        bound = _first_bound(svc, server, start)
    finally:
        hung.set()
        query.set()
    if waits == "for its server's share":
        assert isinstance(out, ToolFailure), out
        assert out.category == ErrorCategory.CONNECTION, out
        assert "a connect to its database server did not complete" in str(out)
    else:
        assert out == "ok", out
    assert ended - bound < 0.25, (ended, bound)
    assert calls == [conn.connection.name for conn in statements] + ["c"]


# ------------------------------------------------------------------ integration round 3 fix-up


class _AnswersDuringTheHook(_Fake):
    """A database that answers the connect late, while the cancel hook runs
    (a network round-trip); the hook stops nothing, so the statement then
    runs on."""

    def cancel_current(self) -> bool:
        self.connect_gate.set()
        time.sleep(0.5)
        return False


@pytest.mark.anyio
async def test_connect_that_completed_during_the_cancel_hook_leaves_the_calls_in_line_in_their_order(
    anyio_backend: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The deadline caught a connect past its bound, and the connect
    completed while the cancel hook ran; its statement runs on. Nothing
    says the server hangs, so a call to that server waiting in line for a
    global token keeps its place ahead of a call to another server."""
    monkeypatch.setattr(executor, "_HUNG_CONNECT_FLOOR", 0.1, raising=False)
    svc = ExecutionService(max_concurrent=4)
    connect, query, hold = threading.Event(), threading.Event(), threading.Event()
    foreign = [object(), object()]
    for holder in foreign:  # other calls hold two of the global tokens
        await svc._limiter.acquire_on_behalf_of(holder)
    out: dict[str, Any] = {}
    ended: dict[str, float] = {}
    start = time.monotonic()
    order: list[str] = []

    def record(c: DatabaseConnector) -> Any:
        order.append(c.connection.name)

    try:
        async with anyio.create_task_group() as tg:
            late = _AnswersDuringTheHook("late", connect=connect, query=query, host="s.example", connect_timeout=0.1)
            tg.start_soon(_call_into, svc, late, _query([], "late"), 0.3, out, ended, start)
            await anyio.sleep(0.05)
            other = _Fake("other", query=hold, host="t.example")
            tg.start_soon(_call_into, svc, other, _query([], "other"), 5.0, out, ended, start)  # the last token
            assert await _until(lambda: _borrowed(svc) == 4)
            tg.start_soon(_call_into, svc, _Fake("ws", host="s.example"), record, 5.0, out, ended, start)
            await anyio.sleep(0.05)  # in this order
            tg.start_soon(_call_into, svc, _Fake("wu", host="u.example"), record, 5.0, out, ended, start)
            assert await _until(lambda: "late" in out)  # the deadline at 0.3 s, then the 0.5 s hook
            assert isinstance(out["late"], ToolFailure), out["late"]
            assert out["late"].category == ErrorCategory.TIMEOUT
            assert order == []
            svc._limiter.release_on_behalf_of(foreign.pop())  # one token goes round the line
            assert await _until(lambda: len(order) == 2)
            hold.set()
        assert order == ["ws", "wu"]
    finally:
        connect.set()
        query.set()
        hold.set()
        for holder in foreign:
            svc._limiter.release_on_behalf_of(holder)
    assert await _until(lambda: _borrowed(svc) == 0)


@pytest.mark.parametrize("waits", ["for its server's share", "in line for a global token"])
def test_call_on_a_later_event_loop_is_woken_when_tokens_handed_back_to_closed_ones_come_back(
    monkeypatch: pytest.MonkeyPatch, waits: str
) -> None:
    """site-check runs every tool call under an event loop of its own.
    Statements that no cancel hook stops are abandoned, and return while a
    call on a later loop waits for a token: their loops have closed, so
    their tokens come back on the latest request's loop, and the call runs
    then instead of waiting out its queue budget."""
    monkeypatch.setattr(executor, "_MIN_QUEUE_SECONDS", 3.0)
    query = threading.Event()
    calls: list[str] = []
    if waits == "for its server's share":
        svc = ExecutionService(max_concurrent=4)
        statements = [_Fake(f"st{i}", query=query, host="s.example") for i in range(3)]
        waiting = _Fake("w", host="s.example")
    else:
        svc = ExecutionService(max_concurrent=2)
        statements = [_Fake(f"st{i}", query=query) for i in range(2)]
        waiting = _Fake("local")

    async def step(conn: _Fake, fn: Callable[[DatabaseConnector], Any], seconds: float) -> Any:
        return await svc.run_bounded(conn, fn, seconds, description=conn.connection.name)

    answers = threading.Timer(0.5, query.set)  # the database answers while the call waits
    out: Any
    try:
        for conn in statements:
            with pytest.raises(ToolFailure):
                anyio.run(step, conn, _query(calls, conn.connection.name), 0.05)
        assert _borrowed(svc) == len(statements)
        start = time.monotonic()
        answers.start()
        try:
            out = anyio.run(step, waiting, lambda c: "ok", 0.2)
        except ToolFailure as exc:
            out = exc
        ended = time.monotonic() - start
    finally:
        answers.cancel()
        query.set()
    assert out == "ok", out
    assert ended < 1.5, ended
    assert calls == [conn.connection.name for conn in statements]
    assert (_borrowed(svc), svc._pending, svc._holding) == (0, {}, {})


@pytest.mark.anyio
async def test_requests_that_come_in_while_a_connect_is_within_its_bound_schedule_no_other_alarm(
    anyio_backend: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The server runs one event loop. Each request that comes in re-arms
    the at-bound alarms that went with another loop, and none of those that
    are on this one: a connect abandoned within its bound gets one alarm
    here, however many requests come in before its bound."""
    monkeypatch.setattr(executor, "_HUNG_CONNECT_FLOOR", 0.5, raising=False)
    alarms: list[float] = []
    at_bound = ExecutionService._at_bound

    def counted(self: ExecutionService, server: tuple[str, str, int | None], bound: float) -> None:
        alarms.append(bound)
        at_bound(self, server, bound)

    monkeypatch.setattr(ExecutionService, "_at_bound", counted)
    svc = ExecutionService(max_concurrent=4)
    hung = threading.Event()
    try:
        with pytest.raises(ToolFailure):
            await svc.run_bounded(_dead("c", "s.example", hung), _health([]), 0.05, description="c")
        for i in range(20):
            assert await svc.run_bounded(_Fake(f"l{i}"), lambda c: "ok", 1.0, description="l") == "ok"
        assert _parked(svc) == 0, "the requests came in within the bound"
        assert await _until(lambda: _parked(svc) == 1)
        await anyio.sleep(0.05)
    finally:
        hung.set()
    assert len(alarms) == 1, len(alarms)
    assert await _until(lambda: _borrowed(svc) == 0 and _parked(svc) == 0)


def test_slot_freed_by_a_connect_that_returned_after_its_loop_closed_hands_a_waiting_call_a_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """site-check runs every tool call under an event loop of its own. A
    parked connect returns after its loop closed, while a connect that
    waited for its stuck-connect slot holds a global token and a call on a
    later loop waits in line for one: the waiting connect moves into the
    slot at once, and its token goes to that call."""
    monkeypatch.setattr(executor, "_HUNG_CONNECT_FLOOR", 0.3, raising=False)
    monkeypatch.setattr(executor, "_STUCK_CONNECT_SLOTS", 1)
    monkeypatch.setattr(executor, "_MIN_QUEUE_SECONDS", 3.0)
    svc = ExecutionService(max_concurrent=3)
    first, second, query = threading.Event(), threading.Event(), threading.Event()

    async def step(conn: _Fake, fn: Callable[[DatabaseConnector], Any], seconds: float) -> Any:
        return await svc.run_bounded(conn, fn, seconds, description=conn.connection.name)

    answers = threading.Timer(0.5, first.set)  # the first dead server answers while the call waits
    out: Any
    try:
        for conn in [_dead("c1", "a.example", first), _dead("c2", "b.example", second)]:
            with pytest.raises(ToolFailure):  # abandoned within its bound
                anyio.run(step, conn, _health([]), 0.05)
        with pytest.raises(ToolFailure):  # a statement no hook stops: the third token
            anyio.run(step, _Fake("st1", query=query), _query([], "st1"), 0.05)
        time.sleep(0.35)  # past both bounds; their loops, and their alarms, are gone
        with pytest.raises(ToolFailure):  # parks c1 (the only slot) and takes its token
            anyio.run(step, _Fake("st2", query=query), _query([], "st2"), 0.05)
        assert (_parked(svc), _borrowed(svc)) == (1, 3), "c2 waits for the slot with its token"
        start = time.monotonic()
        answers.start()
        try:
            out = anyio.run(step, _Fake("local"), lambda c: "ok", 0.2)
        except ToolFailure as exc:
            out = exc
        ended = time.monotonic() - start
        assert out == "ok", out
        assert ended < 1.5, ended
        assert (_parked(svc), _borrowed(svc)) == (1, 2), "c2 took the freed slot"
    finally:
        answers.cancel()
        first.set()
        second.set()
        query.set()
    waited = time.monotonic() + 3.0
    while (svc._parked or svc._abandoned) and time.monotonic() < waited:
        time.sleep(0.01)
    assert anyio.run(step, _Fake("pg", host="pg.example"), lambda c: "ok", 0.5) == "ok"
    assert (_parked(svc), _borrowed(svc), svc._pending) == (0, 0, {})


def _answers_once_parked(
    monkeypatch: pytest.MonkeyPatch, server: tuple[str, str, int | None], connect: threading.Event
) -> list[bool]:
    """The first connect to the server that is parked completes right after
    it is parked, before anything else looks at it (a race of a few
    microseconds, forced here). Returns a list that says whether it did."""
    park = ExecutionService._park_hung_connects
    completed: list[bool] = []

    def park_then_complete(self: ExecutionService) -> None:
        before = _parked(self)
        park(self)
        if _parked(self) > before and not completed:
            completed.append(True)
            run = self._parked[server][0]
            connect.set()  # the database answers
            waited = time.monotonic() + 1.0
            while executor._in_connect(run.worker, run.connect_code) and time.monotonic() < waited:
                time.sleep(0.001)

    monkeypatch.setattr(ExecutionService, "_park_hung_connects", park_then_complete)
    return completed


@pytest.mark.anyio
async def test_call_waiting_for_its_servers_share_runs_when_a_parked_connect_completes_before_the_wake(
    anyio_backend: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two statements and a connect hold a server's share of 3, and a call
    to that server waits for the share. The connect is abandoned past its
    bound and parked, which frees its place in the share; it then completes
    before anything looks again, so nothing says the server hangs. The
    waiting call runs at once instead of waiting out its queue budget for a
    share the server no longer fills."""
    monkeypatch.setattr(executor, "_HUNG_CONNECT_FLOOR", 0.1, raising=False)
    monkeypatch.setattr(executor, "_MIN_QUEUE_SECONDS", 2.0)
    svc = ExecutionService(max_concurrent=4)
    connect, query, statement = threading.Event(), threading.Event(), threading.Event()
    server = ("fake", "s.example", 50001)
    completed = _answers_once_parked(monkeypatch, server, connect)
    out: dict[str, Any] = {}
    ended: dict[str, float] = {}
    start = time.monotonic()
    try:
        async with anyio.create_task_group() as tg:
            for i in range(2):
                conn = _Fake(f"st{i}", query=query, host="s.example", port=50001)
                tg.start_soon(_call_into, svc, conn, _query([], f"st{i}"), 5.0, out, ended, start)
            late = _Fake("late", connect=connect, query=statement, host="s.example", port=50001, connect_timeout=0.1)
            tg.start_soon(_call_into, svc, late, _query([], "late"), 0.3, out, ended, start)
            assert await _until(lambda: len(svc._holding.get(server, [])) == 3)
            waiting = _Fake("w", host="s.example", port=50001)
            tg.start_soon(_call_into, svc, waiting, lambda c: "ok", 0.2, out, ended, start)
            await anyio.sleep(0.05)
            assert list(svc._server_waiters[server].values()) == [True], "w waits for the share"
            assert await _until(lambda: "w" in out)
            query.set()
    finally:
        connect.set()
        query.set()
        statement.set()
    assert completed
    assert isinstance(out["late"], ToolFailure), out["late"]
    assert out["late"].category == ErrorCategory.TIMEOUT
    assert out["w"] == "ok", out["w"]
    assert ended["w"] - ended["late"] < 0.5, ended
    assert await _until(lambda: _borrowed(svc) == 0 and _parked(svc) == 0)
    assert svc._holding == {}


@pytest.mark.anyio
async def test_parked_connect_that_completes_before_the_wake_leaves_the_calls_in_line_in_their_order(
    anyio_backend: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A connect abandoned past its bound is parked, and completes before
    anything looks again, so nothing says its server hangs. Its token goes
    to the first call in line, and a call to its server behind that one
    keeps its place ahead of a call to another server."""
    monkeypatch.setattr(executor, "_HUNG_CONNECT_FLOOR", 0.1, raising=False)
    svc = ExecutionService(max_concurrent=4)
    connect, statement = threading.Event(), threading.Event()
    server = ("fake", "s.example", 50001)
    completed = _answers_once_parked(monkeypatch, server, connect)
    foreign = [object(), object(), object()]
    for holder in foreign:  # other calls hold three of the global tokens
        await svc._limiter.acquire_on_behalf_of(holder)
    out: dict[str, Any] = {}
    ended: dict[str, float] = {}
    start = time.monotonic()
    order: list[str] = []

    def record(c: DatabaseConnector) -> Any:
        order.append(c.connection.name)

    try:
        async with anyio.create_task_group() as tg:
            late = _Fake("late", connect=connect, query=statement, host="s.example", port=50001, connect_timeout=0.1)
            tg.start_soon(_call_into, svc, late, _query([], "late"), 0.5, out, ended, start)  # the last token
            assert await _until(lambda: _borrowed(svc) == 4)
            for name, host in [("wx", "x.example"), ("ws", "s.example"), ("wu", "u.example")]:
                tg.start_soon(_call_into, svc, _Fake(name, host=host, port=50001), record, 5.0, out, ended, start)
                await anyio.sleep(0.05)  # in this order
            assert list(svc._server_waiters[server].values()) == [False], "ws waits in line for a global token"
            assert await _until(lambda: "late" in out and len(order) == 3)
    finally:
        connect.set()
        statement.set()
        for holder in foreign:
            svc._limiter.release_on_behalf_of(holder)
    assert completed
    assert isinstance(out["late"], ToolFailure), out["late"]
    assert out["late"].category == ErrorCategory.TIMEOUT
    assert order == ["wx", "ws", "wu"]
    assert await _until(lambda: _borrowed(svc) == 0 and _parked(svc) == 0)
    assert svc._holding == {}


@pytest.mark.parametrize(
    ("engine", "host", "options", "server"),
    [
        # libpq takes a socket directory as the host: it is a server here.
        ("postgres", "/var/run/postgresql", {}, ("postgres", "/var/run/postgresql", 5432)),
        # MySQL reaches a local socket through options.unix_socket, without a
        # host: the mysqld behind that socket is its server.
        ("mysql", None, {"unix_socket": "/var/run/mysqld/mysqld.sock"},
         ("mysql", "unix_socket:/var/run/mysqld/mysqld.sock", None)),
        ("sqlite", None, {}, None),
    ],
)
def test_only_a_connection_without_a_host_has_no_database_server(
    engine: str, host: str | None, options: dict[str, str], server: tuple[str, str, int | None] | None
) -> None:
    conn = _Fake("x", host=host, engine=engine)
    conn.connection.config.options = options
    assert executor._server(conn) == server


# ================================================================ wave 4
# I29: an Oracle connection with options.tns_alias dials what its alias's
# tnsnames.ora descriptor names, never the configured host or port: it is
# keyed on the alias (and the directory that resolves it), so two aliases
# behind one placeholder host are two servers. A MySQL connection with
# options.unix_socket dials the socket, whatever its host says.


def _oracle(name: str, alias: str | None, *, host: str = "tns", admin: str = "/etc/udbmcp/tns", **kw: Any) -> _Fake:
    from universal_db_mcp.config import ConnectionConfig

    conn = _Fake(name, connect=kw.pop("connect", None))
    options = {"tns_alias": alias, "tns_admin": admin} if alias else {}
    conn.connection.config = ConnectionConfig(  # type: ignore[attr-defined]
        type="oracle", host=host, database="unused", connect_timeout_seconds=0.1, options=options, **kw
    )
    return conn


def test_two_tns_aliases_behind_one_placeholder_host_are_two_servers() -> None:
    fin, hr = executor._server(_oracle("finance", "FINPROD")), executor._server(_oracle("hr", "HRPROD"))
    assert fin is not None and hr is not None and fin != hr
    # the alias the driver resolves, however it is spelled, under whatever id
    assert executor._server(_oracle("finance2", "finprod", host="elsewhere")) == fin
    # another tnsnames.ora may say something else under the same name
    assert executor._server(_oracle("finance3", "FINPROD", admin="/etc/udbmcp/tns-dr")) != fin
    # an alias is not the host/port its placeholder names
    assert executor._server(_oracle("direct", None, host="tns", port=1521)) not in (fin, hr)


def test_one_tns_alias_is_one_server_however_its_directory_is_spelled() -> None:
    """Review round 2: each spelling of one tnsnames.ora directory (or stray
    whitespace around the alias) was a server of its own, with its own share
    and breaker, so one dead listener could take the whole stuck-connect
    budget. In Thick mode the process-wide config_dir resolves every alias
    and a connection's tns_admin is not read."""
    fin = executor._server(_oracle("finance", "FINPROD"))
    for admin in ("/etc/udbmcp/tns/", "/etc/udbmcp//tns", "/etc/../etc/udbmcp/tns", "/etc/udbmcp/./tns"):
        assert executor._server(_oracle("finance2", "FINPROD", admin=admin)) == fin, admin
    padded = _oracle("finance3", "FINPROD")
    padded.connection.config.options["tns_alias"] = " FINPROD\t"  # the config refuses it; the key does not care
    assert executor._server(padded) == fin
    spellings = [("FINPROD", "/etc/udbmcp/tns"), ("FINPROD", "/opt/tns"), ("HRPROD", "/opt/tns")]
    thick = [_oracle(f"t{i}", alias, admin=admin) for i, (alias, admin) in enumerate(spellings)]
    for conn in thick:
        conn.connection.config.options["thick_mode"] = True
    assert executor._server(thick[0]) == executor._server(thick[1]) != executor._server(thick[2])


def test_a_thick_tls_alias_is_keyed_on_its_own_tns_admin() -> None:
    """Final review: with tls.enabled, Thick mode also reads the alias from the
    connection's own tns_admin (OracleConnector._connect builds the TCPS
    descriptor from it), so one alias name under two directories reaches two
    listeners and must be two servers; without TLS the process-wide
    config_dir still resolves it and they stay one."""
    from universal_db_mcp.config import TlsConfig

    def thick(name: str, admin: str, tls: bool) -> _Fake:
        conn = _oracle(name, "PROD", admin=admin)
        conn.connection.config.options["thick_mode"] = True
        # only the key is under test: skip the CA/wallet validation a real TLS block needs
        config = conn.connection.config  # type: ignore[attr-defined]
        conn.connection.config = config.model_copy(update={"tls": TlsConfig.model_construct(enabled=tls)})  # type: ignore[attr-defined]
        return conn

    fin_tls = executor._server(thick("fin", "/opt/fin/tns", True))
    assert fin_tls != executor._server(thick("hr", "/opt/hr/tns", True))
    assert fin_tls == executor._server(thick("fin2", "/opt/fin/tns/", True))
    assert executor._server(thick("fin", "/opt/fin/tns", False)) == executor._server(thick("hr", "/opt/hr/tns", False))


@pytest.mark.anyio
async def test_a_hung_listener_behind_one_alias_does_not_refuse_another_alias(
    anyio_backend: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The review's repro: FINPROD's listener accepts and never answers, HRPROD
    is healthy, both behind host 'tns'. hr was refused with the hung-server
    CONNECTION_ERROR for as long as finance's connect hung."""
    monkeypatch.setattr(executor, "_HUNG_CONNECT_FLOOR", 0.1, raising=False)
    svc = ExecutionService(max_concurrent=4)
    dead = threading.Event()
    try:
        with pytest.raises(ToolFailure) as first:
            await svc.run_bounded(_oracle("finance", "FINPROD", connect=dead), _health([]), 0.3, description="finance")
        assert first.value.category == ErrorCategory.TIMEOUT
        assert await _until(lambda: _parked(svc) == 1)
        assert await svc.run_bounded(_oracle("hr", "HRPROD"), lambda c: "hr ok", 1.0, description="hr") == "hr ok"
        # another connection to FINPROD is still refused while it hangs
        with pytest.raises(ToolFailure) as again:
            await svc.run_bounded(_oracle("fin2", "finprod"), lambda c: "no", 1.0, description="fin2")
        assert "a connect to its database server did not complete" in str(again.value)
    finally:
        dead.set()
    assert await _until(lambda: _borrowed(svc) == 0 and _parked(svc) == 0)


def _socket(
    name: str, path: str = "/var/run/mysqld/mysqld.sock", *, host: str | None = "localhost", **kw: Any
) -> _Fake:
    conn = _Fake(name, host=host, port=3306, engine="mysql", **kw)
    conn.connection.config.options = {"unix_socket": path}
    return conn


@pytest.mark.parametrize("host", [None, "db.example"])
def test_a_mysql_connection_through_a_socket_is_keyed_on_its_socket_whatever_its_host(host: str | None) -> None:
    """PyMySQL ignores the host when options.unix_socket is set: keyed on the
    host, a socket connection shared the breaker and the share of a server it
    never dials; keyed on nothing, it had neither share nor breaker, and hung
    socket connects held every global token (review round 2)."""
    server = ("mysql", "unix_socket:/var/run/mysqld/mysqld.sock", None)
    assert executor._server(_socket("x", host=host)) == server
    # one socket, however its path is spelled, is one mysqld
    assert executor._server(_socket("y", "/var/run/mysqld//mysqld.sock", host="other.example")) == server
    assert executor._server(_socket("z", "/var/run/mysqld/../mysqld/mysqld.sock")) == server
    assert executor._server(_socket("w", "/var/run/mysqld/other.sock")) != server
    # and never the TCP server its host and port name
    assert executor._server(_Fake("tcp", host="db.example", port=3306, engine="mysql")) != server


@pytest.mark.anyio
async def test_hung_socket_connects_to_one_mysqld_leave_the_other_servers_a_token(
    anyio_backend: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The review's repro: four connection ids on one local mysqld's socket,
    each connect hung. Without a server key they held all four global tokens
    and a call to another server was refused with LIMIT_EXCEEDED. Keyed on
    the socket they take the server's share at most, are parked past their
    bound, and the breaker refuses the rest."""
    monkeypatch.setattr(executor, "_HUNG_CONNECT_FLOOR", 0.2, raising=False)
    monkeypatch.setattr(executor, "_MIN_QUEUE_SECONDS", 1.0)
    svc = ExecutionService(max_concurrent=4)
    hung = threading.Event()
    outcomes: list[str] = []
    try:
        for i in range(4):
            with pytest.raises(ToolFailure) as info:
                await svc.run_bounded(
                    _socket(f"my{i}", connect=hung, connect_timeout=0.2), lambda c: c.health_check(), 0.1,
                    description=f"my{i}",
                )
            outcomes.append(info.value.category)
        assert await _until(lambda: _parked(svc) >= 1)
        assert "CONNECTION_ERROR" in outcomes, outcomes  # the breaker refused the later ones
        assert _borrowed(svc) < 4
        assert await svc.run_bounded(_Fake("pg", host="pg.example", port=5432), lambda c: "pg ok", 0.5,
                                     description="pg") == "pg ok"
    finally:
        hung.set()
    assert await _until(lambda: _borrowed(svc) == 0 and _parked(svc) == 0)


@pytest.mark.anyio
async def test_call_in_line_behind_another_server_is_refused_at_an_early_alarm_on_a_coarse_clock(
    anyio_backend: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The at-bound alarm runs a tick early on Windows' clock. A call to the
    hung server waits in line behind a call to another server, which takes
    the token the parking frees and runs long: the call to the hung server
    is still woken and refused at the bound (the breaker's clock reads the
    bound the alarm acted on), not when a token next frees."""
    monkeypatch.setattr(executor, "_HUNG_CONNECT_FLOOR", 0.4, raising=False)
    monkeypatch.setattr(executor, "_MIN_QUEUE_SECONDS", 3.0)
    _coarse_monotonic(monkeypatch)
    svc = ExecutionService(max_concurrent=4)
    hung, hold = threading.Event(), threading.Event()
    foreign = [object() for _ in range(3)]
    for holder in foreign:  # other servers' calls hold three global tokens
        await svc._limiter.acquire_on_behalf_of(holder)
    calls: list[str] = []
    out: dict[str, Any] = {}
    ended: dict[str, float] = {}
    start = time.monotonic()
    stop = anyio.Event()
    try:
        async with anyio.create_task_group() as tg:
            tg.start_soon(_traffic, stop)
            async with anyio.create_task_group() as in_line:
                # a1 takes the last token and is abandoned at 0.1 s, within its bound
                a1 = _dead("a1", "s.example", hung)
                in_line.start_soon(_call_into, svc, a1, _health(calls), 0.1, out, ended, start)
                assert await _until(lambda: "a1" in calls)
                wx = _Fake("wx", query=hold, host="x.example")
                in_line.start_soon(_call_into, svc, wx, _query(calls, "wx"), 5.0, out, ended, start)
                await anyio.sleep(0.02)  # in this order
                a2 = _dead("a2", "s.example", hung)
                in_line.start_soon(_call_into, svc, a2, _health(calls), 0.5, out, ended, start)
                assert await _until(lambda: "a2" in out, 2.0), "a2 still waits in line past the bound"
                hold.set()
            stop.set()
    finally:
        hung.set()
        hold.set()
        for holder in foreign:
            svc._limiter.release_on_behalf_of(holder)
    assert isinstance(out["a2"], ToolFailure), out["a2"]
    assert out["a2"].category == ErrorCategory.CONNECTION, out["a2"]
    assert "a connect to its database server did not complete" in str(out["a2"])
    assert ended["a2"] - _HUNG_BOUND < 0.25, ended
    assert calls == ["a1", "wx"], "a2 must never connect"
    assert await _until(lambda: _borrowed(svc) == 0 and _parked(svc) == 0)


_HUNG_BOUND = 0.4  # the patched connect floor: a1's bound, from its start


# ------------------------------------------------------------------ wave 4, review round 1: on_start


def _starts(seen: list[str], tag: str) -> Callable[[], None]:
    """An on_start hook that records that it ran."""

    def hook() -> None:
        seen.append(tag)

    return hook


@pytest.mark.anyio
async def test_on_start_runs_once_the_worker_begins_the_driver_call(anyio_backend: str) -> None:
    """The server audits a statement as sent from this hook: it runs on the
    worker thread, before fn, only for a call whose worker started."""
    svc = ExecutionService(max_concurrent=4)
    order: list[str] = []

    def fn(c: DatabaseConnector) -> Any:
        order.append("fn")
        return c.execute_query(QuerySpec(sql="q"))

    assert await svc.run_bounded(_Fake("a"), fn, 5.0, description="t", on_start=lambda: order.append("start")) == "q"
    assert order == ["start", "fn"]


@pytest.mark.anyio
async def test_on_start_runs_under_the_executors_lock_once_the_run_counts_as_started(anyio_backend: str) -> None:
    """A request that gives up takes the lock to see whether its worker
    started (_forestall): once it sees the run started, what on_start
    recorded (the server's 'the statement was sent') is there too."""
    svc = ExecutionService(max_concurrent=4)
    seen: list[tuple[bool, bool]] = []

    def hook() -> None:
        # held (by this very thread: nothing else runs), so it cannot be taken
        held, taken = svc._lock.locked(), svc._lock.acquire(blocking=False)
        if taken:
            svc._lock.release()
        seen.append((held, taken))

    assert await svc.run_bounded(_Fake("a"), lambda c: "ok", 5.0, description="t", on_start=hook) == "ok"
    assert seen == [(True, False)], seen


@pytest.mark.anyio
async def test_on_start_never_runs_for_a_call_that_gave_up_before_its_worker_started(anyio_backend: str) -> None:
    """Refused by the breaker, given up in line on the gate, or cancelled
    before a thread picked the call up: nothing reached the database."""
    svc = ExecutionService(max_concurrent=4)
    seen: list[str] = []
    ran: list[str] = []
    # the breaker: a poisoned connector is refused before any worker starts
    poisoned = _Fake("p")
    svc._poisoned.add(poisoned)
    with pytest.raises(ToolFailure):
        await svc.run_bounded(poisoned, _query(ran, "p"), 5.0, description="p", on_start=_starts(seen, "p"))
    # in line on the connection's gate, until the request is cancelled
    query = threading.Event()
    busy = _Fake("g", query=query)
    try:
        async with anyio.create_task_group() as tg:
            tg.start_soon(lambda: svc.run_bounded(busy, _query(ran, "running"), 30.0, description="running"))
            assert await _until(lambda: ran == ["running"])
            with anyio.move_on_after(0.1):
                await svc.run_bounded(busy, _query(ran, "queued"), 30.0, description="q", on_start=_starts(seen, "q"))
            query.set()
    finally:
        query.set()
    # cancelled while anyio still waits for a worker thread
    threads = anyio.to_thread.current_default_thread_limiter()
    saved = threads.total_tokens
    hold = threading.Event()
    threads.total_tokens = 1
    try:
        async with anyio.create_task_group() as tg:
            tg.start_soon(anyio.to_thread.run_sync, lambda: hold.wait(10))
            assert await _until(lambda: threads.borrowed_tokens == 1)
            with anyio.move_on_after(0.2):
                await svc.run_bounded(_Fake("t"), _query(ran, "never"), 5.0, description="t",
                                      on_start=_starts(seen, "t"))
            hold.set()
    finally:
        hold.set()
        threads.total_tokens = saved
    await anyio.sleep(0.1)  # a thread that picks the call up late must skip it, hook and all
    assert ran == ["running"] and seen == [], (ran, seen)
