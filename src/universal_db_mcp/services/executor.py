"""Bounded execution for synchronous database drivers.

Blocking driver calls never run on the MCP event loop: they run on worker
threads under a hard deadline and a global concurrency limiter.

Cancellation semantics (truthful, per spec §9):
- Requests to the same connector are gated here: a request queues on its
  connector's gate BEFORE its deadline clock starts, so only one request per
  connector is ever inside a deadline scope. A queued request therefore
  cannot time out (and cannot fire the connector-global ``cancel_current()``
  hook) while another request's query is running — when a deadline fires,
  the caller is the request actually executing against the connector and
  the cancel hook targets its own query.
- On timeout the connector's ``cancel_current()`` hook fires in a separate
  thread under a hard budget; a hook that blocks past the budget is
  abandoned (treated as "not cancelled"), so the timeout path stays bounded.
- The worker thread itself cannot be killed; if the engine lacks a cancel
  hook (or the hook does not stop the query), the process cannot reclaim that
  worker immediately and the connection is marked poisoned and discarded.
  This residual limitation is reported in tool output and in the driver
  matrix rather than advertised as hard cancellation.

Concurrency accounting (truthful, per spec §9): a worker thread abandoned
past its deadline keeps its concurrency token until the thread actually
finishes — the token is returned to the limiter from the event loop as soon
as the worker's cleanup runs, so ``security.max_concurrent_queries`` bounds
live driver executions, not merely awaited requests.
"""

from __future__ import annotations

import sys
import threading
import weakref
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

import anyio

from universal_db_mcp.connectors.base import DatabaseConnector
from universal_db_mcp.errors import ToolFailure
from universal_db_mcp.models.responses import ErrorCategory

if TYPE_CHECKING:
    from anyio.lowlevel import EventLoopToken

_QUEUE_TIMEOUT_FACTOR = 4.0
_CANCEL_HOOK_BUDGET = 2.0


class ExecutionService:
    def __init__(self, max_concurrent: int) -> None:
        self._limiter = anyio.CapacityLimiter(max_concurrent)
        # WeakSet: poisoned connectors that were discarded and freed by the
        # caller leave the set automatically, so a recycled object address
        # never poisons a healthy replacement connector.
        self._poisoned: weakref.WeakSet[DatabaseConnector] = weakref.WeakSet()
        # Guards the poison set, the per-run lease-release flags and worker
        # handshakes between the event loop and worker threads.
        self._lock = threading.Lock()
        # One gate per connector (created lazily on the event loop; the
        # get/set below never awaits, so it is atomic with respect to the
        # loop). Held across the deadline scope so that a request queues
        # before its deadline starts — see the module docstring.
        self._connector_gates: dict[int, anyio.Lock] = {}

    async def run_bounded(
        self,
        connector: DatabaseConnector,
        fn: Callable[[DatabaseConnector], Any],
        timeout_seconds: float,
        *,
        description: str,
    ) -> Any:
        if self.is_poisoned(connector):
            raise ToolFailure(
                ErrorCategory.CONNECTION,
                "connection is in an uncertain state after a previous "
                "cancelled query and was discarded; reconnect or restart",
            )
        queue_budget = max(timeout_seconds * _QUEUE_TIMEOUT_FACTOR, 10.0)
        # The worker thread runs under this lease (not under a task identity),
        # so the token can be returned from wherever the worker's lifetime is
        # observed — see _run_worker.
        lease = threading.Event()
        release_token = anyio.lowlevel.current_token()
        acquired = False
        with anyio.move_on_after(queue_budget):
            await self._limiter.acquire_on_behalf_of(lease)
            acquired = True
        if not acquired:
            raise ToolFailure(
                ErrorCategory.LIMIT,
                "query concurrency limit reached; retry later",
            )
        # Queue on the connector gate OUTSIDE the deadline scope. The wait is
        # bounded in practice by the in-flight request's own deadline (its
        # scope always fires), and this request's deadline starts only once it
        # is the request actually executing against the connector — so its
        # timeout can never cancel an unrelated in-flight query via the
        # connector-global cancel hook.
        async with self._gate_for(connector):
            released = [False]  # exactly-once flag, guarded by self._lock
            try:
                if self.is_poisoned(connector):
                    # The connector was poisoned by a previous request's
                    # timeout while this request was queued on the gate: fail
                    # closed instead of running against an uncertain
                    # connection.
                    raise ToolFailure(
                        ErrorCategory.CONNECTION,
                        "connection is in an uncertain state after a "
                        "previous cancelled query and was discarded; "
                        "reconnect or restart",
                    )
                try:
                    with anyio.move_on_after(timeout_seconds):
                        # abandon_on_cancel=True: the deadline must fire while
                        # the worker thread is still running; the thread
                        # itself cannot be killed and is handled by the
                        # cancel hook + poisoning.
                        return await anyio.to_thread.run_sync(
                            lambda: self._run_worker(connector, fn, lease, released, release_token),
                            abandon_on_cancel=True,
                        )
                except TimeoutError as exc:
                    # Drivers raise the builtin TimeoutError for their own
                    # connect/read timeouts (socket.timeout aliases it since
                    # 3.10). That is a connection failure, NOT the executor
                    # deadline, and must not poison the connection.
                    raise ToolFailure(
                        ErrorCategory.CONNECTION,
                        f"{description} failed with a driver-level timeout "
                        f"(connect/read), not the executor deadline; the "
                        f"connection was not poisoned. Retry or check "
                        f"database health.",
                    ) from exc
                # move_on_after exited normally without returning: our
                # deadline fired and the cancellation was swallowed by the
                # scope.
                await self._handle_timeout(connector, description)
                raise AssertionError("unreachable") from None  # _handle_timeout always raises
            finally:
                with self._lock:
                    # Release only when the worker already finished and has
                    # not claimed the token itself. A worker that is still
                    # running keeps the token until its cleanup returns it
                    # from the event loop (below), so abandoned driver calls
                    # keep counting against max_concurrent_queries.
                    if not released[0] and lease.is_set():
                        released[0] = True
                        do_release = True
                    else:
                        do_release = False
                if do_release:
                    self._limiter.release_on_behalf_of(lease)

    def _gate_for(self, connector: DatabaseConnector) -> anyio.Lock:
        gate = self._connector_gates.get(id(connector))
        if gate is None:
            gate = anyio.Lock()
            self._connector_gates[id(connector)] = gate
        return gate

    def _run_worker(
        self,
        connector: DatabaseConnector,
        fn: Callable[[DatabaseConnector], Any],
        lease: threading.Event,
        released: list[bool],
        release_token: EventLoopToken,
    ) -> Any:
        """Runs on the worker thread. Marks completion and, when the request
        already gave up on this thread (deadline fired, request cancelled),
        returns the concurrency token to the limiter via the event loop."""
        try:
            return fn(connector)
        finally:
            lease.set()
            self._release_lease_once(lease, released, release_token)

    def _release_lease_once(
        self,
        lease: threading.Event,
        released: list[bool],
        release_token: EventLoopToken,
    ) -> None:
        """Exactly-once lease release, shared between the request path (event
        loop) and the worker's cleanup."""
        with self._lock:
            if released[0]:
                return  # the other side already released the lease
            released[0] = True
        try:
            anyio.from_thread.run_sync(self._release_lease, lease, token=release_token)
        except Exception as exc:  # noqa: BLE001 - best effort: loop may be gone
            print(
                f"universal-db-mcp: abandoned worker token release failed: {exc}",
                file=sys.stderr,
            )

    def _release_lease(self, lease: threading.Event) -> None:
        """Runs on the event loop (scheduled from a worker thread)."""
        self._limiter.release_on_behalf_of(lease)

    async def _handle_timeout(self, connector: DatabaseConnector, description: str) -> None:
        cancelled = False
        cancel_fn = getattr(connector, "cancel_current", None)
        if callable(cancel_fn):
            try:
                with anyio.move_on_after(_CANCEL_HOOK_BUDGET):
                    # abandon_on_cancel=True so the budget actually bounds the
                    # wait: a blocking cancel hook (libpq PQcancel, a network
                    # round-trip) is left running in its thread and the
                    # budget expiry is treated as "not cancelled".
                    cancelled = bool(await anyio.to_thread.run_sync(cancel_fn, abandon_on_cancel=True))
            except Exception:  # noqa: BLE001 - cancel is best effort
                cancelled = False
        # The worker thread cannot be killed. Mark the connection poisoned so
        # it is never reused with uncertain cancellation/transaction state.
        with self._lock:
            self._poisoned.add(connector)
        if cancelled:
            raise ToolFailure(
                ErrorCategory.TIMEOUT,
                f"{description} exceeded its deadline; cancellation was issued "
                f"and the connection was discarded. Where the engine lacks "
                f"server-side cancel, the query may continue server-side "
                f"(docs/driver-matrix.md).",
            )
        raise ToolFailure(
            ErrorCategory.TIMEOUT,
            f"{description} exceeded its deadline; the driver exposes no "
            f"cancellation hook, so the query may still run server-side. The "
            f"connection was discarded (docs/driver-matrix.md).",
        )

    def is_poisoned(self, connector: DatabaseConnector) -> bool:
        return connector in self._poisoned
