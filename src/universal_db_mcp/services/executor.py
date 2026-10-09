"""Bounded execution for synchronous database drivers.

Blocking driver calls never run on the MCP event loop: they run on worker
threads under a hard deadline and a global concurrency limiter.

Queueing (per spec §9):
- A request first queues on its connection's gate while holding no
  concurrency token, and only then takes a token from the global limiter.
  Every wait shares one queue budget (``max(timeout x 4, 10 s)``) and ends in
  LIMIT_EXCEEDED. The only lock order is gate, then limiter. Requests waiting
  behind a busy connection therefore hold no token, and an idle connection
  never waits behind them.
- The calls to one database server (engine, host, port) that hold a global
  token may hold every global token but one (``max_concurrent_queries - 1``),
  counting the calls their requests abandoned until they return: a request
  to that server waits for its share before it takes a global token, and
  checks it again once it has the token. Calls that fan out in parallel over
  a server's connections all start before any breaker can trip, and
  statements there that no cancel hook stops (Db2) run on past their
  requests; they cannot take the other servers offline. The price is that
  healthy calls to one server run at most ``max_concurrent_queries - 1`` at
  a time (three at the default of 4). With a limit of 2 only abandoned calls
  count, so two calls to one server still run side by side; two such
  statements started together then hold both tokens until they return.
- A database server is its engine, its host (case and a trailing dot aside;
  a host name and an IP address for it are two servers here) and the port
  the driver dials, the engine's default when the config leaves it out. An
  Oracle connection through ``options.tns_alias`` does not dial its
  configured host or port: its server is the alias, with the ``tns_admin``
  directory that resolves it (in Thick mode, the alias alone). MySQL through
  ``options.unix_socket`` is the mysqld behind that socket, whatever its
  host. Paths compare normalized but not through symlinks, and two aliases
  (or a symlinked and a real directory) for one listener are two servers.
- The gate belongs to the connection id, not to one connector object. The
  server builds a new connector object once the old one is discarded, even
  while the old one's call is still in flight; both queue on the same gate,
  so one connection runs one driver call at a time.
- The gate is held across the deadline scope, so a request's deadline clock
  starts only once it is the request actually executing against the
  connector. A queued request therefore cannot time out (and cannot fire the
  connector-global ``cancel_current()`` hook) while another request's query is
  running — when a deadline fires, the caller is the request actually
  executing against the connector and the cancel hook targets its own query.

Cancellation semantics (truthful, per spec §9):
- When the deadline fires, or the request is cancelled (client cancellation,
  disconnect) while its driver call runs, the connector is marked poisoned
  and discarded, and its ``cancel_current()`` hook fires in a separate thread
  under a hard budget; a hook that blocks past the budget is abandoned
  (treated as "not cancelled"), so the path stays bounded. A call the hook
  cancelled gets a moment to return, so a prompt retry does not find the
  connection still recovering.
- The worker thread itself cannot be killed; if the engine lacks a cancel
  hook (or the hook does not stop the query), the process cannot reclaim that
  worker immediately. This residual limitation is reported in tool output and
  in the driver matrix rather than advertised as hard cancellation. A deadline
  that catches the worker still connecting is reported as a connect that had
  not completed (blaming the database only once the connect has run past its
  connection's connect bound), and one that fires before any worker thread
  picked the call up as a call that never started, not as a query that may
  still run server-side.

Concurrency accounting (truthful, per spec §9):
- Each token is returned exactly once. If a request gives up (fails, is
  cancelled or times out) before its worker thread starts, the request returns
  the token and the worker skips the driver call. Once the worker has started
  it owns the token and hands it back to the request's event loop when the
  driver call ends, without waiting on that loop. When that loop has closed
  already (site-check runs every tool call under a loop of its own), the
  token goes back on the loop of the latest request, so a request waiting
  there for it gets it; a loop that closes before it runs the hand-back (the
  end of ``asyncio.run``) leaves the token to the next request, which
  returns it on its own loop. A worker abandoned past its
  deadline therefore keeps counting against ``security.max_concurrent_queries``
  until it actually finishes: the limiter bounds live driver executions, not
  merely awaited requests.
- The one exception is a worker still inside ``_connect`` past its
  connection's connect bound (below). It holds no database session, so it
  gives its global token back and takes a slot of the stuck-connect budget
  (10 slots, whatever ``max_concurrent_queries`` is) until the driver
  returns; one database server takes every slot but one at most. Otherwise
  one sweep over dead connections on several servers would take every
  connection offline. A connect that crosses its bound after its request
  left moves at the bound (on asyncio, which the server runs on, also for
  requests waiting on a later event loop than the one it was abandoned on;
  elsewhere when the next request comes in): its token goes to the next
  request in line for one, the requests waiting for its server's share look
  again, and the requests waiting for a token to its server wake to be
  refused while it hangs. Once the budget is full, a request to any
  database server is refused with CONNECTION_ERROR until a parked connect
  returns, rather than start a connect that could no longer be parked;
  connections without one (SQLite) still run. A connect that was already
  running when the budget filled keeps its global token past its bound
  until a slot frees up. A
  parked connect that connects after all runs its statement outside the
  limiter, in its slot: at most ``max_concurrent_queries + 10`` driver
  calls run at once.
- A connection with an abandoned worker fails fast with CONNECTION_ERROR until
  that worker returns. The breaker is keyed by connection id, not by connector
  object: every retry of a poisoned connection gets a freshly built connector,
  and each retry against a hung database would otherwise strand one more token
  until every connection was refused. A worker abandoned inside ``_connect``
  also refuses the other connections to the same database server (engine,
  host, port), whose connects would hang the same way, but only while it is
  still connecting past its connection's connect bound
  (``connect_timeout_seconds``, at least 5 s): a short caller-chosen deadline
  or an early client cancel that catches a normal connect says nothing about
  the server. The worker clears its breaker entries on its own thread the
  moment the driver call returns.
"""

from __future__ import annotations

import asyncio
import contextlib
import math
import os
import sys
import threading
import time
import weakref
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

import anyio

from universal_db_mcp.connectors.base import DatabaseConnector
from universal_db_mcp.errors import ToolFailure
from universal_db_mcp.models.responses import ErrorCategory

if TYPE_CHECKING:
    from types import CodeType

    from anyio.lowlevel import EventLoopToken

_QUEUE_TIMEOUT_FACTOR = 4.0
_MIN_QUEUE_SECONDS = 10.0
_CANCEL_HOOK_BUDGET = 2.0
# Within the hook budget: how long a call the cancel hook stopped may take to
# return before its connection is left to the breaker.
_CANCEL_SETTLE_SECONDS = 0.2
# A connect still running past its connection's connect_timeout_seconds (the
# bound every driver is given), and never less than this, is evidence that the
# database server does not answer, not of a deadline shorter than a connect.
_HUNG_CONNECT_FLOOR = 5.0
# An abandoned driver call still running this long after its request left
# (well past the default statement timeout plus a driver connect timeout) is
# unlikely to end by itself; the refusal then says how to get out.
_STUCK_AFTER_SECONDS = 120.0
# Threads parked in a connect hung past its bound cannot be reclaimed, and
# they sit outside anyio's worker-thread limiter (40 threads by default): the
# stuck-connect budget stays small whatever max_concurrent_queries is, and
# no smaller, so a few dead servers do not fill it.
_STUCK_CONNECT_SLOTS = 10

_POISONED = (
    "connection is in an uncertain state after a previous cancelled query and was discarded; reconnect or restart"
)

_Server = tuple[str, str, int | None]

# The port each connector dials when the config leaves it out (their
# ``cfg.port or ...``; ClickHouse's depends on TLS), so that one database
# server spelled with and without its port is one server here as well.
_DEFAULT_PORTS = {"postgres": 5432, "mysql": 3306, "oracle": 1521, "mssql": 1433, "db2": 50000}


def _connection_id(connector: DatabaseConnector) -> str | None:
    """The configured connection id, shared by every connector object that is
    built for the connection (bare test doubles may carry none)."""
    name = getattr(getattr(connector, "connection", None), "name", None)
    return name if isinstance(name, str) else None


def _server(connector: DatabaseConnector) -> _Server | None:
    """The database server the connector connects to (engine, host, port),
    shared by every connection id configured against it; None without a host
    (SQLite, bare test doubles). A PostgreSQL socket directory given as the
    host is a server like any other, and MySQL through ``options.unix_socket``
    is the mysqld behind that socket, whatever its host (PyMySQL ignores
    it). The host is compared as
    written, but for case and a trailing dot (a host name and its IP address
    are two servers here); a port left out is the one the driver dials, and
    beside a port an SQL Server instance name is dropped, as the driver does.
    An Oracle ``options.tns_alias`` dials what its tnsnames.ora descriptor
    names, never the configured host and port: it is the server, with the
    ``tns_admin`` directory that resolves it (the alias ignoring case, as
    Oracle Net does; in Thick mode without TLS the process-wide config
    directory resolves every alias and no connection's own is read, while
    with TLS the connector builds the TCPS descriptor from the connection's
    own ``tns_admin`` in either mode), and the same
    database reached by host and port, or by two aliases, is another one
    here. Paths compare normalized (``/etc/tns/`` is ``/etc/tns``), not
    through symlinks."""
    config = getattr(getattr(connector, "connection", None), "config", None)
    host = getattr(config, "host", None)
    engine = str(getattr(config, "type", ""))
    options = getattr(config, "options", None)
    options = options if isinstance(options, dict) else {}
    alias = options.get("tns_alias")
    if engine == "oracle" and isinstance(alias, str) and alias.strip():
        tls = getattr(getattr(config, "tls", None), "enabled", False) is True
        admin = "thick" if options.get("thick_mode") and not tls else _path_key(options.get("tns_admin"))
        return (engine, f"tns_alias:{alias.strip().lower()}@{admin}", None)
    socket = options.get("unix_socket")
    if engine == "mysql" and isinstance(socket, str) and socket:
        return (engine, f"unix_socket:{_path_key(socket)}", None)
    if not isinstance(host, str) or not host:
        return None
    host = host.lower()
    port = getattr(config, "port", None)
    if isinstance(port, int):
        if engine == "mssql":
            host = host.partition("\\")[0]  # the driver dials the port, not the named instance
    elif engine == "clickhouse":
        port = 8443 if getattr(getattr(config, "tls", None), "enabled", False) is True else 8123
    else:
        port = _DEFAULT_PORTS.get(engine)
    return (engine, host.rstrip(".") or host, port)


def _path_key(path: object) -> str:
    """A configured path as compared for identity: normalized, and in the
    case the platform's filesystem compares it (Windows ignores case)."""
    return os.path.normcase(os.path.normpath(path)) if isinstance(path, str) and path else str(path)


def _connect_bound(connector: DatabaseConnector) -> float:
    """How long a connect may run before it is evidence of a hung server."""
    config = getattr(getattr(connector, "connection", None), "config", None)
    bound = getattr(config, "connect_timeout_seconds", None)
    return max(float(bound), _HUNG_CONNECT_FLOOR) if isinstance(bound, int | float) else _HUNG_CONNECT_FLOOR


def _connect_code(connector: DatabaseConnector) -> frozenset[CodeType]:
    return frozenset(
        code
        for klass in type(connector).__mro__
        if (code := getattr(vars(klass).get("_connect"), "__code__", None)) is not None
    )


def _in_connect(ident: int | None, connect_code: frozenset[CodeType]) -> bool:
    """Whether the thread is inside a ``_connect``. Drivers expose no
    connect-phase hook; the worker's live stack is the one signal every
    connector shares."""
    frame = sys._current_frames().get(ident) if ident is not None else None
    while frame is not None:
        if frame.f_code in connect_code:
            return True
        frame = frame.f_back
    return False


def _stuck_hint(age: float) -> str:
    if age < _STUCK_AFTER_SECONDS:
        return ""
    return ". If this persists, the call may never return: check the database and the network, or restart the server"


def _count(n: int, noun: str) -> str:
    return f"{n} {noun}" if n == 1 else f"{n} {noun}s"


class _Run:
    """One request's handshake with its worker thread. It is also the limiter
    borrower, so the token can be returned by whichever side observes the end
    of the request. Fields are guarded by ``ExecutionService._lock``, except
    those the event loop sets before the run can be abandoned (``connecting``,
    ``connect_code``, ``hung_after``, ``returned``, ``server``) and ``alarm``,
    which only event loops touch."""

    __slots__ = (
        "abandoned",
        "alarm",
        "connect_code",
        "connecting",
        "finished",
        "hung_after",
        "parked",
        "released",
        "returned",
        "server",
        "started",
        "started_at",
        "worker",
    )

    def __init__(self, server: _Server | None = None) -> None:
        self.server = server  # its database server, for the server's share and the breaker
        self.started = False  # the worker thread began the driver call
        self.started_at = 0.0  # when it began (time.monotonic)
        self.finished = False  # the driver call returned or raised
        self.released = False  # the request gave up before the worker started; _settle returns the token
        self.worker: int | None = None  # worker thread ident, for the connect-phase probe
        self.connecting = False  # the deadline or cancellation caught the worker inside _connect
        self.connect_code: frozenset[CodeType] = frozenset()  # the connector's _connect, to probe again later
        self.hung_after = math.inf  # from then on, a connect still running speaks for the whole server
        self.abandoned: float | None = None  # when the request left its still-running worker (in the breaker)
        self.parked = False  # a connect hung past its bound: its token went back, it holds a stuck-connect slot
        self.alarm: asyncio.AbstractEventLoop | None = None  # the loop its at-bound alarm is scheduled on
        self.returned: anyio.Event | None = None  # set once the call ended, for a request waiting on it


def _oldest(runs: list[_Run]) -> float | None:
    return min((run.abandoned for run in runs if run.abandoned is not None), default=None)


def _unregister[K](registry: dict[K, list[_Run]], key: K | None, run: _Run) -> bool:
    """Drop the run from the key's list; whether it was listed."""
    if key is None:
        return False
    runs = registry.get(key)
    if runs is None or run not in runs:
        return False
    runs.remove(run)
    if not runs:
        del registry[key]
    return True


class ExecutionService:
    def __init__(self, max_concurrent: int) -> None:
        self._limiter = anyio.CapacityLimiter(max_concurrent)
        # WeakSet: poisoned connectors that were discarded and freed by the
        # caller leave the set automatically, so a recycled object address
        # never poisons a healthy replacement connector.
        self._poisoned: weakref.WeakSet[DatabaseConnector] = weakref.WeakSet()
        # Guards the poison set, the breaker, the live-worker counts, the
        # pending hand-backs and every _Run handshake between the event loop
        # and worker threads.
        self._lock = threading.Lock()
        # Database server -> its calls that hold a global token, abandoned or
        # not. They may hold every global token but one (none is set aside
        # when there is only one); a request to the server waits for its
        # share. With two tokens only the abandoned ones count, since one
        # call at a time per server would serialize healthy calls. Bounded
        # by the configuration, like the gates below.
        self._server_share = max_concurrent - 1
        self._share_counts_all = max_concurrent >= 3
        self._holding: dict[_Server, list[_Run]] = {}
        # Database server -> requests waiting for a token (and whether each
        # waits for the server's share), woken when its share frees up or a
        # connect to it runs past its bound.
        self._server_waiters: dict[_Server, dict[anyio.CancelScope, bool]] = {}
        # The stuck-connect budget: database server -> its connects parked
        # past their bound (see _park_hung_connects). One server takes every
        # slot but one at most.
        self._stuck_slots = _STUCK_CONNECT_SLOTS
        self._stuck_share = max(self._stuck_slots - 1, 1)
        self._parked: dict[_Server, list[_Run]] = {}
        # The latest connect bound _at_bound has acted on. The event loop may
        # run that alarm up to a clock tick early (15.6 ms with Windows'
        # monotonic clock before Python 3.13), so the breaker's clock (_now)
        # never reads earlier: every later check agrees with the alarm.
        self._acted_until = -math.inf
        # One gate per connection id, so bounded by the configuration (created
        # lazily on the event loop; the get/set below never awaits, so it is
        # atomic with respect to the loop). Held across the deadline scope so
        # that a request queues before its deadline starts — see the module
        # docstring.
        self._connection_gates: dict[str, anyio.Lock] = {}
        # A connector with no connection id gets a gate of its own, weakly
        # keyed: a discarded connector's gate goes with it, and a new
        # connector never inherits a recycled address's gate.
        self._connector_gates: weakref.WeakKeyDictionary[DatabaseConnector, anyio.Lock] = weakref.WeakKeyDictionary()
        # The breaker: connection id -> its abandoned workers (still running
        # after their request left), and database server -> the abandoned
        # workers stuck in a connect to it.
        self._abandoned: dict[str, list[_Run]] = {}
        self._hung_connects: dict[_Server, list[_Run]] = {}
        # Connector -> worker threads still inside a driver call on it.
        self._live: weakref.WeakKeyDictionary[DatabaseConnector, int] = weakref.WeakKeyDictionary()
        # Runs whose worker handed its token back to the request's event loop
        # (None: to a loop that had already finished) and that loop has not
        # returned it yet. The next request returns the token on its own loop
        # once the other loop has closed.
        self._pending: dict[_Run, asyncio.AbstractEventLoop | None] = {}
        # The asyncio event loop the latest request came in on: a worker whose
        # request's loop has closed hands its token back there instead, so a
        # request already waiting on it gets the token (see _hand_back).
        # Set by event loops; worker threads only read the reference.
        self._latest_loop: asyncio.AbstractEventLoop | None = None

    async def run_bounded(
        self,
        connector: DatabaseConnector,
        fn: Callable[[DatabaseConnector], Any],
        timeout_seconds: float,
        *,
        description: str,
        on_start: Callable[[], object] | None = None,
    ) -> Any:
        """Run ``fn(connector)`` on a worker thread within the concurrency
        limits and the deadline. ``on_start`` runs on that thread, under the
        executor's lock, once it begins the driver call and before ``fn``:
        never for a call refused, given up in line or cancelled before then,
        so the caller learns whether anything reached the database. It must
        not block."""
        loop = anyio.lowlevel.current_token().native_token
        if isinstance(loop, asyncio.AbstractEventLoop):
            self._latest_loop = loop
        self._return_orphaned_tokens()
        self._park_hung_connects()
        self._rearm_alarms()
        self._refuse_if_unusable(connector)
        queue_deadline = anyio.current_time() + max(timeout_seconds * _QUEUE_TIMEOUT_FACTOR, _MIN_QUEUE_SECONDS)
        # Queue on the connection's gate first, holding no token and OUTSIDE
        # the deadline scope: this request's deadline starts only once it is
        # the request actually executing against the connector, so its timeout
        # can never cancel an unrelated in-flight query via the
        # connector-global cancel hook.
        gate = self._gate_for(connector)
        gated = False
        with anyio.move_on_at(queue_deadline):
            await gate.acquire()
            gated = True
        if not gated:
            connection_id = _connection_id(connector)
            where = f"connection '{connection_id}'" if connection_id else "the connection"
            raise ToolFailure(ErrorCategory.LIMIT, f"{where} is busy with earlier requests; retry later")
        try:
            # The connector may have been poisoned (or this connection may have
            # abandoned a worker) by a previous request's timeout while this
            # request was queued on the gate: fail closed instead of running
            # against an uncertain connection.
            self._refuse_if_unusable(connector)
            # The worker thread runs under this handshake (not under a task
            # identity), so the token can be returned from wherever the end of
            # the request is observed — see _settle and _run_worker.
            run = _Run(_server(connector))
            release_token = anyio.lowlevel.current_token()
            await self._take_token(connector, run, queue_deadline)
            try:
                # Again after the token wait, which can be long: a worker may
                # have been abandoned on this connection or its server, or
                # the stuck-connect budget may have filled up, meanwhile (the
                # token may come from the connect that filled it).
                self._refuse_if_unusable(connector)
                try:
                    with anyio.move_on_after(timeout_seconds):
                        # abandon_on_cancel=True: the deadline must fire while
                        # the worker thread is still running; the thread
                        # itself cannot be killed and is handled by the
                        # cancel hook + poisoning.
                        return await anyio.to_thread.run_sync(
                            lambda: self._run_worker(connector, fn, run, release_token, on_start),
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
                except anyio.get_cancelled_exc_class():
                    # The request itself was cancelled (client cancellation,
                    # disconnect). A driver call still running is cut off as
                    # on a deadline: shielded, so it happens under the pending
                    # cancellation, and before the gate is released, so the
                    # hook targets this request's own query.
                    if not self._forestall(run) and not run.finished:
                        with anyio.CancelScope(shield=True):
                            await self._cut_off(connector, run)
                    raise
                # move_on_after exited normally without returning: our
                # deadline fired and the cancellation was swallowed by the
                # scope.
                await self._handle_timeout(connector, description, run)
                raise AssertionError("unreachable") from None  # _handle_timeout always raises
            finally:
                self._settle(run, connector)
        finally:
            gate.release()

    def _gate_for(self, connector: DatabaseConnector) -> anyio.Lock:
        connection_id = _connection_id(connector)
        if connection_id is None:
            gate = self._connector_gates.get(connector)
            if gate is None:
                gate = anyio.Lock()
                self._connector_gates[connector] = gate
            return gate
        gate = self._connection_gates.get(connection_id)
        if gate is None:
            gate = anyio.Lock()
            self._connection_gates[connection_id] = gate
        return gate

    async def _take_token(self, connector: DatabaseConnector, run: _Run, queue_deadline: float) -> None:
        """Take a global token within the queue budget (LIMIT_EXCEEDED past
        it), once the connector's database server has room for the call in
        its share. The wait also wakes when something changes for the
        server, and the breaker is re-checked each time. The token is
        returned by _settle or by the worker."""
        server = run.server
        while True:
            crowded = self._server_crowded(server)
            waiters = self._server_waiters.setdefault(server, {}) if server is not None else {}
            with anyio.CancelScope(deadline=queue_deadline) as wake:
                waiters[wake] = crowded
                try:
                    if crowded:
                        await anyio.sleep_forever()
                    else:
                        await self._limiter.acquire_on_behalf_of(run)
                        if self._hold(run):
                            return
                        # Other calls to the server took its share while this
                        # one waited in line: the token goes to the next.
                        self._limiter.release_on_behalf_of(run)
                        crowded = True
                finally:
                    del waiters[wake]
            if anyio.current_time() >= queue_deadline:
                break
            self._park_hung_connects()
            self._refuse_if_unusable(connector)
        if crowded:
            # The refusal must not name the server: other connection ids on
            # it may be hidden from this caller.
            abandoned = "calls that timed out or were cancelled and have not returned yet"
            if self._share_counts_all:  # a share of 2 calls at least
                limit = f"{self._server_share} calls in flight, counting {abandoned}"
            else:
                limit = f"{_count(self._server_share, 'abandoned call')} ({abandoned})"
            raise ToolFailure(
                ErrorCategory.LIMIT,
                f"query concurrency limit reached: this connection's database server is at its limit of {limit}; "
                f"retry later",
            )
        raise ToolFailure(ErrorCategory.LIMIT, "query concurrency limit reached; retry later")

    def _server_crowded(self, server: _Server | None) -> bool:
        """Whether the server's calls that hold a global token (only the
        abandoned ones with two tokens) hold its whole share."""
        if server is None or self._server_share < 1:
            return False
        with self._lock:
            return self._crowded(server)

    def _crowded(self, server: _Server) -> bool:
        """_server_crowded; caller holds self._lock."""
        runs = self._holding.get(server, ())
        counted = len(runs) if self._share_counts_all else sum(run.abandoned is not None for run in runs)
        return counted >= self._server_share

    def _hold(self, run: _Run) -> bool:
        """Counts the run's new global token toward its server's share,
        unless the server has its whole share already. On the event loop,
        with no await since the token was taken, so the share never runs
        over."""
        if run.server is None or self._server_share < 1:
            return True
        with self._lock:
            if self._crowded(run.server):
                return False
            self._holding.setdefault(run.server, []).append(run)
        return True

    def _now(self) -> float:
        """The breaker's clock: time.monotonic(), never earlier than a connect
        bound the event loop has already acted on (see _at_bound)."""
        return max(time.monotonic(), self._acted_until)

    def _park_hung_connects(self) -> None:
        """Move every abandoned connect still running past its connect bound
        out of the global limiter into the stuck-connect budget, while it has
        slots. Such a worker holds no database session; counted against
        max_concurrent_queries, a sweep over several dead servers would take
        every connection offline. Runs on an event loop: it returns tokens,
        each to the next request in line for one.

        A parked connect that completes after all runs its statement on,
        outside the global limiter but still in its slot: it had already run
        past its driver's own connect timeout, so that is rare, and the
        budget bounds it (at most max_concurrent_queries + 10 driver calls
        at once). A connect that crosses its bound once the budget is full
        keeps its global token until a slot frees up, so that bound holds."""
        now = self._now()
        parked: list[tuple[_Run, bool]] = []
        with self._lock:
            free = self._stuck_slots - sum(len(runs) for runs in self._parked.values())
            for server, runs in list(self._hung_connects.items()):
                for run in list(runs):
                    if run.parked or run.hung_after > now:
                        continue
                    if free < 1 or len(self._parked.get(server, ())) >= self._stuck_share:
                        continue  # keeps its global token until a slot frees up
                    if not _in_connect(run.worker, run.connect_code):
                        _unregister(self._hung_connects, server, run)  # it connected after all
                        continue
                    run.parked = True
                    free -= 1
                    self._parked.setdefault(server, []).append(run)
                    parked.append((run, _unregister(self._holding, server, run)))
        # The requests waiting for its server's share look again: they are
        # refused while it hangs, and run if it connected since this probe.
        # Those in line for a global token keep their places.
        for run, held in parked:
            self._limiter.release_on_behalf_of(run)
            if held:
                self._wake(run.server, crowded_only=True)  # its share has room again

    def _wake(self, server: _Server | None, *, crowded_only: bool = False) -> None:
        """Wake the requests waiting for a token to the server, to look
        again. One waiting on the global limiter loses its place there, so
        news that only concerns the server's share leaves it waiting."""
        if server is not None:
            for wake, crowded in list(self._server_waiters.get(server, {}).items()):
                if crowded or not crowded_only:
                    wake.cancel()

    def _return_token(self, run: _Run) -> None:
        """Returns the run's global token (on an event loop), unless it was
        parked and gave it back already."""
        with self._lock:
            parked = run.parked
            held = _unregister(self._holding, run.server, run)
        if not parked:
            self._limiter.release_on_behalf_of(run)
        if held:
            self._wake(run.server, crowded_only=True)  # its share has room again

    def _return_orphaned_tokens(self) -> None:
        """Return, on this request's loop, the tokens handed back to a loop
        that closed before it could return them."""
        with self._lock:
            orphaned = [run for run, loop in self._pending.items() if loop is None or loop.is_closed()]
            for run in orphaned:
                del self._pending[run]
        for run in orphaned:
            self._return_token(run)

    def _return_orphans(self) -> None:
        """Runs on the latest request's event loop, scheduled by _hand_back
        for a token handed back to a loop that had closed: returns it, and
        moves a connect waiting for the stuck-connect slot it may free, as
        the next request would when it comes in."""
        self._return_orphaned_tokens()
        self._park_hung_connects()

    def _refuse_if_unusable(self, connector: DatabaseConnector) -> None:
        """Fail fast, before any worker is started, on a poisoned connector, a
        connection whose abandoned worker has not returned yet, a database
        server whose connect hangs, or any database server while the
        stuck-connect budget is full."""
        if self.is_poisoned(connector):
            raise ToolFailure(ErrorCategory.CONNECTION, _POISONED)
        connection_id = _connection_id(connector)
        server = _server(connector)
        now = self._now()
        with self._lock:
            own = _oldest(self._abandoned.get(connection_id, [])) if connection_id is not None else None
            hung = self._hung_connect(server, now) if server is not None else None
            stuck = [run for runs in self._parked.values() for run in runs] if server is not None else []
        if own is not None:
            raise ToolFailure(
                ErrorCategory.CONNECTION,
                f"connection '{connection_id}' is still recovering from a driver call that "
                f"timed out or was cancelled {now - own:.0f} s ago and has not returned yet; "
                f"retry later{_stuck_hint(now - own)}",
            )
        # Other connection ids may be hidden from this caller: the refusals
        # below name neither them nor any server.
        where = f"connection '{connection_id}'" if connection_id else "the connection"
        if hung is not None:
            age = now - hung.started_at
            raise ToolFailure(
                ErrorCategory.CONNECTION,
                f"{where} is unavailable: a connect to its database server did not complete "
                f"within {hung.hung_after - hung.started_at:.0f} s and has not returned "
                f"{age:.0f} s after it started; retry later{_stuck_hint(age)}",
            )
        if len(stuck) >= self._stuck_slots:
            age = now - min(run.started_at for run in stuck)
            raise ToolFailure(
                ErrorCategory.CONNECTION,
                f"{where} is unavailable: the limit of {_count(self._stuck_slots, 'pending connect')} to "
                f"database servers that did not answer has been reached; retry later{_stuck_hint(age)}",
            )

    def _hung_connect(self, server: _Server, now: float) -> _Run | None:
        """The longest-running abandoned connect to the server that shows the
        server hangs: past its connect bound, and still connecting. Caller
        holds self._lock, so no listed worker can finish (and its thread start
        other work) during the probe. A connect that completed since its
        request left no longer speaks for the server and is dropped."""
        hung: _Run | None = None
        for run in list(self._hung_connects.get(server, [])):
            if run.hung_after > now:
                continue
            if not _in_connect(run.worker, run.connect_code):
                _unregister(self._hung_connects, server, run)
            elif hung is None or run.started_at < hung.started_at:
                hung = run
        return hung

    def _forestall(self, run: _Run) -> bool:
        """Whether the worker had not started yet when the request gave up; it
        then never will, and _settle returns the token."""
        with self._lock:
            if not run.started:
                run.released = True
            return not run.started

    def _settle(self, run: _Run, connector: DatabaseConnector) -> None:
        """Request side of the token handshake, on every exit after the token
        was taken. A worker that has not started never will: the token is
        returned here and _run_worker skips the driver call. A started worker
        owns the token; if it is still running, the request is abandoning it
        and the breaker counts it until the driver call ends."""
        hung: _Server | None = None  # the server of a connect abandoned past its bound
        within_bound: _Server | None = None  # the server of a connect abandoned within its bound
        with self._lock:
            give_back = not run.started
            if give_back:
                run.released = True
            elif not run.finished:
                # Its token keeps counting toward the server's share (with two
                # tokens, from now on) until the call returns or the connect
                # is parked.
                now = run.abandoned = time.monotonic()
                connection_id = _connection_id(connector)
                if connection_id is not None:
                    self._abandoned.setdefault(connection_id, []).append(run)
                if run.server is not None and run.connecting:
                    # Listed now; it speaks for the server only once it has
                    # run past its connect bound, still connecting.
                    self._hung_connects.setdefault(run.server, []).append(run)
                    if run.hung_after <= now:
                        hung = run.server
                    else:
                        within_bound = run.server
        if give_back:
            self._return_token(run)
        elif hung is not None:
            # Parked at once where the budget allows. Requests waiting for a
            # token to the server re-check the breaker instead of waiting out
            # their queue budget.
            self._park_hung_connects()
            self._wake_if_hung(hung)
        elif within_bound is not None:
            self._alarm_at_bound(within_bound, run)

    def _alarm_at_bound(self, server: _Server, run: _Run) -> None:
        """Schedules _at_bound on this event loop for a connect abandoned
        within its connect bound, unless its alarm is on this loop already,
        so that the requests already waiting for a token see it at the
        bound, not at the end of their queue budget. On anyio backends other
        than asyncio, the next request to come in parks it."""
        loop = anyio.lowlevel.current_token().native_token
        if isinstance(loop, asyncio.AbstractEventLoop) and run.alarm is not loop:
            run.alarm = loop
            loop.call_later(max(run.hung_after - time.monotonic(), 0.0), self._at_bound, server, run.hung_after)

    def _rearm_alarms(self) -> None:
        """Schedules again, on this request's event loop, the alarms of the
        connects still within their bound whose alarm went with another loop
        (site-check runs every tool call under a loop of its own), so that a
        request waiting here for a token is woken at their bound as well."""
        now = self._now()
        with self._lock:
            due = [
                (server, run)
                for server, runs in self._hung_connects.items()
                for run in runs
                if not run.parked and run.hung_after > now
            ]
        for server, run in due:
            self._alarm_at_bound(server, run)

    def _at_bound(self, server: _Server, bound: float) -> None:
        """Runs on the event loop at an abandoned connect's bound. A connect
        still running then is parked where the budget allows, and its token
        goes to the next request in line for one. It shows that its server
        hangs: the requests waiting for a token to that server wake, to be
        refused."""
        with self._lock:
            # The loop may run the alarm a clock tick early; from now on the
            # breaker's clock reads the bound at least, so the requests it
            # wakes see the same connect past its bound.
            self._acted_until = max(self._acted_until, bound)
        self._park_hung_connects()
        self._wake_if_hung(server)

    def _wake_if_hung(self, server: _Server) -> None:
        """Wakes the requests waiting for a token to the server, to be
        refused, while a connect to it hangs past its bound. One that
        completed since it was listed (while the cancel hook ran, say) says
        nothing about the server: a wake would only cost the requests in
        line for a global token their places."""
        with self._lock:
            hangs = self._hung_connect(server, self._now()) is not None
        if hangs:
            self._wake(server)

    def _run_worker(
        self,
        connector: DatabaseConnector,
        fn: Callable[[DatabaseConnector], Any],
        run: _Run,
        release_token: EventLoopToken,
        on_start: Callable[[], object] | None = None,
    ) -> Any:
        """Runs on the worker thread. Skips the driver call when the request
        already gave up (and returned the token) before this thread started;
        otherwise clears its breaker entries and hands the token back once the
        call ends, whether the request is still waiting or abandoned this
        thread."""
        with self._lock:
            if run.released:
                return None
            run.started = True
            run.started_at = time.monotonic()
            run.worker = threading.get_ident()
            self._live[connector] = self._live.get(connector, 0) + 1
            if on_start is not None:
                # under the lock: a request that sees the run started sees this too
                on_start()
        try:
            return fn(connector)
        finally:
            with self._lock:
                run.finished = True
                # Here, not on the event loop: the request's loop may be gone
                # (site-check runs every tool call under a loop of its own).
                if run.abandoned is not None:
                    _unregister(self._abandoned, _connection_id(connector), run)
                    _unregister(self._hung_connects, run.server, run)
                    _unregister(self._parked, run.server, run)
                if self._live[connector] > 1:
                    self._live[connector] -= 1
                else:
                    del self._live[connector]
            self._hand_back(run, release_token)

    def _hand_back(self, run: _Run, release_token: EventLoopToken) -> None:
        """Runs on the worker thread: schedules the token's return on the
        request's event loop without waiting for it. Waiting would block this
        thread for good on a loop that is stopped and then closed (the end of
        asyncio.run), which drops the call. The run stays pending until its
        loop returns the token, or _return_orphaned_tokens finds that loop
        closed and returns it on its own: on the latest request's loop at
        once when the request's loop has closed already, so that a request
        waiting there for a token gets it (site-check runs every tool call
        under a loop of its own), or else when the next request comes in."""
        loop = release_token.native_token
        if not isinstance(loop, asyncio.AbstractEventLoop):
            # Other anyio backends (trio) run every call they accept.
            try:
                anyio.from_thread.run_sync(self._release_lease, run, token=release_token)
            except anyio.RunFinishedError:
                with self._lock:
                    self._pending[run] = None
            return
        with self._lock:
            self._pending[run] = loop
        try:
            loop.call_soon_threadsafe(self._release_pending, run)
        except RuntimeError:  # the loop has closed; the run stays pending
            latest = self._latest_loop
            if latest is not None and latest is not loop:
                with contextlib.suppress(RuntimeError):  # so has the latest one
                    latest.call_soon_threadsafe(self._return_orphans)

    def _release_pending(self, run: _Run) -> None:
        """Runs on the request's event loop, scheduled by _hand_back."""
        with self._lock:
            if run not in self._pending:
                return  # another loop returned the token already
            del self._pending[run]
        self._release_lease(run)

    def _release_lease(self, run: _Run) -> None:
        """Runs on the request's event loop once the driver call ended."""
        self._return_token(run)
        if run.returned is not None:
            run.returned.set()
        if run.parked:
            # Its stuck-connect slot is free: a connect waiting for one moves.
            self._park_hung_connects()

    def _worker_in_connect(self, connector: DatabaseConnector, run: _Run) -> bool:
        """Whether the worker is still inside the connector's ``_connect``, so
        the deadline fired before a connection was established."""
        run.connect_code = _connect_code(connector)
        with self._lock:
            # Under the lock: a worker that finishes cannot hand its thread to
            # other work while its stack is probed.
            ident = run.worker if run.started and not run.finished else None
            return _in_connect(ident, run.connect_code)

    async def _cut_off(self, connector: DatabaseConnector, run: _Run) -> bool:
        """Stop the worker's driver call as far as the engine allows, and say
        whether the cancel hook reported a cancellation."""
        # The worker thread cannot be killed. Mark the connection poisoned
        # first, so it is never reused with uncertain cancellation/transaction
        # state even if the wait below is itself cancelled.
        with self._lock:
            self._poisoned.add(connector)
        # Before the hook's await, which the request's own cancellation may
        # cut short: a connect abandoned then still needs its marks to be
        # parked and to speak for its server. A connect that completes after
        # this probe is probed again before it does (_hung_connect,
        # _park_hung_connects).
        run.hung_after = run.started_at + _connect_bound(connector)
        run.connecting = self._worker_in_connect(connector, run)
        cancelled = False
        budget_ends = anyio.current_time() + _CANCEL_HOOK_BUDGET
        cancel_fn = getattr(connector, "cancel_current", None)
        if callable(cancel_fn):
            try:
                with anyio.move_on_at(budget_ends):
                    # abandon_on_cancel=True so the budget actually bounds the
                    # wait: a blocking cancel hook (libpq PQcancel, a network
                    # round-trip) is left running in its thread and the
                    # budget expiry is treated as "not cancelled".
                    cancelled = bool(await anyio.to_thread.run_sync(cancel_fn, abandon_on_cancel=True))
            except Exception:  # noqa: BLE001 - cancel is best effort
                cancelled = False
        if cancelled:
            # _release_lease sets the event on this loop, so it cannot fire
            # between the check and the wait.
            run.returned = anyio.Event()
            if not run.finished:
                with anyio.move_on_at(min(budget_ends, anyio.current_time() + _CANCEL_SETTLE_SECONDS)):
                    await run.returned.wait()
        return cancelled

    async def _handle_timeout(self, connector: DatabaseConnector, description: str, run: _Run) -> None:
        if self._forestall(run):
            raise ToolFailure(
                ErrorCategory.TIMEOUT,
                f"{description} did not start within its deadline: every worker thread was busy, "
                f"so nothing ran against the database and the connection was kept. Retry later.",
            )
        fired = time.monotonic() - run.started_at
        cancelled = await self._cut_off(connector, run)
        if run.connecting:
            # A deadline shorter than a normal connect says nothing about the
            # database; one past the connection's connect bound does.
            unanswered = " (the database or network did not answer)" if run.started_at + fired >= run.hung_after else ""
            raise ToolFailure(
                ErrorCategory.TIMEOUT,
                f"{description} exceeded its deadline: the connect had not completed when the "
                f"deadline fired, {fired:.2f} s after it started{unanswered}. The attempt was "
                f"abandoned and the connection was discarded (docs/driver-matrix.md).",
            )
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

    def has_live_worker(self, connector: DatabaseConnector) -> bool:
        """Whether a worker thread is still inside a driver call on this
        connector, including one its request abandoned. A discarded connector
        is safe to close only once this is False."""
        with self._lock:
            return connector in self._live
