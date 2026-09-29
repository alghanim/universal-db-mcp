"""Pre-auth hardening for the Streamable HTTP listener (uvicorn + h11).

The bearer token can be checked only once uvicorn has accepted the connection
and h11 has parsed a complete request head. Anything that can open a socket
to the listener - every local user on the default loopback bind, every peer
on the container network - reaches the code before that point without a
token. This module bounds what such a client can cost:

* a header deadline (``GuardedH11Protocol``): a connection must deliver a
  complete request head within ``header_timeout`` seconds of connecting or of
  its previous response completing. uvicorn's own keep-alive timer is armed
  only after a response and is cancelled by any received byte, so an idle
  socket, a header block sent one byte at a time, or a stray byte after a 401
  held a file descriptor forever;
* a request head cap: more than ``MAX_HEADERS`` header lines or
  ``MAX_HEADER_BYTES`` bytes is answered 431 before h11 parses it. h11's own
  16 KiB limit applies only while a head is incomplete, so a head that
  arrived in one read (up to 256 KiB) was parsed whole;
* the bearer check on the request head: a request without the token is
  answered 401 and its connection closed before h11 parses its body, so
  chunked trailer fields and chunks (parsed with no count limit, ~16 ms for
  20,000 trailers, ~90 ms for 40,000 one-byte chunks) never cost anything
  before auth, and a client without the token cannot keep a connection
  (and its descriptor) alive by sending one small request per deadline.
  What the client still sends after a refusal is read and discarded
  unparsed for at most ``LINGER_SECONDS`` and ``LINGER_MAX_BYTES``, so it
  reads the refusal instead of a reset. An idle connection still holds its
  descriptor for up to ``header_timeout``, so exhausting the limit takes
  (descriptor limit / header_timeout) new connections per second,
  sustained;
* a rate limit on the warnings a client can make uvicorn and asyncio log
  before auth (``PreAuthWarningFilter``), and an optional size-bounded log
  file for service managers that do not bound stdout and stderr (launchd),
  which then keeps those under the same cap (``cap_service_output``);
* a raised open-file soft limit (``raise_open_file_limit``).

The protocol class subclasses uvicorn's h11 implementation (uvicorn is pinned
through the lock file); the head checks sit on h11's public API.
"""

from __future__ import annotations

import asyncio
import hmac
import logging
import logging.config
import math
import os
import re
import stat
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from typing import Any, TextIO

import h11
from uvicorn.config import Config
from uvicorn.protocols.http.h11_impl import H11Protocol
from uvicorn.server import ServerState

HEADER_TIMEOUT_ENV = "UDBMCP_HTTP_HEADER_TIMEOUT"
DEFAULT_HEADER_TIMEOUT = 10.0

# Request line excluded. Real MCP clients send about ten headers; a reverse
# proxy adds a few X-Forwarded-* ones.
MAX_HEADERS = 100
MAX_HEADER_BYTES = 16 * 1024

# After a refusal (401, 431) the rest of the request is drained before the
# connection is closed: closing with unread bytes makes the kernel send a
# reset, and a client still sending its body then never reads the refusal.
# The drain never outlasts the header deadline, so a refused connection
# holds its descriptor no longer than an idle one.
LINGER_SECONDS = 2.0
LINGER_MAX_BYTES = 16 * 1024 * 1024

OPEN_FILE_TARGET = 65536
# OPEN_MAX: what macOS allows when kern.maxfilesperproc cannot be read.
_DARWIN_FALLBACK_MAX_FILES = 10240

LOG_FILE_ENV = "UDBMCP_HTTP_LOG_FILE"
# Rotated by the server itself, as the service account. With the log file set,
# what still reaches stdout and stderr is kept under the same size.
LOG_FILE_MAX_BYTES = 5 * 1024 * 1024
LOG_FILE_BACKUPS = 3

# The end of a request head, as h11 finds it (bare LF line endings included).
_HEAD_END = re.compile(rb"\n\r?\n")

_HEAD_TOO_LARGE = "Request header fields too large."
_UNAUTHORIZED_BODY = b'{"error": "unauthorized"}'


def header_timeout_from_env(env: Mapping[str, str]) -> float:
    """The header deadline in seconds: ``UDBMCP_HTTP_HEADER_TIMEOUT`` or the
    default. Raises ``ValueError`` for anything but a positive finite number."""
    raw = env.get(HEADER_TIMEOUT_ENV)
    if raw is None or not raw.strip():
        return DEFAULT_HEADER_TIMEOUT
    try:
        value = float(raw)
    except ValueError:
        value = math.nan
    if not math.isfinite(value) or value <= 0:
        raise ValueError(f"{HEADER_TIMEOUT_ENV} must be a positive number of seconds, got {raw!r}")
    return value


class _HeadScan:
    """The size check of one request head, fed the head's bytes as they
    arrive and scanning each byte once (a head sent one byte per read is
    not re-scanned from its start every time).

    ``too_large`` is True when the head has more than ``MAX_HEADERS`` header
    lines or more than ``MAX_HEADER_BYTES`` bytes up to its final line
    break; ``head_end`` is where that final line break starts, once it has
    arrived. Bytes after the head (a body, a pipelined request) are not
    looked at.

    An incomplete head is judged on what has arrived, never more strictly
    than the same head once complete: its end may still be two bytes away,
    and its first line is the request line."""

    def __init__(self) -> None:
        self._window = bytearray()  # the first MAX_HEADER_BYTES + 4 bytes
        self._newlines = 0
        self.head_end: int | None = None
        self.too_large = False

    def feed(self, data: bytes) -> None:
        room = MAX_HEADER_BYTES + 4 - len(self._window)
        if self.head_end is not None or room <= 0 or not data:
            return  # nothing new, or the verdict can no longer change
        # a line break split across reads: its first byte may be up to two back
        start = max(0, len(self._window) - 2)
        chunk = data[:room]
        self._window += chunk
        self._newlines += chunk.count(b"\n")
        end = _HEAD_END.search(self._window, start)
        if end is not None:
            self.head_end = end.start()
            lines = self._window.count(b"\n", 0, self.head_end)
            self.too_large = self.head_end > MAX_HEADER_BYTES or lines > MAX_HEADERS
        else:
            self.too_large = len(self._window) - 2 > MAX_HEADER_BYTES or self._newlines - 1 > MAX_HEADERS


def request_head_too_large(pending: bytes) -> bool:
    """True when the request head at the start of ``pending`` has more than
    ``MAX_HEADERS`` header lines or more than ``MAX_HEADER_BYTES`` bytes up to
    its final line break (see ``_HeadScan``)."""
    scan = _HeadScan()
    scan.feed(pending)
    return scan.too_large


def bearer_token_matches(headers: Iterable[tuple[bytes, bytes]], token: bytes) -> bool:
    """Whether the first ``authorization`` header of a request (names in
    lower case, as h11 and ASGI give them) carries ``Bearer <token>``."""
    auth = next((value for name, value in headers if name == b"authorization"), b"")
    return auth.startswith(b"Bearer ") and hmac.compare_digest(auth[7:], token)


class _HeadGuardConnection(h11.Connection):
    """h11 server connection that checks each request head before parsing it
    and hands each parsed head to its protocol before uvicorn sees it.

    Every head is parsed from ``next_event`` while the client is in the IDLE
    state, whichever path fed the bytes in (a read, or a pipelined request
    resumed after the previous response), so the checks here cannot be
    bypassed and run before h11 spends time on the head or on what follows
    it. The size check reads what is already buffered once per head (bytes
    pipelined behind the previous request) and is then fed each read. Once a
    request is refused nothing more is parsed.
    """

    def __init__(self, protocol: GuardedH11Protocol, max_incomplete_event_size: int | None) -> None:
        if max_incomplete_event_size is None:
            super().__init__(h11.SERVER)
        else:
            super().__init__(h11.SERVER, max_incomplete_event_size)
        self._protocol = protocol
        self._refused = False
        self._head: _HeadScan | None = None  # the head awaited while the client is IDLE

    def receive_data(self, data: bytes) -> None:
        super().receive_data(data)
        if self._head is not None:
            self._head.feed(data)

    def next_event(self) -> h11.Event | type[h11.NEED_DATA] | type[h11.PAUSED]:
        # NEED_DATA, not PAUSED, after a refusal: uvicorn then keeps reading,
        # and the protocol discards what arrives (see GuardedH11Protocol).
        if self._refused:
            return h11.NEED_DATA
        if self.their_state is h11.IDLE:
            if self._head is None:
                self._head = _HeadScan()
                self._head.feed(self.trailing_data[0])
            if self._head.too_large:
                self._refused = True
                self._protocol.reject_oversized_head()
                return h11.NEED_DATA
        event = super().next_event()
        if self.their_state is not h11.IDLE:
            self._head = None  # parsed; the next cycle starts a new head
        if isinstance(event, h11.Request) and not self._protocol.request_head_received(event):
            self._refused = True
            return h11.NEED_DATA
        return event


class GuardedH11Protocol(H11Protocol):
    """uvicorn's h11 protocol with a header deadline, a request head cap and
    the bearer check on the request head.

    The deadline is armed when a connection is made and again when a response
    completes, and is cancelled only when h11 produces a Request event, never
    by received bytes. It is therefore never running between a request head
    and the end of its response: a slow authenticated request body or a long
    SSE stream is not cut off.

    With ``bearer_token`` set, a request head without it is answered 401 and
    the connection closed; the body is never parsed and the request never
    reaches the ASGI app (whose own check stays as the second one).

    A refused connection is half-closed after the response and drained
    (read, not parsed) until the client closes, for at most
    ``LINGER_SECONDS`` (never longer than the header deadline) and
    ``LINGER_MAX_BYTES``, then closed.
    """

    header_timeout: float = DEFAULT_HEADER_TIMEOUT
    bearer_token: bytes | None = None

    def __init__(
        self,
        config: Config,
        server_state: ServerState,
        app_state: dict[str, Any],
        _loop: asyncio.AbstractEventLoop | None = None,
    ) -> None:
        super().__init__(config, server_state, app_state, _loop)
        self.conn = _HeadGuardConnection(self, config.h11_max_incomplete_event_size)
        self._header_deadline: asyncio.TimerHandle | None = None
        self._linger: asyncio.TimerHandle | None = None
        self._linger_budget = 0

    def connection_made(self, transport: asyncio.Transport) -> None:  # type: ignore[override]
        super().connection_made(transport)
        self._arm_header_deadline()

    def connection_lost(self, exc: Exception | None) -> None:
        self._cancel_header_deadline()
        if self._linger is not None:
            self._linger.cancel()
            self._linger = None
        super().connection_lost(exc)

    def data_received(self, data: bytes) -> None:
        if self._linger is None:
            super().data_received(data)
            return
        # the rest of a refused request: discarded, never parsed
        self._linger_budget -= len(data)
        if self._linger_budget < 0:
            self.transport.close()

    def on_response_complete(self) -> None:
        # Armed before uvicorn resumes a pipelined request, whose Request
        # event then cancels it again.
        if not self.transport.is_closing():
            self._arm_header_deadline()
        super().on_response_complete()

    def request_head_received(self, request: h11.Request) -> bool:
        """Whether uvicorn may go on with *request*: False once it has been
        answered 401 (no or a wrong bearer token) and the connection closed."""
        self._cancel_header_deadline()
        if self.bearer_token is None or bearer_token_matches(request.headers, self.bearer_token):
            return True
        self._refuse(
            401,
            b"Unauthorized",
            [(b"www-authenticate", b"Bearer"), (b"content-type", b"application/json")],
            b"" if request.method == b"HEAD" else _UNAUTHORIZED_BODY,
        )
        return False

    def reject_oversized_head(self) -> None:
        """Answer 431 and close, without parsing the head."""
        self._cancel_header_deadline()
        self.logger.warning(_HEAD_TOO_LARGE)
        self._refuse(
            431,
            b"Request Header Fields Too Large",
            [(b"content-type", b"text/plain; charset=utf-8")],
            _HEAD_TOO_LARGE.encode("ascii"),
        )

    def _refuse(self, status: int, reason: bytes, headers: list[tuple[bytes, bytes]], body: bytes) -> None:
        """Send a complete response that closes the connection, half-close
        it and drain what the client still sends (then close it)."""
        if self.transport.is_closing():
            return
        headers = [*self.server_state.default_headers, *headers, (b"connection", b"close")]
        events: list[h11.Response | h11.Data | h11.EndOfMessage] = [
            h11.Response(status_code=status, headers=headers, reason=reason)
        ]
        if body:
            events.append(h11.Data(data=body))
        events.append(h11.EndOfMessage())
        for event in events:
            self.transport.write(self.conn.send(event))
        if self.transport.can_write_eof():
            self.transport.write_eof()  # the client sees the end of the response now
        self._linger_budget = LINGER_MAX_BYTES
        self._linger = self.loop.call_later(min(LINGER_SECONDS, self.header_timeout), self.transport.close)

    def _arm_header_deadline(self) -> None:
        self._cancel_header_deadline()
        self._header_deadline = self.loop.call_later(self.header_timeout, self._header_deadline_expired)

    def _cancel_header_deadline(self) -> None:
        if self._header_deadline is not None:
            self._header_deadline.cancel()
            self._header_deadline = None

    def _header_deadline_expired(self) -> None:
        self._header_deadline = None
        if self.transport.is_closing():
            return
        if self.cycle is not None and not self.cycle.response_complete:
            return  # a request is in flight; its completion re-arms the deadline
        try:
            self.conn.send(h11.ConnectionClosed())
        except h11.LocalProtocolError:
            pass  # h11 refuses this mid-response; the socket is closed regardless
        self.transport.close()


def guarded_h11_protocol(timeout: float, token: bytes | None = None) -> type[GuardedH11Protocol]:
    """The protocol class for ``uvicorn.run(http=...)`` with this deadline
    and, when given, this bearer token checked on every request head."""

    class ConfiguredH11Protocol(GuardedH11Protocol):
        header_timeout = timeout
        bearer_token = token

    return ConfiguredH11Protocol


# ---------------------------------------------------------------------------
# logging
# ---------------------------------------------------------------------------

# Messages uvicorn (uvicorn.error) and asyncio log for requests and
# connections that have not been authenticated; each can be produced at
# request rate by any client that reaches the socket.
_PRE_AUTH_MESSAGES = (
    "Unsupported upgrade request.",
    "No supported WebSocket library detected.",
    "Invalid HTTP request received.",
    _HEAD_TOO_LARGE,
    "socket.accept() out of system resource",
)


class PreAuthWarningFilter(logging.Filter):
    """Token bucket over the pre-auth protocol warnings.

    Up to ``burst`` such records pass, then one more every ``refill_seconds``.
    The first record let through after some were dropped carries a
    "suppressed N pre-auth protocol warnings" summary, so under a sustained
    flood the log gets one summary line per refill interval instead of one
    line per request. When the flood ends first, a timer logs the count
    ``refill_seconds`` after the first dropped record (on the event loop of
    the thread that dropped it, or through *schedule*). Other records always
    pass.
    """

    def __init__(
        self,
        burst: int = 10,
        refill_seconds: float = 6.0,
        clock: Callable[[], float] = time.monotonic,
        schedule: Callable[[float, Callable[[], None]], object] | None = None,
    ) -> None:
        super().__init__()
        self._burst = burst
        self._refill_seconds = refill_seconds
        self._clock = clock
        self._schedule = schedule
        self._tokens = float(burst)
        self._stamp = clock()
        self._suppressed = 0
        self._summary_due = False
        self._lock = threading.Lock()

    def filter(self, record: logging.LogRecord) -> bool:
        if not (isinstance(record.msg, str) and record.msg.startswith(_PRE_AUTH_MESSAGES)):
            return True
        arm = False
        suppressed = 0
        with self._lock:
            now = self._clock()
            self._tokens = min(float(self._burst), self._tokens + (now - self._stamp) / self._refill_seconds)
            self._stamp = now
            admit = self._tokens >= 1
            if admit:
                self._tokens -= 1
                suppressed, self._suppressed = self._suppressed, 0
            else:
                self._suppressed += 1
                arm, self._summary_due = not self._summary_due, True
        if not admit:
            if arm:
                self._arm_summary(record.name)
            return False
        if suppressed:
            record.msg = f"{record.getMessage()} (suppressed {suppressed} pre-auth protocol warnings)"
            record.args = None
        return True

    def _arm_summary(self, logger_name: str) -> None:
        schedule = self._schedule
        if schedule is None:
            try:
                schedule = asyncio.get_running_loop().call_later
            except RuntimeError:
                # no event loop in this thread: the next admitted warning
                # carries the count
                with self._lock:
                    self._summary_due = False
                return
        schedule(self._refill_seconds, lambda: self._log_summary(logger_name))

    def _log_summary(self, logger_name: str) -> None:
        with self._lock:
            suppressed, self._suppressed = self._suppressed, 0
            self._summary_due = False
        if suppressed:
            logging.getLogger(logger_name).warning("suppressed %d pre-auth protocol warnings", suppressed)


def cap_service_output(fds: Iterable[int] = (1, 2), max_bytes: int = LOG_FILE_MAX_BYTES) -> None:
    """Empty each descriptor in *fds* that is a regular file over *max_bytes*
    with one link, owned by this process's effective user.

    launchd appends the daemon's stdout and stderr to server.log and
    server.err.log and never rotates them, and no root job may: one over the
    service account's log directory (the newsyslog rule earlier .pkg releases
    installed) renames, chmods and chowns by name whatever that account put
    there, following symlinks. So the daemon, as that account, caps them
    itself: serve does this before it prints anything when
    ``UDBMCP_HTTP_LOG_FILE`` is set (a crash loop adds a failure per start),
    and ``CappedStreamHandler`` before each ERROR record. A pipe, a socket or
    a terminal is left alone. launchd opens those files as root and follows a
    symlink there, so a descriptor it hands over may be any file: this
    empties only one the account could empty by name itself (the .pkg keeps
    them in a directory only root can write and makes them the account's).
    The offset goes back to the top as well, so a descriptor opened without
    O_APPEND does not write past a hole."""
    owner = os.geteuid() if hasattr(os, "geteuid") else None
    for fd in fds:
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_size <= max_bytes or st.st_nlink != 1:
                continue
            if owner is not None and st.st_uid != owner:
                continue
            os.ftruncate(fd, 0)
            os.lseek(fd, 0, os.SEEK_SET)
            os.write(fd, f"universal-db-mcp: emptied this file at {st.st_size} bytes (cap {max_bytes})\n".encode())
        except OSError:
            continue


class CappedStreamHandler(logging.StreamHandler[TextIO]):
    """A ``logging.StreamHandler`` that keeps a stream which is a regular file
    (launchd's StandardErrorPath) under ``LOG_FILE_MAX_BYTES``: see
    ``cap_service_output``."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            fd = self.stream.fileno()
        except (AttributeError, OSError, ValueError):
            pass
        else:
            self.flush()
            cap_service_output((fd,))
        super().emit(record)


def http_log_config(log_file: str | None) -> dict[str, Any]:
    """``logging.config.dictConfig`` schema for the HTTP listener.

    uvicorn's own default configuration, plus the pre-auth filter on the
    ``uvicorn.error`` and ``asyncio`` loggers (one shared bucket). With
    ``log_file`` every handler - uvicorn's and the root one the MCP SDK
    installed - is replaced by a size-bounded rotating file, and ERROR
    records also go to stderr (capped, ``CappedStreamHandler``), so a startup
    failure (a port in use) shows where the service manager keeps it. The
    pre-auth records that reach ERROR are rate limited by the same filter.
    """
    console = {"class": "logging.StreamHandler", "stream": "ext://sys.stderr", "formatter": "console"}
    handlers: dict[str, Any]
    if log_file:
        handlers = {
            "default": {
                "class": "logging.handlers.RotatingFileHandler",
                "filename": log_file,
                "maxBytes": LOG_FILE_MAX_BYTES,
                "backupCount": LOG_FILE_BACKUPS,
                "encoding": "utf-8",
                "formatter": "file",
            },
            "errors": {**console, "class": f"{__name__}.CappedStreamHandler", "level": "ERROR"},
        }
    else:
        handlers = {"default": console}
    config: dict[str, Any] = {
        "version": 1,
        "disable_existing_loggers": False,
        "filters": {"pre_auth": {"()": PreAuthWarningFilter}},
        "formatters": {
            "console": {"()": "uvicorn.logging.DefaultFormatter", "fmt": "%(levelprefix)s %(message)s"},
            "file": {"format": "%(asctime)s %(levelname)s %(name)s: %(message)s"},
        },
        "handlers": handlers,
        "loggers": {
            "uvicorn": {"handlers": list(handlers), "level": "INFO", "propagate": False},
            "uvicorn.error": {"filters": ["pre_auth"]},
            "asyncio": {"filters": ["pre_auth"]},
        },
    }
    if log_file:
        config["root"] = {"handlers": list(handlers)}
    return config


def configure_http_logging(env: Mapping[str, str]) -> None:
    """Apply ``http_log_config`` with the log file named by
    ``UDBMCP_HTTP_LOG_FILE``, if any. Raises ``ValueError`` when the handler
    cannot be set up (for example an unwritable log file)."""
    log_file = env.get(LOG_FILE_ENV) or None
    try:
        logging.config.dictConfig(http_log_config(log_file))
    except ValueError as exc:
        # dictConfig reports only "Unable to configure handler"; the reason is
        # the chained error.
        raise ValueError(f"{LOG_FILE_ENV}={log_file!r}: {exc.__cause__ or exc}") from exc


# ---------------------------------------------------------------------------
# descriptor limit
# ---------------------------------------------------------------------------


def _darwin_max_files_per_process() -> int:
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv
            ["/usr/sbin/sysctl", "-n", "kern.maxfilesperproc"],
            capture_output=True,
            text=True,
            timeout=5,
            check=True,
        )
        return int(proc.stdout.strip())
    except (OSError, subprocess.SubprocessError, ValueError):
        return _DARWIN_FALLBACK_MAX_FILES


def raise_open_file_limit(target: int = OPEN_FILE_TARGET) -> None:
    """Raise the RLIMIT_NOFILE soft limit to ``min(hard, target)``.

    launchd starts daemons with a soft limit of 256 and systemd with 1024;
    the service definitions raise it too, this covers manual starts. Never
    lowers the limit, and a refusal keeps the inherited one. On macOS the
    soft limit is also capped at kern.maxfilesperproc, above which
    setrlimit fails.
    """
    try:
        import resource
    except ImportError:  # win32
        return
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        wanted = target if hard == resource.RLIM_INFINITY else min(hard, target)
        if soft == resource.RLIM_INFINITY or soft >= wanted:
            return
        if sys.platform == "darwin":
            wanted = min(wanted, _darwin_max_files_per_process())
        if soft < wanted:
            resource.setrlimit(resource.RLIMIT_NOFILE, (wanted, hard))
    except (OSError, ValueError):
        pass
