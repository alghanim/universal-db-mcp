"""Local JSONL audit log with size rotation.

Records: connection id, authenticated caller, action/tool, timing, row count,
policy outcome, and a redacted SQL fingerprint. Raw SQL text, bound values,
and rows are recorded only when explicitly enabled by policy (off by
default). Never records credentials or connection objects.

``audit_fail_closed=true`` (default) means a failure to write a required
audit record fails the operation (operations fail closed). With it off, a
failed write is counted in ``dropped_records`` and reported on stderr (at
most once per ``_WARN_INTERVAL_SECONDS``) instead of vanishing silently.

Several server processes may share one ``audit_path`` (every stdio client
spawns its own server from the same per-user config), so rotation and append
are serialized across processes by an exclusive lock on the sidecar file
``<audit_path>.lock``. The audit path must be on a local filesystem. A
record that cannot take the lock within ``_LOCK_WAIT_SECONDS`` is a failed
write like any other; the records after it wait at most
``_CONTENDED_WAIT_SECONDS`` until one gets the lock again.

Retention is a fixed budget (``audit_max_bytes x (audit_max_backups + 1)``)
that every record spends, and a call that failed before anything was sent
to a database costs a caller nothing to repeat. Such calls come through
``record_refusal``: in each window of ``_COALESCE_WINDOW_SECONDS`` the first
few of a kind (caller, action, outcome, category, connection id, SQL
fingerprint: exact repeats) are written in full, up to a total for the
window, and the rest are counted into one ``tool_call_summary`` record per
kind, written once the window has closed (by a timer, or with the next
record if that comes first) and when the process exits normally. Only a
process ended by a signal (an HTTP server's SIGTERM included) loses the
counts of the window still open. Summaries alone never create a missing
audit directory: their counts wait for the next record.

The SQL text (security.audit_sql_text) written per window is capped too.
Every record keeps the head and the tail of its text (``_SQL_TEXT_ENDS``
bytes each, as written; a short statement whole), whatever any caller sent
before it. The rest of the texts written in a window share
``_SQL_TEXT_BUDGET`` bytes, charged what a record writes past those ends
once it is written; past the budget (or past what one record holds) a
record keeps only the ends, in ``sql_text`` and ``sql_text_tail``, and
``sql_text_omitted`` says why, how many characters were left out and the
digest and length of the whole text.
"""

from __future__ import annotations

import atexit
import contextlib
import errno
import hashlib
import json
import os
import stat
import sys
import threading
import time
import weakref
from pathlib import Path
from typing import Any

from universal_db_mcp.security.redact import redact_value

# One serialized record never exceeds this: longer string values are replaced
# by a {"sha256", "len"} marker so an oversized statement cannot bloat the log.
_MAX_LINE_BYTES = 128 * 1024

_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
# Windows: os.open defaults to text mode, which would rewrite b"\n" and make
# the byte count checked after each write meaningless.
_O_BINARY = getattr(os, "O_BINARY", 0)

# A fail-open audit log that cannot write says so on stderr at most this often.
_WARN_INTERVAL_SECONDS = 60.0

# How often the lock file is reopened because the one held is no longer the one
# at its path. Each reopen means another process replaced it; a filesystem
# whose file identities never agree (some network or FUSE mounts) would
# otherwise spin forever with the thread lock held.
_LOCK_REOPEN_ATTEMPTS = 50
# The same bound for a name that O_CREAT|O_EXCL finds and the plain open that
# follows does not, again and again (inconsistent lookups on such a mount).
_CREATE_OR_OPEN_ATTEMPTS = 50
# How long one record waits for the log (its thread lock, then the file lock)
# before the call fails. A writer holds it for one append and fsync; one that
# never lets go (a server process suspended mid-append, or stuck in fsync on
# a dead mount) would otherwise hang every audited call of every process.
_LOCK_WAIT_SECONDS = 10.0
# Once a record gave up on a held log, the next ones wait only this long until
# one gets the lock again: a tool call writes two records (db_query and its
# statement, or the refusal after a failure), and a holder that never lets go
# must not cost every call the full wait once per record.
_CONTENDED_WAIT_SECONDS = 1.0
# Polling interval cap while another process holds the file lock.
_LOCK_POLL_SECONDS = 0.01

# Refusals (record_refusal) per window: of one kind, and of every kind
# together, written in full; kinds counted, the others sharing one summary;
# the distinct connection ids and fingerprints a summary names. A flood that
# spreads over every kind still writes at most _COALESCE_FULL records and
# _COALESCE_KINDS + 1 summaries per window.
_COALESCE_WINDOW_SECONDS = 10.0
_COALESCE_BURST = 10
_COALESCE_FULL = 64
_COALESCE_KINDS = 64
_COALESCE_SAMPLES = 8
_OTHER_KINDS = "<other kinds>"
# SQL text (as serialized) written per window past the ends below, whatever
# the records; a flood of cheap statements padded to the guard's 64 KiB
# ceiling otherwise rotates the trail away in seconds.
_SQL_TEXT_BUDGET = 1024 * 1024
# The head and the tail of a statement's text (as serialized, each) that
# every record keeps whatever the budget, so a caller who spent it cannot
# strip the text of the statements that run after (a short one stays whole).
_SQL_TEXT_ENDS = 1024
_TEXT_OMITTED = "per-window text budget spent"
_TEXT_TOO_LONG = f"longer than one record holds ({_MAX_LINE_BYTES // 1024} KiB)"

_Kind = tuple[Any, Any, Any, Any, Any, Any]  # caller, action, outcome, category, connection id, fingerprint

if sys.platform == "win32":
    import msvcrt

    def _try_lock_file(fd: int) -> bool:
        # msvcrt.locking locks from the current position; the lock is byte 0.
        # LK_NBLCK fails at once when another process holds it.
        os.lseek(fd, 0, os.SEEK_SET)
        try:
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        except OSError as exc:
            if exc.errno not in (errno.EACCES, errno.EDEADLOCK):
                raise
            return False
        return True

    def _unlock_file(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)

else:
    import fcntl

    def _try_lock_file(fd: int) -> bool:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        return True

    def _unlock_file(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_UN)


def _lock_file(fd: int, deadline: float) -> bool:
    """Take the exclusive lock on *fd*, polling while another process holds
    it; False when it is still held at *deadline* (time.monotonic()). It
    polls because a blocking flock cannot be abandoned at a deadline."""
    delay = 0.001
    while not _try_lock_file(fd):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(delay, remaining))
        delay = min(delay * 2, _LOCK_POLL_SECONDS)
    return True


class AuditWriteFailure(RuntimeError):
    pass


class _Tally:
    """Refusals of one kind that were counted instead of written."""

    __slots__ = ("caller_uid", "connection_ids", "count", "fingerprints", "first", "last")

    def __init__(self) -> None:
        self.count = 0
        self.first = self.last = 0.0  # time.time() of the first and the last
        self.caller_uid: Any = None
        self.connection_ids: list[Any] = []
        self.fingerprints: list[Any] = []

    def add(self, event: dict[str, Any], now: float) -> None:
        self.count += 1
        self.first = self.first or now
        self.last = now
        self.caller_uid = event.get("caller_uid", self.caller_uid)
        _sample(self.connection_ids, event.get("connection_id"))
        _sample(self.fingerprints, event.get("sql_fingerprint"))

    def merge(self, other: _Tally) -> None:
        self.count += other.count
        self.first = min(self.first, other.first) if self.first else other.first
        self.last = max(self.last, other.last)
        self.caller_uid = self.caller_uid if other.caller_uid is None else other.caller_uid
        for value in other.connection_ids:
            _sample(self.connection_ids, value)
        for value in other.fingerprints:
            _sample(self.fingerprints, value)


def _sample(values: list[Any], value: Any) -> None:
    if value is not None and value not in values and len(values) < _COALESCE_SAMPLES:
        values.append(value)


def _stamp(t: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(t))


def _other(kind: _Kind) -> _Kind:
    """The kind a refusal is counted under once the kinds counted are many."""
    return (kind[0], _OTHER_KINDS, kind[2], None, None, None)


def _summary(kind: _Kind, tally: _Tally) -> dict[str, Any]:
    caller, action, outcome, category = kind[:4]
    record: dict[str, Any] = {"event": "tool_call_summary", "caller": caller}
    if tally.caller_uid is not None:
        record["caller_uid"] = tally.caller_uid
    record.update(
        action=action, outcome=outcome, category=category, count=tally.count,
        first_ts=_stamp(tally.first), last_ts=_stamp(tally.last), connection_ids=tally.connection_ids,
    )
    if tally.fingerprints:
        record["sql_fingerprints"] = tally.fingerprints
    return record


class _Coalescer:
    """Which refusals are written in full and which are counted, per window.
    Its lock is never held across I/O."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._window: float | None = None  # when the current window began (time.monotonic)
        self._generation = 0  # which window, so a failed write is taken back from its own
        self._written: dict[_Kind, int] = {}  # records written in full this window, per kind
        self._full = 0  # and of every kind together
        self._counted: dict[_Kind, _Tally] = {}  # this window's counted refusals
        self._closed: dict[_Kind, _Tally] = {}  # closed windows' summaries, not written yet
        self._text = 0  # SQL text bytes written in full this window

    def admit(self, kind: _Kind, event: dict[str, Any]) -> int | None:
        """The window's generation when the refusal is to be written in full,
        else None: it was counted."""
        with self._lock:
            self._roll(time.monotonic())
            if (
                self._written.get(kind, 0) < _COALESCE_BURST
                and self._full < _COALESCE_FULL
                and (kind in self._written or len(self._written) < _COALESCE_KINDS)
            ):
                self._written[kind] = self._written.get(kind, 0) + 1
                self._full += 1
                return self._generation
            if kind not in self._counted and len(self._counted) >= _COALESCE_KINDS:
                kind = _other(kind)
            self._counted.setdefault(kind, _Tally()).add(event, time.time())
            return None

    def spend_text(self, size: int) -> int | None:
        """The window's generation when ``size`` more bytes of SQL text fit
        in its budget (they are then spent), else None."""
        with self._lock:
            self._roll(time.monotonic())
            if self._text + size > _SQL_TEXT_BUDGET:
                return None
            self._text += size
            return self._generation

    def refund_text(self, size: int, generation: int) -> None:
        """The text spent in that window was not written: it does not count."""
        with self._lock:
            if generation == self._generation:
                self._text -= size

    def unadmit(self, kind: _Kind, generation: int) -> None:
        """The refusal admitted in that window was not written: it does not count."""
        with self._lock:
            if generation == self._generation and self._written.get(kind):
                self._written[kind] -= 1
                self._full -= 1

    def take(self, *, close: bool = False) -> dict[_Kind, _Tally]:
        """The summaries of the windows that have closed (and of the current
        one, with ``close``), handed over to be written."""
        with self._lock:
            self._roll(time.monotonic(), close=close)
            closed, self._closed = self._closed, {}
            return closed

    def due_in(self) -> float | None:
        """Seconds until the current window's counts are due to be written;
        None when it counted nothing."""
        with self._lock:
            if not self._counted or self._window is None:
                return None
            return max(self._window + _COALESCE_WINDOW_SECONDS - time.monotonic(), 0.0)

    def restore(self, closed: dict[_Kind, _Tally]) -> None:
        """Summaries whose write failed, kept for the next record."""
        with self._lock:
            for kind, tally in closed.items():
                self._fold(self._closed, kind, tally)

    def _roll(self, now: float, *, close: bool = False) -> None:
        if self._window is not None and (close or now - self._window >= _COALESCE_WINDOW_SECONDS):
            for kind, tally in self._counted.items():
                self._fold(self._closed, kind, tally)
            self._window = None
            self._written, self._full, self._counted, self._text = {}, 0, {}, 0
        if self._window is None and not close:
            self._window = now
            self._generation += 1

    @staticmethod
    def _fold(into: dict[_Kind, _Tally], kind: _Kind, tally: _Tally) -> None:
        if kind not in into and len(into) >= _COALESCE_KINDS:
            kind = _other(kind)
        into.setdefault(kind, _Tally()).merge(tally)


# Logs holding counted refusals, whose summaries are written at a normal exit.
_WITH_COUNTS: weakref.WeakSet[AuditLog] = weakref.WeakSet()


@atexit.register
def _flush_at_exit() -> None:
    for log in list(_WITH_COUNTS):
        with contextlib.suppress(Exception):
            log.flush()


class AuditLog:
    def __init__(
        self,
        path: str | None,
        max_bytes: int = 50 * 1024 * 1024,
        max_backups: int = 5,
        fail_closed: bool = True,
    ) -> None:
        self._path = Path(path) if path else None
        self._lock_path = Path(f"{path}.lock") if path else None
        self._max_bytes = max_bytes
        self._max_backups = max_backups
        self._fail_closed = fail_closed
        # Audit writes come from worker threads (anyio.to_thread), so the
        # size-check + rotation + append sequence must be atomic. Without
        # this lock, two threads can both decide to rotate and the second
        # rename fails (source already moved), which under fail-closed
        # wrongly refuses a legitimate request. The sidecar file lock below
        # extends the same guarantee to other processes; this lock also
        # guards the two long-lived descriptors.
        self._lock = threading.Lock()
        self._lock_fd: int | None = None
        self._fd: int | None = None
        # set when a record gave up waiting for the log, cleared when one gets
        # it (a plain flag: a racing read costs one wait of the other length)
        self._contended = False
        # fail-open only: records lost to write failures, and when the last
        # stderr warning about them went out. They have a lock of their own,
        # never held across I/O: a record that gave up waiting for self._lock
        # (held by a thread stuck in fsync) must still be counted at once.
        self._stats_lock = threading.Lock()
        self.dropped_records = 0
        self._last_warning: float | None = None
        self._coalescer = _Coalescer()
        self._timer_lock = threading.Lock()
        self._timer: threading.Timer | None = None  # writes the counts once their window closed

    def __del__(self) -> None:
        # The descriptors are plain ints, which garbage collection never closes.
        for fd in (getattr(self, "_fd", None), getattr(self, "_lock_fd", None)):
            if fd is not None:
                with contextlib.suppress(OSError):
                    os.close(fd)

    def record(self, event: dict[str, Any]) -> None:
        """Append one audit record. Raises AuditWriteFailure when fail-closed
        is enabled and the write did not succeed."""
        if self._path is None:
            return
        event = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), **redact_value(event)}
        whole = _serialize(event)
        ends = _text_ends(event)
        if ends is None:
            self._write(_fit(whole))
            return
        if len(whole) > _MAX_LINE_BYTES:
            # the line cap would leave a digest of the whole text: its ends, for free
            ends["sql_text_omitted"]["reason"] = _TEXT_TOO_LONG
            self._write(_encode_line(ends))
            return
        cut = _encode_line(ends)
        # the window's budget pays what the whole record writes past its ends
        cost = len(whole) - len(cut)
        generation = self._coalescer.spend_text(cost) if cost > 0 else None
        if generation is None:
            self._write(cut if cost > 0 else whole)
            return
        try:
            written = self._write(whole)
        except BaseException:
            self._coalescer.refund_text(cost, generation)
            raise
        if not written:
            self._coalescer.refund_text(cost, generation)

    def record_refusal(self, event: dict[str, Any], kind_action: str | None = None) -> None:
        """record() for a call that failed before anything was sent to a
        database: written in full while its kind (caller, action, outcome,
        category, connection id, SQL fingerprint) is within the window's
        allowance, else counted into the kind's summary. ``kind_action``
        stands for the action in the kind where the caller chose it (an
        unknown tool's name). A record that could not be written is taken
        back, so fail-closed every such call is refused."""
        if self._path is None:
            return
        kind = (
            event.get("caller"), kind_action or event.get("action"), event.get("outcome"), event.get("category"),
            event.get("connection_id"), event.get("sql_fingerprint"),
        )
        generation = self._coalescer.admit(kind, event)
        if generation is None:
            _WITH_COUNTS.add(self)
            self._flush_later()
            return
        try:
            self.record(event)
        except BaseException:
            self._coalescer.unadmit(kind, generation)
            raise

    def flush(self) -> None:
        """Write the summaries of the refusals counted so far (at exit)."""
        if self._path is not None:
            self._write(b"", closing=True)

    def _flush_later(self) -> None:
        """Writes the counts once their window has closed, whether or not
        another record comes: an idle server, or an HTTP server stopped by
        SIGTERM (uvicorn raises it again after its shutdown, so no exit
        handler runs), would hold them until then."""
        due = self._coalescer.due_in()
        if due is None:
            return
        with self._timer_lock:
            if self._timer is not None:
                return
            timer = self._timer = threading.Timer(due + 0.05, self._flush_due)
        timer.daemon = True
        timer.start()

    def _flush_due(self) -> None:
        with self._timer_lock:
            self._timer = None
        self._write(b"")
        self._flush_later()  # the counts of a window opened meanwhile

    def _write(self, line: bytes, *, closing: bool = False) -> bool:
        """Append *line*, after the summaries of the windows that closed;
        whether it was written. A write of summaries alone that fails keeps
        them for the next record: no call waits on it, and nothing was lost.
        Only a record creates a missing audit directory: one removed since
        (a purge, an uninstall) is not created again for a summary."""
        assert self._path is not None
        summaries_only = not line
        closed = self._coalescer.take(close=closing)
        if closed:
            now = time.strftime("%Y-%m-%dT%H:%M:%S%z")
            line = b"".join(_encode_line({"ts": now, **redact_value(_summary(k, t))}) for k, t in closed.items()) + line
        if not line:
            return False
        # one deadline for the whole wait: a thread queued behind another
        # that waits for the file lock does not wait its full turn again
        contended = self._contended or closing
        wait = min(_CONTENDED_WAIT_SECONDS, _LOCK_WAIT_SECONDS) if contended else _LOCK_WAIT_SECONDS
        held = f"{wait:g} s"
        if self._contended:
            # the caller of a two-record call sees this one's failure
            held += f", after an earlier record gave up waiting {_LOCK_WAIT_SECONDS:g} s"
        deadline = time.monotonic() + wait
        try:
            if not self._lock.acquire(timeout=wait):
                self._contended = True
                raise OSError(
                    errno.EAGAIN,
                    f"audit log held by another thread of this process for more than {held}",
                    str(self._path),
                )
            try:
                # a missing directory (e.g. the per-user default) is private
                try:
                    if not summaries_only:
                        self._path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                except FileExistsError as exc:
                    # a regular file stands where the directory should be
                    raise NotADirectoryError(errno.ENOTDIR, os.strerror(errno.ENOTDIR), str(self._path.parent)) from exc
                lock_fd = self._acquire_file_lock(deadline, held)
                self._contended = False
                try:
                    self._append(line)
                finally:
                    _unlock_file(lock_fd)
            finally:
                self._lock.release()
        except OSError as exc:
            if not isinstance(exc, _UnsyncedWrite):
                # nothing reached the file: the counts wait for the next record
                self._coalescer.restore(closed)
            if summaries_only:
                return False
            if self._fail_closed:
                raise AuditWriteFailure(
                    f"audit log write to '{self._path}' failed and "
                    f"application.audit_fail_closed=true; operation refused "
                    f"({exc})"
                ) from exc
            self._dropped(exc)
            return False
        return True

    def _dropped(self, exc: OSError) -> None:
        with self._stats_lock:
            self.dropped_records += 1
            now = time.monotonic()
            if self._last_warning is not None and now - self._last_warning < _WARN_INTERVAL_SECONDS:
                return
            self._last_warning = now
            dropped = self.dropped_records
        code = errno.errorcode.get(exc.errno, str(exc.errno)) if exc.errno is not None else type(exc).__name__
        print(
            f"universal-db-mcp: audit log write to '{self._path}' failed ({code}: {exc.strerror or exc}); "
            f"application.audit_fail_closed=false, so the call went ahead unaudited "
            f"({dropped} audit record(s) dropped so far)",
            file=sys.stderr,
        )

    def _acquire_file_lock(self, deadline: float, held: str) -> int:
        """Hold the cross-process lock on ``<audit_path>.lock`` and return its
        descriptor, waiting for it until *deadline* (*held*: that wait, as
        the error names it). Stat, rotation, open, append and fsync all
        happen under it: on Windows os.replace fails while another process
        has the file open, so rotation cannot be locked on its own."""
        assert self._lock_path is not None
        for _attempt in range(_LOCK_REOPEN_ATTEMPTS):
            if self._lock_fd is None:
                self._lock_fd = _open_state_file(self._lock_path, os.O_RDWR)
            if not _lock_file(self._lock_fd, deadline):
                self._contended = True
                raise OSError(
                    errno.EAGAIN,
                    f"audit lock held by another process for more than {held}",
                    str(self._lock_path),
                )
            # A lock file removed or replaced while this process waited is
            # not the one the next process will lock: reopen until they agree.
            try:
                held_is_current = os.path.samestat(os.fstat(self._lock_fd), os.stat(self._lock_path))
            except FileNotFoundError:
                held_is_current = False
            except BaseException:
                _unlock_file(self._lock_fd)
                raise
            if held_is_current:
                return self._lock_fd
            _unlock_file(self._lock_fd)
            os.close(self._lock_fd)
            self._lock_fd = None
        raise OSError(
            errno.EAGAIN,
            f"audit lock file keeps changing ({_LOCK_REOPEN_ATTEMPTS} reopen attempts); the audit path must be "
            "on a local filesystem",
            str(self._lock_path),
        )

    def _append(self, line: bytes) -> None:
        """Rotate if needed and append *line* with one write. Runs under the
        file lock; the append descriptor is kept open across records and
        reopened when another process rotated the file away."""
        assert self._path is not None
        try:
            try:
                st: os.stat_result | None = os.stat(self._path)
            except FileNotFoundError:
                st = None
            # only a regular file is rotated: renaming a directory away would
            # turn a fail-closed EISDIR into a silently fresh log
            due = st is not None and stat.S_ISREG(st.st_mode) and st.st_size >= self._max_bytes
            if self._max_backups > 0 and (due or os.path.lexists(self._staging_path())):
                self._close_fd()
                self._rotate(live=due)
                st = None
            if self._fd is not None and (st is None or not os.path.samestat(os.fstat(self._fd), st)):
                self._close_fd()
            if self._fd is None:
                self._fd = self._open_log()
            elif sys.platform != "win32" and st is not None and st.st_mode & 0o077:
                # loosened (chmod 644) while this process kept it open: the
                # record about to be appended may carry SQL text
                os.fchmod(self._fd, 0o600)
            _write_record(self._fd, line)
        except OSError:
            self._close_fd()
            raise
        if sys.platform == "win32":
            # an open handle would make the next rotation (by any process) fail
            self._close_fd()

    def _open_log(self) -> int:
        assert self._path is not None
        return _open_state_file(self._path, os.O_RDWR | os.O_APPEND)

    def _close_fd(self) -> None:
        if self._fd is not None:
            fd, self._fd = self._fd, None
            with contextlib.suppress(OSError):
                os.close(fd)

    def _backup_path(self, suffix: str) -> Path:
        assert self._path is not None
        return self._path.with_suffix(self._path.suffix + f".{suffix}")

    def _staging_path(self) -> Path:
        return self._backup_path("rotating")

    def _rotate(self, *, live: bool) -> None:
        """Move the log to <audit_path>.1 (when *live*), first finishing a
        rotation that stopped part-way. No failure loses a generation: the log
        is moved to <audit_path>.rotating before any backup moves, so a log
        that cannot be moved (a Windows reader holding it open, EBUSY) leaves
        everything as it was; and each backup only ever moves into a free
        slot, so a retry resumes where the failed attempt stopped instead of
        shifting the chain again. The oldest generation is replaced only
        once the log itself has moved."""
        staging = self._staging_path()
        if os.path.lexists(staging):
            # an earlier rotation moved the log there and then failed
            self._settle(staging)
        if not live:
            return
        try:
            assert self._path is not None
            self._path.replace(staging)
        except FileNotFoundError:
            return  # already moved away by an administrator: nothing to rotate
        self._settle(staging)

    def _settle(self, staging: Path) -> None:
        """Shift the backups below the first free slot (the oldest slot when
        there is none) down by one and move *staging* to .1. Tolerant of
        missing generations (a hole left by an administrator takes the
        shift): ENOENT here is never an audit failure. Any other error
        (EACCES, ENOSPC, ...) still fails closed, with every generation
        still under some name."""
        free = next(
            (n for n in range(1, self._max_backups + 1) if not os.path.lexists(self._backup_path(str(n)))),
            self._max_backups,
        )
        for i in range(free - 1, 0, -1):
            try:
                self._backup_path(str(i)).replace(self._backup_path(str(i + 1)))
            except FileNotFoundError:
                continue
        with contextlib.suppress(FileNotFoundError):
            staging.replace(self._backup_path("1"))


def _open_state_file(path: Path, flags: int) -> int:
    """Open the log or its lock, creating it when missing. The service
    account owns the audit directory, so an existing name there may be a
    link it planted to a file it may not write, which a root run would then
    chmod and append to: a symlink (O_NOFOLLOW), anything but a regular file
    and a file with a second hard link are refused."""
    flags |= _O_NOFOLLOW | _O_BINARY
    for _attempt in range(_CREATE_OR_OPEN_ATTEMPTS):
        try:
            fd, created = os.open(path, flags | os.O_CREAT | os.O_EXCL, 0o600), True
            break
        except FileExistsError:
            pass
        try:
            fd, created = os.open(path, flags), False
            break
        except FileNotFoundError:
            continue  # removed between the two opens: create it after all
    else:
        raise OSError(
            errno.EAGAIN,
            f"audit file keeps appearing and disappearing ({_CREATE_OR_OPEN_ATTEMPTS} attempts to create or open "
            "it); the audit path must be on a local filesystem",
            str(path),
        )
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise OSError(errno.EINVAL, "not a regular file", str(path))
        if st.st_nlink > 1:
            raise OSError(errno.EMLINK, f"refused: the file has {st.st_nlink} hard links", str(path))
        # 0600: the audit trail may contain SQL text and must never be
        # group/world readable, regardless of the process umask. fchmod is
        # idempotent and also tightens files created by an older build with
        # a looser mode.
        # POSIX only: NTFS has no POSIX mode bits, so on Windows there is no
        # 0600 to apply (and fchmod would raise on every write). On Windows
        # the audit file inherits the ACL of the state directory it lives
        # in; hardening there means provisioning THAT directory's ACL at
        # install time (see docs/offline-deployment.md) — documented, not
        # faked with a permission bit the filesystem cannot represent.
        if sys.platform != "win32":
            os.fchmod(fd, 0o600)
            if created:
                _give_to_directory_owner(fd, path.parent)
    except OSError:
        os.close(fd)
        raise
    return fd


def _give_to_directory_owner(fd: int, directory: Path) -> None:
    """Running as root, hand a file this process has just created to the
    owner of its directory. A one-off root run against the service's audit
    directory (sudo site-check) would otherwise leave a root-owned 0600 lock
    or log that the service account is denied on every later record. Only a
    new file is handed over: an existing name in a directory the service
    account owns may be a link it planted. Best effort; nothing changes when
    not running as root or when root owns the directory."""
    if os.geteuid() != 0:
        return
    dst = os.stat(directory)
    if dst.st_uid != 0 and os.fstat(fd).st_uid != dst.st_uid:
        with contextlib.suppress(OSError):
            os.fchown(fd, dst.st_uid, dst.st_gid)


class _UnsyncedWrite(OSError):
    """The record is in the file (written in full) but fsync failed, so it may
    not be on disk: still a failed write, but what it carried is not written
    again with the next record."""


def _write_record(fd: int, line: bytes) -> None:
    """Append *line* with a single write on the O_APPEND descriptor. A short
    write (disk full, file-size limit) is truncated away so the fragment can
    never be glued to the next record; a fragment some other writer left is
    closed with a newline first."""
    start = os.lseek(fd, 0, os.SEEK_END)
    if start:
        os.lseek(fd, start - 1, os.SEEK_SET)
        if os.read(fd, 1) != b"\n":
            line = b"\n" + line
    written = os.write(fd, line)
    if written != len(line):
        with contextlib.suppress(OSError):
            os.ftruncate(fd, start)
        raise OSError(errno.EIO, f"short write: {written} of {len(line)} bytes (disk full or file-size limit)")
    try:
        os.fsync(fd)
    except OSError as exc:
        raise _UnsyncedWrite(*exc.args) from exc


def _serialize(event: dict[str, Any]) -> bytes:
    return (json.dumps(event, separators=(",", ":"), default=str) + "\n").encode("utf-8")


def _encode_line(event: dict[str, Any]) -> bytes:
    """One JSONL record of at most _MAX_LINE_BYTES (see _fit)."""
    return _fit(_serialize(event))


def _fit(line: bytes) -> bytes:
    """The serialized record *line*, or if it is over _MAX_LINE_BYTES, one
    that fits: string values longer than a shrinking threshold are replaced
    by digest markers until it does; one that still does not fit keeps only
    its identifying fields and a digest of the whole record."""
    if len(line) <= _MAX_LINE_BYTES:
        return line
    plain = json.loads(line)
    limit = _MAX_LINE_BYTES
    while limit > 64:
        limit //= 4
        shrunk = (json.dumps(_digest_strings(plain, limit), separators=(",", ":")) + "\n").encode("utf-8")
        if len(shrunk) <= _MAX_LINE_BYTES:
            return shrunk
    kept = {k: plain[k] for k in ("ts", "event", "request_id", "action", "connection_id", "outcome") if k in plain}
    kept["oversized_record"] = _digest(line.decode("utf-8"))
    return (json.dumps(_digest_strings(kept, 256), separators=(",", ":")) + "\n").encode("utf-8")


def _digest_strings(value: Any, limit: int) -> Any:
    if isinstance(value, str):
        return _digest(value) if len(value) > limit else value
    if isinstance(value, dict):
        return {k: _digest_strings(v, limit) for k, v in value.items()}
    if isinstance(value, list):
        return [_digest_strings(v, limit) for v in value]
    return value


def _digest(text: str) -> dict[str, Any]:
    # surrogatepass: a statement may carry a lone surrogate (JSON "\ud800")
    return {"sha256": hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest(), "len": len(text)}


def _text_ends(event: dict[str, Any]) -> dict[str, Any] | None:
    """The event with its ``sql_text`` cut to the head and the tail every
    record keeps (``sql_text`` and ``sql_text_tail``), and what was left out
    named; None when the text is no longer than those ends."""
    text = event.get("sql_text")
    if not isinstance(text, str) or len(json.dumps(text)) - 2 <= 2 * _SQL_TEXT_ENDS:
        return None
    head = _prefix_within(text, _SQL_TEXT_ENDS)
    # sizes as written do not depend on order: a suffix is a reversed prefix
    tail = _prefix_within(text[len(head):][::-1], _SQL_TEXT_ENDS)[::-1]
    omitted = {"reason": _TEXT_OMITTED, "chars": len(text) - len(head) - len(tail), **_digest(text)}
    return {**event, "sql_text": head, "sql_text_tail": tail, "sql_text_omitted": omitted}


def _prefix_within(text: str, size: int) -> str:
    """The longest prefix of *text* whose JSON form takes at most *size*
    bytes (a character takes 1 to 12)."""
    low, high = 0, min(len(text), size)
    while low < high:
        mid = (low + high + 1) // 2
        if len(json.dumps(text[:mid])) - 2 <= size:
            low = mid
        else:
            high = mid - 1
    return text[:low]
