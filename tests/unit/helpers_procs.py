"""Tie a test's long-lived child process to the life of the test process.

Tests that start a server or a lock holder stop it in a ``finally``. That
cannot run when pytest itself is killed (an interrupted run, a harness
timeout, SIGKILL), and the child, re-parented to init, then runs for days
(an HTTP listener on a free port, a holder looping until a file appears).

``tie(proc)`` starts a small watchdog that blocks reading a pipe whose write
end only this test process holds. Whatever ends the test process - exit,
crash, SIGKILL - closes that end; the watchdog then sees EOF and kills the
child. A normal teardown calls ``release()``, which writes ``done`` first,
and the watchdog leaves the child alone. Before killing, the watchdog checks
the child is still the process it was started for (its start time and
command line, read with ps), so a recycled pid is never hit. POSIX only;
elsewhere ``tie`` does nothing.
"""

from __future__ import annotations

import subprocess
import sys
from typing import Any

_WATCHDOG = r"""
import os, signal, subprocess, sys
pid = sys.argv[1]
def identity():
    try:
        out = subprocess.run(["ps", "-o", "lstart=,command=", "-p", pid], capture_output=True, text=True, timeout=10)
    except Exception:
        return None
    return out.stdout.strip() or None
first = identity()
data = sys.stdin.buffer.read()  # returns at EOF: released, or the test process is gone
if data != b"done" and first is not None and identity() == first:
    try:
        os.kill(int(pid), signal.SIGKILL)
    except OSError:
        pass
"""


class Tie:
    """The watchdog of one child; ``release()`` before a normal teardown."""

    def __init__(self, watchdog: subprocess.Popen[bytes] | None) -> None:
        self._watchdog = watchdog

    def release(self) -> None:
        watchdog, self._watchdog = self._watchdog, None
        if watchdog is None or watchdog.stdin is None:
            return
        try:
            watchdog.stdin.write(b"done")
            watchdog.stdin.close()
        except OSError:
            pass
        try:
            watchdog.wait(timeout=15)
        except subprocess.TimeoutExpired:
            watchdog.kill()
            watchdog.wait(timeout=5)


def tie(proc: subprocess.Popen[Any]) -> Tie:
    """Kill ``proc`` if this test process dies before ``release()``."""
    if sys.platform == "win32":
        return Tie(None)
    watchdog = subprocess.Popen(  # noqa: S603 - fixed argv, the interpreter running the tests
        [sys.executable, "-I", "-c", _WATCHDOG, str(proc.pid)],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,  # a Ctrl-C to the test's process group must not reach it first
    )
    return Tie(watchdog)
