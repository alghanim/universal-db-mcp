"""helpers_procs.tie: a child outlives neither a killed nor a finished test."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX process model")

HERE = Path(__file__).resolve().parent

# A stand-in for a test process: starts a long-lived child, ties it, prints
# the child's pid, then waits to be killed (or releases and exits when asked).
_PARENT = r"""
import subprocess, sys, time
sys.path.insert(0, sys.argv[1])
from helpers_procs import tie
child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(600)"], stdout=subprocess.DEVNULL)
handle = tie(child)
print(child.pid, flush=True)
if sys.argv[2] == "release":
    handle.release()  # a normal teardown; this stand-in then exits without stopping the child
    print("released", flush=True)
else:
    time.sleep(600)
"""


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    out = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True)  # noqa: S603, S607
    return "Z" not in out.stdout  # a zombie is gone in all but name


def _until(predicate, timeout: float = 15.0) -> bool:  # type: ignore[no-untyped-def]
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.1)
    return predicate()


def test_a_killed_test_process_takes_its_child_with_it() -> None:
    parent = subprocess.Popen(  # noqa: S603
        [sys.executable, "-c", _PARENT, str(HERE), "hold"], stdout=subprocess.PIPE, text=True
    )
    assert parent.stdout is not None
    child = int(parent.stdout.readline())
    assert _alive(child)
    parent.send_signal(signal.SIGKILL)  # what a harness timeout does: no finally runs
    parent.wait(timeout=10)
    assert _until(lambda: not _alive(child)), f"child {child} outlived the killed test process"


def test_a_released_child_is_left_alone() -> None:
    """After release() the watchdog must not kill the child when the test
    process later exits (here the stand-in exits and leaves it running)."""
    parent = subprocess.Popen(  # noqa: S603
        [sys.executable, "-c", _PARENT, str(HERE), "release"], stdout=subprocess.PIPE, text=True
    )
    out, _ = parent.communicate(timeout=30)
    assert parent.returncode == 0
    child, last = int(out.splitlines()[0]), out.splitlines()[-1]
    assert last == "released"
    try:
        time.sleep(1.0)  # longer than the watchdog takes to act on EOF
        assert _alive(child), "the watchdog killed a released child"
    finally:
        os.kill(child, signal.SIGKILL)
