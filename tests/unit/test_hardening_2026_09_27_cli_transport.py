"""Hardening 2026-09-27, cli-transport group: the HTTP listener before bearer
auth, the bearer token file, and stdio shutdown on SIGTERM.

Bearer auth runs in the ASGI app, so everything uvicorn and h11 do before a
request head is complete is reachable by any client that can open a socket to
the listener (every local user on the default loopback bind, every peer on
the container network). The review found:

* F13: idle, half-sent and 401-then-one-byte connections were never closed,
  so ~256 (launchd) or ~1024 (systemd) sockets exhausted the descriptor limit
  and every authenticated call failed, including audit writes.
* F57: pre-auth protocol warnings were logged at 1-2 MiB/s, into a launchd log
  that newsyslog rotates to an unlinked inode, and compose logs had no cap.
* F92: h11 parsed up to 256 KiB and 20,000 headers per request before auth.
* F69: a non-UTF-8 token file crashed serve; a one-character token started it.
* F86: SIGTERM killed a stdio server mid-query without the audit record.

The listener tests start a real ``serve --transport http`` subprocess with
RLIMIT_NOFILE=128 and a 2 s header deadline and speak raw HTTP/1.1 to it.

Part 2 covers the ``add-connection`` wizard, ``site-check --out`` and the
onboarding commands:

* F43: re-adding a connection replaced its whole block, dropping
  allowed_schemas (which opened every schema), session, options, timeouts
  and client certificates.
* F44: credential files were overwritten before anything was validated, and
  names that differ only in case shared one pair of secret files.
* F47: under sudo the secrets came out root-only and the service could not
  start.
* F49: the config was rewritten in place, so ENOSPC left it empty.
* F50: on Windows a pre-existing (squatted) secrets directory was trusted.
* F52: a relative --config stored secret and CA paths relative to the cwd.
* F77: every comment after the header was dropped, and said so only after.
* F78: ``site-check --out X --force`` followed a symlink planted at X.
* F81: nothing told the admin that a stdio agent can read the credentials.

Part 3 covers what review round 3 still found (the integration wave):

* I38: the SIGTERM grace watchdog needs the GIL, so a cancel hook that holds
  it (PQcancel against a frozen host) kept a stdio server alive.
* I39: as root, the secrets directory was chowned through a config directory
  its owner could swap for a symlink.
* I40: ``--read-write`` and the "Read-only connection?" prompt always ended
  in a pydantic dump, since the config refuses read_only: false.
* I41: configure-agents exited 0 when an adapter failed closed.
* I42: scripts/http_client_evidence.py resolved relative paths in its copy.
* I43: scripts/demo_agent_probe.py forced the SQL Server sa login and called
  a login failure a staging limitation.
* I44: canonically equivalent Unicode names shared one pair of secret files.
* I45: a credential re-add kept the old password_env.
* I46: the config backup followed a symlink planted at its stamped name.
* I47: no agent notice when root wrote secrets for a per-user stdio config.
* I48: with UDBMCP_HTTP_LOG_FILE, a bind failure never reached stderr.
* I49: serve did not say where it audits when audit_path is unset.

Fix-up round 1 (tests say so in their docstrings) covers what the re-review
still found: as root the directory walk ran only for credentials, ignored
macOS ACLs, and the old secret was copied from a file opened by name (I39);
text-mode configure-agents exited 0 after a failed confirmed write (I41); the
probe's 'ODBC Driver' and 'SQL30082N' markers hid real failures (I43); a
per-user http config lost the agent notice (I47).

Fix-up round 2 covers what the second re-review found: a harness config
that was already malformed still let configure-agents exit 0 (I41); the
server redacts the SQL30082N reason, so a live Db2 login failure passed the
probe (I43); the evidence script rebased a symlinked config onto its target
(I42); Windows device names passed as connection names (I44); and
--password-file stored the whole file and, as root, followed a link (I39).

The final round: the config backup copied setuid, setgid and, as root,
others' write bits (I46); and an xfail keeps visible that the SIGTERM alarm
does not cover a cancel hook the deadline fired before the SIGTERM (I38).
"""

from __future__ import annotations

import asyncio
import builtins
import contextlib
import errno
import http.client
import json
import logging
import os
import plistlib
import re
import secrets
import select
import signal
import socket
import sqlite3
import stat
import subprocess
import sys
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
import yaml

from universal_db_mcp import config as config_module
from universal_db_mcp import wizard
from universal_db_mcp.__main__ import main
from universal_db_mcp.config import load_config, load_resolved
from universal_db_mcp.diagnostics import site_check
from universal_db_mcp.security.policy import EffectivePolicy

REPO = Path(__file__).resolve().parents[2]
SYSTEMD_UNIT = REPO / "packaging" / "systemd" / "universal-db-mcp.service"
PLIST = REPO / "packaging" / "launchd" / "com.udbmcp.server.plist"
COMPOSE = REPO / "packaging" / "compose.offline.yaml"

POSIX_ONLY = pytest.mark.skipif(sys.platform == "win32", reason="POSIX rlimits and signals")

HEADER_TIMEOUT = 2.0
LISTENER_NOFILE = 128
INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "hardening-probe", "version": "1"},
    },
}
INITIALIZED = {"jsonrpc": "2.0", "method": "notifications/initialized"}
LIST_CONNECTIONS = {
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {"name": "db_list_connections", "arguments": {}},
}

_XML_COMMENT = re.compile(rb"<!--.*?-->", re.S)


# --------------------------------------------------------------------------
# a real HTTP listener
# --------------------------------------------------------------------------


@dataclass
class _Listener:
    port: int
    token: str
    stderr: Path
    proc: subprocess.Popen[bytes]


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port: int = s.getsockname()[1]
        return port


def _sqlite_db(path: Path) -> Path:
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE t (id INTEGER)")
    con.execute("INSERT INTO t VALUES (1)")
    con.commit()
    con.close()
    return path


def _jsonrpc(data: bytes) -> Any:
    """The JSON-RPC message of a Streamable HTTP reply (JSON or SSE framed)."""
    text = data.decode("utf-8", "replace")
    if text.lstrip().startswith("{"):
        return json.loads(text)
    for line in text.splitlines():
        if line.startswith("data:"):
            return json.loads(line[5:].strip())
    return None


def _mcp_post(
    port: int, token: str, body: dict[str, Any], session: str | None = None, timeout: float = 15.0
) -> tuple[int, dict[str, str], Any]:
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "Authorization": f"Bearer {token}",
    }
    if session:
        headers["mcp-session-id"] = session
        headers["mcp-protocol-version"] = "2025-06-18"
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        conn.request("POST", "/mcp", body=json.dumps(body), headers=headers)
        response = conn.getresponse()
        data = response.read()
        return response.status, {k.lower(): v for k, v in response.getheaders()}, _jsonrpc(data)
    finally:
        conn.close()


def _session(port: int, token: str, timeout: float = 15.0) -> str:
    status, headers, message = _mcp_post(port, token, INITIALIZE, timeout=timeout)
    assert status == 200, (status, message)
    session = headers.get("mcp-session-id")
    assert session
    _mcp_post(port, token, INITIALIZED, session, timeout=timeout)
    return session


def _list_connections(port: int, token: str, timeout: float = 15.0) -> Any:
    session = _session(port, token, timeout)
    status, _, message = _mcp_post(port, token, LIST_CONNECTIONS, session, timeout=timeout)
    assert status == 200, (status, message)
    return message


def _connect(port: int) -> socket.socket:
    return socket.create_connection(("127.0.0.1", port), timeout=5)


def _peer_closed(sock: socket.socket, wait: float = 0.0) -> bool:
    """True once the server closed the connection (EOF or reset); pending
    response bytes are drained and do not count."""
    deadline = time.monotonic() + wait
    while True:
        readable, _, _ = select.select([sock], [], [], max(0.0, deadline - time.monotonic()))
        if not readable:
            return False
        try:
            chunk = sock.recv(65536)
        except OSError:
            return True
        if chunk == b"":
            return True


def _read_until(sock: socket.socket, marker: bytes, timeout: float = 5.0) -> bytes:
    data = b""
    deadline = time.monotonic() + timeout
    while marker not in data and time.monotonic() < deadline:
        readable, _, _ = select.select([sock], [], [], max(0.0, deadline - time.monotonic()))
        if not readable:
            break
        chunk = sock.recv(65536)
        if not chunk:
            break
        data += chunk
    return data


def _raise_own_fd_limit(target: int) -> None:
    import resource

    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft != resource.RLIM_INFINITY and soft < target:
        wanted = target if hard == resource.RLIM_INFINITY else min(target, hard)
        resource.setrlimit(resource.RLIMIT_NOFILE, (wanted, hard))


@pytest.fixture(scope="module")
def listener(tmp_path_factory: pytest.TempPathFactory) -> Iterator[_Listener]:
    if sys.platform == "win32":
        pytest.skip("POSIX rlimits")
    import resource

    work = tmp_path_factory.mktemp("http-listener")
    db = _sqlite_db(work / "demo.db")
    token = secrets.token_hex(32)
    token_file = work / "http-token"
    token_file.write_text(token + "\n", encoding="utf-8")
    token_file.chmod(0o600)
    port = _free_port()
    config = work / "config.yaml"
    config.write_text(
        "application:\n"
        "  transport: http\n"
        "  http_host: 127.0.0.1\n"
        f"  http_port: {port}\n"
        f"  http_bearer_token_file: {token_file}\n"
        f"  audit_path: {work / 'audit.jsonl'}\n"
        f"  metadata_cache_path: {work / 'cache.sqlite'}\n"
        "connections:\n"
        "  demo:\n"
        "    type: sqlite\n"
        f"    database: {db}\n",
        encoding="utf-8",
    )
    env = dict(os.environ, UDBMCP_HTTP_HEADER_TIMEOUT=str(HEADER_TIMEOUT))
    env.pop("UDBMCP_HTTP_LOG_FILE", None)

    def _limit_fds() -> None:
        # soft == hard, so the server cannot raise it: the deadline alone
        # must keep descriptors available
        resource.setrlimit(resource.RLIMIT_NOFILE, (LISTENER_NOFILE, LISTENER_NOFILE))

    stderr = work / "server.err"
    with stderr.open("wb") as err:
        proc = subprocess.Popen(  # noqa: S603 - fixed argv, the interpreter running the tests
            [sys.executable, "-m", "universal_db_mcp", "serve", "--config", str(config), "--transport", "http"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=err,
            env=env,
            cwd=work,
            preexec_fn=_limit_fds,  # noqa: PLW1509 - single-threaded test process
        )
    try:
        deadline = time.monotonic() + 30
        while True:
            if proc.poll() is not None:
                pytest.fail(f"serve exited rc={proc.returncode}: {stderr.read_text(errors='replace')[-2000:]}")
            try:
                if _mcp_post(port, token, INITIALIZE, timeout=2)[0] == 200:
                    break
            except OSError:
                pass
            if time.monotonic() > deadline:
                pytest.fail(f"serve never answered: {stderr.read_text(errors='replace')[-2000:]}")
            time.sleep(0.2)
        yield _Listener(port=port, token=token, stderr=stderr, proc=proc)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=10)


# --------------------------------------------------------------------------
# F13: the header deadline, the descriptor limit, the service definitions
# --------------------------------------------------------------------------


@POSIX_ONLY
def test_f13_preauth_connections_are_closed_by_the_header_deadline(listener: _Listener) -> None:
    port = listener.port
    started: dict[str, float] = {}
    socks: dict[str, socket.socket] = {}

    socks["idle"] = _connect(port)  # sends nothing at all
    started["idle"] = time.monotonic()
    socks["dribble"] = _connect(port)  # one byte of an unfinished header block per second
    started["dribble"] = time.monotonic()

    # A 401 now also ends its connection (next test); these two stay to
    # show that no byte sent after it keeps the socket open.
    stray = _connect(port)
    stray.sendall(b"GET /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
    assert b" 401 " in _read_until(stray, b"0\r\n\r\n").split(b"\r\n", 1)[0]
    with contextlib.suppress(OSError):
        stray.sendall(b"G")  # the start of a request line that never ends
    socks["401-then-stray-byte"] = stray
    started["401-then-stray-byte"] = time.monotonic()

    body_byte = _connect(port)
    body_byte.sendall(
        b"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 10\r\n\r\n"
    )
    assert b" 401 " in _read_until(body_byte, b"0\r\n\r\n").split(b"\r\n", 1)[0]
    with contextlib.suppress(OSError):
        body_byte.sendall(b"{")  # one body byte after the 401, the other nine never come
    socks["401-then-one-body-byte"] = body_byte
    started["401-then-one-body-byte"] = time.monotonic()

    partial = b"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Slow: abcdefghijklmnop"
    closed_after: dict[str, float] = {}
    sent = 0
    limit = HEADER_TIMEOUT + 2.0
    try:
        while len(closed_after) < len(socks) and time.monotonic() - min(started.values()) < limit + 2.0:
            if "dribble" not in closed_after and time.monotonic() - started["dribble"] >= sent:
                try:
                    socks["dribble"].send(partial[sent : sent + 1])
                    sent += 1
                except OSError:
                    pass  # the server closed it; noticed below
            for name, sock in socks.items():
                if name not in closed_after and _peer_closed(sock):
                    closed_after[name] = time.monotonic() - started[name]
            time.sleep(0.1)
    finally:
        for sock in socks.values():
            sock.close()

    assert set(closed_after) == set(socks), f"still open after {limit + 2.0}s: {set(socks) - set(closed_after)}"
    assert sent >= 2, "the dribbling client must have sent bytes before the deadline"
    for name, after in closed_after.items():
        assert after <= limit, f"{name} closed only after {after:.1f}s (deadline {HEADER_TIMEOUT}s)"


@POSIX_ONLY
def test_f13_a_401_ends_the_connection(listener: _Listener) -> None:
    """A 401 used to keep the connection alive and re-arm the header
    deadline, so a client without a token held its descriptor for as long
    as it sent one tiny request per deadline (review round 1: 0 of 11
    authenticated calls got through at a limit of 256)."""
    sock = _connect(listener.port)
    try:
        sock.sendall(b"GET /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        head = _read_until(sock, b"\r\n\r\n")
        assert head.startswith(b"HTTP/1.1 401 "), head[:200]
        assert b"connection: close" in head.lower(), head
        # closed with the response, long before the header deadline
        assert _peer_closed(sock, wait=HEADER_TIMEOUT / 2), "the 401 left the connection open"
    finally:
        sock.close()


@POSIX_ONLY
def test_f13_a_refused_request_with_a_large_body_still_gets_its_401(listener: _Listener) -> None:
    """Review round 2: a client with a wrong token that POSTs more than
    about 1 MB saw a reset or a broken pipe instead of the 401, because the
    connection was closed with its body still arriving."""
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {"pad": "x" * 4_000_000}})
    for _ in range(3):
        conn = http.client.HTTPConnection("127.0.0.1", listener.port, timeout=10)
        try:
            conn.request(
                "POST", "/mcp", body=body, headers={"Content-Type": "application/json", "Authorization": "Bearer wrong"}
            )
            response = conn.getresponse()
            response.read()
        finally:
            conn.close()
        assert response.status == 401


@POSIX_ONLY
def test_f13_a_refused_connection_is_drained_for_a_bounded_time(listener: _Listener) -> None:
    """A client that keeps sending after its refusal is closed once the
    drain time (never longer than the header deadline) is over."""
    from universal_db_mcp.http_protocol import LINGER_SECONDS

    sock = _connect(listener.port)
    closed_after = None
    try:
        sock.sendall(b"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 100000000\r\n\r\n")
        head = _read_until(sock, b"\r\n\r\n")
        assert head.startswith(b"HTTP/1.1 401 "), head[:200]
        started = time.monotonic()
        while time.monotonic() - started < HEADER_TIMEOUT + 3.0:
            try:
                sock.send(b"x" * 1024)
            except OSError:
                closed_after = time.monotonic() - started
                break
            time.sleep(0.05)
    finally:
        sock.close()
    assert closed_after is not None, "a refused client kept its connection by sending body bytes"
    assert closed_after <= min(LINGER_SECONDS, HEADER_TIMEOUT) + 1.0, closed_after


@POSIX_ONLY
def test_f13_idle_sockets_do_not_lock_out_authenticated_clients(listener: _Listener) -> None:
    _raise_own_fd_limit(1024)
    idle: list[socket.socket] = []
    try:
        for _ in range(200):  # more than the listener's 128 descriptors
            idle.append(_connect(listener.port))
        time.sleep(HEADER_TIMEOUT + 1.0)
        message = _list_connections(listener.port, listener.token, timeout=20)
        assert "result" in message and not message["result"].get("isError"), message
        assert "demo" in json.dumps(message["result"])
    finally:
        for sock in idle:
            sock.close()


@POSIX_ONLY
def test_f13_authenticated_requests_and_streams_outlive_the_header_deadline(listener: _Listener) -> None:
    port, token = listener.port, listener.token
    session = _session(port, token)

    # a standalone SSE stream stays open while its response is in flight
    stream = _connect(port)
    try:
        stream.sendall(
            (
                f"GET /mcp HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAccept: text/event-stream\r\n"
                f"Authorization: Bearer {token}\r\nmcp-session-id: {session}\r\n"
                "mcp-protocol-version: 2025-06-18\r\n\r\n"
            ).encode()
        )
        head = _read_until(stream, b"\r\n\r\n")
        assert b" 200 " in head.split(b"\r\n", 1)[0], head[:200]
        time.sleep(HEADER_TIMEOUT + 2.0)
        assert not _peer_closed(stream), "an authenticated SSE stream was cut off by the header deadline"
    finally:
        stream.close()

    # a request whose body arrives slower than the deadline is still served
    body = json.dumps(LIST_CONNECTIONS).encode()
    slow = _connect(port)
    try:
        slow.sendall(
            (
                f"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\n"
                f"Accept: application/json, text/event-stream\r\nAuthorization: Bearer {token}\r\n"
                f"mcp-session-id: {session}\r\nmcp-protocol-version: 2025-06-18\r\n"
                f"Content-Length: {len(body)}\r\n\r\n"
            ).encode()
        )
        third = len(body) // 3 + 1
        for i in range(3):
            time.sleep((HEADER_TIMEOUT + 1.0) / 3)
            slow.sendall(body[i * third : (i + 1) * third])
        reply = _read_until(slow, b'"demo"', timeout=10)
        assert b" 200 " in reply.split(b"\r\n", 1)[0], reply[:300]
        assert b'"demo"' in reply
    finally:
        slow.close()


def _fake_resource(monkeypatch: pytest.MonkeyPatch, soft: int, hard: int) -> list[tuple[int, int]]:
    import resource

    calls: list[tuple[int, int]] = []
    monkeypatch.setattr(resource, "getrlimit", lambda _which: (soft, hard))
    monkeypatch.setattr(resource, "setrlimit", lambda _which, limits: calls.append(tuple(limits)))
    return calls


@POSIX_ONLY
def test_f13_open_file_soft_limit_is_raised_to_the_hard_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    from universal_db_mcp import http_protocol

    monkeypatch.setattr(sys, "platform", "linux")  # macOS adds its own cap (next test)
    calls = _fake_resource(monkeypatch, 1024, 4096)
    http_protocol.raise_open_file_limit()
    assert calls == [(4096, 4096)]

    calls = _fake_resource(monkeypatch, 256, 1 << 20)
    http_protocol.raise_open_file_limit()
    assert calls == [(65536, 1 << 20)], "capped at 65536"

    calls = _fake_resource(monkeypatch, 100_000, 1 << 20)
    http_protocol.raise_open_file_limit()
    assert calls == [], "a higher soft limit is never lowered"


@POSIX_ONLY
def test_f13_macos_infinite_hard_limit_is_capped_at_maxfilesperproc(monkeypatch: pytest.MonkeyPatch) -> None:
    import resource

    from universal_db_mcp import http_protocol

    calls = _fake_resource(monkeypatch, 256, resource.RLIM_INFINITY)
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(http_protocol, "_darwin_max_files_per_process", lambda: 10240)
    http_protocol.raise_open_file_limit()
    assert calls == [(10240, resource.RLIM_INFINITY)]

    # a finite hard limit above kern.maxfilesperproc is capped too: macOS
    # refuses such a soft limit (EINVAL) and the soft limit would stay at 256
    calls = _fake_resource(monkeypatch, 256, 1 << 20)
    http_protocol.raise_open_file_limit()
    assert calls == [(10240, 1 << 20)]


@POSIX_ONLY
def test_f13_open_file_limit_failure_is_not_fatal(monkeypatch: pytest.MonkeyPatch) -> None:
    import resource

    from universal_db_mcp import http_protocol

    def refuse(_which: int, _limits: tuple[int, int]) -> None:
        raise ValueError("not allowed")

    monkeypatch.setattr(resource, "getrlimit", lambda _which: (256, 4096))
    monkeypatch.setattr(resource, "setrlimit", refuse)
    http_protocol.raise_open_file_limit()  # must not raise


def test_f13_service_definitions_raise_the_descriptor_limit() -> None:
    unit = SYSTEMD_UNIT.read_text(encoding="utf-8")
    assert re.search(r"^LimitNOFILE=65536$", unit, re.MULTILINE), "systemd unit must set LimitNOFILE=65536"

    plist = plistlib.loads(_XML_COMMENT.sub(b"", PLIST.read_bytes()))
    for key in ("SoftResourceLimits", "HardResourceLimits"):
        limits = plist.get(key)
        assert isinstance(limits, dict), f"plist must set {key}"
        assert limits.get("NumberOfFiles") == 65536, f"{key} NumberOfFiles must be 65536"

    service = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))["services"]["universal-db-mcp"]
    nofile = service.get("ulimits", {}).get("nofile")
    assert nofile == {"soft": 65536, "hard": 65536}, f"compose must set ulimits.nofile, got {nofile!r}"


# --------------------------------------------------------------------------
# F92: request head caps
# --------------------------------------------------------------------------


def _head(n_headers: int, value: bytes = b"v") -> bytes:
    lines = b"".join(b"X-Pad-%d: %s\r\n" % (i, value) for i in range(n_headers))
    return b"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\n" + lines


def test_f92_request_head_limits() -> None:
    from universal_db_mcp.http_protocol import MAX_HEADER_BYTES, MAX_HEADERS, request_head_too_large

    assert MAX_HEADERS == 100 and MAX_HEADER_BYTES == 16 * 1024
    # the count includes Host
    assert not request_head_too_large(_head(MAX_HEADERS - 1) + b"\r\n")
    assert request_head_too_large(_head(MAX_HEADERS) + b"\r\n")
    # an incomplete head is judged on what has arrived, never more strictly
    # than the same head once complete
    assert request_head_too_large(_head(MAX_HEADERS))
    assert not request_head_too_large(_head(MAX_HEADERS - 1))
    assert not request_head_too_large(_head(10))
    # bytes: one header larger than the cap, complete or not
    assert request_head_too_large(_head(1, b"a" * MAX_HEADER_BYTES) + b"\r\n")
    assert request_head_too_large(_head(1, b"a" * MAX_HEADER_BYTES))
    assert not request_head_too_large(_head(1, b"a" * (MAX_HEADER_BYTES - 200)) + b"\r\n")
    # a head of exactly MAX_HEADER_BYTES (up to its final line break) passes,
    # also while its final CRLF is still on the way
    at_cap = _head(0) + b"X-Pad: "
    at_cap += b"a" * (MAX_HEADER_BYTES - len(at_cap) - 1) + b"\r\n\r\n"
    assert not request_head_too_large(at_cap)
    assert not request_head_too_large(at_cap[:-1])
    assert request_head_too_large(at_cap[:-4] + b"a\r\n\r\n")
    # only the head counts: a large body or a pipelined request behind it does not
    assert not request_head_too_large(_head(5) + b"\r\n" + b"{" * 200_000)
    assert not request_head_too_large(_head(5) + b"\r\n" + _head(20_000) + b"\r\n")
    # bare LF line endings, which h11 also accepts
    assert request_head_too_large(_head(MAX_HEADERS).replace(b"\r\n", b"\n") + b"\n")


@POSIX_ONLY
def test_f92_oversized_header_block_is_refused_before_the_app(listener: _Listener) -> None:
    sock = _connect(listener.port)
    try:
        request = _head(1000) + b"Content-Length: 0\r\n\r\n"
        started = time.monotonic()
        sock.sendall(request)
        readable, _, _ = select.select([sock], [], [], 2.0)
        elapsed = time.monotonic() - started
        reply = sock.recv(65536) if readable else None
    finally:
        sock.close()
    assert reply is not None, "no answer to a 1,000-header request"
    # generous: the refusal itself is under a millisecond, but a loaded CI
    # runner schedules the listener process late
    assert elapsed < 1.0, f"took {elapsed * 1000:.0f} ms"
    assert reply == b"" or reply.startswith(b"HTTP/1.1 431 "), reply[:120]
    # and the listener still serves authenticated clients
    message = _list_connections(listener.port, listener.token)
    assert "result" in message and not message["result"].get("isError"), message


@POSIX_ONLY
def test_f92_oversized_head_arriving_in_pieces_is_refused(listener: _Listener) -> None:
    """1,000 headers are about 14 KiB, under h11's own 16 KiB limit for an
    incomplete head, so without the cap they reach the app piece by piece."""
    request = _head(1000) + b"Content-Length: 0\r\n\r\n"
    sock = _connect(listener.port)
    try:
        for start in range(0, len(request), 2048):
            try:
                sock.sendall(request[start : start + 2048])
            except OSError:
                break  # already refused and closed
            time.sleep(0.05)
        try:
            reply = _read_until(sock, b"\r\n", timeout=3)
        except ConnectionResetError:
            reply = b""  # closed with our later pieces unread
    finally:
        sock.close()
    assert reply == b"" or reply.startswith(b"HTTP/1.1 431 "), reply[:120]


@POSIX_ONLY
def test_f92_pipelined_oversized_head_is_refused(listener: _Listener) -> None:
    """A small request followed in the same write by an oversized one: the
    second head sits in h11's buffer and is parsed only after the first
    response, without passing through data_received again."""
    sock = _connect(listener.port)
    try:
        sock.sendall(b"GET /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n" + _head(1000) + b"Content-Length: 0\r\n\r\n")
        data = b""
        while not _peer_closed(sock, 0) and len(data) < 1 << 20:
            readable, _, _ = select.select([sock], [], [], 3.0)
            if not readable:
                break
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
    finally:
        sock.close()
    statuses = re.findall(rb"HTTP/1\.1 (\d{3}) ", data)
    assert statuses[:1] == [b"401"], data[:300]
    assert statuses[1:] in ([], [b"431"]), f"the oversized pipelined request reached the app: {statuses}"


# Review round 1: the head cap looked only at request heads. Chunked trailer
# fields (up to 20,000 in one read, ~16 ms of event loop each) and 40,000
# one-byte chunks (~90 ms) were still parsed before the bearer check ran in
# the app, and a 4-thread flood took authenticated round trips from 2.5 ms
# to 792 ms. The token is now checked on the request head itself.

_CHUNKED_HEAD = b"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\n\r\n"
_PRE_AUTH_BODIES = {
    "20k-trailer-fields": b"1\r\na\r\n0\r\n" + b"".join(b"X%d: v\r\n" % i for i in range(20_000)) + b"\r\n",
    "40k-one-byte-chunks": b"1\r\na\r\n" * 40_000 + b"0\r\n\r\n",
}
# (request head, what follows it) sent in one read, none with the token
_PRE_AUTH_REQUESTS = {
    **{name: (_CHUNKED_HEAD, body) for name, body in _PRE_AUTH_BODIES.items()},
    "wrong-token": (
        b"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer wrong\r\nContent-Length: 2\r\n\r\n",
        b"{}",
    ),
    "head-method": (b"HEAD /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", b""),
}


class _RecordingTransport(asyncio.Transport):
    """A transport that keeps what the protocol writes (no socket)."""

    def __init__(self) -> None:
        super().__init__()
        self.written = bytearray()
        self.eof_written = False
        self.closed = False

    def get_extra_info(self, name: str, default: Any = None) -> Any:
        return {"sockname": ("127.0.0.1", 8765), "peername": ("127.0.0.1", 50000)}.get(name, default)

    def write(self, data: bytes | bytearray | memoryview) -> None:
        self.written += data

    def can_write_eof(self) -> bool:
        return True

    def write_eof(self) -> None:
        self.eof_written = True

    def close(self) -> None:
        self.closed = True

    def is_closing(self) -> bool:
        return self.closed

    def pause_reading(self) -> None:
        pass

    def resume_reading(self) -> None:
        pass


@contextlib.contextmanager
def _guarded_protocol() -> Iterator[tuple[Any, _RecordingTransport]]:
    """A connected listener protocol (token 't' * 64) on a recording transport."""
    from uvicorn.config import Config
    from uvicorn.server import ServerState

    from universal_db_mcp.http_protocol import guarded_h11_protocol

    async def app(scope: Any, receive: Any, send: Any) -> None:  # pragma: no cover - must never run
        raise AssertionError("the app ran for an unauthenticated request")

    loop = asyncio.new_event_loop()
    protocol = guarded_h11_protocol(HEADER_TIMEOUT, b"t" * 64)(
        Config(app=app, log_config=None, lifespan="off"), ServerState(), {}, loop
    )
    transport = _RecordingTransport()
    try:
        protocol.connection_made(transport)
        yield protocol, transport
    finally:
        protocol.connection_lost(None)
        loop.close()


@pytest.mark.parametrize("request_name", list(_PRE_AUTH_REQUESTS), ids=list(_PRE_AUTH_REQUESTS))
def test_f92_an_unauthenticated_request_is_refused_before_its_body_is_parsed(request_name: str) -> None:
    import h11

    with _guarded_protocol() as (protocol, transport):
        head, rest = _PRE_AUTH_REQUESTS[request_name]
        protocol.data_received(head + rest)

        reply_head, _, reply_body = bytes(transport.written).partition(b"\r\n\r\n")
        assert reply_head.lower().startswith(b"http/1.1 401 "), bytes(transport.written)[:200]
        assert b"www-authenticate: bearer" in reply_head.lower() and b"connection: close" in reply_head.lower()
        assert (b"unauthorized" in reply_body) is (request_name != "head-method")
        # half-closed after the response; closed once what follows is drained
        assert transport.eof_written
        assert protocol.cycle is None and not protocol.tasks, "the request reached the ASGI app"
        if rest:
            # h11 stopped right after the head: the whole body is still unparsed
            assert protocol.conn.their_state is h11.SEND_BODY
            assert protocol.conn.trailing_data[0] == rest


def test_f13_a_refused_connection_is_drained_within_a_byte_budget() -> None:
    """Review round 2: closing right after the refusal, with request bytes
    still unread, made the kernel reset the connection, so a client still
    sending its body never read the 401. What follows a refusal is now read
    and discarded unparsed, up to LINGER_MAX_BYTES (and LINGER_SECONDS)."""
    from universal_db_mcp.http_protocol import LINGER_MAX_BYTES

    with _guarded_protocol() as (protocol, transport):
        protocol.data_received(b"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 100000000\r\n\r\n")
        assert bytes(transport.written).startswith(b"HTTP/1.1 401 ")
        assert transport.eof_written and not transport.closed
        answered = len(transport.written)
        received = 0
        while received + 65536 <= LINGER_MAX_BYTES:
            protocol.data_received(b"x" * 65536)
            received += 65536
        assert not transport.closed, "closed within the drain budget"
        assert len(transport.written) == answered and protocol.cycle is None, "the drained bytes were parsed"
        protocol.data_received(b"x" * (LINGER_MAX_BYTES - received + 1))
        assert transport.closed, "a refused client kept sending past the drain budget"


def _reference_head_too_large(pending: bytes) -> bool:
    """request_head_too_large as first written: one scan of the whole buffer."""
    from universal_db_mcp.http_protocol import MAX_HEADER_BYTES, MAX_HEADERS

    window = pending[: MAX_HEADER_BYTES + 4]
    end = re.search(rb"\n\r?\n", window)
    if end is not None:
        head = window[: end.start()]
        return len(head) > MAX_HEADER_BYTES or head.count(b"\n") > MAX_HEADERS
    return len(window) - 2 > MAX_HEADER_BYTES or window.count(b"\n") - 1 > MAX_HEADERS


def test_f92_the_incremental_head_check_matches_a_full_scan() -> None:
    import random

    from universal_db_mcp.http_protocol import MAX_HEADER_BYTES, MAX_HEADERS, _HeadScan

    at_cap = _head(0) + b"X-Pad: "
    at_cap += b"a" * (MAX_HEADER_BYTES - len(at_cap) - 1) + b"\r\n\r\n"
    heads = [
        _head(MAX_HEADERS - 1) + b"\r\n",
        _head(MAX_HEADERS) + b"\r\n",
        _head(MAX_HEADERS).replace(b"\r\n", b"\n") + b"\n",
        _head(1, b"a" * MAX_HEADER_BYTES) + b"\r\n",
        _head(1, b"a" * (MAX_HEADER_BYTES - 200)) + b"\r\n",
        at_cap,
        at_cap[:-4] + b"a\r\n\r\n",
        _head(5) + b"\r\n" + b"{" * 20_000,
        _head(5) + b"\r\n" + _head(2_000) + b"\r\n",
    ]
    rng = random.Random(2026_09_27)  # noqa: S311 - reproducible test input, not a secret
    # line breaks split at every possible point
    heads += [bytes(rng.choice(b"a\r\n") for _ in range(rng.randrange(1, 400))) for _ in range(300)]
    for head in heads:
        scan = _HeadScan()
        fed = 0
        while fed < len(head):
            step = rng.choice((1, 1, 2, 3, 5, 64, 1500, 20_000))
            scan.feed(head[fed : fed + step])
            fed += step
            prefix = head[:fed]
            assert scan.too_large is _reference_head_too_large(prefix), (len(head), fed)
            end = re.search(rb"\n\r?\n", prefix[: MAX_HEADER_BYTES + 4])
            assert scan.head_end == (end.start() if end else None), (head[:80], fed)


def test_f92_a_head_sent_one_byte_per_read_is_scanned_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """Review round 2: the head check copied h11's whole pending buffer and
    scanned it again on every read, so a head arriving one byte per read cost
    O(n^2) (93 ms against h11's own 8.6 ms for 15 KiB). It now reads what is
    buffered once per head and scans only the new bytes after that."""
    import h11

    copies: list[int] = []
    trailing_data = h11.Connection.trailing_data
    monkeypatch.setattr(
        h11.Connection, "trailing_data", property(lambda conn: copies.append(1) or trailing_data.fget(conn))
    )
    head = _head(90, b"v" * 150) + b"\r\n"  # 91 header lines, ~14.5 KiB: allowed
    with _guarded_protocol() as (protocol, transport):
        for i in range(len(head)):
            protocol.data_received(head[i : i + 1])
        assert bytes(transport.written).startswith(b"HTTP/1.1 401 "), "the complete head was parsed and refused"
    assert len(copies) <= 1, f"the pending head was copied {len(copies)} times"


@POSIX_ONLY
def test_f92_an_unauthenticated_trailer_flood_is_refused_and_closed(listener: _Listener) -> None:
    sock = _connect(listener.port)
    try:
        sock.sendall(_CHUNKED_HEAD + _PRE_AUTH_BODIES["20k-trailer-fields"])
        head = _read_until(sock, b"\r\n\r\n")
        assert head.startswith(b"HTTP/1.1 401 "), head[:200]
        assert b"connection: close" in head.lower(), head
        assert _peer_closed(sock, wait=HEADER_TIMEOUT / 2)
    finally:
        sock.close()
    message = _list_connections(listener.port, listener.token)
    assert "result" in message and not message["result"].get("isError"), message


# --------------------------------------------------------------------------
# F57: pre-auth warnings are rate limited and the logs are bounded
# --------------------------------------------------------------------------


@pytest.fixture
def restore_logging() -> Iterator[None]:
    names = [None, "uvicorn", "uvicorn.error", "uvicorn.access", "asyncio"]
    saved = []
    for name in names:
        logger = logging.getLogger(name)
        saved.append((logger, list(logger.handlers), list(logger.filters), logger.level, logger.propagate))
    try:
        yield
    finally:
        for logger, handlers, filters, level, propagate in saved:
            for handler in logger.handlers:
                if handler not in handlers:
                    handler.close()
            logger.handlers[:] = handlers
            logger.filters[:] = filters
            logger.setLevel(level)
            logger.propagate = propagate


def _record(name: str, msg: str) -> logging.LogRecord:
    return logging.LogRecord(name, logging.WARNING, __file__, 1, msg, None, None)


def test_f57_preauth_warning_filter_is_a_token_bucket_with_a_summary() -> None:
    from universal_db_mcp.http_protocol import PreAuthWarningFilter

    now = [1000.0]
    flt = PreAuthWarningFilter(burst=10, refill_seconds=6.0, clock=lambda: now[0])
    passed = []
    for i in range(1000):
        for msg in ("Unsupported upgrade request.", "Invalid HTTP request received."):
            record = _record("uvicorn.error", msg)
            if flt.filter(record):
                passed.append(record)
        if i == 500:
            record = _record("uvicorn.error", "Exception in ASGI application\n")
            assert flt.filter(record), "warnings that are not pre-auth noise are never suppressed"
    assert len(passed) == 10
    now[0] += 6.0
    summary = _record("uvicorn.error", "Unsupported upgrade request.")
    assert flt.filter(summary)
    assert "suppressed 1990 pre-auth protocol warnings" in summary.getMessage()
    # burst + 1 records in all; the count restarts after a summary
    follow = _record("uvicorn.error", "Unsupported upgrade request.")
    assert not flt.filter(follow)


def test_f57_filter_covers_every_preauth_message() -> None:
    from universal_db_mcp.http_protocol import PreAuthWarningFilter

    flt = PreAuthWarningFilter(burst=0, refill_seconds=60.0, clock=lambda: 0.0)
    for name, msg in [
        ("uvicorn.error", "Unsupported upgrade request."),
        ("uvicorn.error", "No supported WebSocket library detected. Please use ..."),
        ("uvicorn.error", "Invalid HTTP request received."),
        ("uvicorn.error", "Request header fields too large."),
        ("asyncio", "socket.accept() out of system resource\nsocket: <...>"),
    ]:
        assert not flt.filter(_record(name, msg)), msg


def test_f57_a_suppressed_burst_is_summarised_once_it_ends() -> None:
    """Review round 1: the count was logged only with the next admitted
    warning, which may come days after the flood."""
    from universal_db_mcp.http_protocol import PreAuthWarningFilter

    timers: list[tuple[float, Any]] = []
    flt = PreAuthWarningFilter(
        burst=2, refill_seconds=6.0, clock=lambda: 0.0, schedule=lambda delay, fn: timers.append((delay, fn))
    )
    logger = logging.getLogger("test.preauth")
    seen: list[str] = []
    handler = logging.Handler()
    handler.emit = lambda record: seen.append(record.getMessage())  # type: ignore[method-assign]
    logger.addHandler(handler)
    logger.addFilter(flt)
    try:
        for _ in range(50):
            logger.warning("Unsupported upgrade request.")
        assert len(seen) == 2
        assert [delay for delay, _fn in timers] == [6.0], "one timer for the burst"
        timers[0][1]()
        assert seen[2:] == ["suppressed 48 pre-auth protocol warnings"]
        timers[0][1]()  # nothing more was suppressed since
        assert len(seen) == 3
        logger.warning("Unsupported upgrade request.")  # suppressed again: a new timer
        assert len(timers) == 2
    finally:
        logger.removeHandler(handler)
        logger.removeFilter(flt)


def test_f57_http_logging_attaches_the_filter(restore_logging: None) -> None:
    from universal_db_mcp.http_protocol import PreAuthWarningFilter, configure_http_logging

    root_handlers = list(logging.getLogger().handlers)
    configure_http_logging({})
    uvicorn_error = logging.getLogger("uvicorn.error")
    asyncio_logger = logging.getLogger("asyncio")
    flt = [f for f in uvicorn_error.filters if isinstance(f, PreAuthWarningFilter)]
    assert len(flt) == 1
    assert flt[0] in asyncio_logger.filters, "one shared bucket for uvicorn and asyncio"
    assert logging.getLogger("uvicorn").handlers, "uvicorn keeps a handler"
    assert logging.getLogger().handlers == root_handlers, "without a log file the root handlers are untouched"


def test_f57_http_log_file_is_size_bounded(tmp_path: Path, restore_logging: None) -> None:
    from logging.handlers import RotatingFileHandler

    from universal_db_mcp.http_protocol import LOG_FILE_ENV, LOG_FILE_MAX_BYTES, configure_http_logging

    target = tmp_path / "http.log"
    configure_http_logging({LOG_FILE_ENV: str(target)})
    for logger in (logging.getLogger("uvicorn"), logging.getLogger()):
        handlers = [h for h in logger.handlers if isinstance(h, RotatingFileHandler)]
        assert len(handlers) == 1, logger.name
        assert handlers[0].baseFilename == str(target)
        assert 0 < handlers[0].maxBytes == LOG_FILE_MAX_BYTES and handlers[0].backupCount > 0
    logging.getLogger("uvicorn.error").warning("Invalid HTTP request received.")
    assert "Invalid HTTP request received." in target.read_text(encoding="utf-8")


def test_f57_unusable_log_file_is_reported(tmp_path: Path, restore_logging: None) -> None:
    from universal_db_mcp.http_protocol import LOG_FILE_ENV, configure_http_logging

    target = tmp_path / "missing-dir" / "http.log"
    with pytest.raises(ValueError, match=rf"{LOG_FILE_ENV}=.*No such file or directory"):
        configure_http_logging({LOG_FILE_ENV: str(target)})


def test_f57_launchd_and_compose_logs_are_bounded() -> None:
    from universal_db_mcp.http_protocol import LOG_FILE_ENV, LOG_FILE_MAX_BYTES

    plist = plistlib.loads(_XML_COMMENT.sub(b"", PLIST.read_bytes()))
    log_file = plist["EnvironmentVariables"].get(LOG_FILE_ENV)
    assert isinstance(log_file, str) and log_file.startswith("/var/log/universal-db-mcp/"), log_file
    # rotated by the server itself (no root job rotates that directory:
    # test_hardening_2026_09_29_root_jobs)
    assert 0 < LOG_FILE_MAX_BYTES

    service = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))["services"]["universal-db-mcp"]
    logging_cfg = service.get("logging") or {}
    driver = logging_cfg.get("driver")
    options = logging_cfg.get("options") or {}
    assert driver == "local" or (driver == "json-file" and options.get("max-size") and options.get("max-file")), (
        f"compose logging must be bounded, got {logging_cfg!r}"
    )


@POSIX_ONLY
def test_f57_unauthenticated_upgrade_flood_does_not_flood_stderr(listener: _Listener) -> None:
    before = listener.stderr.stat().st_size
    conn = http.client.HTTPConnection("127.0.0.1", listener.port, timeout=10)
    statuses: set[int] = set()
    try:
        for _ in range(500):
            conn.request("GET", "/mcp", headers={"Connection": "Upgrade", "Upgrade": "websocket"})
            response = conn.getresponse()
            response.read()
            statuses.add(response.status)
    finally:
        conn.close()
    invalid: set[bytes] = set()
    for _ in range(20):
        sock = _connect(listener.port)
        try:
            sock.sendall(b"NOT HTTP AT ALL\r\n\r\n")
            invalid.add(_read_until(sock, b"\r\n").split(b" ", 2)[1])
        finally:
            sock.close()
    time.sleep(0.5)
    grown = listener.stderr.stat().st_size - before
    assert statuses == {401}
    assert invalid == {b"400"}
    assert grown < 64 * 1024, f"stderr grew {grown} bytes for 520 unauthenticated requests"
    status, _, _ = _mcp_post(listener.port, listener.token, INITIALIZE)
    assert status == 200


@POSIX_ONLY
def test_f57_the_listener_rate_limits_an_invalid_request_flood(listener: _Listener) -> None:
    """Review round 2: the upgrade flood above is answered 401 before uvicorn
    logs anything, so with the configure_http_logging call removed from
    _serve_http every other F57 test still passed while the listener logged
    each invalid request (263.7 KiB/s). 2,000 invalid requests reach
    uvicorn's own warning; only the filter keeps them to a burst and a
    'suppressed N' summary."""
    before = listener.stderr.stat().st_size
    for _ in range(2000):
        sock = _connect(listener.port)
        try:
            sock.sendall(b"\x00BOGUS\r\n\r\n")
            _read_until(sock, b"\r\n")
        finally:
            sock.close()
    # the summary comes with the next admitted warning, or from the timer one
    # refill interval (6 s) after the first dropped one
    deadline = time.monotonic() + 10.0
    while True:
        with listener.stderr.open("rb") as fh:
            fh.seek(before)
            grown = fh.read()
        if re.search(rb"suppressed \d+ pre-auth protocol warnings", grown) or time.monotonic() > deadline:
            break
        time.sleep(0.25)
    assert len(grown) < 16 * 1024, f"stderr grew {len(grown)} bytes for 2,000 invalid requests"
    assert re.search(rb"suppressed \d+ pre-auth protocol warnings", grown), grown[-2000:]


@POSIX_ONLY
def test_f57_serve_http_applies_the_bounded_logging_before_uvicorn_starts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import uvicorn

    from universal_db_mcp import http_protocol
    from universal_db_mcp.__main__ import _serve_http

    calls: list[tuple[str, Any]] = []
    monkeypatch.setattr(http_protocol, "configure_http_logging", lambda env: calls.append(("logging", env)))
    monkeypatch.setattr(http_protocol, "raise_open_file_limit", lambda: None)
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: calls.append(("uvicorn.run", kw["log_config"])))
    assert _serve_http(_token_config(tmp_path, secrets.token_hex(32).encode()), _FakeServer()) == 0
    assert [name for name, _ in calls] == ["logging", "uvicorn.run"]
    assert calls[0][1] is os.environ, "UDBMCP_HTTP_LOG_FILE is read from the service environment"
    assert calls[1][1] is None, "uvicorn must not replace the configured logging"


# --------------------------------------------------------------------------
# F69: bearer token file
# --------------------------------------------------------------------------


class _FakeServer:
    def streamable_http_app(self, host: str) -> Any:
        async def app(scope: Any, receive: Any, send: Any) -> None:  # pragma: no cover - never served
            return None

        return app


@pytest.fixture
def stub_listener(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    import uvicorn

    from universal_db_mcp import http_protocol

    ran: dict[str, Any] = {}
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: ran.update(kw))
    monkeypatch.setattr(http_protocol, "configure_http_logging", lambda env: None)
    monkeypatch.setattr(http_protocol, "raise_open_file_limit", lambda: None)
    return ran


def _token_config(tmp_path: Path, content: bytes) -> Any:
    from universal_db_mcp.config import AppConfig

    token = tmp_path / "http-token"
    token.write_bytes(content)
    token.chmod(0o600)
    return AppConfig(application={"transport": "http", "http_bearer_token_file": str(token)})


@POSIX_ONLY
@pytest.mark.parametrize("content", [b"\xff\xfe\x00tok", b"x\n", b"a" * 31 + b"\n"])
def test_f69_bad_token_files_are_config_errors(
    tmp_path: Path, content: bytes, stub_listener: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    from universal_db_mcp.__main__ import _serve_http

    assert _serve_http(_token_config(tmp_path, content), _FakeServer()) == 1
    err = capsys.readouterr().err
    assert "CONFIG_ERROR" in err and "Traceback" not in err
    assert stub_listener == {}, "the listener must not start"


@POSIX_ONLY
def test_f69_an_unsafe_token_file_error_has_one_prefix(
    tmp_path: Path, stub_listener: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    from universal_db_mcp.__main__ import _serve_http

    cfg = _token_config(tmp_path, secrets.token_hex(32).encode())
    (tmp_path / "http-token").chmod(0o644)
    assert _serve_http(cfg, _FakeServer()) == 1
    err = capsys.readouterr().err
    assert "unsafe permissions" in err and err.count("CONFIG_ERROR") == 1, err
    assert stub_listener == {}


@POSIX_ONLY
def test_f69_short_token_error_names_the_generate_command(
    tmp_path: Path, stub_listener: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    from universal_db_mcp.__main__ import _serve_http

    assert _serve_http(_token_config(tmp_path, b"x\n"), _FakeServer()) == 1
    err = capsys.readouterr().err
    assert "at least 32" in err and "secrets.token_hex(32)" in err


@POSIX_ONLY
def test_f69_generated_token_starts_the_guarded_listener(
    tmp_path: Path, stub_listener: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    from universal_db_mcp.__main__ import _serve_http
    from universal_db_mcp.http_protocol import GuardedH11Protocol

    assert _serve_http(_token_config(tmp_path, secrets.token_hex(32).encode() + b"\n"), _FakeServer()) == 0
    assert issubclass(stub_listener["http"], GuardedH11Protocol)
    assert stub_listener["log_config"] is None, "logging is configured before uvicorn starts"
    assert "CONFIG_ERROR" not in capsys.readouterr().err


@POSIX_ONLY
def test_f69_a_byte_order_mark_is_not_part_of_the_token(
    tmp_path: Path, stub_listener: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    """A token file saved by Notepad starts with a BOM, which no client
    sends: every request was answered 401."""
    from universal_db_mcp.__main__ import _serve_http

    token = secrets.token_hex(32)
    content = b"\xef\xbb\xbf" + token.encode() + b"\r\n"
    assert _serve_http(_token_config(tmp_path, content), _FakeServer()) == 0, capsys.readouterr().err
    # the listener checks the token on the request head (F92)
    assert stub_listener["http"].bearer_token == token.encode()


def test_f13_header_timeout_default_and_override() -> None:
    from universal_db_mcp.http_protocol import DEFAULT_HEADER_TIMEOUT, HEADER_TIMEOUT_ENV, header_timeout_from_env

    assert DEFAULT_HEADER_TIMEOUT == 10.0
    assert header_timeout_from_env({}) == DEFAULT_HEADER_TIMEOUT
    assert header_timeout_from_env({HEADER_TIMEOUT_ENV: " "}) == DEFAULT_HEADER_TIMEOUT
    assert header_timeout_from_env({HEADER_TIMEOUT_ENV: "2.5"}) == 2.5


@POSIX_ONLY
@pytest.mark.parametrize("value", ["0", "-1", "soon", "nan", "inf"])
def test_f13_invalid_header_timeout_override_is_a_config_error(
    tmp_path: Path,
    value: str,
    stub_listener: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from universal_db_mcp.__main__ import _serve_http

    monkeypatch.setenv("UDBMCP_HTTP_HEADER_TIMEOUT", value)
    assert _serve_http(_token_config(tmp_path, secrets.token_hex(32).encode()), _FakeServer()) == 1
    assert "UDBMCP_HTTP_HEADER_TIMEOUT" in capsys.readouterr().err
    assert stub_listener == {}


# --------------------------------------------------------------------------
# F86: SIGTERM in stdio mode
# --------------------------------------------------------------------------


@POSIX_ONLY
def test_f86_sigterm_during_a_stdio_query_writes_the_cancelled_audit_record(tmp_path: Path) -> None:
    db = _sqlite_db(tmp_path / "a.db")
    audit = tmp_path / "audit.jsonl"
    config = tmp_path / "config.yaml"
    config.write_text(
        "application:\n"
        "  transport: stdio\n"
        f"  audit_path: {audit}\n"
        f"  metadata_cache_path: {tmp_path / 'cache.sqlite'}\n"
        "connections:\n"
        "  a:\n"
        "    type: sqlite\n"
        f"    database: {db}\n",
        encoding="utf-8",
    )
    proc = subprocess.Popen(  # noqa: S603 - fixed argv, the interpreter running the tests
        [sys.executable, "-m", "universal_db_mcp", "serve", "--config", str(config)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        cwd=tmp_path,
    )
    assert proc.stdin is not None and proc.stdout is not None

    def send(message: dict[str, Any]) -> None:
        assert proc.stdin is not None
        proc.stdin.write((json.dumps(message) + "\n").encode())
        proc.stdin.flush()

    try:
        send(INITIALIZE)
        assert b'"result"' in proc.stdout.readline()
        send(INITIALIZED)
        slow = (
            "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 400000000) "
            "SELECT count(*) FROM c, t"
        )
        send(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "db_query", "arguments": {"connection_id": "a", "sql": slow}},
            }
        )
        time.sleep(1.0)
        started = time.monotonic()
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pytest.fail("the stdio server did not exit within 5 s of SIGTERM")
        assert time.monotonic() - started < 5
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=10)
        proc.stdin.close()
        proc.stdout.close()
    records = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines()] if audit.exists() else []
    outcomes = [(r.get("action"), r.get("outcome")) for r in records]
    assert ("db_query", "cancelled") in outcomes, outcomes


# ==========================================================================
# Part 2: the add-connection wizard, site-check --out, onboarding notices
# ==========================================================================

FIN_CONFIG = """\
# site config header (the wizard keeps it)
application:
  transport: stdio
  audit_path: {d}/audit.jsonl
  metadata_cache_path: {d}/metadata.sqlite
security:
  require_remote_tls: true
connections:
  fin:
    type: postgres
    host: db.internal
    port: 5432
    database: fin
    username_file: {d}/secrets/fin.username
    password_file: {d}/secrets/fin.password
    tls:
      enabled: true
      verify_server: true
      ca_file: {d}/ca.pem
      client_cert_file: {d}/client.crt
      client_key_file: {d}/client.key
    allowed_schemas: [reporting]
    connect_timeout_seconds: 5
    options:
      krbsrvname: postgres
    session:
      application_name: udbmcp-fin
      lock_timeout_seconds: 1
"""

HAND_WRITTEN_FIELDS = {
    "allowed_schemas",
    "connect_timeout_seconds",
    "options",
    "session",
    "tls.client_cert_file",
    "tls.client_key_file",
}


@dataclass
class _Site:
    config: Path
    secrets: Path
    ca: Path
    new_password: Path

    def snapshot(self) -> dict[str, bytes]:
        """Every file in the config and secrets directories (dotfiles, .bak and
        .tmp included), by name."""
        files: dict[str, bytes] = {}
        for directory in (self.config.parent, self.secrets):
            for path in directory.iterdir():
                if path.is_file():
                    files[str(path.relative_to(self.config.parent))] = path.read_bytes()
        return files


def _private(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    path.chmod(0o600)
    return path


@pytest.fixture
def site(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> _Site:
    """A hand-restricted connection 'fin' (allowlist, session, options,
    timeout, client certificate) whose secrets say svc_ro / OLD-pass."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("UDBMCP_CONFIG", raising=False)
    d = tmp_path / "site"
    secrets_dir = d / "secrets"
    secrets_dir.mkdir(parents=True, mode=0o700)
    _private(secrets_dir / "fin.username", "svc_ro\n")
    _private(secrets_dir / "fin.password", "OLD-pass\n")
    ca = d / "ca.pem"
    ca.write_text("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n", encoding="utf-8")
    (d / "client.crt").write_text("cert\n", encoding="utf-8")
    _private(d / "client.key", "key\n")
    config = _private(d / "config.yaml", FIN_CONFIG.format(d=d))
    return _Site(config, secrets_dir, ca, _private(tmp_path / "new-password", "NEW-pass\n"))


def _add_args(site: _Site, *switches: str, drop: tuple[str, ...] = (), **flags: str) -> list[str]:
    """``add-connection --json --no-test`` re-adding 'fin' with every flag
    (a password rotation); keyword flags override, ``drop`` removes."""
    values = {
        "--config": str(site.config),
        "--name": "fin",
        "--engine": "postgres",
        "--host": "db.internal",
        "--port": "5432",
        "--database": "fin",
        "--username": "svc_ro",
        "--password-file": str(site.new_password),
        "--tls-ca-file": str(site.ca),
    }
    values.update({f"--{key.replace('_', '-')}": value for key, value in flags.items()})
    args = ["add-connection", "--json", "--no-test", *switches]
    for flag, value in values.items():
        if flag not in drop:
            args += [flag, value]
    return args


class _Tty:
    """stdin for the interactive wizard; answers come through input()."""

    def isatty(self) -> bool:
        return True


def _scripted_input(monkeypatch: pytest.MonkeyPatch, answers: list[str], *, interrupt_at: str = "") -> list[str]:
    prompts: list[str] = []
    pending = iter(answers)

    def fake_input(prompt: str = "") -> str:
        prompts.append(prompt)
        if interrupt_at and prompt.startswith(interrupt_at):
            raise KeyboardInterrupt
        return next(pending)

    monkeypatch.setattr(builtins, "input", fake_input)
    monkeypatch.setattr(wizard.getpass, "getpass", lambda prompt="": "NEW-pass")
    monkeypatch.setattr(sys, "stdin", _Tty())
    return prompts


def _interactive_fin_answers(site: _Site) -> list[str]:
    # engine, name, host, port, database, username, TLS, CA file, test
    return ["2", "fin", "db.internal", "5432", "fin", "svc_ro", "y", str(site.ca), "n"]


def _tmp_leftovers(*directories: Path) -> list[str]:
    return [name for d in directories if d.is_dir() for name in os.listdir(d) if name.endswith(".tmp")]


# --- F43: re-adding a connection updates it in place ------------------------


def test_f43_re_adding_a_connection_keeps_its_hand_written_settings(
    site: _Site, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = main(_add_args(site))
    captured = capsys.readouterr()
    assert rc == 0, captured.err
    result = json.loads(captured.out)

    cfg, resolved = load_resolved(site.config)
    fin = cfg.connections["fin"]
    assert fin.allowed_schemas == ["reporting"]
    assert fin.session.application_name == "udbmcp-fin"
    assert fin.session.lock_timeout_seconds == 1
    assert fin.options == {"krbsrvname": "postgres"}
    assert fin.connect_timeout_seconds == 5
    assert fin.tls.client_cert_file == str(site.config.parent / "client.crt")
    assert fin.tls.client_key_file == str(site.config.parent / "client.key")
    password = resolved["fin"].password
    assert password is not None and password.value == "NEW-pass"
    assert EffectivePolicy.build(cfg.security, resolved["fin"]).schema_allowed("hr") is False

    assert result["replaced"] is True
    assert HAND_WRITTEN_FIELDS <= set(result["preserved_fields"])
    assert result["dropped_fields"] == []


def test_f43_an_engine_change_needs_replace_and_writes_nothing(site: _Site, capsys: pytest.CaptureFixture[str]) -> None:
    before = site.snapshot()
    rc = main(_add_args(site, engine="mysql", port="3306"))
    err = capsys.readouterr().err
    assert rc != 0
    assert "--replace" in err
    assert site.snapshot() == before, "a refused engine change must not write the config, a .bak or a secret"


def test_f43_replace_lists_what_it_drops(site: _Site, capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(_add_args(site, "--replace", engine="mysql", port="3306"))
    captured = capsys.readouterr()
    assert rc == 0, captured.err
    result = json.loads(captured.out)
    assert HAND_WRITTEN_FIELDS <= set(result["dropped_fields"])
    assert result["preserved_fields"] == []
    assert load_config(site.config).connections["fin"].type == "mysql"


def test_f43_interactive_update_declined_leaves_everything_untouched(
    site: _Site, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    before = site.snapshot()
    prompts = _scripted_input(monkeypatch, [*_interactive_fin_answers(site), "n"])
    rc = main(["add-connection", "--config", str(site.config)])
    out = capsys.readouterr().out
    assert rc != 0
    assert site.snapshot() == before
    assert "allowed_schemas" in out, "the kept fields are shown before the question"
    assert prompts[-1].rstrip().endswith("[y/N]:"), prompts[-1]


def test_f43_interactive_update_accepted_keeps_the_hand_written_settings(
    site: _Site, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _scripted_input(monkeypatch, [*_interactive_fin_answers(site), "y"])
    rc = main(["add-connection", "--config", str(site.config)])
    out = capsys.readouterr().out
    assert rc == 0, out
    fin = load_config(site.config).connections["fin"]
    assert fin.allowed_schemas == ["reporting"]
    assert (site.secrets / "fin.password").read_text(encoding="utf-8") == "NEW-pass\n"


def test_f43_a_config_load_config_refuses_is_never_rewritten(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A repeated top-level key: yaml.safe_load keeps the last one, so a
    rewrite would silently change the policy the server refuses to load."""
    config = tmp_path / "config.yaml"
    config.write_text(
        f"application:\n  transport: stdio\n  audit_path: {tmp_path}/audit.jsonl\n"
        "security:\n  require_remote_tls: true\n"
        "security:\n  require_remote_tls: false\n",
        encoding="utf-8",
    )
    before = config.read_bytes()
    db = _sqlite_db(tmp_path / "a.db")
    rc = main(
        ["add-connection", "--json", "--no-test", "--config", str(config), "--name", "s1",
         "--engine", "sqlite", "--database", str(db)]
    )  # fmt: skip
    err = capsys.readouterr().err
    assert rc != 0
    assert "refusing to edit" in err and "security" in err, err
    assert err.count("CONFIG_ERROR") == 1, f"the error prefix is repeated: {err}"
    assert config.read_bytes() == before
    assert sorted(p.name for p in tmp_path.iterdir()) == ["a.db", "config.yaml"], "no .bak, no secrets, no temp file"


def test_f43_turning_tls_off_is_a_warning(site: _Site, capsys: pytest.CaptureFixture[str]) -> None:
    """Review round 1: a password rotation without --tls-ca-file turned TLS
    off (and dropped the client certificate) with no warning."""
    rc = main(_add_args(site, drop=("--tls-ca-file",)))
    captured = capsys.readouterr()
    assert rc == 0, captured.err
    result = json.loads(captured.out)
    assert any("TLS" in w and "turned off" in w and "--tls-ca-file" in w for w in result["warnings"]), result
    assert load_config(site.config).connections["fin"].tls.enabled is False

    rc = main(_add_args(site))  # TLS back on: nothing to warn about
    result = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert not any("turned off" in w for w in result["warnings"]), result


def test_f43_an_empty_schema_allowlist_is_a_warning(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    config = tmp_path / "config.yaml"
    config.write_text(f"application:\n  transport: stdio\n  audit_path: {tmp_path}/audit.jsonl\n", encoding="utf-8")
    db = _sqlite_db(tmp_path / "a.db")
    base = ["add-connection", "--no-test", "--config", str(config), "--engine", "sqlite", "--database", str(db)]

    assert main([*base, "--name", "a"]) == 0
    out = capsys.readouterr().out
    assert re.search(r"WARNING: .*allowed_schemas", out), out

    assert main([*base, "--json", "--name", "b"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert any("allowed_schemas" in w for w in result["warnings"]), result


def _custom_port(site: _Site) -> None:
    site.config.write_text(site.config.read_text(encoding="utf-8").replace("port: 5432", "port: 5433"))


def test_f43_a_re_add_without_a_port_keeps_the_existing_one(site: _Site, capsys: pytest.CaptureFixture[str]) -> None:
    """Review round 2: a password rotation that left out the optional
    --port moved the connection from its custom port to the engine default,
    shown only as dropped_fields ['port']."""
    _custom_port(site)
    rc = main(_add_args(site, drop=("--port",)))
    captured = capsys.readouterr()
    assert rc == 0, captured.err
    result = json.loads(captured.out)
    assert load_config(site.config).connections["fin"].port == 5433
    assert "port" in result["preserved_fields"] and "port" not in result["dropped_fields"]
    assert result["changed_fields"] == []


def test_f43_a_changed_managed_value_is_shown_before_and_after(
    site: _Site, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = main(_add_args(site, host="db2.internal"))
    captured = capsys.readouterr()
    assert rc == 0, captured.err
    assert json.loads(captured.out)["changed_fields"] == ["host"]

    # engine, name, host, port, database, username, TLS, CA file, test, then: update?
    answers = ["2", "fin", "db3.internal", "5433", "fin", "svc_ro", "y", str(site.ca), "n", "y"]
    _scripted_input(monkeypatch, answers)
    assert main(["add-connection", "--config", str(site.config)]) == 0
    out = capsys.readouterr().out
    confirmation = out[: out.index("==> updated")]
    assert "host: 'db2.internal' -> 'db3.internal'" in confirmation, out
    assert "port: 5432 -> 5433" in confirmation, out
    assert "changed: host, port" in out[out.index("==> updated") :], out


def test_f43_the_interactive_wizard_offers_the_existing_values(
    site: _Site, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Review round 2: the prompts offered the engine defaults, so pressing
    Enter through a password rotation moved the connection to 127.0.0.1 and
    the default port."""
    _custom_port(site)
    # engine, name, then Enter for host, port and database; username;
    # Enter for TLS and the CA file; no test; update
    answers = ["2", "fin", "", "", "", "svc_ro", "", "", "n", "y"]
    prompts = _scripted_input(monkeypatch, answers)
    rc = main(["add-connection", "--config", str(site.config)])
    out = capsys.readouterr().out
    assert rc == 0, out
    fin = load_config(site.config).connections["fin"]
    assert (fin.host, fin.port, fin.database) == ("db.internal", 5433, "fin")
    assert fin.tls.enabled and fin.tls.ca_file == str(site.ca)
    assert "Port [5433]: " in prompts, prompts
    assert (site.secrets / "fin.password").read_text(encoding="utf-8") == "NEW-pass\n"


# --- F44: credentials are staged and committed with the config --------------


@pytest.mark.parametrize("failure", ["no-host", "port-zero"])
def test_f44_a_failed_re_add_leaves_the_existing_secret_files(
    site: _Site, capsys: pytest.CaptureFixture[str], failure: str
) -> None:
    before = site.snapshot()
    args = _add_args(site, drop=("--host",)) if failure == "no-host" else _add_args(site, port="0")
    rc = main(args)
    err = capsys.readouterr().err
    assert rc != 0
    assert "CONFIG_ERROR" in err
    assert site.snapshot() == before, "the old connection would log in with the new account after a restart"


def test_f44_a_password_file_that_is_not_utf8_is_a_config_error(
    site: _Site, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Review round 2: a Latin-1 password file ended in a raw traceback
    whose codec message quoted a byte of the password and its position."""
    password = tmp_path / "latin1-password"
    password.write_bytes(b"S\xe9cret\n")
    password.chmod(0o600)
    before = site.snapshot()
    rc = main(_add_args(site, password_file=str(password)))
    err = capsys.readouterr().err
    assert rc == 1
    assert f"CONFIG_ERROR: password file {password} is not UTF-8 text" in err, err
    assert "Traceback" not in err and "0xe9" not in err and "position" not in err, err
    assert site.snapshot() == before


def test_f44_an_interactive_abort_leaves_the_existing_secret_files(
    site: _Site, monkeypatch: pytest.MonkeyPatch
) -> None:
    before = site.snapshot()
    _scripted_input(monkeypatch, _interactive_fin_answers(site), interrupt_at="Use TLS for this connection?")
    with pytest.raises(KeyboardInterrupt):
        main(["add-connection", "--config", str(site.config)])
    assert site.snapshot() == before


def test_f44_a_name_differing_only_in_case_is_refused(site: _Site, capsys: pytest.CaptureFixture[str]) -> None:
    before = site.snapshot()
    rc = main(_add_args(site, name="FIN", username="dba_admin"))
    err = capsys.readouterr().err
    assert rc != 0
    assert "CONFIG_ERROR" in err and "case" in err
    assert "FIN" not in load_config(site.config).connections
    assert site.snapshot() == before


def test_f44_a_secret_file_differing_only_in_case_is_refused(site: _Site, capsys: pytest.CaptureFixture[str]) -> None:
    _private(site.secrets / "prod.username", "left_over\n")
    before = site.snapshot()
    rc = main(_add_args(site, name="PROD", username="dba_admin"))
    err = capsys.readouterr().err
    assert rc != 0
    assert "CONFIG_ERROR" in err and "prod.username" in err
    assert "PROD" not in load_config(site.config).connections
    assert site.snapshot() == before


def test_f44_a_re_add_without_a_password_retires_the_old_password_file(
    site: _Site, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = main(_add_args(site, password_file=str(_private(tmp_path / "no-password", "\n"))))
    captured = capsys.readouterr()
    assert rc == 0, captured.err
    assert "password_file" not in yaml.safe_load(site.config.read_text(encoding="utf-8"))["connections"]["fin"]
    assert not (site.secrets / "fin.password").exists()
    assert [p.read_text(encoding="utf-8") for p in site.secrets.glob("fin.password.bak.*")] == ["OLD-pass\n"]
    assert "password_file" in json.loads(captured.out)["dropped_fields"]


@POSIX_ONLY
@pytest.mark.parametrize("link", ["symlink", "hardlink"])
def test_f44_a_linked_secret_file_is_never_replaced(
    site: _Site, tmp_path: Path, capsys: pytest.CaptureFixture[str], link: str
) -> None:
    other = _private(tmp_path / "other-file", "OTHER\n")
    password = site.secrets / "fin.password"
    password.unlink()
    if link == "symlink":
        password.symlink_to(other)
    else:
        os.link(other, password)
    username = (site.secrets / "fin.username").read_bytes()
    config = site.config.read_bytes()

    rc = main(_add_args(site))
    err = capsys.readouterr().err
    assert rc != 0
    assert "CONFIG_ERROR" in err and "link" in err, err
    assert other.read_text(encoding="utf-8") == "OTHER\n"
    assert (site.secrets / "fin.username").read_bytes() == username, "the committed username went back"
    assert site.config.read_bytes() == config
    assert not _tmp_leftovers(site.secrets, site.config.parent)


@POSIX_ONLY
def test_f44_a_symlinked_secrets_directory_is_refused(tmp_path: Path) -> None:
    config = tmp_path / "config.yaml"
    config.write_text("application:\n  transport: stdio\n", encoding="utf-8")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir(mode=0o755)
    (tmp_path / "secrets").symlink_to(elsewhere)
    with pytest.raises(wizard.WizardError, match="link"):
        wizard.store_credentials(config, "fin", "svc", "pw")
    assert list(elsewhere.iterdir()) == []
    assert stat.S_IMODE(elsewhere.stat().st_mode) == 0o755


@POSIX_ONLY
@pytest.mark.parametrize("renameat", [True, False], ids=["renameat", "no-renameat"])
def test_f47_secrets_go_into_the_directory_that_was_checked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, renameat: bool
) -> None:
    """Review round 1: the secrets directory was checked with lstat, then
    chmodded and written through its path, so an account that can write the
    config directory could swap in a symlink after the check (root runs the
    wizard on that account's per-user config) and root wrote there.

    Review round 2: the renames still went through the path, because the
    wizard looked for renameat under ``os.replace`` in ``os.supports_dir_fd``,
    where CPython lists it only as ``os.rename``; a swap right after the
    inode check made the first rename follow the symlink."""
    config = tmp_path / "config.yaml"
    config.write_text("application:\n  transport: stdio\n", encoding="utf-8")
    victim = tmp_path / "victim"
    victim.mkdir(mode=0o755)
    real_prepare = wizard._prepare_secrets_dir

    def prepare_then_swap(sdir: Path, owner: tuple[int, int] | None) -> Any:
        prepared = real_prepare(sdir, owner)
        sdir.rename(tmp_path / "checked")
        sdir.symlink_to(victim)
        return prepared

    monkeypatch.setattr(wizard, "_prepare_secrets_dir", prepare_then_swap)
    if renameat:
        # Linux and macOS both have renameat: every rename goes through the
        # checked directory's descriptor, and the swap changes nothing
        assert os.rename in os.supports_dir_fd
        wizard.store_credentials(config, "fin", "svc", "pw")
        assert sorted(os.listdir(tmp_path / "checked")) == ["fin.password", "fin.username"]
    else:
        # a platform without renameat: the swap is noticed before the first
        # rename, and the staged files are removed through the descriptor
        monkeypatch.setattr(os, "supports_dir_fd", os.supports_dir_fd - {os.rename})
        with pytest.raises(wizard.WizardError, match="was replaced"):
            wizard.store_credentials(config, "fin", "svc", "pw")
        assert os.listdir(tmp_path / "checked") == []
    assert list(victim.iterdir()) == []
    assert stat.S_IMODE(victim.stat().st_mode) == 0o755


def test_f43_file_credentials_take_the_place_of_environment_ones(
    site: _Site, capsys: pytest.CaptureFixture[str]
) -> None:
    text = site.config.read_text(encoding="utf-8")
    text = re.sub(r"    username_file: .*\n    password_file: .*\n", "    username_env: U\n    password_env: P\n", text)
    site.config.write_text(text, encoding="utf-8")
    rc = main(_add_args(site))
    captured = capsys.readouterr()
    assert rc == 0, captured.err
    block = yaml.safe_load(site.config.read_text(encoding="utf-8"))["connections"]["fin"]
    assert "username_env" not in block and "password_env" not in block
    assert block["password_file"] == str(site.secrets / "fin.password")
    result = json.loads(captured.out)
    assert {"username_env", "password_env"} <= set(result["dropped_fields"])
    assert HAND_WRITTEN_FIELDS <= set(result["preserved_fields"])


# --- F47: as root, the secrets belong to the service account ----------------


def _record_chowns(monkeypatch: pytest.MonkeyPatch) -> list[tuple[Any, ...]]:
    calls: list[tuple[Any, ...]] = []

    def chown(path: Any, uid: int, gid: int, *, follow_symlinks: bool = True) -> None:
        calls.append(("chown", str(path), uid, gid, follow_symlinks))

    def fchown(fd: int, uid: int, gid: int) -> None:
        calls.append(("fchown", uid, gid))

    monkeypatch.setattr(os, "chown", chown)
    monkeypatch.setattr(os, "fchown", fchown)
    return calls


def _trust_every_directory(monkeypatch: pytest.MonkeyPatch) -> None:
    """As if every directory on the way to the config belonged to root and
    were closed to everyone else (a test cannot make its tmp_path so)."""
    monkeypatch.setattr(wizard, "_only_root_can_change", lambda st: True)
    monkeypatch.setattr(wizard, "_has_extended_acl", lambda fd: False)


@POSIX_ONLY
def test_f47_as_root_the_secrets_belong_to_the_config_owner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = tmp_path / "config.yaml"
    config.write_text("application:\n  transport: stdio\n", encoding="utf-8")
    config.chmod(0o640)
    st = config.stat()
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    _trust_every_directory(monkeypatch)
    calls = _record_chowns(monkeypatch)

    username_file, password_file = wizard.store_credentials(config, "fin", "svc", "pw")

    secrets_dir = tmp_path / "secrets"
    # the directory, then each file, through their descriptors
    assert calls == [("fchown", st.st_uid, st.st_gid)] * 3
    assert stat.S_IMODE(secrets_dir.stat().st_mode) == 0o700
    assert password_file is not None
    for path in (username_file, password_file):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


@POSIX_ONLY
def test_f47_a_root_owned_config_names_the_service_account_by_its_group(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import grp
    import pwd
    from types import SimpleNamespace

    config = tmp_path / "config.yaml"
    config.write_text("application:\n  transport: stdio\n", encoding="utf-8")
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    _trust_every_directory(monkeypatch)
    monkeypatch.setattr(wizard, "_config_ownership", lambda path, dir_fd=None: (0, 4242))  # pkg: root:_udbmcp 0640
    monkeypatch.setattr(grp, "getgrgid", lambda gid: SimpleNamespace(gr_name="_udbmcp" if gid == 4242 else "wheel"))

    def getpwnam(name: str) -> SimpleNamespace:
        if name != "_udbmcp":
            raise KeyError(name)
        return SimpleNamespace(pw_uid=250, pw_gid=4242)

    monkeypatch.setattr(pwd, "getpwnam", getpwnam)
    calls = _record_chowns(monkeypatch)

    wizard.store_credentials(config, "fin", "svc", "pw")

    assert calls == [("fchown", 250, 4242)] * 3


@POSIX_ONLY
def test_f47_without_root_nothing_is_chowned(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    if os.geteuid() == 0:
        pytest.skip("runs as root")
    config = tmp_path / "config.yaml"
    config.write_text("application:\n  transport: stdio\n", encoding="utf-8")
    calls = _record_chowns(monkeypatch)
    wizard.store_credentials(config, "fin", "svc", "pw")
    assert calls == []


@POSIX_ONLY
def test_f47_an_unknown_service_account_is_refused_before_anything_is_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import grp
    from types import SimpleNamespace

    from universal_db_mcp.agents import core as agents_core

    etc = tmp_path / "etc"
    etc.mkdir()
    config = etc / "config.yaml"
    config.write_text(f"application:\n  transport: stdio\n  audit_path: {tmp_path}/audit.jsonl\n", encoding="utf-8")
    ca = tmp_path / "ca.pem"
    ca.write_text("x", encoding="utf-8")
    password = _private(tmp_path / "pw", "s3cret\n")
    monkeypatch.setattr(agents_core, "system_config_dir", lambda: etc)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", str(os.getuid()))  # sudo from the account that owns the password file
    _trust_every_directory(monkeypatch)
    monkeypatch.setattr(wizard, "_config_ownership", lambda path, dir_fd=None: (0, 0))  # root:root: no service account
    monkeypatch.setattr(grp, "getgrgid", lambda gid: SimpleNamespace(gr_name="root"))
    before = config.read_bytes()

    rc = main(
        [
            "add-connection", "--json", "--no-test", "--config", str(config), "--name", "fin",
            "--engine", "postgres", "--host", "h", "--database", "d", "--username", "u",
            "--password-file", str(password), "--tls-ca-file", str(ca),
        ]
    )  # fmt: skip
    err = capsys.readouterr().err
    assert rc != 0
    assert "install -o" in err and "-m 600" in err
    assert not (etc / "secrets").exists()
    assert config.read_bytes() == before
    assert sorted(p.name for p in etc.iterdir()) == ["config.yaml"]


def test_f47_editing_the_system_config_says_how_to_restart_the_service(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    config = tmp_path / "config.yaml"
    config.write_text(f"application:\n  transport: stdio\n  audit_path: {tmp_path}/audit.jsonl\n", encoding="utf-8")
    db = _sqlite_db(tmp_path / "a.db")
    monkeypatch.setattr(wizard, "_is_system_config", lambda path: True)
    base = ["add-connection", "--no-test", "--config", str(config), "--engine", "sqlite", "--database", str(db)]

    assert main([*base, "--json", "--name", "a"]) == 0
    assert json.loads(capsys.readouterr().out)["service_restart"] == wizard.service_restart_command()
    assert main([*base, "--name", "b"]) == 0
    assert f"restart the service to load the connection: {wizard.service_restart_command()}" in capsys.readouterr().out


@POSIX_ONLY
def test_f47_a_live_test_as_root_says_the_service_reads_the_secrets_as_their_owner(
    site: _Site, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", str(os.getuid()))  # sudo from the account that owns the password file
    _trust_every_directory(monkeypatch)
    _record_chowns(monkeypatch)
    monkeypatch.setattr(
        wizard, "test_connection", lambda cfg, name: {"healthy": True, "server_version": "16", "latency_ms": 1}
    )
    rc = main([arg for arg in _add_args(site) if arg != "--no-test"])
    captured = capsys.readouterr()
    assert rc == 0, captured.err
    result = json.loads(captured.out)
    assert result["tested"] is True
    owner_uid = site.config.stat().st_uid
    assert any("ran as root" in notice and f"uid {owner_uid}" in notice for notice in result["notices"]), result


# --- F49: the config is replaced atomically ---------------------------------


@pytest.mark.parametrize("failing", ["write_text", "replace", "fsync"])
def test_f49_a_full_disk_never_leaves_a_truncated_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], failing: str
) -> None:
    config = tmp_path / "config.yaml"
    text = f"# header\napplication:\n  transport: stdio\n  audit_path: {tmp_path}/audit.jsonl\n"
    config.write_text(text, encoding="utf-8")
    config.chmod(0o640)
    db = _sqlite_db(tmp_path / "a.db")

    def enospc(*args: Any, **kwargs: Any) -> Any:
        if failing == "write_text":
            Path(args[0]).open("w").close()  # what a full disk leaves after the truncating open
        raise OSError(errno.ENOSPC, "No space left on device")

    target = Path if failing == "write_text" else os
    monkeypatch.setattr(target, failing, enospc)
    rc = main(
        ["add-connection", "--json", "--no-test", "--config", str(config), "--name", "s1",
         "--engine", "sqlite", "--database", str(db)]
    )  # fmt: skip
    err = capsys.readouterr().err
    monkeypatch.undo()

    load_config(config)  # the live config is always valid
    assert not _tmp_leftovers(tmp_path)
    if failing == "write_text":
        assert rc == 0, "the live config is never written in place"
        return
    assert rc != 0
    assert config.read_text(encoding="utf-8") == text
    backups = list(tmp_path.glob("config.yaml.bak.*"))
    if failing == "fsync":
        # the backup is synced too, so a full disk stops the run there (I46)
        assert backups == [] and "could not back up" in err, err
    else:
        assert len(backups) == 1 and str(backups[0]) in err, err
    assert "unchanged" in err


def test_f49_a_failed_config_replace_rolls_the_secrets_back(
    site: _Site, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    before = site.snapshot()
    real_replace = os.replace

    def replace(src: Any, dst: Any, *args: Any, **kwargs: Any) -> None:
        if Path(dst) == site.config:
            raise OSError(errno.ENOSPC, "No space left on device")
        real_replace(src, dst, *args, **kwargs)

    monkeypatch.setattr(os, "replace", replace)
    rc = main(_add_args(site))
    capsys.readouterr()
    assert rc != 0
    after = site.snapshot()
    backups = [name for name in after if ".bak." in name]
    assert len(backups) == 1 and backups[0].startswith("config.yaml.bak."), "the secret copies went back into place"
    assert {k: v for k, v in after.items() if ".bak." not in k} == before


def test_f49_a_successful_run_keeps_the_config_mode(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    config = tmp_path / "config.yaml"
    config.write_text(f"application:\n  transport: stdio\n  audit_path: {tmp_path}/audit.jsonl\n", encoding="utf-8")
    config.chmod(0o640)
    db = _sqlite_db(tmp_path / "a.db")
    rc = main(
        ["add-connection", "--json", "--no-test", "--config", str(config), "--name", "s1",
         "--engine", "sqlite", "--database", str(db)]
    )  # fmt: skip
    capsys.readouterr()
    assert rc == 0
    assert stat.S_IMODE(config.stat().st_mode) == 0o640
    assert "s1" in load_config(config).connections


_USER_SID = "S-1-5-21-1-2-3-1001"


@pytest.mark.parametrize(
    ("config_owner", "expected"),
    [("S-1-5-18", [("S-1-5-32-544",)]), ("S-1-5-32-544", [("S-1-5-32-544",)]), (_USER_SID, []), ("fail", None)],
    ids=["msi-system", "msi-administrators", "per-user", "cannot-set"],
)
def test_f49_on_windows_a_machine_config_stays_owned_by_administrators(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, config_owner: str, expected: list[tuple[str]] | None
) -> None:
    """Review round 1: the replacement file belongs to whoever ran the
    wizard, and service.ps1 refuses a config.yaml that SYSTEM or
    Administrators do not own (MSI repair or upgrade)."""
    config = tmp_path / "config.yaml"
    config.write_text(f"application:\n  transport: stdio\n  audit_path: {tmp_path}/audit.jsonl\n", encoding="utf-8")
    before = config.read_bytes()
    plan = wizard.plan_merge(
        config, "s1", wizard.build_connection(name="s1", engine="sqlite", database=str(_sqlite_db(tmp_path / "a.db")))
    )
    set_owner: list[tuple[str, str]] = []

    def file_security(path: Path) -> tuple[str, str, list[Any]]:
        owner = config_owner if Path(path) == config else _USER_SID  # the temp file: the elevated admin
        return ("S-1-5-18" if owner == "fail" else owner), _USER_SID, []

    def set_owner_of(path: Path, sid: str) -> None:
        if config_owner == "fail":
            raise RuntimeError("SetNamedSecurityInfo: access denied")
        set_owner.append((Path(path).name, sid))

    monkeypatch.setattr(config_module, "_win32_file_security", file_security)
    monkeypatch.setattr(wizard, "_win32_set_owner", set_owner_of)
    monkeypatch.setattr(wizard.sys, "platform", "win32")
    try:
        if expected is None:
            with pytest.raises(wizard.WizardError, match="Administrators"):
                wizard.commit_merge(plan)
        else:
            wizard.commit_merge(plan)
    finally:
        monkeypatch.undo()

    if expected is None:
        assert config.read_bytes() == before
    else:
        assert [(sid,) for _name, sid in set_owner] == expected
        assert all(name.endswith(".tmp") for name, _sid in set_owner), "set on the replacement, before os.replace"
        assert "s1" in load_config(config).connections
    assert not _tmp_leftovers(tmp_path)


@POSIX_ONLY
def test_f49_a_symlinked_config_stays_a_link_to_the_updated_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Review round 1: os.replace onto the named path turned a symlinked
    config (a dotfile manager, config management) into a regular file and
    left the file it pointed to without the connection."""
    managed = tmp_path / "managed"
    managed.mkdir()
    target = managed / "config.yaml"
    target.write_text(f"application:\n  transport: stdio\n  audit_path: {tmp_path}/audit.jsonl\n", encoding="utf-8")
    target.chmod(0o640)
    link = tmp_path / "config.yaml"
    link.symlink_to(Path("managed") / "config.yaml")
    db = _sqlite_db(tmp_path / "a.db")
    rc = main(
        ["add-connection", "--json", "--no-test", "--config", str(link), "--name", "s1",
         "--engine", "sqlite", "--database", str(db)]
    )  # fmt: skip
    captured = capsys.readouterr()
    assert rc == 0, captured.err
    assert link.is_symlink() and link.resolve() == target.resolve()
    assert "s1" in load_config(target).connections
    assert stat.S_IMODE(target.stat().st_mode) == 0o640
    assert not _tmp_leftovers(tmp_path, managed)


@POSIX_ONLY
def test_f49_the_config_keeps_its_group(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Review round 1: the replacement file got the caller's (or the
    directory's) group, so a root:udbmcp 0660 config edited by a member of
    udbmcp could stop being readable by the service."""
    if os.geteuid() == 0:
        pytest.skip("runs as root")
    others = [g for g in os.getgroups() if g not in (os.getegid(), tmp_path.stat().st_gid)]
    if not others:
        pytest.skip("this account is in no second group")
    config = tmp_path / "config.yaml"
    config.write_text(f"application:\n  transport: stdio\n  audit_path: {tmp_path}/audit.jsonl\n", encoding="utf-8")
    config.chmod(0o660)
    os.chown(config, -1, others[0])
    db = _sqlite_db(tmp_path / "a.db")
    rc = main(
        ["add-connection", "--json", "--no-test", "--config", str(config), "--name", "s1",
         "--engine", "sqlite", "--database", str(db)]
    )  # fmt: skip
    capsys.readouterr()
    assert rc == 0
    assert config.stat().st_gid == others[0]
    assert stat.S_IMODE(config.stat().st_mode) == 0o660


# --- F50: Windows secrets directory -----------------------------------------


def test_f50_on_windows_every_secret_is_written_only_after_its_dacl_is_protected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "config.yaml"
    config.write_text("application:\n  transport: stdio\n", encoding="utf-8")
    (tmp_path / "secrets").mkdir()  # created first by another local user
    events: list[tuple[str, str]] = []

    def restrict(path: Path, *, directory: bool) -> None:
        events.append(("restrict", Path(path).name))

    def problems(path: Path) -> list[str]:
        events.append(("check", Path(path).name))
        return []

    real_write = os.write

    def write(fd: int, data: bytes) -> int:
        events.append(("write", ""))
        return real_write(fd, data)

    monkeypatch.setattr(wizard.sys, "platform", "win32")
    monkeypatch.setattr(wizard, "_win32_restrict", restrict)
    monkeypatch.setattr(config_module, "win32_secret_file_problems", problems)
    monkeypatch.setattr(os, "write", write)

    wizard.store_credentials(config, "fin", "svc", "pw")
    monkeypatch.undo()

    assert events[:2] == [("restrict", "secrets"), ("check", "secrets")]
    staged = [name for kind, name in events if kind == "restrict" and name != "secrets"]
    assert len(staged) == 2 and staged[0].endswith(".username.tmp") and staged[1].endswith(".password.tmp")
    for name in staged:
        at = events.index(("restrict", name))
        assert events[at + 1] == ("check", name)
        assert events[at + 2][0] == "write", events


def test_f50_on_windows_a_directory_other_users_can_read_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "config.yaml"
    config.write_text("application:\n  transport: stdio\n", encoding="utf-8")
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    monkeypatch.setattr(wizard.sys, "platform", "win32")
    monkeypatch.setattr(wizard, "_win32_restrict", lambda path, *, directory: None)
    monkeypatch.setattr(config_module, "win32_secret_file_problems", lambda path: ["readable by Users (S-1-5-32-545)"])

    with pytest.raises(wizard.WizardError, match="Users"):
        wizard.store_credentials(config, "fin", "svc", "pw")
    monkeypatch.undo()
    assert list(secrets_dir.iterdir()) == []


def test_f50_on_windows_a_junction_at_the_secrets_directory_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Review round 2: the check was only S_ISDIR(lstat), which a directory
    junction passes (a mount-point reparse point reports S_IFDIR), so the
    junction target's DACL was rewritten and the secrets written there."""
    from types import SimpleNamespace

    config = tmp_path / "config.yaml"
    config.write_text("application:\n  transport: stdio\n", encoding="utf-8")
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    lstat = os.lstat

    def junction_lstat(path: Any, *args: Any, **kwargs: Any) -> Any:
        st = lstat(path, *args, **kwargs)
        if Path(path) == secrets_dir:
            return SimpleNamespace(st_mode=st.st_mode, st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT)
        return st

    restricted: list[Path] = []
    monkeypatch.setattr(wizard.sys, "platform", "win32")
    monkeypatch.setattr(os, "lstat", junction_lstat)
    monkeypatch.setattr(wizard, "_win32_restrict", lambda path, *, directory: restricted.append(path))
    monkeypatch.setattr(config_module, "win32_secret_file_problems", lambda path: [])

    with pytest.raises(wizard.WizardError, match="link"):
        wizard.store_credentials(config, "fin", "svc", "pw")
    monkeypatch.undo()
    assert restricted == [], "the junction target's DACL was replaced"
    assert list(secrets_dir.iterdir()) == []


def test_f50_on_windows_the_secrets_dacl_copies_no_domain_wide_group(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Review round 2: the protected DACL copied the config directory's
    entries for every trustee but the local broad ones, while the check
    after it also refuses the domain-wide groups (Domain Users, ...), so a
    config directory that granted Domain Users failed every run with advice
    that could not help."""
    from types import SimpleNamespace

    domain = "S-1-5-21-1-2-3"
    read, full, inherit_only = 0x120089, 0x1F01FF, 0x08
    parent_aces = [
        ((0, 0), read, f"{domain}-513"),  # Domain Users
        ((0, 0), read, "S-1-5-32-545"),  # Users
        ((0, 0), read, f"{domain}-1105"),  # the service account the MSI grants
        ((0, inherit_only), full, f"{domain}-1106"),
    ]
    granted: list[str] = []

    class Dacl:
        def GetAceCount(self) -> int:
            return len(parent_aces)

        def GetAce(self, i: int) -> tuple[tuple[int, int], int, str]:
            return parent_aces[i]

    class Acl:
        def AddAccessAllowedAceEx(self, revision: int, inherit: int, mask: int, sid: str) -> None:
            granted.append(sid)

    win32security = SimpleNamespace(
        TOKEN_QUERY=8,
        TokenUser=1,
        DACL_SECURITY_INFORMATION=4,
        PROTECTED_DACL_SECURITY_INFORMATION=0x80000000,
        ACCESS_ALLOWED_ACE_TYPE=0,
        INHERIT_ONLY_ACE=inherit_only,
        OBJECT_INHERIT_ACE=1,
        CONTAINER_INHERIT_ACE=2,
        ACL_REVISION=2,
        SE_FILE_OBJECT=1,
        ACL=Acl,
        OpenProcessToken=lambda process, access: "token",
        GetTokenInformation=lambda token, kind: (f"{domain}-1001", 0),
        ConvertStringSidToSid=lambda sid: sid,
        ConvertSidToStringSid=lambda sid: sid,
        GetFileSecurity=lambda path, info: SimpleNamespace(GetSecurityDescriptorDacl=Dacl),
        SetNamedSecurityInfo=lambda *args: None,
    )
    monkeypatch.setitem(sys.modules, "win32security", win32security)
    monkeypatch.setitem(sys.modules, "win32api", SimpleNamespace(GetCurrentProcess=lambda: -1))
    monkeypatch.setitem(sys.modules, "ntsecuritycon", SimpleNamespace(FILE_ALL_ACCESS=full))
    monkeypatch.setattr(wizard.sys, "platform", "win32")

    wizard._win32_restrict(tmp_path / "secrets", directory=True)
    monkeypatch.undo()
    assert granted == ["S-1-5-18", "S-1-5-32-544", f"{domain}-1001", f"{domain}-1105"]


def test_f50_on_windows_an_access_control_error_is_a_wizard_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class PyWinTypesError(Exception):
        """pywintypes.error, which is not an OSError"""

    def restrict(path: Path, *, directory: bool) -> None:
        raise PyWinTypesError(5, "SetNamedSecurityInfo", "Access is denied.")

    config = tmp_path / "config.yaml"
    config.write_text("application:\n  transport: stdio\n", encoding="utf-8")
    monkeypatch.setattr(wizard.sys, "platform", "win32")
    monkeypatch.setattr(wizard, "_win32_restrict", restrict)
    with pytest.raises(wizard.WizardError, match="Access is denied"):
        wizard.store_credentials(config, "fin", "svc", "pw")
    monkeypatch.undo()
    assert list((tmp_path / "secrets").iterdir()) == []


def test_the_wizard_imports_without_the_windows_access_checks() -> None:
    """Review round 2: wizard.py imported config.win32_secret_file_problems
    at module level, so add-connection and configure-agents (which imports
    the wizard for its notice) depended on it everywhere; like the other
    Windows helpers it is imported where it is used."""
    code = "import universal_db_mcp.config as c; del c.win32_secret_file_problems; import universal_db_mcp.wizard"
    subprocess.run([sys.executable, "-c", code], check=True, timeout=120)  # noqa: S603 - fixed argv


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DACLs")
def test_f50_windows_secret_files_get_a_protected_dacl(tmp_path: Path) -> None:
    import win32security

    from universal_db_mcp.config import win32_secret_file_problems

    config = tmp_path / "config.yaml"
    config.write_text("application:\n  transport: stdio\n", encoding="utf-8")
    username_file, password_file = wizard.store_credentials(config, "fin", "svc", "pw")
    assert password_file is not None
    for path in (username_file.parent, username_file, password_file):
        assert win32_secret_file_problems(path) == []
        sd = win32security.GetFileSecurity(str(path), win32security.DACL_SECURITY_INFORMATION)
        control, _revision = sd.GetSecurityDescriptorControl()
        assert control & win32security.SE_DACL_PROTECTED, path


# --- F52: absolute paths -------------------------------------------------------


def test_f52_paths_given_relative_to_the_cwd_are_stored_absolute(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    work = tmp_path / "work"
    elsewhere = tmp_path / "elsewhere"
    work.mkdir()
    elsewhere.mkdir()
    (work / "conf.yaml").write_text(
        f"application:\n  transport: stdio\n  audit_path: {tmp_path}/audit.jsonl\n", encoding="utf-8"
    )
    (work / "ca.pem").write_text("x", encoding="utf-8")
    _private(work / "pw", "s3cret\n")
    _sqlite_db(work / "demo.db")
    monkeypatch.chdir(work)

    rc = main(
        ["add-connection", "--json", "--no-test", "--config", "conf.yaml", "--name", "fin",
         "--engine", "postgres", "--host", "db.internal", "--database", "fin", "--username", "svc",
         "--password-file", "pw", "--tls-ca-file", "ca.pem"]
    )  # fmt: skip
    captured = capsys.readouterr()
    assert rc == 0, captured.err
    assert Path(json.loads(captured.out)["config"]).is_absolute()
    rc = main(
        ["add-connection", "--json", "--no-test", "--config", "conf.yaml", "--name", "demo",
         "--engine", "sqlite", "--database", "demo.db"]
    )  # fmt: skip
    capsys.readouterr()
    assert rc == 0

    connections = yaml.safe_load((work / "conf.yaml").read_text(encoding="utf-8"))["connections"]
    for value in (
        connections["fin"]["username_file"],
        connections["fin"]["password_file"],
        connections["fin"]["tls"]["ca_file"],
        connections["demo"]["database"],
    ):
        assert Path(value).is_absolute(), value
    monkeypatch.chdir(elsewhere)
    _cfg, resolved = load_resolved(work / "conf.yaml")
    assert resolved["demo"].config.database == str(work / "demo.db")


# --- F77: comments after the header -------------------------------------------


COMMENTED_CONFIG = """\
# header comment (kept)
application:
  transport: stdio  # the service passes --transport http
  audit_path: {d}/audit.jsonl
# connections are added by the wizard below
"""


@pytest.mark.parametrize(
    "body",
    [
        COMMENTED_CONFIG,
        "application:\n  transport: stdio  # inline only\n  audit_path: {d}/audit.jsonl\n",
        # review round 1: PyYAML's block scalar token starts at the '|' and
        # took the comment on the indicator line with it
        "application:\n  transport: stdio\n  audit_path: {d}/audit.jsonl\nsecurity:\n  mask_columns:\n"
        "    - |  # keep this note: why ssn is masked\n      (?i)ssn\n",
    ],
    ids=["full-line", "inline", "after-a-block-scalar-indicator"],
)
def test_f77_json_mode_refuses_to_drop_comments_without_the_flag(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], body: str
) -> None:
    config = tmp_path / "config.yaml"
    config.write_text(body.format(d=tmp_path), encoding="utf-8")
    before = config.read_bytes()
    db = _sqlite_db(tmp_path / "a.db")
    args = ["add-connection", "--json", "--no-test", "--config", str(config), "--name", "s1",
            "--engine", "sqlite", "--database", str(db)]  # fmt: skip

    rc = main(args)
    err = capsys.readouterr().err
    assert rc != 0
    assert "--accept-comment-loss" in err
    assert config.read_bytes() == before
    assert not list(tmp_path.glob("config.yaml.bak.*"))

    rc = main([*args, "--accept-comment-loss"])
    captured = capsys.readouterr()
    assert rc == 0, captured.err
    assert json.loads(captured.out)["comments_dropped"] is True
    assert config.read_text(encoding="utf-8").startswith("# header comment (kept)\n" if "header" in body else "")


@pytest.mark.parametrize(
    "masks",
    ["  mask_columns: ['(?i)card #']\n", "  mask_columns:\n    - |-\n      (?i)card #\n"],
    ids=["flow", "block-scalar"],
)
def test_f77_a_hash_inside_a_value_is_not_a_comment(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], masks: str
) -> None:
    config = tmp_path / "config.yaml"
    config.write_text(
        f"application:\n  transport: stdio\n  audit_path: {tmp_path}/audit.jsonl\nsecurity:\n{masks}",
        encoding="utf-8",
    )
    db = _sqlite_db(tmp_path / "a.db")
    rc = main(
        ["add-connection", "--json", "--no-test", "--config", str(config), "--name", "s1",
         "--engine", "sqlite", "--database", str(db)]
    )  # fmt: skip
    captured = capsys.readouterr()
    assert rc == 0, captured.err
    assert json.loads(captured.out)["comments_dropped"] is False


def test_f77_interactive_mode_asks_before_dropping_comments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    config = tmp_path / "config.yaml"
    config.write_text(COMMENTED_CONFIG.format(d=tmp_path), encoding="utf-8")
    before = config.read_bytes()
    db = _sqlite_db(tmp_path / "a.db")
    # engine, name, database file, test, then: rewrite without the comments?
    prompts = _scripted_input(monkeypatch, ["1", "s1", str(db), "n", "n"])
    rc = main(["add-connection", "--config", str(config)])
    out = capsys.readouterr().out
    assert rc != 0
    assert config.read_bytes() == before
    assert "comment" in out
    assert len(prompts) == 5, prompts
    assert prompts[3].startswith("Test the connection now?"), prompts
    assert prompts[-1].startswith("Rewrite it without those comments?"), prompts
    assert prompts[-1].rstrip().endswith("[y/N]:"), prompts[-1]


# --- F78: site-check --out --force ----------------------------------------------


@POSIX_ONLY
def test_f78_force_does_not_follow_a_planted_symlink(tmp_path: Path) -> None:
    victim = tmp_path / "audit.jsonl"
    victim.write_text("audit record\n", encoding="utf-8")
    victim.chmod(0o640)
    link = tmp_path / "udbmcp-site-check.json"
    link.symlink_to(victim)

    with pytest.raises(SystemExit) as refused:
        site_check.write_report({"ok": True}, str(link), force=True)
    assert refused.value.code not in (0, None)
    assert victim.read_text(encoding="utf-8") == "audit record\n"
    assert stat.S_IMODE(victim.stat().st_mode) == 0o640
    assert link.is_symlink()
    assert not _tmp_leftovers(tmp_path)


@POSIX_ONLY
def test_f78_site_check_cli_refuses_a_symlinked_out(tmp_path: Path) -> None:
    db = _sqlite_db(tmp_path / "a.db")
    config = tmp_path / "config.yaml"
    config.write_text(
        f"application:\n  transport: stdio\n  audit_path: {tmp_path}/audit.jsonl\n"
        f"  metadata_cache_path: {tmp_path}/cache.sqlite\n"
        f"connections:\n  a:\n    type: sqlite\n    database: {db}\n",
        encoding="utf-8",
    )
    victim = tmp_path / "victim.txt"
    victim.write_text("keep me\n", encoding="utf-8")
    link = tmp_path / "report.json"
    link.symlink_to(victim)
    with pytest.raises(SystemExit) as refused:
        main(["site-check", "--config", str(config), "--out", str(link), "--force"])
    assert refused.value.code not in (0, None)
    assert victim.read_text(encoding="utf-8") == "keep me\n"


@POSIX_ONLY
def test_f78_force_refuses_a_file_another_user_owns(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    out = tmp_path / "report.json"
    out.write_text("earlier run\n", encoding="utf-8")
    monkeypatch.setattr(os, "geteuid", lambda: out.stat().st_uid + 1)
    with pytest.raises(SystemExit):
        site_check.write_report({"ok": True}, str(out), force=True)
    assert out.read_text(encoding="utf-8") == "earlier run\n"


@POSIX_ONLY
@pytest.mark.parametrize("where", ["missing-directory", "unwritable-directory"])
def test_f78_an_unwritable_out_is_a_clean_error_without_force(tmp_path: Path, where: str) -> None:
    """Review round 2: without --force only FileExistsError was caught, so a
    missing or unwritable --out directory ended in a raw traceback."""
    if where == "missing-directory":
        out = tmp_path / "missing" / "report.json"
    else:
        if os.geteuid() == 0:
            pytest.skip("root writes into a 0500 directory")
        (tmp_path / "ro").mkdir(mode=0o500)
        out = tmp_path / "ro" / "report.json"
    with pytest.raises(SystemExit, match=f"cannot write {re.escape(str(out))}"):
        site_check.write_report({"ok": True}, str(out))
    assert not out.exists()


def test_f78_force_replaces_an_own_report_privately(tmp_path: Path) -> None:
    out = tmp_path / "report.json"
    out.write_text("earlier run\n", encoding="utf-8")
    out.chmod(0o644)
    site_check.write_report({"ok": True}, str(out), force=True)
    assert json.loads(out.read_text(encoding="utf-8")) == {"ok": True}
    if sys.platform != "win32":
        assert stat.S_IMODE(out.stat().st_mode) == 0o600
    assert not _tmp_leftovers(tmp_path)


# --- F81: the onboarding commands say what a stdio agent can read ---------------


def test_f81_add_connection_says_that_agents_can_read_the_secrets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from universal_db_mcp.agents import core as agents_core

    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("UDBMCP_CONFIG", raising=False)
    monkeypatch.setattr(agents_core, "SYSTEM_CONFIG_PATH", tmp_path / "no-system-config.yaml")
    ca = tmp_path / "ca.pem"
    ca.write_text("x", encoding="utf-8")
    password = _private(tmp_path / "pw", "Sup3r-s3cret\n")
    base = ["add-connection", "--no-test", "--engine", "postgres", "--host", "h", "--database", "d",
            "--username", "svc", "--password-file", str(password), "--tls-ca-file", str(ca)]  # fmt: skip
    secrets_dir = home / ".universal-db-mcp" / "secrets"

    assert main([*base, "--name", "fin"]) == 0
    captured = capsys.readouterr()
    assert "NOTICE" in captured.out and str(secrets_dir) in captured.out, captured.out
    assert "shell" in captured.out
    assert "Sup3r-s3cret" not in captured.out + captured.err

    assert main([*base, "--json", "--name", "fin2"]) == 0
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert any(str(secrets_dir) in notice for notice in result["notices"]), result
    assert "Sup3r-s3cret" not in captured.out + captured.err


def test_f81_no_notice_when_no_secret_file_is_written(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    config = tmp_path / "config.yaml"
    config.write_text(f"application:\n  transport: stdio\n  audit_path: {tmp_path}/audit.jsonl\n", encoding="utf-8")
    db = _sqlite_db(tmp_path / "a.db")
    assert main(["add-connection", "--no-test", "--config", str(config), "--name", "s1", "--engine", "sqlite",
                 "--database", str(db)]) == 0  # fmt: skip
    assert "NOTICE" not in capsys.readouterr().out


@pytest.fixture
def cursor_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    from universal_db_mcp.agents import core as agents_core

    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("UDBMCP_CONFIG", raising=False)
    monkeypatch.setattr(agents_core, "SYSTEM_CONFIG_PATH", tmp_path / "no-system-config.yaml")
    return home


def test_f81_configure_agents_says_that_the_agent_can_read_the_secrets(
    cursor_home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (cursor_home / ".cursor").mkdir()
    rc = main(["configure-agents", "--agent", "cursor", "--yes"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "-> configured" in out
    assert "NOTICE" in out and str(cursor_home / ".universal-db-mcp" / "secrets") in out, out


def test_f81_configure_agents_json_keeps_stdout_json(cursor_home: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (cursor_home / ".cursor").mkdir()
    rc = main(["configure-agents", "--json", "--agent", "cursor", "--yes"])
    captured = capsys.readouterr()
    assert rc == 0
    assert json.loads(captured.out)["applied"][0]["status"] == "configured"
    assert "NOTICE" in captured.err


def test_f81_no_notice_when_nothing_is_registered(cursor_home: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["configure-agents", "--agent", "cursor", "--yes"])  # no ~/.cursor: nothing to register
    captured = capsys.readouterr()
    assert rc == 0
    assert "NOTICE" not in captured.out + captured.err


# ==========================================================================
# Part 3: review round 3 (integration wave)
# ==========================================================================


def _load_script(name: str) -> Any:
    """scripts/<name>.py as a module (the scripts are not a package)."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(f"{name}_under_test", REPO / "scripts" / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --- I38: SIGTERM ends a stdio server even while the GIL is held ------------

_FROZEN_CANCEL_LAUNCHER = """\
import ctypes
import pathlib
import sys

from universal_db_mcp.connectors.sqlite import SQLiteConnector


def cancel_current(self):
    pathlib.Path("cancel-hook-started").touch()
    # a C call that keeps the GIL, as libpq's PQcancel does against a frozen host
    ctypes.PyDLL(None).sleep(30)
    return False


SQLiteConnector.cancel_current = cancel_current
from universal_db_mcp.__main__ import main

sys.exit(main(sys.argv[1:]))
"""


@contextlib.contextmanager
def _slow_query_on_a_frozen_cancel_hook(tmp_path: Path, config_extra: str = "") -> Iterator[subprocess.Popen[bytes]]:
    """A stdio server (sqlite cancel hook patched to hold the GIL for 30 s)
    that is running a slow db_query; killed on the way out."""
    db = _sqlite_db(tmp_path / "a.db")
    config = tmp_path / "config.yaml"
    config.write_text(
        "application:\n"
        "  transport: stdio\n"
        f"  audit_path: {tmp_path / 'audit.jsonl'}\n"
        f"  metadata_cache_path: {tmp_path / 'cache.sqlite'}\n"
        f"{config_extra}"
        "connections:\n"
        "  a:\n"
        "    type: sqlite\n"
        f"    database: {db}\n",
        encoding="utf-8",
    )
    proc = subprocess.Popen(  # noqa: S603 - fixed argv, the interpreter running the tests
        [sys.executable, "-c", _FROZEN_CANCEL_LAUNCHER, "serve", "--config", str(config)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        cwd=tmp_path,
    )
    assert proc.stdin is not None and proc.stdout is not None

    def send(message: dict[str, Any]) -> None:
        assert proc.stdin is not None
        proc.stdin.write((json.dumps(message) + "\n").encode())
        proc.stdin.flush()

    slow = (
        "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 400000000) "
        "SELECT count(*) FROM c, t"
    )
    try:
        send(INITIALIZE)
        assert b'"result"' in proc.stdout.readline()
        send(INITIALIZED)
        send(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "db_query", "arguments": {"connection_id": "a", "sql": slow}},
            }
        )
        yield proc
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=10)
        proc.stdin.close()
        proc.stdout.close()


@POSIX_ONLY
def test_i38_sigterm_ends_a_stdio_server_whose_cancel_hook_holds_the_gil(tmp_path: Path) -> None:
    """Review round 3 (F86): the grace watchdog is a Python thread, which
    cannot run while a cancel hook blocks in C holding the GIL, so the
    server never exited. The kernel's alarm ends it with no Python running."""
    from universal_db_mcp.__main__ import _SIGTERM_HARD_EXIT_SECONDS

    with _slow_query_on_a_frozen_cancel_hook(tmp_path) as proc:
        time.sleep(1.0)
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=_SIGTERM_HARD_EXIT_SECONDS + 2)
        except subprocess.TimeoutExpired:
            pytest.fail(f"the stdio server did not exit within {_SIGTERM_HARD_EXIT_SECONDS + 2} s of SIGTERM")
        # the cancel hook still held the GIL: only the kernel could end it
        assert proc.returncode == -signal.SIGALRM


@POSIX_ONLY
@pytest.mark.xfail(
    strict=True,
    raises=pytest.fail.Exception,
    reason="documented limit (__main__._serve_stdio): a cancel hook the deadline already fired keeps the GIL, "
    "so the SIGTERM handler that arms the alarm cannot run; the supervisor's SIGKILL ends the process",
)
def test_i38_sigterm_while_a_deadline_cancel_hook_holds_the_gil(tmp_path: Path) -> None:
    """Final round: the alarm is armed by the Python SIGTERM handler, so it
    covers a cancel hook that SIGTERM fires, not one the statement deadline
    (or a client cancel) fired before the SIGTERM came. This test keeps the
    limit visible: it fails for as long as the process outlives the alarm's
    deadline, and an XPASS says the limit is gone."""
    from universal_db_mcp.__main__ import _SIGTERM_HARD_EXIT_SECONDS

    deadline = "security:\n  default_query_timeout_seconds: 1\n"
    with _slow_query_on_a_frozen_cancel_hook(tmp_path, deadline) as proc:
        hook_started = tmp_path / "cancel-hook-started"
        waited = time.monotonic() + 30
        while not hook_started.exists():
            assert proc.poll() is None and time.monotonic() < waited, "the deadline never fired the cancel hook"
            time.sleep(0.05)
        time.sleep(0.5)  # the hook is in the C call, holding the GIL
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=_SIGTERM_HARD_EXIT_SECONDS + 2)
        except subprocess.TimeoutExpired:
            pytest.fail(f"the stdio server did not exit within {_SIGTERM_HARD_EXIT_SECONDS + 2} s of SIGTERM")


# --- I39: as root, secrets only under directories only root can change -------


def _pg_add_args(config: Path, password: Path, name: str = "fin") -> list[str]:
    return [
        "add-connection", "--json", "--no-test", "--config", str(config), "--name", name, "--engine", "postgres",
        "--host", "db", "--database", "fin", "--username", "svc", "--password-file", str(password),
    ]  # fmt: skip


@POSIX_ONLY
def test_i39_as_root_a_config_in_a_directory_another_account_can_change_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Review round 3 (F47): root chowned the secrets directory to the owner
    of a per-user config, through a directory that owner could swap for a
    symlink. As root, the wizard now writes secrets only where no other
    account can change a directory on the way."""
    if os.geteuid() == 0:
        pytest.skip("needs a directory that does not belong to root")
    config_dir = tmp_path / "alice"
    config_dir.mkdir()
    config = _private(config_dir / "config.yaml", "application:\n  transport: stdio\n")
    before = config.read_bytes()
    password = _private(tmp_path / "pw", "s3cret\n")
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    calls = _record_chowns(monkeypatch)

    rc = main(_pg_add_args(config, password))
    err = capsys.readouterr().err
    assert rc != 0
    assert "CONFIG_ERROR" in err and "only root" in err and "sudo -u" in err, err
    assert calls == []
    assert not (config_dir / "secrets").exists()
    assert config.read_bytes() == before
    assert sorted(p.name for p in config_dir.iterdir()) == ["config.yaml"]


@POSIX_ONLY
def test_i39_a_directory_swapped_after_the_ownership_check_is_never_written_through(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The reviewer's race: the config directory is swapped for a symlink to
    another service's directory between secret_owner() and the secrets
    directory being prepared. O_NOFOLLOW guarded only the last component, so
    root chmodded and chowned the other service's secrets directory."""
    victim = tmp_path / "etc-otherservice"
    (victim / "secrets").mkdir(parents=True)
    (victim / "secrets").chmod(0o755)
    (victim / "secrets" / "other.password").write_text("theirs\n", encoding="utf-8")
    config_dir = tmp_path / "alice"
    config_dir.mkdir()
    config = _private(config_dir / "config.yaml", "application:\n  transport: stdio\n")
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    _trust_every_directory(monkeypatch)
    touched: list[tuple[str, int]] = []
    real_fchmod = os.fchmod

    def fchmod(fd: int, mode: int) -> None:
        touched.append(("fchmod", os.fstat(fd).st_ino))
        real_fchmod(fd, mode)

    def fchown(fd: int, uid: int, gid: int) -> None:
        touched.append(("fchown", os.fstat(fd).st_ino))

    monkeypatch.setattr(os, "fchmod", fchmod)
    monkeypatch.setattr(os, "fchown", fchown)
    real_owner = wizard.secret_owner

    def owner_then_swap(*args: Any, **kwargs: Any) -> Any:
        owner = real_owner(*args, **kwargs)
        config_dir.rename(tmp_path / "alice.real")
        config_dir.symlink_to(victim)
        return owner

    monkeypatch.setattr(wizard, "secret_owner", owner_then_swap)

    with contextlib.suppress(wizard.WizardError):
        wizard.store_credentials(config, "fin", "svc", "pw")

    victim_inode = (victim / "secrets").stat().st_ino
    assert [call for call in touched if call[1] == victim_inode] == []
    assert stat.S_IMODE((victim / "secrets").stat().st_mode) == 0o755
    assert sorted(os.listdir(victim / "secrets")) == ["other.password"]


@POSIX_ONLY
def test_i39_the_root_only_walk_follows_only_links_root_placed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Links in a directory only root can change are followed (macOS /etc is
    one); a link into, or anything under, a directory another account can
    change is refused."""
    alice = tmp_path / "alice"
    (alice / "cfg").mkdir(parents=True)
    private_etc = tmp_path / "private-etc"
    (private_etc / "universal-db-mcp").mkdir(parents=True)
    (tmp_path / "etc").symlink_to("private-etc")
    (tmp_path / "into-alice").symlink_to(alice / "cfg")
    untrusted = (alice.stat().st_dev, alice.stat().st_ino)
    monkeypatch.setattr(wizard, "_only_root_can_change", lambda st: (st.st_dev, st.st_ino) != untrusted)

    fd = wizard._open_root_only_directory(tmp_path / "etc" / "universal-db-mcp")
    try:
        opened = os.fstat(fd)
        expected = (private_etc / "universal-db-mcp").stat()
        assert (opened.st_dev, opened.st_ino) == (expected.st_dev, expected.st_ino)
    finally:
        os.close(fd)
    for where in (alice / "cfg", tmp_path / "into-alice"):
        with pytest.raises(wizard.WizardError, match="only root"):
            wizard._open_root_only_directory(where)


@POSIX_ONLY
def test_i39_the_owner_is_read_through_the_checked_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The account the secrets are given to comes from the config found in
    the directory that was checked, not from a later lookup by path."""
    config = _private(tmp_path / "config.yaml", "application:\n  transport: stdio\n")
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    _trust_every_directory(monkeypatch)
    calls = _record_chowns(monkeypatch)
    seen: list[int | None] = []
    real_ownership = wizard._config_ownership

    def ownership(path: Path, dir_fd: int | None = None) -> tuple[int, int]:
        seen.append(dir_fd)
        return real_ownership(path, dir_fd)

    monkeypatch.setattr(wizard, "_config_ownership", ownership)
    wizard.store_credentials(config, "fin", "svc", "pw")
    assert len(seen) == 1 and seen[0] is not None
    st = config.stat()
    assert calls == [("fchown", st.st_uid, st.st_gid)] * 3


@pytest.mark.skipif(
    sys.platform != "darwin",
    reason="macOS extended ACLs do not show in the mode bits; a Linux ACL's mask shows in the group bits",
)
def test_i39_a_directory_with_a_macos_acl_is_not_trusted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Fix-up round 1: the walk read only the mode bits, and 'everyone allow
    add_file,add_subdirectory,delete_child' leaves a directory at 0755, so
    another account could plant a link in a directory the walk trusted."""
    shared = tmp_path / "shared"
    shared.mkdir(mode=0o755)
    plain = tmp_path / "plain"
    plain.mkdir(mode=0o755)
    subprocess.run(  # noqa: S603 - fixed argv
        ["/bin/chmod", "+a", "everyone allow add_file,add_subdirectory,delete_child", str(shared)], check=True
    )
    assert stat.S_IMODE(shared.stat().st_mode) == 0o755
    for directory, expected in ((shared, True), (plain, False)):
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            assert wizard._has_extended_acl(fd) is expected
        finally:
            os.close(fd)
    monkeypatch.setattr(wizard, "_only_root_can_change", lambda st: True)  # the mode bits pass
    with pytest.raises(wizard.WizardError, match="access control list"):
        wizard._open_root_only_directory(shared)
    os.close(wizard._open_root_only_directory(plain))


def _sqlite_add_args(config: Path, db: Path, name: str = "lite") -> list[str]:
    return ["add-connection", "--json", "--no-test", "--config", str(config), "--name", name, "--engine", "sqlite",
            "--database", str(db)]  # fmt: skip


@POSIX_ONLY
def test_i39_as_root_an_add_without_secrets_checks_the_directories_too(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Fix-up round 1: the root-only walk ran only when credentials were
    staged. A sqlite add as root wrote the backup and the temp file through
    the per-user config's directory, fchowned the temp file to her and
    renamed it into place, so she could swap that directory for a link to
    another root-only directory (the system config's) once the .bak
    appeared and have root put a file she owns, holding her text, there."""
    if os.geteuid() == 0:
        pytest.skip("needs a directory that does not belong to root")
    alice = tmp_path / "alice"
    alice.mkdir()
    config = _private(alice / "config.yaml", "# alice's header\napplication:\n  transport: stdio\n")
    before = config.read_bytes()
    victim = tmp_path / "etc-universal-db-mcp"
    victim.mkdir()
    system_config = "# the system config\napplication:\n  transport: stdio\n"
    (victim / "config.yaml").write_text(system_config, encoding="utf-8")
    db = _sqlite_db(tmp_path / "a.db")
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    calls = _record_chowns(monkeypatch)
    real_mkstemp = wizard.tempfile.mkstemp

    def swap_then_mkstemp(*args: Any, **kwargs: Any) -> Any:
        # she watches her directory and swaps it once the backup is there
        if not alice.is_symlink():
            alice.rename(tmp_path / "alice.real")
            alice.symlink_to(victim)
        return real_mkstemp(*args, **kwargs)

    monkeypatch.setattr(wizard.tempfile, "mkstemp", swap_then_mkstemp)

    rc = main(_sqlite_add_args(config, db))
    err = capsys.readouterr().err
    assert rc != 0
    assert "CONFIG_ERROR" in err and "only root" in err and "sudo -u" in err, err
    assert calls == []
    assert (victim / "config.yaml").read_text(encoding="utf-8") == system_config
    assert sorted(os.listdir(victim)) == ["config.yaml"]
    assert not alice.is_symlink(), "refused before anything was written"
    assert config.read_bytes() == before
    assert sorted(p.name for p in alice.iterdir()) == ["config.yaml"]


@POSIX_ONLY
def test_i39_as_root_a_new_config_is_created_only_under_directories_only_root_can_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """ensure_config_exists (mkdir -p, then the create) ran before any walk."""
    if os.geteuid() == 0:
        pytest.skip("needs a directory that does not belong to root")
    alice = tmp_path / "alice"
    alice.mkdir()
    config = alice / "new" / "config.yaml"
    db = _sqlite_db(tmp_path / "a.db")
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    calls = _record_chowns(monkeypatch)

    rc = main(_sqlite_add_args(config, db))
    err = capsys.readouterr().err
    assert rc != 0
    assert "CONFIG_ERROR" in err and "only root" in err, err
    assert calls == []
    assert os.listdir(alice) == []


@POSIX_ONLY
def test_i39_as_root_the_file_a_symlinked_config_points_to_is_checked_too(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A symlinked config is replaced where it points: the backup, temp file
    and rename happen in that directory, so it must be one only root can
    change as well."""
    real_dir = tmp_path / "alice"
    real_dir.mkdir()
    real = _private(real_dir / "config.yaml", "application:\n  transport: stdio\n")
    before = real.read_bytes()
    link_dir = tmp_path / "etc"
    link_dir.mkdir()
    (link_dir / "config.yaml").symlink_to(real)
    db = _sqlite_db(tmp_path / "a.db")
    untrusted = (real_dir.stat().st_dev, real_dir.stat().st_ino)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(wizard, "_only_root_can_change", lambda st: (st.st_dev, st.st_ino) != untrusted)
    calls = _record_chowns(monkeypatch)

    rc = main(_sqlite_add_args(link_dir / "config.yaml", db))
    err = capsys.readouterr().err
    assert rc != 0
    assert "CONFIG_ERROR" in err and "only root" in err and str(real_dir) in err, err
    assert calls == []
    assert real.read_bytes() == before
    assert sorted(os.listdir(real_dir)) == ["config.yaml"]
    assert sorted(os.listdir(link_dir)) == ["config.yaml"]


@POSIX_ONLY
def test_i39_as_root_the_commit_checks_the_file_the_link_leads_to_now(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """commit_merge resolves a symlinked config again: a link whose target
    passes through a directory another account can change (with '..', say)
    can lead elsewhere by then, so the directory it writes in is checked
    again, not only the one plan_merge saw."""
    trusted, untrusted = tmp_path / "etc", tmp_path / "alice"
    trusted.mkdir()
    untrusted.mkdir()
    original = "application:\n  transport: stdio\n"
    real = _private(trusted / "real.yaml", original)
    elsewhere = _private(untrusted / "real.yaml", original)
    link = trusted / "config.yaml"
    link.symlink_to(real)
    db = _sqlite_db(tmp_path / "a.db")
    bad = (untrusted.stat().st_dev, untrusted.stat().st_ino)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(wizard, "_only_root_can_change", lambda st: (st.st_dev, st.st_ino) != bad)
    calls = _record_chowns(monkeypatch)
    plan = wizard.plan_merge(link, "lite", wizard.build_connection(name="lite", engine="sqlite", database=str(db)))
    link.unlink()
    link.symlink_to(elsewhere)  # it now resolves into the other account's directory

    with pytest.raises(wizard.WizardError, match="only root"):
        wizard.commit_merge(plan)
    assert calls == []
    assert elsewhere.read_text(encoding="utf-8") == original
    assert sorted(os.listdir(untrusted)) == ["real.yaml"]
    assert sorted(os.listdir(trusted)) == ["config.yaml", "real.yaml"]


@POSIX_ONLY
def test_i39_as_root_a_sqlite_add_under_directories_only_root_can_change_goes_ahead(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The system deployment (root-owned /etc/universal-db-mcp) keeps working,
    including a config whose directory does not exist yet."""
    config = tmp_path / "etc" / "universal-db-mcp" / "config.yaml"
    db = _sqlite_db(tmp_path / "a.db")
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    _trust_every_directory(monkeypatch)
    calls = _record_chowns(monkeypatch)
    walked: list[Path] = []
    real_walk = wizard._open_root_only_directory

    def walk(directory: Path) -> int:
        walked.append(Path(directory))
        return real_walk(directory)

    monkeypatch.setattr(wizard, "_open_root_only_directory", walk)

    rc = main(_sqlite_add_args(config, db))
    captured = capsys.readouterr()
    assert rc == 0, captured.err
    assert load_config(config).connections["lite"].type == "sqlite"
    # the nearest directory that existed, then the config's own
    assert walked[0] == tmp_path and config.parent in walked
    st = config.stat()
    assert calls == [("fchown", st.st_uid, st.st_gid)]


@POSIX_ONLY
@pytest.mark.parametrize("swap", ["hard-link", "fifo"])
def test_i39_the_old_secret_is_copied_only_from_the_file_that_was_checked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, swap: str
) -> None:
    """Fix-up round 1: _keep_copy checked the old secret by name, then opened
    it by name. The secrets directory's owner (the service account, as root)
    could swap in a hard link to a file only root can read, which root then
    copied into a backup it gave her, or a FIFO, whose open blocked."""
    config = _private(tmp_path / "config.yaml", "application:\n  transport: stdio\n")
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    _trust_every_directory(monkeypatch)
    _record_chowns(monkeypatch)
    wizard.store_credentials(config, "fin", "old_user", "old_pw")
    root_only = _private(tmp_path / "root-only", "ROOT-ONLY CONTENT\n")
    secrets_dir = tmp_path / "secrets"
    real_check = wizard._refuse_linked_secret
    swapped: list[str] = []

    def check_then_swap(path: Path, dir_fd: int | None = None) -> Any:
        result = real_check(path, dir_fd)
        if path.name == "fin.username" and not swapped:
            swapped.append(path.name)
            (secrets_dir / "fin.username").unlink()
            if swap == "hard-link":
                os.link(root_only, secrets_dir / "fin.username")
            else:
                os.mkfifo(secrets_dir / "fin.username", 0o600)
        return result

    monkeypatch.setattr(wizard, "_refuse_linked_secret", check_then_swap)

    def blocked(signum: int, frame: Any) -> None:
        raise TimeoutError("the wizard blocked opening the old secret")

    previous = signal.signal(signal.SIGALRM, blocked)
    signal.alarm(10)
    try:
        with pytest.raises(wizard.WizardError, match="fin.username"):
            wizard.store_credentials(config, "fin", "new_user", "new_pw")
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)
    assert swapped
    copies = [p for p in secrets_dir.iterdir() if ".bak." in p.name]
    assert copies == [], [p.name for p in copies]
    assert root_only.read_text(encoding="utf-8") == "ROOT-ONLY CONTENT\n"
    assert (secrets_dir / "fin.password").read_text(encoding="utf-8") == "old_pw\n"
    assert not _tmp_leftovers(secrets_dir)


@POSIX_ONLY
def test_i39_the_copy_of_an_old_secret_belongs_to_the_account_that_owned_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """As root, the copy of a replaced secret goes to the account that owned
    the original, not to whoever owns the secrets directory now: root never
    hands a file's content to another account."""
    config = _private(tmp_path / "config.yaml", "application:\n  transport: stdio\n")
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    _trust_every_directory(monkeypatch)
    calls = _record_chowns(monkeypatch)
    wizard.store_credentials(config, "fin", "old_user", "old_pw")
    old = (tmp_path / "secrets" / "fin.username").stat()
    monkeypatch.setattr(wizard, "secret_owner", lambda *args, **kwargs: (4242, 4243))
    calls.clear()

    wizard.store_credentials(config, "fin", "new_user", "new_pw")
    # the directory and both staged files, then the copies of the old pair
    assert calls == [("fchown", 4242, 4243)] * 3 + [("fchown", old.st_uid, old.st_gid)] * 2


def test_i39_the_password_file_gives_its_first_line(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Fix-up round 2: the help says '(first line)', but the whole file,
    less its trailing line ending, became the password."""
    config = tmp_path / "config.yaml"
    config.write_text(f"application:\n  transport: stdio\n  audit_path: {tmp_path}/audit.jsonl\n", encoding="utf-8")
    rc = main(_pg_add_args(config, _private(tmp_path / "pw", "line1\r\nline2-something-else\n")))
    captured = capsys.readouterr()
    assert rc == 0, captured.err
    assert (tmp_path / "secrets" / "fin.password").read_text(encoding="utf-8") == "line1\n"


@pytest.mark.parametrize(
    ("content", "password"), [("pw", "pw"), ("pw\r\n", "pw"), ("\n", ""), ("", ""), ("\n  \n", "")]
)
def test_i39_the_password_is_the_first_line_less_its_ending(tmp_path: Path, content: str, password: str) -> None:
    path = tmp_path / "pw"
    path.write_bytes(content.encode("utf-8"))
    assert wizard.read_password_file(str(path)) == password


def test_i39_a_password_file_that_starts_with_an_empty_line_is_refused(tmp_path: Path) -> None:
    """Only the first line is read, so '\\nsecret' would register a
    password-less login; the old whole-file read stripped the blank line."""
    with pytest.raises(wizard.WizardError, match="starts with an empty line"):
        wizard.read_password_file(str(_private(tmp_path / "pw", "\nsecret\n")))


def test_i39_a_password_file_line_past_the_limit_is_refused(tmp_path: Path) -> None:
    path = _private(tmp_path / "pw", "a" * (wizard.PASSWORD_FILE_LIMIT + 1))
    with pytest.raises(wizard.WizardError, match="longer than"):
        wizard.read_password_file(str(path))
    assert wizard.read_password_file(str(_private(tmp_path / "ok", "a" * wizard.PASSWORD_FILE_LIMIT + "\n"))) == (
        "a" * wizard.PASSWORD_FILE_LIMIT
    )


@POSIX_ONLY
@pytest.mark.parametrize("planted", ["symlink", "hardlink", "fifo"])
def test_i39_as_root_a_password_file_that_is_a_link_or_not_a_file_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, planted: str
) -> None:
    """Fix-up round 2: as root, --password-file was read by name through
    any link, and its content went into a secret file the config's owner
    can read, so a name another account can swap would hand it a root-only
    file (macOS has no protected_symlinks or protected_hardlinks)."""
    root_only = _private(tmp_path / "root-only", "root-secret\n")
    path = tmp_path / "pw"
    keep: list[int] = []
    if planted == "symlink":
        path.symlink_to(root_only)
    elif planted == "hardlink":
        os.link(root_only, path)
    else:
        os.mkfifo(path)
        # a reader and a writer with a line queued: a wrong implementation
        # reads the line instead of blocking the suite
        keep.append(os.open(path, os.O_RDONLY | os.O_NONBLOCK))
        keep.append(os.open(path, os.O_WRONLY | os.O_NONBLOCK))
        os.write(keep[-1], b"fifo-secret\n")
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", str(os.getuid()))
    try:
        with pytest.raises(wizard.WizardError, match="password file"):
            wizard.read_password_file(str(path))
    finally:
        for fd in keep:
            os.close(fd)


@POSIX_ONLY
def test_i39_as_root_the_operators_own_password_file_is_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _private(tmp_path / "pw", "s3cret\nignored\n")
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", str(os.getuid()))
    assert wizard.read_password_file(str(path)) == "s3cret"


@POSIX_ONLY
@pytest.mark.skipif(sys.platform != "win32" and os.getuid() == 0, reason="a file root creates belongs to root")
def test_i39_as_root_a_password_file_of_another_account_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _private(tmp_path / "pw", "planted\n")
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.delenv("SUDO_UID", raising=False)  # root itself, not sudo: only root's files
    with pytest.raises(wizard.WizardError, match=f"belongs to uid {os.getuid()}"):
        wizard.read_password_file(str(path))


@POSIX_ONLY
def test_i39_without_root_a_linked_password_file_is_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    real = _private(tmp_path / "real", "pw\n")
    link = tmp_path / "link"
    link.symlink_to(real)
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    assert wizard.read_password_file(str(link)) == "pw"


# --- I40: no read-write switch -------------------------------------------------


@pytest.mark.parametrize("json_mode", [True, False], ids=["json", "text"])
def test_i40_read_write_is_refused_up_front_in_one_line(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], json_mode: bool
) -> None:
    config = tmp_path / "c.yaml"
    db = _sqlite_db(tmp_path / "d.db")
    args = ["add-connection", "--config", str(config), "--name", "w", "--engine", "sqlite",
            "--database", str(db), "--read-write", "--no-test"]  # fmt: skip
    rc = main([*args, "--json"] if json_mode else args)
    captured = capsys.readouterr()
    assert rc == 2
    assert captured.out == ""
    assert captured.err == "CONFIG_ERROR: read_only: false is not supported (v1 is read-only)\n"
    assert not config.exists()


def test_i40_read_write_is_not_advertised(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        main(["add-connection", "--help"])
    assert "--read-write" not in capsys.readouterr().out


def test_i40_the_interactive_wizard_does_not_ask_about_read_only(
    site: _Site, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    prompts = _scripted_input(monkeypatch, [*_interactive_fin_answers(site), "y"])
    rc = main(["add-connection", "--config", str(site.config)])
    out = capsys.readouterr().out
    assert rc == 0, out
    assert not [p for p in prompts if "read-only" in p.lower()], prompts
    fin = load_config(site.config).connections["fin"]
    assert fin.read_only is True and fin.tls.enabled
    assert "read_only" not in yaml.safe_load(site.config.read_text(encoding="utf-8"))["connections"]["fin"]


def test_i40_the_wizard_writes_no_read_only_key_and_keeps_a_hand_written_one(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = tmp_path / "config.yaml"
    db = _sqlite_db(tmp_path / "a.db")
    config.write_text(
        f"application:\n  transport: stdio\n  audit_path: {tmp_path}/audit.jsonl\n"
        f"connections:\n  kept:\n    type: sqlite\n    database: {db}\n    read_only: true\n",
        encoding="utf-8",
    )
    base = ["add-connection", "--json", "--no-test", "--config", str(config), "--engine", "sqlite",
            "--database", str(db)]  # fmt: skip
    assert main([*base, "--name", "new"]) == 0
    capsys.readouterr()
    assert main([*base, "--name", "kept"]) == 0
    result = json.loads(capsys.readouterr().out)
    connections = yaml.safe_load(config.read_text(encoding="utf-8"))["connections"]
    assert "read_only" not in connections["new"]
    assert connections["kept"]["read_only"] is True
    assert "read_only" in result["preserved_fields"] and "read_only" not in result["dropped_fields"]


# --- I41: configure-agents fails when an adapter fails closed --------------------


@pytest.fixture
def failing_detection(cursor_home: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Cursor is installed, but UDBMCP_CONFIG is a relative path to nothing,
    which every registering adapter refuses at detection."""
    (cursor_home / ".cursor").mkdir()
    monkeypatch.chdir(cursor_home.parent)
    monkeypatch.setenv("UDBMCP_CONFIG", "missing/config.yaml")
    return cursor_home


@pytest.mark.parametrize("json_mode", [True, False], ids=["json", "text"])
@pytest.mark.parametrize(
    "switches", [("--agent", "cursor"), ("--agent", "cursor", "--yes"), ("--yes",)], ids=["agent", "agent-yes", "yes"]
)
def test_i41_an_adapter_that_fails_closed_is_a_config_error(
    failing_detection: Path, capsys: pytest.CaptureFixture[str], json_mode: bool, switches: tuple[str, ...]
) -> None:
    rc = main(["configure-agents", *switches, *(["--json"] if json_mode else [])])
    captured = capsys.readouterr()
    assert rc == 2, captured.out + captured.err
    if json_mode:
        payload = json.loads(captured.out)
        assert payload["errors"] >= 1
        cursor = next(h for h in payload["harnesses"] if h["agent"] == "cursor")
        assert cursor["writable"] is False and "CONFIG_ERROR" in cursor["detail"]
    else:
        assert "CONFIG_ERROR" in captured.err and "cursor" in captured.err, captured.err
    assert not (failing_detection / ".cursor" / "mcp.json").exists()


def test_i41_plain_detection_still_succeeds_and_counts_the_errors(
    failing_detection: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = main(["configure-agents", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    failed = [h for h in payload["harnesses"] if h["status"] in ("adapter_error", "fail_closed")]
    assert failed and payload["errors"] == len(failed)


def test_i41_a_clean_detection_reports_no_errors(cursor_home: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (cursor_home / ".cursor").mkdir()
    rc = main(["configure-agents", "--json", "--agent", "cursor"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload["errors"] == 0


def _failing_apply(outcome: str) -> Any:
    """registry.apply_confirmed for a write that does not happen: a refused
    Plan, an unavailable adapter, or a crash mid-write."""
    from universal_db_mcp.agents.core import AgentConfigError, AgentStatus, Plan

    def apply(name: str, env: Any, home: Path, confirmed: bool) -> Plan:
        if outcome == "refused":
            return Plan(agent=name, status=AgentStatus.UNKNOWN_STATE_FAIL_CLOSED, summary="changed; refusing to write")
        if outcome == "adapter-error":
            raise AgentConfigError("cannot import universal_db_mcp under -I")
        raise RuntimeError("disk vanished")

    return apply


@pytest.mark.parametrize("mode", ["text", "json", "interactive"])
@pytest.mark.parametrize("outcome", ["refused", "adapter-error", "crash"])
def test_i41_a_confirmed_write_that_does_not_happen_fails_the_run(
    cursor_home: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], mode: str, outcome: str
) -> None:
    """Fix-up round 1: text mode printed the failed apply and exited 0, while
    --json exited 1 for the same outcome."""
    from universal_db_mcp.agents import registry

    (cursor_home / ".cursor").mkdir()
    monkeypatch.setattr(registry, "apply_confirmed", _failing_apply(outcome))
    args = ["configure-agents", "--agent", "cursor"]
    if mode == "interactive":
        _scripted_input(monkeypatch, ["y"])
    else:
        args.append("--yes")
    if mode == "json":
        args.append("--json")

    rc = main(args)
    captured = capsys.readouterr()
    assert rc == 1, captured.out + captured.err
    if mode == "json":
        assert json.loads(captured.out)["applied"][0]["status"] != "configured"
    else:
        assert "CONFIG_ERROR" in captured.err and "cursor" in captured.err, captured.err
    assert "NOTICE" not in captured.out + captured.err


@pytest.mark.parametrize("json_mode", [True, False], ids=["json", "text"])
def test_i41_a_harness_config_that_changes_before_the_write_fails_the_run(
    cursor_home: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], json_mode: bool
) -> None:
    """The reviewer's race with the real cursor adapter: mcp.json turns
    malformed between the plan and the write, and the adapter refuses."""
    from universal_db_mcp.agents import registry

    mcp_json = cursor_home / ".cursor" / "mcp.json"
    mcp_json.parent.mkdir()
    mcp_json.write_text(json.dumps({"mcpServers": {}}), encoding="utf-8")
    real_apply = registry.apply_confirmed

    def racing_apply(name: str, env: Any, home: Path, confirmed: bool) -> Any:
        mcp_json.write_text("{ not json", encoding="utf-8")  # the harness rewrote it
        return real_apply(name, env, home, confirmed)

    monkeypatch.setattr(registry, "apply_confirmed", racing_apply)
    rc = main(["configure-agents", "--agent", "cursor", "--yes", *(["--json"] if json_mode else [])])
    captured = capsys.readouterr()
    assert rc == 1, captured.out + captured.err
    assert "unknown_state_fail_closed" in captured.out
    assert mcp_json.read_text(encoding="utf-8") == "{ not json"


@pytest.fixture
def malformed_cursor(cursor_home: Path) -> Path:
    """~/.cursor/mcp.json is malformed before the run starts, so the cursor
    adapter detects UNKNOWN_STATE_FAIL_CLOSED without raising."""
    mcp_json = cursor_home / ".cursor" / "mcp.json"
    mcp_json.parent.mkdir()
    mcp_json.write_text("{ not json", encoding="utf-8")
    return mcp_json


@pytest.mark.parametrize("json_mode", [True, False], ids=["json", "text"])
@pytest.mark.parametrize(
    "switches", [("--agent", "cursor"), ("--agent", "cursor", "--yes"), ("--yes",)], ids=["agent", "agent-yes", "yes"]
)
def test_i41_a_harness_config_that_is_malformed_before_the_run_fails_it(
    malformed_cursor: Path, capsys: pytest.CaptureFixture[str], json_mode: bool, switches: tuple[str, ...]
) -> None:
    """Fix-up round 2: only an adapter that raised failed the run; one that
    failed closed at detection (a malformed or unreadable harness config)
    exited 0 with "errors": 0, although the same file turning
    malformed during the run exits 1."""
    rc = main(["configure-agents", *switches, *(["--json"] if json_mode else [])])
    captured = capsys.readouterr()
    assert rc == 2, captured.out + captured.err
    if json_mode:
        payload = json.loads(captured.out)
        cursor = next(h for h in payload["harnesses"] if h["agent"] == "cursor")
        assert cursor["status"] == "unknown_state_fail_closed" and cursor["writable"] is False
        assert payload["errors"] >= 1
        assert not [a for a in payload.get("applied", []) if a["agent"] == "cursor"]
    else:
        assert "FAIL CLOSED" in captured.out
    assert "CONFIG_ERROR" in captured.err and "cursor" in captured.err, captured.err
    assert malformed_cursor.read_text(encoding="utf-8") == "{ not json"


@pytest.mark.parametrize("json_mode", [True, False], ids=["json", "text"])
def test_i41_plain_detection_of_a_malformed_harness_config_succeeds(
    malformed_cursor: Path, capsys: pytest.CaptureFixture[str], json_mode: bool
) -> None:
    # text mode: --dry-run, so a harness installed on this machine is not
    # left pending confirmation (exit 1 without a TTY)
    rc = main(["configure-agents", "--json" if json_mode else "--dry-run"])
    captured = capsys.readouterr()
    assert rc == 0, captured.out + captured.err
    if json_mode:
        payload = json.loads(captured.out)
        failed = [h for h in payload["harnesses"] if h["status"] == "unknown_state_fail_closed"]
        assert [h["agent"] for h in failed] == ["cursor"]
        assert payload["errors"] == 1
    else:
        assert "FAIL CLOSED" in captured.out
    assert "CONFIG_ERROR" not in captured.err
    assert malformed_cursor.read_text(encoding="utf-8") == "{ not json"


# Final round, fix-up 1: the report named the wrong status for a relative
# UDBMCP_CONFIG and the comments counted a missing harness config as failed
# closed; these pin what the report and docs now say.


@pytest.mark.parametrize("json_mode", [True, False], ids=["json", "text"])
def test_i41_yes_with_dry_run_reports_a_failed_closed_harness_and_succeeds(
    malformed_cursor: Path, capsys: pytest.CaptureFixture[str], json_mode: bool
) -> None:
    rc = main(["configure-agents", "--yes", "--dry-run", *(["--json"] if json_mode else [])])
    captured = capsys.readouterr()
    assert rc == 0, captured.out + captured.err
    if json_mode:
        payload = json.loads(captured.out)
        assert payload["errors"] == 1 and "applied" not in payload
    else:
        assert "FAIL CLOSED" in captured.out
    assert "CONFIG_ERROR" not in captured.err
    assert malformed_cursor.read_text(encoding="utf-8") == "{ not json"


@pytest.mark.parametrize("json_mode", [True, False], ids=["json", "text"])
def test_i41_a_missing_harness_config_is_not_failed_closed(
    cursor_home: Path, capsys: pytest.CaptureFixture[str], json_mode: bool
) -> None:
    (cursor_home / ".cursor").mkdir()
    rc = main(["configure-agents", "--agent", "cursor", *(["--json"] if json_mode else ["--dry-run"])])
    captured = capsys.readouterr()
    assert rc == 0, captured.out + captured.err
    if json_mode:
        payload = json.loads(captured.out)
        assert payload["harnesses"][0]["status"] == "installed_unconfigured" and payload["errors"] == 0
    else:
        assert "installed_unconfigured" in captured.out and "FAIL CLOSED" not in captured.out
    assert "CONFIG_ERROR" not in captured.err
    assert not (cursor_home / ".cursor" / "mcp.json").exists()


def test_i41_a_relative_udbmcp_config_is_fail_closed_not_adapter_error(
    failing_detection: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The ConfigError that a relative UDBMCP_CONFIG naming no file raises is
    not an AgentConfigError: the harness is 'fail_closed' in --json and
    'fail-closed; skipped (adapter error: ...)' in text."""
    assert main(["configure-agents", "--json", "--agent", "cursor"]) == 2
    cursor = json.loads(capsys.readouterr().out)["harnesses"][0]
    assert cursor["status"] == "fail_closed" and cursor["writable"] is False
    assert cursor["detail"].startswith("ConfigError: CONFIG_ERROR: UDBMCP_CONFIG="), cursor["detail"]

    assert main(["configure-agents", "--agent", "cursor"]) == 2
    out = capsys.readouterr().out
    assert "fail-closed; skipped (adapter error: ConfigError: CONFIG_ERROR: UDBMCP_CONFIG=" in out, out
    assert "adapter-unavailable" not in out


def test_i41_an_adapter_that_cannot_be_imported_is_an_adapter_error(
    cursor_home: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from universal_db_mcp.agents import registry

    (cursor_home / ".cursor").mkdir()
    monkeypatch.setitem(registry.ADAPTER_MODULES, "cursor", "universal_db_mcp.agents.nonexistent_adapter_zz")
    assert main(["configure-agents", "--json", "--agent", "cursor"]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["harnesses"][0]["status"] == "adapter_error" and payload["errors"] == 1

    assert main(["configure-agents", "--agent", "cursor"]) == 2
    captured = capsys.readouterr()
    assert "adapter-unavailable; skipped" in captured.out
    assert "CONFIG_ERROR: cursor failed closed" in captured.err
    assert not (cursor_home / ".cursor" / "mcp.json").exists()


# --- I42: the HTTP evidence script rebases its config copy -------------------------


def test_i42_http_evidence_config_copy_keeps_the_relative_paths_of_the_original(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """config.mockdbs.yaml names its secret files relative to itself; the
    script's copy in a temp directory resolved them there, so serve exited 1
    with 'secret file ... is not readable'."""
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    original = checkout / "config.mockdbs.yaml"
    original.write_bytes((REPO / "config.mockdbs.yaml").read_bytes())
    raw = yaml.safe_load(original.read_text(encoding="utf-8"))
    for conn in raw["connections"].values():
        assert not os.path.isabs(conn["password_file"])
        secret = checkout / conn["password_file"]
        secret.parent.mkdir(parents=True, exist_ok=True)
        _private(secret, "pw\n")
        monkeypatch.setenv(conn["username_env"], "reader")
    # as the script does: the token file comes from the environment
    monkeypatch.setenv("UDBMCP_HTTP_BEARER_TOKEN_FILE", str(_private(tmp_path / "http-token", secrets.token_hex(32))))
    monkeypatch.chdir(tmp_path)
    evidence = _load_script("http_client_evidence")

    cfg = evidence.evidence_config(Path("checkout/config.mockdbs.yaml"), 8795)
    work = tmp_path / "work"
    work.mkdir()
    copy = work / "config.yaml"
    copy.write_text(yaml.safe_dump(cfg), encoding="utf-8")

    loaded, resolved = load_resolved(copy)
    assert len(resolved) == len(raw["connections"])
    assert loaded.application.transport == "http" and loaded.application.http_port == 8795
    assert loaded.application.audit_path == str(checkout / raw["application"]["audit_path"])


@POSIX_ONLY
def test_i42_a_symlinked_config_is_rebased_where_serve_rebases_it(tmp_path: Path) -> None:
    """Fix-up round 2: the copy was rebased onto the link's target
    (Path.resolve), while load_config rebases onto the directory the link
    sits in (os.path.abspath), so the evidence server read other secret,
    audit and cache files than `serve --config <link>` would."""
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / "config.mockdbs.yaml").write_bytes((REPO / "config.mockdbs.yaml").read_bytes())
    alt = tmp_path / "alt"
    alt.mkdir()
    link = alt / "config.yaml"
    link.symlink_to(checkout / "config.mockdbs.yaml")
    evidence = _load_script("http_client_evidence")

    cfg = evidence.evidence_config(link, 8795)
    served = load_config(link)
    assert cfg["application"]["audit_path"] == served.application.audit_path
    assert cfg["application"]["metadata_cache_path"] == served.application.metadata_cache_path
    assert cfg["application"]["audit_path"].startswith(str(alt))
    for name, conn in cfg["connections"].items():
        assert conn["password_file"] == served.connections[name].password_file


# --- I43: the demo probe logs in as the fixture's readers ------------------------


def test_i43_demo_probe_uses_the_accounts_the_fixture_script_prints() -> None:
    probe = _load_script("demo_agent_probe")
    script = (REPO / "scripts" / "fixtures" / "start_mock_dbs.sh").read_text(encoding="utf-8")
    exports = " ".join(line for line in script.splitlines() if "export UDBMCP_DEMO_" in line)
    printed = dict(re.findall(r"(UDBMCP_DEMO_\w+_USER)=([^\s\"]+)", exports))
    assert printed and probe.USER_ENV == printed


def test_i43_exported_accounts_win_over_the_probe_defaults() -> None:
    probe = _load_script("demo_agent_probe")
    env = probe.server_env({"UDBMCP_DEMO_MSSQL_USER": "site_reader", "PATH": "/bin"}, "c.yaml")
    assert env["UDBMCP_DEMO_MSSQL_USER"] == "site_reader"
    assert env["UDBMCP_DEMO_PG_USER"] == probe.USER_ENV["UDBMCP_DEMO_PG_USER"]
    assert env["UDBMCP_CONFIG"] == "c.yaml" and env["PATH"] == "/bin"


@pytest.mark.parametrize(
    "message",
    [
        "('28000', \"[28000] [Microsoft][ODBC Driver 18 for SQL Server][SQL Server]Login failed for user "
        "'udbmcp_ro'. (18456) (SQLDriverConnect)\")",
        "[Microsoft][ODBC Driver 18 for SQL Server][SQL Server]Login failed for user 'sa'.",
        "CONNECTION_ERROR: ODBC Driver 18 for SQL Server: (18456)",
        'SQL30082N  Security processing failed with reason "24" ("USERNAME AND/OR PASSWORD INVALID").',
    ],
)
def test_i43_a_login_failure_is_a_failure_not_a_staging_limitation(message: str) -> None:
    probe = _load_script("demo_agent_probe")
    assert probe.is_known_blocked_error(message) is False
    assert probe.query_error_check(message)["status"] == "failed"


@pytest.mark.parametrize(
    "message",
    [
        "IM002 [Microsoft][ODBC Driver 18 for SQL Server] not found",
        # live, 2026-09-27: the server redacts the quoted driver name
        "tool error: CONNECTION_ERROR: ConnectorError: RuntimeError: <redacted> is not installed on this machine "
        "(installed SQL Server ODBC drivers: none); it is an administrator-supplied OS package",
    ],
)
def test_i43_a_missing_odbc_driver_is_still_a_staging_limitation(message: str) -> None:
    probe = _load_script("demo_agent_probe")
    assert probe.query_error_check(message)["status"] == "blocked"


@pytest.mark.parametrize(
    "message",
    [
        "('42000', \"[42000] [Microsoft][ODBC Driver 18 for SQL Server][SQL Server]The SELECT permission was denied "
        "on the object 'Admissions', database 'hospital', schema 'dbo'. (229) (SQLExecDirectW)\")",
        "('42S02', \"[42S02] [Microsoft][ODBC Driver 18 for SQL Server][SQL Server]Invalid object name "
        "'dbo.Admissions'. (208) (SQLExecDirectW)\")",
        # live through the msodbc runner, 2026-09-27
        "Error executing tool db_query: QUERY_ERROR: ConnectorError: DataError: ('22012', '[22012] [Microsoft][ODBC "
        "Driver 18 for SQL Server][SQL Server]Divide by zero error encountered. (8134) (SQLExecDirectW)')",
        "('08001', '[08001] [Microsoft][ODBC Driver 18 for SQL Server]TCP Provider: Error code 0x2749 (10057) "
        "(SQLDriverConnect)')",
        '[IBM][CLI Driver] SQL30082N  Security processing failed with reason "1" ("PASSWORD EXPIRED").  '
        "SQLSTATE=08001 SQLCODE=-30082",
        '[IBM][CLI Driver] SQL30082N  Security processing failed with reason "19" ("USERID DISABLED or '
        'RESTRICTED").  SQLSTATE=08001 SQLCODE=-30082',
    ],
    ids=["mssql-229-permission", "mssql-208-object", "mssql-8134-runtime", "mssql-08001-unreachable",
         "db2-reason-1-expired", "db2-reason-19-disabled"],
)  # fmt: skip
def test_i43_any_other_engine_error_is_a_failure(message: str) -> None:
    """Fix-up round 1: every pyodbc error names '[ODBC Driver 18 for SQL
    Server]', so the bare 'ODBC Driver' marker counted every SQL Server
    failure as KNOWN-BLOCKED; 'SQL30082N' did the same for every Db2
    security failure, expired and disabled accounts included."""
    probe = _load_script("demo_agent_probe")
    assert probe.is_known_blocked_error(message) is False
    assert probe.query_error_check(message)["status"] == "failed"


@pytest.mark.parametrize(
    "message",
    [
        '[IBM][CLI Driver] SQL30082N  Security processing failed with reason "17" ("UNSUPPORTED FUNCTION").  '
        "SQLSTATE=08001 SQLCODE=-30082",
        "('01000', \"[01000] [unixODBC][Driver Manager]Can't open lib 'ODBC Driver 18 for SQL Server' : file not "
        'found (0) (SQLDriverConnect)")',
    ],
    ids=["db2-reason-17", "cant-open-lib"],
)
def test_i43_the_documented_limitations_are_still_blocked(message: str) -> None:
    probe = _load_script("demo_agent_probe")
    assert probe.query_error_check(message)["status"] == "blocked"


# live, 2026-09-27, UDBMCP_DEMO_DB2_USER=udbmcp_nouser: the server redacts the
# quoted reason code and its text
_DB2_LIVE_LOGIN_FAILURE = (
    "Error executing tool db_query: CONNECTION_ERROR: ConnectorError: Exception: [IBM][CLI Driver] SQL30082N  "
    "Security processing failed with reason <redacted>).  SQLSTATE=08001 SQLCODE=-30082"
)


def _probe_exception_text(tool_error: str) -> str:
    """str() of the exception the probe raises for a tool error, built from
    the SDK's own TextContent as the probe gets it."""
    from mcp.types import TextContent

    return str(RuntimeError(f"tool error: {[TextContent(type='text', text=tool_error)][:1]}"))


@pytest.mark.parametrize("cut", [None, 220, 188], ids=["whole", "report-cut", "cut-after-reason"])
def test_i43_a_db2_security_failure_whose_reason_was_redacted_is_a_failure(cut: int | None) -> None:
    """Fix-up round 2: the server redacts the SQL30082N reason ('reason
    <redacted>)'), and the classifier called a reason it could not read the
    staging limitation, so a wrong Db2 user left the probe 'passed'."""
    probe = _load_script("demo_agent_probe")
    message = _probe_exception_text(_DB2_LIVE_LOGIN_FAILURE)[:cut]
    assert "SQL30082N" in message and "reason" in message
    assert probe.is_known_blocked_error(message) is False
    check = probe.query_error_check(message)
    assert check["status"] == "failed" and check["passed"] is False


def test_i43_the_report_cuts_the_detail_but_classifies_the_whole_error() -> None:
    """The probe cut the error to 220 characters before classifying it, so
    a marker past the cut (a login failure after a long prefix) was lost."""
    probe = _load_script("demo_agent_probe")
    message = "tool error: " + "x" * 300 + " Login failed for user <redacted>. (18456)"
    check = probe.query_error_check(message)
    assert check["status"] == "failed"
    assert check["detail"] == "FAILED: " + message[: probe.DETAIL_LIMIT]
    blocked = probe.query_error_check("x" * 300 + " IM002 driver not found")
    assert blocked["status"] == "blocked" and len(blocked["detail"]) == len("KNOWN-BLOCKED: ") + probe.DETAIL_LIMIT


# --- I44: connection names are ASCII ---------------------------------------------


@pytest.mark.parametrize(
    "name",
    ["\u03acx", "\u03b1\u0301x", "caf\u00e9", "\u212ax", "\uff46in", "-x", "1x", "a b", ""],
    ids=["greek-precomposed", "greek-decomposed", "latin-accent", "kelvin-sign", "fullwidth", "dash", "digit",
         "space", "empty"],
)  # fmt: skip
def test_i44_connection_names_are_plain_ascii(name: str) -> None:
    with pytest.raises(wizard.WizardError, match="invalid connection name"):
        wizard.validate_connection_name(name)


@pytest.mark.parametrize("name", ["fin", "Fin_2", "a-b", "_x", "x" * 64])
def test_i44_ascii_names_are_accepted(name: str) -> None:
    assert wizard.validate_connection_name(name) == name


@pytest.mark.parametrize("name", ["CON", "con", "Prn", "AUX", "nul", "NUL", "COM0", "com1", "Com9", "LPT1", "lpt9"])
def test_i44_windows_device_names_are_refused_on_every_platform(name: str) -> None:
    """Fix-up round 2: the name derives '<secrets>/<name>.username', and on
    Windows 'NUL.username' is the NUL device whatever the extension. Refused
    everywhere, since a config moves between hosts."""
    with pytest.raises(wizard.WizardError, match="invalid connection name.*reserved"):
        wizard.validate_connection_name(name)


@pytest.mark.parametrize("name", ["console", "nul_x", "com10", "lpt", "aux-db", "CON_", "com"])
def test_i44_names_that_only_start_like_a_device_are_accepted(name: str) -> None:
    assert wizard.validate_connection_name(name) == name


def test_i44_a_device_name_writes_nothing(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    config = tmp_path / "config.yaml"
    config.write_text(f"application:\n  transport: stdio\n  audit_path: {tmp_path}/audit.jsonl\n", encoding="utf-8")
    before = config.read_bytes()
    rc = main(_pg_add_args(config, _private(tmp_path / "pw", "pass\n"), name="NUL"))
    err = capsys.readouterr().err
    assert rc != 0 and "invalid connection name" in err, err
    assert config.read_bytes() == before
    assert not (tmp_path / "secrets").exists()


def test_i44_canonically_equivalent_names_never_share_secret_files(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Review round 3: 'ά' precomposed and decomposed passed the casefold
    check; on APFS (normalization-insensitive) the second add replaced the
    first connection's credentials."""
    config = tmp_path / "config.yaml"
    config.write_text(f"application:\n  transport: stdio\n  audit_path: {tmp_path}/audit.jsonl\n", encoding="utf-8")
    before = config.read_bytes()
    for i, name in enumerate(("\u03acx", "\u03b1\u0301x")):
        rc = main(_pg_add_args(config, _private(tmp_path / f"pw{i}", f"pass-{i}\n"), name=name))
        err = capsys.readouterr().err
        assert rc != 0 and "invalid connection name" in err, err
    assert config.read_bytes() == before
    assert not (tmp_path / "secrets").exists()


# --- I45: a credential re-add replaces both environment forms ------------------------


def test_i45_a_re_add_without_a_password_drops_the_environment_password(
    site: _Site, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Review round 3 (F43): a password-less re-add dropped username_env but
    kept password_env, pairing the new account with the old password."""
    text = site.config.read_text(encoding="utf-8")
    env_credentials = "    username_env: FIN_USER\n    password_env: FIN_PASS\n"
    text = re.sub(r"    username_file: .*\n    password_file: .*\n", env_credentials, text)
    site.config.write_text(text, encoding="utf-8")
    rc = main(_add_args(site, username="new_user", password_file=str(_private(tmp_path / "empty", "\n"))))
    captured = capsys.readouterr()
    assert rc == 0, captured.err
    block = yaml.safe_load(site.config.read_text(encoding="utf-8"))["connections"]["fin"]
    assert "username_env" not in block and "password_env" not in block, block
    assert "password_file" not in block
    assert block["username_file"] == str(site.secrets / "fin.username")
    assert {"username_env", "password_env"} <= set(json.loads(captured.out)["dropped_fields"])


# --- I46: the config backup is a new file ------------------------------------------


@POSIX_ONLY
def test_i46_the_config_backup_never_writes_through_a_planted_link(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Review round 3 (F49): shutil.copy2 followed a symlink planted at the
    stamped backup name, so the run truncated and chmodded its target."""
    victim = tmp_path / "victim.conf"
    victim.write_text("important=1\n", encoding="utf-8")
    victim.chmod(0o644)
    config_dir = tmp_path / "cfg"
    config_dir.mkdir()
    config = _private(
        config_dir / "config.yaml", f"# h\napplication:\n  transport: stdio\n  audit_path: {tmp_path}/a.jsonl\n"
    )
    before = config.read_bytes()
    db = _sqlite_db(tmp_path / "x.db")
    monkeypatch.setattr(wizard, "_stamp", lambda: "20260927T000000000000Z")
    planted = config_dir / "config.yaml.bak.20260927T000000000000Z"
    planted.symlink_to(victim)

    rc = main(["add-connection", "--json", "--no-test", "--config", str(config), "--name", "n", "--engine", "sqlite",
               "--database", str(db)])  # fmt: skip
    err = capsys.readouterr().err
    assert rc != 0
    assert "could not back up" in err, err
    assert victim.read_text(encoding="utf-8") == "important=1\n"
    assert stat.S_IMODE(victim.stat().st_mode) == 0o644
    assert config.read_bytes() == before
    assert planted.is_symlink(), "a file the wizard did not create is left alone"
    assert not _tmp_leftovers(config_dir)


def test_i46_the_backup_holds_the_config_as_it_was(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    config = tmp_path / "config.yaml"
    config.write_text(f"application:\n  transport: stdio\n  audit_path: {tmp_path}/a.jsonl\n", encoding="utf-8")
    if sys.platform != "win32":
        config.chmod(0o640)
    before = config.read_bytes()
    db = _sqlite_db(tmp_path / "x.db")
    rc = main(["add-connection", "--json", "--no-test", "--config", str(config), "--name", "n", "--engine", "sqlite",
               "--database", str(db)])  # fmt: skip
    backup = Path(json.loads(capsys.readouterr().out)["backup"])
    assert rc == 0
    assert backup.read_bytes() == before
    if sys.platform != "win32":
        assert stat.S_IMODE(backup.stat().st_mode) == 0o640


@POSIX_ONLY
@pytest.mark.parametrize(("as_root", "expected"), [(False, 0o664), (True, 0o644)], ids=["user", "root"])
def test_i46_the_backup_takes_only_the_config_s_permission_bits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], as_root: bool, expected: int
) -> None:
    """Final round: the backup copied the config's whole mode, so a config
    its owner had made setuid and group-writable came back, after a sudo
    add-connection, as a root-owned setuid copy others could write. The
    mode asked for is checked too: a write by a non-root test process makes
    the kernel clear setuid, which a real root's write does not. Setuid, not
    setgid: the kernel drops setgid when the file's group is not one of the
    caller's (a tmp dir owned by a foreign group, macOS group inheritance)."""
    if not as_root and os.geteuid() == 0:
        pytest.skip("runs as root")
    config = tmp_path / "config.yaml"
    config.write_text(f"application:\n  transport: stdio\n  audit_path: {tmp_path}/a.jsonl\n", encoding="utf-8")
    config.chmod(0o4664)
    assert stat.S_IMODE(config.stat().st_mode) == 0o4664, "the owner may set these bits on its own file"
    db = _sqlite_db(tmp_path / "x.db")
    if as_root:
        monkeypatch.setattr(os, "geteuid", lambda: 0)
        _trust_every_directory(monkeypatch)
        _record_chowns(monkeypatch)
    created: dict[str, int] = {}
    create_file = wizard._create_file

    def record(path: Path, data: bytes, mode: int) -> None:
        created[path.name] = mode
        create_file(path, data, mode)

    monkeypatch.setattr(wizard, "_create_file", record)
    rc = main(["add-connection", "--json", "--no-test", "--config", str(config), "--name", "n", "--engine", "sqlite",
               "--database", str(db)])  # fmt: skip
    captured = capsys.readouterr()
    assert rc == 0, captured.err
    backup = Path(json.loads(captured.out)["backup"])
    assert created[backup.name] == expected, oct(created[backup.name])
    assert stat.S_IMODE(backup.stat().st_mode) == expected


# --- I47: the agent notice follows the config, not the chown --------------------------


@POSIX_ONLY
@pytest.mark.parametrize("target", ["per-user-stdio", "system", "http"])
def test_i47_root_writing_secrets_for_a_per_user_stdio_config_prints_the_agent_notice(
    site: _Site, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], target: str
) -> None:
    """Review round 3 (F81): the notice was printed only when nothing was
    chowned, so root writing secrets for a per-user stdio config (chowned to
    its owner) printed none."""
    import pwd

    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", str(os.getuid()))  # sudo from the account that owns the password file
    monkeypatch.setattr(wizard.getpass, "getuser", lambda: "root")
    _trust_every_directory(monkeypatch)
    _record_chowns(monkeypatch)
    if target == "system":
        monkeypatch.setattr(wizard, "_is_system_config", lambda path: True)
    elif target == "http":
        http = f"transport: http\n  http_bearer_token_file: {site.config.parent / 'http-token'}"
        site.config.write_text(
            site.config.read_text(encoding="utf-8").replace("transport: stdio", http), encoding="utf-8"
        )
    rc = main(_add_args(site))
    captured = capsys.readouterr()
    assert rc == 0, captured.err
    notices = [n for n in json.loads(captured.out)["notices"] if n.startswith("NOTICE")]
    if target == "system":
        assert notices == []
        return
    # an http per-user config too (fix-up round 1): every registration runs
    # `serve --transport stdio` as the account the secrets belong to
    owner = pwd.getpwuid(site.config.stat().st_uid).pw_name
    assert len(notices) == 1 and str(site.secrets) in notices[0]
    assert f"as {owner}," in notices[0] and "as root," not in notices[0], notices[0]


@pytest.mark.parametrize("transport", ["stdio", "http"])
def test_i47_a_per_user_config_gets_the_agent_notice_whatever_its_transport(
    site: _Site, capsys: pytest.CaptureFixture[str], transport: str
) -> None:
    """Fix-up round 1: the notice was left out for any per-user config with
    transport: http, although agent registrations always run the server over
    stdio as this user and an HTTP server started from it runs as this user
    too."""
    if transport == "http":
        token = _private(site.config.parent / "http-token", secrets.token_hex(32) + "\n")
        http = f"transport: http\n  http_bearer_token_file: {token}"
        site.config.write_text(
            site.config.read_text(encoding="utf-8").replace("transport: stdio", http), encoding="utf-8"
        )
    rc = main(_add_args(site))
    captured = capsys.readouterr()
    assert rc == 0, captured.err
    notices = [n for n in json.loads(captured.out)["notices"] if n.startswith("NOTICE")]
    assert len(notices) == 1 and str(site.secrets) in notices[0], notices


# --- I48: a startup failure reaches stderr with a log file set ------------------------


@POSIX_ONLY
def test_i48_a_bind_failure_reaches_stderr_when_logging_to_a_file(tmp_path: Path) -> None:
    """Review round 3 (F57): with UDBMCP_HTTP_LOG_FILE every record went to
    the file, so a service whose port was taken exited with nothing on
    stderr, which the launchd comments call the startup-failure log."""
    token = tmp_path / "http-token"
    token.write_text(secrets.token_hex(32) + "\n", encoding="utf-8")
    token.chmod(0o600)
    log_file = tmp_path / "http.log"
    with socket.socket() as held:
        held.bind(("127.0.0.1", 0))
        held.listen(1)
        port = held.getsockname()[1]
        config = tmp_path / "config.yaml"
        config.write_text(
            "application:\n"
            "  transport: http\n"
            "  http_host: 127.0.0.1\n"
            f"  http_port: {port}\n"
            f"  http_bearer_token_file: {token}\n"
            f"  audit_path: {tmp_path / 'audit.jsonl'}\n"
            f"  metadata_cache_path: {tmp_path / 'cache.sqlite'}\n",
            encoding="utf-8",
        )
        proc = subprocess.run(  # noqa: S603 - fixed argv, the interpreter running the tests
            [sys.executable, "-m", "universal_db_mcp", "serve", "--config", str(config)],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            env=dict(os.environ, UDBMCP_HTTP_LOG_FILE=str(log_file)),
            cwd=tmp_path,
            timeout=60,
            check=False,
        )
    stderr = proc.stderr.decode("utf-8", "replace")
    assert proc.returncode != 0
    assert "address already in use" in stderr.lower(), stderr
    assert "address already in use" in log_file.read_text(encoding="utf-8").lower()


def test_i48_the_log_file_mode_keeps_errors_on_stderr(tmp_path: Path, restore_logging: None) -> None:
    from logging.handlers import RotatingFileHandler

    from universal_db_mcp.http_protocol import LOG_FILE_ENV, configure_http_logging

    configure_http_logging({LOG_FILE_ENV: str(tmp_path / "http.log")})
    for logger in (logging.getLogger("uvicorn"), logging.getLogger()):
        to_stderr = [
            h for h in logger.handlers
            if isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler)
            and getattr(h, "stream", None) is sys.stderr
        ]
        assert len(to_stderr) == 1 and to_stderr[0].level == logging.ERROR, logger.handlers
        assert any(isinstance(h, RotatingFileHandler) for h in logger.handlers)


def test_i48_the_launchd_comments_match_the_logging() -> None:
    comments = PLIST.read_text(encoding="utf-8")
    assert "stderr is left for startup failures" not in comments
    assert "only carry startup failures" not in comments


# --- I49: serve names the default audit path ------------------------------------


@pytest.mark.parametrize("audit_path_set", [False, True], ids=["default", "configured"])
def test_i49_serve_names_the_default_audit_path_on_stderr_only(tmp_path: Path, audit_path_set: bool) -> None:
    home = tmp_path / "home"
    (home / ".universal-db-mcp").mkdir(parents=True)
    db = _sqlite_db(tmp_path / "a.db")
    audit = f"  audit_path: {tmp_path / 'audit.jsonl'}\n" if audit_path_set else ""
    config = tmp_path / "config.yaml"
    config.write_text(
        "application:\n"
        "  transport: stdio\n"
        f"{audit}"
        f"  metadata_cache_path: {tmp_path / 'cache.sqlite'}\n"
        "connections:\n"
        "  a:\n"
        "    type: sqlite\n"
        f"    database: {db}\n",
        encoding="utf-8",
    )
    proc = subprocess.run(  # noqa: S603 - fixed argv, the interpreter running the tests
        [sys.executable, "-m", "universal_db_mcp", "serve", "--config", str(config)],
        stdin=subprocess.DEVNULL,  # EOF: the stdio server stops at once
        capture_output=True,
        env=dict(os.environ, HOME=str(home), USERPROFILE=str(home)),
        cwd=tmp_path,
        timeout=60,
        check=False,
    )
    stderr = proc.stderr.decode("utf-8", "replace")
    assert proc.returncode == 0, stderr
    assert proc.stdout == b"", "stdout carries only the MCP protocol"
    user_dir = home / ".universal-db-mcp"
    line = (
        f"universal-db-mcp: application.audit_path is unset; auditing to {user_dir / 'audit.jsonl'} "
        f"(per-user state directory {user_dir})"
    )
    if audit_path_set:
        assert "audit_path is unset" not in stderr, stderr
    else:
        assert line in stderr.splitlines(), stderr


@POSIX_ONLY
def test_i46_a_new_config_is_never_created_through_a_planted_link(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Same class as the backup: a dangling symlink at a config path that
    does not exist yet made the run (root, say) create the file it names."""
    config_dir = tmp_path / "cfg"
    config_dir.mkdir()
    target = tmp_path / "cron.d-entry"
    (config_dir / "config.yaml").symlink_to(target)
    db = _sqlite_db(tmp_path / "x.db")
    rc = main(["add-connection", "--json", "--no-test", "--config", str(config_dir / "config.yaml"), "--name", "n",
               "--engine", "sqlite", "--database", str(db)])  # fmt: skip
    err = capsys.readouterr().err
    assert rc != 0 and "CONFIG_ERROR" in err, err
    assert not target.exists()
