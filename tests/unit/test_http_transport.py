"""End-to-end checks for the Streamable HTTP transport.

Audit 2026-09-15: nothing in this repo had ever started the HTTP transport and
spoken MCP to it. Every HTTP "test" asserted on the text of packaging files,
and both protocol probes hardcode stdio - yet HTTP is the transport the daemon
deployment requires, because a service manager gives the process no stdin.

That gap hid a defect: the app was built with `streamable_http_app()` and no
host, so the SDK defaulted to 127.0.0.1 and auto-enabled DNS-rebinding
protection pinned to loopback Host headers. Every client connecting by
hostname - the documented cross-machine setup, and any reverse proxy that
forwards the original Host - was answered 421, while the code comment said
host checking was the proxy's job.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from universal_db_mcp.__main__ import build_http_app
from universal_db_mcp.config import load_resolved
from universal_db_mcp.server import AppContext, build_server

TOKEN = "test-bearer-token-value"  # noqa: S105 - test fixture, not a real secret
INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "audit-probe", "version": "1.0"},
    },
}


@pytest.fixture
def http_server(tmp_path: Path) -> tuple[Any, Any]:
    db = tmp_path / "demo.db"
    db.touch()
    token_file = tmp_path / "http-token"
    token_file.write_text(TOKEN + "\n", encoding="utf-8")
    token_file.chmod(0o600)
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(
        "application:\n"
        "  transport: http\n"
        "  http_host: 0.0.0.0\n"
        "  http_port: 8765\n"
        f"  http_bearer_token_file: {token_file}\n"
        f"  audit_path: {tmp_path / 'audit.jsonl'}\n"
        f"  metadata_cache_path: {tmp_path / 'cache.sqlite'}\n"
        "connections:\n"
        "  demo:\n    type: sqlite\n"
        f"    database: {db}\n",
        encoding="utf-8",
    )
    cfg, resolved = load_resolved(cfg_path)
    return cfg, build_server(AppContext(cfg, resolved))


class _Response:
    """What the ASGI app sent back."""

    def __init__(self) -> None:
        self.status_code = 0
        self.headers: dict[str, str] = {}
        self.body = b""

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def json(self) -> Any:
        return json.loads(self.text)


async def _request(app: Any, headers: dict[str, str], body: dict[str, Any]) -> _Response:
    payload = json.dumps(body).encode()
    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/mcp",
        "raw_path": b"/mcp",
        "query_string": b"",
        "root_path": "",
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
        "client": ("10.0.0.5", 51234),
        "server": ("0.0.0.0", 8765),  # noqa: S104 - ASGI scope of a non-loopback bind
    }
    response = _Response()
    chunks: list[bytes] = []
    got_body = asyncio.Event()
    sent_request = {"done": False}

    async def receive() -> dict[str, Any]:
        if sent_request["done"]:
            await asyncio.sleep(3600)  # client keeps the stream open
        sent_request["done"] = True
        return {"type": "http.request", "body": payload, "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        if message["type"] == "http.response.start":
            response.status_code = message["status"]
            response.headers = {k.decode().lower(): v.decode() for k, v in message.get("headers", [])}
        elif message["type"] == "http.response.body":
            chunks.append(message.get("body", b""))
            if chunks and b"".join(chunks).strip():
                got_body.set()

    task = asyncio.create_task(app(scope, receive, send))
    done = asyncio.create_task(got_body.wait())
    await asyncio.wait({task, done}, timeout=20, return_when=asyncio.FIRST_COMPLETED)
    for pending in (task, done):
        if not pending.done():
            pending.cancel()
    response.body = b"".join(chunks)
    return response


def _post(app: Any, headers: dict[str, str], body: dict[str, Any]) -> _Response:
    """Drive the ASGI app directly, lifespan included: no HTTP client
    dependency is added to an air-gapped project to exercise its own
    transport."""

    async def go() -> _Response:
        lifespan_in: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        started = asyncio.Event()

        async def lifespan_receive() -> dict[str, Any]:
            return await lifespan_in.get()

        async def lifespan_send(message: dict[str, Any]) -> None:
            if message["type"].startswith("lifespan.startup"):
                started.set()

        lifespan = asyncio.create_task(
            app({"type": "lifespan", "asgi": {"version": "3.0"}}, lifespan_receive, lifespan_send)
        )
        await lifespan_in.put({"type": "lifespan.startup"})
        try:
            await asyncio.wait_for(started.wait(), timeout=15)
            return await _request(app, headers, body)
        finally:
            await lifespan_in.put({"type": "lifespan.shutdown"})
            lifespan.cancel()

    return asyncio.run(go())


def _headers(token: str | None = TOKEN) -> dict[str, str]:
    headers = {
        "Host": "udbmcp.internal.example:8765",
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def test_initialize_succeeds_for_a_client_connecting_by_hostname(http_server: tuple[Any, Any]) -> None:
    cfg, server = http_server
    response = _post(build_http_app(cfg, server, TOKEN), _headers(), INITIALIZE)

    assert response.status_code != 421, (
        "421 means the SDK's loopback host check is active: the bind host was not passed through"
    )
    assert response.status_code == 200, response.text
    assert "protocolVersion" in response.text, response.text[:300]


def test_negotiated_protocol_version_is_reported(http_server: tuple[Any, Any]) -> None:
    cfg, server = http_server
    response = _post(build_http_app(cfg, server, TOKEN), _headers(), INITIALIZE)

    payload = None
    for line in response.text.splitlines():
        if line.startswith("data: "):
            payload = json.loads(line[6:])
            break
    if payload is None:  # json_response mode
        payload = response.json()
    assert payload["result"]["protocolVersion"], payload
    assert payload["result"]["serverInfo"]["name"], payload


def test_missing_bearer_is_401(http_server: tuple[Any, Any]) -> None:
    cfg, server = http_server
    response = _post(build_http_app(cfg, server, TOKEN), _headers(token=None), INITIALIZE)
    assert response.status_code == 401
    assert response.headers.get("www-authenticate", "").startswith("Bearer")


def test_wrong_bearer_is_401(http_server: tuple[Any, Any]) -> None:
    cfg, server = http_server
    response = _post(
        build_http_app(cfg, server, TOKEN),
        _headers(token="wrong"),  # noqa: S106 - deliberately invalid token
        INITIALIZE,
    )
    assert response.status_code == 401


def test_sdk_rejects_hostname_clients_when_the_bind_host_is_not_passed(
    http_server: tuple[Any, Any]
) -> None:
    """Pins the SDK behavior this fix exists for: with no host argument the
    transport answers 421 to exactly the deployment our docs describe."""
    _cfg, server = http_server
    raw_app = server.streamable_http_app()

    response = _post(raw_app, _headers(), INITIALIZE)

    assert response.status_code == 421, (
        "if this stops being 421 the SDK changed its auto-protection default"
    )
