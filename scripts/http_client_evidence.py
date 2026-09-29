#!/usr/bin/env python3
"""HTTP transport evidence: a real MCP client over TLS through a reverse proxy.

    .venv/bin/python scripts/http_client_evidence.py --config config.mockdbs.yaml

Starts the server in HTTP mode (bearer token file) on loopback, puts an
nginx TLS terminator in front of it (self-signed certificate, Docker,
proxying to the host), and drives it with the MCP SDK's streamable HTTP
client the way a remote agent would: initialize, list tools, call a tool,
then the negatives (wrong token, no token) which must be refused with 401
before any tool runs. Writes test-evidence/http-transport/results.txt.
"""
from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import os
import secrets
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import httpx2 as httpx  # noqa: E402 - the mcp 2.x SDK's HTTP stack
from mcp.client.session import ClientSession  # noqa: E402
from mcp.client.streamable_http import streamable_http_client  # noqa: E402

NGINX_CONF = """
events {}
http {
  server {
    listen 8443 ssl;
    ssl_certificate /certs/server.crt;
    ssl_certificate_key /certs/server.key;
    location / {
      proxy_pass http://host.docker.internal:%(port)d;
      proxy_http_version 1.1;
      # the server validates Host against its own listener (DNS-rebinding
      # protection); a reverse proxy must present the listener's address
      proxy_set_header Host 127.0.0.1:%(port)d;
      proxy_set_header Connection "";
      proxy_buffering off;
      proxy_read_timeout 300s;
    }
  }
}
"""


def _leaves(exc: BaseException) -> list[str]:
    """The innermost exceptions of an (anyio) exception group, as text."""
    subs = getattr(exc, "exceptions", None)
    if subs:
        return [line for sub in subs for line in _leaves(sub)]
    return [f"{type(exc).__name__}: {str(exc)[:160]}"]


async def _mcp_round_trip(url: str, token: str | None, ca_file: str) -> dict:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    ctx = ssl.create_default_context(cafile=ca_file)
    async with httpx.AsyncClient(headers=headers, verify=ctx, timeout=60.0) as client:
        async with streamable_http_client(url, http_client=client) as (read, write):
            async with ClientSession(read, write) as session:
                init = await session.initialize()
                tools = await session.list_tools()
                names = sorted(t.name for t in tools.tools)
                result = await session.call_tool("db_list_connections", {})
                info = getattr(init, "server_info", None) or getattr(init, "serverInfo", None)
                return {
                    "server": getattr(info, "name", None),
                    "protocol": getattr(init, "protocol_version", None) or getattr(init, "protocolVersion", None),
                    "tools": len(names),
                    "has_review": "db_review_schema" in names,
                    "call_ok": not (getattr(result, "is_error", None) or getattr(result, "isError", False)),
                }


def evidence_config(config: Path, port: int) -> dict:
    """The config the evidence server runs with: *config* with
    application.http_host/http_port/transport overridden for the loopback
    listener. The copy lives in a temp directory, so the paths the original
    gives relative to itself (config.mockdbs.yaml's secret files and state)
    are made absolute against the original's directory first: the one
    load_config uses, where a symlinked *config* sits, not its target."""
    import yaml  # the config is YAML

    from universal_db_mcp.config import _resolve_relative_paths

    cfg = yaml.safe_load(config.read_text(encoding="utf-8"))
    _resolve_relative_paths(cfg, Path(os.path.abspath(config)).parent)
    cfg.setdefault("application", {})["http_host"] = "127.0.0.1"
    cfg["application"]["http_port"] = int(port)
    cfg["application"]["transport"] = "http"
    return cfg


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config.mockdbs.yaml")
    ap.add_argument(
        "--port", type=int, default=8795,
        help="loopback port for the evidence server (a copy of the config with application.http_port set to it "
        "is used, so an installed service on 8765 is untouched)",
    )
    ap.add_argument("--tls-port", type=int, default=8443)
    args = ap.parse_args()
    out: list[str] = [
        "# HTTP transport: a real MCP client (mcp SDK streamable HTTP) over TLS through nginx to the server",
        f"date_utc: {dt.datetime.now(dt.UTC).strftime('%Y-%m-%dT%H:%M:%SZ')}",
    ]
    work = Path(tempfile.mkdtemp(prefix="udbmcp-http-"))
    token = secrets.token_hex(32)
    token_file = work / "http-token"
    token_file.write_text(token + "\n", encoding="utf-8")
    token_file.chmod(0o600)
    certs = work / "certs"
    certs.mkdir()
    subprocess.run(  # noqa: S603, S607 - staging-only evidence script, fixed argv
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(certs / "server.key"),
         "-out", str(certs / "server.crt"), "-days", "2", "-subj", "/CN=localhost",
         "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
        check=True, capture_output=True,
    )
    (work / "nginx.conf").write_text(NGINX_CONF % {"port": args.port}, encoding="utf-8")
    import yaml

    config_copy = work / "config.yaml"
    config_copy.write_text(yaml.safe_dump(evidence_config(Path(args.config), args.port)), encoding="utf-8")
    env = dict(os.environ)
    env["UDBMCP_HTTP_BEARER_TOKEN_FILE"] = str(token_file)
    server: subprocess.Popen[str] | None = None
    nginx = f"udbmcp-tls-proxy-{os.getpid()}"  # unique: a stale container of another run is never reused
    stderr_path = work / "server.stderr"  # a file, so a chatty server can never block on a full pipe
    try:
        with stderr_path.open("w", encoding="utf-8") as stderr_file:
            server = subprocess.Popen(  # noqa: S603 - our own interpreter and config
                [str(ROOT / ".venv/bin/python"), "-m", "universal_db_mcp", "serve", "--transport", "http",
                 "--config", str(config_copy)],
                env=env, stdout=subprocess.DEVNULL, stderr=stderr_file, text=True,
            )
        subprocess.run(  # noqa: S603, S607 - fixed argv
            ["docker", "run", "-d", "--name", nginx, "-p", f"127.0.0.1:{args.tls_port}:8443",
             "-v", f"{work / 'nginx.conf'}:/etc/nginx/nginx.conf:ro", "-v", f"{certs}:/certs:ro",
             "nginx:1.27-alpine"],
            check=True, capture_output=True,
        )
        url = f"https://localhost:{args.tls_port}/mcp"
        ready = False
        for _ in range(60):
            try:
                r = httpx.get(url, verify=ssl.create_default_context(cafile=str(certs / "server.crt")), timeout=3.0)
                ready = r.status_code in (401, 405, 406, 400)
                if ready:
                    break
            except Exception:  # noqa: BLE001, S110 - still starting
                pass
            time.sleep(1)
        out.append(f"== proxy + server ready: {ready} (url {url}, server on 127.0.0.1:{args.port}, token file 0600)")
        if not ready:
            err = stderr_path.read_text(encoding="utf-8", errors="replace") if stderr_path.exists() else ""
            out.append(f"   server stderr: {err[-400:]}")
        t0 = time.monotonic()
        try:
            res = asyncio.run(_mcp_round_trip(url, token, str(certs / "server.crt")))
            out.append(
                f"== authenticated client over TLS: initialize ok (server={res['server']}, "
                f"protocol={res['protocol']}), tools listed={res['tools']} "
                f"(db_review_schema present={res['has_review']}), db_list_connections call ok={res['call_ok']}, "
                f"{time.monotonic() - t0:.2f}s"
            )
        except Exception as exc:  # noqa: BLE001 - recorded, not hidden
            detail = getattr(exc, "message", None) or str(exc)
            code = getattr(exc, "code", None)
            inner = _leaves(exc)
            out.append(
                f"== authenticated client over TLS: FAILED ({type(exc).__name__} code={code}: {str(detail)[:120]})"
            )
            for line in inner[:4]:
                out.append(f"   {line}")
            out.append("   NOT REFUSED-check skipped: the positive path failed")
        # the SDK client folds an HTTP 401 into a generic MCP error, so the
        # status code itself is taken from a direct request as well
        init_body = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                     "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                                "clientInfo": {"name": "evidence", "version": "0"}}}
        for label, hdrs in (("wrong token", {"Authorization": "Bearer not-the-token"}), ("no token", {})):
            r = httpx.post(url, json=init_body, headers={**hdrs, "Accept": "application/json, text/event-stream"},
                           verify=ssl.create_default_context(cafile=str(certs / "server.crt")), timeout=10.0)
            out.append(f"== {label}, direct POST initialize: HTTP {r.status_code}"
                       + (" (refused before any tool ran)" if r.status_code in (401, 403) else " (investigate)"))
        for label, tok in (("wrong token", "not-the-token"), ("no token", None)):
            try:
                asyncio.run(_mcp_round_trip(url, tok, str(certs / "server.crt")))
                out.append(f"== {label}: NOT REFUSED (investigate)")
            except BaseException as exc:  # noqa: BLE001 - the refusal is the evidence (anyio wraps it in a group)
                text = " | ".join(_leaves(exc)) or str(exc)
                code = "401" if "401" in text else ("403" if "403" in text else "MCP error")
                out.append(f"== {label}, SDK client: refused ({code}: {text[:120]})")
        try:
            r = httpx.get(f"http://localhost:{args.tls_port}/mcp", timeout=3.0)
            if r.status_code == 400:
                out.append(
                    "== plain HTTP on the TLS port: refused by the proxy (400 plain HTTP request sent to HTTPS port)"
                )
            else:
                out.append(f"== plain HTTP on the TLS port: answered {r.status_code} (investigate)")
        except Exception as exc:  # noqa: BLE001
            out.append(f"== plain HTTP on the TLS port: refused ({type(exc).__name__})")
    finally:
        # cleanup runs whatever failed above: the proxy container, the server, the scratch dir
        subprocess.run(["docker", "rm", "-f", nginx], capture_output=True)  # noqa: S603, S607
        if server is not None:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
        shutil.rmtree(work, ignore_errors=True)
    ev = ROOT / "test-evidence" / "http-transport"
    ev.mkdir(parents=True, exist_ok=True)
    text = "\n".join(out) + "\n"
    (ev / "results.txt").write_text(text, encoding="utf-8")
    print(text)
    ok = "NOT REFUSED" not in text and "ready: True" in text and "(investigate)" not in text and "FAILED" not in text
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
