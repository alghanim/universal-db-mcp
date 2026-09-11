"""CLI entry point: ``python -m universal_db_mcp <command>``.

Commands:
  serve    Run the MCP server (stdio by default; http optional).
  doctor   Check local artifacts and effective policy (no network).
  version  Print version and pinned SDK information.
"""

from __future__ import annotations

import argparse
import hmac
import os
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="universal_db_mcp",
        description="Universal Database MCP Server (air-gapped)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="run the MCP server")
    serve.add_argument("--transport", choices=["stdio", "http"], default=None)
    serve.add_argument("--config", default=None, help="path to config.yaml (default: $UDBMCP_CONFIG)")

    doctor = sub.add_parser("doctor", help="check local installation and policy")
    doctor.add_argument("--config", default=None)
    doctor.add_argument("--connectivity", action="store_true", help="also probe configured databases")

    sub.add_parser("version", help="print version information")

    args = parser.parse_args(argv)

    if args.command == "version":
        import mcp

        from universal_db_mcp import __version__

        print(f"universal-db-mcp {__version__}")
        print(f"mcp-sdk {getattr(mcp, '__version__', 'unknown')}")
        return 0

    if args.command == "doctor":
        import json

        from universal_db_mcp.diagnostics.doctor import run_doctor

        report = run_doctor(args.config or os.environ.get("UDBMCP_CONFIG"), connectivity=args.connectivity)
        print(json.dumps(report, indent=2))
        return 0 if report["healthy"] else 1

    if args.command == "serve":
        return _serve(args)

    parser.error(f"unknown command {args.command!r}")
    return 2


def _serve(args: argparse.Namespace) -> int:

    from universal_db_mcp.config import load_resolved
    from universal_db_mcp.server import AppContext, build_server

    config_path = args.config or os.environ.get("UDBMCP_CONFIG")
    if not config_path:
        print(
            "CONFIG_ERROR: no configuration; pass --config or set UDBMCP_CONFIG",
            file=sys.stderr,
        )
        return 1
    try:
        cfg, resolved = load_resolved(config_path)
    except Exception as exc:
        print(f"CONFIG_ERROR: {exc}", file=sys.stderr)
        return 1

    app = AppContext(cfg, resolved)
    server = build_server(app)

    transport = args.transport or cfg.application.transport
    if transport == "stdio":
        # stdout is protocol-only; keep our logs on stderr.
        # MCPServer.run owns its own anyio.run; do not wrap it again.
        server.run("stdio")
        return 0
    if transport == "http":
        return _serve_http(cfg, server)
    print(f"CONFIG_ERROR: unsupported transport '{transport}'", file=sys.stderr)
    return 1


def _serve_http(cfg, server) -> int:  # type: ignore[no-untyped-def]
    """Authenticated internal Streamable HTTP deployment.

    Bearer token is read from a local file (application.http_bearer_token_file).
    Bind defaults to loopback. Origin/host restrictions are enforced by the
    reverse proxy in front of this service (docs/offline-deployment.md)."""
    import uvicorn

    from universal_db_mcp.security.redact import SecretMark

    token_path = cfg.application.http_bearer_token_file
    if not token_path:
        print(
            "CONFIG_ERROR: http transport requires application.http_bearer_token_file",
            file=sys.stderr,
        )
        return 1
    with open(token_path, encoding="utf-8") as fh:
        raw_token = fh.read().strip()
    if not raw_token:
        print("CONFIG_ERROR: bearer token file is empty", file=sys.stderr)
        return 1
    token = SecretMark(raw_token)

    asgi_app = server.streamable_http_app()
    token_bytes = token.value.encode()

    async def _auth_app(scope, receive, send):  # type: ignore[no-untyped-def]
        # Pure ASGI bearer-auth wrapper (Starlette's app.middleware helper is
        # not available on a bare ASGI app).
        if scope["type"] != "http":
            await asgi_app(scope, receive, send)
            return
        auth = next((v for k, v in scope.get("headers", []) if k == b"authorization"), b"")
        if not (auth.startswith(b"Bearer ") and hmac.compare_digest(auth[7:], token_bytes)):
            await send(
                {
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [(b"www-authenticate", b"Bearer"), (b"content-type", b"application/json")],
                }
            )
            await send({"type": "http.response.body", "body": b'{"error": "unauthorized"}'})
            return
        await asgi_app(scope, receive, send)

    uvicorn.run(
        _auth_app,
        host=cfg.application.http_host,
        port=cfg.application.http_port,
        log_level="warning",
        access_log=False,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
