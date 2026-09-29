"""CLI entry point: ``python -m universal_db_mcp <command>``.

Commands:
  serve             Run the MCP server (stdio by default; http optional).
  doctor            Check local artifacts and effective policy (no network).
  version           Print version and pinned SDK information.
  configure-agents  Register the server into detected AI-agent harnesses
                    (ask-before-write; see docs/claude-code-integration.md).
"""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import sys
import textwrap
from collections.abc import Mapping
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import anyio
    from mcp.server.mcpserver import MCPServer

# The installers generate 64 hex characters (secrets.token_hex(32)).
_MIN_BEARER_TOKEN_CHARS = 32


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

    site = sub.add_parser(
        "site-check",
        help="read-only first-run check of every configured connection; writes a JSON report with counts, "
        "codes and timings only (no row values), suitable to take off-site for diagnosis",
    )
    site.add_argument("--config", default=None)
    site.add_argument(
        "--out", default=None,
        help="write the JSON report here (mode 0600, never over an existing file); stdout otherwise",
    )
    site.add_argument(
        "--force", action="store_true",
        help="replace an existing --out file (only a regular file you own; a symlink is refused)",
    )
    site.add_argument("--sample-rows", type=int, default=200)
    site.add_argument("--review-tables", type=int, default=3)

    configure = sub.add_parser(
        "configure-agents",
        help="register the MCP server into detected AI-agent harnesses (ask-before-write)",
    )
    configure.add_argument(
        "--dry-run",
        action="store_true",
        help="print what would be written; never prompt and never write",
    )
    configure.add_argument(
        "--yes",
        action="store_true",
        help="apply without interactive confirmation (for non-interactive use)",
    )
    configure.add_argument(
        "--agent",
        default=None,
        metavar="NAME",
        help="only consider one harness (claude-code, claude-desktop, dsh, cursor, vscode, cline)",
    )
    configure.add_argument(
        "--json",
        action="store_true",
        help="machine-readable output for GUI front ends; never prompts and never "
        "writes unless --yes is also given (then applies only the writable "
        "harness(es), restricted to --agent when set)",
    )

    add_conn = sub.add_parser(
        "add-connection",
        help="interactive wizard: add a database connection to a config file",
    )
    add_conn.add_argument(
        "--config", default=None,
        help="config file to edit (default: the per-user/harness-resolved config)",
    )
    add_conn.add_argument("--name", default=None, help="connection name (skips the prompt)")
    add_conn.add_argument(
        "--engine", default=None,
        choices=["sqlite", "postgres", "mysql", "clickhouse", "oracle", "mssql", "db2"],
        help="engine type (skips the prompt)",
    )
    add_conn.add_argument("--host", default=None)
    add_conn.add_argument("--port", type=int, default=None)
    add_conn.add_argument("--database", default=None)
    add_conn.add_argument(
        "--username", default=None,
        help="username (stored in a private secrets file, never in the config)",
    )
    add_conn.add_argument(
        "--password-file", default=None,
        help="file with the password (first line; as root, a regular file of root or the sudo user, not a "
        "link, in a directory only they can change); the password itself is only read interactively",
    )
    # Kept only to refuse it in one line: every connection is read-only (v1).
    add_conn.add_argument("--read-write", action="store_true", help=argparse.SUPPRESS)
    add_conn.add_argument("--no-test", action="store_true", help="skip the live connection test")
    add_conn.add_argument(
        "--tls-ca-file",
        help="enable TLS for this connection and verify the server against this CA certificate "
        "(without it the server refuses every call while security.require_remote_tls is on)",
    )
    add_conn.add_argument(
        "--json", action="store_true",
        help="machine-readable result (non-interactive: all flags required)",
    )
    add_conn.add_argument(
        "--replace", action="store_true",
        help="replace an existing connection's whole block (needed to change its engine); without it "
        "only the fields the wizard sets are updated and allowed_schemas, session, options etc. are kept",
    )
    add_conn.add_argument(
        "--accept-comment-loss", action="store_true",
        help="go ahead although the config has comments after its leading header, which the rewrite "
        "drops (the .bak keeps them); interactive runs ask instead",
    )

    args = parser.parse_args(argv)

    if args.command == "version":
        import mcp

        from universal_db_mcp import __version__

        print(f"universal-db-mcp {__version__}")
        # The mcp package defines no __version__, so the attribute lookup
        # always fell through to "unknown": the one command whose job is to
        # report the pinned SDK reported nothing, and a wheel that resolved a
        # different 2.x was undetectable.
        try:
            mcp_version = importlib.metadata.version("mcp")
        except importlib.metadata.PackageNotFoundError:  # pragma: no cover
            mcp_version = getattr(mcp, "__version__", "unknown")
        print(f"mcp-sdk {mcp_version}")
        return 0

    if args.command == "doctor":
        import json

        from universal_db_mcp.agents.core import resolve_harness_config_path
        from universal_db_mcp.diagnostics.doctor import run_doctor

        # Bare `udbmcp doctor` resolves the SAME default config as the wizard
        # and configure-agents (env override -> READABLE system deployment ->
        # per-user). Failing with "no config path" while a valid per-user
        # config sits beside the command made the doctor useless exactly when
        # the user needed it (seen live 2026-09-15).
        config = (
            args.config
            or os.environ.get("UDBMCP_CONFIG")
            or resolve_harness_config_path(dict(os.environ), Path.home())
        )
        report = run_doctor(config, connectivity=args.connectivity)
        print(json.dumps(report, indent=2))
        return 0 if report["healthy"] else 1

    if args.command == "site-check":
        import json

        from universal_db_mcp.agents.core import resolve_harness_config_path
        from universal_db_mcp.diagnostics.site_check import render_summary, run_site_check, write_report

        config = (
            args.config
            or os.environ.get("UDBMCP_CONFIG")
            or resolve_harness_config_path(dict(os.environ), Path.home())
        )
        report = run_site_check(config, sample_rows=args.sample_rows, review_tables=args.review_tables)
        if args.out:
            write_report(report, args.out, force=bool(args.force))
            print(render_summary(report))
            print(f"report written to {args.out}")
        else:
            print(json.dumps(report, indent=2, default=str))
            print(render_summary(report), file=sys.stderr)
        return 0 if report["ok"] else 1

    if args.command == "serve":
        return _serve(args)

    if args.command == "configure-agents":
        return _configure_agents(args)

    if args.command == "add-connection":
        return _add_connection(args)

    parser.error(f"unknown command {args.command!r}")
    return 2


def _serve(args: argparse.Namespace) -> int:
    from universal_db_mcp import http_protocol

    if os.environ.get(http_protocol.LOG_FILE_ENV):
        # Set by the service definitions. Under launchd stdout and stderr are
        # files nothing rotates: cap them before anything is printed, so a
        # crash loop (a failure per start) stays bounded.
        http_protocol.cap_service_output()

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
        if cfg.application.audit_path_default:
            # stderr: in stdio mode stdout carries only the protocol
            print(
                f"universal-db-mcp: application.audit_path is unset; auditing to {cfg.application.audit_path} "
                f"({cfg.application.audit_path_default})",
                file=sys.stderr,
            )
        # AppContext opens the audit log and the metadata cache; a failure
        # there (unwritable audit file, corrupt cache file) is a startup
        # configuration failure and must surface as CONFIG_ERROR, not a
        # raw traceback.
        app = AppContext(cfg, resolved)
        server = build_server(app)
    except Exception as exc:
        print(f"CONFIG_ERROR: {exc}", file=sys.stderr)
        return 1

    transport = args.transport or cfg.application.transport
    if transport == "stdio":
        # stdout is protocol-only; keep our logs on stderr.
        _serve_stdio(server)
        return 0
    if transport == "http":
        return _serve_http(cfg, server)
    print(f"CONFIG_ERROR: unsupported transport '{transport}'", file=sys.stderr)
    return 1


# After SIGTERM, how long cancelled tool calls get to write their audit records
# before the process exits although a worker thread is still blocked.
_SIGTERM_GRACE_SECONDS = 2.0
# After SIGTERM, when the kernel ends the process whatever Python is doing: the
# watchdog above is a thread and needs the GIL, which a C call can keep (a
# cancel hook the SIGTERM fired, blocked against a frozen host; see
# _serve_stdio for what the alarm cannot cover). Above the executor's
# cancel-hook budget (services/executor.py, 2 s) plus the audit write.
_SIGTERM_HARD_EXIT_SECONDS = 5


def _serve_stdio(server: MCPServer) -> None:
    """Serve MCP over stdio; SIGTERM cancels in-flight calls instead of killing them.

    SIGTERM is the MCP stdio shutdown escalation and what service managers and
    container stop send. Its default action ended the process at once, so a
    tool call whose statement had already run left no audit record: tool_span
    writes it in a shielded finally block that never ran. Here SIGTERM cancels
    the server task group and those finally blocks write the 'cancelled'
    records. The stdio transport reads stdin in a worker thread that
    cancellation cannot interrupt, so while the client keeps stdin open the
    process exits after a short grace instead of waiting for the next line,
    and an alarm ends it even when no Python code can run any more.

    The alarm is armed by the Python-level handler, so it covers a cancel
    hook that the SIGTERM itself fires and that then holds the GIL. It does
    not cover anything that already holds the GIL when the SIGTERM arrives:
    a driver call, or a cancel hook the statement deadline or a client
    cancel fired earlier. The handler then runs only once that call returns.
    No shipped driver call was seen doing so (ibm_db, measured live,
    releases the GIL), and the PostgreSQL cancel hook no longer uses libpq's
    GIL-holding PQcancel. For a call that does, the stop still relies on the
    client or supervisor escalating to SIGKILL, as the MCP stdio shutdown
    sequence, systemd, launchd and docker stop all do.

    Runs ``run_stdio_async`` under our own ``anyio.run``, exactly as
    ``MCPServer.run("stdio")`` does (never wrap ``server.run`` itself: it owns
    an ``anyio.run``).
    """
    import anyio

    if sys.platform == "win32":  # no SIGTERM delivery to handle
        server.run("stdio")
        return

    async def _main() -> None:
        async with anyio.create_task_group() as tg:
            tg.start_soon(_cancel_on_sigterm, tg.cancel_scope)
            await server.run_stdio_async()
            tg.cancel_scope.cancel()

    anyio.run(_main)


async def _cancel_on_sigterm(scope: anyio.CancelScope) -> None:
    import signal
    import threading

    import anyio

    with anyio.open_signal_receiver(signal.SIGTERM) as signals:
        async for _signum in signals:
            break
    # The receiver is closed again, so a second SIGTERM kills at once. The
    # alarm's default action ends the process in the kernel, with no Python
    # thread (and no GIL) needed.
    signal.signal(signal.SIGALRM, signal.SIG_DFL)
    signal.alarm(_SIGTERM_HARD_EXIT_SECONDS)
    watchdog = threading.Timer(_SIGTERM_GRACE_SECONDS, _exit_after_sigterm_grace)
    watchdog.daemon = True
    watchdog.start()
    scope.cancel()


def _exit_after_sigterm_grace() -> None:
    sys.stderr.flush()
    os._exit(0)


def build_http_app(cfg, server, token_value: str):  # type: ignore[no-untyped-def]
    """Bearer-authenticated ASGI app for the Streamable HTTP transport.

    ``host`` must be handed to ``streamable_http_app``: when it is omitted the
    SDK defaults to 127.0.0.1 and AUTO-ENABLES DNS-rebinding protection pinned
    to loopback Host headers, so every client that connects by hostname - the
    documented cross-machine deployment, and any reverse proxy forwarding the
    original Host - is answered 421 "Invalid Host header" no matter what the
    listener binds. The comment here used to claim host checking was left to
    the proxy; the SDK had silently turned it on.
    """
    from universal_db_mcp.http_protocol import bearer_token_matches

    asgi_app = server.streamable_http_app(host=cfg.application.http_host)
    token_bytes = token_value.encode()

    async def _auth_app(scope, receive, send):  # type: ignore[no-untyped-def]
        # Pure ASGI bearer-auth wrapper (Starlette's app.middleware helper is
        # not available on a bare ASGI app). Under serve the listener's
        # protocol has already refused a request head without the token
        # (http_protocol.GuardedH11Protocol); this is the second check.
        if scope["type"] != "http":
            await asgi_app(scope, receive, send)
            return
        if not bearer_token_matches(scope.get("headers", []), token_bytes):
            await send(
                {
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [
                        (b"www-authenticate", b"Bearer"),
                        (b"content-type", b"application/json"),
                        # uvicorn closes the connection after the response
                        (b"connection", b"close"),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": b'{"error": "unauthorized"}'})
            return
        await asgi_app(scope, receive, send)

    return _auth_app


def _serve_http(cfg, server) -> int:  # type: ignore[no-untyped-def]
    """Authenticated internal Streamable HTTP deployment.

    Bearer token is read from a local file (application.http_bearer_token_file).
    Bind defaults to loopback. Origin/host restrictions are enforced by the
    reverse proxy in front of this service (docs/offline-deployment.md)."""
    from pathlib import Path

    import uvicorn

    from universal_db_mcp import http_protocol
    from universal_db_mcp.config import _check_secret_file_permissions
    from universal_db_mcp.errors import ConfigError
    from universal_db_mcp.security.redact import SecretMark

    token_path = cfg.application.http_bearer_token_file
    if not token_path:
        print(
            "CONFIG_ERROR: http transport requires application.http_bearer_token_file",
            file=sys.stderr,
        )
        return 1
    # The bearer token is the only authentication on the HTTP listener: it is
    # a secret file and must meet the same permission rule as password files
    # (no group/other access), and a missing/unreadable file is a CONFIG_ERROR
    # instead of an uncaught traceback.
    try:
        token_file = Path(token_path)
        _check_secret_file_permissions(token_file)
        # utf-8-sig: a file saved by Notepad starts with a BOM no client sends
        raw_token = token_file.read_text(encoding="utf-8-sig").strip()
    except UnicodeDecodeError:
        # The codec message would quote a byte of the file.
        print(f"CONFIG_ERROR: bearer token file {token_path} is not UTF-8 text", file=sys.stderr)
        return 1
    except ConfigError as exc:  # its message already starts with CONFIG_ERROR
        print(exc, file=sys.stderr)
        return 1
    except (OSError, ValueError) as exc:
        print(f"CONFIG_ERROR: {exc}", file=sys.stderr)
        return 1
    if not raw_token:
        print("CONFIG_ERROR: bearer token file is empty", file=sys.stderr)
        return 1
    if len(raw_token) < _MIN_BEARER_TOKEN_CHARS:
        print(
            f"CONFIG_ERROR: the bearer token in {token_path} must be at least {_MIN_BEARER_TOKEN_CHARS} "
            "characters; generate one with: python3 -c 'import secrets; print(secrets.token_hex(32))'",
            file=sys.stderr,
        )
        return 1
    token = SecretMark(raw_token)

    # Pre-auth limits (header deadline, head cap, the bearer check on the
    # request head, bounded logging, descriptor limit): see
    # universal_db_mcp.http_protocol.
    try:
        header_timeout = http_protocol.header_timeout_from_env(os.environ)
        http_protocol.configure_http_logging(os.environ)
    except (ValueError, OSError) as exc:
        print(f"CONFIG_ERROR: {exc}", file=sys.stderr)
        return 1
    http_protocol.raise_open_file_limit()

    _auth_app = build_http_app(cfg, server, token.value)

    uvicorn.run(
        _auth_app,
        host=cfg.application.http_host,
        port=cfg.application.http_port,
        http=http_protocol.guarded_h11_protocol(header_timeout, token.value.encode()),
        # configure_http_logging already applied the logging configuration
        log_config=None,
        log_level="warning",
        access_log=False,
    )
    return 0


def _indent_block(text: str, prefix: str = "    ") -> str:
    return textwrap.indent(text, prefix) if text else ""


def _apply_registration(name: str, registry: ModuleType, env: Mapping[str, str], home: Path) -> bool:
    """Run one confirmed apply and print the outcome; never raises. Returns
    whether the harness is now configured: an adapter may refuse the write
    by returning a fail-closed Plan instead of raising."""
    from universal_db_mcp.agents.core import AgentConfigError, AgentStatus, ensure_per_user_harness_config

    try:
        result = registry.apply_confirmed(name, env, home, True)
    except AgentConfigError as exc:
        print(f"  -> write skipped, adapter unavailable: {exc}")
        return False
    except Exception as exc:  # adapter crash mid-write: report, never retry
        print(f"  -> FAIL CLOSED: write aborted ({type(exc).__name__}: {exc})")
        return False
    for backup in result.backup_paths:
        print(f"  backup: {backup}")
    print(f"  -> {result.status.value}: {result.summary}")
    # The advertised config path may be the per-user default (the system
    # deployment is service-account owned and unreadable by this user): seed
    # it so the harness's spawns actually start. Only-if-absent.
    seeded, note = ensure_per_user_harness_config(env, home)
    if seeded is not None:
        print(f"  seeded per-user harness config: {seeded} ({note})")
    if result.status is not AgentStatus.CONFIGURED:
        return False
    _warn_env_secret_connections(env, home)
    notice = _agent_credentials_notice(env, home)
    print(_wrap_notice(notice, "  "))
    return True


def _agent_credentials_notice(env: Mapping[str, str], home: Path) -> str:
    """The registration runs the server over stdio as this user, inside the
    agent: say that the agent's own tools can read the credentials."""
    from universal_db_mcp.agents.core import resolve_harness_config_path
    from universal_db_mcp.wizard import agent_credentials_notice, secrets_dir_for

    return agent_credentials_notice(secrets_dir_for(Path(resolve_harness_config_path(env, home))))


def _warn_env_secret_connections(env: Mapping[str, str], home: Path) -> None:
    """After a registration is written: name every connection whose
    credentials come from ``username_env``/``password_env``.

    The adapters put only UDBMCP_CONFIG into the harness entry's env, so such
    variables must exist in the HARNESS process environment - which a GUI
    harness (Claude Desktop, VS Code, Cursor launched from the Dock/Finder)
    does not inherit from any shell. The registered server then dies at
    startup with "environment variable ... is not set". Names only: the
    values are never read or printed here.
    """
    from universal_db_mcp.agents.core import resolve_harness_config_path
    from universal_db_mcp.config import load_config
    from universal_db_mcp.errors import ConfigError

    cfg_path = Path(resolve_harness_config_path(env, home))
    if not cfg_path.is_file():
        return
    try:
        cfg = load_config(cfg_path)
    except ConfigError:
        return  # `doctor --config` reports config problems; this notice is about env-sourced secrets only
    for name, conn in sorted(cfg.connections.items()):
        variables = [v for v in (conn.username_env, conn.password_env) if v]
        if not variables:
            continue
        print(
            f"  WARNING: connection '{name}' in {cfg_path} reads {', '.join(variables)} from the "
            "environment; a GUI harness does not inherit shell variables, so the registered server "
            "will fail at startup unless they are set in the harness's own environment. "
            "Prefer username_file/password_file (see `udbmcp add-connection`).",
            file=sys.stderr,
        )


def _configure_agents(args: argparse.Namespace) -> int:
    """``configure-agents``: detect harnesses, show exact plans, ask, then write.

    Ask-before-write contract:

    * Detection and planning never write anything.
    * ``--dry-run`` prints the plans and exits without prompting or writing.
    * On a TTY, each candidate is applied only after an explicit ``y`` answer.
    * Without a TTY, a write requires ``--yes``; otherwise nothing is written
      and the command exits 1.
    * Malformed/unreadable existing configs and unavailable adapter modules
      are reported and never overwritten (fail closed). Such a harness, or
      one whose adapter raises, makes the command exit 2 when --agent names
      it, or --yes is given without --dry-run; --json also counts them as
      "errors". Writes go through the
      adapter's ``apply(confirmed=True)``, which backs up each target with a
      timestamped ``.bak`` and is idempotent.
    * A confirmed write that does not happen (the adapter refuses it, for
      example because the harness config changed since the plan, or raises)
      makes the command exit 1, with or without --json.
    """
    from universal_db_mcp.agents import registry
    from universal_db_mcp.agents.core import AgentConfigError, AgentStatus, ensure_per_user_harness_config

    env = os.environ
    home = Path.home()

    names = registry.HARNESS_NAMES
    if args.agent is not None:
        if args.agent not in names:
            valid = ", ".join(names)
            print(
                f"CONFIG_ERROR: unknown agent {args.agent!r}; valid --agent values: {valid}",
                file=sys.stderr,
            )
            return 2
        names = (args.agent,)

    if args.dry_run and args.yes:
        notice = "dry-run: --yes ignored; nothing will be written or prompted"
        if args.json:
            # stdout stays pure JSON for GUI consumers; the notice is a
            # human-facing diagnostic.
            print(notice, file=sys.stderr)
        else:
            print(notice)

    # Harnesses that failed closed: the adapter raised (a ConfigError such as
    # a relative UDBMCP_CONFIG, an adapter that cannot be imported, a crash)
    # or found the harness config unreadable or malformed, or in a state it
    # will not write. Nothing is written to them, and the run fails when the
    # caller named one or asked to apply (see _failed_closed_is_fatal).
    failed: list[str] = []

    # --- machine-readable mode for GUI front ends ------------------------------
    # Contract: --json NEVER prompts and NEVER writes unless --yes is also
    # given (the GUI's dialog/checkbox selection is the consent step; --yes
    # then applies exactly the harnesses the user selected, restricted to
    # --agent when set). Detection itself is always read-only.
    if args.json:
        payload: dict[str, object] = {"home": str(home), "harnesses": []}
        harnesses = payload["harnesses"]
        assert isinstance(harnesses, list)
        for name in names:
            try:
                status = registry.detect_status(name, env, home)
            except AgentConfigError as exc:
                failed.append(name)
                harnesses.append(
                    {"agent": name, "status": "adapter_error", "detail": str(exc), "writable": False}
                )
                continue
            except Exception as exc:  # unexpected adapter crash: fail closed
                failed.append(name)
                harnesses.append(
                    {
                        "agent": name,
                        "status": "fail_closed",
                        "detail": f"{type(exc).__name__}: {exc}",
                        "writable": False,
                    }
                )
                continue
            if status is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED:
                failed.append(name)
            harnesses.append(
                {
                    "agent": name,
                    "status": status.value,
                    "writable": status is AgentStatus.INSTALLED_UNCONFIGURED,
                }
            )
        payload["errors"] = len(failed)
        exit_code = 0
        if args.yes and not args.dry_run:
            applied: list[dict[str, object]] = []
            for name in names:
                writable = any(
                    isinstance(h, dict)
                    and h.get("agent") == name
                    and h.get("writable") is True
                    for h in harnesses
                )
                if not writable:
                    continue
                try:
                    result = registry.apply_confirmed(name, env, home, True)
                    seeded, _seed_note = ensure_per_user_harness_config(env, home)
                    if result.status is AgentStatus.CONFIGURED:
                        _warn_env_secret_connections(env, home)  # stderr only; stdout stays JSON
                        print(_agent_credentials_notice(env, home), file=sys.stderr)
                    applied.append(
                        {
                            "agent": name,
                            "status": result.status.value,
                            "summary": result.summary,
                            "backups": [str(p) for p in result.backup_paths],
                            "config_seeded": str(seeded) if seeded else None,
                        }
                    )
                    # Adapters may report a REFUSED write by returning a
                    # fail-closed Plan instead of raising (e.g. the config
                    # changed state between detection and apply): that is a
                    # failure for the caller even though nothing raised.
                    if result.status is not AgentStatus.CONFIGURED:
                        exit_code = 1
                except AgentConfigError as exc:
                    applied.append({"agent": name, "status": "error", "detail": str(exc)})
                    exit_code = 1
                except Exception as exc:  # adapter crash mid-write: report, never retry
                    applied.append(
                        {"agent": name, "status": "fail_closed", "detail": f"{type(exc).__name__}: {exc}"}
                    )
                    exit_code = 1
            payload["applied"] = applied
        print(json.dumps(payload, indent=2))
        if failed and _failed_closed_is_fatal(args):
            _report_failed_closed(failed)
            return 2
        return exit_code

    # Phase 1: read-only detection table.
    print(f"Detecting agent harnesses (HOME={home}):")
    detected: dict[str, AgentStatus | None] = {}
    for name in names:
        try:
            status = registry.detect_status(name, env, home)
        except AgentConfigError as exc:
            detected[name] = None
            failed.append(name)
            print(f"  {name:<16} adapter-unavailable; skipped ({exc})")
        except Exception as exc:  # unexpected adapter crash: fail closed
            detected[name] = None
            failed.append(name)
            print(f"  {name:<16} fail-closed; skipped (adapter error: {type(exc).__name__}: {exc})")
        else:
            detected[name] = status
            print(f"  {name:<16} {status.value}")

    # Phase 2: print the exact plan per actionable harness and ask.
    pending: list[str] = []
    not_written: list[str] = []  # confirmed, but the adapter refused, raised or crashed
    for name in names:
        if detected.get(name) is None:
            continue
        try:
            planned = registry.build_plan(name, env, home)
        except AgentConfigError as exc:
            failed.append(name)
            print(f"\n== {name} ==\n  adapter unavailable; nothing written: {exc}")
            continue
        except Exception as exc:
            failed.append(name)
            print(f"\n== {name} ==\n  FAIL CLOSED: adapter error ({type(exc).__name__}: {exc}); nothing written")
            continue

        if planned.status is AgentStatus.NOT_INSTALLED:
            continue
        if planned.status is AgentStatus.CONFIGURED:
            print(f"\n== {name} ==\n  {planned.summary}")
            continue

        print(f"\n== {name} ==")
        if planned.config_path is not None:
            print(f"  config file: {planned.config_path}")
        for extra in planned.config_paths:
            if extra != planned.config_path:
                print(f"  also: {extra}")
        print(f"  {planned.summary}")
        block = planned.config_block or planned.block
        if block:
            print("  would add:")
            print(_indent_block(block))

        if planned.status is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED:
            failed.append(name)
            print("  FAIL CLOSED: fix or inspect the existing config above; nothing will be written")
            continue
        if planned.status is not AgentStatus.INSTALLED_UNCONFIGURED:
            print(f"  no write offered (status: {planned.status.value})")
            continue
        if args.dry_run:
            print("  dry-run: nothing written")
            continue

        if args.yes:
            if not _apply_registration(name, registry, env, home):
                not_written.append(name)
            continue

        if not sys.stdin.isatty():
            print("  NOT CONFIRMED: stdin is not a TTY and --yes was not given; nothing written")
            pending.append(name)
            continue

        try:
            answer = input(f"  Register universal-db into {name} ({planned.config_path})? [y/N] ")
        except EOFError:
            answer = ""
        if answer.strip().lower() in ("y", "yes"):
            if not _apply_registration(name, registry, env, home):
                not_written.append(name)
        else:
            print("  skipped (declined)")

    if pending:
        print(
            f"\nCONFIG_ERROR: {len(pending)} harness(es) need confirmation but stdin is not a TTY; "
            "re-run with --yes to apply non-interactively. Nothing was written.",
            file=sys.stderr,
        )
    if not_written:
        # as --json: a confirmed write that did not happen fails the run
        print(
            f"\nCONFIG_ERROR: the confirmed registration of {', '.join(not_written)} was not written "
            "(the reason is shown above)",
            file=sys.stderr,
        )
    if failed and _failed_closed_is_fatal(args):
        _report_failed_closed(failed)
        return 2
    return 1 if pending or not_written else 0


def _failed_closed_is_fatal(args: argparse.Namespace) -> bool:
    """Whether a harness that failed closed (its adapter raised, or its
    config is unreadable or malformed, or in a state the adapter will not
    write) fails the run: the caller named it with --agent, or asked to
    apply with --yes (without --dry-run), and a script or the macOS app must
    not read a fail-closed harness as success. Plain detection, and --yes
    with --dry-run, report it and succeed."""
    return args.agent is not None or (args.yes and not args.dry_run)


def _report_failed_closed(failed: list[str]) -> None:
    print(
        f"CONFIG_ERROR: {', '.join(failed)} failed closed (the reason is shown for each); nothing was written there",
        file=sys.stderr,
    )


def _add_connection(args: argparse.Namespace) -> int:
    """``add-connection``: interactive wizard (or fully-flagged non-interactive
    run) that adds one connection to a config file. Secrets become private
    files under <config dir>/secrets/; the config itself never holds
    credentials. Nothing is written until every answer is in and the merged
    config is valid."""
    from pydantic import ValidationError

    from universal_db_mcp.agents.core import resolve_harness_config_path
    from universal_db_mcp.errors import ConfigError
    from universal_db_mcp.wizard import (
        StagedCredentials,
        WizardError,
        apply_connection,
        build_connection,
        collect_answers_interactive,
        confirm_merge,
        ensure_config_exists,
        plan_merge,
        read_password_file,
        secret_paths,
        validate_connection_name,
    )

    if args.read_write:
        # the config refuses a connection with read_only: false
        print("CONFIG_ERROR: read_only: false is not supported (v1 is read-only)", file=sys.stderr)
        return 2

    # Absolute: the secret paths written into the config derive from it, and
    # the server resolves paths from its own working directory.
    if args.config:
        cfg_path = Path(os.path.abspath(os.path.expanduser(args.config)))
    else:
        cfg_path = Path(os.path.abspath(resolve_harness_config_path(dict(os.environ), Path.home())))
        if cfg_path.is_file() and not os.access(cfg_path, os.W_OK):
            # The wizard WRITES: a readable-but-not-writable default (the
            # root-owned system deployment) must not be chosen - fall back to
            # the per-user config instead of failing halfway through
            # credential creation (seen live 2026-09-15).
            cfg_path = Path.home() / ".universal-db-mcp" / "config.yaml"
    interactive = not args.json

    provided = all(
        v is not None for v in (args.name, args.engine, args.database)
    )
    if interactive and not sys.stdin.isatty() and not provided:
        print(
            "CONFIG_ERROR: add-connection needs a TTY for the interactive wizard; "
            "for non-interactive use pass --json with --name/--engine/--database "
            "(and --username/--password-file for server-backed engines)",
            file=sys.stderr,
        )
        return 2

    try:
        if args.name is not None:
            # Validate BEFORE any filesystem effect: the name derives secret
            # file paths, and nothing may ever see a path-like name.
            validate_connection_name(args.name)
        created = ensure_config_exists(cfg_path)
        if created:
            # stdout stays pure in --json mode: the creation notice is a
            # human-facing diagnostic.
            notice = f"==> created new config: {cfg_path}"
            if args.json:
                print(notice, file=sys.stderr)
            else:
                print(notice)

        credentials: tuple[str, str | None] | None = None
        if args.json or provided:
            if not provided:
                print(
                    "CONFIG_ERROR: --json mode is non-interactive; provide --name, "
                    "--engine and --database (plus --username/--password-file for "
                    "server-backed engines)",
                    file=sys.stderr,
                )
                return 2
            username_file = password_file = None
            if args.engine != "sqlite":
                if not args.username or not args.password_file:
                    print(
                        "CONFIG_ERROR: server-backed connections need --username and "
                        "--password-file (the password is never a command-line value)",
                        file=sys.stderr,
                    )
                    return 2
                password = read_password_file(args.password_file)
                credentials = (args.username, password or None)
                username_file, password_file = secret_paths(cfg_path, args.name, has_password=bool(password))
            name, run_test = args.name, not args.no_test
            # Validated before anything is written: a bad value (a missing
            # host, port 0) must not have replaced the old secret files.
            connection = build_connection(
                name=name,
                engine=args.engine,
                database=args.database,
                host=args.host,
                port=args.port,
                username_file=str(username_file) if username_file else None,
                password_file=str(password_file) if password_file else None,
                tls_enabled=bool(args.tls_ca_file),
                tls_ca_file=args.tls_ca_file,
            )
        else:
            name, connection, run_test, credentials = collect_answers_interactive(cfg_path)

        plan = plan_merge(cfg_path, name, connection, replace=args.replace)
        # only the prompting wizard asks; flag runs need --accept-comment-loss
        if not confirm_merge(plan, accept_comment_loss=args.accept_comment_loss, ask=not (args.json or provided)):
            print(f"==> nothing written; {cfg_path} is unchanged")
            return 1
        staged = StagedCredentials(cfg_path, name, *credentials) if credentials else None
        try:
            result = apply_connection(
                cfg_path, name, connection, run_test=run_test, plan=plan, credentials=staged
            )
        finally:
            if staged is not None:
                staged.discard()
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            _print_add_result(result)
        return 0 if not result.get("tested") or result["test"].get("healthy", True) else 1
    except WizardError as exc:
        print(f"CONFIG_ERROR: {exc}", file=sys.stderr)
        return 1
    except ConfigError as exc:  # its message already starts with CONFIG_ERROR
        print(exc, file=sys.stderr)
        return 1
    except ValidationError as exc:
        print(f"CONFIG_ERROR: invalid value: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"CONFIG_ERROR: {exc}", file=sys.stderr)
        return 1


def _print_add_result(result: dict[str, Any]) -> None:
    print(f"==> {result.get('action', 'added')} connection {result['connection']!r} in {result['config']}")
    if result.get("changed_fields"):
        print(f"    changed: {', '.join(result['changed_fields'])}")
    if result.get("preserved_fields"):
        print(f"    kept as they are: {', '.join(result['preserved_fields'])}")
    if result.get("dropped_fields"):
        print(f"    dropped: {', '.join(result['dropped_fields'])}")
    print(f"    backup: {result['backup']}")
    if result.get("comments_dropped"):
        print("    NOTE: comments inside the config body were not preserved (the header was).")
    policy = result.get("policy") or {}
    if policy.get("would_be_refused"):
        print(f"    WARNING: {policy['detail']}")
    for warning in result.get("warnings") or ():
        print(f"    WARNING: {warning}")
    if result.get("tested"):
        test = result["test"]
        if test.get("healthy"):
            print(f"    live test: HEALTHY ({test.get('server_version')}, {test.get('latency_ms')} ms)")
        else:
            print(f"    live test: FAILED ({test.get('error')}) — the connection was kept; check host/port/credentials")
    else:
        print("    validate with: udbmcp doctor --config <config>")
    if result.get("service_restart"):
        print(f"    restart the service to load the connection: {result['service_restart']}")
    else:
        print("    restart your agent harness to pick up the new connection")
    for notice in result.get("notices") or ():
        print(_wrap_notice(notice, "    "))


def _wrap_notice(text: str, indent: str) -> str:
    # never split a path: the admin copies it
    return textwrap.fill(
        text, width=100, initial_indent=indent, subsequent_indent=indent,
        break_long_words=False, break_on_hyphens=False,
    )


if __name__ == "__main__":
    sys.exit(main())
