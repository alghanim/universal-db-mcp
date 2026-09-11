#!/usr/bin/env python3
"""Gate B probe: drives the real stdio MCP server with the pinned SDK client
over the protocol lifecycle, against a bundled SQLite demo fixture. No
browser inspector, no npm, no network. Prints one JSON evidence object."""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path


async def main() -> int:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    venv_python = sys.argv[1]
    demo_db = sys.argv[2]
    results: dict[str, object] = {"probe": "protocol_lifecycle", "checks": {}}
    ok = True

    def record(name: str, passed: bool, detail: str = "") -> None:
        nonlocal ok
        results["checks"][name] = {"passed": passed, "detail": detail}  # type: ignore[index]
        if not passed:
            ok = False

    with tempfile.TemporaryDirectory() as td:
        cfg = Path(td) / "config.yaml"
        cfg.write_text(
            f"""
application:
  airgapped: true
  transport: stdio
  metadata_cache_path: {td}/meta.sqlite
  audit_path: {td}/audit.jsonl
  telemetry_enabled: false
security:
  read_only: true
  default_deny_objects: true
connections:
  demo_sqlite:
    type: sqlite
    database: {demo_db}
    read_only: true
""",
            encoding="utf-8",
        )
        env = dict(os.environ)
        env["UDBMCP_CONFIG"] = str(cfg)
        params = StdioServerParameters(
            command=venv_python,
            args=["-m", "universal_db_mcp", "serve", "--transport", "stdio"],
            env=env,
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                init = await session.initialize()
                record("initialize", init.server_info.name == "universal-db-mcp", init.server_info.name)

                tools = await session.list_tools()
                names = {t.name for t in tools.tools}
                record("tools_listed", len(names) >= 19, f"{len(names)} tools")

                res = await session.call_tool("db_list_connections", {})
                record("list_connections", not res.is_error)

                res = await session.call_tool(
                    "db_query",
                    {"connection_id": "demo_sqlite", "sql": "SELECT COUNT(*) FROM customers"},
                )
                record("query", not res.is_error)
                if not res.is_error and res.structured_content:
                    rows = res.structured_content["data"]["rows"]
                    record("query_result_content", bool(rows), json.dumps(rows))

                res = await session.call_tool(
                    "db_query",
                    {"connection_id": "demo_sqlite", "sql": "DROP TABLE customers"},
                )
                record("write_denied", res.is_error)

                res = await session.call_tool(
                    "db_sample_table",
                    {"connection_id": "demo_sqlite", "object_name": "customers", "limit": 5},
                )
                record("sample", not res.is_error)

        results["status"] = "passed" if ok else "failed"
        print(json.dumps(results, indent=2))
        return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
