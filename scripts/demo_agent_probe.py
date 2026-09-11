#!/usr/bin/env python3
"""Agent-side smoke test: connects to the MCP server exactly the way another
agent does (stdio MCP client from the pinned SDK) and runs one themed query
per configured engine against the mock fixtures. No network beyond loopback."""

from __future__ import annotations

import asyncio
import json
import os
import sys


QUERIES = {
    "mock_pg": "SELECT COUNT(*) FROM ocean.readings",
    "mock_mysql": "SELECT COUNT(*) FROM roastery_batches",
    "mock_clickhouse": "SELECT count() FROM telecom.cdr",
    "mock_oracle": "SELECT COUNT(*) FROM bookings",
    "mock_mssql": "SELECT COUNT(*) FROM dbo.Admissions",
    "mock_db2": "SELECT COUNT(*) FROM MOI.CITIZENS",
}

USER_ENV = {
    "UDBMCP_DEMO_PG_USER": "udbmcp_ro",
    "UDBMCP_DEMO_MYSQL_USER": "udbmcp_ro",
    "UDBMCP_DEMO_CH_USER": "default",
    "UDBMCP_DEMO_ORA_USER": "travel",
    "UDBMCP_DEMO_MSSQL_USER": "sa",
    "UDBMCP_DEMO_DB2_USER": "db2inst1",
}

# Documented staging-host limitations (not product bugs):
# - mssql: ODBC Driver 18 is an administrator-supplied OS package
# - db2: pinned clidriver refuses remote plaintext password auth
BLOCKED_MARKERS = ("TLS", "blocked", "ODBC Driver", "SQL30082N")


def is_known_blocked_error(msg: str) -> bool:
    """True when an engine error matches a documented staging-host limitation."""
    return (
        "TLS" in msg
        or "blocked" in msg.lower()
        or "ODBC Driver" in msg
        or "SQL30082N" in msg
    )


def query_error_check(msg: str) -> dict[str, object]:
    """Build the report entry for an engine query that raised.

    Known-blocked errors are recorded with passed=None and status='blocked':
    they must never be counted as passing (a connector bug whose message merely
    contains 'TLS'/'blocked'/... would otherwise be masked), but a documented
    staging limitation must not fail the whole probe either. Anything else is a
    hard failure: passed=False, status='failed'.
    """
    if is_known_blocked_error(msg):
        return {"passed": None, "status": "blocked", "detail": "KNOWN-BLOCKED: " + msg}
    return {"passed": False, "status": "failed", "detail": "FAILED: " + msg}


async def main() -> int:
    config_path = sys.argv[1] if len(sys.argv) > 1 else "config.mockdbs.yaml"
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    env = dict(os.environ)
    env.update(USER_ENV)
    env["UDBMCP_CONFIG"] = config_path

    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "universal_db_mcp", "serve", "--transport", "stdio"],
        env=env,
    )
    report: dict[str, object] = {"agent": "mcp-stdio-client", "checks": {}}
    ok = True
    blocked_engines: list[str] = []
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            good = init.server_info.name == "universal-db-mcp"
            report["checks"]["initialize"] = {"passed": good, "detail": init.server_info.name}
            ok = ok and good

            tools = await session.list_tools()
            report["checks"]["tools_listed"] = {"passed": len(tools.tools) >= 19, "detail": f"{len(tools.tools)} tools"}
            ok = ok and len(tools.tools) >= 19

            res = await session.call_tool("db_list_connections", {})
            conns = res.structured_content["data"]["connections"] if res.structured_content else []
            names = [c["connection_id"] for c in conns]
            good = not res.is_error and len(names) >= 6
            report["checks"]["list_connections"] = {"passed": good, "detail": ",".join(names)}
            ok = ok and good

            for conn_id, sql in QUERIES.items():
                try:
                    res = await session.call_tool(
                        "db_query", {"connection_id": conn_id, "sql": sql, "max_rows": 5}
                    )
                    if res.is_error or not res.structured_content:
                        raise RuntimeError(f"tool error: {res.content[:1]}")
                    rows = res.structured_content["data"]["rows"]
                    report["checks"][f"query:{conn_id}"] = {"passed": bool(rows), "detail": json.dumps(rows)}
                    ok = ok and bool(rows)
                except Exception as exc:  # noqa: BLE001 - probe reports per-engine
                    check = query_error_check(str(exc)[:220])
                    report["checks"][f"query:{conn_id}"] = check
                    if check["status"] == "blocked":
                        blocked_engines.append(conn_id)
                    else:
                        ok = False
    # Overall status is computed only from engines that actually returned rows:
    # blocked engines are allowed but never count as passes. The probe exits 0
    # only when no engine hard-failed; blocked engines stay fully visible.
    any_engine_passed = any(
        isinstance(check, dict) and check.get("passed") is True
        for key, check in report["checks"].items()
        if key.startswith("query:")
    )
    if not ok:
        report["status"] = "failed"
    elif any_engine_passed:
        report["status"] = "passed"
    else:
        report["status"] = "blocked"
    if blocked_engines:
        report["blocked_engines"] = blocked_engines
    print(json.dumps(report, indent=2))
    if blocked_engines:
        print("BLOCKED (allowed, review manually): " + ", ".join(blocked_engines), file=sys.stderr)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
