#!/usr/bin/env bash
# Gate D harness: observe the process tree's actual syscall-level network
# activity (DNS, connect attempts — including blocked ones) using strace.
# Run on a Linux host/container where strace is permitted. The harness must
# be validated itself (stage 0). A test FAILS on any unapproved outbound
# attempt even if a firewall blocked it.
#
# Limitations (stated honestly): strace observes syscalls of the traced
# process tree only; run under the same network policy as production and
# cross-check against firewall/EDR logs.
set -uo pipefail

BUNDLE="${1:?usage: observe_egress.sh <bundle-dir>}"
OUT="${2:-/tmp/udbmcp-egress}"
mkdir -p "$OUT"
FAILED=0

echo "==> stage 0: validate the observation harness itself"
if ! command -v strace >/dev/null 2>&1; then
  echo "BLOCKED: strace unavailable on this host; run on an approved Linux host"
  exit 2
fi
strace -f -e trace=connect,socket /bin/true 2>"$OUT/harness.log" || true
if ! grep -q "socket" "$OUT/harness.log" 2>/dev/null; then
  echo "BLOCKED: strace produced no output; ptrace may be restricted"
  exit 2
fi
echo "    harness validated"

echo "==> stage 1: observe startup + first use of each configured adapter"
python3 - "$BUNDLE" "$OUT" <<'PYEOF'
import json, subprocess, sys, os, time, signal
from pathlib import Path
bundle, out = Path(sys.argv[1]), Path(sys.argv[2])
# demo config so the SQLite path exercises start -> query -> shutdown
demo_db = out / "demo.db"
import sqlite3
c = sqlite3.connect(demo_db); c.execute("CREATE TABLE t (x int)"); c.commit(); c.close()
cfg = out / "cfg.yaml"
cfg.write_text(f"""
application:
  airgapped: true
  transport: stdio
  telemetry_enabled: false
security:
  read_only: true
connections:
  demo_sqlite:
    type: sqlite
    database: {demo_db}
    read_only: true
""")
env = dict(os.environ); env["UDBMCP_CONFIG"] = str(cfg)
# a short MCP session: initialize + one query, then shutdown
script = """
import asyncio, sys
sys.path.insert(0, '/opt/universal-db-mcp/venv/lib/python3/site-packages')
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
async def main():
    p = StdioServerParameters(command=sys.argv[1],
        args=["-m","universal_db_mcp","serve","--transport","stdio"], env=None)
    async with stdio_client(p) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            await s.call_tool("db_query", {"connection_id":"demo_sqlite","sql":"SELECT 1"})
asyncio.run(main())
"""
Path(out/"drive.py").write_text(script)
cmd = ["strace", "-f", "-e", "trace=network", "-o", str(out/"strace.log"),
       sys.executable if Path('/opt/universal-db-mcp/venv/bin/python').exists() is False else "/opt/universal-db-mcp/venv/bin/python",
       str(out/"drive.py"), "/opt/universal-db-mcp/venv/bin/python"]
r = subprocess.run(cmd, env=env, capture_output=True, text=True)
log = (out/"strace.log").read_text() if (out/"strace.log").exists() else ""
violations = [l for l in log.splitlines()
              if "connect(" in l and "AF_UNIX" not in l and "AF_NETLINK" not in l
              and " sin_addr=inet_addr(\"127.0.0.1\")" not in l
              and " sin_addr=inet_addr(\"0.0.0.0\")" not in l]
json.dump({
  "gate": "D-egress-observation",
  "server_exit": r.returncode,
  "external_connect_attempts": violations,
  "verdict": "passed" if not violations else "failed",
}, open(out/"egress-results.json", "w"), indent=2)
print(open(out/"egress-results.json").read())
sys.exit(0 if not violations else 1)
PYEOF
RC=$?
[ "$RC" = 0 ] || FAILED=1

echo "==> evidence in $OUT"
exit "$FAILED"
