#!/usr/bin/env bash
# Gate A+B: clean offline installation + no-network protocol test.
# Designed to run INSIDE a network-restricted container (docker --network none)
# with only the bundle mounted. Writes machine-readable evidence to $EVIDENCE.
set -uo pipefail

BUNDLE="${BUNDLE_DIR:?BUNDLE_DIR must be set}"
EVIDENCE="${EVIDENCE_DIR:-/evidence}"
mkdir -p "$EVIDENCE"
RESULT="$EVIDENCE/airgap-test-results.json"
FAILED=0
note() { echo "[airgap-test] $*"; }
fail() { echo "[airgap-test] FAIL: $*"; FAILED=1; }

{
  echo "{"
  echo "  \"profile\": \"linux-x86_64-ubuntu24.04-cp312\","
  echo "  \"network\": \"none (docker --network none)\","
  echo "  \"platform_caveat\": \"amd64 userland under Docker Desktop emulation on the staging host; wheels and installer are genuine x86_64 artifacts\","
  echo "  \"started\": \"$(date -u +%FT%TZ)\","
} > "$RESULT"

python3 -c 'import sys; assert sys.version_info[:2] == (3,12), sys.version' \
  && note "python3.12 present (ubuntu:24.04 baseline)" \
  || fail "CPython 3.12 not available in baseline image"

note "verifying bundle (integrity/lock/slots)"
PUBKEY_ARGS=""
[ -n "${UDBMCP_RELEASE_PUBKEY:-}" ] && PUBKEY_ARGS="--pubkey $UDBMCP_RELEASE_PUBKEY"
# The trusted tools are mounted separately (never taken from the bundle):
# the installer refuses to execute from inside the bundle it verifies.
TRUST="${UDBMCP_TRUST_DIR:-/trusted-tools}"
if python3 "$TRUST/verify_bundle.py" --bundle "$BUNDLE" $PUBKEY_ARGS >> /tmp/verify.log 2>&1; then
  note "bundle verification passed"
  echo "  \"bundle_verification\": \"passed\"," >> "$RESULT"
else
  fail "bundle verification failed (see /tmp/verify.log)"
  echo "  \"bundle_verification\": \"failed\"," >> "$RESULT"
fi

note "installing from wheelhouse only"
if UDBMCP_TRUST_DIR="$TRUST" bash "$TRUST/install_offline.sh" "$BUNDLE" /opt/universal-db-mcp >> /tmp/install.log 2>&1; then
  note "installation passed"
  echo "  \"installation\": \"passed\"," >> "$RESULT"
else
  fail "installation failed (see /tmp/install.log)"
  echo "  \"installation\": \"failed\"," >> "$RESULT"
fi

VENV=/opt/universal-db-mcp/venv/bin
if [ "$FAILED" = 0 ]; then
  note "creating synthetic SQLite demo fixture + config (writable copy; bundle mount is read-only)"
  mkdir -p /tmp/demo && cp "$BUNDLE/config-templates/create_demo.py" "$BUNDLE/config-templates/config.template.yaml" /tmp/demo/
  "$VENV/python" /tmp/demo/create_demo.py --path /tmp/finlink_demo.db >> /tmp/demo.log 2>&1 \
    || fail "demo fixture creation failed"

  note "doctor (local artifacts + generated config, no database credentials needed)"
  if "$VENV/python" -m universal_db_mcp doctor --config /tmp/demo/config.yaml > /tmp/doctor.json 2>/tmp/doctor.err; then
    cp /tmp/doctor.json "$EVIDENCE/doctor.json"
    note "doctor passed"
    echo "  \"doctor\": \"passed\"," >> "$RESULT"
  else
    cp /tmp/doctor.json "$EVIDENCE/doctor.json" 2>/dev/null || true
    fail "doctor reported fatal checks"
    echo "  \"doctor\": \"failed\"," >> "$RESULT"
  fi

  note "protocol probe over stdio (no network)"
  if "$VENV/python" "$BUNDLE/tests/protocol_probe.py" "$VENV/python" /tmp/finlink_demo.db > "$EVIDENCE/protocol-probe.json" 2>/tmp/probe.err; then
    note "protocol probe passed"
    echo "  \"protocol_probe\": \"passed\"," >> "$RESULT"
  else
    cp /tmp/probe.err "$EVIDENCE/protocol-probe-stderr.txt" || true
    fail "protocol probe failed"
    echo "  \"protocol_probe\": \"failed\"," >> "$RESULT"
  fi

  note "restart test (misconfigured start fails fast; then the server starts again and serves the protocol)"
  BAD_RC=0
  printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"probe","version":"0"}}}' \
    | UDBMCP_CONFIG=/tmp/nonexistent.yaml timeout 10 "$VENV/python" -m universal_db_mcp serve --transport stdio >/dev/null 2>/tmp/bad-start.err || BAD_RC=$?
  # A misconfigured start must fail fast: nonzero exit (but NOT a timeout
  # hang, rc=124) with CONFIG_ERROR on stderr. The exit code used to be
  # discarded inside `if ...; then :; fi`, so a hang or an accepted bad
  # config produced the same "passed" evidence as a clean rejection.
  if [ "$BAD_RC" -ne 0 ] && [ "$BAD_RC" -ne 124 ] && grep -q CONFIG_ERROR /tmp/bad-start.err; then
    note "misconfigured start rejected (rc=$BAD_RC, CONFIG_ERROR on stderr)"
  else
    fail "misconfigured start did not fail fast with CONFIG_ERROR (rc=$BAD_RC)"
  fi
  # The restart claim needs a SECOND server start with a valid config; the
  # `version` subcommand is not a server start. Exercise a full initialize
  # round-trip over stdio against a freshly generated valid config.
  if "$VENV/python" - "$VENV/python" <<'PYEOF' >/tmp/restart.json 2>/tmp/restart.err; then
import asyncio
import os
import sys
import tempfile
from pathlib import Path


async def main() -> int:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    venv_python = sys.argv[1]
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
    database: /tmp/finlink_demo.db
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
                return 0 if init.server_info.name == "universal-db-mcp" else 1


raise SystemExit(asyncio.run(main()))
PYEOF
    note "restart: second server start completed a full initialize round-trip"
    echo "  \"restart\": \"passed\"," >> "$RESULT"
  else
    cp /tmp/restart.err "$EVIDENCE/restart-stderr.txt" 2>/dev/null || true
    fail "restart: second server start failed (see /tmp/restart.err)"
    echo "  \"restart\": \"failed\"," >> "$RESULT"
  fi
fi

echo "  \"finished\": \"$(date -u +%FT%TZ)\"," >> "$RESULT"
if [ "$FAILED" = 0 ]; then echo "  \"status\": \"passed\"" >> "$RESULT"; else echo "  \"status\": \"failed\"" >> "$RESULT"; fi
echo "}" >> "$RESULT"

note "evidence written to $RESULT"
cat "$RESULT"
exit "$FAILED"
