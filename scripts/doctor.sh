#!/usr/bin/env bash
# Wrapper: run doctor against the installed deployment (no network).
set -euo pipefail
TARGET="${TARGET:-/opt/universal-db-mcp}"
CONFIG="${UDBMCP_CONFIG:-/etc/universal-db-mcp/config.yaml}"
exec "$TARGET/venv/bin/python" -m universal_db_mcp doctor --config "$CONFIG" "$@"
