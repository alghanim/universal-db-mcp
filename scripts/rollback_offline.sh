#!/usr/bin/env bash
# Roll back to the previous venv left by upgrade_offline.sh, or restore the
# configuration backup from a failed upgrade. Local-only.
set -euo pipefail

TARGET="${1:-/opt/universal-db-mcp}"
BACKUP_ROOT="${2:-/var/backups/universal-db-mcp}"

if systemctl list-unit-files 2>/dev/null | grep -q universal-db-mcp; then systemctl stop universal-db-mcp || true; fi
if [ -d "$TARGET/venv.previous" ]; then
  echo "==> rolling back venv"
  rm -rf "$TARGET/venv.failed"
  mv "$TARGET/venv" "$TARGET/venv.failed"
  mv "$TARGET/venv.previous" "$TARGET/venv"
  # doctor resolves the config as args.config or $UDBMCP_CONFIG and fails
  # closed with "no config path" when neither is set; pass it explicitly so
  # the rollback is not aborted by its own validation after the venv swap.
  "$TARGET/venv/bin/python" -m universal_db_mcp doctor \
    --config "${UDBMCP_CONFIG:-/etc/universal-db-mcp/config.yaml}"
  echo "==> rollback complete (failed venv kept at $TARGET/venv.failed for analysis)"
else
  echo "no $TARGET/venv.previous found"
fi

LATEST_BACKUP="$(ls -1dt "$BACKUP_ROOT"/pre-upgrade-* 2>/dev/null | head -1 || true)"
if [ -n "$LATEST_BACKUP" ] && [ -f "$LATEST_BACKUP/universal-db-mcp/config.yaml" ]; then
  echo "==> restoring configuration from $LATEST_BACKUP (validated before deleting anything)"
  rm -rf /etc/universal-db-mcp.new
  cp -a "$LATEST_BACKUP/universal-db-mcp" /etc/universal-db-mcp.new
  rm -rf /etc/universal-db-mcp.old
  [ -d /etc/universal-db-mcp ] && mv /etc/universal-db-mcp /etc/universal-db-mcp.old
  mv /etc/universal-db-mcp.new /etc/universal-db-mcp
  rm -rf /etc/universal-db-mcp.old
elif [ -n "$LATEST_BACKUP" ]; then
  echo "WARN: backup at $LATEST_BACKUP has no config.yaml; leaving live configuration untouched"
fi

if [ -n "$LATEST_BACKUP" ] && [ -f "$LATEST_BACKUP/metadata.sqlite" ]; then
  mkdir -p /var/lib/universal-db-mcp
  [ -f /var/lib/universal-db-mcp/metadata.sqlite ] && \
    cp /var/lib/universal-db-mcp/metadata.sqlite /var/lib/universal-db-mcp/metadata.sqlite.pre-rollback
  cp "$LATEST_BACKUP/metadata.sqlite" /var/lib/universal-db-mcp/metadata.sqlite
fi

echo "==> restart the service (systemctl restart universal-db-mcp)"
