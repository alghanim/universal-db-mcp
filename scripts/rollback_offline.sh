#!/usr/bin/env bash
# Roll back to the previous venv left by upgrade_offline.sh, or restore the
# configuration backup from a failed upgrade. Local-only.
#
# The venv swap is always performed. Restoring the pre-upgrade configuration
# and metadata overwrites live state (which may hold post-upgrade edits made
# AFTER that backup was taken), so it requires the explicit --restore-config
# flag. When it runs, the live configuration is displaced to
# <backup-root>/pre-rollback-<ts>/ and preserved — never deleted — and the
# backup is validated through the restored venv before anything is moved.
set -euo pipefail

usage() {
  echo "usage: rollback_offline.sh [target-dir] [backup-root] [--restore-config]" >&2
}

TARGET=""
BACKUP_ROOT=""
RESTORE_CONFIG=0
for arg in "$@"; do
  case "$arg" in
    --restore-config) RESTORE_CONFIG=1 ;;
    -h|--help) usage; exit 0 ;;
    *)
      if [ -z "$TARGET" ]; then TARGET="$arg"
      elif [ -z "$BACKUP_ROOT" ]; then BACKUP_ROOT="$arg"
      else usage; exit 2
      fi ;;
  esac
done
: "${TARGET:=/opt/universal-db-mcp}"
: "${BACKUP_ROOT:=/var/backups/universal-db-mcp}"
# Overridable only so this script can be exercised against a sandbox in the
# unit tests; production uses the defaults.
ETC_DIR="${UDBMCP_CONFIG_DIR:-/etc/universal-db-mcp}"
STATE_DIR="${UDBMCP_STATE_DIR:-/var/lib/universal-db-mcp}"

if systemctl list-unit-files 2>/dev/null | grep -q universal-db-mcp; then systemctl stop universal-db-mcp || true; fi
if [ -d "$TARGET/venv.previous" ]; then
  echo "==> rolling back venv"
  # An upgrade killed between its two renames leaves NO current venv at all;
  # under set -e that used to abort here, before venv.previous was restored,
  # leaving the service's ExecStart path missing.
  if [ -d "$TARGET/venv" ]; then
    rm -rf "$TARGET/venv.failed"
    mv "$TARGET/venv" "$TARGET/venv.failed"
  else
    echo "    no current venv (upgrade interrupted mid-switch); restoring venv.previous in place"
  fi
  mv "$TARGET/venv.previous" "$TARGET/venv"
  # doctor resolves the config as args.config or $UDBMCP_CONFIG and fails
  # closed with "no config path" when neither is set; pass it explicitly so
  # the rollback is not aborted by its own validation after the venv swap.
  "$TARGET/venv/bin/python" -m universal_db_mcp doctor \
    --config "${UDBMCP_CONFIG:-$ETC_DIR/config.yaml}"
  if [ -d "$TARGET/venv.failed" ]; then
    echo "==> rollback complete (failed venv kept at $TARGET/venv.failed for analysis)"
  else
    echo "==> rollback complete"
  fi
else
  echo "no $TARGET/venv.previous found"
fi

LATEST_BACKUP="$(ls -1dt "$BACKUP_ROOT"/pre-upgrade-* 2>/dev/null | head -1 || true)"
if [ -n "$LATEST_BACKUP" ] && [ -f "$LATEST_BACKUP/universal-db-mcp/config.yaml" ]; then
  if [ "$RESTORE_CONFIG" -ne 1 ]; then
    echo "NOTE: a configuration backup exists at $LATEST_BACKUP, but --restore-config was not given;"
    echo "      the live configuration is left untouched (venv-only rollback)."
  else
    echo "==> restoring configuration from $LATEST_BACKUP (validated before anything is displaced)"
    rm -rf "$ETC_DIR.new"
    cp -a "$LATEST_BACKUP/universal-db-mcp" "$ETC_DIR.new"
    if [ -x "$TARGET/venv/bin/python" ]; then
      UDBMCP_CONFIG="$ETC_DIR.new/config.yaml" "$TARGET/venv/bin/python" -m universal_db_mcp doctor \
        || {
          echo "FAIL: the backup configuration failed validation; live configuration left untouched" >&2
          rm -rf "$ETC_DIR.new"
          exit 1
        }
    else
      echo "WARN: $TARGET/venv/bin/python not executable; restoring the backup without validation" >&2
    fi
    # The live configuration may contain edits made after the backup (new
    # connections, rotated CA paths); it is moved aside and KEPT, never
    # deleted, so a wrong rollback is itself reversible.
    PRE_ROLLBACK="$BACKUP_ROOT/pre-rollback-$(date -u +%Y%m%dT%H%M%SZ)"
    mkdir -p "$PRE_ROLLBACK"
    if [ -d "$ETC_DIR" ]; then mv "$ETC_DIR" "$PRE_ROLLBACK/universal-db-mcp"; fi
    mv "$ETC_DIR.new" "$ETC_DIR"
    echo "    previous live configuration preserved at $PRE_ROLLBACK/universal-db-mcp"
  fi
elif [ -n "$LATEST_BACKUP" ]; then
  echo "WARN: backup at $LATEST_BACKUP has no config.yaml; leaving live configuration untouched"
fi

if [ "$RESTORE_CONFIG" -eq 1 ] && [ -n "$LATEST_BACKUP" ] && [ -f "$LATEST_BACKUP/metadata.sqlite" ]; then
  mkdir -p "$STATE_DIR"
  if [ -f "$STATE_DIR/metadata.sqlite" ]; then
    cp "$STATE_DIR/metadata.sqlite" "$STATE_DIR/metadata.sqlite.pre-rollback"
  fi
  cp "$LATEST_BACKUP/metadata.sqlite" "$STATE_DIR/metadata.sqlite"
fi

echo "==> restart the service (systemctl restart universal-db-mcp)"
