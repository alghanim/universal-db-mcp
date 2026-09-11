#!/usr/bin/env bash
# Offline upgrade using only local signed bundles. Never updates production
# dependencies automatically; never contacts any registry.
set -euo pipefail

NEW_BUNDLE="${1:?usage: upgrade_offline.sh <new-bundle-dir>}"
TARGET="${2:-/opt/universal-db-mcp}"
BACKUP="${3:-/var/backups/universal-db-mcp}"

echo "==> preflight: verify new bundle (authenticity REQUIRED)"
PUBKEY="${UDBMCP_RELEASE_PUBKEY:-}"
if [ -z "$PUBKEY" ]; then
  echo "FAIL: set UDBMCP_RELEASE_PUBKEY to the release public key PEM path." >&2
  exit 1
fi

# --- trust boundary ---------------------------------------------------------
# The verifier must NOT come from the bundle it verifies: a tampered bundle
# would simply ship a verifier that prints PASSED. Both the verifier and this
# installer are distributed on the same trusted channel as the release public
# key and installed at a root-owned path; a copy inside the bundle is a
# reference copy only and is never executed by these scripts.
TRUST_DIR="${UDBMCP_TRUST_DIR:-/usr/local/lib/udbmcp-trust}"
VERIFIER="${UDBMCP_VERIFIER:-$TRUST_DIR/verify_bundle.py}"
self_path="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)/$(basename "${BASH_SOURCE[0]}")"
bundle_real="$(cd "$NEW_BUNDLE" && pwd -P)"
case "$self_path" in
  "$bundle_real"/*)
    echo "FAIL: refusing to run from inside the bundle being verified ($self_path)." >&2
    echo "      Install the trusted tools first (see docs/offline-deployment.md, 'Trust bootstrap'):" >&2
    echo "        sudo install -d -m 755 $TRUST_DIR" >&2
    echo "        sudo install -m 644 <trusted-channel>/verify_bundle.py $TRUST_DIR/" >&2
    echo "        sudo install -m 755 <trusted-channel>/install_offline.sh $TRUST_DIR/" >&2
    echo "      then run: sudo bash $TRUST_DIR/install_offline.sh <bundle-dir>" >&2
    exit 1 ;;
esac
if [ ! -f "$VERIFIER" ]; then
  echo "FAIL: trusted verifier not found at $VERIFIER (set UDBMCP_VERIFIER or install the trusted tools)." >&2
  exit 1
fi
case "$(cd "$(dirname "$VERIFIER")" && pwd -P)" in
  "$bundle_real"/*)
    echo "FAIL: UDBMCP_VERIFIER points inside the bundle; the verifier must come from the trusted channel." >&2
    exit 1 ;;
esac
python3 "$VERIFIER" --bundle "$NEW_BUNDLE" --pubkey "$PUBKEY"

echo "==> backing up current configuration and local state"
mkdir -p "$BACKUP/pre-upgrade-$(date -u +%Y%m%dT%H%M%SZ)"
cp -a /etc/universal-db-mcp "$BACKUP/pre-upgrade-$(date -u +%Y%m%dT%H%M%SZ)/" 2>/dev/null || true
[ -f /var/lib/universal-db-mcp/metadata.sqlite ] && \
  cp /var/lib/universal-db-mcp/metadata.sqlite "$BACKUP/pre-upgrade-$(date -u +%Y%m%dT%H%M%SZ)/" || true

echo "==> building new venv alongside current (atomic switch on success)"
PY=python3.12
command -v "$PY" >/dev/null 2>&1 || PY=python3
"$PY" -c 'import sys; assert sys.version_info[:2] == (3, 12), f"CPython 3.12.x required, got {sys.version}"'
NEWVENV="$TARGET/venv.new-$(date -u +%Y%m%dT%H%M%SZ)"
"$PY" -m venv "$NEWVENV"
PIP_CONFIG_FILE=/dev/null PIP_DISABLE_PIP_VERSION_CHECK=1 \
"$NEWVENV/bin/python" -m pip --isolated --disable-pip-version-check install \
  --no-index --no-cache-dir \
  --find-links="$NEW_BUNDLE/wheelhouse" \
  --only-binary=:all: --require-hashes \
  -r "$NEW_BUNDLE/requirements/runtime.lock"

echo "==> smoke check + doctor on the NEW venv before switching"
"$NEWVENV/bin/python" -m universal_db_mcp version
if [ -f /etc/universal-db-mcp/config.yaml ]; then
  UDBMCP_CONFIG=/etc/universal-db-mcp/config.yaml "$NEWVENV/bin/python" -m universal_db_mcp doctor \
    || { echo "FAIL: doctor failed on the new venv; aborting without switching" >&2; rm -rf "$NEWVENV"; exit 1; }
fi

echo "==> switching (old venv kept for rollback; depth 1)"
if systemctl list-unit-files 2>/dev/null | grep -q universal-db-mcp; then systemctl stop universal-db-mcp || true; fi
if [ -d "$TARGET/venv" ]; then
  rm -rf "$TARGET/venv.previous"   # rollback depth is one release
  mv "$TARGET/venv" "$TARGET/venv.previous"
fi
mv "$NEWVENV" "$TARGET/venv"

echo "==> validating effective installation"
# doctor resolves the config as args.config or $UDBMCP_CONFIG and fails closed
# with "no config path" when neither is set; pass it explicitly so a healthy
# upgrade is not rolled back by its own validation.
if ! "$TARGET/venv/bin/python" -m universal_db_mcp doctor \
  --config "${UDBMCP_CONFIG:-/etc/universal-db-mcp/config.yaml}"; then
  echo "FAIL: doctor failed after switch; rolling back automatically" >&2
  rm -rf "$TARGET/venv.failed"; mv "$TARGET/venv" "$TARGET/venv.failed"
  [ -d "$TARGET/venv.previous" ] && mv "$TARGET/venv.previous" "$TARGET/venv"
  exit 1
fi
if systemctl list-unit-files 2>/dev/null | grep -q universal-db-mcp; then systemctl start universal-db-mcp || true; fi

echo "==> upgraded. Rollback if needed:"
echo "    rollback_offline.sh $TARGET"
echo "Interrupted mid-way? Re-run: the .new-* venv is discarded and rebuilt."
