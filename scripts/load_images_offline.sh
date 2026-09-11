#!/usr/bin/env bash
# Container mode: load bundle images locally and verify identities.
# No registry access. An absent image file fails with the exact artifact name.
set -euo pipefail

BUNDLE="${1:?usage: load_images_offline.sh <bundle-dir>}"

expected_digest_for() {
  python3 - "$BUNDLE/manifest.json" "$1" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
ident = m.get("image_identity") or {}
if "baseline" in sys.argv[2]:
    print(ident.get("sha256", ""))
else:
    print(ident.get("sha256", ""))
PY
}

load_one() {
  local tar="$1" expect="$2"
  if [ ! -f "$tar" ]; then
    echo "FAIL: required image archive '$tar' is missing from the bundle" >&2
    exit 1
  fi
  local want
  want=$(sha256sum "$tar" | awk '{print $1}')
  local recorded
  recorded=$(python3 -c "import json,sys; print((json.load(open('$BUNDLE/manifest.json')).get('image_identity') or {}).get('sha256',''))" 2>/dev/null || true)
  if [ -n "$recorded" ] && [ "$want" != "$recorded" ] && echo "$tar" | grep -q baseline; then
    echo "FAIL: baseline image tar sha256 does not match manifest image_identity" >&2
    exit 1
  fi
  echo "==> loading $(basename "$tar")"
  docker load -i "$tar"
  if [ -n "$expect" ]; then
    docker image inspect "$expect" > /dev/null 2>&1 || {
      echo "FAIL: image '$expect' not present after load (identity mismatch)" >&2
      exit 1
    }
    echo "    identity verified: $expect"
  fi
}

BASELINE_TAR="$BUNDLE/images/udbmcp-baseline-ubuntu24.04-cp312.tar"
APP_TAR="$BUNDLE/images/universal-db-mcp.tar"
APP_REF=$(python3 - "$BUNDLE/manifest.json" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
ident = m.get("image_identity") or {}
print(ident.get("application_image", "udbmcp/universal-db-mcp:0.1.0-linux-x86_64-ubuntu24.04-cp312"))
PY
)

load_one "$BASELINE_TAR" "udbmcp-baseline:ubuntu24.04-cp312"
if [ -f "$APP_TAR" ]; then
  load_one "$APP_TAR" "$APP_REF"
else
  echo "NOTE: application image not in bundle (native mode deployment); baseline loaded."
fi
echo "==> images ready (pull_policy: never in compose.offline.yaml)"
