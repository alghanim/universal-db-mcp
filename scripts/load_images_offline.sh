#!/usr/bin/env bash
# Container mode: verify the offline bundle (integrity + authenticity), then
# load its images locally. No registry access. An absent image file fails
# with the exact artifact name.
set -euo pipefail

BUNDLE="${1:?usage: load_images_offline.sh <bundle-dir>}"

# Fail closed: manifest.json and the image tars are untrusted until the
# trusted-path verifier (installed from a separate channel, never read from
# inside the bundle it verifies) has checked every artifact against the
# SIGNED SHA256SUMS and the SIGNATURE against the independently distributed
# public key. This covers images/universal-db-mcp.tar too — comparing a tar
# against a digest recorded in the unauthenticated manifest.json inside the
# same bundle would verify nothing.
TRUST="${UDBMCP_TRUST_DIR:-/trusted-tools}"
PUBKEY="${UDBMCP_RELEASE_PUBKEY:?UDBMCP_RELEASE_PUBKEY must point at the release public key PEM obtained through your trusted channel}"
echo "==> verifying bundle before any image is loaded"
python3 "$TRUST/verify_bundle.py" --bundle "$BUNDLE" --pubkey "$PUBKEY"

load_one() {
  local tar="$1" expect="$2"
  if [ ! -f "$tar" ]; then
    echo "FAIL: required image archive '$tar' is missing from the bundle" >&2
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

APP_REF=$(python3 - "$BUNDLE/manifest.json" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
ident = m.get("image_identity") or {}
print(ident.get("application_image", "udbmcp/universal-db-mcp:0.1.0-linux-x86_64-ubuntu24.04-cp312"))
PY
)

load_one "$BUNDLE/images/udbmcp-baseline-ubuntu24.04-cp312.tar" "udbmcp-baseline:ubuntu24.04-cp312"
if [ -f "$BUNDLE/images/universal-db-mcp.tar" ]; then
  load_one "$BUNDLE/images/universal-db-mcp.tar" "$APP_REF"
else
  echo "NOTE: application image not in bundle (native mode deployment); baseline loaded."
fi
echo "==> images ready (pull_policy: never in compose.offline.yaml)"
