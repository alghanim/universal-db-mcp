#!/usr/bin/env bash
# Gate A+B orchestrator: clean offline installation + no-network protocol
# test inside the verified baseline container (no registry access at run
# time: the baseline image is loaded from the bundle or already local).
# Evidence lands in out/airgap-evidence/.
set -euo pipefail

PROJECT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$PROJECT/out"
IMAGE="udbmcp-baseline:ubuntu24.04-cp312"
BUNDLE_DIR_DEFAULT="$(ls -d "$OUT"/bundle/universal-db-mcp-* 2>/dev/null | head -1 || true)"
BUNDLE="${BUNDLE_DIR:-$BUNDLE_DIR_DEFAULT}"

if [ -z "$BUNDLE" ]; then
  echo "no bundle found; building one first (staging machine, network allowed here)"
  # The in-container verifier is always handed a public key, so the bootstrap
  # bundle MUST be signed or verification fails closed ("SIGNATURE missing but
  # a public key was provided"). Sign with UDBMCP_RELEASE_KEY when it is set;
  # otherwise generate an EPHEMERAL Ed25519 key pair for this run only — a
  # local test convenience, never a release trust anchor.
  BOOTSTRAP_KEYS="$OUT/airgap-bootstrap"
  mkdir -p "$BOOTSTRAP_KEYS"
  if [ -n "${UDBMCP_RELEASE_KEY:-}" ] && [ -f "$UDBMCP_RELEASE_KEY" ]; then
    BOOTSTRAP_SIGNING_KEY="$UDBMCP_RELEASE_KEY"
    echo "==> signing bootstrap bundle with UDBMCP_RELEASE_KEY"
  else
    BOOTSTRAP_SIGNING_KEY="$BOOTSTRAP_KEYS/ephemeral-signing-key.pem"
    echo "==> UDBMCP_RELEASE_KEY not set; generating an EPHEMERAL signing key (local test convenience, not a release trust anchor)"
    "$PROJECT/.venv/bin/python" - "$BOOTSTRAP_SIGNING_KEY" <<'PY'
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

key = Ed25519PrivateKey.generate()
key_path = Path(sys.argv[1])
key_path.write_bytes(
    key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
)
key_path.chmod(0o600)
PY
  fi
  BOOTSTRAP_PUBKEY="$BOOTSTRAP_KEYS/release-pubkey.pem"
  # Derive the matching public key so the container verifies against exactly
  # the key that signed this bundle.
  "$PROJECT/.venv/bin/python" - "$BOOTSTRAP_SIGNING_KEY" "$BOOTSTRAP_PUBKEY" <<'PY'
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization

key = serialization.load_pem_private_key(Path(sys.argv[1]).read_bytes(), password=None)
Path(sys.argv[2]).write_bytes(
    key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
)
PY
  "$PROJECT/.venv/bin/python" "$PROJECT/scripts/prepare_offline_bundle.py" \
    --out "$OUT/bundle" \
    --source-rev "$(date -u +%Y%m%d%H%M%S)" \
    --signing-key "$BOOTSTRAP_SIGNING_KEY"
  BUNDLE="$(ls -d "$OUT"/bundle/universal-db-mcp-* | head -1)"
  # Verify against the key that actually signed this freshly built bundle: any
  # UDBMCP_RELEASE_PUBKEY pre-set in the environment cannot match it.
  UDBMCP_RELEASE_PUBKEY="$BOOTSTRAP_PUBKEY"
fi

# Baseline image: load from the bundle if not present locally (this is the
# offline path targets use; no pull, no registry).
if ! docker image inspect "$IMAGE" > /dev/null 2>&1; then
  TAR="$BUNDLE/images/udbmcp-baseline-ubuntu24.04-cp312.tar"
  if [ -f "$TAR" ]; then
    echo "==> loading baseline image from bundle (offline path)"
    docker load -i "$TAR"
  else
    echo "==> baseline image not local and not in bundle; building it (staging only)"
    bash "$PROJECT/scripts/prepare_baseline_image.sh" "$BUNDLE"
  fi
fi

mkdir -p "$OUT/airgap-evidence"
echo "==> running air-gap test with bundle: $BUNDLE"
echo "==> container network: NONE, platform: linux/amd64 (emulated on this host)"
PUBKEY_MOUNT=""
if [ -n "${UDBMCP_RELEASE_PUBKEY:-}" ] && [ -f "$UDBMCP_RELEASE_PUBKEY" ]; then
  PUBKEY_MOUNT="-v $UDBMCP_RELEASE_PUBKEY:/pubkey.pem:ro"
fi
TRUSTED_TOOLS="$(dirname "$BUNDLE")/trusted-tools"
[ -d "$TRUSTED_TOOLS" ] || { echo "FAIL: trusted-tools dir not found next to the bundle: $TRUSTED_TOOLS"; exit 1; }
docker run --rm --network none --platform linux/amd64 \
  -v "$BUNDLE":/bundle:ro \
  -v "$TRUSTED_TOOLS":/trusted-tools:ro \
  ${PUBKEY_MOUNT} \
  -e UDBMCP_RELEASE_PUBKEY=/pubkey.pem \
  -v "$OUT/airgap-evidence":/evidence \
  -e BUNDLE_DIR=/bundle -e EVIDENCE_DIR=/evidence \
  "$IMAGE" \
  bash /bundle/tests/in_container_test.sh
