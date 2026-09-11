#!/usr/bin/env bash
# Staging machine only (network allowed here): build and export the verified
# platform baseline image for the profile linux-x86_64-ubuntu24.04-cp312.
# The baseline contains ONLY the OS + CPython 3.12 + venv support; no
# application code, no drivers. On the target, this image is loaded from the
# bundle (never pulled from a registry).
set -euo pipefail

PROJECT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="udbmcp-baseline:ubuntu24.04-cp312"
SIGNING_KEY="${UDBMCP_RELEASE_KEY:-}"
BUNDLE_DIR="${1:-$(ls -d "$PROJECT"/out/bundle/universal-db-mcp-* 2>/dev/null | head -1 || true)}"

echo "==> building baseline image $IMAGE for linux/amd64 (staging, network used here)"
docker build --platform linux/amd64 -t "$IMAGE" -f - . <<'DOCKERFILE'
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3.12 python3.12-venv python3.12-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && ln -sf /usr/bin/python3.12 /usr/local/bin/python3
DOCKERFILE

if [ -n "$BUNDLE_DIR" ] && [ -d "$BUNDLE_DIR/images" ]; then
  # Fail closed BEFORE touching the bundle: refreshing SHA256SUMS under an
  # existing SIGNATURE we cannot re-create leaves the bundle unverifiable.
  if [ -f "$BUNDLE_DIR/SIGNATURE" ] && [ -z "$SIGNING_KEY" ]; then
    echo "ERROR: bundle already contains a SIGNATURE but UDBMCP_RELEASE_KEY is not set; refreshing SHA256SUMS would invalidate it. Re-run with UDBMCP_RELEASE_KEY set to re-sign, or remove SIGNATURE for an explicitly unsigned bundle." >&2
    exit 1
  fi
  echo "==> exporting baseline image into bundle images/"
  docker save "$IMAGE" -o "$BUNDLE_DIR/images/udbmcp-baseline-ubuntu24.04-cp312.tar"
  sha256sum "$BUNDLE_DIR/images/udbmcp-baseline-ubuntu24.04-cp312.tar" > "$BUNDLE_DIR/images/SHA256SUMS"
  # refresh bundle checksums + manifest image identity
  "$PROJECT/.venv/bin/python" - "$BUNDLE_DIR" "$IMAGE" <<'PYEOF'
import hashlib, json, os, sys
from pathlib import Path
bundle, image = Path(sys.argv[1]), sys.argv[2]
# A pre-existing SIGNATURE without UDBMCP_RELEASE_KEY is rejected in bash,
# before the bundle is touched; this re-check fails closed if reached anyway.
if (bundle / "SIGNATURE").exists() and not os.environ.get("UDBMCP_RELEASE_KEY"):
    sys.exit(
        "ERROR: bundle already contains a SIGNATURE but UDBMCP_RELEASE_KEY is not "
        "set; refreshing SHA256SUMS would invalidate it.")
mf = bundle / "manifest.json"
m = json.loads(mf.read_text())
tar = bundle / "images" / "udbmcp-baseline-ubuntu24.04-cp312.tar"
m["image_identity"] = {
    "baseline_image": image,
    "file": "images/udbmcp-baseline-ubuntu24.04-cp312.tar",
    "sha256": hashlib.sha256(tar.read_bytes()).hexdigest(),
    "note": "load with: docker load -i images/udbmcp-baseline-*.tar (no registry access)",
}
mf.write_text(json.dumps(m, indent=2))
sums = []
for f in sorted(bundle.rglob("*")):
    if f.is_file() and f.name not in ("SHA256SUMS", "SIGNATURE"):
        sums.append(f"{hashlib.sha256(f.read_bytes()).hexdigest()}  {f.relative_to(bundle)}")
(bundle / "SHA256SUMS").write_text("\n".join(sums) + "\n")
print("manifest image_identity updated; SHA256SUMS refreshed")
if os.environ.get("UDBMCP_RELEASE_KEY"):
    import subprocess
    sig = subprocess.run(
        ["openssl", "pkeyutl", "-sign", "-inkey", os.environ["UDBMCP_RELEASE_KEY"], "-rawin"],
        input=(bundle / "SHA256SUMS").read_bytes(), capture_output=True)
    if sig.returncode == 0:
        (bundle / "SIGNATURE").write_bytes(sig.stdout)
    else:
        # Staging hosts with LibreSSL reject Ed25519 pkeyutl -rawin; fall
        # back to the python cryptography package (same primitive).
        try:
            from cryptography.hazmat.primitives.serialization import load_pem_private_key

            key = load_pem_private_key(
                Path(os.environ["UDBMCP_RELEASE_KEY"]).read_bytes(), password=None)
            (bundle / "SIGNATURE").write_bytes(key.sign((bundle / "SHA256SUMS").read_bytes()))
            print("(signed with python cryptography; host openssl lacks Ed25519 pkeyutl)")
        except ImportError:
            sys.exit(f"re-signing failed: {sig.stderr.decode()!r} and no cryptography fallback")
    print("SIGNATURE refreshed over the new SHA256SUMS")
else:
    # Unreachable with a pre-existing SIGNATURE (guarded above); this only
    # covers a bundle that was never signed.
    print("NOTE: no UDBMCP_RELEASE_KEY set; SHA256SUMS refreshed, bundle remains UNSIGNED")
PYEOF
else
  echo "NOTE: no bundle dir given/ found; baseline image built but not exported"
fi
echo "==> baseline ready"
