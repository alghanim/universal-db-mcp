#!/usr/bin/env bash
# Staging machine only (network allowed here): build and export the verified
# platform baseline image for the profile linux-x86_64-ubuntu24.04-cp312.
# The baseline contains ONLY the OS + CPython 3.12 + venv support; no
# application code, no drivers. On the target, this image is loaded from the
# bundle (never pulled from a registry).
#
# The base image is pinned by content digest: the default ubuntu:24.04 ref is
# resolved to its registry digest before building (or UDBMCP_BASE_IMAGE can be
# set to an already digest-pinned ref). The resolved reference is recorded in
# the bundle manifest and build log, and a rebuild that resolves a different
# digest fails closed unless UDBMCP_ALLOW_FLOATING_BASE=1.
set -euo pipefail

PROJECT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="udbmcp-baseline:ubuntu24.04-cp312"
SIGNING_KEY="${UDBMCP_RELEASE_KEY:-}"
BUNDLE_DIR="${1:-$(ls -d "$PROJECT"/out/bundle/universal-db-mcp-* 2>/dev/null | head -1 || true)}"
BASE_IMAGE="${UDBMCP_BASE_IMAGE:-ubuntu:24.04}"

case "$BASE_IMAGE" in
  *@sha256:*)
    # Already digest-pinned: use the reference verbatim.
    BASE_DIGEST="$BASE_IMAGE"
    PINNED_BASE="$BASE_IMAGE"
    ;;
  *)
    echo "==> resolving content digest for base image $BASE_IMAGE (staging, network used here)"
    docker pull "$BASE_IMAGE" >/dev/null 2>&1 \
      || echo "WARNING: docker pull $BASE_IMAGE failed; resolving digest from the local image" >&2
    BASE_DIGEST="$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$BASE_IMAGE" 2>/dev/null | head -n1 | tr -d '[:space:]' || true)"
    PINNED_BASE="${BASE_DIGEST:-$BASE_IMAGE}"
    ;;
esac
if [ -n "$BASE_DIGEST" ]; then
  echo "==> base image pinned by digest: $PINNED_BASE"
else
  echo "WARNING: unable to resolve a content digest for $BASE_IMAGE; building from the floating reference. Set UDBMCP_BASE_IMAGE to a digest-pinned ref (e.g. ubuntu@sha256:...) for reproducible baselines." >&2
fi

echo "==> building baseline image $IMAGE for linux/amd64 from $PINNED_BASE (staging, network used here)"
docker build --platform linux/amd64 -t "$IMAGE" --build-arg "BASE_IMAGE=$PINNED_BASE" -f - . <<'DOCKERFILE'
ARG BASE_IMAGE=ubuntu:24.04
FROM ${BASE_IMAGE}
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
  # Fail closed BEFORE touching the bundle: a rebuild whose base image
  # resolves to a different digest than the one recorded in the manifest
  # would silently change the signed baseline. Also refuse when the bundle
  # was pinned but this host cannot resolve a digest at all.
  OLD_BASE_DIGEST=""
  if [ -f "$BUNDLE_DIR/manifest.json" ]; then
    OLD_BASE_DIGEST="$("$PROJECT/.venv/bin/python" -c 'import json, sys
mf = json.load(open(sys.argv[1]))
print((mf.get("image_identity") or {}).get("base_image_digest") or "")' "$BUNDLE_DIR/manifest.json" 2>/dev/null || true)"
  fi
  if [ -n "$OLD_BASE_DIGEST" ] && [ "${UDBMCP_ALLOW_FLOATING_BASE:-}" != "1" ]; then
    if [ -z "$BASE_DIGEST" ]; then
      echo "ERROR: bundle was previously built from pinned base image digest $OLD_BASE_DIGEST but no digest could be resolved for $BASE_IMAGE on this host. Re-run with UDBMCP_BASE_IMAGE set to a digest-pinned ref, or UDBMCP_ALLOW_FLOATING_BASE=1 to accept an unpinned rebuild." >&2
      exit 1
    fi
    if [ "$OLD_BASE_DIGEST" != "$BASE_DIGEST" ]; then
      echo "ERROR: base image digest changed: bundle was built from $OLD_BASE_DIGEST but the current base resolves to $BASE_DIGEST. Re-run with UDBMCP_ALLOW_FLOATING_BASE=1 to accept the new base image." >&2
      exit 1
    fi
  fi
  echo "==> exporting baseline image into bundle images/"
  docker save "$IMAGE" -o "$BUNDLE_DIR/images/udbmcp-baseline-ubuntu24.04-cp312.tar"
  sha256sum "$BUNDLE_DIR/images/udbmcp-baseline-ubuntu24.04-cp312.tar" > "$BUNDLE_DIR/images/SHA256SUMS"
  # refresh bundle checksums + manifest image identity
  "$PROJECT/.venv/bin/python" - "$BUNDLE_DIR" "$IMAGE" "$PINNED_BASE" "$BASE_DIGEST" <<'PYEOF'
import hashlib, json, os, sys
from pathlib import Path
bundle, image = Path(sys.argv[1]), sys.argv[2]
pinned_base, pinned_digest = sys.argv[3], (sys.argv[4] or None)
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
    "base_image": pinned_base,
    "base_image_digest": pinned_digest,
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
    sums_path, sig_path = bundle / "SHA256SUMS", bundle / "SIGNATURE"
    data = sums_path.read_bytes()
    sig_path.unlink(missing_ok=True)  # never leave a partial artifact behind
    sig = subprocess.run(
        ["openssl", "pkeyutl", "-sign", "-inkey", os.environ["UDBMCP_RELEASE_KEY"],
         "-rawin", "-in", str(sums_path), "-out", str(sig_path)],
        capture_output=True)
    if sig.returncode == 0:
        print("signed with openssl pkeyutl (Ed25519)")
    else:
        # OpenSSL 3.x cannot feed `pkeyutl -rawin` over a non-seekable stdin
        # ('unable to determine file size for oneshot operation' — Ed25519 is
        # a one-shot signer and pkeyutl needs a seekable -in), which is why
        # the payload goes through -in/-out files above. If the host openssl
        # still refuses Ed25519 (e.g. a LibreSSL-based openssl binary), fall
        # back to the python cryptography package (same primitive), loudly.
        err = sig.stderr.decode(errors="replace").strip()[:200]
        print(f"WARNING: openssl Ed25519 signing failed ({err!r}); "
              "falling back to the python cryptography package")
        try:
            from cryptography.hazmat.primitives.serialization import load_pem_private_key

            key = load_pem_private_key(
                Path(os.environ["UDBMCP_RELEASE_KEY"]).read_bytes(), password=None)
            sig_path.write_bytes(key.sign(data))
            print("signed with python cryptography (host openssl lacks Ed25519 pkeyutl)")
        except ImportError:
            sig_path.unlink(missing_ok=True)
            sys.exit(
                f"re-signing failed: openssl error {err!r} and "
                "no cryptography fallback installed")
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
