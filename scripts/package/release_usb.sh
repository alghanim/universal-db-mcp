#!/usr/bin/env bash
# Build the release for an air-gapped Ubuntu site from the CURRENT commit:
#   signed linux bundle -> .deb -> no-network deb gate,
#   signed macOS bundle -> .pkg -> pkg gate,
#   dist/usb-ubuntu-<sha7>/ : the .deb, the trust bootstrap folder (verifier,
#   installer, profiles, os_packages helper, release PUBLIC key), the Oracle
#   Instant Client folder (client zip, libaio, unzip, README) and the site
#   runbook as UPGRADE-README.md, with SHA256SUMS over everything.
#
# Usage:  scripts/package/release_usb.sh
#   UDBMCP_RELEASE_KEY   signing key PEM (default: out/demo-keys/udbmcp-release-demo.pem)
#   UDBMCP_PUBKEY        matching public key (default: out/demo-keys/udbmcp-release-demo.pub.pem)
#   UDBMCP_ORACLE_CLIENT folder with the Instant Client files (default: out/oracle-client)
#
# Requirements: a clean working tree (the bundle's source_rev must be the
# commit), Docker (deb gate), macOS with pkgbuild/productbuild (pkg gate).
# The gates would stamp a timestamp as source_rev if they built the bundle
# themselves, so both bundles are built here and the gates REUSE them (they
# verify the reused bundle with the trusted key before packaging).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT="$(cd "$HERE/../.." && pwd -P)"
cd "$PROJECT"
PY="$PROJECT/.venv/bin/python"
SHA="$(git rev-parse HEAD)"; SHA7="${SHA:0:7}"
[ -z "$(git status --porcelain)" ] || { echo "FAIL: working tree not clean at $SHA7 (the bundle must carry the commit)" >&2; exit 1; }
KEY="${UDBMCP_RELEASE_KEY:-$PROJECT/out/demo-keys/udbmcp-release-demo.pem}"
PUB="${UDBMCP_PUBKEY:-$PROJECT/out/demo-keys/udbmcp-release-demo.pub.pem}"
ORA="${UDBMCP_ORACLE_CLIENT:-$PROJECT/out/oracle-client}"
case "$KEY" in /*) ;; *) KEY="$PROJECT/$KEY";; esac
case "$PUB" in /*) ;; *) PUB="$PROJECT/$PUB";; esac   # the gates bind-mount the public key: absolute
[ -s "$KEY" ] && [ -s "$PUB" ] || { echo "FAIL: signing key or public key missing ($KEY, $PUB)" >&2; exit 1; }
echo "=== release build at $SHA7 $(date -u +%FT%TZ)"

bundle_rev() { "$PY" -c "import json,glob; m=glob.glob('$1/universal-db-mcp-*/manifest.json'); print(json.load(open(m[0]))['source_rev'] if m else '')" 2>/dev/null; }
if [ "$(bundle_rev out/bundle)" = "$SHA" ]; then echo "=== linux bundle already built at $SHA7 (reused)"; else
  rm -rf out/bundle; echo "=== linux bundle (signed, source_rev=$SHA7)"
  "$PY" scripts/prepare_offline_bundle.py --out out/bundle --source-rev "$SHA" --signing-key "$KEY"; fi
if [ "$(bundle_rev out/bundle-macos)" = "$SHA" ]; then echo "=== macos bundle already built at $SHA7 (reused)"; else
  rm -rf out/bundle-macos; echo "=== macos bundle (signed, source_rev=$SHA7)"
  "$PY" scripts/prepare_offline_bundle.py --profile macos-arm64-cp312 --out out/bundle-macos --source-rev "$SHA" --signing-key "$KEY"; fi

echo "=== deb gate (reuses the signed linux bundle, builds the .deb, installs it with no network)"
UDBMCP_PUBKEY="$PUB" bash scripts/package/test_package_deb.sh
DEB="$(ls -t dist/universal-db-mcp_*.g${SHA7}_amd64.deb 2>/dev/null | head -1 || true)"
[ -n "$DEB" ] || { echo "FAIL: no .deb for $SHA in dist/" >&2; exit 1; }

echo "=== pkg gate (reuses the signed macos bundle, builds and inspects the .pkg)"
UDBMCP_PUBKEY="$PUB" bash scripts/package/test_package_pkg.sh
PKG=dist/universal-db-mcp-0.1.0-macos-arm64.pkg
[ -f "$PKG" ] || { echo "FAIL: no .pkg in dist/" >&2; exit 1; }

echo "=== USB folder"
USB="dist/usb-ubuntu-$SHA7"
rm -rf "$USB"; mkdir -p "$USB/trust-bootstrap-linux/lib" "$USB/oracle-instantclient"
cp "$DEB" "$USB/"
cp packaging/trust-bootstrap-linux/bootstrap.sh "$USB/trust-bootstrap-linux/"
cp scripts/install_offline.sh scripts/verify_bundle.py scripts/profiles.py "$USB/trust-bootstrap-linux/"
cp scripts/lib/os_packages.sh "$USB/trust-bootstrap-linux/lib/"
cp "$PUB" "$USB/trust-bootstrap-linux/release.pub.pem"
for f in README.txt instantclient-basiclite-linux.x64-19.28.zip libaio1t64_*.deb unzip_*.deb; do
  cp "$ORA"/$f "$USB/oracle-instantclient/"
done
cp docs/site-upgrade-runbook.md "$USB/UPGRADE-README.md"
( cd "$USB" && find . -type f ! -name SHA256SUMS | sed 's|^\./||' | sort | xargs shasum -a 256 > SHA256SUMS \
  && shasum -a 256 -c SHA256SUMS | grep -c ': OK$' | sed 's/^/usb files verified: /' )
echo "folder: $USB"; ls "$USB"
shasum -a 256 "$DEB" "$PKG"
echo "=== release build done $(date -u +%FT%TZ)"
