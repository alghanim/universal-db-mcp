#!/usr/bin/env bash
# macOS trust bootstrap — one command before installing the .pkg.
#
# The .pkg's preinstall/postinstall refuse to touch the bundle payload until
# the trusted verifier and the release public key are installed at fixed
# root-owned paths OUTSIDE the bundle (verify-before-execute; a verifier or
# key shipped inside the bundle authenticates nothing). This script installs
# exactly that trust material from the staging machine's trusted-channel copy
# (out/bundle-macos/trusted-tools, produced by the signed bundle builder and
# kept outside the bundle by design).
#
# Usage (from the repo root, as root because the destinations are root-owned):
#   sudo bash scripts/package/bootstrap_trust_macos.sh [trusted-tools-dir] [pubkey]
#
# Defaults match the macOS bundle this repo builds:
#   trusted-tools dir : out/bundle-macos/trusted-tools
#   release pubkey    : out/demo-keys/udbmcp-release-demo.pub.pem
set -euo pipefail

TRUST_DIR="/usr/local/lib/udbmcp-trust"
PUBKEY_DEST="/etc/universal-db-mcp/keys/release.pub.pem"

TRUSTED="${1:-out/bundle-macos/trusted-tools}"
PUBKEY="${2:-out/demo-keys/udbmcp-release-demo.pub.pem}"

if [ "$(id -u)" -ne 0 ]; then
  echo "FAIL: run with sudo (destinations under /usr/local and /etc are root-owned)." >&2
  exit 1
fi
for f in "$TRUSTED/verify_bundle.py" "$TRUSTED/profiles.py" \
         "$TRUSTED/install_offline.sh" "$TRUSTED/lib/os_packages.sh"; do
  [ -s "$f" ] || { echo "FAIL: trusted-channel file missing or empty: $f (run from the repo root, or pass the trusted-tools dir as \$1)." >&2; exit 1; }
done
[ -s "$PUBKEY" ] || { echo "FAIL: release pubkey missing or empty: $PUBKEY (pass it as \$2)." >&2; exit 1; }

install -d -m 755 "$TRUST_DIR" "$TRUST_DIR/lib" "$(dirname "$PUBKEY_DEST")"
install -m 644 "$TRUSTED/verify_bundle.py" "$TRUST_DIR/"
install -m 644 "$TRUSTED/profiles.py" "$TRUST_DIR/"
install -m 755 "$TRUSTED/install_offline.sh" "$TRUST_DIR/"
install -m 644 "$TRUSTED/lib/os_packages.sh" "$TRUST_DIR/lib/"
install -m 644 "$PUBKEY" "$PUBKEY_DEST"

echo "==> trust bootstrap complete:"
echo "    verifier : $TRUST_DIR/verify_bundle.py"
echo "    registry : $TRUST_DIR/profiles.py"
echo "    installer: $TRUST_DIR/install_offline.sh"
echo "    helper   : $TRUST_DIR/lib/os_packages.sh"
echo "    pubkey   : $PUBKEY_DEST"
echo "==> remaining prerequisite: an all-users CPython 3.12 (python.org"
echo "    installer -> /Library/Frameworks). Then re-run the .pkg installer."
