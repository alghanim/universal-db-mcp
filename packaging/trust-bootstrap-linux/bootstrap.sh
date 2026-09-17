#!/bin/bash
# Trust bootstrap for universal-db-mcp on Ubuntu/Debian.
#
# Run FROM the trusted channel: this folder, carried on the same USB stick
# that delivered the .deb. It installs the trusted verifier, the profile
# registry, the offline installer and its helper, and the release PUBLIC key
# at the fixed root-owned paths the package's preinst/postinst require.
# Nothing here touches the package payload - the payload stays verified by
# THESE tools after unpacking.
#
# The release public key is the trust anchor of the site. Once one is
# installed, this script REFUSES to replace it with a different key unless
# the operator passes --rotate-key after comparing the fingerprint printed
# below with the value recorded out-of-band (a stick that carries its own
# key, verifier and package would otherwise verify itself).
#
# Usage (from this folder):  sudo bash bootstrap.sh [--rotate-key]
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd -P)"
TRUST_DIR="/usr/local/lib/udbmcp-trust"
KEY_DST="/etc/universal-db-mcp/keys/release.pub.pem"
ROTATE=0
for arg in "$@"; do
  case "$arg" in
    --rotate-key) ROTATE=1 ;;
    *) echo "usage: sudo bash bootstrap.sh [--rotate-key]" >&2; exit 2 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "FAIL: run with sudo (destinations are root-owned)." >&2; exit 1; }
for f in verify_bundle.py profiles.py install_offline.sh lib/os_packages.sh release.pub.pem; do
  [ -s "$DIR/$f" ] || { echo "FAIL: missing or empty: $DIR/$f" >&2; exit 1; }
done

fingerprint() {
  # SHA-256 of the DER-encoded public key; stable across PEM line wrapping
  if command -v openssl >/dev/null 2>&1; then
    openssl pkey -pubin -in "$1" -outform DER 2>/dev/null | sha256sum | awk '{print $1}'
  else
    sed -e '/^-----/d' "$1" | tr -d '\n' | base64 -d 2>/dev/null | sha256sum | awk '{print $1}'
  fi
}

NEW_FP="$(fingerprint "$DIR/release.pub.pem")"
[ -n "$NEW_FP" ] || { echo "FAIL: $DIR/release.pub.pem is not a readable public key." >&2; exit 1; }
echo "==> release public key on this stick: sha256 $NEW_FP"
if [ -s "$KEY_DST" ]; then
  CUR_FP="$(fingerprint "$KEY_DST")"
  echo "==> release public key already installed: sha256 $CUR_FP"
  if [ "$CUR_FP" != "$NEW_FP" ] && [ "$ROTATE" -ne 1 ]; then
    echo "FAIL: the key on this stick differs from the installed trust anchor; refusing to replace it." >&2
    echo "      Compare BOTH fingerprints with the value your release administrator gave you" >&2
    echo "      out-of-band. Only if the stick's key is the legitimate new key, re-run with:" >&2
    echo "        sudo bash $DIR/bootstrap.sh --rotate-key" >&2
    exit 1
  fi
fi

install -d -m 755 "$TRUST_DIR" "$TRUST_DIR/lib" /etc/universal-db-mcp/keys
install -m 644 "$DIR/verify_bundle.py" "$TRUST_DIR/"
install -m 644 "$DIR/profiles.py" "$TRUST_DIR/"
install -m 755 "$DIR/install_offline.sh" "$TRUST_DIR/"
install -m 644 "$DIR/lib/os_packages.sh" "$TRUST_DIR/lib/"
if [ -s "$KEY_DST" ] && [ "$(fingerprint "$KEY_DST")" = "$NEW_FP" ]; then
  echo "==> release public key unchanged (same fingerprint); left in place"
else
  install -m 644 "$DIR/release.pub.pem" "$KEY_DST"
  echo "==> release public key installed at $KEY_DST"
fi

echo "==> trust bootstrap complete:"
echo "    verifier : $TRUST_DIR/verify_bundle.py"
echo "    registry : $TRUST_DIR/profiles.py"
echo "    installer: $TRUST_DIR/install_offline.sh"
echo "    helper   : $TRUST_DIR/lib/os_packages.sh"
echo "    pubkey   : $KEY_DST (sha256 $NEW_FP)"
echo "==> now install the package:"
echo "    sudo dpkg -i /path/to/universal-db-mcp_<version>_amd64.deb"
