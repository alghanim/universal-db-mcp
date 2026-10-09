#!/usr/bin/env bash
# Build the release for an air-gapped Ubuntu site from the CURRENT commit:
#   signed linux bundle -> .deb -> no-network deb gate,
#   signed macOS bundle -> .pkg -> pkg gate,
#   dist/usb-ubuntu-<sha7>/ : the .deb, the trust bootstrap folder (verifier,
#   installer, profiles, os_packages helper, release PUBLIC key), the Oracle
#   Instant Client folder (client zip, libaio, unzip, README) and the site
#   runbook as UPGRADE-README.md, the release's release_seq in
#   trust-bootstrap-linux/RELEASE (bootstrap.sh refuses a stick older than the
#   one whose tools it installed), with SHA256SUMS over everything and
#   SHA256SUMS.sig, a detached Ed25519 signature over SHA256SUMS made with the
#   release key. The bundle signature covers only the payload inside the
#   package; the .deb's maintainer scripts, bootstrap.sh and the trust tools
#   are covered by SHA256SUMS.sig alone. It protects the site only when the
#   site's INSTALLED tools check it with the installed key before anything
#   from the stick runs (sudo bash /usr/local/lib/udbmcp-trust/bootstrap.sh
#   --stick <stick>, the copy an earlier bootstrap installed); the stick's own
#   bootstrap.sh can only prove the stick matches the key it carries.
#
# Usage:  UDBMCP_RELEASE_KEY=<key.pem> UDBMCP_PUBKEY=<pub.pem> scripts/package/release_usb.sh
#         scripts/package/release_usb.sh --demo     (the DEMO key pair in out/demo-keys; never for a real site)
#         ... release_usb.sh [--demo] --sign-stick <dir>
#             (re)write <dir>/SHA256SUMS and SHA256SUMS.sig for a stick folder
#             and exit; no build, no gates, no clean-tree requirement
#   UDBMCP_RELEASE_KEY   signing key PEM (required unless --demo)
#   UDBMCP_PUBKEY        matching public key (required unless --demo)
#   UDBMCP_ORACLE_CLIENT folder with the Instant Client files (default: out/oracle-client)
#   UDBMCP_WITHOUT_MSSQL_DRIVER=1  build the Linux bundle (and so the .deb) without
#                        Microsoft's ODBC Driver 18 and its unixODBC closure, for a release
#                        that must not redistribute it (a public one); the manifest declares
#                        the driver administrator_supplied. A site's own stick keeps it.
# The public key's fingerprint (sha256 of the DER encoding, what the site's
# bootstrap.sh prints) is printed and written to RELEASE-KEY-FINGERPRINT.txt
# on the stick so the operator can compare it out-of-band.
#
# Requirements: a clean working tree (the bundle's source_rev must be the
# commit), Docker (deb gate), macOS with pkgbuild/productbuild (pkg gate).
# The gates would stamp a timestamp as source_rev if they built the bundle
# themselves, so both bundles are built here and the gates REUSE them (they
# verify the reused bundle with the trusted key before packaging).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT="$(cd "$HERE/../.." && pwd -P)"
PY="$PROJECT/.venv/bin/python"
DEMO=0
SIGN_STICK=""
usage() { echo "usage: [UDBMCP_RELEASE_KEY=<key.pem> UDBMCP_PUBKEY=<pub.pem>] scripts/package/release_usb.sh [--demo] [--sign-stick <dir>]" >&2; exit 2; }
while [ "$#" -gt 0 ]; do
  case "$1" in
    --demo) DEMO=1 ;;
    --sign-stick)
      [ "$#" -ge 2 ] && [ -d "$2" ] || usage
      SIGN_STICK="$(cd "$2" && pwd -P)"; shift ;;
    *) usage ;;
  esac
  shift
done
cd "$PROJECT"
# The key pair is never implied: a release signed with the demo key by
# accident would verify at a site bootstrapped with the demo public key.
if [ -n "${UDBMCP_RELEASE_KEY:-}" ] && [ -n "${UDBMCP_PUBKEY:-}" ]; then
  [ "$DEMO" -eq 0 ] || { echo "FAIL: --demo and UDBMCP_RELEASE_KEY/UDBMCP_PUBKEY are exclusive" >&2; exit 1; }
  KEY="$UDBMCP_RELEASE_KEY"; PUB="$UDBMCP_PUBKEY"
elif [ "$DEMO" -eq 1 ]; then
  KEY="$PROJECT/out/demo-keys/udbmcp-release-demo.pem"; PUB="$PROJECT/out/demo-keys/udbmcp-release-demo.pub.pem"
else
  echo "FAIL: set BOTH UDBMCP_RELEASE_KEY and UDBMCP_PUBKEY to the site's release key pair," >&2
  echo "      or pass --demo to build with the DEMO key in out/demo-keys (never for a real site)." >&2
  exit 1
fi
ORA="${UDBMCP_ORACLE_CLIENT:-$PROJECT/out/oracle-client}"
case "$KEY" in /*) ;; *) KEY="$PROJECT/$KEY";; esac
case "$PUB" in /*) ;; *) PUB="$PROJECT/$PUB";; esac   # the gates bind-mount the public key: absolute
[ -s "$KEY" ] && [ -s "$PUB" ] || { echo "FAIL: signing key or public key missing ($KEY, $PUB)" >&2; exit 1; }
FP="$(openssl pkey -pubin -in "$PUB" -outform DER 2>/dev/null | shasum -a 256 | awk '{print $1}')"
[ -n "$FP" ] || { echo "FAIL: $PUB is not a readable public key" >&2; exit 1; }
KEY_NOTE=""; [ "$DEMO" -eq 0 ] || KEY_NOTE=" (DEMO KEY PAIR from out/demo-keys)"
echo "=== release public key sha256 $FP$KEY_NOTE"

# SHA256SUMS over every file in the stick folder, then SHA256SUMS.sig: the
# release key's detached Ed25519 signature over it (openssl first, the python
# cryptography package where the host openssl is LibreSSL). A plain checksum
# list proves nothing on its own: whoever can write the stick regenerates it.
# The signature is checked here with the TRUSTED verifier's own code against
# the public key, so a key pair that does not match fails the release instead
# of the site.
# What the stick holds is what bootstrap.sh checks on the site: every file
# but the metadata a Mac or Windows writes onto a stick (._* AppleDouble
# files, .DS_Store, the volume's Spotlight/fseventsd/Trashes folders and
# System Volume Information), which nothing reads and Finder rewrites. A ._*
# or .DS_Store name is skipped only as a regular file, as on the site.
stick_files() {
  ( cd "$1" && shift && find . \( -path ./.Spotlight-V100 -o -path ./.fseventsd -o -path ./.Trashes \
      -o -path ./.TemporaryItems -o -path './System Volume Information' \) -prune \
      -o ! -type d ! \( -type f \( -name '._*' -o -name .DS_Store \) \) \
      ! -path ./SHA256SUMS ! -path ./SHA256SUMS.sig "$@" -print ) \
    | sed 's|^\./||'
}
sign_stick() {
  local dir="$1" odd
  rm -f "$dir/SHA256SUMS" "$dir/SHA256SUMS.sig"
  # the site refuses anything but regular files (a symlink can change after the check)
  odd="$(stick_files "$dir" ! -type f)"
  [ -z "$odd" ] || { printf 'FAIL: not a regular file (bootstrap.sh refuses the stick): %s\n' "$odd" >&2; exit 1; }
  # the release order bootstrap.sh keeps: one release_seq, as it reads it
  if [ -e "$dir/trust-bootstrap-linux/RELEASE" ]; then
    [ "$(wc -l < "$dir/trust-bootstrap-linux/RELEASE")" -le 1 ] \
      && grep -qxE '[0-9]{1,18}' "$dir/trust-bootstrap-linux/RELEASE" \
      || { echo "FAIL: $dir/trust-bootstrap-linux/RELEASE must hold the release_seq alone (bootstrap.sh refuses the stick)" >&2; exit 1; }
  fi
  stick_files "$dir" | LC_ALL=C sort | ( cd "$dir" && tr '\n' '\0' | xargs -0 shasum -a 256 > SHA256SUMS )
  openssl pkeyutl -sign -inkey "$KEY" -rawin -in "$dir/SHA256SUMS" -out "$dir/SHA256SUMS.sig" 2>/dev/null \
    || "$PY" - "$KEY" "$dir/SHA256SUMS" "$dir/SHA256SUMS.sig" <<'PY'
import sys
from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_pem_private_key

key = load_pem_private_key(Path(sys.argv[1]).read_bytes(), password=None)
Path(sys.argv[3]).write_bytes(key.sign(Path(sys.argv[2]).read_bytes()))
PY
  "$PY" "$PROJECT/scripts/verify_bundle.py" --verify-file "$dir/SHA256SUMS" \
    --signature "$dir/SHA256SUMS.sig" --pubkey "$PUB" \
    || { echo "FAIL: SHA256SUMS.sig does not verify against $PUB (key pair mismatch?)" >&2; exit 1; }
  ( cd "$dir" && shasum -a 256 -c SHA256SUMS | grep -c ': OK$' | sed 's/^/usb files verified: /' )
}
if [ -n "$SIGN_STICK" ]; then
  sign_stick "$SIGN_STICK"
  echo "=== signed $SIGN_STICK/SHA256SUMS (SHA256SUMS.sig)"
  exit 0
fi
SHA="$(git rev-parse HEAD)"; SHA7="${SHA:0:7}"
[ -z "$(git status --porcelain)" ] || { echo "FAIL: working tree not clean at $SHA7 (the bundle must carry the commit)" >&2; exit 1; }
echo "=== release build at $SHA7 $(date -u +%FT%TZ)"
# The bundles ship exactly the committed hashed locks (requirements/locks/);
# a missing lock, or one compiled from an older requirements/runtime.in,
# fails the release here instead of shipping whatever the index serves.
"$PY" scripts/prepare_offline_bundle.py --check-locks \
  || { echo "FAIL: requirements/locks/ is missing or out of date; run '$PY scripts/prepare_offline_bundle.py --refresh-locks', review and commit" >&2; exit 1; }

# A bundle is reused only when it was built from this commit AND carries the
# integer release_seq the installers' anti-rollback check orders releases by.
# The release_seq of a bundle, which orders the trust tools on the stick too.
bundle_seq() { "$PY" -c "import json,glob; m=glob.glob('$1/universal-db-mcp-*/manifest.json'); s=json.load(open(m[0])).get('release_seq') if m else None; print(s if type(s) is int and s >= 0 else '')" 2>/dev/null; }
bundle_rev() { "$PY" -c "import json,glob; m=glob.glob('$1/universal-db-mcp-*/manifest.json'); d=json.load(open(m[0])) if m else {}; print(d.get('source_rev', '') if type(d.get('release_seq')) is int else '')" 2>/dev/null; }
# Whether a bundle ships OS packages (the Microsoft driver closure): a bundle
# built the other way round is never reused.
bundle_os() { "$PY" -c "import json,glob; m=glob.glob('$1/universal-db-mcp-*/manifest.json'); d=json.load(open(m[0])) if m else {}; print('yes' if d.get('os_packages') else 'no')" 2>/dev/null; }
DRIVER_FLAG=""; WANT_OS="yes"
if [ "${UDBMCP_WITHOUT_MSSQL_DRIVER:-}" = 1 ]; then DRIVER_FLAG="--without-mssql-driver"; WANT_OS="no"; fi
if [ "$(bundle_rev out/bundle)" = "$SHA" ] && [ "$(bundle_os out/bundle)" = "$WANT_OS" ]; then echo "=== linux bundle already built at $SHA7 (reused)"; else
  rm -rf out/bundle; echo "=== linux bundle (signed, source_rev=$SHA7${DRIVER_FLAG:+, without the Microsoft ODBC driver})"
  # shellcheck disable=SC2086 # DRIVER_FLAG is one flag or nothing
  "$PY" scripts/prepare_offline_bundle.py --out out/bundle --source-rev "$SHA" --signing-key "$KEY" $DRIVER_FLAG; fi
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
SEQ="$(bundle_seq out/bundle)"
[ -n "$SEQ" ] || { echo "FAIL: the linux bundle has no integer release_seq to order the trust tools by" >&2; exit 1; }
printf '%s\n' "$SEQ" > "$USB/trust-bootstrap-linux/RELEASE"
for f in README.txt instantclient-basiclite-linux.x64-19.28.zip libaio1t64_*.deb unzip_*.deb; do
  cp "$ORA"/$f "$USB/oracle-instantclient/"
done
cp docs/site-upgrade-runbook.md "$USB/UPGRADE-README.md"
{
  echo "release public key fingerprint (sha256 of the DER encoding; bootstrap.sh prints the same value):"
  echo "$FP"
  echo "built from commit $SHA"
  [ "$DEMO" -eq 0 ] || {
    echo "NOTE: signed with the DEMO key pair (out/demo-keys on the staging machine). Only a site whose installed"
    echo "trust anchor is this demo public key accepts it. Before wider use generate a site-specific key pair"
    echo "(UDBMCP_RELEASE_KEY / UDBMCP_PUBKEY) and rotate the site's anchor with bootstrap.sh --rotate-key."
  }
} > "$USB/RELEASE-KEY-FINGERPRINT.txt"
sign_stick "$USB"
echo "folder: $USB"; ls "$USB"
shasum -a 256 "$DEB" "$PKG"
echo "=== release build done $(date -u +%FT%TZ)"
