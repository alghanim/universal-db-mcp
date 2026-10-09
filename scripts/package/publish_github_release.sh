#!/usr/bin/env bash
# Assemble the public GitHub release from a release_usb.sh build at HEAD, sign
# it with the release key, verify it the way a user would and, with --publish,
# publish it and verify the published copy.
#
# The public set is not the site's USB stick. The stick also carries the
# Oracle Instant Client and Ubuntu helper packages, which are not ours to
# publish, and the public Linux bundle and .deb must not carry Microsoft's ODBC
# driver: build them with UDBMCP_WITHOUT_MSSQL_DRIVER=1 (docs/offline-build.md).
# dist/release-v<version>/ gets:
#   the .deb and the .pkg; the Linux and macOS bundles (.tar.gz); the Linux
#   trust bootstrap (.tar.gz); the release public key and its fingerprint;
#   SHA256SUMS over all of them and SHA256SUMS.sig (Ed25519, the release key).
#
# Usage (macOS, clean tree, after release_usb.sh built HEAD with the same key):
#   UDBMCP_WITHOUT_MSSQL_DRIVER=1 UDBMCP_RELEASE_KEY=<key.pem> UDBMCP_PUBKEY=<pub.pem> \
#     scripts/package/release_usb.sh
#   UDBMCP_RELEASE_KEY=<key.pem> UDBMCP_PUBKEY=<pub.pem> \
#     scripts/package/publish_github_release.sh [--publish <notes.md> [--stable]]
# Without --publish it stops once the set is verified and prints how to publish.
# --publish creates the tag v<version> at HEAD and the release (a pre-release
# unless --stable), only when CI passed for HEAD, then downloads the published
# files and verifies them again.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT="$(cd "$HERE/../.." && pwd -P)"
cd "$PROJECT"
PY="$PROJECT/.venv/bin/python"

NOTES=""; STABLE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --publish) [ $# -ge 2 ] || { echo "usage: --publish <notes.md>" >&2; exit 2; }; NOTES="$2"; shift ;;
    --stable) STABLE=1 ;;
    *) echo "usage: $0 [--publish <notes.md> [--stable]]" >&2; exit 2 ;;
  esac
  shift
done
[ "$STABLE" -eq 0 ] || [ -n "$NOTES" ] || { echo "FAIL: --stable needs --publish" >&2; exit 2; }
[ -z "$NOTES" ] || [ -s "$NOTES" ] || { echo "FAIL: release notes $NOTES missing or empty" >&2; exit 1; }
fail() { echo "FAIL: $*" >&2; exit 1; }

[ "$(uname -s)" = Darwin ] || fail "run on the macOS staging machine release_usb.sh ran on (it builds the .pkg)"
KEY="${UDBMCP_RELEASE_KEY:-}"; PUB="${UDBMCP_PUBKEY:-}"
[ -n "$KEY" ] && [ -n "$PUB" ] || fail "set UDBMCP_RELEASE_KEY and UDBMCP_PUBKEY to the release key pair release_usb.sh used"
[ -r "$KEY" ] && [ -r "$PUB" ] || fail "release key files not readable"
[ -z "$(git status --porcelain)" ] || fail "working tree not clean"
SHA="$(git rev-parse HEAD)"; SHA7="${SHA:0:7}"
VERSION="$("$PY" -c 'import tomllib; print(tomllib.load(open("pyproject.toml", "rb"))["project"]["version"])')"
TAG="v$VERSION"

# The key must be the one SECURITY.md publishes: users compare against that.
FP="$(openssl pkey -pubin -in "$PUB" -outform DER | shasum -a 256 | awk '{print $1}')"
PUBLISHED="$("$PY" - <<'PY'
import re
text = open("SECURITY.md", encoding="utf-8").read()
section = text.split("## Release signing key", 1)[1].split("\n## ", 1)[0] if "## Release signing key" in text else ""
found = re.findall(r"^([0-9a-f]{64})$", section, re.M)
print(found[0] if len(found) == 1 else "")
PY
)"
[ -n "$PUBLISHED" ] || fail "SECURITY.md publishes no release key fingerprint (section 'Release signing key')"
[ "$FP" = "$PUBLISHED" ] || fail "the release key ($FP) is not the one SECURITY.md publishes ($PUBLISHED)"
echo "=== $TAG at $SHA7, release key $FP (as SECURITY.md publishes)"

# What release_usb.sh built: from this commit, and the public way.
one() { [ $# -eq 1 ] && [ -e "$1" ] || fail "expected exactly one match, found: $*"; echo "$1"; }
LINUX_DIR="$(one out/bundle/universal-db-mcp-"$VERSION"-linux-*)"; LINUX="$(basename "$LINUX_DIR")"
MAC_DIR="$(one out/bundle-macos/universal-db-mcp-"$VERSION"-macos-*)"; MAC="$(basename "$MAC_DIR")"
STICK="dist/usb-ubuntu-$SHA7"
[ -d "$STICK" ] || fail "no $STICK: run release_usb.sh at this commit first"
DEB_SRC="$(one "$STICK"/universal-db-mcp_*_amd64.deb)"
PKG_SRC="$(one dist/universal-db-mcp-"$VERSION"-macos-arm64.pkg)"
for dir in "$LINUX_DIR" "$MAC_DIR"; do
  rev="$("$PY" -c 'import json,sys; print(json.load(open(sys.argv[1]))["source_rev"])' "$dir/manifest.json")"
  [ "$rev" = "$SHA" ] || fail "$dir was built from $rev, not HEAD"
done
"$PY" -c 'import json,sys; sys.exit(1 if json.load(open(sys.argv[1]))["os_packages"] else 0)' "$LINUX_DIR/manifest.json" \
  || fail "the Linux bundle ships OS packages (Microsoft's ODBC driver): rebuild with UDBMCP_WITHOUT_MSSQL_DRIVER=1"
for gate in deb pkg; do
  "$PY" - "$gate" "$PROJECT" "$DEB_SRC" "$PKG_SRC" <<'PY' || fail "the $gate gate did not pass for this build"
import json, os, sys
gate, project, deb, pkg = sys.argv[1:]
result = json.load(open(os.path.join(project, "out/package-evidence", gate, "results.json")))
built = os.path.join(project, "dist", os.path.basename(deb)) if gate == "deb" else os.path.join(project, pkg)
sys.exit(0 if result.get("status") == "passed" and result.get("package") == built else 1)
PY
done
[ "$PKG_SRC" -nt "$MAC_DIR/manifest.json" ] || fail "the .pkg is older than the macOS bundle: run release_usb.sh again"

REL="dist/release-$TAG"
echo "=== assemble $REL"
rm -rf "$REL"; mkdir -p "$REL"
cp "$DEB_SRC" "$PKG_SRC" "$REL/"
export COPYFILE_DISABLE=1  # no AppleDouble ._ files in the archives
TARFLAGS=(--no-mac-metadata --uid 0 --gid 0 --uname root --gname root)
tar "${TARFLAGS[@]}" -C "$(dirname "$LINUX_DIR")" -czf "$REL/$LINUX.tar.gz" "$LINUX"
tar "${TARFLAGS[@]}" -C "$(dirname "$MAC_DIR")" -czf "$REL/$MAC.tar.gz" "$MAC"
tar "${TARFLAGS[@]}" -C "$STICK" -czf "$REL/trust-bootstrap-linux.tar.gz" trust-bootstrap-linux
cp "$PUB" "$REL/release.pub.pem"
cp "$STICK/RELEASE-KEY-FINGERPRINT.txt" "$REL/"
UDBMCP_RELEASE_KEY="$KEY" UDBMCP_PUBKEY="$PUB" bash "$HERE/release_usb.sh" --sign-stick "$REL"

# A user's checks, on a directory of release files: the key, the signed list,
# every file against it, nothing else in it.
verify_set() {
  local dir="$1"
  [ "$(openssl pkey -pubin -in "$dir/release.pub.pem" -outform DER | shasum -a 256 | awk '{print $1}')" = "$PUBLISHED" ] \
    || fail "$dir/release.pub.pem is not the published key"
  "$PY" scripts/verify_bundle.py --verify-file "$dir/SHA256SUMS" --signature "$dir/SHA256SUMS.sig" --pubkey "$dir/release.pub.pem" >/dev/null \
    || fail "$dir/SHA256SUMS.sig does not verify"
  (cd "$dir" && shasum -a 256 -c SHA256SUMS >/dev/null) || fail "a file in $dir does not match SHA256SUMS"
  local listed present
  listed="$(awk '{print $2}' "$dir/SHA256SUMS" | sed 's|^\./||' | sort)"
  present="$(cd "$dir" && find . -type f ! -name SHA256SUMS ! -name SHA256SUMS.sig | sed 's|^\./||' | sort)"
  [ "$listed" = "$present" ] || fail "$dir holds files SHA256SUMS does not list, or lacks some it does"
}

echo "=== verify $REL"
verify_set "$REL"
if find "$REL" -name '._*' | grep -q .; then fail "AppleDouble files in $REL"; fi
CHECK="$(mktemp -d)"; trap 'rm -rf "$CHECK"' EXIT
tar -xzf "$REL/$LINUX.tar.gz" -C "$CHECK"; tar -xzf "$REL/$MAC.tar.gz" -C "$CHECK"
"$PY" scripts/verify_bundle.py --bundle "$CHECK/$LINUX" --pubkey "$REL/release.pub.pem" \
  --allow-platform-mismatch --no-installed-manifest >/dev/null 2>&1 || fail "the unpacked Linux bundle does not verify"
"$PY" scripts/verify_bundle.py --bundle "$CHECK/$MAC" --pubkey "$REL/release.pub.pem" \
  --no-installed-manifest >/dev/null 2>&1 || fail "the unpacked macOS bundle does not verify"
if [ -r out/demo-keys/udbmcp-release-demo.pub.pem ] && "$PY" scripts/verify_bundle.py --bundle "$CHECK/$MAC" \
    --pubkey out/demo-keys/udbmcp-release-demo.pub.pem --no-installed-manifest >/dev/null 2>&1; then
  fail "the macOS bundle verifies against the DEMO key"
fi
# No Microsoft ODBC driver anywhere: list first, so a listing that failed
# cannot read as "nothing found".
BUNDLE_LIST="$(tar -tzf "$REL/$LINUX.tar.gz")" && [ -n "$BUNDLE_LIST" ] || fail "could not list the Linux bundle"
if printf '%s\n' "$BUNDLE_LIST" | grep -iE 'msodbcsql|os-packages/[^/]+\.deb$'; then fail "the Linux bundle carries OS packages"; fi
DEB_LIST="$(docker run --rm --platform linux/amd64 -v "$PROJECT/$REL":/r:ro ubuntu:24.04 \
  dpkg-deb -c "/r/$(basename "$DEB_SRC")")" && [ -n "$DEB_LIST" ] || fail "could not list the .deb (docker)"
if printf '%s\n' "$DEB_LIST" | grep -iE 'msodbcsql|os-packages/[^/]+\.deb$'; then fail "the .deb carries OS packages"; fi
echo "verified: key, signed SHA256SUMS, every file, both bundles unpacked, no demo signature, no Microsoft driver"

FILES=()
while IFS= read -r name; do FILES+=("$REL/$name"); done < <(cd "$REL" && find . -type f | sed 's|^\./||' | sort)
if [ -z "$NOTES" ]; then
  echo "=== not published. To publish $TAG:"
  echo "    UDBMCP_RELEASE_KEY=... UDBMCP_PUBKEY=... $0 --publish <notes.md> [--stable]"
  exit 0
fi

echo "=== publish $TAG"
CI="$(gh run list --workflow ci.yml --commit "$SHA" --json conclusion --jq '[.[] | select(.conclusion == "success")] | length')"
[ "${CI:-0}" -ge 1 ] || fail "no successful CI run for $SHA7 on GitHub"
if gh release view "$TAG" >/dev/null 2>&1; then fail "release $TAG exists already"; fi
KIND=(--prerelease); [ "$STABLE" -eq 0 ] || KIND=(--latest)
gh release create "$TAG" --target "$SHA" "${KIND[@]}" --title "universal-db-mcp $VERSION" --notes-file "$NOTES" "${FILES[@]}"
DOWNLOADED="$(mktemp -d)"; trap 'rm -rf "$CHECK" "$DOWNLOADED"' EXIT
gh release download "$TAG" --dir "$DOWNLOADED"
verify_set "$DOWNLOADED"
echo "published and verified from GitHub: $(gh release view "$TAG" --json url --jq .url)"
