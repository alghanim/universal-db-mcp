#!/usr/bin/env bash
# Build the macOS .pkg installer from a SIGNED offline bundle.
#
# Usage:
#   scripts/package/build_pkg.sh <signed-bundle-dir> --pubkey <pem> \
#       [--out dist] [--sign "Developer ID Installer"]
#
# Trust model (invariants that must never be broken):
#   1. No payload staging happens before a trusted-channel
#      `verify_bundle.py --pubkey` run has PASSED on the source bundle.
#      The verifier is taken from the repo / trusted tools — never from
#      inside the bundle being verified.
#   2. The release public key is NEVER shipped inside the package: the
#      admin distributes it out-of-band. The staged payload is scanned
#      and the build fails closed if any key material would be embedded.
#   3. The build stages files only; nothing in the bundle is executed.
#   4. Every verification failure fails closed (non-zero exit, no output
#      artifact left behind).
#
# The package is NON-RELOCATABLE: the payload uses absolute paths
# (/usr/local/universal-db-mcp/bundle, /Library/LaunchDaemons) and no
# --install-location is given, so the absolute paths are load-bearing.
#
# The preinstall/postinstall scripts (packaging/pkg) re-verify the payload
# on the target before anything executes it; this build script never
# weakens that: an unsigned bundle is refused here, at the source.
set -euo pipefail

PROJECT="$(cd "$(dirname "$0")/../.." && pwd)"
EVIDENCE_DIR="${UDBMCP_PACKAGE_EVIDENCE_DIR:-$PROJECT/out/package-evidence/pkg}"
BUILD_ID="$(date -u +%Y%m%dT%H%M%SZ)"
LOG_FILE="$EVIDENCE_DIR/build-$BUILD_ID.log"

usage() {
  echo "usage: $0 <signed-bundle-dir> --pubkey <pem> [--out dir] [--sign \"identity\"]" >&2
  exit 2
}

fail() {
  echo "ERROR: $*" >&2
  echo "ERROR: $*" >>"$LOG_FILE" 2>/dev/null || true
  exit 1
}

log() {
  echo "$*"
  echo "$*" >>"$LOG_FILE"
}

warn() {
  echo "WARNING: $*" >&2
  echo "WARNING: $*" >>"$LOG_FILE"
}

mkdir -p "$EVIDENCE_DIR"

BUNDLE_DIR=""
PUBKEY=""
OUT_DIR="$PROJECT/dist"
SIGN_IDENTITY=""

while [ $# -gt 0 ]; do
  case "$1" in
    --pubkey)
      [ $# -ge 2 ] || usage
      PUBKEY="$2"
      shift 2
      ;;
    --out)
      [ $# -ge 2 ] || usage
      OUT_DIR="$2"
      shift 2
      ;;
    --sign)
      [ $# -ge 2 ] || usage
      SIGN_IDENTITY="$2"
      shift 2
      ;;
    --help|-h)
      usage
      ;;
    -*)
      fail "unknown option: $1"
      ;;
    *)
      if [ -n "$BUNDLE_DIR" ]; then
        usage
      fi
      BUNDLE_DIR="$1"
      shift
      ;;
  esac
done

[ -n "$BUNDLE_DIR" ] || usage
[ -n "$PUBKEY" ] || usage

log "==> build_pkg start: $BUILD_ID"
log "    project: $PROJECT"
log "    bundle:  $BUNDLE_DIR"
log "    pubkey:  $PUBKEY"
log "    out:     $OUT_DIR"

[ -d "$BUNDLE_DIR" ] || fail "bundle dir not found: $BUNDLE_DIR"
[ -f "$PUBKEY" ] || fail "pubkey not found: $PUBKEY"

# --- Invariant 1 gate: refuse an unsigned/incomplete bundle BEFORE staging ---
# A bundle without both SIGNATURE and SHA256SUMS cannot have passed the
# trusted-channel verification, so there is nothing this script may package.
[ -f "$BUNDLE_DIR/SIGNATURE" ] || fail "refusing to package an UNSIGNED bundle: $BUNDLE_DIR/SIGNATURE missing"
[ -f "$BUNDLE_DIR/SHA256SUMS" ] || fail "refusing to package an UNVERIFIABLE bundle: $BUNDLE_DIR/SHA256SUMS missing"
[ -f "$BUNDLE_DIR/manifest.json" ] || fail "bundle manifest missing: $BUNDLE_DIR/manifest.json"
log "bundle signature material present (SIGNATURE + SHA256SUMS + manifest.json)"

PYTHON_BIN="${UDBMCP_PYTHON:-$PROJECT/.venv/bin/python}"
if [ ! -x "$PYTHON_BIN" ]; then
  PYTHON_BIN="$(command -v python3)" || fail "no python3 available to run the verifier"
fi

# The verifier comes from the trusted channel (repo copy, or an explicit
# override) — NEVER from inside the bundle being verified. A release installed
# on this build machine never decides the build (--no-installed-manifest).
VERIFIER="${UDBMCP_VERIFIER:-$PROJECT/scripts/verify_bundle.py}"
[ -f "$VERIFIER" ] || fail "trusted verifier not found: $VERIFIER (set UDBMCP_VERIFIER)"

log "==> trusted-channel verification of source bundle (fail closed)"
if ! "$PYTHON_BIN" "$VERIFIER" --bundle "$BUNDLE_DIR" --pubkey "$PUBKEY" --allow-platform-mismatch \
    --no-installed-manifest >>"$LOG_FILE" 2>&1; then
  fail "verify_bundle.py FAILED for $BUNDLE_DIR; refusing to stage any payload (see $LOG_FILE)"
fi
log "    verify_bundle.py PASSED"

# --- Version from the signed manifest (release field) ---
VERSION="$("$PYTHON_BIN" -c 'import json, sys
print(json.load(open(sys.argv[1]))["release"])' "$BUNDLE_DIR/manifest.json")"
case "$VERSION" in
  ""|*[!A-Za-z0-9.]*) fail "invalid release version in manifest: '$VERSION'" ;;
esac
log "    release: $VERSION"

# The payload's release_seq goes into the pkg scripts: preinstall refuses an
# OLDER release before the Installer writes any of the payload, and the
# downgrade flag names the release it authorises. Empty for a bundle without
# one (the verifier orders such a release in postinstall).
RELEASE_SEQ="$("$PYTHON_BIN" -c 'import json, sys
seq = json.load(open(sys.argv[1])).get("release_seq")
print(seq if type(seq) is int and seq >= 0 else "")' "$BUNDLE_DIR/manifest.json")"
log "    release_seq: ${RELEASE_SEQ:-<none>}"

PROFILE="$("$PYTHON_BIN" -c 'import json, sys
print(json.load(open(sys.argv[1])).get("profile", ""))' "$BUNDLE_DIR/manifest.json")"
case "$PROFILE" in
  macos-*)
    PKG_TAG="macos-arm64"
    ;;
  *)
    # Not a hard failure: the payload is verified byte-for-byte either way,
    # but a non-macOS bundle inside a .pkg is almost certainly a mistake, so
    # say so loudly and record it.
    PKG_TAG="$(printf '%s' "$PROFILE" | sed 's/-cp[0-9]*$//')"
    [ -n "$PKG_TAG" ] || PKG_TAG="unknown-profile"
    warn "bundle profile is '$PROFILE', not a macOS profile; building .pkg anyway (UDBMCP_PKG_ALLOW wrong-profile builds is the operator's call)"
    ;;
esac
log "    profile: $PROFILE (pkg tag: $PKG_TAG)"

PKG_NAME="universal-db-mcp-$VERSION-$PKG_TAG.pkg"

# --- Inputs owned by sibling artifacts; fail closed if absent ---
PLIST_SRC="$PROJECT/packaging/launchd/com.udbmcp.server.plist"
SCRIPTS_DIR="$PROJECT/packaging/pkg"
[ -f "$PLIST_SRC" ] || fail "launchd plist missing: $PLIST_SRC (expected from the packaging/launchd artifact)"
[ -f "$SCRIPTS_DIR/preinstall" ] || fail "pkg preinstall missing: $SCRIPTS_DIR/preinstall"
[ -f "$SCRIPTS_DIR/postinstall" ] || fail "pkg postinstall missing: $SCRIPTS_DIR/postinstall"
for f in "$SCRIPTS_DIR/preinstall" "$SCRIPTS_DIR/postinstall"; do
  [ -x "$f" ] || fail "pkg script not executable: $f"
done

PUBKEY_FPR="$(openssl pkey -pubin -in "$PUBKEY" -outform DER 2>/dev/null | shasum -a 256 | awk '{print $1}')" || PUBKEY_FPR=""
log "    pubkey fingerprint (sha256 of DER): ${PUBKEY_FPR:-unavailable}"
log "    signing identity: ${SIGN_IDENTITY:-<none — package will be UNSIGNED>}"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/udbmcp-pkg.XXXXXX")" || fail "mktemp failed"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT
log "    workdir: $WORK"

# --- Stage the pkg root ---
# Payload layout (all absolute paths -> non-relocatable):
#   /usr/local/universal-db-mcp/bundle/   <- the signed bundle, verbatim
#   /Library/LaunchDaemons/com.udbmcp.server.plist
ROOT="$WORK/pkgroot"
BUNDLE_DEST="$ROOT/usr/local/universal-db-mcp/bundle"
LAUNCH_DEST="$ROOT/Library/LaunchDaemons"
mkdir -p "$BUNDLE_DEST" "$LAUNCH_DEST"

log "==> staging signed bundle payload at /usr/local/universal-db-mcp/bundle/"
cp -R "$BUNDLE_DIR/" "$BUNDLE_DEST/"
# Fix modes on the staged copy: dirs 0755, files 0644, ownership root:wheel.
find "$ROOT" -type d -exec chmod 0755 {} +
find "$ROOT" -type f -exec chmod 0644 {} +
if [ "$(id -u)" -eq 0 ]; then
  chown -R root:wheel "$ROOT"
else
  # Not root: pkgbuild's --ownership recommended maps payload ownership to
  # the installing user (root) at install time; note it honestly.
  log "    note: not running as root; pkgbuild --ownership recommended assigns root:wheel at install time"
fi

# Invariant 2: the release pubkey must never ship inside a package.
log "==> scanning staged payload for key material (fail closed)"
if find "$ROOT" -type f \( -name '*.pem' -o -name '*.pub' -o -name '*pubkey*' -o -name '*.key' \) -print -quit | grep -q .; then
  find "$ROOT" -type f \( -name '*.pem' -o -name '*.pub' -o -name '*pubkey*' -o -name '*.key' \) >>"$LOG_FILE"
  fail "key material found in staged payload; the release pubkey is distributed out-of-band and must never be packaged"
fi
log "    no key material in payload"

log "==> staging launchd plist at /Library/LaunchDaemons/com.udbmcp.server.plist"
install -m 0644 "$PLIST_SRC" "$LAUNCH_DEST/com.udbmcp.server.plist"

# GUI front end for `configure-agents` (native dialogs; runs as the logged-in
# user, never root — agent configs are per-user files). Staged as a root-owned
# payload script at /usr/local/universal-db-mcp/share/; postinstall assembles
# the thin /Applications app wrapper around it.
APP_SRC="$PROJECT/packaging/macos-app/configure_agents_app.sh"
[ -f "$APP_SRC" ] || fail "GUI app script missing at $APP_SRC"
SHARE_DEST="$ROOT/usr/local/universal-db-mcp/share"
mkdir -p "$SHARE_DEST"
install -m 0755 "$APP_SRC" "$SHARE_DEST/configure_agents_app.sh"

# --- pkg scripts, with the payload's release_seq written in ---
SCRIPTS_STAGE="$WORK/scripts"
mkdir -p "$SCRIPTS_STAGE"
for f in preinstall postinstall; do
  [ "$(grep -cx 'PAYLOAD_RELEASE_SEQ=""' "$SCRIPTS_DIR/$f")" = 1 ] \
    || fail "pkg $f must hold exactly one PAYLOAD_RELEASE_SEQ=\"\" line for the release_seq"
  sed "s/^PAYLOAD_RELEASE_SEQ=\"\"\$/PAYLOAD_RELEASE_SEQ=\"$RELEASE_SEQ\"/" "$SCRIPTS_DIR/$f" >"$SCRIPTS_STAGE/$f"
  chmod 0755 "$SCRIPTS_STAGE/$f"
done

# --- pkgbuild: component package ---
CORE_PKG="$WORK/core.pkg"
log "==> pkgbuild (non-relocatable, ownership recommended)"
PKGBUILD_ARGS=(
  --root "$ROOT"
  --identifier com.udbmcp.universal-db-mcp
  --version "$VERSION"
  --scripts "$SCRIPTS_STAGE"
  --ownership recommended
)
log "    pkgbuild ${PKGBUILD_ARGS[*]} $CORE_PKG"
pkgbuild "${PKGBUILD_ARGS[@]}" "$CORE_PKG" >>"$LOG_FILE" 2>&1 \
  || fail "pkgbuild failed (see $LOG_FILE)"

# --- productbuild: distribution wrapper ---
DIST_XML="$WORK/distribution.xml"
cat >"$DIST_XML" <<EOF
<?xml version="1.0" encoding="utf-8" standalone="no"?>
<installer-gui-script minSpecVersion="2">
    <title>Universal DB MCP</title>
    <options customize="never" rootVolumeOnly="true"/>
    <welcome file="welcome.rtf" mime-type="text/rtf"/>
    <conclusion file="conclusion.rtf" mime-type="text/rtf"/>
    <!-- Top-level pkg-ref: the text content names the component package file
         (resolved against the package-path argument). Without it productbuild
         cannot resolve the identifier and fails with 'No URL for pkg-ref'. -->
    <pkg-ref id="com.udbmcp.universal-db-mcp" version="$VERSION" auth="root">core.pkg</pkg-ref>
    <choices-outline>
        <line choice="default"/>
    </choices-outline>
    <choice id="default" title="Universal DB MCP" description="Installs the verified offline bundle, launchd service plist, and re-verifies payload before first start." start_selected="true">
        <pkg-ref id="com.udbmcp.universal-db-mcp"/>
    </choice>
</installer-gui-script>
EOF
# welcome/conclusion resources are optional and wired PER FILE: resources
# live in packaging/pkg-resources/ (a sibling of the pkgbuild --scripts dir,
# so nothing here leaks into the component package's Scripts payload). A
# referenced-but-missing page (e.g. <welcome> wired while only conclusion
# exists) makes productbuild's output version-dependently skip the page or
# fail the install, so each ref is stripped when its file is absent.
RES_DIR="$WORK/resources"
mkdir -p "$RES_DIR"
[ -f "$PROJECT/packaging/pkg-resources/welcome.rtf" ] && \
  cp "$PROJECT/packaging/pkg-resources/welcome.rtf" "$RES_DIR/"
[ -f "$PROJECT/packaging/pkg-resources/conclusion.rtf" ] && \
  cp "$PROJECT/packaging/pkg-resources/conclusion.rtf" "$RES_DIR/"
[ -f "$RES_DIR/welcome.rtf" ] || sed -i '' '/<welcome /d' "$DIST_XML"
[ -f "$RES_DIR/conclusion.rtf" ] || sed -i '' '/<conclusion /d' "$DIST_XML"

PRODUCTBUILD_ARGS=(--distribution "$DIST_XML" --package-path "$WORK" --identifier com.udbmcp.universal-db-mcp)
if [ -f "$RES_DIR/welcome.rtf" ] || [ -f "$RES_DIR/conclusion.rtf" ]; then
  log "==> using distribution resources from packaging/pkg-resources/"
  PRODUCTBUILD_ARGS+=(--resources "$RES_DIR")
fi
FINAL_PKG="$OUT_DIR/$PKG_NAME"
mkdir -p "$OUT_DIR"
rm -f "$FINAL_PKG"

if [ -n "$SIGN_IDENTITY" ]; then
  log "==> productbuild (signed with: $SIGN_IDENTITY)"
  productbuild "${PRODUCTBUILD_ARGS[@]}" --sign "$SIGN_IDENTITY" "$FINAL_PKG" >>"$LOG_FILE" 2>&1 \
    || fail "productbuild --sign failed (see $LOG_FILE)"
  log "    SIGNED package: $FINAL_PKG"
else
  log "==> productbuild (UNSIGNED)"
  productbuild "${PRODUCTBUILD_ARGS[@]}" "$FINAL_PKG" >>"$LOG_FILE" 2>&1 \
    || fail "productbuild failed (see $LOG_FILE)"
  warn "the .pkg is UNSIGNED: '$FINAL_PKG'. Gatekeeper/installer will not attribute it to a developer identity; record this in the release ledger."
fi

PKG_SHA="$(shasum -a 256 "$FINAL_PKG" | awk '{print $1}')"
log "==> done"
log "    artifact: $FINAL_PKG"
log "    sha256:   $PKG_SHA"
{
  echo "artifact: $FINAL_PKG"
  echo "sha256: $PKG_SHA"
  echo "version: $VERSION"
  echo "profile: $PROFILE"
  echo "identifier: com.udbmcp.universal-db-mcp"
  echo "signed: $([ -n "$SIGN_IDENTITY" ] && echo "yes ($SIGN_IDENTITY)" || echo "NO — UNSIGNED (WARNING recorded)")"
  echo "relocatable: no (absolute payload paths, no --install-location)"
} >>"$LOG_FILE"
echo "==> package ready: $FINAL_PKG (sha256 $PKG_SHA)"
