#!/usr/bin/env bash
# build_deb.sh — build the Ubuntu .deb from the SIGNED offline bundle.
#
# Usage:
#   scripts/package/build_deb.sh <signed-bundle-dir> --pubkey <release.pub.pem> [--out dist]
#
# What it does (approved plan, Phase 4):
#   1. Refuses to run against an unsigned/unverified bundle: the bundle is
#      verified FIRST via the trusted-tools copy of verify_bundle.py that
#      ships next to the bundle on the trusted staging channel
#      (<bundle-dir>/../trusted-tools/), with the admin-supplied public key.
#      Any verification failure aborts the build (fail closed).
#   2. Stages a deb root:
#        DEBIAN/control  — Version = manifest.release + "+" + build stamp
#                          (manifest.created as YYYYMMDDHHMM UTC) + ".g" + the
#                          first 7 characters of manifest.source_rev
#                          (a manifest whose source_rev is missing or is the
#                          builder sentinel "unknown" FAILS the build — see
#                          the provenance guard below)
#        DEBIAN/{preinst,postinst,prerm,postrm}
#                        — copied executable from packaging/deb/.
#        DEBIAN/conffiles — rendered from packaging/deb/conffiles (REQUIRED;
#                          fail-loud gate below): registers
#                          /etc/universal-db-mcp/config.yaml as a dpkg
#                          conffile. The config file itself is ALSO staged
#                          into the payload at etc/universal-db-mcp/
#                          config.yaml — dpkg treats a conffile entry whose
#                          file is missing from the payload as "deleted by
#                          the packager".
#        usr/share/universal-db-mcp/bundle/        — the entire signed bundle
#        usr/share/universal-db-mcp/trusted-tools/ — INERT reference copy of
#                          the trusted verifier/installer (postinst NEVER
#                          executes it and NEVER bootstraps the trust dir
#                          from it — see the trust gate below; the trust dir
#                          is admin-bootstrapped from the trusted channel)
#        usr/share/universal-db-mcp/systemd/universal-db-mcp.service
#                          (postinst copies this to /etc/systemd/system/, so
#                          the unit stays a non-dpkg-managed, admin-controlled
#                          path — see packaging/deb/postinst step 3)
#
#      Deliberately NOT in the payload (not a dpkg path; see the staging
#      code below for why):
#        the systemd unit under /etc — installing it via dpkg would make the
#                          unit dpkg-owned, so admin edits would be silently
#                          lost on upgrade; postinst installs the deb-shipped
#                          canonical copy to /etc/systemd/system instead.
#      The default config IS in the payload at etc/universal-db-mcp/
#      config.yaml as a dpkg conffile (registered via packaging/deb/conffiles,
#      plan Phase 4): dpkg owns the file, preserves admin edits across
#      upgrades (prompting only on a conflict), keeps it on remove and
#      deletes it on purge. postinst's only-if-absent seeding stays as the
#      fallback for a config an admin deleted before an upgrade — it never
#      overwrites an existing file. NOTE: --root-owner-group forces the
#      unpacked conffile to root:root (the staged 0644 mode is preserved);
#      postinst's udbmcp:udbmcp 0640 seeding therefore only applies to the
#      fallback path.
#   3. Builds the .deb INSIDE the baseline container (the staging host may be
#      macOS, which has no trustworthy dpkg-deb environment):
#        docker run --rm -v <staged root>:/debroot <baseline image> \
#            dpkg-deb --root-owner-group --build /debroot <out>.deb
#   4. Writes dist/universal-db-mcp_<version>_amd64.deb (or --out dir).
#
# Trust invariants enforced here (NEVER break):
#   - No package is produced before a trusted-channel
#     verify_bundle.py --pubkey run has passed on the source bundle.
#   - The release public key is NEVER copied into the package: it is
#     distributed out-of-band by the admin. The staged root is scanned and
#     the build fails if any public key material is found in it.
#   - Every verification failure fails closed (non-zero exit, no artifact).
#
# Relative --out paths resolve against the PROJECT ROOT (not the caller's
# CWD) so the script behaves identically from any directory.

set -euo pipefail

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(cd "$SELF_DIR/../.." && pwd -P)"

die() {
    echo "FAIL: $*" >&2
    echo "universal-db-mcp: deb build ABORTED (fail closed)." >&2
    exit 1
}

usage() {
    sed -n '2,27p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

sha256_of() {
    # Portable sha256 for the staging host (macOS: shasum, Linux: sha256sum).
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        die "no sha256 tool found on staging host (sha256sum/shasum)"
    fi
}

find_pubkey_material() {
    # Any file whose NAME looks like key material, anywhere under the given
    # trees. Same pattern set as build_msi.sh's find_pubkey_material (plus
    # '*.key', which the deb gate's own payload scan also checks): a stray
    # '*.pem' (e.g. key.pem, even a PRIVATE key) or '*pubkey*' file in the
    # bundle or trusted-tools payload must fail the build exactly as it fails
    # the .pkg and .msi builders. Trust invariant: the release public key is
    # NEVER shipped inside a package — it is distributed out-of-band by the
    # admin.
    find "$@" -type f \( -name '*.pub' -o -name '*.pub.pem' -o -name '*.pem' -o -name 'release.pub*' -o -name '*pubkey*' -o -name '*.key' \)
}

# ---------------------------------------------------------------------------
# argument parsing
# ---------------------------------------------------------------------------

BUNDLE=""
PUBKEY=""
OUT_REL="dist"

while [ $# -gt 0 ]; do
    case "$1" in
        --pubkey)
            [ $# -ge 2 ] || die "--pubkey requires a PEM path argument"
            PUBKEY="$2"; shift 2 ;;
        --out)
            [ $# -ge 2 ] || die "--out requires a directory argument"
            OUT_REL="$2"; shift 2 ;;
        -h|--help)
            usage; exit 0 ;;
        --)
            shift; break ;;
        -*)
            die "unknown option: $1 (see --help)" ;;
        *)
            if [ -z "$BUNDLE" ]; then
                BUNDLE="$1"
            else
                die "unexpected extra argument: $1 (only one bundle directory is accepted)"
            fi
            shift ;;
    esac
done
[ $# -eq 0 ] || die "unexpected extra argument: $1"

[ -n "$BUNDLE" ] || die "missing bundle directory argument (see --help)"
[ -n "$PUBKEY" ] || die "missing --pubkey <release.pub.pem> argument (see --help)"

# Fail closed BEFORE anything else: an admin-supplied public key is the
# prerequisite for verification; without it we must not stage anything.
[ -d "$BUNDLE" ] || die "bundle directory not found: $BUNDLE"
BUNDLE="$(cd "$BUNDLE" && pwd -P)"
[ -f "$PUBKEY" ] || die "release public key not found: $PUBKEY"
PUBKEY="$(cd "$(dirname "$PUBKEY")" && pwd -P)/$(basename "$PUBKEY")"

# ---------------------------------------------------------------------------
# manifest: release version + target sanity
# ---------------------------------------------------------------------------

MANIFEST="$BUNDLE/manifest.json"
[ -f "$MANIFEST" ] || die "manifest.json not found in bundle: $BUNDLE"

# NOTE: heredocs are never placed inside $( ... ) — macOS still ships bash
# 3.2, which mis-parses quoted heredoc bodies inside command substitutions.
# The python blocks below therefore write to a temp file that bash reads.
FIELDS_TMP="$(mktemp "${TMPDIR:-/tmp}/udbmcp-fields.XXXXXX")"

_fields_ok=1
python3 - "$MANIFEST" > "$FIELDS_TMP" <<'PYEOF' || _fields_ok=0
import json, sys

with open(sys.argv[1]) as fh:
    m = json.load(fh)

release = m.get("release")
source_rev = m.get("source_rev")
created = m.get("created")
target = m.get("target") or {}

missing = [k for k, v in (("release", release), ("source_rev", source_rev), ("created", created)) if not v]
if missing:
    print("MISSING:" + ",".join(missing))
    raise SystemExit(1)

# The bundle's build instant, as a 12-digit UTC stamp (YYYYMMDDHHMM): the
# monotonic part of the package version. created is written by the bundle
# builder in ISO 8601 (with offset) and travels inside the SIGNED manifest.
import datetime
try:
    ts = datetime.datetime.fromisoformat(str(created).replace("Z", "+00:00"))
except ValueError:
    print("BAD-CREATED:" + str(created))
    raise SystemExit(1)
if ts.tzinfo is not None:
    ts = ts.astimezone(datetime.UTC)
build_stamp = ts.strftime("%Y%m%d%H%M")

# This builder only produces Ubuntu .debs; refuse anything else loudly
# instead of silently mis-packaging another platform bundle.
os_name = str(target.get("os", ""))
if "ubuntu" not in os_name:
    print("WRONG-TARGET:" + os_name)
    raise SystemExit(1)

print(release)
print(source_rev)
print(os_name)
print(str(target.get("arch", "")))
print(build_stamp)
PYEOF
if [ "$_fields_ok" -ne 1 ]; then
    rm -f "$FIELDS_TMP"
    die "could not read release/target from $MANIFEST (fail closed)"
fi

RELEASE="$(sed -n '1p' "$FIELDS_TMP")"
SOURCE_REV="$(sed -n '2p' "$FIELDS_TMP")"
TARGET_OS="$(sed -n '3p' "$FIELDS_TMP")"
TARGET_ARCH="$(sed -n '4p' "$FIELDS_TMP")"
BUILD_STAMP="$(sed -n '5p' "$FIELDS_TMP")"
rm -f "$FIELDS_TMP"

case "$TARGET_ARCH" in
    x86_64) DEB_ARCH="amd64" ;;
    *) die "unsupported target arch for .deb: '$TARGET_ARCH' (this builder ships amd64 only)" ;;
esac

# Fail closed on missing provenance (completeness-critic round 2): the deb
# version embeds manifest.source_rev (0.1.0+<stamp>.g<rev7>), and the bundle builder's
# sentinel value "unknown" (prepare_offline_bundle.py's default when neither
# --source-rev nor UDBMCP_SOURCE_REV was given) would ship a package whose
# version ties it to NO source revision — the signature would attest the
# bytes but not the source that produced them. ROOT FIX lives in the bundle
# builder (scripts/prepare_offline_bundle.py: auto-capture the rev, refuse
# "unknown" on signed builds) and is owned by that workflow; until it lands,
# this downstream guard keeps the sentinel out of every package. Remedy: the
# bundle must be rebuilt per docs/offline-build.md step 2 (a real
# --source-rev: git rev-parse HEAD, or the documented UTC-timestamp fallback)
# and re-signed before it can be packaged.
case "$SOURCE_REV" in
    unknown|UNKNOWN|Unknown)
        die "manifest source_rev is the builder sentinel 'unknown' (scripts/prepare_offline_bundle.py ran without --source-rev) — the bundle carries no source revision; refusing to emit version '$RELEASE~$SOURCE_REV'. Rebuild the bundle with a real --source-rev (see docs/offline-build.md step 2) and re-sign it." ;;
    # NOTE: '~' and '-' are placed LAST in the bracket so '-' cannot be
    # parsed as a glob range ('+-~' would mean chars 0x2B..0x7E and let
    # '/', ':' etc. through). Hyphen-at-end is a literal in POSIX patterns.
    *[!A-Za-z0-9.+~-]*)
        die "manifest source_rev contains characters invalid in a dpkg version: '$SOURCE_REV' — refusing to build a package around a malformed revision" ;;
esac

# dpkg version: <release>+<build stamp>.g<rev7>, e.g. 0.1.0+202609181305.gab90e02.
# Everything comes from the SIGNED manifest (release, created, source_rev),
# never from the staging host. The build stamp makes versions MONOTONIC for
# dpkg and apt (the earlier 0.1.0~<full hash> scheme compared hashes as
# text, so a newer build could sort as a downgrade), and because '~' sorts
# before everything, every package of this scheme upgrades a legacy
# 0.1.0~<hash> install. The short revision keeps the source tie visible in
# the file name; the full revision stays in the manifest.
case "$BUILD_STAMP" in
    [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]) ;;
    *) die "manifest created did not yield a 12-digit UTC build stamp ('$BUILD_STAMP')" ;;
esac
REV7="$(printf '%s' "$SOURCE_REV" | cut -c1-7)"
DEB_VERSION="${RELEASE}+${BUILD_STAMP}.g${REV7}"
DEB_FILE="universal-db-mcp_${DEB_VERSION}_${DEB_ARCH}.deb"

echo "==> bundle:    $BUNDLE"
echo "==> target:    $TARGET_OS/$TARGET_ARCH"
echo "==> version:   $DEB_VERSION (from signed manifest)"

# ---------------------------------------------------------------------------
# 1. verify the source bundle BEFORE staging anything (fail closed)
# ---------------------------------------------------------------------------

[ -f "$BUNDLE/SIGNATURE" ] || die "bundle is UNSIGNED (no SIGNATURE file) — refusing to package it"
[ -f "$BUNDLE/SHA256SUMS" ] || die "bundle is UNSIGNED (no SHA256SUMS file) — refusing to package it"

# The trusted tools are distributed by prepare_offline_bundle.py as a
# SIBLING of the bundle directory on the same trusted channel
# (<staging-out>/trusted-tools/), or via an explicit UDBMCP_TRUST_DIR
# override. An IN-BUNDLE copy is NEVER used as the verifier: a tampered
# bundle would ship a verifier that prints PASSED (the self-verification
# bypass this check exists to prevent — commit security review flagged
# exactly this fallback on 2026-09-12). If no out-of-bundle copy exists,
# fail closed: verifying with the bundle's own copies proves nothing.
TRUSTED=""
for cand in "${UDBMCP_TRUST_DIR:-}" "$BUNDLE/../trusted-tools"; do
    [ -n "$cand" ] || continue
    [ -f "$cand/verify_bundle.py" ] || continue
    cand_real="$(cd "$cand" && pwd -P)"
    bundle_real="$(cd "$BUNDLE" && pwd -P)"
    case "$cand_real" in
        # exact match too: if the bundle dir itself is named "trusted-tools",
        # "$BUNDLE/../trusted-tools" resolves TO the bundle, and trusting it
        # would let a tampered bundle verify itself.
        "$bundle_real"|"$bundle_real"/*) continue ;;  # in-bundle copy: never trusted
    esac
    TRUSTED="$cand_real"
    break
done
[ -n "$TRUSTED" ] || die "no trusted verifier found OUTSIDE the bundle (expected $BUNDLE/../trusted-tools or \$UDBMCP_TRUST_DIR) — an in-bundle verifier is never trusted; bootstrap the trust channel first"

# The deb stages this copy as INERT reference material at
# /usr/share/universal-db-mcp/trusted-tools/: postinst NEVER bootstraps or
# completes /usr/local/lib/udbmcp-trust from the package payload (see the
# trust gate below — the deb-shipped copy rides on the same channel as the
# payload it would verify). Keep it complete anyway so the copy that ships
# next to the bundle on the trusted channel is usable by the admin: the ONE
# installer sources lib/os_packages.sh from its own directory, and
# verify_bundle.py imports profiles.py from its own directory.
[ -f "$TRUSTED/lib/os_packages.sh" ] || die "trusted-tools copy is incomplete: lib/os_packages.sh missing from $TRUSTED"

# ... and profiles.py, for the same reason.
[ -f "$TRUSTED/profiles.py" ] || die "trusted-tools copy is incomplete: profiles.py missing from $TRUSTED (verify_bundle.py imports it from its own directory)"

echo "==> verifying bundle via trusted-channel verifier: $TRUSTED/verify_bundle.py"
# --allow-platform-mismatch is the documented STAGING-side mode (the staging
# host is often macOS while the bundle targets ubuntu-24.04): it skips only
# the local python-version check, never a signature check. The install
# target re-verifies WITHOUT this flag in postinst.
python3 "$TRUSTED/verify_bundle.py" \
    --bundle "$BUNDLE" \
    --pubkey "$PUBKEY" \
    --allow-platform-mismatch \
    || die "bundle verification FAILED against $BUNDLE — refusing to package unverified payload"

# ---------------------------------------------------------------------------
# 2. baseline container (macOS has no trustworthy dpkg-deb environment)
# ---------------------------------------------------------------------------

command -v docker >/dev/null 2>&1 || die "docker not found on staging host; the .deb must be built inside the baseline container"

# Prefer the exact image pinned in the signed manifest's image_identity;
# UDBMCP_BASELINE_IMAGE overrides (staging hosts that rebuilt locally).
IMAGE_TMP="$(mktemp "${TMPDIR:-/tmp}/udbmcp-image.XXXXXX")"
python3 - "$MANIFEST" > "$IMAGE_TMP" <<'PYEOF'
import json, sys
with open(sys.argv[1]) as fh:
    m = json.load(fh)
identity = (m.get("image_identity") or {}).get("baseline_image") or ""
print(identity)
PYEOF
BASELINE_IMAGE="$(cat "$IMAGE_TMP")"
rm -f "$IMAGE_TMP"
BASELINE_IMAGE="${UDBMCP_BASELINE_IMAGE:-${BASELINE_IMAGE:-udbmcp-baseline:ubuntu24.04-cp312}}"

docker image inspect "$BASELINE_IMAGE" >/dev/null 2>&1 \
    || die "baseline image not loaded: $BASELINE_IMAGE (docker load -i $BUNDLE/images/udbmcp-baseline-*.tar)"

# ---------------------------------------------------------------------------
# 3. stage the deb root
# ---------------------------------------------------------------------------

DEBROOT="$(mktemp -d "${TMPDIR:-/tmp}/udbmcp-debroot.XXXXXX")"
# mktemp creates the root 0700; dpkg-deb records the staged root's mode as
# "./" in the package, so normalize it to the conventional 0755.
chmod 0755 "$DEBROOT"
cleanup() { rm -rf "$DEBROOT"; }
trap cleanup EXIT INT TERM

PKG_SHARE="$DEBROOT/usr/share/universal-db-mcp"
# Exactly ONE /etc path is staged: the default config conffile (below), which
# dpkg owns via DEBIAN/conffiles. The systemd unit is still installed by
# postinst OUTSIDE dpkg management (see above), so dpkg never owns the unit
# path.
mkdir -p "$PKG_SHARE/bundle" "$PKG_SHARE/trusted-tools" "$PKG_SHARE/systemd" \
         "$DEBROOT/etc/universal-db-mcp" "$DEBROOT/DEBIAN"

# Payload: the ENTIRE signed bundle, byte-for-byte (cp -a preserves modes so
# the postinst verification sees exactly what was signed).
echo "==> staging signed bundle payload"
cp -a "$BUNDLE/." "$PKG_SHARE/bundle/"

echo "==> staging trusted-tools payload"
cp -a "$TRUSTED/." "$PKG_SHARE/trusted-tools/"
chmod -R u+rwX,go+rX "$PKG_SHARE/trusted-tools"

# systemd unit: the deb-shipped canonical copy lives under the payload
# (/usr/share/universal-db-mcp/systemd/) where postinst finds it and installs
# it to /etc/systemd/system. It is deliberately NOT staged at
# etc/systemd/system in the payload: a dpkg-owned unit would be silently
# overwritten on every upgrade, losing admin edits to a path the package
# documents as admin-controlled (kept OUT of dpkg management on purpose, see
# packaging/deb/postinst step 3). postinst installs the canonical copy to
# /etc/systemd/system and preserves any admin-modified unit there.
UNIT_SRC="$PROJECT_ROOT/packaging/systemd/universal-db-mcp.service"
[ -f "$UNIT_SRC" ] || die "systemd unit template missing: $UNIT_SRC (expected from packaging/systemd/)"
cp "$UNIT_SRC" "$PKG_SHARE/systemd/universal-db-mcp.service"
chmod 0644 "$PKG_SHARE/systemd/universal-db-mcp.service"

# Default config: staged as a dpkg conffile from the verified bundle's
# config-templates/ copy (checked to exist below) and registered via
# packaging/deb/conffiles in the gate below. Mode 0644 is preserved by
# dpkg-deb (--root-owner-group forces only the ownership to root:root), so
# the udbmcp service account can read the config; postinst's
# only-if-absent seeding remains as the fallback for a conffile an admin
# deleted before an upgrade and never overwrites an existing file.
CONFIG_TEMPLATE="$BUNDLE/config-templates/config.yaml"
[ -f "$CONFIG_TEMPLATE" ] || die "default config template missing from bundle: $CONFIG_TEMPLATE"
install -m 0644 "$CONFIG_TEMPLATE" "$DEBROOT/etc/universal-db-mcp/config.yaml"

# Maintainer scripts from packaging/deb/ — copied executable, as dpkg
# requires. Missing files fail the build loudly: a .deb whose postinst cannot
# re-verify the payload must never be produced.
MAINT_DIR="$PROJECT_ROOT/packaging/deb"
[ -d "$MAINT_DIR" ] || die "maintainer script directory missing: $MAINT_DIR"
for script in preinst postinst prerm postrm; do
    [ -f "$MAINT_DIR/$script" ] || die "maintainer script missing: $MAINT_DIR/$script (refusing to build an unverifiable package)"
    cp "$MAINT_DIR/$script" "$DEBROOT/DEBIAN/$script"
    chmod 0755 "$DEBROOT/DEBIAN/$script"
done
# --- conffiles gate (fail-loud) ---------------------------------------------
# packaging/deb/conffiles is a REQUIRED plan Phase 4 input: it registers
# /etc/universal-db-mcp/config.yaml as a dpkg conffile (the file is staged
# above at etc/universal-db-mcp/config.yaml). Both failure directions abort
# the build — a soft NOTE must never be possible:
#   1. conffiles ABSENT: abort. A package whose default config is silently
#      unregistered loses the dpkg conffile semantics the package documents
#      (dpkg ownership, `dpkg -V` verification, admin-edit prompts on
#      upgrade, keep-on-remove / delete-on-purge).
#   2. conffiles PRESENT: every path entry must point at a file that is
#      actually in the staged payload — dpkg would treat a payload-foreign
#      entry as a conffile deleted by the packager.
CONFFILES_SRC="$MAINT_DIR/conffiles"
[ -f "$CONFFILES_SRC" ] \
    || die "conffiles template missing: $CONFFILES_SRC (required plan Phase 4 input; it must register /etc/universal-db-mcp/config.yaml as a dpkg conffile)"
# dpkg-deb does NOT strip comments from conffiles — only absolute
# pathnames may remain, so drop comment/blank lines while staging.
grep -v -e '^[[:space:]]*#' -e '^[[:space:]]*$' "$CONFFILES_SRC" \
    > "$DEBROOT/DEBIAN/conffiles" \
    || true
[ -s "$DEBROOT/DEBIAN/conffiles" ] || die "conffiles template contains no path entries after comment stripping ($CONFFILES_SRC)"
chmod 0644 "$DEBROOT/DEBIAN/conffiles"
while IFS= read -r _conffile_path; do
    [ -n "$_conffile_path" ] || continue
    [ -e "$DEBROOT$_conffile_path" ] \
        || die "conffiles entry '$_conffile_path' is NOT in the staged deb payload ($CONFFILES_SRC): dpkg would treat it as a conffile deleted by the packager. Stage the file or drop the entry."
done < "$DEBROOT/DEBIAN/conffiles"

# postinst/postrm config-semantics guards. These run UNCONDITIONALLY: with the
# config registered as a conffile, dpkg places it at unpack, so postinst's
# only-if-absent seeding is the FALLBACK for a conffile an admin deleted
# before an upgrade — it must stay only-if-absent (never overwrite
# dpkg-owned/admin-edited content) and keep sourcing the verified bundle's
# config-templates/ copy. postrm must keep deleting the config on purge and
# documenting the keep-on-remove retention.
grep -qF 'if [ ! -e "$CONFIG" ]; then' "$DEBROOT/DEBIAN/postinst" \
    || die "packaging/deb/postinst lost the only-if-absent config seeding: it is the fallback that restores a conffile an admin deleted before an upgrade — refusing to build"
grep -qF '"$BUNDLE/config-templates/config.yaml"' "$DEBROOT/DEBIAN/postinst" \
    || die "packaging/deb/postinst no longer seeds the config from the verified bundle payload (config-templates/) — refusing to build"
grep -qF 'rm -f "$CONFIG_FILE"' "$DEBROOT/DEBIAN/postrm" \
    || die "packaging/deb/postrm no longer deletes the config on purge: dpkg removes conffiles on purge and postrm must stay consistent (belt and braces for the seeded fallback copy) — refusing to build"
grep -qF 'are retained' "$DEBROOT/DEBIAN/postrm" \
    || die "packaging/deb/postrm no longer documents conffile retention on remove (the config and installer artifacts must be kept on remove, deleted on purge) — refusing to build"
# --- end conffiles gate ------------------------------------------------------

# --- trust gate (fail-loud): postinst must NEVER self-bootstrap the trust dir
# The deb-shipped trusted-tools/ copy travels on the SAME channel as the
# payload it would verify: a tampered package would ship a tampered verifier
# that prints PASSED and a tampered installer that skips verification. Any
# postinst that copies them into /usr/local/lib/udbmcp-trust — fully when the
# dir is absent, or as a "completion" of a partial admin install — would run
# that tampered code as root in the privileged configure context. postinst
# must instead FAIL CLOSED when the admin-installed trust dir is absent or
# incomplete (the preinst already refuses without it; postinst re-checks
# because it is also reachable without a preinst run, e.g.
# `dpkg --configure universal-db-mcp`). Both directions fail the build:
if grep -q 'TRUSTED_TOOLS' "$DEBROOT/DEBIAN/postinst"; then
    die "packaging/deb/postinst still references the deb-shipped trusted-tools copy: the postinst must NEVER bootstrap or complete /usr/local/lib/udbmcp-trust from the package payload (a tampered package would ship a tampered verifier that prints PASSED)"
fi
grep -qF 'trusted tool missing from the admin trust dir' "$DEBROOT/DEBIAN/postinst" \
    || die "packaging/deb/postinst lost the fail-closed admin trust-dir completeness check: an absent or incomplete /usr/local/lib/udbmcp-trust must abort the configure step with bootstrap instructions"
# --- end trust gate ----------------------------------------------------------

# --- control: template from packaging/deb/control when available, with the
# Version forced to the SIGNED manifest version. Supported template
# placeholders (any/all): @UDBMCP_VERSION@, @VERSION@, ${VERSION}, __VERSION__,
# %%VERSION%%. Any Version: line already present in the template is replaced
# so the package version can only ever come from the signed manifest.
CONTROL="$DEBROOT/DEBIAN/control"
if [ -f "$MAINT_DIR/control" ]; then
    # shellcheck disable=SC2016  # ${VERSION} below is a deliberate template token
    _control_ok=1
    python3 - "$MAINT_DIR/control" "$CONTROL" "$DEB_VERSION" <<'PYEOF' || _control_ok=0
import re, sys

src, dst, version = sys.argv[1], sys.argv[2], sys.argv[3]
with open(src) as fh:
    text = fh.read()
for token in ("@UDBMCP_VERSION@", "@VERSION@", "${VERSION}", "__VERSION__", "%%VERSION%%"):
    text = text.replace(token, version)
# Strip any template Version line WITH its newline (a leftover empty line
# would end the stanza and make dpkg-deb see several package entries), then
# drop any other empty lines: a single-stanza control has none (Description
# paragraph breaks are " ." lines, not empty lines).
text = re.sub(r"(?mi)^Version:[^\n]*\n?", "", text)
text = "\n".join(ln for ln in text.splitlines() if ln.strip() != "") + "\n"
if re.search(r"(?mi)^Version:", text) is None:
    if re.search(r"(?mi)^Package:", text) is None:
        print("FAIL: control template has neither Version: nor Package: field", file=sys.stderr)
        raise SystemExit(1)
    text = re.sub(r"(?mi)^(Package:[^\n]*\n)", rf"\g<1>Version: {version}\n", text, count=1)
with open(dst, "w") as fh:
    fh.write(text)
PYEOF
[ "$_control_ok" -eq 1 ] || die "failed to render DEBIAN/control from $MAINT_DIR/control (fail closed)"
else
    cat > "$CONTROL" <<EOF
Package: universal-db-mcp
Version: $DEB_VERSION
Section: database
Priority: optional
Architecture: $DEB_ARCH
Depends: python3 (>= 3.12~), python3-venv, libc6 (>= 2.36)
Recommends: systemd
Maintainer: Universal DB MCP Release Engineering <release@udbmcp.invalid>
Description: Universal Database MCP server (read-only, air-gapped)
 MCP server exposing read-only, policy-checked SQL access to relational
 databases, installed from the signed offline bundle. Nothing in this
 package executes payload before the admin-installed trusted verifier has
 re-verified the unpacked bundle against the admin-held release public key
 (verify before execute; every failure is fatal, never bypassed).
EOF
fi
chmod 0644 "$CONTROL"

# --- trust invariant check: the release public key must NEVER ship inside
# the package. Scan the staged root for public-key material (same name-based
# pattern set as build_pkg.sh / build_msi.sh, see find_pubkey_material above)
# and fail closed. NOTE: find_pubkey_material places -type f \( ... \) AFTER
# its path arguments, so no -print/-quit may be passed through (it would land
# before the expression and match the root directory itself, like BSD/GNU
# find's left-to-right evaluation); hits are CAPTURED, not piped to grep -q,
# so a large hit list cannot SIGPIPE find under pipefail (see below).
# NOTE: build_msi.sh/build_pkg.sh use the old piped form — apply the same
# capture fix there for consistency.
# CAPTURE the hits instead of `... | grep -q .`: under `set -o pipefail`,
# grep -q exits after its first match and a large hit list would SIGPIPE
# find (rc=141), making the pipeline non-zero and silently taking the
# "no keys" branch — i.e. the build would PROCEED with key material staged.
_key_hits="$(find_pubkey_material "$DEBROOT" || true)"
if [ -n "$_key_hits" ]; then
    printf '%s\n' "$_key_hits"
    unset _key_hits
    die "public key material found in staged deb root — the release pubkey is never shipped inside a package"
fi
unset _key_hits

echo "==> staged deb root at $DEBROOT"

# ---------------------------------------------------------------------------
# 4. build inside the baseline container
# ---------------------------------------------------------------------------

OUTDIR="$OUT_REL"
case "$OUTDIR" in
    /*) ;;                       # absolute: use as-is
    *) OUTDIR="$PROJECT_ROOT/$OUTDIR" ;;
esac
mkdir -p "$OUTDIR"
OUTDIR="$(cd "$OUTDIR" && pwd -P)"

echo "==> building .deb inside $BASELINE_IMAGE (dpkg-deb --root-owner-group)"
# debroot is mounted read-only: dpkg-deb only reads it; the .deb lands in the
# dist mount. --root-owner-group forces root:root ownership regardless of the
# staging host's uid (staging is often macOS).
docker run --rm \
    -v "$DEBROOT":/debroot:ro \
    -v "$OUTDIR":/dist \
    "$BASELINE_IMAGE" \
    dpkg-deb --root-owner-group --build /debroot "/dist/$DEB_FILE"

DEB_PATH="$OUTDIR/$DEB_FILE"
[ -s "$DEB_PATH" ] || die "dpkg-deb reported success but $DEB_PATH is missing/empty (fail closed)"

# ---------------------------------------------------------------------------
# done
# ---------------------------------------------------------------------------

echo "==> built: $DEB_PATH"
echo "    sha256: $(sha256_of "$DEB_PATH")"
echo "==> version $DEB_VERSION derives from the signed manifest (release=$RELEASE source_rev=$SOURCE_REV)."
