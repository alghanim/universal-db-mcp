#!/usr/bin/env bash
# build_msi.sh — build the Windows .msi from the SIGNED offline bundle.
#
# Usage:
#   scripts/package/build_msi.sh <signed-bundle-dir> --pubkey <release.pub.pem> [--out dist]
#
# What it does (approved plan, Phase 5):
#   1. Refuses to run without the Phase 0 staging-host prerequisites
#      (dotnet SDK + the global `wix` tool) and prints the exact install
#      commands instead of failing somewhere halfway through.
#   2. Refuses to run against an unsigned/unverified bundle: the bundle is
#      verified FIRST via the trusted-tools copy of verify_bundle.py that
#      ships next to the bundle on the trusted staging channel
#      (<bundle-dir>/../trusted-tools/), with the admin-supplied public key.
#      Any verification failure aborts the build (fail closed).
#   3. Harvests the staged signed bundle into a WiX fragment with a built-in
#      WiX v4-native generator (section 3 below). `heat` is NOT a command of
#      the WiX v4+ `wix` CLI — that CLI implements only `build` and `eula`
#      (plus commands contributed by extensions, and no heat extension ships
#      with it; heat was split into the separate, deprecated WixToolset.Heat
#      package) — so the harvest cannot be delegated to `wix`. The generator
#      emits the heat-equivalent authoring directly:
#        ComponentGroup Id="HarvestedBundleComponents", components directly
#        under DirectoryRef Id="BundleDir", File/@Source resolved via the
#        BundleSourceDir preprocessor variable
#      (harvest.wxi is a BUILD PRODUCT — the .wxs includes it relatively and
#      it is intentionally never committed; the build runs out of a temp dir
#      so the repo tree stays clean).
#   4. Substitutes the SIGNED manifest.release into the .wxs preprocessor
#      variables (ProductVersion) plus the build-time paths, then:
#        wix build -arch x64 \
#            -define ProductVersion=<manifest.release> \
#            -define ConfigTemplateSource=<staged config template> \
#            -define BundleSourceDir=<staged signed bundle> \
#            -out dist/universal-db-mcp-<version>-win-x86_64.msi \
#            <staged copy of packaging/msi/udbmcp.wxs>
#   5. Sanity-checks the artifact: first 8 bytes MUST be the OLE Compound
#      Document magic D0 CF 11 E0 A1 B1 1A E1 (checked directly; `file(1)`
#      output is shown as corroboration when available), and xmllint
#      validates the .wxs syntax when xmllint is installed.
#
# Trust invariants enforced here (NEVER break):
#   - No package is produced before a trusted-channel
#     verify_bundle.py --pubkey run has passed on the source bundle.
#   - The release public key is NEVER shipped inside the package: it is
#     distributed out-of-band by the admin (on Windows it is provisioned to
#     C:\ProgramData\udbmcp-trust by the admin BEFORE running the MSI). The
#     staged payload is scanned and the build fails if any public key
#     material would be embedded.
#   - Nothing in the bundle is executed on the staging host; the build only
#     copies bytes. Runtime verification happens in the deferred custom
#     actions (packaging/msi/custom/*.ps1) on the target machine.
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
    echo "universal-db-mcp: msi build ABORTED (fail closed)." >&2
    exit 1
}

usage() {
    sed -n '2,8p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
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
    # trees. Trust invariant: the release public key is NEVER shipped inside
    # a package — it is distributed out-of-band by the admin (on Windows it
    # is provisioned to C:\ProgramData\universal-db-mcp\keys BEFORE msiexec
    # runs; the MSI custom actions read it from machine scope only).
    find "$@" -type f \( -name '*.pub' -o -name '*.pub.pem' -o -name '*.pem' -o -name 'release.pub*' -o -name '*pubkey*' \)
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
# 0. staging-host prerequisites (plan Phase 0): dotnet + wix
# ---------------------------------------------------------------------------

_missing=0
if ! command -v dotnet >/dev/null 2>&1; then
    echo "FAIL: dotnet not found on staging host." >&2
    echo "      Install the .NET 8 SDK (plan Phase 0 prerequisite):" >&2
    echo "        macOS:   brew install --cask dotnet-sdk" >&2
    echo "        Windows: winget install Microsoft.DotNet.SDK.8" >&2
    echo "        Linux:   https://dotnet.microsoft.com/download/dotnet/8.0" >&2
    _missing=1
fi
if ! command -v wix >/dev/null 2>&1; then
    echo "FAIL: wix not found on staging host." >&2
    echo "      Install the WiX v4+ global tool (plan Phase 0 prerequisite):" >&2
    echo "        dotnet tool install --global wix" >&2
    _missing=1
fi
[ "$_missing" -eq 0 ] || die "staging host prerequisites missing (install commands printed above)"

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
target = m.get("target") or {}

if not release:
    print("FAIL: manifest has no release field", file=sys.stderr)
    raise SystemExit(1)

# This builder only produces Windows MSIs; refuse anything else loudly
# instead of silently mis-packaging another platform bundle.
os_name = str(target.get("os", ""))
arch = str(target.get("arch", ""))
if os_name != "windows" or arch != "x86_64":
    print("FAIL: manifest target is " + os_name + "/" + arch
          + "; build_msi.sh only packages windows-x86_64 bundles "
          + "(use build_deb.sh / build_pkg.sh for those)", file=sys.stderr)
    raise SystemExit(1)

print(release)
print(os_name)
print(arch)
PYEOF
if [ "$_fields_ok" -ne 1 ]; then
    rm -f "$FIELDS_TMP"
    die "could not read release/target from $MANIFEST (fail closed)"
fi

RELEASE="$(sed -n '1p' "$FIELDS_TMP")"
TARGET_OS="$(sed -n '2p' "$FIELDS_TMP")"
TARGET_ARCH="$(sed -n '3p' "$FIELDS_TMP")"
rm -f "$FIELDS_TMP"

case "$RELEASE" in
    ""|*[!A-Za-z0-9.]*) die "invalid release version in manifest: '$RELEASE'" ;;
esac

# MSI ProductVersion is numerically limited (first three fields, each
# <= 65535). Verify against the SIGNED manifest version so a bad version
# fails here instead of surfacing as a broken installer on the target.
_fields_ok=1
python3 - "$RELEASE" <<'PYEOF' || _fields_ok=0
import sys

version = sys.argv[1]
parts = version.split(".")
if not all(p.isdigit() for p in parts) or not parts:
    print("FAIL: release version is not numeric-dotted: " + version, file=sys.stderr)
    raise SystemExit(1)
if len(parts) > 3:
    print("WARN: release has more than 3 numeric fields; MSI ProductVersion keeps only the first three: "
          + ".".join(parts[:3]), file=sys.stderr)
for field in parts[:3]:
    if int(field) > 65535:
        print("FAIL: ProductVersion field exceeds 65535: " + field, file=sys.stderr)
        raise SystemExit(1)
PYEOF
[ "$_fields_ok" -eq 1 ] || die "manifest release '$RELEASE' is not a valid MSI ProductVersion (fail closed)"

MSI_FILE="universal-db-mcp-${RELEASE}-win-${TARGET_ARCH}.msi"

echo "==> bundle:    $BUNDLE"
echo "==> target:    $TARGET_OS/$TARGET_ARCH"
echo "==> version:   $RELEASE (from signed manifest)"

# ---------------------------------------------------------------------------
# 1. verify the source bundle BEFORE staging anything (fail closed)
# ---------------------------------------------------------------------------

[ -f "$BUNDLE/SIGNATURE" ] || die "bundle is UNSIGNED (no SIGNATURE file) — refusing to package it"
[ -f "$BUNDLE/SHA256SUMS" ] || die "bundle is UNSIGNED (no SHA256SUMS file) — refusing to package it"

# The trusted tools are distributed by prepare_offline_bundle.py as a
# SIBLING of the bundle directory on the same trusted channel
# (<staging-out>/trusted-tools/). Fall back to an in-bundle copy only for
# layouts that ship it there. If neither exists, fail closed: verifying with
# the bundle's own installers/ copies proves nothing (reference copies).
TRUSTED=""
for cand in "$BUNDLE/../trusted-tools" "$BUNDLE/trusted-tools"; do
    if [ -f "$cand/verify_bundle.py" ]; then
        TRUSTED="$(cd "$cand" && pwd -P)"
        break
    fi
done
[ -n "$TRUSTED" ] || die "trusted-tools/ (with verify_bundle.py) not found next to the bundle — cannot verify from the trusted channel"

echo "==> verifying bundle via trusted-channel verifier: $TRUSTED/verify_bundle.py"
# --allow-platform-mismatch is the documented STAGING-side mode (the staging
# host is macOS/Linux while the bundle targets windows-x86_64): it skips only
# the local python-version check, never a signature check. The deferred
# custom action on the Windows target re-verifies WITHOUT this flag.
python3 "$TRUSTED/verify_bundle.py" \
    --bundle "$BUNDLE" \
    --pubkey "$PUBKEY" \
    --allow-platform-mismatch \
    || die "bundle verification FAILED against $BUNDLE — refusing to package unverified payload"

# ---------------------------------------------------------------------------
# 2. stage the build tree (nothing here executes; bytes are only copied)
# ---------------------------------------------------------------------------

STAGE="$(mktemp -d "${TMPDIR:-/tmp}/udbmcp-msi.XXXXXX")"
cleanup() { rm -rf "$STAGE"; }
trap cleanup EXIT INT TERM

STAGE_BUNDLE="$STAGE/bundle"
mkdir -p "$STAGE_BUNDLE"

# Payload: the ENTIRE signed bundle, byte-for-byte (cp -a preserves modes so
# the target-side verification sees exactly what was signed).
echo "==> staging signed bundle payload"
cp -a "$BUNDLE/." "$STAGE_BUNDLE/"

# Trust invariant check: the release public key must NEVER ship inside the
# package (on Windows the admin provisions it out-of-band into
# C:\ProgramData\universal-db-mcp\keys before the MSI runs; the deferred
# verify action reads it from machine scope). Scan the staged payload for
# public-key material and fail closed.
if find_pubkey_material "$STAGE_BUNDLE" | grep -q .; then
    find_pubkey_material "$STAGE_BUNDLE"
    die "public key material found in staged msi payload — the release pubkey is never shipped inside a package"
fi

# Config template for the machine-wide config component
# (ProgramData\UniversalDB MCP\config.yaml, NeverOverwrite). Must exist in
# the signed bundle — a missing template fails the build, never silently
# dropped, because the .wxs File/@Source has to resolve at compile time.
CONFIG_TEMPLATE="$STAGE_BUNDLE/config-templates/config.template.yaml"
[ -f "$CONFIG_TEMPLATE" ] || die "config template missing from bundle: config-templates/config.template.yaml"

# Authoring: a build-time copy of packaging/msi/udbmcp.wxs so the relative
# <?include "harvest.wxi" ?> resolves inside the temp staging dir and the
# repo tree stays free of build products.
WXS_SRC="$PROJECT_ROOT/packaging/msi/udbmcp.wxs"
[ -f "$WXS_SRC" ] || die "WiX authoring missing: $WXS_SRC (expected from packaging/msi/)"
cp "$WXS_SRC" "$STAGE/udbmcp.wxs"

# Custom action scripts: the deferred PowerShell actions that perform the
# runtime verification / venv build / doctor smoke / service registration on
# the Windows target ship INSIDE the MSI. udbmcp.wxs installs them into
# INSTALLFOLDER\scripts (OUTSIDE the bundle dir, so verify.ps1's containment
# guards hold) and schedules them as deferred, impersonate=no actions; this
# staging copy is what -define CustomActionScriptsDir resolves at compile
# time. A missing script is a packaging bug: fail closed, never silently
# ship a half-wired installer.
CUSTOM_SRC="$PROJECT_ROOT/packaging/msi/custom"
[ -d "$CUSTOM_SRC" ] || die "custom action scripts missing: $CUSTOM_SRC (expected from packaging/msi/custom/)"
CUSTOM_STAGE="$STAGE/custom"
mkdir -p "$CUSTOM_STAGE"
for ps1 in verify.ps1 venv.ps1 doctor.ps1 service.ps1 uninstall.ps1; do
    [ -f "$CUSTOM_SRC/$ps1" ] || die "custom action script missing: $CUSTOM_SRC/$ps1 (the deferred action wiring in udbmcp.wxs requires it)"
    cp "$CUSTOM_SRC/$ps1" "$CUSTOM_STAGE/$ps1"
done

# Same trust invariant as the payload above, applied to the custom action
# scripts: they are part of the package, so they may not ship key material.
if find_pubkey_material "$CUSTOM_STAGE" | grep -q .; then
    find_pubkey_material "$CUSTOM_STAGE"
    die "public key material found in the staged custom action scripts — the release pubkey is never shipped inside a package"
fi

# ---------------------------------------------------------------------------
# 3. harvest the staged signed bundle -> harvest.wxi (WiX v4-native)
# ---------------------------------------------------------------------------

# `heat` is NOT a command of the WiX v4+ `wix` CLI: that CLI implements only
# `build` and `eula` (plus commands contributed by extensions, and no heat
# extension ships with it — heat was split into the separate, deprecated
# WixToolset.Heat package). Rather than adding a second, deprecated tool to
# the Phase 0 prerequisites, the harvest fragment is generated natively here:
# the heat-equivalent authoring udbmcp.wxs expects (components directly under
# DirectoryRef Id="BundleDir", grouped as ComponentGroup
# Id="HarvestedBundleComponents", File/@Source resolved via the
# -define BundleSourceDir variable) is emitted straight from the staged
# SIGNED bundle. Nothing is executed — the bundle is only READ (file names
# and directory structure); the payload bytes are packaged verbatim by wix.

HARVESTER="$STAGE/harvest.py"
cat > "$HARVESTER" <<'PYEOF'
# -*- coding: utf-8 -*-
"""WiX v4-native harvest for scripts/package/build_msi.sh (fail closed).

`heat` is not a command of the WiX v4+ `wix` CLI, so the heat-equivalent
fragment is generated natively: ComponentGroup Id="HarvestedBundleComponents"
of components directly under DirectoryRef Id="BundleDir" (the -srd shape),
with every File/@Source resolved through the BundleSourceDir preprocessor
variable.

Deterministic: a sorted walk and hashed identifiers, so repeated builds of
the same signed bundle produce byte-identical authoring (and stable
auto-generated component GUIDs). The bundle is only READ — nothing is
executed. Any entry that is not a regular file or a real directory (symlinks,
devices, fifos, an empty tree) fails the build: an MSI must package exactly
the signed bytes, never a link target resolved at build time.
"""

import hashlib
import os
import sys
from xml.sax.saxutils import quoteattr

WIX_NS = "http://wixtoolset.org/schemas/v4/wxs"


def fail(msg):
    sys.stderr.write("FAIL: harvest: " + msg + "\n")
    raise SystemExit(1)


bundle = sys.argv[1]
out_path = sys.argv[2]

# --- collect the payload (sorted walk -> deterministic output) --------------
payload = []  # relative POSIX paths of every regular file, sorted
for root, dirs, names in os.walk(bundle):
    dirs.sort()
    names.sort()
    for d in list(dirs):
        full = os.path.join(root, d)
        if os.path.islink(full):
            fail("symlinked directory in staged payload ("
                 + os.path.relpath(full, bundle)
                 + "): the MSI must package exactly the signed bytes")
    for n in names:
        full = os.path.join(root, n)
        if os.path.islink(full) or not os.path.isfile(full):
            fail("non-regular file in staged payload ("
                 + os.path.relpath(full, bundle)
                 + "): the MSI must package exactly the signed bytes")
        payload.append(os.path.relpath(full, bundle).replace(os.sep, "/"))

if not payload:
    fail("staged bundle is empty — nothing to harvest (fail closed)")

# --- nested directory tree; "" marks the files of the current directory ----
tree = {}
for rel in payload:
    parts = rel.split("/")
    node = tree
    for part in parts[:-1]:
        node = node.setdefault(part, {})
    node.setdefault("", []).append(parts[-1])

# --- every harvested subdirectory (relpath) ---------------------------------
all_dirs = set()
for rel in payload:
    parts = rel.split("/")
    for i in range(1, len(parts)):
        all_dirs.add("/".join(parts[:i]))

# --- stable, unique MSI identifiers (heat-style cmp_/fil_/dir_ + hash) ------
_used = set()


def ident(prefix, key):
    i = prefix + hashlib.sha256(("udbmcp-harvest:" + key).encode("utf-8")).hexdigest()[:20]
    if i in _used:
        fail("identifier collision: " + i + " (" + key + ")")
    _used.add(i)
    return i


comp_id = {rel: ident("cmp_", "f:" + rel) for rel in payload}
file_id = {rel: ident("fil_", "f:" + rel) for rel in payload}
dir_id = {d: ident("dir_", "d:" + d) for d in all_dirs}

lines = [
    '<?xml version="1.0" encoding="utf-8"?>',
    '<!--',
    '  GENERATED AT BUILD TIME by scripts/package/build_msi.sh - do not edit, do not commit.',
    '',
    '  Heat-equivalent harvest of the staged SIGNED bundle (heat is not part of the WiX v4+',
    '  wix CLI): one component per payload file directly under DirectoryRef Id="BundleDir",',
    '  grouped as ComponentGroup Id="HarvestedBundleComponents". Every File/@Source resolves',
    '  through the BundleSourceDir preprocessor variable passed by build_msi.sh.',
    '  Deterministic (sorted walk + hashed identifiers) so repeated builds of the same',
    '  signed bundle produce identical authoring and stable auto component GUIDs.',
    '-->',
    # A .wxi preprocessor include MUST use <Include> as its document element
    # (WiX error WIX0048: "A WiX include file must use 'Include' as the
    # document element name"); its children are spliced into the including
    # document at the <?include?> site (directly inside <Wix>, so a Fragment
    # child is what lands there). The namespace is declared here because the
    # fragment is parsed as its own XML document before inclusion.
    '<Include xmlns="' + WIX_NS + '">',
    '  <Fragment>',
    '    <DirectoryRef Id="BundleDir">',
]


def emit(node, prefix, depth):
    pad = "    " + "  " * depth
    for name in sorted(k for k in node if k != ""):
        rel = prefix + "/" + name if prefix else name
        lines.append(pad + "<Directory Id=" + quoteattr(dir_id[rel])
                     + " Name=" + quoteattr(name) + ">")
        emit(node[name], rel, depth + 1)
        lines.append(pad + "</Directory>")
    for name in sorted(node.get("", [])):
        rel = prefix + "/" + name if prefix else name
        lines.append(pad + "<Component Id=" + quoteattr(comp_id[rel])
                     + ' Guid="*">')
        lines.append(pad + "  <File Id=" + quoteattr(file_id[rel])
                     + " Name=" + quoteattr(name)
                     + " Source=" + quoteattr("$(var.BundleSourceDir)/" + rel)
                     + ' KeyPath="yes" />')
        lines.append(pad + "</Component>")


emit(tree, "", 1)

lines.append('    </DirectoryRef>')
lines.append('    <ComponentGroup Id="HarvestedBundleComponents">')
for rel in payload:
    lines.append("      <ComponentRef Id=" + quoteattr(comp_id[rel]) + " />")
lines.append('    </ComponentGroup>')
lines.append('  </Fragment>')
lines.append('</Include>')

with open(out_path, "w", encoding="utf-8") as fh:
    fh.write("\n".join(lines) + "\n")
PYEOF

echo "==> harvesting bundle payload with the built-in WiX v4 fragment generator"
python3 "$HARVESTER" "$STAGE_BUNDLE" "$STAGE/harvest.wxi" \
    || die "bundle payload harvest failed — no MSI is produced from an unharvestable payload"

[ -s "$STAGE/harvest.wxi" ] || die "harvest reported success but harvest.wxi is missing/empty (fail closed)"

# Syntax validation of the authoring + generated fragment (plan Phase 5).
# xmllint is build-only validation; it is not always installed on the staging
# host, in which case we say so loudly and continue (the wix compile itself
# is the real gate). If it IS present and the XML is malformed: fail closed.
if command -v xmllint >/dev/null 2>&1; then
    xmllint --noout "$STAGE/udbmcp.wxs" || die "udbmcp.wxs is not well-formed XML (xmllint)"
    xmllint --noout "$STAGE/harvest.wxi" || die "harvest.wxi is not well-formed XML (xmllint)"
else
    echo "NOTE: xmllint not installed; skipping XML syntax validation (wix build still validates the authoring)" >&2
fi

# ---------------------------------------------------------------------------
# 4. compile the .msi
# ---------------------------------------------------------------------------

OUTDIR="$OUT_REL"
case "$OUTDIR" in
    /*) ;;                       # absolute: use as-is
    *) OUTDIR="$PROJECT_ROOT/$OUTDIR" ;;
esac
mkdir -p "$OUTDIR"
OUTDIR="$(cd "$OUTDIR" && pwd -P)"
MSI_PATH="$OUTDIR/$MSI_FILE"

echo "==> compiling $MSI_PATH"

# KNOWN WIX-ON-UNIX LIMITATION (documented, not worked around): the WiX
# compiler validates every allowRelative filename — including Directory/@Name
# — through BundleValidator.GetCanonicalRelativePath, which does
#   Path.GetFullPath("C:\" + name) and requires the result to start with "C:\".
# On macOS/Linux GetFullPath never yields a "C:\"-rooted path, so current WiX
# (v4 through v7) rejects EVERY Directory/@Name with
#   error WIX0389: ... is not a relative path.
# Consequence: the compile step below only SUCCEEDS on a Windows staging
# host. On this Unix host it fails closed here — after the bundle has been
# trusted-channel-verified, staged, harvested and xmllint-validated — and no
# artifact is produced. That is the honest state recorded in the ledger
# (Windows MSI: NOT built; install gate not_run) until a Windows host runs
# this script (plan Phase 0 prerequisites apply there too).
if [ "$(uname -s)" != "Windows_NT" ]; then
    echo "NOTE: compiling on a non-Windows staging host. WiX v4-v7 reject every" >&2
    echo "      Directory/@Name on Unix (WIX0389, WiX toolchain limitation), so the" >&2
    echo "      compile below is expected to FAIL CLOSED here. MSI compilation needs" >&2
    echo "      a Windows staging host with the same Phase 0 prerequisites." >&2
fi

wix build -arch x64 \
    -define "ProductVersion=$RELEASE" \
    -define "ConfigTemplateSource=$CONFIG_TEMPLATE" \
    -define "BundleSourceDir=$STAGE_BUNDLE" \
    -define "CustomActionScriptsDir=$CUSTOM_STAGE" \
    -out "$MSI_PATH" \
    "$STAGE/udbmcp.wxs" \
    || { rm -f "$MSI_PATH"; die "wix build failed — no MSI is produced from a failed compile"; }

[ -s "$MSI_PATH" ] || { rm -f "$MSI_PATH"; die "wix build reported success but $MSI_PATH is missing/empty (fail closed)"; }

# ---------------------------------------------------------------------------
# 5. sanity: the artifact MUST be an OLE Compound Document (MSI container)
# ---------------------------------------------------------------------------

MAGIC_TMP="$(mktemp "${TMPDIR:-/tmp}/udbmcp-magic.XXXXXX")"
# first 8 bytes, hex, lowercase, no separators: d0cf11e0a1b11ae1
if command -v xxd >/dev/null 2>&1; then
    head -c 8 "$MSI_PATH" | xxd -p | tr -d ' \n' > "$MAGIC_TMP"
elif command -v od >/dev/null 2>&1; then
    head -c 8 "$MSI_PATH" | od -An -tx1 | tr -d ' \n' > "$MAGIC_TMP"
else
    die "neither xxd nor od available to verify the MSI file magic (fail closed)"
fi
MAGIC="$(cat "$MAGIC_TMP")"
rm -f "$MAGIC_TMP"

# D0 CF 11 E0 A1 B1 1A E1 — OLE2 / Compound File Binary Format
[ "$MAGIC" = "d0cf11e0a1b11ae1" ] \
    || { rm -f "$MSI_PATH"; die "$MSI_PATH is not an OLE compound file (first 8 bytes: $MAGIC) — refusing to ship a corrupt artifact"; }

if command -v file >/dev/null 2>&1; then
    echo "==> file(1): $(file -b "$MSI_PATH")"
fi

# ---------------------------------------------------------------------------
# done
# ---------------------------------------------------------------------------

echo "==> built: $MSI_PATH"
echo "    sha256: $(sha256_of "$MSI_PATH")"
echo "==> version $RELEASE derives from the signed manifest (release=$RELEASE, target=$TARGET_OS/$TARGET_ARCH)."
echo "    Runtime verification, venv build, and service install are performed by deferred"
echo "    custom actions on the Windows target (wired in packaging/msi/udbmcp.wxs; scripts"
echo "    staged from packaging/msi/custom/*.ps1) and are gated by scripts/test_package_msi.ps1"
echo "    — record Windows runtime rows as not_run until then."
