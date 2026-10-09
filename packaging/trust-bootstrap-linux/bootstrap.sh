#!/bin/bash
# Trust bootstrap for universal-db-mcp on Ubuntu/Debian.
#
# Run FROM the trusted channel: this folder, carried on the same USB stick
# that delivered the .deb. It installs itself, the trusted verifier, the
# profile registry, the offline installer and its helper, and the release
# PUBLIC key at the fixed root-owned paths the package's preinst/postinst
# require.
# Nothing here touches the package payload - the payload stays verified by
# THESE tools after unpacking.
#
# The stick is checked BEFORE anything is copied. release_usb.sh lists every
# file on the stick in SHA256SUMS and signs that list with the release key
# (SHA256SUMS.sig). The bundle signature covers only the payload inside the
# package, so this list is what covers the .deb's maintainer scripts (dpkg
# runs preinst as root before any payload exists), this folder and the Oracle
# client. When a release key is already installed, the signature is checked
# with THAT key, never with the one on the stick; then every file on the
# stick must be on the list and match it (a file the list does not name is
# refused). On any failure the trust dir is left untouched. dpkg -i reads a
# .deb again, so the packages on the list are copied where only root can
# change them and those checked copies are the ones it is told to install.
# On a first install only the stick's own key exists, so the check proves the
# stick matches that key and authenticity rests on comparing its fingerprint
# (printed below) with the value recorded out-of-band.
#
# Releases are ordered: every stick of an earlier release signed with the
# same key passes the signature check, and replaying one would put back that
# release's trust tools (a verifier without a later fix). release_usb.sh
# writes the release_seq into trust-bootstrap-linux/RELEASE, which the signed
# list covers; the trust dir keeps the value this script last installed, and
# a lower one (or a stick that names none, once a value is recorded) is
# refused unless --allow-downgrade is passed, as the verifier refuses an
# older package.
#
# The release public key is the trust anchor of the site. Once one is
# installed, this script REFUSES to replace it with a different key unless
# the operator passes --rotate-key after comparing the fingerprint printed
# below with the value recorded out-of-band (a stick that carries its own
# key, verifier and package would otherwise verify itself).
#
# This script also installs itself in the trust dir. That installed copy is
# the one to run on every later upgrade: it comes from a stick the site
# already checked, so nothing from the NEW stick runs before the new stick's
# signature has been checked with the installed key. The stick's own copy of
# this script checks the same signature, but under this file's threat model
# (someone could change the stick) it is the stick vouching for itself.
#
# Usage:  sudo bash /usr/local/lib/udbmcp-trust/bootstrap.sh --stick <stick> [--rotate-key] [--allow-downgrade]
#           (an upgrade: the copy a previous bootstrap installed checks <stick>)
#         sudo bash <stick>/trust-bootstrap-linux/bootstrap.sh [--rotate-key] [--allow-downgrade]
#           (a first install, or a site whose trust dir has no bootstrap.sh yet)
# The stick is the folder named on the command line, as typed: never where a
# symlinked trust-bootstrap-linux leads, which could move every check below
# into a signed copy nested on the stick and away from the files next to it.
# UDBMCP_BOOTSTRAP_ROOT=<dir> treats <dir> as the site's / : every destination
# and the system openssl are looked up below it (a scratch site for tests; no
# root needed there). It is refused when the script runs as root: `sudo -E`
# keeps the caller's environment, and root would then trust a key, run an
# openssl and hand dpkg packages from a directory the caller chose.
set -euo pipefail
unset CDPATH  # a relative stick path is taken as typed, never searched for
# sudo -E keeps the caller's TMPDIR (and python's tempfile takes TEMP or TMP):
# root's temporary files, such as bash's here-strings below, go to the
# system's own directory, never to one another account can write.
unset TMPDIR TEMP TMP

ROOT="${UDBMCP_BOOTSTRAP_ROOT:-}"
if [ -n "$ROOT" ] && [ "$(id -u)" -eq 0 ]; then
  echo "FAIL: UDBMCP_BOOTSTRAP_ROOT is set ($ROOT): it is a test hook for unprivileged runs and is" >&2
  echo "      refused as root (sudo -E keeps it). Run: sudo bash <this script> without it. Nothing was installed." >&2
  exit 1
fi
TRUST_DIR="$ROOT/usr/local/lib/udbmcp-trust"
KEY_DST="$ROOT/etc/universal-db-mcp/keys/release.pub.pem"
SYSTEM_OPENSSL="$ROOT/usr/bin/openssl"
usage() {
  echo "usage: sudo bash $TRUST_DIR/bootstrap.sh --stick <stick> [--rotate-key] [--allow-downgrade]" >&2
  echo "       sudo bash <stick>/trust-bootstrap-linux/bootstrap.sh [--rotate-key] [--allow-downgrade]" >&2
  exit 2
}
ROTATE=0
ALLOW_DOWNGRADE=0
STICK_ARG=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --rotate-key) ROTATE=1 ;;
    --allow-downgrade) ALLOW_DOWNGRADE=1 ;;
    --stick) [ "$#" -ge 2 ] && [ -n "$2" ] || usage; STICK_ARG="$2"; shift ;;
    *) usage ;;
  esac
  shift
done
if [ -n "$STICK_ARG" ]; then
  STICK="$(cd -- "$STICK_ARG" && pwd -P)" || { echo "FAIL: no such stick folder: $STICK_ARG" >&2; exit 1; }
  RERUN="sudo bash $0 --stick $STICK"
else
  # The parent of the folder named in the path this script was run by. cd
  # takes a '..' in it textually, so a symlinked trust-bootstrap-linux is not
  # followed here; it is refused below, like every symlink on the stick. A
  # bare `bash bootstrap.sh` names no stick: under sudo, which drops the
  # logical $PWD, '..' would be wherever the folder really is.
  case "$0" in
    trust-bootstrap-linux/bootstrap.sh | */trust-bootstrap-linux/bootstrap.sh) ;;
    *) echo "FAIL: run this script by its path on the stick, which names the stick:" >&2
       echo "        sudo bash <stick>/trust-bootstrap-linux/bootstrap.sh" >&2
       usage ;;
  esac
  STICK="$(cd "$(dirname "$(dirname "$0")")" && pwd -P)"
  RERUN="sudo bash $STICK/trust-bootstrap-linux/bootstrap.sh"
fi
# The stick's trust tools: what this script checks and installs.
DIR="$STICK/trust-bootstrap-linux"

[ -n "$ROOT" ] || [ "$(id -u)" -eq 0 ] || { echo "FAIL: run with sudo (destinations are root-owned)." >&2; exit 1; }
for f in bootstrap.sh verify_bundle.py profiles.py install_offline.sh lib/os_packages.sh release.pub.pem; do
  [ -s "$DIR/$f" ] || { echo "FAIL: missing or empty: $DIR/$f" >&2; exit 1; }
done
# -f as well: a directory by either name has a size too, and would end this
# script at the copy below with nothing but cp's own complaint.
for f in SHA256SUMS SHA256SUMS.sig; do
  [ -f "$STICK/$f" ] && [ -s "$STICK/$f" ] || {
    echo "FAIL: the stick has no $STICK/$f." >&2
    echo "      A release stick lists every file in SHA256SUMS and signs that list (SHA256SUMS.sig);" >&2
    echo "      without both nothing on this stick can be trusted. Get the stick again from the" >&2
    echo "      release administrator. Nothing was installed." >&2
    exit 1
  }
done

# --- the stick holds regular files only, checked before any is read -----------
# release_usb.sh signs regular files only, and a symlink can change after the
# checks below. This needs nothing from the signed list, so it runs before the
# copy and the checksum runs read the stick: a FIFO at a listed name would
# block them, and a link to a device would be read forever. Skipped, on both
# sides (release_usb.sh never signs them): the metadata a Mac writes when the
# stick is copied on it (._* AppleDouble files, .DS_Store, the volume's
# .Spotlight-V100, .fseventsd, .Trashes and .TemporaryItems) and Windows'
# System Volume Information. Nothing reads them, and a shell glob such as
# libaio1t64_*.deb never matches a name that starts with a dot. A ._* or
# .DS_Store name is skipped only as a regular file, which is what a Mac
# writes: a symlink or FIFO by such a name is refused like any other.
on_stick() {
  ( cd "$STICK" && find . \( -path ./.Spotlight-V100 -o -path ./.fseventsd -o -path ./.Trashes \
      -o -path ./.TemporaryItems -o -path './System Volume Information' \) -prune \
      -o ! -type d ! \( -type f \( -name '._*' -o -name .DS_Store \) \) "$@" -print ) | sed 's|^\./||'
}
unlisted_fail() {
  local f
  while IFS= read -r f; do
    echo "FAIL: $f $1" >&2
  done <<< "$2"
  echo "      $3 Nothing was installed." >&2
  exit 1
}
unreadable_stick() {
  echo "FAIL: the files on the stick could not be listed. Nothing was installed." >&2
  exit 1
}
# find prints a name with a line break as two lines, which the comparison
# with the signed list would read as two other names: a release stick never
# holds one.
NL=$'\n'
LINE_BREAK="$(cd "$STICK" && find . -name "*$NL*" -print -quit)" || unreadable_stick
[ -z "$LINE_BREAK" ] || {
  echo "FAIL: the stick holds a file name with a line break; a release stick never does. Nothing was installed." >&2
  exit 1
}
NOT_REGULAR="$(on_stick ! -type f)" || unreadable_stick
[ -z "$NOT_REGULAR" ] || unlisted_fail "is not a regular file; a release stick holds regular files only." \
  "$NOT_REGULAR" "Get the stick again from the release administrator."

# Everything below reads a private copy of this folder and of the signed list,
# so the stick cannot change between check and copy. The copy lives in the
# site's /var/tmp, never where root's TMPDIR points (sudo -E keeps the
# caller's): in a directory another account can write, that account could
# rename the copy and put its own in its place. /var/tmp is sticky, so only
# root can rename what root creates there. The stick may still change while
# it is copied, so cp follows no link (-P: -L would read a link to /dev/zero
# as root forever) and copies a FIFO as a FIFO, and anything in the copy that
# is not a regular file is refused before any of it is read.
STAGE="$(mktemp -d "$ROOT/var/tmp/udbmcp-bootstrap.XXXXXX")"
DEB_NEW=""  # the copies for dpkg -i while they are made and checked (below)
trap 'rm -rf -- "$STAGE"; [ -z "$DEB_NEW" ] || rm -rf -- "$DEB_NEW"' EXIT
cp -RP "$DIR" "$STAGE/trust-bootstrap-linux"
cp -RP "$STICK/SHA256SUMS" "$STICK/SHA256SUMS.sig" "$STAGE/"
SRC="$STAGE/trust-bootstrap-linux"
STAGED_NOT_REGULAR="$(cd "$STAGE" && find . ! -type d ! -type f -print | sed 's|^\./||')" || {
  echo "FAIL: the private copy of the stick could not be listed. Nothing was installed." >&2
  exit 1
}
[ -z "$STAGED_NOT_REGULAR" ] || unlisted_fail "is not a regular file; a release stick holds regular files only." \
  "$STAGED_NOT_REGULAR" "The stick changed while it was read. Get the stick again from the release administrator."

fingerprint() {
  # SHA-256 of the DER-encoded public key; stable across PEM line wrapping
  if command -v openssl >/dev/null 2>&1; then
    openssl pkey -pubin -in "$1" -outform DER 2>/dev/null | sha256sum | awk '{print $1}'
  else
    sed -e '/^-----/d' "$1" | tr -d '\n' | base64 -d 2>/dev/null | sha256sum | awk '{print $1}'
  fi
}

# A key openssl cannot read fails the pipeline above (pipefail), which alone
# would end this script without a word: the refusals below say why.
NEW_FP="$(fingerprint "$SRC/release.pub.pem")" || NEW_FP=""
[ -n "$NEW_FP" ] || { echo "FAIL: $DIR/release.pub.pem is not a readable public key." >&2; exit 1; }
echo "==> release public key on this stick: sha256 $NEW_FP"
CUR_FP=""
if [ -s "$KEY_DST" ]; then
  CUR_FP="$(fingerprint "$KEY_DST")" || CUR_FP=""
  [ -n "$CUR_FP" ] || {
    echo "FAIL: the installed release key $KEY_DST is not a readable public key; it was left as it is." >&2
    echo "      Restore it from the trusted channel (its fingerprint is the value recorded out-of-band)." >&2
    echo "      Nothing was installed." >&2
    exit 1
  }
  echo "==> release public key already installed: sha256 $CUR_FP"
  if [ "$CUR_FP" != "$NEW_FP" ] && [ "$ROTATE" -ne 1 ]; then
    echo "FAIL: the key on this stick differs from the installed trust anchor; refusing to replace it." >&2
    echo "      Compare BOTH fingerprints with the value your release administrator gave you" >&2
    echo "      out-of-band. Only if the stick's key is the legitimate new key, re-run with:" >&2
    echo "        $RERUN --rotate-key" >&2
    exit 1
  fi
fi

# --- the stick must be the one the release key signed -------------------------
if [ -n "$CUR_FP" ] && [ "$CUR_FP" = "$NEW_FP" ]; then
  SIG_KEY="$KEY_DST"
  echo "==> checking the stick's SHA256SUMS.sig with the INSTALLED release key"
elif [ -n "$CUR_FP" ]; then
  SIG_KEY="$SRC/release.pub.pem"
  echo "==> --rotate-key: checking the stick's SHA256SUMS.sig with the stick's NEW key"
  echo "    (trusted only because you compared its fingerprint out-of-band)"
else
  SIG_KEY="$SRC/release.pub.pem"
  echo "==> first install: checking the stick's SHA256SUMS.sig with the stick's own key"
  echo "    (trusted only if its fingerprint above matches the value recorded out-of-band)"
fi

# Nothing from the stick checks the stick: the verifier a previous bootstrap
# installed in the trust dir (its built-in Ed25519 needs no openssl), or, when
# there is none or it predates detached verification, the system openssl by
# absolute path (OpenSSL 3 on Ubuntu 24.04 verifies Ed25519).
verify_stick_signature() {
  local out rc=0
  if [ -s "$TRUST_DIR/verify_bundle.py" ] && grep -q -- '--verify-file' "$TRUST_DIR/verify_bundle.py"; then
    out="$(python3 -I -S "$TRUST_DIR/verify_bundle.py" --verify-file "$STAGE/SHA256SUMS" \
             --signature "$STAGE/SHA256SUMS.sig" --pubkey "$1" 2>&1)" || rc=$?
    printf '%s\n' "$out"
    # exit 0 alone is not proof (an empty verifier exits 0): the PASSED line is
    [ "$rc" -eq 0 ] && printf '%s\n' "$out" | grep -qx 'signature verification PASSED' \
      && ! printf '%s\n' "$out" | grep -q '^FAIL:'
  elif [ -x "$SYSTEM_OPENSSL" ]; then
    "$SYSTEM_OPENSSL" pkeyutl -verify -pubin -inkey "$1" -rawin \
      -in "$STAGE/SHA256SUMS" -sigfile "$STAGE/SHA256SUMS.sig"
  else
    echo "FAIL: nothing to check the stick signature with: no trusted verifier at $TRUST_DIR" >&2
    echo "      and no $SYSTEM_OPENSSL. Install the openssl package, then re-run." >&2
    return 1
  fi
}
verify_stick_signature "$SIG_KEY" || {
  echo "FAIL: the stick's SHA256SUMS is NOT signed by the release key ($SIG_KEY)." >&2
  echo "      The stick was altered after release_usb.sh signed it, or it is not a release" >&2
  echo "      stick. Do not run or install anything from it. Nothing was installed." >&2
  exit 1
}
echo "==> stick signature verified: SHA256SUMS is the list the release key signed"

# --- every file on the stick must match the signed list -----------------------
for f in bootstrap.sh verify_bundle.py profiles.py install_offline.sh lib/os_packages.sh release.pub.pem; do
  awk -v p="trust-bootstrap-linux/$f" '$2 == p { found = 1 } END { exit !found }' "$STAGE/SHA256SUMS" || {
    echo "FAIL: trust-bootstrap-linux/$f is not on the stick's signed SHA256SUMS; refusing it." >&2
    exit 1
  }
done
( cd "$STAGE" && grep '  trust-bootstrap-linux/' SHA256SUMS | sha256sum -c --strict --quiet - ) || {
  echo "FAIL: the trust tools on the stick do not match its signed SHA256SUMS (see above). Nothing was installed." >&2
  exit 1
}
( cd "$STICK" && sha256sum -c --strict --quiet "$STAGE/SHA256SUMS" ) || {
  echo "FAIL: a file on the stick does not match its signed SHA256SUMS (see above); the .deb" >&2
  echo "      and every other file on it are untrusted. Nothing was installed." >&2
  exit 1
}
# sha256sum -c checks only the files the list names. A file added to a signed
# stick (a second .deb, one more libaio1t64_*.deb for the runbook's dpkg -i,
# a helper next to these tools) is on nobody's list, so it is refused.
{ awk '{ p = substr($0, 67); sub(/^\.\//, "", p); print p }' "$STAGE/SHA256SUMS"
  printf '%s\n' SHA256SUMS SHA256SUMS.sig; } | LC_ALL=C sort > "$STAGE/listed"
on_stick | LC_ALL=C sort > "$STAGE/on-stick" || unreadable_stick
UNLISTED="$(LC_ALL=C comm -23 "$STAGE/on-stick" "$STAGE/listed")"
[ -z "$UNLISTED" ] || unlisted_fail "is on the stick but not on its signed SHA256SUMS." "$UNLISTED" \
  "It was never checked: remove it, or get the stick again from the release administrator."
echo "==> every file on the stick matches the signed SHA256SUMS"
# The same for the private copy, before anything in it is read: the stick
# may change while it is read, so a file that was in this folder only while
# it was copied (a RELEASE naming any release, a helper) passed none of the
# checks above. The metadata skipped on the stick is skipped here too.
awk '{ p = substr($0, 67); sub(/^\.\//, "", p); if (index(p, "trust-bootstrap-linux/") == 1) print p }' \
  "$STAGE/SHA256SUMS" | LC_ALL=C sort > "$STAGE/listed-tools"
( cd "$STAGE" && find trust-bootstrap-linux -type f ! -name '._*' ! -name .DS_Store -print ) \
  | LC_ALL=C sort > "$STAGE/staged-tools" || {
  echo "FAIL: the private copy of the stick could not be listed. Nothing was installed." >&2
  exit 1
}
STAGED_UNLISTED="$(LC_ALL=C comm -23 "$STAGE/staged-tools" "$STAGE/listed-tools")"
[ -z "$STAGED_UNLISTED" ] || unlisted_fail "is in the private copy of the stick but not on its signed SHA256SUMS." \
  "$STAGED_UNLISTED" "The stick changed while it was read. Get the stick again from the release administrator."

# --- release order: an older signed stick never replaces newer trust tools ----
# The stick's RELEASE is read from the private copy, which holds only what the
# signed list names and matches it (above): a RELEASE the list does not name is
# refused there, and a stick whose list names none names no release. The
# recorded one is in the root-owned trust dir.
RELEASE_DST="$TRUST_DIR/RELEASE"
release_number() {
  # $1: a RELEASE file; prints its number, and fails when it holds anything else
  [ -f "$1" ] && [ ! -L "$1" ] && [ "$(wc -l < "$1")" -le 1 ] && grep -xE '[0-9]{1,18}' "$1"
}
STICK_RELEASE=""
if [ -e "$SRC/RELEASE" ] || [ -L "$SRC/RELEASE" ]; then
  STICK_RELEASE="$(release_number "$SRC/RELEASE")" || {
    echo "FAIL: trust-bootstrap-linux/RELEASE on this stick is not a release number; a release stick names" >&2
    echo "      its release_seq there. Get the stick again from the release administrator. Nothing was installed." >&2
    exit 1
  }
fi
INSTALLED_RELEASE=""
if [ -e "$RELEASE_DST" ] || [ -L "$RELEASE_DST" ]; then
  INSTALLED_RELEASE="$(release_number "$RELEASE_DST")" || {
    INSTALLED_RELEASE=""
    if [ "$ALLOW_DOWNGRADE" -ne 1 ]; then
      echo "FAIL: $RELEASE_DST cannot be read as a release number, so the release order cannot be checked." >&2
      echo "      If you mean to install this stick anyway, re-run with: $RERUN --allow-downgrade" >&2
      echo "      Nothing was installed." >&2
      exit 1
    fi
    echo "WARNING: $RELEASE_DST cannot be read as a release number; release order NOT checked (--allow-downgrade)"
  }
fi
# RELEASE holds the release_seq only, which defaults to a commit timestamp:
# a rebase can give two releases the same one, so an equal number orders
# nothing. It passes for the same release only: every trust tool on the stick
# byte-identical to the installed one (a re-run of the same stick, or another
# stick of that release). Tools that differ under the same number are another
# release, which may be the older one, and are refused like a downgrade.
same_trust_tools() {
  local tool
  for tool in bootstrap.sh verify_bundle.py profiles.py install_offline.sh lib/os_packages.sh; do
    cmp -s -- "$SRC/$tool" "$TRUST_DIR/$tool" || return 1
  done
}
if [ -z "$INSTALLED_RELEASE" ]; then
  echo "==> release order: stick release ${STICK_RELEASE:-none}, nothing recorded yet"
else
  RELEASE_ORDER="stick release ${STICK_RELEASE:-none}, installed release $INSTALLED_RELEASE"
  if [ -n "$STICK_RELEASE" ] && [ "$STICK_RELEASE" -gt "$INSTALLED_RELEASE" ]; then
    echo "==> release order: $RELEASE_ORDER (not a downgrade)"
  elif [ -n "$STICK_RELEASE" ] && [ "$STICK_RELEASE" -eq "$INSTALLED_RELEASE" ] && same_trust_tools; then
    echo "==> release order: $RELEASE_ORDER (the same release)"
  elif [ -n "$STICK_RELEASE" ] && [ "$STICK_RELEASE" -eq "$INSTALLED_RELEASE" ]; then
    if [ "$ALLOW_DOWNGRADE" -ne 1 ]; then
      echo "FAIL: this stick is release $STICK_RELEASE, the release whose trust tools are installed, but its tools differ" >&2
      echo "      from the installed ones: it is another release with the same number, which may be the older one." >&2
      echo "      If you mean to install this stick's tools, re-run with: $RERUN --allow-downgrade" >&2
      echo "      Nothing was installed." >&2
      exit 1
    fi
    echo "WARNING: another release with the installed release number allowed by --allow-downgrade: $RELEASE_ORDER"
  elif [ "$ALLOW_DOWNGRADE" -eq 1 ]; then
    echo "WARNING: DOWNGRADE allowed by --allow-downgrade: $RELEASE_ORDER"
  else
    if [ -n "$STICK_RELEASE" ]; then
      echo "FAIL: this stick is release $STICK_RELEASE, OLDER than release $INSTALLED_RELEASE whose trust tools are installed." >&2
    else
      echo "FAIL: this stick names no release, OLDER than release $INSTALLED_RELEASE whose trust tools are installed." >&2
    fi
    echo "      Its tools are genuinely signed, and they would put back what later releases fixed." >&2
    echo "      If the downgrade is intended, re-run with: $RERUN --allow-downgrade" >&2
    echo "      Nothing was installed." >&2
    exit 1
  fi
fi

# --- dpkg -i gets copies only root can change ---------------------------------
# dpkg -i reads a .deb again, and its preinst runs as root before anything
# else checks it (for this package, before the trusted verifier sees the
# payload): a stick that changes after the check above would hand it another
# package. So every package the signed list names (this one, and the
# runbook's thick-mode Oracle ones) is copied into a new directory only root
# can write, next to the one dpkg -i is pointed at. THOSE copies are checked
# against the private copy of the signed list, and only then does the new
# directory replace that one (and an earlier release's copies with it): a
# failure at any step, a cp error included, leaves no unchecked copy (the
# EXIT trap removes the new directory). They are what dpkg -i is told to
# install. cp copies as for the private copy above, and a copy that is not a
# regular file is refused before it is read.
DEB_DIR="$ROOT/var/cache/udbmcp-trust"
awk '$2 ~ /\.deb$/' "$STAGE/SHA256SUMS" > "$STAGE/debs"
mkdir -p "$(dirname "$DEB_DIR")"
DEB_NEW="$(mktemp -d "$DEB_DIR.new.XXXXXX")"
while read -r _ deb; do
  { mkdir -p "$DEB_NEW/$(dirname "$deb")" && cp -RP "$STICK/$deb" "$DEB_NEW/$deb"; } || {
    echo "FAIL: $deb could not be copied from the stick (see above); the stick changed after it" >&2
    echo "      was checked, or it cannot be read. Nothing was installed." >&2
    exit 1
  }
  [ -f "$DEB_NEW/$deb" ] && [ ! -L "$DEB_NEW/$deb" ] || \
    unlisted_fail "is not a regular file; a release stick holds regular files only." "$deb" \
      "The stick changed while it was read. Get the stick again from the release administrator."
done < "$STAGE/debs"
# (GNU sha256sum -c refuses an empty list: a stick without packages has none to check)
[ ! -s "$STAGE/debs" ] || ( cd "$DEB_NEW" && sha256sum -c --strict --quiet "$STAGE/debs" ) || {
  echo "FAIL: a package copied from the stick does not match its signed SHA256SUMS (see above):" >&2
  echo "      the stick changed after it was checked. Get the stick again from the release" >&2
  echo "      administrator. Nothing was installed." >&2
  exit 1
}
rm -rf -- "$DEB_DIR"
mv -- "$DEB_NEW" "$DEB_DIR"
DEB_NEW=""

install -d -m 755 "$TRUST_DIR" "$TRUST_DIR/lib" "$(dirname "$KEY_DST")"
# Renamed into place: the running script may be the installed copy, and bash
# reads it as it goes, so it must keep reading the file it started.
install -m 755 "$SRC/bootstrap.sh" "$TRUST_DIR/bootstrap.sh.new"
mv -f "$TRUST_DIR/bootstrap.sh.new" "$TRUST_DIR/bootstrap.sh"
install -m 644 "$SRC/verify_bundle.py" "$TRUST_DIR/"
install -m 644 "$SRC/profiles.py" "$TRUST_DIR/"
install -m 755 "$SRC/install_offline.sh" "$TRUST_DIR/"
install -m 644 "$SRC/lib/os_packages.sh" "$TRUST_DIR/lib/"
# the release whose tools the trust dir now holds (none: a stick that names none)
if [ -n "$STICK_RELEASE" ]; then
  printf '%s\n' "$STICK_RELEASE" > "$RELEASE_DST.new"
  mv -f "$RELEASE_DST.new" "$RELEASE_DST"
else
  rm -f -- "$RELEASE_DST"
fi
if [ -s "$KEY_DST" ] && [ "$(fingerprint "$KEY_DST")" = "$NEW_FP" ]; then
  echo "==> release public key unchanged (same fingerprint); left in place"
else
  install -m 644 "$SRC/release.pub.pem" "$KEY_DST"
  echo "==> release public key installed at $KEY_DST"
fi

echo "==> trust bootstrap complete:"
echo "    bootstrap: $TRUST_DIR/bootstrap.sh"
echo "    verifier : $TRUST_DIR/verify_bundle.py"
echo "    registry : $TRUST_DIR/profiles.py"
echo "    installer: $TRUST_DIR/install_offline.sh"
echo "    helper   : $TRUST_DIR/lib/os_packages.sh"
echo "    release  : ${STICK_RELEASE:-none named by this stick} ($RELEASE_DST)"
echo "    pubkey   : $KEY_DST (sha256 $NEW_FP)"
# Name the checked copy of the exact package the signed list covers: a .deb
# added to the stick later is not on the list and was never checked, and the
# one on the list may have changed since.
PACKAGE='^universal-db-mcp_[^/]*[.]deb$'  # no backslash: awk -v expands escapes
echo "==> now install the package on the stick's signed SHA256SUMS, from the copy checked above:"
awk -v dir="$DEB_DIR" -v p="$PACKAGE" '$2 ~ p { print "    sudo dpkg -i " dir "/" $2 }' "$STAGE/debs"
if awk -v p="$PACKAGE" '$2 !~ p { found = 1 } END { exit !found }' "$STAGE/debs"; then
  echo "==> the stick's other packages (the runbook's thick-mode Oracle step) were checked and copied too;"
  echo "    dpkg -i them from these copies, never from the stick:"
  awk -v dir="$DEB_DIR" -v p="$PACKAGE" '$2 !~ p { print "    " dir "/" $2 }' "$STAGE/debs"
fi
echo "==> on the next upgrade, check the new stick with the installed copy BEFORE running anything from it:"
echo "    sudo bash $TRUST_DIR/bootstrap.sh --stick <the next stick>"
