#!/usr/bin/env bash
# Container mode: verify the offline bundle (integrity + authenticity), then
# load its images locally. No registry access. An absent image file fails
# with the exact artifact name.
#
# This is a trusted tool, like install_offline.sh: it runs from the trust
# directory (installed from the trusted channel together with the verifier
# and the release public key), never from inside the bundle it loads. It
# verifies the bundle, copies it into a private root-owned staging directory,
# verifies THAT copy, and from then on reads only the copy: the image tars and
# manifest.json on the (possibly writable) bundle path are never opened again,
# so a tar swapped there after verification is never the one that is loaded.
#
# Anti-rollback: a container host installs nothing natively, so it has no
# installed manifest.json to compare a bundle with. This loader keeps a
# release record instead, $RELEASE_RECORD: the signed manifest of the last
# bundle whose images it loaded, written by root after a successful load. The
# verifier refuses a bundle that is an OLDER release than it, as it does for
# the .deb and the .pkg; an intended downgrade passes --allow-downgrade (or
# UDBMCP_ALLOW_DOWNGRADE=1). The record must be on persistent storage: a lost
# record reads as nothing loaded yet.
set -euo pipefail

ALLOW_DOWNGRADE=0
[ "${UDBMCP_ALLOW_DOWNGRADE:-}" != "1" ] || ALLOW_DOWNGRADE=1
positional=()
for arg in "$@"; do
  case "$arg" in
    --allow-downgrade) ALLOW_DOWNGRADE=1 ;;
    *) positional+=("$arg") ;;
  esac
done
set -- ${positional[@]+"${positional[@]}"}

BUNDLE="${1:?usage: load_images_offline.sh <bundle-dir> [--allow-downgrade]}"

# Fail closed: manifest.json and the image tars are untrusted until the
# trusted-path verifier (installed from a separate channel, never read from
# inside the bundle it verifies) has checked every artifact against the
# SIGNED SHA256SUMS and the SIGNATURE against the independently distributed
# public key. This covers images/universal-db-mcp.tar too — comparing a tar
# against a digest recorded in the unauthenticated manifest.json inside the
# same bundle would verify nothing.
TRUST="${UDBMCP_TRUST_DIR:-/usr/local/lib/udbmcp-trust}"
VERIFIER="$TRUST/verify_bundle.py"
PUBKEY="${UDBMCP_RELEASE_PUBKEY:?UDBMCP_RELEASE_PUBKEY must point at the release public key PEM obtained through your trusted channel}"
RELEASE_RECORD="${UDBMCP_RELEASE_RECORD:-/var/lib/universal-db-mcp/release.json}"
case "$RELEASE_RECORD" in
  /*) ;;
  *) echo "FAIL: UDBMCP_RELEASE_RECORD ($RELEASE_RECORD) must be an absolute path; no image was loaded." >&2
     exit 1 ;;
esac
RECORD_DIR="$(dirname "$RELEASE_RECORD")"

# --- trust boundary (the same refusals as install_offline.sh) ----------------
# A copy of this loader, of the verifier or of the key read from inside the
# bundle authenticates nothing: a tampered bundle ships its own.
self_path="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)/$(basename "${BASH_SOURCE[0]}")"
bundle_real="$(cd "$BUNDLE" && pwd -P)"
case "$self_path" in
  "$bundle_real"/*)
    echo "FAIL: refusing to run from inside the bundle being verified ($self_path)." >&2
    echo "      Install the trusted tools first (see docs/offline-deployment.md, 'Trust bootstrap'):" >&2
    echo "        sudo install -d -m 755 $TRUST" >&2
    echo "        sudo install -m 644 <trusted-channel>/verify_bundle.py <trusted-channel>/profiles.py $TRUST/" >&2
    echo "        sudo install -m 755 <trusted-channel>/load_images_offline.sh $TRUST/" >&2
    echo "      then run: sudo bash $TRUST/load_images_offline.sh <bundle-dir>" >&2
    exit 1 ;;
esac
if [ ! -s "$VERIFIER" ]; then
  echo "FAIL: trusted verifier not found (or empty) at $VERIFIER; install it from the trusted channel" >&2
  echo "      (set UDBMCP_TRUST_DIR if the trusted tools live elsewhere)." >&2
  exit 1
fi
verifier_real="$(cd "$(dirname "$VERIFIER")" && pwd -P)/$(basename "$VERIFIER")"
case "$verifier_real" in
  "$bundle_real"/*)
    echo "FAIL: UDBMCP_TRUST_DIR points inside the bundle; the verifier must come from the trusted channel." >&2
    exit 1 ;;
esac
pubkey_dir="$(cd "$(dirname "$PUBKEY")" 2>/dev/null && pwd -P)" || pubkey_dir=""
case "$pubkey_dir/$(basename "$PUBKEY")" in
  "$bundle_real"/*)
    echo "FAIL: UDBMCP_RELEASE_PUBKEY ($PUBKEY) is inside the bundle; refusing to verify with a pubkey shipped inside the bundle." >&2
    exit 1 ;;
esac

# --- privilege is decided once, from identity --------------------------------
# The staging copy is root-owned and mode 700, so copying, verifying, reading
# and loading it all run as root (directly or via sudo).
sudo_ok=""
if [ "$(id -u)" -ne 0 ]; then
  sudo_bin="$(command -v sudo 2>/dev/null || true)"
  if [ -z "$sudo_bin" ] || [ ! -x "$sudo_bin" ]; then
    echo "FAIL: run as root, or install sudo: the verified private copy of the bundle is root-owned." >&2
    exit 1
  fi
  sudo_ok="sudo"
fi

# >>> directories root alone can change: identical in install_offline.sh, upgrade_offline.sh and load_images_offline.sh
# What this script makes as root and uses later (the private copy of the
# bundle, root's temporary files) must sit where no other account can rename
# it away and put its own in its place: in a directory that, like every
# directory above it, is a real directory owned by root (the account the
# privileged steps run as) that group and others cannot write, or a
# root-owned sticky one such as /var/tmp, where nobody else can rename what
# root makes there.
PRIV_UID="$($sudo_ok id -u)"
real_dir() {
  # $1: a directory; prints its real path (no link on the way), nothing when it cannot be entered
  $sudo_ok sh -c 'cd -P -- "$1" 2>/dev/null && pwd -P' sh "$1" || true
}
not_roots_alone() {
  # $1: a real path; prints the first of it and the directories above it that is not root's
  # alone (nothing when every one is)
  local dir="$1"
  while :; do
    [ -n "$($sudo_ok find "$dir" -maxdepth 0 -type d \( -user 0 -o -user "$PRIV_UID" \) \
      \( -perm -1000 -o ! -perm -0020 ! -perm -0002 \) -print 2>/dev/null)" ] || { printf '%s' "$dir"; return 0; }
    [ "$dir" != / ] || return 0
    dir="$(dirname "$dir")"
  done
}
staging_base() {
  # $1: the staging base (UDBMCP_STAGING_DIR or /var/tmp), created as root when missing; $2: what
  # was not done when it is refused. Prints its real path, checked once it exists.
  local base untrusted
  # umask 022: what is created here is root's alone whatever the caller's umask
  $sudo_ok sh -c 'umask 022 && mkdir -p -- "$1"' sh "$1" 2>/dev/null || true
  base="$(real_dir "$1")"
  [ -n "$base" ] || { echo "FAIL: the staging directory $1 cannot be created or entered. $2" >&2; return 1; }
  untrusted="$(not_roots_alone "$base")"
  [ -z "$untrusted" ] || {
    echo "FAIL: the private copy of the bundle would be made in $base, and $untrusted is not root's alone" >&2
    echo "      (not a real directory owned by root, or group or others can write it and it is not" >&2
    echo "      sticky): another account could put its own copy in place of the verified one. Point" >&2
    echo "      UDBMCP_STAGING_DIR at a directory that, like every directory above it, root alone can" >&2
    echo "      write (the default /var/tmp is one). $2" >&2
    return 1
  }
  printf '%s\n' "$base"
}
# sudo -E and a plain su keep the caller's TMPDIR, where root's temporary
# files are made (bash's here-documents, python -m venv's copy of pip, pip's
# own, podman's copy of an image), and python's tempfile takes TEMP, then TMP,
# when TMPDIR is unset. Each is kept only when it is root's alone, and then as
# the real path that was checked: a link on the way could be re-pointed later.
# Otherwise it is unset; with none left, root's temporary files go to the
# system's own directory (/tmp).
for tmp_var in TMPDIR TEMP TMP; do
  tmp_real=""
  [ -z "${!tmp_var:-}" ] || tmp_real="$(real_dir "${!tmp_var}")"
  if [ -n "$tmp_real" ] && [ -z "$(not_roots_alone "$tmp_real")" ]; then
    export "$tmp_var=$tmp_real"
  else
    [ -z "${!tmp_var:-}" ] ||
      echo "NOTE: $tmp_var (${!tmp_var}) is not root's alone; root's temporary files are not made there"
    unset "$tmp_var"
  fi
done
private_copy() {
  # $1: the verified bundle; $2: the directory mktemp -d made for its copy; $3: what was not done
  # when the copy is refused. Copies the bundle to $2/bundle and prints that path.
  # The copy gets a name of its own inside $2, never $2 itself, and keeps neither the owners nor
  # the modes of the bundle: `cp -a BUNDLE/. $2/` gave $2 the bundle directory's mode (0777 on
  # world-writable media) and, as root, its owner once it was done, and every file its owner, so
  # whoever could write the bundle path could change the copy after it was verified. $2 stays
  # root's, mode 700, throughout, so nobody else reaches what cp makes below it before the chmod
  # (which also covers a cp that gives a directory the source's mode, unmasked).
  local copy="$2/bundle" found
  $sudo_ok chmod 700 "$2" && $sudo_ok cp -RP -- "$1"/. "$copy" && $sudo_ok chmod -R go-rwx "$copy" || {
    echo "FAIL: the private copy of the bundle could not be made in $2. $3" >&2
    return 1
  }
  # cp -P copies a link as a link, which would still lead where whoever can write the bundle path
  # decides: a bundle holds regular files and directories only (the verifier refuses anything
  # else as well).
  found="$($sudo_ok find "$2" ! -type f ! -type d -print)" && [ -z "$found" ] || {
    echo "FAIL: the private copy holds what is not a regular file or directory; a bundle holds regular files and directories only: $found" >&2
    echo "      $3" >&2
    return 1
  }
  # and what is there is root's alone
  found="$($sudo_ok find "$2" \( ! -user "$PRIV_UID" -o -perm -0020 -o -perm -0002 \) -print)" &&
    [ -z "$found" ] && [ -n "$($sudo_ok find "$2" -maxdepth 0 -perm 0700 -print)" ] || {
    echo "FAIL: the private copy is not root's alone (another account owns it, or group or others can write it): ${found:-$2}" >&2
    echo "      $3" >&2
    return 1
  }
  printf '%s\n' "$copy"
}
# <<< directories root alone can change

# --- the release record counts only where root alone can change it -----------
# Whoever can lower or delete it could load an older release's images without
# a word. Its directory must be a real directory owned by root that neither
# group nor others can write, and the record a root-owned regular file that
# neither can write. The record may be absent (nothing loaded yet); the
# first successful load writes it. What is missing of its directory is
# created below, before anything is verified or loaded.
record_untrusted() {
  # $1: path, $2: its find type (d or f); prints $1 when it is not root's alone
  $sudo_ok test -e "$1" || $sudo_ok test -L "$1" || return 0
  [ -n "$($sudo_ok find "$1" -maxdepth 0 -type "$2" -user 0 ! -perm -0020 ! -perm -0002 -print 2>/dev/null)" ] \
    || printf '%s' "$1"
}
# Every directory above it as well, up to /: renaming the record's directory
# away needs write on its parent only, and an absent record reads as nothing
# loaded yet. Each must be a real directory (not a link) owned by root that
# group and others cannot write, or a sticky one such as /tmp, where nobody
# else can rename what root owns.
above_record_untrusted() {
  # prints the first directory above the record's that is not root's alone
  local dir="$RECORD_DIR"
  while [ "$dir" != / ]; do
    dir="$(dirname "$dir")"
    $sudo_ok test -e "$dir" || $sudo_ok test -L "$dir" || continue
    [ -n "$($sudo_ok find "$dir" -maxdepth 0 -type d -user 0 \( -perm -1000 -o ! -perm -0020 ! -perm -0002 \) \
      -print 2>/dev/null)" ] || { printf '%s' "$dir"; return 0; }
  done
}
check_record() {
  # $1: what was (not) done when the record is not root's alone
  local untrusted
  for untrusted in "$(above_record_untrusted)" "$(record_untrusted "$RECORD_DIR" d)" \
      "$(record_untrusted "$RELEASE_RECORD" f)"; do
    [ -z "$untrusted" ] || refuse_record "$untrusted" "$1"
  done
}
refuse_record() {
  # $1: the path that is not root's alone, $2: what was (not) done
  echo "FAIL: the release record $RELEASE_RECORD orders the releases this host loads, and" >&2
  echo "      $1 is not root's alone (not a plain directory or file owned by root, or group" >&2
  echo "      or others can write it)." >&2
  # On a host that also runs the native package, /var/lib/universal-db-mcp
  # is the service's state directory, and every native install hands it
  # back to udbmcp: taking it from the service is no fix.
  if [ -n "$($sudo_ok find "$1" -maxdepth 0 -user udbmcp -print 2>/dev/null)" ]; then
    echo "      It belongs to the udbmcp service account (a native install on this host keeps its state" >&2
    echo "      there): leave its owner as it is and point UDBMCP_RELEASE_RECORD at a record whose" >&2
    echo "      directory, and every directory above it, root alone can write" >&2
    echo "      (e.g. UDBMCP_RELEASE_RECORD=/var/lib/udbmcp-images/release.json). $2" >&2
  else
    echo "      Make it root's alone (sudo chown root $1; sudo chmod go-w $1)," >&2
    echo "      or point UDBMCP_RELEASE_RECORD at a record whose directory, and every directory above it," >&2
    echo "      root alone can write. $2" >&2
  fi
  exit 1
}
check_record "No image was loaded."

# What is missing of the record's directory is created now, as root, before
# anything is verified or loaded, and everything is checked again once it
# exists. Created after the load (minutes later), a directory below a sticky
# one such as /tmp could be another account's first: root's record would then
# sit where that account can delete it, and an older release would load as a
# first load. One another account makes before root does fails the check;
# one root made cannot be renamed or removed by anyone else, below a
# directory root alone can write or a root-owned sticky one. Each is created
# on its own (not mkdir -p: that follows a link another account puts on the
# way) and checked before the next one is made below it.
missing=()
dir="$RECORD_DIR"
until $sudo_ok test -e "$dir" || $sudo_ok test -L "$dir"; do
  missing=("$dir" ${missing[@]+"${missing[@]}"})
  dir="$(dirname "$dir")"
done
for dir in ${missing[@]+"${missing[@]}"}; do
  $sudo_ok mkdir -m 755 "$dir" 2>/dev/null || true
  untrusted="$(record_untrusted "$dir" d)"
  $sudo_ok test -d "$dir" && [ -z "$untrusted" ] || refuse_record "$dir" "No image was loaded."
done
check_record "No image was loaded."
# A world-writable directory above it (/tmp, /var/tmp) is emptied at boot when
# it is a tmpfs and aged out by systemd-tmpfiles, and a lost record lets an
# older release load as a first load, with no attacker at all.
dir="$RECORD_DIR"
while [ "$dir" != / ]; do
  dir="$(dirname "$dir")"
  if [ -n "$($sudo_ok find "$dir" -maxdepth 0 -perm -0002 -print 2>/dev/null)" ]; then
    echo "WARNING: the release record $RELEASE_RECORD is below $dir, a directory every account can write"
    echo "         such as /tmp or /var/tmp, which boot or systemd-tmpfiles may empty: a lost record lets an"
    echo "         older release load again. Keep it on persistent storage, in a directory root alone can"
    echo "         write (e.g. UDBMCP_RELEASE_RECORD=/var/lib/udbmcp-images/release.json)."
    break
  fi
done

# Exit code alone is not proof of verification (python3 on an empty or no-op
# verifier exits 0): success requires exit 0 AND the literal
# 'bundle verification PASSED' AND no 'FAIL:' line, as in install_offline.sh.
# Every python here runs with -I -S: as root it must not read PYTHON* variables,
# the user site, the working directory (the verifier adds its own directory
# to sys.path for profiles.py) or the .pth files in the interpreter's
# site-packages, which can name code outside it; it needs only the stdlib.
# Both runs also check the release order against the release record.
ROLLBACK_ARGS=(--installed-manifest "$RELEASE_RECORD")
[ "$ALLOW_DOWNGRADE" -eq 0 ] || ROLLBACK_ARGS+=(--allow-downgrade)
verify_with_proof() {
  # $1: the bundle directory to verify. The output is kept in the shell, never
  # in a file: root would open one by name, through whatever link another
  # account put in its place.
  local vout vrc=0
  vout="$($sudo_ok python3 -I -S "$VERIFIER" --bundle "$1" --pubkey "$PUBKEY" "${ROLLBACK_ARGS[@]}" 2>&1)" || vrc=$?
  printf '%s\n' "$vout"
  if [ "$vrc" -ne 0 ] && [[ $'\n'"$vout" == *$'\n''FAIL: rollback '* ]]; then
    echo "FAIL: this bundle is an OLDER release than the one whose images this host last loaded (release record $RELEASE_RECORD), or that record is unreadable (see above); no image was loaded. To load it anyway, re-run with --allow-downgrade (or UDBMCP_ALLOW_DOWNGRADE=1)." >&2
    exit 1
  fi
  if [ "$vrc" -ne 0 ] && [[ "$vout" == *'unrecognized arguments: --installed-manifest'* ]]; then
    echo "FAIL: the trusted verifier at $VERIFIER is an OUTDATED copy (no --installed-manifest option): it cannot refuse an older release. Install verify_bundle.py and profiles.py from this release's trusted channel into $TRUST, then re-run; no image was loaded." >&2
    exit 1
  fi
  if [ "$vrc" -ne 0 ] || [[ $'\n'"$vout" == *$'\n'FAIL:* ]] || [[ "$vout" != *'bundle verification PASSED'* ]]; then
    echo "FAIL: the trusted verifier did not certify $1 (exit $vrc); no image was loaded." >&2
    exit 1
  fi
}

echo "==> verifying bundle before any image is loaded"
verify_with_proof "$BUNDLE"

# --- verify-then-use: load ONLY a private root-owned staging copy -------------
# The staging base is root's alone (above); mktemp -d makes the private directory the copy is
# made in (private_copy, above).
STAGING_BASE="$(staging_base "${UDBMCP_STAGING_DIR:-/var/tmp}" "No image was loaded.")" || exit 1
STAGING_DIR="$($sudo_ok mktemp -d "$STAGING_BASE/udbmcp-images.XXXXXX")"
cleanup_staging() { ${sudo_ok:+sudo }rm -rf -- "$STAGING_DIR" 2>/dev/null || true; }
trap cleanup_staging EXIT
echo "==> staging a private copy of the verified bundle (closes the verify-then-load race)"
STAGING="$(private_copy "$BUNDLE" "$STAGING_DIR" "No image was loaded.")" || exit 1
verify_with_proof "$STAGING"

load_one() {
  local tar="$1" expect="$2"
  if ! $sudo_ok test -f "$tar"; then
    echo "FAIL: required image archive '$(basename "$tar")' is missing from the bundle" >&2
    exit 1
  fi
  echo "==> loading $(basename "$tar")"
  $sudo_ok docker load -i "$tar"
  if [ -n "$expect" ]; then
    $sudo_ok docker image inspect "$expect" > /dev/null 2>&1 || {
      echo "FAIL: image '$expect' not present after load (identity mismatch)" >&2
      exit 1
    }
    echo "    identity verified: $expect"
  fi
}

APP_REF=$($sudo_ok cat "$STAGING/manifest.json" | python3 -I -S -c '
import json, sys
m = json.load(sys.stdin)
ident = m.get("image_identity") or {}
print(ident.get("application_image", "udbmcp/universal-db-mcp:0.1.0-linux-x86_64-ubuntu24.04-cp312"))
')

load_one "$STAGING/images/udbmcp-baseline-ubuntu24.04-cp312.tar" "udbmcp-baseline:ubuntu24.04-cp312"
if $sudo_ok test -f "$STAGING/images/universal-db-mcp.tar"; then
  load_one "$STAGING/images/universal-db-mcp.tar" "$APP_REF"
else
  echo "NOTE: application image not in bundle (native mode deployment); baseline loaded."
fi

# Every image loaded: the verified copy's manifest becomes the release record
# (renamed into place, so a reader never sees half of it), in the directory
# created and checked before the load, which is checked once more first.
check_record "The images are loaded, but the record was not written."
$sudo_ok install -m 644 "$STAGING/manifest.json" "$RELEASE_RECORD.new"
$sudo_ok mv -f "$RELEASE_RECORD.new" "$RELEASE_RECORD"
RECORDED_SEQ=$($sudo_ok cat "$RELEASE_RECORD" | python3 -I -S -c '
import json, sys
seq = json.load(sys.stdin).get("release_seq")
print(seq if isinstance(seq, int) and not isinstance(seq, bool) and seq >= 0
      else "none (the bundle predates release_seq)")
')
echo "==> release record $RELEASE_RECORD: release_seq $RECORDED_SEQ (an older bundle is refused from now on)"
echo "==> images ready (pull_policy: never in compose.offline.yaml)"
