#!/usr/bin/env bash
# udbmcp-installer-format: 4
# (the marker above is checked by the package's preinst/postinst: a trusted
# copy of this installer that lacks the current format number predates a
# change the package relies on and is refused; refresh it from the stick)
# Stage B, step 2: install the verified bundle inside the air gap.
# Network-independent: pip runs with --no-index against the bundle wheelhouse
# only, with a hostile inherited environment neutralized (PIP_CONFIG_FILE,
# proxies, index URLs are all overridden). OS packages ship in os-packages/
# and are installed with dpkg ONLY — apt is never invoked, so nothing here
# can reach a network or a vendor repository.
#
# This is a privileged operation: the service account, the state/log
# directories, dpkg and the root-owned install tree all require root, so the
# installer runs as root (directly or via sudo). It never chowns the
# application tree to the invoking operator.
#
# Anti-rollback: a bundle that is an OLDER release than the installed one
# ($TARGET/manifest.json) is refused by the verifier. An intended rollback
# passes --allow-downgrade (or UDBMCP_ALLOW_DOWNGRADE=1, which also reaches
# this script from the .deb's postinst).
set -euo pipefail
# Every python this script starts runs as root. -I keeps an interpreter from
# reading PYTHON* variables, but not the ensurepip child `-m venv` starts
# (venv runs the new interpreter without -I), and a PYTHONPYCACHEPREFIX would
# have root write, then read, bytecode wherever it names: the caller's are
# dropped here, before any python runs.
for _var in $(compgen -e); do case "$_var" in PYTHON*) unset "$_var" ;; esac; done

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

BUNDLE="${1:?usage: install_offline.sh <bundle-dir> [target-dir] [--allow-downgrade]}"
TARGET="${2:-/opt/universal-db-mcp}"
ORIG_BUNDLE="$BUNDLE"  # reported at the end; $BUNDLE is redirected to staging

echo "==> verifying bundle first (authenticity REQUIRED)"
PUBKEY="${UDBMCP_RELEASE_PUBKEY:-}"
if [ -z "$PUBKEY" ]; then
  echo "FAIL: set UDBMCP_RELEASE_PUBKEY to the release public key PEM path;" >&2
  echo "       an unsigned/unverified bundle must never be installed." >&2
  exit 1
fi

# --- trust boundary ---------------------------------------------------------
# The verifier must NOT come from the bundle it verifies: a tampered bundle
# would simply ship a verifier that prints PASSED. Both the verifier and this
# installer are distributed on the same trusted channel as the release public
# key and installed at a root-owned path; a copy inside the bundle is a
# reference copy only and is never executed by these scripts.
TRUST_DIR="${UDBMCP_TRUST_DIR:-/usr/local/lib/udbmcp-trust}"
VERIFIER="${UDBMCP_VERIFIER:-$TRUST_DIR/verify_bundle.py}"
self_path="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)/$(basename "${BASH_SOURCE[0]}")"
bundle_real="$(cd "$BUNDLE" && pwd -P)"
case "$self_path" in
  "$bundle_real"/*)
    echo "FAIL: refusing to run from inside the bundle being verified ($self_path)." >&2
    echo "      Install the trusted tools first (see docs/offline-deployment.md, 'Trust bootstrap'):" >&2
    echo "        sudo install -d -m 755 $TRUST_DIR" >&2
    echo "        sudo install -m 644 <trusted-channel>/verify_bundle.py $TRUST_DIR/" >&2
    echo "        sudo install -m 755 <trusted-channel>/install_offline.sh $TRUST_DIR/" >&2
    echo "      then run: sudo bash $TRUST_DIR/install_offline.sh <bundle-dir>" >&2
    exit 1 ;;
esac
if [ ! -f "$VERIFIER" ]; then
  echo "FAIL: trusted verifier not found at $VERIFIER (set UDBMCP_VERIFIER or install the trusted tools)." >&2
  exit 1
fi
# A zero-length verifier is not a verifier: python3 on an empty script exits 0
# without ever running argparse, so a truncated trusted-channel copy would
# 'verify' vacuously and the unverified bundle would be installed. The .pkg
# preinstall ([ ! -s ]) and the deb preinst/postinst guard this same case;
# fail closed here too.
if [ ! -s "$VERIFIER" ]; then
  echo "FAIL: trusted verifier at $VERIFIER is empty; refusing to proceed." >&2
  echo "      python3 on an empty script exits 0 without verifying anything, so" >&2
  echo "      a truncated trusted-channel copy must abort the install. Re-install" >&2
  echo "      the real verifier from the trusted channel:" >&2
  echo "        sudo install -m 644 <trusted-channel>/verify_bundle.py $TRUST_DIR/" >&2
  exit 1
fi
verifier_real="$(cd "$(dirname "$VERIFIER")" && pwd -P)/$(basename "$VERIFIER")"
case "$verifier_real" in
  "$bundle_real"/*)
    echo "FAIL: UDBMCP_VERIFIER points inside the bundle; the verifier must come from the trusted channel." >&2
    exit 1 ;;
esac
# Same rule for the release public key: a tampered bundle ships its own key
# (and a re-signed SHA256SUMS/SIGNATURE), so a key read from inside the bundle
# authenticates nothing — verification would PASSED against attacker material.
# Like the verifier, the key is distributed out-of-band on the trusted channel.
# The RESOLVED FILE PATH is compared (not just its directory): a key sitting
# directly in the bundle root has dirname == $bundle_real, which would slip
# past a "$bundle_real"/* match on the directory alone.
pubkey_dir="$(cd "$(dirname "$PUBKEY")" 2>/dev/null && pwd -P)" || pubkey_dir=""
case "$pubkey_dir/$(basename "$PUBKEY")" in
  "$bundle_real"/*)
    echo "FAIL: UDBMCP_RELEASE_PUBKEY ($PUBKEY) is inside the bundle; refusing to verify with a pubkey shipped inside the bundle." >&2
    echo "      Install the key outside the bundle from the trusted channel" >&2
    echo "      (e.g. sudo install -m 644 <trusted-channel>/release.pub.pem $TRUST_DIR/)." >&2
    exit 1 ;;
esac
LIB_DIR="$(dirname "$self_path")/lib"
if [ ! -r "$LIB_DIR/os_packages.sh" ]; then
  echo "FAIL: shared OS-package helper not found at $LIB_DIR/os_packages.sh;" >&2
  echo "      install it alongside this script on the trusted channel." >&2
  exit 1
fi
# shellcheck source=lib/os_packages.sh
source "$LIB_DIR/os_packages.sh"

# --- leave the operator's working directory ----------------------------------
# `python -m` and `python -c` put the working directory first on sys.path, and
# the pythons below run as root: a pip.py or venv/ lying where the operator
# stands (often the stick or the unpacked bundle) would be imported as root.
# The path inputs are made absolute first; everything after this runs from /.
abs_path() { case "$1" in /*) printf '%s\n' "$1" ;; *) printf '%s/%s\n' "$PWD" "$1" ;; esac; }
BUNDLE="$(abs_path "$BUNDLE")"
TARGET="$(abs_path "$TARGET")"
PUBKEY="$(abs_path "$PUBKEY")"
VERIFIER="$(abs_path "$VERIFIER")"
[ -z "${UDBMCP_STAGING_DIR:-}" ] || UDBMCP_STAGING_DIR="$(abs_path "$UDBMCP_STAGING_DIR")"
cd /

# How to run the trusted verifier. On the documented channel it is installed
# with `install -m 644` (a Python file), so it is executed via python3; a
# non-Python executable verifier (e.g. a compiled helper or /bin/sh script) is
# exec'd directly. A Python file that happens to carry an exec bit still goes
# through python3: on some staging hosts (macOS Docker Desktop bind mounts)
# the directory presents the exec bit but is mounted noexec, so exec'ing the
# file directly fails with rc=126 'bad interpreter' AFTER [ -x ] succeeded.
# Either way it comes from the trusted path validated above — never from the
# bundle. -I keeps the verifier (run as root) from reading PYTHON* variables,
# the user site or the working directory; it puts its own directory on
# sys.path for profiles.py. -S keeps it from reading the interpreter's
# site-packages, whose .pth files can put any directory on sys.path or run
# code (an admin's `sudo pip install -e` writes one pointing into a home
# directory); the verifier needs only the standard library. Every python this
# script runs as root outside a venv does the same. $VEXEC is deliberately
# unquoted at the call sites (it is either empty, or "python3 -I -S") so the
# same expression works under the $sudo_ok prefix.
VEXEC=""
if [ -x "$VERIFIER" ]; then
  case "$(head -n 1 "$VERIFIER" 2>/dev/null)" in
    *"python"*) VEXEC="python3 -I -S" ;;
    *) VEXEC="" ;;
  esac
else
  VEXEC="python3 -I -S"
fi

# --- privilege is decided ONCE, from identity, never from a path ------------
# groupadd/useradd, the service state directories and dpkg all require root
# regardless of where the venv goes; deriving this from the writability of
# the target's parent used to skip those steps silently on non-root runs.
# Decided up front so every privileged step below (including staging and
# re-verification) shares one decision and an unusable sudo fails loudly
# before any bundle work starts.
sudo_ok=""
if [ "$(id -u)" -ne 0 ]; then
  # `command -v` reports a PATH match even when the file is not executable,
  # so the probe must check executability explicitly — a non-executable sudo
  # (or none at all) must fail loudly here instead of dying mid-install.
  sudo_bin="$(command -v sudo 2>/dev/null || true)"
  if [ -z "$sudo_bin" ] || [ ! -x "$sudo_bin" ]; then
    echo "FAIL: run as root, or install sudo: the installer needs privileged" >&2
    echo "      steps (service account, state dirs, dpkg) no matter where the venv goes." >&2
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

# --- verifier PROOF gate -----------------------------------------------------
# Exit code alone is not proof of verification: python3 on an empty, truncated
# or no-op verifier exits 0 vacuously, and a verifier that exits 0 without
# certifying proves nothing. Success requires exit 0 AND the verifier's
# literal 'bundle verification PASSED' AND no 'FAIL:' diagnostic — the same
# rule packaging/msi/custom/verify.ps1 enforces. Output is echoed through so
# the admin sees the canonical diagnostics either way. Both runs also check
# the release order against the installed manifest (anti-rollback).
ROLLBACK_ARGS=(--installed-manifest "$TARGET/manifest.json")
[ "$ALLOW_DOWNGRADE" -eq 0 ] || ROLLBACK_ARGS+=(--allow-downgrade)
verify_with_proof() {
  # $1: the bundle directory to verify. The output is kept in the shell, never
  # in a file: root would open one by name, through whatever link another
  # account put in its place.
  local vout vrc=0
  vout="$($sudo_ok $VEXEC "$VERIFIER" --bundle "$1" --pubkey "$PUBKEY" "${ROLLBACK_ARGS[@]}" 2>&1)" || vrc=$?
  printf '%s\n' "$vout"
  if [ "$vrc" -ne 0 ]; then
    echo "FAIL: trusted verifier exited $vrc; the bundle is untrusted: installation ABORTED." >&2
    exit 1
  fi
  if [[ $'\n'"$vout" == *$'\n'FAIL:* ]] || [[ "$vout" != *'bundle verification PASSED'* ]]; then
    echo "FAIL: trusted verifier exited 0 but did not print 'bundle verification PASSED' (or printed a FAIL line); without explicit proof of verification the bundle is treated as untrusted: installation ABORTED." >&2
    exit 1
  fi
}

verify_with_proof "$BUNDLE"

# --- verify-then-use: consume ONLY a private root-owned staging copy --------
# Verification hashed the tree once, but the bundle is then read for tens of
# seconds (pip, dpkg -i, the manifest) in a different — privileged — context.
# Anyone who can write to the bundle path during that window (bundle unpacked
# in an operator's $HOME, world-writable removable media) can swap a verified
# .deb or lock after verification and before use, and `dpkg -i` would run the
# attacker's maintainer scripts as root. Copy the verified bundle into a
# root-owned, mode-700 staging directory, re-verify THE COPY in the same
# privileged context that will consume it, and never touch the original again.
# The staging base is root's alone (above); mktemp -d makes the private directory the copy is
# made in (private_copy, above).
STAGING_BASE="$(staging_base "${UDBMCP_STAGING_DIR:-/var/tmp}" "Installation ABORTED.")" || exit 1
STAGING_DIR="$($sudo_ok mktemp -d "$STAGING_BASE/udbmcp-install.XXXXXX")"
cleanup_staging() { ${sudo_ok:+sudo }rm -rf -- "$STAGING_DIR" 2>/dev/null || true; }
# An install killed between the two renames of the venv switch (the only
# window with no venv in place) is recovered here: the demoted venv comes
# back so the service can start again without manual help.
restore_previous_venv_on_interrupt() {
  if [ -n "${TARGET:-}" ] && [ -d "$TARGET/venv.previous" ] && [ ! -d "$TARGET/venv" ]; then
    echo "==> install interrupted mid-switch; restoring $TARGET/venv.previous" >&2
    $sudo_ok mv "$TARGET/venv.previous" "$TARGET/venv"
  fi
}
on_exit() { restore_previous_venv_on_interrupt; cleanup_staging; }
trap on_exit EXIT
echo "==> staging a private copy of the verified bundle (closes the verify-then-use race)"
STAGING="$(private_copy "$BUNDLE" "$STAGING_DIR" "Installation ABORTED.")" || exit 1
verify_with_proof "$STAGING"
BUNDLE="$STAGING"

echo "==> checking platform baseline"
PY=python3.12
command -v "$PY" >/dev/null 2>&1 || PY=python3
PY="$(command -v "$PY")"
"$PY" -I -S -c 'import sys; assert sys.version_info[:2] == (3, 12), f"CPython 3.12.x required, got {sys.version}"'
"$PY" -I -S -c 'import ensurepip, venv' || { echo "FAIL: venv/ensurepip not available"; exit 1; }

echo "==> preflight: storage + service account"
AVAIL_KB=$(df -Pk "$(dirname "$TARGET")" | awk 'NR==2 {print $4}')
if [ "${AVAIL_KB:-0}" -lt 524288 ]; then
  echo "FAIL: less than 512 MiB free on $(dirname "$TARGET") (need ~512 MiB for the venv)" >&2
  exit 1
fi
if ! id udbmcp >/dev/null 2>&1; then
  $sudo_ok groupadd -r udbmcp 2>/dev/null || $sudo_ok groupadd udbmcp || true
  $sudo_ok useradd -r -g udbmcp -s /usr/sbin/nologin -M udbmcp 2>/dev/null || $sudo_ok useradd -r -g udbmcp udbmcp || true
  # fail loudly: the systemd unit runs as udbmcp; a silent skip here used to
  # surface much later as an unrelated dpkg error or a service that cannot start
  id udbmcp >/dev/null 2>&1 || {
    echo "FAIL: could not create the udbmcp service account (groupadd/useradd)." >&2
    echo "      Create it manually and re-run: the service runs as this user." >&2
    exit 1
  }
fi
$sudo_ok install -d -o udbmcp -g udbmcp /var/lib/universal-db-mcp /var/log/universal-db-mcp || {
  echo "FAIL: could not create /var/lib/universal-db-mcp and /var/log/universal-db-mcp" >&2
  echo "      (the service's state and log directories)." >&2
  exit 1
}
# An older release's root site check (sudo udbmcp site-check or doctor) could
# leave the audit log, its .lock sidecar or a rotated backup in the log
# directory owned by root. This release no longer repairs them at run time, so
# under audit_fail_closed the service would refuse every audited call: hand
# them back, as the .deb and the .pkg do on upgrade. udbmcp owns the
# directory, so each entry is opened without following links and checked on
# the open descriptor (a regular file, one link, owned by root) before
# fchown: a symlink, or a name that is a second link to another file, is left
# alone. Best effort: a failure warns and never aborts the install.
LOG_DIR=/var/log/universal-db-mcp
# >>> hand root-owned audit files back: identical in the deb postinst, the pkg postinstall, install_offline.sh and upgrade_offline.sh
$sudo_ok "$PY" -I -S - "$LOG_DIR" udbmcp <<'PYEOF' || echo "WARNING: could not hand root-owned audit files in $LOG_DIR back to the service account" >&2
import os
import pwd
import stat
import sys

ROOT = 0
log_dir, account = sys.argv[1], sys.argv[2]
owner = pwd.getpwnam(account)
try:
    # Logs moved to another volume and linked back: the link is followed only
    # when root owns it and the directory it is in, so no other account made or
    # can re-point it. Where it leads is opened like the name itself.
    if os.path.islink(log_dir):
        if os.lstat(log_dir).st_uid != ROOT or os.stat(os.path.dirname(os.path.abspath(log_dir))).st_uid != ROOT:
            sys.exit(f"{log_dir}: a symlink another account could have made or re-pointed")
        log_dir = os.path.realpath(log_dir)
    dir_fd = os.open(log_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
except OSError as exc:
    sys.exit(f"{log_dir}: {exc.strerror}")
try:
    for name in sorted(os.listdir(dir_fd)):
        if not name.startswith("audit.jsonl"):
            continue
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
        except OSError:
            continue  # a symlink, or gone
        try:
            st = os.fstat(fd)
            if stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_uid == ROOT:
                os.fchmod(fd, 0o600)  # the audit writer's own mode: it opens the file read-write
                os.fchown(fd, owner.pw_uid, owner.pw_gid)
                print(f"==> {log_dir}/{name} was owned by root; handed back to {account}")
        finally:
            os.close(fd)
except OSError as exc:
    sys.exit(f"{log_dir}: {exc.strerror}")
finally:
    os.close(dir_fd)
PYEOF
# <<< hand root-owned audit files back

if [ ! -d "$TARGET" ]; then
  # root-owned 755: the venv is code that root-run tools and the service
  # execute; it must never be owned (or writable) by the invoking operator.
  $sudo_ok install -d -m 755 -o root -g root "$TARGET"
fi
# Build-then-switch. A first install builds $TARGET/venv directly. An
# UPGRADE (a venv already exists) builds the new venv BESIDE it and switches
# with two renames, keeping the running release as venv.previous with its
# integrity manifest: exactly the layout rollback_offline.sh restores. The
# live venv is never modified in place, so an install that dies mid-pip
# leaves the current release untouched, and a stdio client that spawns the
# venv during the upgrade keeps a consistent tree until the switch.
if [ -d "$TARGET/venv" ]; then
  # re-run hygiene: an earlier attempt that died between venv creation and
  # the switch leaves a venv.new-* tree behind (hundreds of MB); discard it
  $sudo_ok rm -rf "$TARGET"/venv.new-* 2>/dev/null || true
  VENV_BUILD="$TARGET/venv.new-$(date -u +%Y%m%dT%H%M%SZ)"
  echo "==> existing installation found: building the new venv at $VENV_BUILD, switching after the smoke check"
else
  VENV_BUILD="$TARGET/venv"
  echo "==> creating virtual environment at $VENV_BUILD"
fi
# --copies: the interpreter is copied INTO the tree instead of symlinked to
# the base install, so the rollback integrity manifest covers the binary the
# service executes and rollback_offline.sh's symlink-containment gate holds
# (a standard venv's bin/python -> /usr/.../python3.12 points outside the
# tree and was refused by that gate, seen in the deb upgrade gate 2026-09-18).
$sudo_ok "$PY" -I -S -m venv --copies "$VENV_BUILD"

echo "==> installing application from bundle wheelhouse (no index, hashed)"
# --force-reinstall stays MANDATORY (mirrors packaging/pkg/postinstall): the
# app wheel's version string does not change between code-only releases
# (0.1.0 -> 0.1.0), and before the build-then-switch above this installer
# re-ran pip over the EXISTING venv, where "already satisfied" kept the
# previous release's code while dpkg reported a successful upgrade (seen
# live 2026-09-15). The switch makes that impossible; the flag remains as
# defence in depth and as the marker packaging/deb/preinst uses to refuse an
# outdated copy of this installer. Every package is still resolved only from
# the verified wheelhouse and checked against runtime.lock's hashes.
$sudo_ok env \
  PIP_CONFIG_FILE=/dev/null \
  PIP_DISABLE_PIP_VERSION_CHECK=1 \
  PIP_NO_INDEX=1 \
  PIP_FIND_LINKS="$BUNDLE/wheelhouse" \
  "$VENV_BUILD/bin/python" -I -m pip --isolated --disable-pip-version-check install \
  --no-index \
  --no-cache-dir \
  --find-links="$BUNDLE/wheelhouse" \
  --only-binary=:all: \
  --require-hashes \
  --force-reinstall \
  -r "$BUNDLE/requirements/runtime.lock"

# --- OS packages (ODBC driver closure): dpkg only, no apt, no network -------
# Shared, version-aware and idempotent; see lib/os_packages.sh.
udbmcp_install_os_packages "$BUNDLE" "$PY" "$sudo_ok"

echo "==> smoke check"
$sudo_ok "$VENV_BUILD/bin/python" -I -m universal_db_mcp version

# Venv mode normalization: the venv is CODE the service account executes, but
# the creating context's umask leaks into it (seen live 2026-09-15: a umask
# 077 install left the venv 0700 root:root and the udbmcp service died with
# 203/EXEC Permission denied - the interpreter was fine, the SERVICE ACCOUNT
# just could not traverse into the tree). Normalize unconditionally: dirs
# 0755 (traversable), files 0644, bin executables 0755. The tree itself is
# root-owned either way - this grants read+traverse, never write.
$sudo_ok find "$VENV_BUILD" -type d -exec chmod 755 {} +
$sudo_ok find "$VENV_BUILD" -type f -exec chmod 644 {} +
$sudo_ok find "$VENV_BUILD/bin" -type f -exec chmod 755 {} +

if [ "$VENV_BUILD" != "$TARGET/venv" ]; then
  echo "==> switching (the running release is kept as $TARGET/venv.previous for rollback_offline.sh; depth 1)"
  $sudo_ok rm -rf "$TARGET/venv.previous"          # rollback depth is one release
  $sudo_ok rm -f "$TARGET/venv.previous.sha256"     # manifest of the discarded release
  $sudo_ok rm -f "$TARGET/venv.previous.manifest.json"  # and its release record
  # rollback_offline.sh executes the demoted venv only after it matches this
  # manifest, so record it BEFORE the rename (same recipe as upgrade_offline.sh:
  # relative paths, regular files only, sorted, sha256sum).
  $sudo_ok sh -c 'cd "$1/venv" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > "$1/venv.previous.sha256"' sh "$TARGET" \
    || { $sudo_ok rm -f "$TARGET/venv.previous.sha256"; $sudo_ok rm -rf "$VENV_BUILD"
         echo "FAIL: could not record the rollback integrity manifest; the running venv was left untouched" >&2; exit 1; }
  # The running release's record goes with its venv: after rolling back to it,
  # rollback_offline.sh raises $TARGET/manifest.json to it when it names an
  # older release (after an intended downgrade), so anti-rollback never
  # compares with a release below the one that runs.
  if $sudo_ok test -f "$TARGET/manifest.json"; then
    $sudo_ok install -m 644 -o root -g root "$TARGET/manifest.json" "$TARGET/venv.previous.manifest.json" \
      || echo "WARNING: could not keep the running release's record for rollback_offline.sh" >&2
  fi
  $sudo_ok mv "$TARGET/venv" "$TARGET/venv.previous"
  $sudo_ok mv "$VENV_BUILD" "$TARGET/venv"
  echo "==> switched: $TARGET/venv is the new release, $TARGET/venv.previous the one before"
fi

# Short CLI alias on PATH: pip's [project.scripts] entry point lands at
# $TARGET/venv/bin/udbmcp; link it into /usr/local/bin so `udbmcp doctor`
# etc. work without the venv path. Guarded: an existing udbmcp that is NOT
# our symlink (an admin's own wrapper) is never clobbered.
echo "==> linking udbmcp CLI alias into /usr/local/bin"
$sudo_ok mkdir -p /usr/local/bin
ALIAS="/usr/local/bin/udbmcp"
if $sudo_ok test -e "$ALIAS" && [ "$($sudo_ok readlink "$ALIAS" 2>/dev/null)" != "$TARGET/venv/bin/udbmcp" ]; then
  echo "    WARNING: $ALIAS already exists and is not our symlink; left untouched." >&2
  echo "         The CLI stays available at $TARGET/venv/bin/udbmcp." >&2
elif ! $sudo_ok ln -sfn "$TARGET/venv/bin/udbmcp" "$ALIAS" 2>/dev/null; then
  # BEST-EFFORT by design: a PATH-convenience alias must never abort an
  # otherwise complete install.
  echo "    WARNING: could not create $ALIAS; the CLI stays available at $TARGET/venv/bin/udbmcp." >&2
fi

# The shipped config template carries a demo_sqlite connection pointing at
# /var/lib/universal-db-mcp/demo/finlink_demo.db, and doctor marks a missing
# SQLite data file FATAL. Without the file, the documented post-install doctor
# run fails on every clean install, and upgrade_offline.sh's pre-switch doctor
# aborts the upgrade blaming the new release. Create an empty database (never
# clobbering a seeded one; an empty file is an empty SQLite database) so the
# template's own example is valid. The udbmcp account owns the state
# directory, so root never follows a link there: the demo directory and the
# file are opened without following links, the file is created only if no
# name is there yet, and both are handed over on their descriptors.
# BEST-EFFORT by design: a convenience file for the template's example
# connection, never a reason to fail an otherwise complete install.
DEMO_DB=/var/lib/universal-db-mcp/demo/finlink_demo.db
if [ ! -f "$DEMO_DB" ]; then
  # >>> create the demo database: identical in install_offline.sh and the pkg postinstall
  $sudo_ok "$PY" -I -S - /var/lib/universal-db-mcp udbmcp <<'PYEOF' 2>/dev/null || {
import os
import pwd
import stat
import sys

state_dir, account = sys.argv[1], sys.argv[2]
owner = pwd.getpwnam(account)
state_fd = os.open(state_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    try:
        os.mkdir("demo", 0o750, dir_fd=state_fd)
    except FileExistsError:
        pass
    demo_fd = os.open("demo", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=state_fd)
finally:
    os.close(state_fd)
try:
    os.fchown(demo_fd, owner.pw_uid, owner.pw_gid)
    os.fchmod(demo_fd, 0o750)
    try:
        fd = os.open("finlink_demo.db", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640, dir_fd=demo_fd)
    except FileExistsError:
        # never clobbered; anything but a regular file there is reported
        st = os.stat("finlink_demo.db", dir_fd=demo_fd, follow_symlinks=False)
        sys.exit(0 if stat.S_ISREG(st.st_mode) else 1)
    try:
        os.fchown(fd, owner.pw_uid, owner.pw_gid)
        os.fchmod(fd, 0o640)
    finally:
        os.close(fd)
finally:
    os.close(demo_fd)
PYEOF
    echo "    WARNING: could not create the demo database at $DEMO_DB; doctor will report" >&2
    echo "             the template's demo_sqlite connection as a missing data file." >&2
  }
  # <<< create the demo database
fi

# Publish the verified bundle's manifest next to the venv ($TARGET/manifest.json)
# so `doctor` can report the profile it was actually built for instead of
# guessing from the running platform. Guarded: a bundle without a manifest must
# not fail the install — doctor falls back to an honest platform description.
# $BUNDLE is the re-verified private staging copy here, so what is published is
# exactly what was verified. That copy is root's alone (mode 700), so a run
# through sudo can only see it through sudo too: an unprivileged test there
# never found it, and the release record anti-rollback compares with was never
# written. A bundle that has one and cannot be published fails the install.
if $sudo_ok test -f "$BUNDLE/manifest.json"; then
  $sudo_ok install -m 644 -o root -g root "$BUNDLE/manifest.json" "$TARGET/manifest.json" || {
    echo "FAIL: could not publish $TARGET/manifest.json, the installed release's record anti-rollback" >&2
    echo "      compares the next bundle with; the new release is installed. Re-run this installer." >&2
    exit 1
  }
fi

echo "==> installed. Next steps:"
echo "    1. Copy $ORIG_BUNDLE/config-templates/config.yaml to /etc/universal-db-mcp/config.yaml and edit."
echo "    2. Run: $TARGET/venv/bin/python -m universal_db_mcp doctor"
echo "    3. See docs/offline-deployment.md for systemd/service setup."
