#!/usr/bin/env bash
# Offline upgrade using only local signed bundles. Never updates production
# dependencies automatically; never contacts any registry.
#
# The upgrade covers BOTH halves of the bundle: the Python venv is rebuilt
# from the new wheelhouse AND the bundle's os-packages/ (ODBC driver closure)
# are installed version-aware via the shared dpkg helper, so driver security
# fixes actually reach the target. OS packages are installed BEFORE the venv
# switch, so a dpkg failure aborts without touching the running venv.
#
# Anti-rollback: a bundle that is an OLDER release than the installed one
# ($TARGET/manifest.json) is refused by the verifier. An intended rollback
# passes --allow-downgrade (or UDBMCP_ALLOW_DOWNGRADE=1).
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

NEW_BUNDLE="${1:?usage: upgrade_offline.sh <new-bundle-dir> [target-dir] [backup-root] [--allow-downgrade]}"
TARGET="${2:-/opt/universal-db-mcp}"
BACKUP="${3:-/var/backups/universal-db-mcp}"
ORIG_BUNDLE="$NEW_BUNDLE"  # reported at the end; $NEW_BUNDLE is redirected to staging

echo "==> preflight: verify new bundle (authenticity REQUIRED)"
PUBKEY="${UDBMCP_RELEASE_PUBKEY:-}"
if [ -z "$PUBKEY" ]; then
  echo "FAIL: set UDBMCP_RELEASE_PUBKEY to the release public key PEM path." >&2
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
bundle_real="$(cd "$NEW_BUNDLE" && pwd -P)"
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
if [ ! -f "$VERIFIER" ] || [ ! -s "$VERIFIER" ]; then
  echo "FAIL: trusted verifier not found (or zero-length) at $VERIFIER (set UDBMCP_VERIFIER or install the trusted tools)." >&2
  echo "      A zero-length verifier would 'verify' vacuously: python3 on an empty script exits 0." >&2
  exit 1
fi
# The RESOLVED FILE PATH is compared, as for the key below: a verifier sitting
# directly in the bundle root has dirname == $bundle_real, which a
# "$bundle_real"/* match on the directory alone let through (and ran as root).
verifier_real="$(cd "$(dirname "$VERIFIER")" && pwd -P)/$(basename "$VERIFIER")"
case "$verifier_real" in
  "$bundle_real"/*)
    echo "FAIL: UDBMCP_VERIFIER points inside the bundle; the verifier must come from the trusted channel." >&2
    exit 1 ;;
esac
# Same rule for the release public key: a tampered bundle ships its own key
# (and a re-signed SHA256SUMS/SIGNATURE), so a key read from inside the bundle
# authenticates nothing — verification would PASS against attacker material.
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
NEW_BUNDLE="$(abs_path "$NEW_BUNDLE")"
TARGET="$(abs_path "$TARGET")"
BACKUP="$(abs_path "$BACKUP")"
PUBKEY="$(abs_path "$PUBKEY")"
VERIFIER="$(abs_path "$VERIFIER")"
[ -z "${UDBMCP_STAGING_DIR:-}" ] || UDBMCP_STAGING_DIR="$(abs_path "$UDBMCP_STAGING_DIR")"
[ -z "${UDBMCP_CONFIG:-}" ] || UDBMCP_CONFIG="$(abs_path "$UDBMCP_CONFIG")"
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

# Privilege: the OS-package step always requires root; the rest of the script
# is usable either way, so sudo is adopted only when identity demands it (the
# helper then fails loudly if the bundle ships os-packages but sudo is not
# available). Decided up front so every privileged step below — including
# staging and re-verification — shares one decision.
sudo_ok=""
if [ "$(id -u)" -ne 0 ]; then
  # `command -v` reports a PATH match even when the file is not executable,
  # so probe executability explicitly: adopting an unusable sudo would fail
  # later with a bare "Permission denied" mid-upgrade instead of here.
  sudo_bin="$(command -v sudo 2>/dev/null || true)"
  if [ -n "$sudo_bin" ] && [ -x "$sudo_bin" ]; then
    sudo_ok="sudo"
  fi
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

# Proof-of-verification gate (same control as install_offline.sh, commit
# security review 2026-09-12: the upgrade path lacked it): a verifier that
# exits 0 WITHOUT printing the canonical PASS line — or that prints a FAIL
# diagnostic — must abort the upgrade. Output is echoed through so the admin
# sees the canonical diagnostics either way. Both runs also check the release
# order against the installed manifest (anti-rollback).
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
    echo "FAIL: trusted verifier exited $vrc; the bundle is untrusted: upgrade ABORTED." >&2
    exit 1
  fi
  if [[ $'\n'"$vout" == *$'\n'FAIL:* ]] || [[ "$vout" != *'bundle verification PASSED'* ]]; then
    echo "FAIL: trusted verifier exited 0 but did not print 'bundle verification PASSED' (or printed a FAIL line); without explicit proof of verification the bundle is treated as untrusted: upgrade ABORTED." >&2
    exit 1
  fi
}

verify_with_proof "$NEW_BUNDLE"

# --- verify-then-use: consume ONLY a private root-owned staging copy --------
# Same race install_offline.sh closes: the tree is hashed once, then pip and
# dpkg read it for tens of seconds in a privileged context. Stage, re-verify,
# and never touch the original again.
# The staging base is root's alone (above); mktemp -d makes the private directory the copy is
# made in (private_copy, above).
STAGING_BASE="$(staging_base "${UDBMCP_STAGING_DIR:-/var/tmp}" "Upgrade ABORTED.")" || exit 1
STAGING_DIR="$($sudo_ok mktemp -d "$STAGING_BASE/udbmcp-upgrade.XXXXXX")"
cleanup_staging() { ${sudo_ok:+sudo }rm -rf -- "$STAGING_DIR" 2>/dev/null || true; }
# A kill between the two switch renames below leaves NO venv in place; the
# exit trap restores venv.previous so the service can start again without
# manual help (rollback_offline.sh tolerates the window too, but recovery
# should not depend on the operator picking the right script).
restore_previous_venv_on_interrupt() {
  if [ -d "$TARGET/venv.previous" ] && [ ! -d "$TARGET/venv" ]; then
    echo "==> upgrade interrupted mid-switch; restoring $TARGET/venv.previous" >&2
    $sudo_ok mv "$TARGET/venv.previous" "$TARGET/venv"
  fi
}
on_exit() { restore_previous_venv_on_interrupt; cleanup_staging; }
trap on_exit EXIT
echo "==> staging a private copy of the verified bundle (closes the verify-then-use race)"
STAGING="$(private_copy "$NEW_BUNDLE" "$STAGING_DIR" "Upgrade ABORTED.")" || exit 1
verify_with_proof "$STAGING"
NEW_BUNDLE="$STAGING"

echo "==> backing up current configuration and local state"
# One timestamp for the whole backup: computing it per command meant that
# across a second boundary the cp targets named a directory mkdir never
# created, and `|| true` swallowed the failure — an upgrade that reported a
# backup it did not take.
BACKUP_STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP_DIR="$BACKUP/pre-upgrade-$BACKUP_STAMP"
mkdir -p "$BACKUP_DIR"
cp -a /etc/universal-db-mcp "$BACKUP_DIR/" 2>/dev/null || true
# cp -a: the service account owns that directory and may have made the name a
# link (to a file only root can read) or a FIFO; it is copied as what it is,
# never read through (rollback_offline.sh restores a regular file only).
[ -f /var/lib/universal-db-mcp/metadata.sqlite ] && \
  cp -a /var/lib/universal-db-mcp/metadata.sqlite "$BACKUP_DIR/" || true

echo "==> installing the bundle's OS packages (dpkg only, no apt, no network)"
PY=python3.12
command -v "$PY" >/dev/null 2>&1 || PY=python3
PY="$(command -v "$PY")"
udbmcp_install_os_packages "$NEW_BUNDLE" "$PY" "$sudo_ok"

echo "==> building new venv alongside current (atomic switch on success)"
"$PY" -I -S -c 'import sys; assert sys.version_info[:2] == (3, 12), f"CPython 3.12.x required, got {sys.version}"'
$sudo_ok mkdir -p "$TARGET"
# Re-run hygiene: an earlier attempt aborted between venv creation and the
# doctor check (pip failure, smoke-check failure, kill) leaves a full
# venv.new-* tree behind — hundreds of MB of dead weight under /opt per
# attempt, and a later upgrade can die on ENOSPC mid-pip. Discard stale ones
# before building the new one. Concurrent upgrades are not supported (both
# would contest the same venv), so anything matching here is debris.
$sudo_ok rm -rf "$TARGET"/venv.new-* 2>/dev/null || true
NEWVENV="$TARGET/venv.new-$(date -u +%Y%m%dT%H%M%SZ)"
# --copies: see install_offline.sh; keeps rollback_offline.sh's containment gate satisfied
$sudo_ok "$PY" -I -S -m venv --copies "$NEWVENV"
$sudo_ok env PIP_CONFIG_FILE=/dev/null PIP_DISABLE_PIP_VERSION_CHECK=1 \
  PIP_NO_INDEX=1 PIP_FIND_LINKS="$NEW_BUNDLE/wheelhouse" \
  "$NEWVENV/bin/python" -I -m pip --isolated --disable-pip-version-check install \
  --no-index --no-cache-dir \
  --find-links="$NEW_BUNDLE/wheelhouse" \
  --only-binary=:all: --require-hashes \
  -r "$NEW_BUNDLE/requirements/runtime.lock"

# Venv mode normalization, identical to install_offline.sh: the creating
# umask leaks into the tree, and a umask 077 upgrade leaves the venv 0700
# root:root so the service account cannot traverse it and systemd reports
# 203/EXEC Permission denied - blaming the interpreter. Both doctor runs below
# execute as root and would pass regardless, so the failure would only surface
# after the switch, on the next service start.
$sudo_ok find "$NEWVENV" -type d -exec chmod 755 {} +
$sudo_ok find "$NEWVENV" -type f -exec chmod 644 {} +
$sudo_ok find "$NEWVENV/bin" -type f -exec chmod 755 {} +

echo "==> smoke check + doctor on the NEW venv before switching"
$sudo_ok "$NEWVENV/bin/python" -I -m universal_db_mcp version
# Both doctor runs go through $sudo_ok like every other privileged step: the
# config is root:udbmcp 0640, so a non-root operator's unprivileged doctor
# cannot even read it and the upgrade aborted with "doctor failed" on a
# healthy release. `env` carries the variable across sudo (same pattern as
# the pip invocation above).
if [ -f /etc/universal-db-mcp/config.yaml ]; then
  $sudo_ok env UDBMCP_CONFIG=/etc/universal-db-mcp/config.yaml "$NEWVENV/bin/python" -m universal_db_mcp doctor \
    || { echo "FAIL: doctor failed on the new venv; aborting without switching" >&2; $sudo_ok rm -rf "$NEWVENV"; exit 1; }
fi

echo "==> switching (old venv kept for rollback; depth 1)"
if systemctl list-unit-files 2>/dev/null | grep -q universal-db-mcp; then systemctl stop universal-db-mcp || true; fi
# An older release's root site check (sudo udbmcp site-check or doctor) could
# leave the audit log, its .lock sidecar or a rotated backup in the log
# directory owned by root. This release no longer repairs them at run time, so
# under audit_fail_closed the service would refuse every audited call: hand
# them back while it is stopped, as the .deb and the .pkg do. udbmcp owns the
# directory, so each entry is opened without following links and checked on
# the open descriptor (a regular file, one link, owned by root) before
# fchown: a symlink, or a name that is a second link to another file, is left
# alone. Best effort: a failure warns and never aborts the upgrade.
LOG_DIR=/var/log/universal-db-mcp
if [ -d "$LOG_DIR" ] && id udbmcp >/dev/null 2>&1; then
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
fi
if [ -d "$TARGET/venv" ]; then
  $sudo_ok rm -rf "$TARGET/venv.previous"   # rollback depth is one release
  $sudo_ok rm -f "$TARGET/venv.previous.sha256"   # manifest of the discarded release
  $sudo_ok rm -f "$TARGET/venv.previous.manifest.json"   # and its release record
  # rollback_offline.sh executes the demoted venv only after it matches this
  # manifest, so record it BEFORE the rename: an upgrade killed between these
  # two operations still leaves a verifiable venv.previous behind. Relative
  # paths keep the manifest valid across the venv.previous -> venv rename.
  echo "==> recording the rollback integrity manifest for the demoted venv"
  $sudo_ok sh -c 'cd "$1/venv" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > "$1/venv.previous.sha256"' sh "$TARGET" \
    || { $sudo_ok rm -f "$TARGET/venv.previous.sha256"; \
         echo "FAIL: could not record the rollback integrity manifest; aborting without switching" >&2; exit 1; }
  # The running release's record goes with its venv: after rolling back to it,
  # rollback_offline.sh raises $TARGET/manifest.json to it when it names an
  # older release (after an intended downgrade), so anti-rollback never
  # compares with a release below the one that runs.
  if $sudo_ok test -f "$TARGET/manifest.json"; then
    $sudo_ok install -m 644 -o root -g root "$TARGET/manifest.json" "$TARGET/venv.previous.manifest.json" \
      || echo "WARNING: could not keep the running release's record for rollback_offline.sh" >&2
  fi
  $sudo_ok mv "$TARGET/venv" "$TARGET/venv.previous"
fi
$sudo_ok mv "$NEWVENV" "$TARGET/venv"

echo "==> validating effective installation"
# doctor resolves the config as args.config or $UDBMCP_CONFIG and fails closed
# with "no config path" — or "config file not found" — when neither resolves
# to an existing file; pass it explicitly so a healthy upgrade is not rolled
# back by its own validation. Mirror the pre-switch guard too: on a
# config-less installation (no /etc/universal-db-mcp/config.yaml yet, no
# UDBMCP_CONFIG) the default path does not exist and would turn a valid
# upgrade into an automatic rollback, so only run the config-aware doctor
# when a config actually resolves.
if [ -n "${UDBMCP_CONFIG:-}" ] || [ -f /etc/universal-db-mcp/config.yaml ]; then
  if ! $sudo_ok "$TARGET/venv/bin/python" -m universal_db_mcp doctor \
    --config "${UDBMCP_CONFIG:-/etc/universal-db-mcp/config.yaml}"; then
    echo "FAIL: doctor failed after switch; rolling back automatically" >&2
    $sudo_ok rm -rf "$TARGET/venv.failed"; $sudo_ok mv "$TARGET/venv" "$TARGET/venv.failed"
    if [ -d "$TARGET/venv.previous" ]; then $sudo_ok mv "$TARGET/venv.previous" "$TARGET/venv"; fi
    $sudo_ok rm -f "$TARGET/venv.previous.manifest.json"  # its release is the running one again
    # The unit was stopped for the switch: leave the rolled-back installation
    # running again instead of exiting with the service down and no hint.
    if systemctl list-unit-files 2>/dev/null | grep -q universal-db-mcp; then systemctl start universal-db-mcp || true; fi
    echo "FAIL: previous release restored and service restarted; see the doctor output above." >&2
    exit 1
  fi
else
  echo "==> no config file present; skipping config-aware doctor validation"
fi

# Publish the re-verified staging copy's manifest next to the venv, mirroring
# install_offline.sh, so `doctor` (and fleet audits) report the profile of the
# bundle that is actually installed instead of the previous release's. It is
# written only AFTER validation succeeds and the switch is final: on the
# auto-rollback path the existing manifest keeps describing the restored venv.
# $NEW_BUNDLE is the re-verified private staging copy here, so what is
# published is exactly what was verified. That copy is root's alone (mode 700):
# through sudo it is tested through sudo too (an unprivileged test never found
# it, and the release record anti-rollback compares with was never written).
# A record that cannot be published fails the upgrade, once the service is
# started again.
PUBLISHED=1
if $sudo_ok test -f "$NEW_BUNDLE/manifest.json"; then
  $sudo_ok install -m 644 -o root -g root "$NEW_BUNDLE/manifest.json" "$TARGET/manifest.json" || PUBLISHED=0
fi

if systemctl list-unit-files 2>/dev/null | grep -q universal-db-mcp; then systemctl start universal-db-mcp || true; fi
if [ "$PUBLISHED" -eq 0 ]; then
  echo "FAIL: could not publish $TARGET/manifest.json, the installed release's record anti-rollback" >&2
  echo "      compares the next bundle with; the new release is installed and running. Re-run this upgrade." >&2
  exit 1
fi

echo "==> upgraded from $ORIG_BUNDLE. Rollback if needed:"
echo "    rollback_offline.sh $TARGET"
echo "Interrupted mid-way? Re-run: stale .new-* venvs are discarded and the build restarts."
