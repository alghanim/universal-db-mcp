#!/usr/bin/env bash
# Offline upgrade using only local signed bundles. Never updates production
# dependencies automatically; never contacts any registry.
#
# The upgrade covers BOTH halves of the bundle: the Python venv is rebuilt
# from the new wheelhouse AND the bundle's os-packages/ (ODBC driver closure)
# are installed version-aware via the shared dpkg helper, so driver security
# fixes actually reach the target. OS packages are installed BEFORE the venv
# switch, so a dpkg failure aborts without touching the running venv.
set -euo pipefail

NEW_BUNDLE="${1:?usage: upgrade_offline.sh <new-bundle-dir> [target-dir] [backup-root]}"
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
case "$(cd "$(dirname "$VERIFIER")" && pwd -P)" in
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

# How to run the trusted verifier. On the documented channel it is installed
# with `install -m 644` (a Python file), so it is executed via python3; a
# non-Python executable verifier (e.g. a compiled helper or /bin/sh script) is
# exec'd directly. A Python file that happens to carry an exec bit still goes
# through python3: on some staging hosts (macOS Docker Desktop bind mounts)
# the directory presents the exec bit but is mounted noexec, so exec'ing the
# file directly fails with rc=126 'bad interpreter' AFTER [ -x ] succeeded.
# Either way it comes from the trusted path validated above — never from the
# bundle. $VEXEC is deliberately unquoted at the call sites (it is either
# empty, or the single word "python3") so the same expression works under the
# $sudo_ok prefix.
VEXEC=""
if [ -x "$VERIFIER" ]; then
  case "$(head -n 1 "$VERIFIER" 2>/dev/null)" in
    *"python"*) VEXEC="python3" ;;
    *) VEXEC="" ;;
  esac
else
  VEXEC="python3"
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

# Proof-of-verification gate (same control as install_offline.sh, commit
# security review 2026-09-12: the upgrade path lacked it): a verifier that
# exits 0 WITHOUT printing the canonical PASS line — or that prints a FAIL
# diagnostic — must abort the upgrade. Output is echoed through so the admin
# sees the canonical diagnostics either way.
verify_with_proof() {
  # $1: the bundle directory to verify
  local vout vrc=0
  vout="$(mktemp "${TMPDIR:-/tmp}/udbmcp-upgrade-verify.XXXXXX")"
  $sudo_ok $VEXEC "$VERIFIER" --bundle "$1" --pubkey "$PUBKEY" >"$vout" 2>&1 || vrc=$?
  cat "$vout"
  if [ "$vrc" -ne 0 ]; then
    echo "FAIL: trusted verifier exited $vrc; the bundle is untrusted: upgrade ABORTED." >&2
    rm -f "$vout"
    exit 1
  fi
  if grep -q '^FAIL:' "$vout" || ! grep -q 'bundle verification PASSED' "$vout"; then
    echo "FAIL: trusted verifier exited 0 but did not print 'bundle verification PASSED' (or printed a FAIL line); without explicit proof of verification the bundle is treated as untrusted: upgrade ABORTED." >&2
    rm -f "$vout"
    exit 1
  fi
  rm -f "$vout"
}

verify_with_proof "$NEW_BUNDLE"

# --- verify-then-use: consume ONLY a private root-owned staging copy --------
# Same race install_offline.sh closes: the tree is hashed once, then pip and
# dpkg read it for tens of seconds in a privileged context. Stage, re-verify,
# and never touch the original again.
STAGING_BASE="${UDBMCP_STAGING_DIR:-/var/tmp}"  # mktemp -d always creates the dir mode 700
$sudo_ok mkdir -p "$STAGING_BASE"
STAGING="$($sudo_ok mktemp -d "$STAGING_BASE/udbmcp-upgrade.XXXXXX")"
cleanup_staging() { ${sudo_ok:+sudo }rm -rf -- "$STAGING" 2>/dev/null || true; }
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
$sudo_ok chmod 700 "$STAGING"
echo "==> staging a private copy of the verified bundle (closes the verify-then-use race)"
$sudo_ok cp -a "$NEW_BUNDLE"/. "$STAGING/"
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
[ -f /var/lib/universal-db-mcp/metadata.sqlite ] && \
  cp /var/lib/universal-db-mcp/metadata.sqlite "$BACKUP_DIR/" || true

echo "==> installing the bundle's OS packages (dpkg only, no apt, no network)"
PY=python3.12
command -v "$PY" >/dev/null 2>&1 || PY=python3
PY="$(command -v "$PY")"
udbmcp_install_os_packages "$NEW_BUNDLE" "$PY" "$sudo_ok"

echo "==> building new venv alongside current (atomic switch on success)"
"$PY" -c 'import sys; assert sys.version_info[:2] == (3, 12), f"CPython 3.12.x required, got {sys.version}"'
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
$sudo_ok "$PY" -m venv --copies "$NEWVENV"
$sudo_ok env PIP_CONFIG_FILE=/dev/null PIP_DISABLE_PIP_VERSION_CHECK=1 \
  PIP_NO_INDEX=1 PIP_FIND_LINKS="$NEW_BUNDLE/wheelhouse" \
  "$NEWVENV/bin/python" -m pip --isolated --disable-pip-version-check install \
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
$sudo_ok "$NEWVENV/bin/python" -m universal_db_mcp version
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
if [ -d "$TARGET/venv" ]; then
  $sudo_ok rm -rf "$TARGET/venv.previous"   # rollback depth is one release
  $sudo_ok rm -f "$TARGET/venv.previous.sha256"   # manifest of the discarded release
  # rollback_offline.sh executes the demoted venv only after it matches this
  # manifest, so record it BEFORE the rename: an upgrade killed between these
  # two operations still leaves a verifiable venv.previous behind. Relative
  # paths keep the manifest valid across the venv.previous -> venv rename.
  echo "==> recording the rollback integrity manifest for the demoted venv"
  $sudo_ok sh -c 'cd "$1/venv" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > "$1/venv.previous.sha256"' sh "$TARGET" \
    || { $sudo_ok rm -f "$TARGET/venv.previous.sha256"; \
         echo "FAIL: could not record the rollback integrity manifest; aborting without switching" >&2; exit 1; }
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
# published is exactly what was verified.
if [ -f "$NEW_BUNDLE/manifest.json" ]; then
  $sudo_ok install -m 644 -o root -g root "$NEW_BUNDLE/manifest.json" "$TARGET/manifest.json"
fi

if systemctl list-unit-files 2>/dev/null | grep -q universal-db-mcp; then systemctl start universal-db-mcp || true; fi

echo "==> upgraded from $ORIG_BUNDLE. Rollback if needed:"
echo "    rollback_offline.sh $TARGET"
echo "Interrupted mid-way? Re-run: stale .new-* venvs are discarded and the build restarts."
