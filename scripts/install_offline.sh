#!/usr/bin/env bash
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
set -euo pipefail

BUNDLE="${1:?usage: install_offline.sh <bundle-dir> [target-dir]}"
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

# --- verifier PROOF gate -----------------------------------------------------
# Exit code alone is not proof of verification: python3 on an empty, truncated
# or no-op verifier exits 0 vacuously, and a verifier that exits 0 without
# certifying proves nothing. Success requires exit 0 AND the verifier's
# literal 'bundle verification PASSED' AND no 'FAIL:' diagnostic — the same
# rule packaging/msi/custom/verify.ps1 enforces. Output is echoed through so
# the admin sees the canonical diagnostics either way.
verify_with_proof() {
  # $1: the bundle directory to verify
  local vout vrc=0
  vout="$(mktemp "${TMPDIR:-/tmp}/udbmcp-verify.XXXXXX")"
  $sudo_ok $VEXEC "$VERIFIER" --bundle "$1" --pubkey "$PUBKEY" >"$vout" 2>&1 || vrc=$?
  cat "$vout"
  if [ "$vrc" -ne 0 ]; then
    echo "FAIL: trusted verifier exited $vrc; the bundle is untrusted: installation ABORTED." >&2
    rm -f "$vout"
    exit 1
  fi
  if grep -q '^FAIL:' "$vout" || ! grep -q 'bundle verification PASSED' "$vout"; then
    echo "FAIL: trusted verifier exited 0 but did not print 'bundle verification PASSED' (or printed a FAIL line); without explicit proof of verification the bundle is treated as untrusted: installation ABORTED." >&2
    rm -f "$vout"
    exit 1
  fi
  rm -f "$vout"
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
STAGING_BASE="${UDBMCP_STAGING_DIR:-/var/tmp}"  # mktemp -d always creates the dir mode 700
$sudo_ok mkdir -p "$STAGING_BASE"
STAGING="$($sudo_ok mktemp -d "$STAGING_BASE/udbmcp-install.XXXXXX")"
cleanup_staging() { ${sudo_ok:+sudo }rm -rf -- "$STAGING" 2>/dev/null || true; }
trap cleanup_staging EXIT
$sudo_ok chmod 700 "$STAGING"
echo "==> staging a private copy of the verified bundle (closes the verify-then-use race)"
$sudo_ok cp -a "$BUNDLE"/. "$STAGING/"
verify_with_proof "$STAGING"
BUNDLE="$STAGING"

echo "==> checking platform baseline"
PY=python3.12
command -v "$PY" >/dev/null 2>&1 || PY=python3
PY="$(command -v "$PY")"
"$PY" -c 'import sys; assert sys.version_info[:2] == (3, 12), f"CPython 3.12.x required, got {sys.version}"'
"$PY" -c 'import ensurepip, venv' || { echo "FAIL: venv/ensurepip not available"; exit 1; }

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

echo "==> creating virtual environment at $TARGET/venv"
if [ ! -d "$TARGET" ]; then
  # root-owned 755: the venv is code that root-run tools and the service
  # execute; it must never be owned (or writable) by the invoking operator.
  $sudo_ok install -d -m 755 -o root -g root "$TARGET"
fi
$sudo_ok "$PY" -m venv "$TARGET/venv"

echo "==> installing application from bundle wheelhouse (no index, hashed)"
# --force-reinstall is MANDATORY on upgrades (mirrors packaging/pkg/postinstall):
# the app wheel's version string does not change between code-only releases
# (0.1.0 -> 0.1.0) and the .deb postinst re-runs this installer over the
# EXISTING venv, so without it pip reports "already satisfied" and keeps the
# previous release's code while dpkg reports a successful upgrade (seen live
# 2026-09-15: the Db2 credential fix was dpkg-installed yet the same
# SQL30082N errors persisted). Every package is still resolved only from the
# verified wheelhouse and checked against runtime.lock's hashes.
$sudo_ok env \
  PIP_CONFIG_FILE=/dev/null \
  PIP_DISABLE_PIP_VERSION_CHECK=1 \
  PIP_NO_INDEX=1 \
  PIP_FIND_LINKS="$BUNDLE/wheelhouse" \
  "$TARGET/venv/bin/python" -m pip --isolated --disable-pip-version-check install \
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
$sudo_ok "$TARGET/venv/bin/python" -m universal_db_mcp version

# Venv mode normalization: the venv is CODE the service account executes, but
# the creating context's umask leaks into it (seen live 2026-09-15: a umask
# 077 install left the venv 0700 root:root and the udbmcp service died with
# 203/EXEC Permission denied - the interpreter was fine, the SERVICE ACCOUNT
# just could not traverse into the tree). Normalize unconditionally: dirs
# 0755 (traversable), files 0644, bin executables 0755. $TARGET/venv itself
# is root-owned either way - this grants read+traverse, never write.
$sudo_ok find "$TARGET/venv" -type d -exec chmod 755 {} +
$sudo_ok find "$TARGET/venv" -type f -exec chmod 644 {} +
$sudo_ok find "$TARGET/venv/bin" -type f -exec chmod 755 {} +

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

# Publish the verified bundle's manifest next to the venv ($TARGET/manifest.json)
# so `doctor` can report the profile it was actually built for instead of
# guessing from the running platform. Guarded: a bundle without a manifest must
# not fail the install — doctor falls back to an honest platform description.
# $BUNDLE is the re-verified private staging copy here, so what is published is
# exactly what was verified.
if [ -f "$BUNDLE/manifest.json" ]; then
  $sudo_ok install -m 644 -o root -g root "$BUNDLE/manifest.json" "$TARGET/manifest.json"
fi

echo "==> installed. Next steps:"
echo "    1. Copy $ORIG_BUNDLE/config-templates/config.yaml to /etc/universal-db-mcp/config.yaml and edit."
echo "    2. Run: $TARGET/venv/bin/python -m universal_db_mcp doctor"
echo "    3. See docs/offline-deployment.md for systemd/service setup."
