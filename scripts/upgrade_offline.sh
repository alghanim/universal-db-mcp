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
if [ ! -f "$VERIFIER" ]; then
  echo "FAIL: trusted verifier not found at $VERIFIER (set UDBMCP_VERIFIER or install the trusted tools)." >&2
  exit 1
fi
case "$(cd "$(dirname "$VERIFIER")" && pwd -P)" in
  "$bundle_real"/*)
    echo "FAIL: UDBMCP_VERIFIER points inside the bundle; the verifier must come from the trusted channel." >&2
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

$sudo_ok $VEXEC "$VERIFIER" --bundle "$NEW_BUNDLE" --pubkey "$PUBKEY"

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
$sudo_ok $VEXEC "$VERIFIER" --bundle "$STAGING" --pubkey "$PUBKEY"
NEW_BUNDLE="$STAGING"

echo "==> backing up current configuration and local state"
mkdir -p "$BACKUP/pre-upgrade-$(date -u +%Y%m%dT%H%M%SZ)"
cp -a /etc/universal-db-mcp "$BACKUP/pre-upgrade-$(date -u +%Y%m%dT%H%M%SZ)/" 2>/dev/null || true
[ -f /var/lib/universal-db-mcp/metadata.sqlite ] && \
  cp /var/lib/universal-db-mcp/metadata.sqlite "$BACKUP/pre-upgrade-$(date -u +%Y%m%dT%H%M%SZ)/" || true

echo "==> installing the bundle's OS packages (dpkg only, no apt, no network)"
PY=python3.12
command -v "$PY" >/dev/null 2>&1 || PY=python3
PY="$(command -v "$PY")"
udbmcp_install_os_packages "$NEW_BUNDLE" "$PY" "$sudo_ok"

echo "==> building new venv alongside current (atomic switch on success)"
"$PY" -c 'import sys; assert sys.version_info[:2] == (3, 12), f"CPython 3.12.x required, got {sys.version}"'
NEWVENV="$TARGET/venv.new-$(date -u +%Y%m%dT%H%M%SZ)"
$sudo_ok mkdir -p "$TARGET"
$sudo_ok "$PY" -m venv "$NEWVENV"
$sudo_ok env PIP_CONFIG_FILE=/dev/null PIP_DISABLE_PIP_VERSION_CHECK=1 \
  PIP_NO_INDEX=1 PIP_FIND_LINKS="$NEW_BUNDLE/wheelhouse" \
  "$NEWVENV/bin/python" -m pip --isolated --disable-pip-version-check install \
  --no-index --no-cache-dir \
  --find-links="$NEW_BUNDLE/wheelhouse" \
  --only-binary=:all: --require-hashes \
  -r "$NEW_BUNDLE/requirements/runtime.lock"

echo "==> smoke check + doctor on the NEW venv before switching"
$sudo_ok "$NEWVENV/bin/python" -m universal_db_mcp version
if [ -f /etc/universal-db-mcp/config.yaml ]; then
  UDBMCP_CONFIG=/etc/universal-db-mcp/config.yaml "$NEWVENV/bin/python" -m universal_db_mcp doctor \
    || { echo "FAIL: doctor failed on the new venv; aborting without switching" >&2; $sudo_ok rm -rf "$NEWVENV"; exit 1; }
fi

echo "==> switching (old venv kept for rollback; depth 1)"
if systemctl list-unit-files 2>/dev/null | grep -q universal-db-mcp; then systemctl stop universal-db-mcp || true; fi
if [ -d "$TARGET/venv" ]; then
  $sudo_ok rm -rf "$TARGET/venv.previous"   # rollback depth is one release
  $sudo_ok mv "$TARGET/venv" "$TARGET/venv.previous"
fi
$sudo_ok mv "$NEWVENV" "$TARGET/venv"

echo "==> validating effective installation"
# doctor resolves the config as args.config or $UDBMCP_CONFIG and fails closed
# with "no config path" when neither is set; pass it explicitly so a healthy
# upgrade is not rolled back by its own validation.
if ! "$TARGET/venv/bin/python" -m universal_db_mcp doctor \
  --config "${UDBMCP_CONFIG:-/etc/universal-db-mcp/config.yaml}"; then
  echo "FAIL: doctor failed after switch; rolling back automatically" >&2
  $sudo_ok rm -rf "$TARGET/venv.failed"; $sudo_ok mv "$TARGET/venv" "$TARGET/venv.failed"
  if [ -d "$TARGET/venv.previous" ]; then $sudo_ok mv "$TARGET/venv.previous" "$TARGET/venv"; fi
  exit 1
fi
if systemctl list-unit-files 2>/dev/null | grep -q universal-db-mcp; then systemctl start universal-db-mcp || true; fi

echo "==> upgraded. Rollback if needed:"
echo "    rollback_offline.sh $TARGET"
echo "Interrupted mid-way? Re-run: the .new-* venv is discarded and rebuilt."
