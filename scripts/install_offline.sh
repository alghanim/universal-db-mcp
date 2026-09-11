#!/usr/bin/env bash
# Stage B, step 2: install the verified bundle inside the air gap.
# Network-independent: pip runs with --no-index against the bundle wheelhouse
# only, with a hostile inherited environment neutralized (PIP_CONFIG_FILE,
# proxies, index URLs are all overridden). OS packages ship in os-packages/
# and are installed with dpkg ONLY — apt is never invoked, so nothing here
# can reach a network or a vendor repository.
set -euo pipefail

BUNDLE="${1:?usage: install_offline.sh <bundle-dir> [target-dir]}"
TARGET="${2:-/opt/universal-db-mcp}"

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
case "$(cd "$(dirname "$VERIFIER")" && pwd -P)" in
  "$bundle_real"/*)
    echo "FAIL: UDBMCP_VERIFIER points inside the bundle; the verifier must come from the trusted channel." >&2
    exit 1 ;;
esac
python3 "$VERIFIER" --bundle "$BUNDLE" --pubkey "$PUBKEY"

sudo_ok=""
if [ ! -w "$(dirname "$TARGET")" ] 2>/dev/null; then sudo_ok="sudo"; fi

echo "==> checking platform baseline"
PY=python3.12
command -v "$PY" >/dev/null 2>&1 || PY=python3
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
fi
$sudo_ok install -d -o udbmcp -g udbmcp /var/lib/universal-db-mcp /var/log/universal-db-mcp 2>/dev/null || true

echo "==> creating virtual environment at $TARGET/venv"
$sudo_ok mkdir -p "$TARGET"
[ -w "$TARGET" ] || $sudo_ok chown "$(id -u):$(id -g)" "$TARGET"
"$PY" -m venv "$TARGET/venv"

echo "==> installing application from bundle wheelhouse (no index, hashed)"
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
  -r "$BUNDLE/requirements/runtime.lock"

# --- OS packages (ODBC driver closure): dpkg only, no apt, no network -------
OSPKG_DIR="$BUNDLE/os-packages"
if compgen -G "$OSPKG_DIR/*.deb" >/dev/null; then
  echo "==> installing OS packages from bundle os-packages/ (dpkg only, no apt, no network)"
  command -v dpkg >/dev/null 2>&1 || { echo "FAIL: dpkg not available; cannot install bundle OS packages"; exit 1; }
  export DEBIAN_FRONTEND=noninteractive

  # Install in the manifest-declared dependency order (unixodbc stack before
  # msodbcsql18, whose postinst runs `odbcinst`). Anything already installed
  # is skipped, so re-runs and upgrades are idempotent.
  order="$("$PY" - "$BUNDLE/manifest.json" <<'PYEOF'
import json, sys
with open(sys.argv[1]) as fh:
    m = json.load(fh)
for entry in (m.get("os_packages") or {}).get("packages", []):
    print(entry["file"])
PYEOF
)"
  if [ -z "$order" ]; then
    # Bundles without a manifest os_packages section: fall back to the
    # documented order for the Microsoft ODBC / unixODBC closure.
    order="$(cd "$OSPKG_DIR" && ls -1 *.deb \
      | awk '/msodbcsql18/{print "9 " $0; next} /unixodbc-/{print "4 " $0; next} /libodbc/{print "5 " $0; next} /libkeyutils1|libkrb5support0|libk5crypto3|libkrb5-3|libltdl7/{print "0 " $0; next} {print "3 " $0}' \
      | sort -k1,1 -k2 | cut -d' ' -f2-)"
  fi

  while IFS= read -r debfile; do
    [ -n "$debfile" ] || continue
    deb="$OSPKG_DIR/$debfile"
    [ -f "$deb" ] || { echo "FAIL: manifest-listed OS package missing from bundle: $debfile"; exit 1; }
    pkg="$(dpkg-deb -f "$deb" Package)"
    if dpkg -s "$pkg" >/dev/null 2>&1; then
      echo "    already installed, skipping: $pkg"
      continue
    fi
    echo "    dpkg -i: $debfile"
    # dpkg alone never touches the network; a missing dependency aborts with
    # dpkg's own dependency error instead of being silently resolved by apt.
    # The assignments must reach dpkg itself: prefixed onto `sudo` they land in
    # sudo's own environment, which env_reset strips before exec'ing dpkg, so
    # msodbcsql18's postinst would never see ACCEPT_EULA and would abort.
    # `sudo env VAR=... dpkg ...` (and plain `env` when root) sets them in the
    # child environment dpkg actually runs in.
    $sudo_ok env ACCEPT_EULA=Y DEBIAN_FRONTEND=noninteractive dpkg -i "$deb" || {
      echo "FAIL: dpkg -i $debfile failed." >&2
      echo "      The bundle ships the full dependency closure in $OSPKG_DIR;" >&2
      echo "      check the ordering/manifest (os_packages.install_order)." >&2
      echo "      Missing base-OS libraries (e.g. libltdl7) must be provided" >&2
      echo "      by the administrator; apt is never used here." >&2
      exit 1
    }
  done < <(printf '%s\n' "$order")

  # The msodbcsql18 postinst registers the driver via odbcinst; verify and
  # register manually from the shipped odbcinst.ini if that did not happen.
  if command -v odbcinst >/dev/null 2>&1; then
    if odbcinst -q -d -n "ODBC Driver 18 for SQL Server" >/dev/null 2>&1; then
      echo "    ODBC driver registered: ODBC Driver 18 for SQL Server"
    elif [ -f /opt/microsoft/msodbcsql18/etc/odbcinst.ini ]; then
      echo "    registering ODBC driver from the shipped odbcinst.ini"
      $sudo_ok odbcinst -i -d -f /opt/microsoft/msodbcsql18/etc/odbcinst.ini
    fi
  fi
else
  echo "==> no OS packages in bundle os-packages/ (skipping dpkg step)"
fi

echo "==> smoke check"
"$TARGET/venv/bin/python" -m universal_db_mcp version

echo "==> installed. Next steps:"
echo "    1. Copy $BUNDLE/config-templates/config.yaml to /etc/universal-db-mcp/config.yaml and edit."
echo "    2. Run: $TARGET/venv/bin/python -m universal_db_mcp doctor"
echo "    3. See docs/offline-deployment.md for systemd/service setup."
