#!/usr/bin/env bash
# Gate: macOS .pkg native package (plan Phase 3).
#
# Proves, on this macOS host, that the .pkg built by scripts/package/build_pkg.sh
# carries EXACTLY the signed offline bundle as its payload and that the launchd
# plist mirrors the systemd unit. Sequence:
#
#   1. acquire a signed macos-arm64-cp312 bundle (reuse or build with an
#      EPHEMERAL key, mirroring scripts/test_airgap.sh) and verify it through
#      the trusted-channel verifier BEFORE anything is packaged;
#   2. build the .pkg;
#   3. pkgutil --expand-full and assert the payload bundle contains
#      SHA256SUMS + SIGNATURE + wheelhouse (+ manifest, installer, runtime.lock);
#   4. run the TRUSTED verify_bundle.py --pubkey against the payload bundle
#      (payload == signed bundle; the payload's own verifier is NEVER executed);
#   5. assert NO public/private key material ships inside the package
#      (the release pubkey is distributed out-of-band, never packaged);
#   6. plutil -lint + value checks on the payload launchd plist
#      (UserName _udbmcp, Umask 63 decimal == 0077 octal, UDBMCP_CONFIG),
#      plus a launchd identity cross-check: the plist Label, postinstall's
#      LABEL, and the plist filename stem must all be the same, or every
#      upgrade/reinstall aborts at launchctl bootstrap;
#   7. run the native unit suite (.venv/bin/python -m pytest tests/unit -q);
#   8. OPTIONAL full installer run ONLY behind UDBMCP_PKG_INSTALL=1
#      (sudo installer -pkg); otherwise the evidence records
#      "installer_run": "not_run".
#
# Every check result is recorded; any failure fails the gate closed and the
# evidence JSON is still written. Machine-readable evidence lands in
# out/package-evidence/pkg/results.json.
#
# This gate never executes payload code: the verifier it runs is the trusted
# repo copy (scripts/verify_bundle.py — the same code trusted-tools ships),
# the unit suite runs repository code, and the only payload execution is the
# explicitly opted-in `installer` run.
set -euo pipefail

PROJECT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$PROJECT/out"
EVIDENCE_DIR="$OUT/package-evidence/pkg"
LOG_DIR="$EVIDENCE_DIR/logs"
EVIDENCE_JSON="$EVIDENCE_DIR/results.json"
PY="$PROJECT/.venv/bin/python"
TRUSTED_VERIFIER="$PROJECT/scripts/verify_bundle.py"
BUILD_PKG="$PROJECT/scripts/package/build_pkg.sh"
PLIST_SRC="$PROJECT/packaging/launchd/com.udbmcp.server.plist"

mkdir -p "$EVIDENCE_DIR" "$LOG_DIR"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/udbmcp-pkg-gate.XXXXXX")"
CHECKS_TSV="$WORK/checks.tsv"
: > "$CHECKS_TSV"
FAILED=0

record() {
  # record <check-name> <passed|failed> <one-line-detail>
  local name="$1" status="$2" detail="$3"
  detail="${detail//$'\n'/ }"
  detail="${detail//$'\t'/ }"
  printf '%s\t%s\t%s\n' "$name" "$status" "$detail" >> "$CHECKS_TSV"
  echo "==> [$status] $name: $detail"
  if [ "$status" != "passed" ]; then
    FAILED=1
  fi
}

require() {
  # require <check-name> <detail-on-failure> -- <command...>
  # Runs the command; records pass/fail; exits 1 on failure (fail closed).
  local name="$1" faildetail="$2"; shift 3 # name, detail, "--"
  local log="$LOG_DIR/$name.log"
  if "$@" >"$log" 2>&1; then
    record "$name" passed "ok (log: ${log#$PROJECT/})"
  else
    record "$name" failed "$faildetail; see ${log#$PROJECT/}: $(tail -c 400 "$log" | tr '\n' ' ')"
    exit 1
  fi
}

update_context() {
  # update_context <bundle> <pubkey> <package> <installer_run>
  "$PY" - "$WORK/context.json" "$1" "$2" "$3" "$4" <<'PY'
import json, sys
from pathlib import Path

Path(sys.argv[1]).write_text(json.dumps({
    "bundle": sys.argv[2] or None,
    "pubkey": sys.argv[3] or None,
    "package": sys.argv[4] or None,
    "installer_run": sys.argv[5],
}, indent=2))
PY
}

finalize() {
  # EXIT trap: always write the evidence JSON, preserving the exit code.
  local rc=$?
  local status="passed"
  if [ "$FAILED" -ne 0 ] || [ "$rc" -ne 0 ]; then status="failed"; fi
  "$PY" - "$CHECKS_TSV" "$EVIDENCE_JSON" "$status" "$PROJECT" <<'PY'
import json, platform, sys
from datetime import datetime, timezone
from pathlib import Path

checks_tsv, out_path, status, project = (
    Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3], Path(sys.argv[4]))
checks = []
for raw in checks_tsv.read_text().splitlines():
    name, chk_status, detail = (raw.split("\t", 2) + [""])[:3]
    checks.append({"name": name, "status": chk_status, "detail": detail})
installer_run = "not_run"
ctx_path = checks_tsv.parent / "context.json"
ctx = json.loads(ctx_path.read_text()) if ctx_path.is_file() else {}
if ctx.get("installer_run"):
    installer_run = ctx["installer_run"]
doc = {
    "gate": "pkg",
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "status": status,
    "host": {"system": platform.system(), "machine": platform.machine(),
             "python": platform.python_version()},
    "bundle": ctx.get("bundle"),
    "pubkey": ctx.get("pubkey"),
    "package": ctx.get("package"),
    "installer_run": installer_run,
    "checks": checks,
}
out_path.write_text(json.dumps(doc, indent=2) + "\n")
print(f"==> evidence written to {out_path} (status: {status})")
PY
  exit "$rc"
}
trap finalize EXIT

# ---------------------------------------------------------------- prerequisites
echo "==> pkg gate starting (project: $PROJECT)"
PREREQ_OK=1
for tool in pkgbuild productbuild pkgutil openssl plutil installer; do
  command -v "$tool" > /dev/null 2>&1 || { echo "missing required tool: $tool"; PREREQ_OK=0; }
done
[ -x "$PY" ] || { echo "missing venv python: $PY"; PREREQ_OK=0; }
[ -f "$TRUSTED_VERIFIER" ] || { echo "missing trusted verifier: $TRUSTED_VERIFIER"; PREREQ_OK=0; }
[ -f "$BUILD_PKG" ] || { echo "missing package builder: $BUILD_PKG"; PREREQ_OK=0; }
[ -f "$PLIST_SRC" ] || { echo "missing launchd plist: $PLIST_SRC"; PREREQ_OK=0; }
if [ "$PREREQ_OK" -eq 1 ]; then
  record prerequisites passed "pkgbuild/productbuild/pkgutil/openssl/plutil/installer + venv python + trusted verifier + build_pkg.sh present"
else
  record prerequisites failed "required tooling missing (see gate output above)"
  exit 1
fi

# ------------------------------------------------- acquire a signed macos bundle
# The .pkg is the macOS artifact, so its payload MUST be a macos-arm64-cp312
# signed bundle. Reuse one when present (UDBMCP_BUNDLE or a previous gate run
# under out/bundle-macos/); otherwise build one with an EPHEMERAL Ed25519 key
# (local test convenience, never a release trust anchor) exactly as
# scripts/test_airgap.sh does for the Linux gate.
BUNDLE="${UDBMCP_BUNDLE:-}"
PUBKEY="${UDBMCP_PUBKEY:-}"
BOOTSTRAP_KEYS="$OUT/pkg-bootstrap"
BUNDLE_ROOT="$OUT/bundle-macos"

if [ -z "$BUNDLE" ]; then
  BUNDLE="$(ls -d "$BUNDLE_ROOT"/universal-db-mcp-*-macos-arm64-cp312 2>/dev/null | head -1 || true)"
fi

if [ -n "$BUNDLE" ]; then
  # Reuse path: a bundle without a matching pubkey cannot be authenticity
  # checked, so refuse (fail closed) rather than packaging an unverified payload.
  if [ -z "$PUBKEY" ] && [ -f "$BOOTSTRAP_KEYS/release-pubkey.pem" ]; then
    PUBKEY="$BOOTSTRAP_KEYS/release-pubkey.pem"
  fi
  if [ -z "$PUBKEY" ]; then
    record bundle_source failed "reusing bundle $BUNDLE but no public key available; set UDBMCP_PUBKEY (trusted channel) or remove the bundle to force an ephemeral-key rebuild"
    exit 1
  fi
  record bundle_source passed "reusing existing bundle: $BUNDLE"
else
  echo "==> no existing macos bundle; building one (staging machine, network allowed here)"
  mkdir -p "$BOOTSTRAP_KEYS"
  if [ -n "${UDBMCP_RELEASE_KEY:-}" ] && [ -f "$UDBMCP_RELEASE_KEY" ]; then
    SIGNING_KEY="$UDBMCP_RELEASE_KEY"
    echo "==> signing bundle with UDBMCP_RELEASE_KEY"
  else
    SIGNING_KEY="$BOOTSTRAP_KEYS/ephemeral-signing-key.pem"
    echo "==> UDBMCP_RELEASE_KEY not set; generating an EPHEMERAL signing key (local test convenience, not a release trust anchor)"
    "$PY" - "$SIGNING_KEY" <<'PY'
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

key = Ed25519PrivateKey.generate()
key_path = Path(sys.argv[1])
key_path.write_bytes(
    key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
)
key_path.chmod(0o600)
PY
  fi
  PUBKEY="$BOOTSTRAP_KEYS/release-pubkey.pem"
  "$PY" - "$SIGNING_KEY" "$PUBKEY" <<'PY'
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization

key = serialization.load_pem_private_key(Path(sys.argv[1]).read_bytes(), password=None)
Path(sys.argv[2]).write_bytes(
    key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
)
PY
  require bundle_build "prepare_offline_bundle.py --profile macos-arm64-cp312 failed" -- \
    "$PY" "$PROJECT/scripts/prepare_offline_bundle.py" \
    --profile macos-arm64-cp312 \
    --out "$BUNDLE_ROOT" \
    --source-rev "$(date -u +%Y%m%d%H%M%S)" \
    --signing-key "$SIGNING_KEY"
  BUNDLE="$(ls -d "$BUNDLE_ROOT"/universal-db-mcp-*-macos-arm64-cp312 | head -1)"
  record bundle_source passed "built signed macos-arm64-cp312 bundle: $BUNDLE"
fi

[ -f "$BUNDLE/SIGNATURE" ] || { record bundle_signed failed "bundle has no SIGNATURE: $BUNDLE (unsigned bundles are never packaged)"; exit 1; }

# ------------------------------------------------- verify the SOURCE bundle first
# Trust invariant (1): nothing downstream may proceed before a trusted-channel
# verify_bundle.py --pubkey run has passed. The pkg build re-verifies too; this
# is the gate's independent confirmation on the staging side.
require source_bundle_verified "trusted verifier rejected the source bundle" -- \
  "$PY" "$TRUSTED_VERIFIER" --bundle "$BUNDLE" --pubkey "$PUBKEY"

# Record gate context early so even an early failure yields a complete
# evidence document (installer_run defaults to the honest "not_run").
update_context "$BUNDLE" "$PUBKEY" "" "not_run"

# --------------------------------------------------------------------- build pkg
BUILD_MARKER="$WORK/build.started"
: > "$BUILD_MARKER"
echo "==> building .pkg from: $BUNDLE"
require pkg_built "build_pkg.sh failed" -- \
  bash "$BUILD_PKG" "$BUNDLE" --pubkey "$PUBKEY"

# Locate the freshly built package: explicit override wins, else the newest
# *.pkg under the conventional output roots newer than the build marker.
PKG="${UDBMCP_PKG_PATH:-}"
if [ -z "$PKG" ]; then
  PKG="$(find "$OUT" "$PROJECT/dist" -maxdepth 3 -name '*.pkg' -type f -newer "$BUILD_MARKER" 2>/dev/null | head -1 || true)"
fi
if [ -n "$PKG" ] && [ -f "$PKG" ]; then
  record package_located passed "$PKG"
  update_context "$BUNDLE" "$PUBKEY" "$PKG" "not_run"
else
  record package_located failed "no *.pkg newer than the build marker found under out/ or dist/; set UDBMCP_PKG_PATH if build_pkg.sh writes elsewhere"
  exit 1
fi

# ------------------------------------------------------------- expand and inspect
# build_pkg.sh wraps the component pkg with productbuild, so the expanded
# product archive carries the component's Payload/Scripts under the embedded
# component directory. Locate them generically; exactly one of each is expected.
EXPANDED="$WORK/expanded"
require pkg_expanded "pkgutil --expand-full failed" -- \
  pkgutil --expand-full "$PKG" "$EXPANDED"
PAYLOAD="$(find "$EXPANDED" -type d -name Payload | head -1 || true)"
if [ -n "$PAYLOAD" ] && [ "$(find "$EXPANDED" -type d -name Payload | wc -l | tr -d ' ')" = "1" ]; then
  record payload_present passed "payload at ${PAYLOAD#$EXPANDED/}"
else
  record payload_present failed "expanded package must contain exactly one Payload directory (found: $(find "$EXPANDED" -type d -name Payload | wc -l | tr -d ' '))"
  exit 1
fi

PBUNDLE="$(find "$PAYLOAD" -type f -name manifest.json | head -1 || true)"
if [ -n "$PBUNDLE" ]; then
  PBUNDLE="$(dirname "$PBUNDLE")"
  if [ "$(find "$PAYLOAD" -type f -name manifest.json | wc -l | tr -d ' ')" != "1" ]; then
    PBUNDLE=""
  fi
fi
if [ -n "$PBUNDLE" ]; then
  record payload_bundle_present passed "payload bundle at ${PBUNDLE#$PAYLOAD/}"
else
  record payload_bundle_present failed "payload must contain exactly one bundle (a universal-db-mcp-* dir with manifest.json) under /usr/local/universal-db-mcp/bundle/"
  exit 1
fi

# Payload bundle contents: SHA256SUMS + SIGNATURE + wheelhouse + runtime.lock
# + the ONE installer implementation, all present in the packaged bundle.
MISSING=""
for rel in SHA256SUMS SIGNATURE manifest.json requirements/runtime.lock installers/install_offline.sh; do
  [ -e "$PBUNDLE/$rel" ] || MISSING="$MISSING $rel"
done
WHEEL_COUNT="$(find "$PBUNDLE/wheelhouse" -name '*.whl' 2>/dev/null | wc -l | tr -d ' ')"
if [ -z "$MISSING" ] && [ "$WHEEL_COUNT" -gt 0 ]; then
  record payload_bundle_contents passed "SHA256SUMS + SIGNATURE + manifest + runtime.lock + installer present; wheelhouse has $WHEEL_COUNT wheels"
else
  record payload_bundle_contents failed "payload bundle incomplete; missing:${MISSING:- none} wheelhouse wheels: $WHEEL_COUNT"
  exit 1
fi

# Payload profile must be the macOS profile (the .pkg is the macOS artifact).
PPROFILE="$("$PY" -c 'import json,sys; print(json.load(open(sys.argv[1]))["profile"])' "$PBUNDLE/manifest.json")"
if [ "$PPROFILE" = "macos-arm64-cp312" ]; then
  record payload_profile passed "payload bundle profile: $PPROFILE"
else
  record payload_profile failed "payload bundle profile is '$PPROFILE', expected macos-arm64-cp312"
  exit 1
fi

# ------------------------------------- trusted verifier against the PAYLOAD bundle
# The decisive check: the payload inside the package is byte-for-byte the
# signed bundle the admin's trusted channel already cleared. Uses the trusted
# repo verifier, NEVER the payload's own copy (trust invariant 1).
require payload_signature_verified "trusted verifier rejected the payload bundle" -- \
  "$PY" "$TRUSTED_VERIFIER" --bundle "$PBUNDLE" --pubkey "$PUBKEY"

# ------------------------------------------------- no key material in the package
# Trust invariant (2): the release pubkey is distributed out-of-band; nothing
# resembling a key (public or private) may ship inside the package.
LEAKS="$(find "$PAYLOAD" -type f \( -name '*.pem' -o -name '*.pub' -o -name '*.key' -o -name 'release.pub*' \) | tr '\n' ' ')"
if [ -z "$LEAKS" ]; then
  record no_keys_in_payload passed "no .pem/.pub/.key/release.pub* files anywhere in the payload"
else
  record no_keys_in_payload failed "key material found in payload: $LEAKS"
  exit 1
fi

# -------------------------------------------------------------- install scripts
PREINSTALL="$(find "$EXPANDED" -type f -name preinstall | head -1 || true)"
POSTINSTALL="$(find "$EXPANDED" -type f -name postinstall | head -1 || true)"
SCRIPTS_OK=1
[ -n "$PREINSTALL" ] && [ -f "$PREINSTALL" ] || { echo "missing preinstall in expanded package"; SCRIPTS_OK=0; }
[ -n "$POSTINSTALL" ] && [ -f "$POSTINSTALL" ] || { echo "missing postinstall in expanded package"; SCRIPTS_OK=0; }
if [ "$SCRIPTS_OK" -eq 1 ]; then
  record install_scripts_present passed "Scripts/preinstall + Scripts/postinstall present in the expanded package"
else
  record install_scripts_present failed "expanded package must carry Scripts/preinstall and Scripts/postinstall"
  exit 1
fi

# Static review of the packaged scripts (they are NOT executed here):
# - preinstall validates trust prerequisites only (trusted verifier + admin
#   pubkey paths), consistent with trust invariant 1;
# - postinstall builds the venv with hostile pip env neutralized and
#   --no-index --require-hashes (trust invariant 3).
PRE_OK=1
for pat in verify_bundle release.pub.pem; do
  grep -q -e "$pat" "$PREINSTALL" 2>/dev/null || PRE_OK=0
done
POST_OK=1
for pat in '--no-index' '--require-hashes' 'PIP_CONFIG_FILE'; do
  grep -q -e "$pat" "$POSTINSTALL" 2>/dev/null || POST_OK=0
done
if [ "$PRE_OK" -eq 1 ] && [ "$POST_OK" -eq 1 ]; then
  record install_script_hardening passed "preinstall references trust prerequisites (verify_bundle + release.pub.pem); postinstall neutralizes pip (PIP_CONFIG_FILE, --no-index, --require-hashes)"
else
  record install_script_hardening failed "preinstall trust-prereq references present: $PRE_OK (need 1); postinstall pip-hardening references present: $POST_OK (need 1)"
  exit 1
fi

# ----------------------------------------------------------- launchd plist checks
PPLIST="$(find "$PAYLOAD" -path '*LaunchDaemons/*.plist' | head -1 || true)"
if [ -n "$PPLIST" ] && [ "$(find "$PAYLOAD" -path '*LaunchDaemons/*.plist' | wc -l | tr -d ' ')" = "1" ]; then
  record payload_plist_present passed "launchd plist at ${PPLIST#$PAYLOAD/}"
else
  record payload_plist_present failed "payload must contain exactly one /Library/LaunchDaemons/*.plist"
  exit 1
fi

require plist_lint "plutil -lint rejected the payload plist" -- plutil -lint "$PPLIST"

if cmp -s "$PPLIST" "$PLIST_SRC"; then
  record plist_matches_source passed "payload plist is byte-identical to packaging/launchd/com.udbmcp.server.plist"
else
  record plist_matches_source failed "payload plist differs from packaging/launchd/com.udbmcp.server.plist"
  exit 1
fi

# Values are extracted with Apple's own parser (plutil -convert json), not
# plistlib: the plist's header comment contains '--' runs, which strict XML
# parsers reject but launchd/plutil (the parsers that actually matter) accept.
PLIST_JSON="$(plutil -convert json -o - "$PPLIST")"
PLIST_VALUES="$("$PY" -c '
import json, sys
p = json.loads(sys.argv[1])
user = p.get("UserName")
umask = p.get("Umask")
config = (p.get("EnvironmentVariables") or {}).get("UDBMCP_CONFIG")
keepalive = (p.get("KeepAlive") or {}).get("SuccessfulExit")
print(f"user={user} umask={umask} config={config} keepalive_successful_exit={keepalive}")
' "$PLIST_JSON")"
PLIST_EXPECTED="user=_udbmcp umask=63 config=/etc/universal-db-mcp/config.yaml keepalive_successful_exit=False"
if [ "$PLIST_VALUES" = "$PLIST_EXPECTED" ]; then
  record plist_values passed "$PLIST_VALUES (Umask 63 decimal == 0077 octal)"
else
  record plist_values failed "got [$PLIST_VALUES] expected [$PLIST_EXPECTED]"
  exit 1
fi

# ------------------------------------------------- launchd identity cross-check
# launchd registers the daemon under the PLIST's Label key, while postinstall's
# service lifecycle (launchctl bootout/bootstrap/print and the admin-facing
# messages) drives its own LABEL variable. If these diverge, every
# upgrade/reinstall with the daemon loaded aborts: bootout targets a
# nonexistent label, bootstrap fails "already bootstrapped", and the fallback
# print fails too — so postinstall exits 1 and the install fails closed but
# unrecoverable via its own remediation hint. The plist's Label must also equal
# the installed filename stem (/Library/LaunchDaemons/<stem>.plist), which is
# the path postinstall bootstraps. Assert all three are one identity.
PLIST_LABEL="$("$PY" -c 'import json,sys; print(json.loads(sys.argv[1]).get("Label", ""))' "$PLIST_JSON")"
POSTINSTALL_LABEL="$(sed -n 's/^LABEL="\([^"]*\)".*$/\1/p' "$POSTINSTALL" | head -1)"
PLIST_STEM="$(basename "$PPLIST" .plist)"
if [ -n "$PLIST_LABEL" ] \
  && [ "$PLIST_LABEL" = "$POSTINSTALL_LABEL" ] \
  && [ "$PLIST_LABEL" = "$PLIST_STEM" ]; then
  record launchd_label_consistency passed "plist Label == postinstall LABEL == plist filename stem: $PLIST_LABEL"
else
  record launchd_label_consistency failed "launchd identity mismatch: plist Label='$PLIST_LABEL' postinstall LABEL='$POSTINSTALL_LABEL' plist filename stem='$PLIST_STEM' (all three must be equal, else upgrades abort at launchctl bootstrap)"
  exit 1
fi

# ----------------------------------------------------------- native unit suite
# Repository code only (never the payload). The suite includes the packaging
# and hardening gate tests owned by the builder workflow.
require unit_suite "tests/unit did not pass natively" -- \
  bash -c "cd '$PROJECT' && '$PY' -m pytest tests/unit -q"

# ------------------------------------------------- optional full installer run
# OFF by default: `sudo installer -pkg` really installs the service on this
# machine. Behind UDBMCP_PKG_INSTALL=1 it runs and its result is recorded;
# otherwise the evidence carries the honest "not_run".
INSTALLER_LOG="$LOG_DIR/installer_run.log"
if [ "${UDBMCP_PKG_INSTALL:-0}" = "1" ]; then
  echo "==> UDBMCP_PKG_INSTALL=1: running full installer (sudo installer -pkg)"
  if sudo installer -pkg "$PKG" -target / >"$INSTALLER_LOG" 2>&1; then
    record installer_run passed "sudo installer -pkg succeeded (log: ${INSTALLER_LOG#$PROJECT/})"
    CONTEXT_INSTALLER="passed (log: ${INSTALLER_LOG#$PROJECT/})"
  else
    record installer_run failed "sudo installer -pkg failed; see ${INSTALLER_LOG#$PROJECT/}: $(tail -c 400 "$INSTALLER_LOG" | tr '\n' ' ')"
    CONTEXT_INSTALLER="failed (log: ${INSTALLER_LOG#$PROJECT/})"
  fi
else
  CONTEXT_INSTALLER="not_run"
  echo "==> full installer run skipped (set UDBMCP_PKG_INSTALL=1 to run 'sudo installer -pkg')"
fi

# ------------------------------------------------------------- final context json
# Refresh the evidence context with the located package + installer outcome.
update_context "$BUNDLE" "$PUBKEY" "$PKG" "$CONTEXT_INSTALLER"

if [ "$FAILED" -eq 0 ]; then
  echo "==> pkg gate PASSED (package: $PKG)"
else
  echo "==> pkg gate FAILED (evidence: $EVIDENCE_JSON)"
  exit 1
fi
