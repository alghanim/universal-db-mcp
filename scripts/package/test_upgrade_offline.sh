#!/usr/bin/env bash
# Gate: offline UPGRADE happy path (gap 31 — install is gate-covered by
# scripts/test_airgap.sh and the deb/pkg gates; the upgrade flow was not).
#
# Proves, end to end inside the verified baseline container (no registry, no
# network at run time), that scripts/upgrade_offline.sh performs the full
# verify -> stage -> re-verify -> os-packages -> venv switch -> post-switch
# doctor sequence against a NEWLY SIGNED second bundle:
#
#   1. acquire a signed linux-x86_64-ubuntu24.04-cp312 bundle v1 (reuse the
#      existing out/bundle release or build one with an EPHEMERAL key, exactly
#      like scripts/test_airgap.sh and the deb gate) and verify it through the
#      trusted-channel verifier BEFORE anything runs;
#   2. build bundle v2: a clone of v1 with a distinct source_rev in
#      manifest.json, freshly regenerated SHA256SUMS and a NEW detached
#      Ed25519 SIGNATURE (i.e. a genuinely new signed release, not a reused
#      artifact) — verified host-side before it is mounted;
#   3. POSITIVE case, docker --network none --platform linux/amd64:
#      - admin trust bootstrap at the documented paths (trusted channel
#        mounted at /trust, NEVER the bundle itself);
#      - install_offline.sh v1: verify-then-use install, --no-index
#        --require-hashes pip, os-packages via the shared dpkg helper;
#      - demo fixture + config at /etc/universal-db-mcp/config.yaml;
#      - protocol_probe.py against the v1 venv;
#      - upgrade_offline.sh v2 (run from the trust dir, as documented): both
#        verifier invocations pass, the venv is switched atomically;
#      - assert the switch artifacts (venv.previous + its rollback integrity
#        manifest), doctor and protocol_probe against the UPGRADED venv, and
#        that the bundle's OS packages are still dpkg-"installed" (the
#        version-aware helper handled them during the upgrade);
#      - rollback_offline.sh: verify-then-use restore of the demoted venv and
#        a protocol probe against it.
#
# Every check result is recorded; any failure fails the gate closed and the
# evidence JSON is still written. Machine-readable evidence lands in
# out/package-evidence/upgrade/results.json with container logs beside it.
#
# Honest limitations (recorded in the evidence):
#   - the container has no systemd as PID 1, so the guarded systemctl
#     stop/start calls in upgrade_offline.sh are exercised only as no-ops;
#   - "new bundle" here differs from v1 by a re-signed manifest (new
#     source_rev) with an identical wheelhouse — sufficient to prove the
#     verify/stage/re-verify/switch flow consumed a NEW signed release;
#     a wheel-content change would not alter any decision the upgrade makes.
set -euo pipefail

PROJECT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$PROJECT/out"
EVIDENCE_DIR="$OUT/package-evidence/upgrade"
LOG_DIR="$EVIDENCE_DIR/logs"
EVIDENCE_JSON="$EVIDENCE_DIR/results.json"
PY="$PROJECT/.venv/bin/python"
TRUSTED_VERIFIER="$PROJECT/scripts/verify_bundle.py"
IMAGE="udbmcp-baseline:ubuntu24.04-cp312"

mkdir -p "$EVIDENCE_DIR" "$LOG_DIR"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/udbmcp-upgrade-gate.XXXXXX")"
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
  # update_context <key> <value>  (accumulates into $WORK/context.json)
  "$PY" - "$WORK/context.json" "$1" "$2" <<'PY'
import json, sys
from pathlib import Path

ctx_path = Path(sys.argv[1])
ctx = json.loads(ctx_path.read_text()) if ctx_path.is_file() else {}
ctx[sys.argv[2]] = sys.argv[3] or None
ctx_path.write_text(json.dumps(ctx, indent=2))
PY
}

merge_container_checks() {
  # merge_container_checks <container-checks.tsv> <container-rc> <label>
  local tsv="$1" rc="$2" label="$3"
  if [ -f "$tsv" ]; then
    cat "$tsv" >> "$CHECKS_TSV"
    if awk -F'\t' '$2 == "failed" { found = 1 } END { exit found ? 0 : 1 }' "$tsv"; then
      FAILED=1
    fi
  fi
  if [ "$rc" -ne 0 ]; then
    record "container_${label}_exit" failed "container exited rc=$rc (full output: logs/${label}-container.log)"
  else
    record "container_${label}_exit" passed "container exited cleanly"
  fi
}

finalize() {
  # EXIT trap: always write the evidence JSON, preserving the exit code.
  local rc=$?
  local status="passed"
  if [ "$FAILED" -ne 0 ] || [ "$rc" -ne 0 ]; then status="failed"; fi
  "$PY" - "$CHECKS_TSV" "$EVIDENCE_JSON" "$status" "$PROJECT" "$EVIDENCE_DIR" "$WORK" <<'PY'
import json, platform, sys
from datetime import datetime, timezone
from pathlib import Path

checks_tsv, out_path, status, project, evid, work = (
    Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3], Path(sys.argv[4]),
    Path(sys.argv[5]), Path(sys.argv[6]))
checks = []
for raw in checks_tsv.read_text().splitlines():
    name, chk_status, detail = (raw.split("\t", 2) + [""])[:3]
    checks.append({"name": name, "status": chk_status, "detail": detail})
ctx = json.loads((work / "context.json").read_text()) if (work / "context.json").is_file() else {}
extras = {}
for extra, key in (("doctor-after-upgrade.json", "doctor_after_upgrade"),
                   ("protocol-probe-v2.json", "protocol_probe_v2"),
                   ("protocol-probe-rollback.json", "protocol_probe_after_rollback")):
    p = evid / extra
    if p.is_file():
        try:
            extras[key] = json.loads(p.read_text())
        except json.JSONDecodeError:
            extras[key] = "present but not valid JSON (see evidence dir)"
doc = {
    "gate": "upgrade",
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "status": status,
    "host": {"system": platform.system(), "machine": platform.machine(),
             "python": platform.python_version()},
    "bundle_v1": ctx.get("bundle_v1"),
    "bundle_v2": ctx.get("bundle_v2"),
    "bundle_v2_source_rev": ctx.get("bundle_v2_source_rev"),
    "pubkey": ctx.get("pubkey"),
    "container": {"image": "udbmcp-baseline:ubuntu24.04-cp312",
                  "network": "none (docker --network none)",
                  "platform": "linux/amd64"},
    "systemd_stop_start": "not_run (container gate: no systemd as PID 1; "
                          "upgrade_offline.sh's guarded systemctl calls are no-ops here)",
    "checks": checks,
    **extras,
}
out_path.write_text(json.dumps(doc, indent=2) + "\n")
print(f"==> evidence written to {out_path} (status: {status})")
PY
  rm -rf "$WORK"
  exit "$rc"
}
trap finalize EXIT

# ---------------------------------------------------------------- prerequisites
echo "==> upgrade gate starting (project: $PROJECT)"
PREREQ_OK=1
command -v docker > /dev/null 2>&1 || { echo "missing required tool: docker"; PREREQ_OK=0; }
[ -x "$PY" ] || { echo "missing venv python: $PY"; PREREQ_OK=0; }
[ -f "$TRUSTED_VERIFIER" ] || { echo "missing trusted verifier: $TRUSTED_VERIFIER"; PREREQ_OK=0; }
# The trusted-channel tools the gate installs into the container's admin trust
# dir — exactly the layout documented in docs/offline-deployment.md.
for trust_src in "$PROJECT/scripts/install_offline.sh" "$PROJECT/scripts/upgrade_offline.sh" \
                 "$PROJECT/scripts/rollback_offline.sh" "$PROJECT/scripts/lib/os_packages.sh" \
                 "$PROJECT/scripts/profiles.py"; do
  [ -f "$trust_src" ] || { echo "missing trusted-channel file: $trust_src"; PREREQ_OK=0; }
done
if [ "$PREREQ_OK" -eq 1 ]; then
  record prerequisites passed "docker + venv python + trusted verifier + trusted-channel tools present"
else
  record prerequisites failed "required tooling missing (see gate output above)"
  exit 1
fi

# ------------------------------------------------ acquire signed bundle v1
BUNDLE_V1="${UDBMCP_BUNDLE:-}"
PUBKEY="${UDBMCP_PUBKEY:-}"
BOOTSTRAP_KEYS="$OUT/upgrade-gate-bootstrap"
SIGNING_KEY="${UDBMCP_RELEASE_KEY:-}"

if [ -z "$BUNDLE_V1" ]; then
  BUNDLE_V1="$(ls -d "$OUT"/bundle/universal-db-mcp-* 2>/dev/null | head -1 || true)"
fi

if [ -n "$BUNDLE_V1" ]; then
  # Reuse path: the existing bundle was signed with the demo release key pair
  # (out/demo-keys/). Without a matching pubkey the bundle cannot be
  # authenticity-checked — refuse (fail closed).
  if [ -z "$PUBKEY" ] && [ -f "$OUT/demo-keys/udbmcp-release-demo.pub.pem" ]; then
    PUBKEY="$OUT/demo-keys/udbmcp-release-demo.pub.pem"
  fi
  if [ -z "$PUBKEY" ] && [ -f "$BOOTSTRAP_KEYS/release-pubkey.pem" ]; then
    PUBKEY="$BOOTSTRAP_KEYS/release-pubkey.pem"
  fi
  if [ -z "$PUBKEY" ]; then
    record bundle_v1_source failed "reusing bundle $BUNDLE_V1 but no public key available; set UDBMCP_PUBKEY (trusted channel) or remove the bundle to force an ephemeral-key rebuild"
    exit 1
  fi
  # The private half of the same key is needed to sign the NEW bundle v2.
  if [ -z "$SIGNING_KEY" ] && [ -f "$OUT/demo-keys/udbmcp-release-demo.pem" ]; then
    SIGNING_KEY="$OUT/demo-keys/udbmcp-release-demo.pem"
  fi
  record bundle_v1_source passed "reusing existing bundle: $BUNDLE_V1"
else
  echo "==> no existing linux bundle; building one (staging machine, network allowed here)"
  mkdir -p "$BOOTSTRAP_KEYS"
  if [ -n "$SIGNING_KEY" ] && [ -f "$SIGNING_KEY" ]; then
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
  require bundle_v1_build "prepare_offline_bundle.py failed" -- \
    "$PY" "$PROJECT/scripts/prepare_offline_bundle.py" \
    --out "$OUT/bundle" \
    --source-rev "$(date -u +%Y%m%d%H%M%S)" \
    --signing-key "$SIGNING_KEY"
  BUNDLE_V1="$(ls -d "$OUT"/bundle/universal-db-mcp-* | head -1)"
  record bundle_v1_source passed "built signed bundle: $BUNDLE_V1"
fi

[ -f "$BUNDLE_V1/SIGNATURE" ] || { record bundle_v1_signed failed "bundle has no SIGNATURE: $BUNDLE_V1 (unsigned bundles are never installed)"; exit 1; }
[ -n "$SIGNING_KEY" ] && [ -f "$SIGNING_KEY" ] || {
  record bundle_v2_signing_key failed \
    "no signing key available to sign bundle v2 (set UDBMCP_RELEASE_KEY, or keep out/demo-keys/udbmcp-release-demo.pem next to the demo-signed bundle); the upgrade gate must upgrade to a NEWLY SIGNED bundle, so it fails closed here"
  exit 1
}

# ------------------------------------------------- verify the SOURCE bundle first
# Trust invariant (1): nothing downstream may proceed before a trusted-channel
# verify_bundle.py --pubkey run has passed. --allow-platform-mismatch is the
# documented staging-side mode (this host may be macOS/arm64); the ENFORCING
# verification happens in the container, on the bundle's own platform, before
# and inside install/upgrade.
require bundle_v1_verified "trusted verifier rejected bundle v1" -- \
  "$PY" "$TRUSTED_VERIFIER" --bundle "$BUNDLE_V1" --pubkey "$PUBKEY" --allow-platform-mismatch

update_context bundle_v1 "$BUNDLE_V1"
update_context pubkey "$PUBKEY"

# ------------------------------------------------------------- build bundle v2
# A clone of v1 with a distinct source_rev, regenerated SHA256SUMS and a NEW
# detached signature: a genuinely new signed release for the upgrade to consume.
BUNDLE_V2="$WORK/bundle-v2"
echo "==> building bundle v2 (re-signed clone with a new source_rev)"
if cp -cR "$BUNDLE_V1" "$BUNDLE_V2" 2>/dev/null; then :; else
  rm -rf "$BUNDLE_V2"; cp -R "$BUNDLE_V1" "$BUNDLE_V2"
fi
V2_REV="$("$PY" - "$BUNDLE_V2" "$SIGNING_KEY" <<'PY'
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

bundle, signing_key = Path(sys.argv[1]), Path(sys.argv[2])
manifest_path = bundle / "manifest.json"
manifest = json.loads(manifest_path.read_text())
old_rev = manifest.get("source_rev")
manifest["source_rev"] = "upgrade-gate-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
manifest_path.write_text(json.dumps(manifest, indent=2))

# Same SHA256SUMS recipe as scripts/prepare_offline_bundle.py (sorted, full
# coverage, manifest/SIGNATURE excluded) so the trusted verifier accepts it.
sums = []
for f in sorted(bundle.rglob("*")):
    if f.is_file() and f.name not in ("SHA256SUMS", "SIGNATURE"):
        rel = f.relative_to(bundle)
        sums.append(f"{hashlib.sha256(f.read_bytes()).hexdigest()}  {rel}")
sums_path = bundle / "SHA256SUMS"
sums_path.write_text("\n".join(sums) + "\n")

# Same signing recipe as prepare_offline_bundle.sign_sha256sums (openssl first,
# loud cryptography fallback).
sig_path = bundle / "SIGNATURE"
sig_path.unlink(missing_ok=True)
sig = subprocess.run(
    ["openssl", "pkeyutl", "-sign", "-inkey", str(signing_key), "-rawin",
     "-in", str(sums_path), "-out", str(sig_path)],
    capture_output=True,
)
if sig.returncode != 0:
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    key = load_pem_private_key(signing_key.read_bytes(), password=None)
    sig_path.write_bytes(key.sign(sums_path.read_bytes()))
print(manifest["source_rev"])
print(f"old source_rev: {old_rev}", file=sys.stderr)
PY
)" || { record bundle_v2_built failed "v2 re-sign failed; see upgrade gate output"; exit 1; }
update_context bundle_v2 "$BUNDLE_V2"
update_context bundle_v2_source_rev "$V2_REV"

[ -n "$V2_REV" ] || { record bundle_v2_built failed "v2 has no source_rev"; exit 1; }
record bundle_v2_built passed "re-signed clone with source_rev=$V2_REV (new SIGNATURE over regenerated SHA256SUMS)"

require bundle_v2_verified "trusted verifier rejected the NEW bundle v2" -- \
  "$PY" "$TRUSTED_VERIFIER" --bundle "$BUNDLE_V2" --pubkey "$PUBKEY" --allow-platform-mismatch

# ------------------------------------------------------------- baseline image
# Offline path: load the baseline image from the bundle if not already local
# (no pull, no registry), mirroring scripts/test_airgap.sh.
if ! docker image inspect "$IMAGE" > /dev/null 2>&1; then
  TAR="$BUNDLE_V1/images/udbmcp-baseline-ubuntu24.04-cp312.tar"
  if [ -f "$TAR" ]; then
    echo "==> loading baseline image from bundle (offline path)"
    require baseline_image "docker load of the bundle's baseline image failed" -- docker load -i "$TAR"
  else
    record baseline_image failed "baseline image $IMAGE not local and no images/udbmcp-baseline-ubuntu24.04-cp312.tar in the bundle"
    exit 1
  fi
else
  record baseline_image passed "baseline image $IMAGE already local"
fi

# --------------------------------------------------- trusted channel layout
# Mounted at /trust in the container: the repo's trusted-channel scripts in the
# documented layout (lib/ next to the installers). NEVER the bundle's own copy.
TRUST_STAGE="$WORK/trust"
mkdir -p "$TRUST_STAGE/lib"
install -m 644 "$PROJECT/scripts/verify_bundle.py" "$TRUST_STAGE/"
install -m 644 "$PROJECT/scripts/profiles.py" "$TRUST_STAGE/"
install -m 755 "$PROJECT/scripts/install_offline.sh" "$TRUST_STAGE/"
install -m 755 "$PROJECT/scripts/upgrade_offline.sh" "$TRUST_STAGE/"
install -m 755 "$PROJECT/scripts/rollback_offline.sh" "$TRUST_STAGE/"
install -m 644 "$PROJECT/scripts/lib/os_packages.sh" "$TRUST_STAGE/lib/"

# --------------------------------------------------------- container gate script
cat > "$WORK/container.sh" <<'CONTAINER_EOF'
#!/bin/bash
# Positive upgrade case: trust bootstrap -> install v1 -> probe -> upgrade to
# v2 -> assert switch/probe/os-packages -> rollback -> probe. Records per-check
# TSV lines to /evidence; exits nonzero on any failed check (fail closed).
set -uo pipefail
EV=/evidence
TSV="$EV/upgrade-checks.tsv"
: > "$TSV"
FAILED=0
V1=/bundles/v1
V2=/bundles/v2
TARGET=/opt/universal-db-mcp
TRUST=/usr/local/lib/udbmcp-trust
VENV="$TARGET/venv/bin"

rec() { # name status detail
  printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$TSV"
  echo "[upgrade-gate] [$2] $1: $3"
  [ "$2" = "passed" ] || FAILED=1
}

# --- admin trust bootstrap (docs/offline-deployment.md, 'Trust bootstrap') ---
install -d -m 755 "$TRUST/lib" /etc/universal-db-mcp/keys
install -m 644 /trust/verify_bundle.py "$TRUST/"
install -m 644 /trust/profiles.py "$TRUST/"
install -m 755 /trust/install_offline.sh /trust/upgrade_offline.sh /trust/rollback_offline.sh "$TRUST/"
install -m 644 /trust/lib/os_packages.sh "$TRUST/lib/"
install -m 644 /pubkey.pem /etc/universal-db-mcp/keys/release.pub.pem
export UDBMCP_RELEASE_PUBKEY=/etc/universal-db-mcp/keys/release.pub.pem
export UDBMCP_VERIFIER="$TRUST/verify_bundle.py"
export UDBMCP_TRUST_DIR="$TRUST"
rec trust_bootstrap passed "trusted verifier + installers + lib + release pubkey installed at the documented admin paths (from the trusted channel, not the bundles)"

# --- install v1 (the documented installer, verify-then-use) -------------------
if bash "$TRUST/install_offline.sh" "$V1" "$TARGET" > /tmp/install-v1.log 2>&1; then
  rec install_v1 passed "install_offline.sh installed bundle v1 (verify -> stage -> re-verify -> hashed offline pip -> os-packages); log: /evidence/install-v1.log"
else
  rc=$?
  rec install_v1 failed "install_offline.sh failed (rc=$rc): $(tail -c 400 /tmp/install-v1.log | tr '\n' ' ')"
  exit 1
fi
cp /tmp/install-v1.log "$EV/install-v1.log"

# --- os-packages installed by the shared dpkg helper (no apt, no network) ----
OSP="$(python3 - "$V1/manifest.json" <<'PY'
import json, sys
order = json.load(open(sys.argv[1]))["os_packages"]["install_order"]
names = [entry.split("/")[-1].split("_")[0] for entry in order]
# assert the driver closure itself, not just its dependency tail
driver = next((n for n in names if n.startswith("msodbc")), None)
print(driver or (names[0] if names else ""))
PY
)"
if [ -n "$OSP" ] && dpkg -s "$OSP" > /dev/null 2>&1 \
    && [ "$(dpkg-query -W -f='${db:Status-Status}' "$OSP" 2>/dev/null)" = "installed" ]; then
  rec os_packages_after_install passed "bundled OS-package closure installed via dpkg only (e.g. $OSP is 'installed')"
else
  pending=/run/universal-db-mcp/os-packages.pending
  if [ -f "$pending" ]; then
    rec os_packages_after_install passed "NOTE: os-packages left PENDING ($pending) by os_packages.sh — recorded honestly; the upgrade step re-checks below"
  else
    rec os_packages_after_install failed "declared OS package '$OSP' is not dpkg-installed after install_offline.sh"
  fi
fi

# --- the installed manifest must be v1's --------------------------------------
V1_REV="$(python3 -c "import json;print(json.load(open('$V1/manifest.json'))['source_rev'])")"
INSTALLED_REV="$(python3 -c "import json;print(json.load(open('$TARGET/manifest.json'))['source_rev'])")"
if [ "$INSTALLED_REV" = "$V1_REV" ]; then
  rec installed_manifest_is_v1 passed "published manifest source_rev matches v1 ($V1_REV)"
else
  rec installed_manifest_is_v1 failed "published manifest source_rev '$INSTALLED_REV' != v1 '$V1_REV'"
fi

# --- demo fixture + config at the documented path -----------------------------
mkdir -p /tmp/demo /etc/universal-db-mcp
cp "$V1/config-templates/create_demo.py" "$V1/config-templates/config.template.yaml" /tmp/demo/
( cd /tmp/demo && "$VENV/python" /tmp/demo/create_demo.py --path /tmp/finlink_demo.db > /tmp/demo.log 2>&1 ) \
  || { rec demo_fixture failed "create_demo.py failed: $(tail -c 300 /tmp/demo.log | tr '\n' ' ')"; exit 1; }
cp /tmp/demo/config.yaml /etc/universal-db-mcp/config.yaml
rec demo_fixture passed "synthetic SQLite demo fixture + config at /etc/universal-db-mcp/config.yaml"

# --- protocol probe against the v1 venv ---------------------------------------
if "$VENV/python" "$V1/tests/protocol_probe.py" "$VENV/python" /tmp/finlink_demo.db \
    > "$EV/protocol-probe-v1.json" 2> "$EV/protocol-probe-v1.stderr.txt"; then
  rec protocol_probe_v1 passed "stdio MCP protocol lifecycle probe passed on the installed v1 venv"
else
  rec protocol_probe_v1 failed "v1 probe failed: $(tail -c 300 "$EV/protocol-probe-v1.stderr.txt" | tr '\n' ' ')"
fi

# --- UPGRADE to v2 (run from the trust dir, as documented) --------------------
echo "[upgrade-gate] ==> upgrade_offline.sh $V2"
if bash "$TRUST/upgrade_offline.sh" "$V2" "$TARGET" /var/backups/universal-db-mcp \
    > /tmp/upgrade.log 2>&1; then
  rec upgrade_v2 passed "upgrade_offline.sh completed: verify v2 -> stage -> re-verify staging -> os-packages -> venv build -> switch; log: /evidence/upgrade.log"
else
  rc=$?
  rec upgrade_v2 failed "upgrade_offline.sh failed (rc=$rc): $(tail -c 600 /tmp/upgrade.log | tr '\n' ' ')"
  cp /tmp/upgrade.log "$EV/upgrade.log" 2>/dev/null || true
  exit 1
fi
cp /tmp/upgrade.log "$EV/upgrade.log"
if grep -q "bundle verification FAILED\|FAIL:" /tmp/upgrade.log; then
  rec upgrade_log_clean failed "upgrade log contains FAIL lines"
else
  rec upgrade_log_clean passed "no FAIL lines in the upgrade log"
fi

# --- switch artifacts: previous venv kept for rollback WITH its manifest ------
if [ -d "$TARGET/venv.previous" ] && [ -f "$TARGET/venv.previous.sha256" ]; then
  rec rollback_artifacts passed "venv.previous kept (rollback depth 1) with the integrity manifest recorded before the rename"
else
  rec rollback_artifacts failed "expected $TARGET/venv.previous + venv.previous.sha256 after a successful switch"
fi

# --- the upgraded venv runs + doctor validates post-switch --------------------
if "$VENV/python" -m universal_db_mcp version > /tmp/version-v2.log 2>&1; then
  rec upgraded_version passed "upgraded venv responds: $(head -c 120 /tmp/version-v2.log | tr '\n' ' ')"
else
  rec upgraded_version failed "upgraded venv smoke check failed: $(tail -c 300 /tmp/version-v2.log | tr '\n' ' ')"
fi
if "$VENV/python" -m universal_db_mcp doctor --config /etc/universal-db-mcp/config.yaml \
    > "$EV/doctor-after-upgrade.json" 2> "$EV/doctor-after-upgrade.stderr.txt"; then
  rec doctor_after_upgrade passed "doctor passed against the upgraded venv"
else
  rec doctor_after_upgrade failed "doctor failed after the switch: $(tail -c 300 "$EV/doctor-after-upgrade.stderr.txt" | tr '\n' ' ')"
fi

# --- protocol probe against the UPGRADED venv ---------------------------------
if "$VENV/python" "$V2/tests/protocol_probe.py" "$VENV/python" /tmp/finlink_demo.db \
    > "$EV/protocol-probe-v2.json" 2> "$EV/protocol-probe-v2.stderr.txt"; then
  rec protocol_probe_v2 passed "stdio MCP protocol lifecycle probe passed on the UPGRADED venv"
else
  rec protocol_probe_v2 failed "v2 probe failed: $(tail -c 300 "$EV/protocol-probe-v2.stderr.txt" | tr '\n' ' ')"
fi

# --- os-packages still handled after the upgrade (version-aware, idempotent) --
if [ -n "$OSP" ] \
    && [ "$(dpkg-query -W -f='${db:Status-Status}' "$OSP" 2>/dev/null)" = "installed" ]; then
  rec os_packages_after_upgrade passed "$OSP still dpkg-'installed' after the upgrade (version-aware helper handled the closure)"
else
  rec os_packages_after_upgrade failed "declared OS package '$OSP' not installed after the upgrade"
fi

# --- rollback: verify-then-use restore of the demoted venv --------------------
if bash "$TRUST/rollback_offline.sh" "$TARGET" /var/backups/universal-db-mcp \
    > /tmp/rollback.log 2>&1; then
  rec rollback passed "rollback_offline.sh restored the demoted venv (manifest-verified before execution); log: /evidence/rollback.log"
else
  rc=$?
  rec rollback failed "rollback_offline.sh failed (rc=$rc): $(tail -c 400 /tmp/rollback.log | tr '\n' ' ')"
fi
cp /tmp/rollback.log "$EV/rollback.log" 2>/dev/null || true
if [ ! -d "$TARGET/venv.previous" ] && [ -d "$TARGET/venv" ]; then
  rec rollback_state passed "venv.previous consumed; venv in place"
else
  rec rollback_state failed "unexpected rollback end state: venv.previous=$([ -d "$TARGET/venv.previous" ] && echo present || echo absent)"
fi
if "$VENV/python" "$V1/tests/protocol_probe.py" "$VENV/python" /tmp/finlink_demo.db \
    > "$EV/protocol-probe-rollback.json" 2> "$EV/protocol-probe-rollback.stderr.txt"; then
  rec protocol_probe_after_rollback passed "protocol probe passed on the ROLLED BACK venv"
else
  rec protocol_probe_after_rollback failed "rollback probe failed: $(tail -c 300 "$EV/protocol-probe-rollback.stderr.txt" | tr '\n' ' ')"
fi

echo "[upgrade-gate] finished, FAILED=$FAILED"
exit "$FAILED"
CONTAINER_EOF

# ------------------------------------------------------------- positive case
echo "==> POSITIVE case: install v1 -> upgrade to v2 -> probe -> rollback (network: NONE, platform: linux/amd64)"
set +e
docker run --rm --network none --platform linux/amd64 \
  -v "$BUNDLE_V1":/bundles/v1:ro \
  -v "$BUNDLE_V2":/bundles/v2:ro \
  -v "$PUBKEY":/pubkey.pem:ro \
  -v "$TRUST_STAGE":/trust:ro \
  -v "$EVIDENCE_DIR":/evidence \
  -v "$WORK/container.sh":/gate/container.sh:ro \
  "$IMAGE" \
  bash /gate/container.sh > "$LOG_DIR/upgrade-container.log" 2>&1
POS_RC=$?
set -e
merge_container_checks "$EVIDENCE_DIR/upgrade-checks.tsv" "$POS_RC" "upgrade"
mv "$EVIDENCE_DIR/upgrade-checks.tsv" "$LOG_DIR/upgrade-checks.tsv" 2>/dev/null || true

# --------------------------------------------------------------------- summary
if [ "$FAILED" -eq 0 ]; then
  echo "==> upgrade gate PASSED (v1: $BUNDLE_V1 -> v2 source_rev: $V2_REV)"
else
  echo "==> upgrade gate FAILED (evidence: $EVIDENCE_JSON)"
  exit 1
fi
