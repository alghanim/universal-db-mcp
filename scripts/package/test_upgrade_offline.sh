#!/usr/bin/env bash
# Gate: offline UPGRADE happy path (gap 31 — install is gate-covered by
# scripts/test_airgap.sh and the deb/pkg gates; the upgrade flow was not).
#
# Proves, end to end inside the verified baseline container (no registry, no
# network at run time), that scripts/upgrade_offline.sh performs the full
# verify -> stage -> re-verify -> os-packages -> venv switch -> post-switch
# doctor sequence against a NEWLY SIGNED second bundle:
#
#   1. acquire a signed linux-x86_64-ubuntu24.04-cp312 bundle (reuse the
#      existing out/bundle release, verified with UDBMCP_PUBKEY when given,
#      or build one), clone it as v1 re-signed with an EPHEMERAL key pair made
#      for this run only (never a release or demo key), and verify v1 through
#      the trusted-channel verifier BEFORE anything runs;
#   2. build bundle v2: a clone of v1 with a distinct source_rev and the next
#      release_seq in manifest.json, freshly regenerated SHA256SUMS and a NEW
#      detached Ed25519 SIGNATURE (i.e. a genuinely newer signed release, not
#      a reused artifact) — verified host-side before it is mounted;
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
#      - anti-rollback: upgrade_offline.sh with the OLDER v1 is refused
#        ("rollback refused") and the installed manifest stays v2's;
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
#     source_rev, next release_seq) with an identical wheelhouse —
#     sufficient to prove the verify/stage/re-verify/switch flow consumed a
#     NEW signed release;
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

# ------------------------------------------------------ ephemeral signing key
# Both bundles are re-signed with a key pair generated for THIS run only,
# inside $WORK (removed by the EXIT trap). The gate never loads a release or
# demo private key: re-signing a doctored manifest (a bumped release_seq) with
# a key some site trusts would mint an installable release. As a guard, the
# generated key is refused if it matches a configured production anchor
# (UDBMCP_PUBKEY, or this host's installed release key).
SIGNING_KEY="$WORK/ephemeral-signing-key.pem"
PUBKEY="$WORK/ephemeral-release-pubkey.pem"
require ephemeral_key "could not generate an ephemeral signing key distinct from the production anchors" -- \
  "$PY" - "$SIGNING_KEY" "$PUBKEY" "${UDBMCP_PUBKEY:-}" /etc/universal-db-mcp/keys/release.pub.pem <<'PY'
import hashlib
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def fingerprint(public_key) -> str:
    der = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


key = Ed25519PrivateKey.generate()
key_path, pub_path = Path(sys.argv[1]), Path(sys.argv[2])
key_path.write_bytes(
    key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
)
key_path.chmod(0o600)
pub_path.write_bytes(
    key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
)
fp = fingerprint(key.public_key())
for anchor in (Path(a) for a in sys.argv[3:] if a):
    if anchor.is_file() and fingerprint(serialization.load_pem_public_key(anchor.read_bytes())) == fp:
        sys.exit(f"refusing to sign with a key that matches the production anchor {anchor}")
print(f"ephemeral release key sha256 {fp} (this run only)")
PY

# resign_clone <src> <dst> <v1|v2>: copy a bundle and sign it with the
# ephemeral key. v1 keeps its manifest and SHA256SUMS; v2 gets a distinct
# source_rev and the NEXT release_seq (a genuinely newer signed release, or the
# upgrade's anti-rollback check refuses it), with SHA256SUMS regenerated by the
# builder's recipe. v2 prints its new source_rev.
resign_clone() {
  if cp -cR "$1" "$2" 2>/dev/null; then :; else
    rm -rf "$2"; cp -R "$1" "$2"
  fi
  "$PY" - "$2" "$SIGNING_KEY" "$3" <<'PY'
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_pem_private_key

bundle, signing_key, mode = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
sums_path = bundle / "SHA256SUMS"
if mode == "v2":
    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    old = (manifest.get("source_rev"), manifest.get("release_seq"))
    manifest["source_rev"] = "upgrade-gate-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    manifest["release_seq"] = int(manifest.get("release_seq") or 0) + 1
    manifest_path.write_text(json.dumps(manifest, indent=2))
    # Same SHA256SUMS recipe as scripts/prepare_offline_bundle.py (sorted, full
    # coverage, manifest/SIGNATURE excluded) so the trusted verifier accepts it.
    sums = []
    for f in sorted(bundle.rglob("*")):
        if f.is_file() and f.name not in ("SHA256SUMS", "SIGNATURE"):
            rel = f.relative_to(bundle)
            sums.append(f"{hashlib.sha256(f.read_bytes()).hexdigest()}  {rel}")
    sums_path.write_text("\n".join(sums) + "\n")
key = load_pem_private_key(signing_key.read_bytes(), password=None)
(bundle / "SIGNATURE").write_bytes(key.sign(sums_path.read_bytes()))
if mode == "v2":
    print(manifest["source_rev"])
    print(f"old source_rev/release_seq: {old}; new release_seq {manifest['release_seq']}", file=sys.stderr)
PY
}

# ------------------------------------------------ acquire bundle v1
# The source is an existing linux bundle (UDBMCP_BUNDLE, or out/bundle) or one
# built here. With UDBMCP_PUBKEY (the trusted-channel key it was released
# under) a reused bundle is verified first; either way the gate installs only
# re-signed CLONES, never the source itself.
SOURCE_BUNDLE="${UDBMCP_BUNDLE:-}"
if [ -z "$SOURCE_BUNDLE" ]; then
  SOURCE_BUNDLE="$(ls -d "$OUT"/bundle/universal-db-mcp-* 2>/dev/null | head -1 || true)"
fi

if [ -n "$SOURCE_BUNDLE" ]; then
  SOURCE_NOTE="its release signature not checked (no UDBMCP_PUBKEY); only re-signed clones are installed"
  if [ -n "${UDBMCP_PUBKEY:-}" ]; then
    require bundle_source_verified "trusted verifier rejected the reused bundle with UDBMCP_PUBKEY" -- \
      "$PY" "$TRUSTED_VERIFIER" --bundle "$SOURCE_BUNDLE" --pubkey "$UDBMCP_PUBKEY" --allow-platform-mismatch \
      --no-installed-manifest
    SOURCE_NOTE="verified with UDBMCP_PUBKEY first"
  fi
  record bundle_v1_source passed "reusing existing bundle: $SOURCE_BUNDLE ($SOURCE_NOTE)"
else
  echo "==> no existing linux bundle; building one (staging machine, network allowed here)"
  require bundle_v1_build "prepare_offline_bundle.py failed" -- \
    "$PY" "$PROJECT/scripts/prepare_offline_bundle.py" \
    --out "$OUT/bundle" \
    --source-rev "$(date -u +%Y%m%d%H%M%S)" \
    --signing-key "$SIGNING_KEY"
  SOURCE_BUNDLE="$(ls -d "$OUT"/bundle/universal-db-mcp-* | head -1)"
  record bundle_v1_source passed "built signed bundle: $SOURCE_BUNDLE"
fi

[ -f "$SOURCE_BUNDLE/SIGNATURE" ] || { record bundle_v1_signed failed "bundle has no SIGNATURE: $SOURCE_BUNDLE (unsigned bundles are never installed)"; exit 1; }
BUNDLE_V1="$WORK/bundle-v1"
require bundle_v1_resigned "re-signing the v1 clone with the ephemeral key failed" -- \
  resign_clone "$SOURCE_BUNDLE" "$BUNDLE_V1" v1

# ------------------------------------------------- verify the SOURCE bundle first
# Trust invariant (1): nothing downstream may proceed before a trusted-channel
# verify_bundle.py --pubkey run has passed. --allow-platform-mismatch is the
# documented staging-side mode (this host may be macOS/arm64); the ENFORCING
# verification happens in the container, on the bundle's own platform, before
# and inside install/upgrade. Every gate verification passes
# --no-installed-manifest: a release installed on the machine running the
# gate never decides it.
require bundle_v1_verified "trusted verifier rejected bundle v1" -- \
  "$PY" "$TRUSTED_VERIFIER" --bundle "$BUNDLE_V1" --pubkey "$PUBKEY" --allow-platform-mismatch --no-installed-manifest

update_context bundle_v1 "$BUNDLE_V1"
update_context bundle_source "$SOURCE_BUNDLE"
update_context pubkey "$PUBKEY"

# ------------------------------------------------------------- build bundle v2
# A clone of v1 with a distinct source_rev, the next release_seq, regenerated
# SHA256SUMS and a NEW detached signature: a genuinely newer signed release
# for the upgrade to consume.
BUNDLE_V2="$WORK/bundle-v2"
echo "==> building bundle v2 (re-signed clone with a new source_rev and release_seq)"
V2_REV="$(resign_clone "$BUNDLE_V1" "$BUNDLE_V2" v2)" \
  || { record bundle_v2_built failed "v2 re-sign failed; see upgrade gate output"; exit 1; }
update_context bundle_v2 "$BUNDLE_V2"
update_context bundle_v2_source_rev "$V2_REV"

[ -n "$V2_REV" ] || { record bundle_v2_built failed "v2 has no source_rev"; exit 1; }
record bundle_v2_built passed "re-signed clone with source_rev=$V2_REV and the next release_seq (new SIGNATURE over regenerated SHA256SUMS)"

require bundle_v2_verified "trusted verifier rejected the NEW bundle v2" -- \
  "$PY" "$TRUSTED_VERIFIER" --bundle "$BUNDLE_V2" --pubkey "$PUBKEY" --allow-platform-mismatch --no-installed-manifest

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

# --- anti-rollback: the older signed v1 is refused over the installed v2 ------
V2_REV_IN="$(python3 -c "import json;print(json.load(open('$V2/manifest.json'))['source_rev'])")"
if bash "$TRUST/upgrade_offline.sh" "$V1" "$TARGET" /var/backups/universal-db-mcp \
    > /tmp/downgrade.log 2>&1; then
  rec downgrade_refused failed "upgrade_offline.sh ACCEPTED the older bundle v1 over the installed v2; log: /evidence/downgrade.log"
elif grep -q "FAIL: rollback refused" /tmp/downgrade.log \
    && [ "$(python3 -c "import json;print(json.load(open('$TARGET/manifest.json'))['source_rev'])")" = "$V2_REV_IN" ]; then
  rec downgrade_refused passed "upgrade_offline.sh refused v1 over v2 ('rollback refused'); the installed manifest is still v2's"
else
  rec downgrade_refused failed "downgrade to v1 failed without the rollback refusal, or the installed manifest changed: $(tail -c 300 /tmp/downgrade.log | tr '\n' ' ')"
fi
cp /tmp/downgrade.log "$EV/downgrade.log" 2>/dev/null || true

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
