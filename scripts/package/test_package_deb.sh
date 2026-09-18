#!/usr/bin/env bash
# Gate: Ubuntu .deb native package (plan Phase 4).
#
# Proves, end to end inside the verified baseline container (no registry, no
# network at run time), that the .deb built by scripts/package/build_deb.sh
# installs cleanly and honors the trust model. Sequence:
#
#   1. acquire a signed linux-x86_64-ubuntu24.04-cp312 bundle (reuse or build
#      with an EPHEMERAL key, mirroring scripts/test_airgap.sh) and verify it
#      through the trusted-channel verifier BEFORE anything is packaged
#      (trust invariant 1: no package may exist from an unverified payload);
#   2. build the .deb from the signed bundle;
#   3. POSITIVE case, docker --network none --platform linux/amd64:
#      - extract the payload with dpkg-deb -R (no execution) and assert the
#        layout (signed bundle + trusted-tools + systemd unit) and that NO key
#        material ships inside the package (trust invariant 2: the release
#        pubkey is distributed out-of-band, never packaged);
#      - simulate the admin trust bootstrap (trusted verifier + pubkey at
#        /etc/universal-db-mcp/keys/release.pub.pem) from the mounted trusted
#        channel, then dpkg -i: preinst checks the prerequisites, postinst
#        re-verifies the unpacked payload via the ONE trusted installer
#        (install_offline.sh: verify-then-use staging, --no-index
#        --require-hashes pip with PIP_CONFIG_FILE neutralized — trust
#        invariant 3). When the bundle ships os-packages/*.deb (the linux
#        profile always does), the postinst defers that dpkg-dependent
#        install to a detached root worker (a nested `dpkg -i` would deadlock
#        against the frontend lock the outer dpkg holds); the gate waits for
#        the worker's status file to report success before doctor/probe;
#      - doctor with a generated demo config;
#      - protocol_probe.py over stdio against the demo SQLite fixture;
#   4. NEGATIVE case, its own container: copy the deb, repack it with ONE
#      tampered wheel inside the payload (SHA256SUMS line refreshed so the
#      rejection comes from the SIGNATURE check, not the integrity hash);
#      dpkg -i must FAIL at postinst verification with the canonical
#      "signature verification FAILED" diagnostic (fail closed).
#   5. NEGATIVE case 2, its own container, WITHOUT the admin trust bootstrap:
#      the deb ships a trusted-tools/ copy on the same channel as the payload
#      it would verify, so the package must never self-bootstrap (or
#      "complete") /usr/local/lib/udbmcp-trust from it — a tampered package
#      would ship a tampered verifier that prints PASSED. The deb-shipped
#      verifier is stubbed with exactly such a stub and the package is
#      installed with NO admin trust dir and NO pubkey: the postinst run
#      directly (the dpkg --configure path, which bypasses preinst) must
#      refuse to self-bootstrap, and dpkg -i must abort (preinst).
#   6. NEGATIVE case 3, its own container, against a TRUNCATED trusted
#      verifier: the admin bootstrap installs verify_bundle.py from the
#      trusted channel and then truncates it to ZERO bytes. python3 on an
#      empty script exits 0 without ever running argparse (vacuous pass), so
#      exit-code-only trust would install the unverified payload and enable
#      the service. The deb must fail closed twice: the unpacked postinst run
#      directly must abort at the trust-dir completeness gate (zero-length is
#      treated like missing), and dpkg -i must abort at the preinst's
#      non-empty check — with NO 'bundle verification PASSED' anywhere, no
#      venv and no enabled service.
#   7. UPGRADE case, its own container: install, then plant a marker in a
#      wheel-tracked file of the installed venv (the previous release's code)
#      and an admin edit in /etc/universal-db-mcp/config.yaml, install the SAME
#      package again and assert the marker is gone (the trusted installer's
#      --force-reinstall replaced the code; without it pip reports "already
#      satisfied" and the site keeps running old code while dpkg reports
#      success — seen live 2026-09-15) while the admin edit survives (dpkg
#      conffile). Then swap the trusted installer for a copy WITHOUT
#      --force-reinstall: the upgrade must be refused at preinst with the
#      OUTDATED diagnostic; restore it and the upgrade must succeed again.
#
# Every check result is recorded; any failure fails the gate closed and the
# evidence JSON is still written. Machine-readable evidence lands in
# out/package-evidence/deb/results.json (per-check status incl. the negative
# case, doctor.json, protocol-probe.json and container logs beside it).
#
# Honest limitation (recorded in the evidence): the container has no systemd
# as PID 1, so `systemctl enable --now` is exercised only through the
# postinst's guarded path; real PID-1 behavior is not_run here.
set -euo pipefail

PROJECT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$PROJECT/out"
EVIDENCE_DIR="$OUT/package-evidence/deb"
LOG_DIR="$EVIDENCE_DIR/logs"
EVIDENCE_JSON="$EVIDENCE_DIR/results.json"
PY="$PROJECT/.venv/bin/python"
TRUSTED_VERIFIER="$PROJECT/scripts/verify_bundle.py"
BUILD_DEB="$PROJECT/scripts/package/build_deb.sh"
IMAGE="udbmcp-baseline:ubuntu24.04-cp312"
CONTAINER_DEB="/pkg/universal-db-mcp.deb"

mkdir -p "$EVIDENCE_DIR" "$LOG_DIR"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/udbmcp-deb-gate.XXXXXX")"
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

merge_container_checks() {
  # merge_container_checks <container-checks.tsv> <container-rc> <label>
  # Appends the in-container check records to the gate ledger; a nonzero
  # container exit adds its own failed record (fail closed).
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

update_context() {
  # update_context <bundle> <pubkey> <package>
  "$PY" - "$WORK/context.json" "$1" "$2" "$3" <<'PY'
import json, sys
from pathlib import Path

Path(sys.argv[1]).write_text(json.dumps({
    "bundle": sys.argv[2] or None,
    "pubkey": sys.argv[3] or None,
    "package": sys.argv[4] or None,
}, indent=2))
PY
}

finalize() {
  # EXIT trap: always write the evidence JSON, preserving the exit code.
  local rc=$?
  local status="passed"
  if [ "$FAILED" -ne 0 ] || [ "$rc" -ne 0 ]; then status="failed"; fi
  "$PY" - "$CHECKS_TSV" "$EVIDENCE_JSON" "$status" "$PROJECT" "$EVIDENCE_DIR" <<'PY'
import json, platform, sys
from datetime import datetime, timezone
from pathlib import Path

checks_tsv, out_path, status, project, evid = (
    Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3], Path(sys.argv[4]), Path(sys.argv[5]))
checks = []
for raw in checks_tsv.read_text().splitlines():
    name, chk_status, detail = (raw.split("\t", 2) + [""])[:3]
    checks.append({"name": name, "status": chk_status, "detail": detail})
ctx_path = checks_tsv.parent / "context.json"
ctx = json.loads(ctx_path.read_text()) if ctx_path.is_file() else {}
extras = {}
for extra, key in (("doctor.json", "doctor"), ("protocol-probe.json", "protocol_probe")):
    p = evid / extra
    if p.is_file():
        try:
            extras[key] = json.loads(p.read_text())
        except json.JSONDecodeError:
            extras[key] = "present but not valid JSON (see evidence dir)"
doc = {
    "gate": "deb",
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "status": status,
    "host": {"system": platform.system(), "machine": platform.machine(),
             "python": platform.python_version()},
    "bundle": ctx.get("bundle"),
    "pubkey": ctx.get("pubkey"),
    "package": ctx.get("package"),
    "container": {"image": "udbmcp-baseline:ubuntu24.04-cp312",
                  "network": "none (docker --network none)",
                  "platform": "linux/amd64"},
    "systemd_enable_now": "not_run (container install: no systemd as PID 1; "
                          "postinst's guarded path exercised instead)",
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
echo "==> deb gate starting (project: $PROJECT)"
PREREQ_OK=1
command -v docker > /dev/null 2>&1 || { echo "missing required tool: docker"; PREREQ_OK=0; }
[ -x "$PY" ] || { echo "missing venv python: $PY"; PREREQ_OK=0; }
[ -f "$TRUSTED_VERIFIER" ] || { echo "missing trusted verifier: $TRUSTED_VERIFIER"; PREREQ_OK=0; }
# The trusted-channel files the container's admin-bootstrap simulation installs:
# exactly the tools the release ships in trusted-tools/ (verify_bundle.py,
# install_offline.sh, lib/os_packages.sh, profiles.py).
for trust_src in "$PROJECT/scripts/install_offline.sh" "$PROJECT/scripts/lib/os_packages.sh" "$PROJECT/scripts/profiles.py"; do
  [ -f "$trust_src" ] || { echo "missing trusted-channel file: $trust_src"; PREREQ_OK=0; }
done
# The builder is a sibling artifact: required unless the caller supplies a
# pre-built package via UDBMCP_DEB.
if [ -z "${UDBMCP_DEB:-}" ] && [ ! -f "$BUILD_DEB" ]; then
  echo "missing package builder: $BUILD_DEB (or set UDBMCP_DEB to a pre-built .deb)"; PREREQ_OK=0
fi
if [ "$PREREQ_OK" -eq 1 ]; then
  record prerequisites passed "docker + venv python + trusted verifier + trusted-channel tools (+ build_deb.sh or UDBMCP_DEB) present"
else
  record prerequisites failed "required tooling missing (see gate output above)"
  exit 1
fi

# ------------------------------------------------- acquire a signed linux bundle
# The .deb payload MUST be a signed linux-x86_64-ubuntu24.04-cp312 bundle.
# Reuse one when present (UDBMCP_BUNDLE or the standard out/bundle/ location);
# otherwise build one with an EPHEMERAL Ed25519 key (local test convenience,
# never a release trust anchor) exactly as scripts/test_airgap.sh does.
BUNDLE="${UDBMCP_BUNDLE:-}"
PUBKEY="${UDBMCP_PUBKEY:-}"
BOOTSTRAP_KEYS="$OUT/deb-bootstrap"

if [ -z "$BUNDLE" ]; then
  BUNDLE="$(ls -d "$OUT"/bundle/universal-db-mcp-* 2>/dev/null | head -1 || true)"
fi

if [ -n "$BUNDLE" ]; then
  # Reuse path: the existing bundle was signed with the demo release key pair
  # (out/demo-keys/); a bundle without a matching pubkey cannot be
  # authenticity checked, so refuse (fail closed) rather than packaging an
  # unverified payload.
  if [ -z "$PUBKEY" ] && [ -f "$OUT/demo-keys/udbmcp-release-demo.pub.pem" ]; then
    PUBKEY="$OUT/demo-keys/udbmcp-release-demo.pub.pem"
  fi
  if [ -z "$PUBKEY" ] && [ -f "$BOOTSTRAP_KEYS/release-pubkey.pem" ]; then
    PUBKEY="$BOOTSTRAP_KEYS/release-pubkey.pem"
  fi
  if [ -z "$PUBKEY" ]; then
    record bundle_source failed "reusing bundle $BUNDLE but no public key available; set UDBMCP_PUBKEY (trusted channel) or remove the bundle to force an ephemeral-key rebuild"
    exit 1
  fi
  record bundle_source passed "reusing existing bundle: $BUNDLE"
else
  echo "==> no existing linux bundle; building one (staging machine, network allowed here)"
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
  require bundle_build "prepare_offline_bundle.py failed" -- \
    "$PY" "$PROJECT/scripts/prepare_offline_bundle.py" \
    --out "$OUT/bundle" \
    --source-rev "$(date -u +%Y%m%d%H%M%S)" \
    --signing-key "$SIGNING_KEY"
  BUNDLE="$(ls -d "$OUT"/bundle/universal-db-mcp-* | head -1)"
  record bundle_source passed "built signed bundle: $BUNDLE"
fi

[ -f "$BUNDLE/SIGNATURE" ] || { record bundle_signed failed "bundle has no SIGNATURE: $BUNDLE (unsigned bundles are never packaged)"; exit 1; }

# ------------------------------------------------- verify the SOURCE bundle first
# Trust invariant (1): nothing downstream may proceed before a trusted-channel
# verify_bundle.py --pubkey run has passed. --allow-platform-mismatch is the
# documented staging-side mode (this host may be macOS/arm64); the ENFORCING
# verification happens in the container, on the bundle's own platform, both
# before dpkg -i (preinst prerequisites) and inside postinst (install_offline.sh).
require source_bundle_verified "trusted verifier rejected the source bundle" -- \
  "$PY" "$TRUSTED_VERIFIER" --bundle "$BUNDLE" --pubkey "$PUBKEY" --allow-platform-mismatch

# Record gate context early so even an early failure yields a complete
# evidence document.
update_context "$BUNDLE" "$PUBKEY" ""

# --------------------------------------------------------------------- build deb
DEB="${UDBMCP_DEB:-}"
if [ -z "$DEB" ]; then
  BUILD_MARKER="$WORK/build.started"
  : > "$BUILD_MARKER"
  echo "==> building .deb from: $BUNDLE"
  BUILD_LOG="$LOG_DIR/deb_build.log"
  # Preferred invocation: bundle argument only. Some builder revisions also
  # accept the pubkey for their own source-bundle re-verification; try that
  # before giving up so the gate works with either interface.
  if bash "$BUILD_DEB" "$BUNDLE" >"$BUILD_LOG" 2>&1; then
    record deb_built passed "build_deb.sh succeeded (log: ${BUILD_LOG#$PROJECT/})"
  elif bash "$BUILD_DEB" "$BUNDLE" --pubkey "$PUBKEY" >>"$BUILD_LOG" 2>&1; then
    record deb_built passed "build_deb.sh succeeded with --pubkey (log: ${BUILD_LOG#$PROJECT/})"
  else
    record deb_built failed "build_deb.sh failed; see ${BUILD_LOG#$PROJECT/}: $(tail -c 400 "$BUILD_LOG" | tr '\n' ' ')"
    exit 1
  fi

  # Locate the freshly built package: the newest universal-db-mcp *.deb under
  # the conventional output roots newer than the build marker. build_deb.sh
  # writes universal-db-mcp_<version>_<arch>.deb (underscore after "mcp", the
  # dpkg naming convention); the bracket expression also accepts a dash so a
  # builder revision using that spelling is found too.
  DEB="$(find "$PROJECT/dist" "$OUT" -maxdepth 3 -name 'universal-db-mcp[-_]*.deb' -type f -newer "$BUILD_MARKER" 2>/dev/null | head -1 || true)"
  if [ -n "$DEB" ] && [ -f "$DEB" ]; then
    record package_located passed "$DEB"
  else
    record package_located failed "no universal-db-mcp[-_]*.deb newer than the build marker found under dist/ or out/; set UDBMCP_DEB if build_deb.sh writes elsewhere"
    exit 1
  fi
else
  [ -f "$DEB" ] || { record package_located failed "UDBMCP_DEB=$DEB does not exist"; exit 1; }
  record deb_built passed "pre-built package used via UDBMCP_DEB (build skipped)"
  record package_located passed "$DEB"
fi
update_context "$BUNDLE" "$PUBKEY" "$DEB"

# ------------------------------------------------------------- baseline image
# Offline path: load the baseline image from the bundle if not already local
# (no pull, no registry), mirroring scripts/test_airgap.sh.
if ! docker image inspect "$IMAGE" > /dev/null 2>&1; then
  TAR="$BUNDLE/images/udbmcp-baseline-ubuntu24.04-cp312.tar"
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

# ------------------------------------- negative: key material in staged root
# Trust invariant (2) at BUILD time: build_deb.sh must refuse to produce any
# package whose staged root contains key material, using the SAME name-based
# pattern set as the .pkg and .msi builders (*.pem / *pubkey* / *.key included
# — a stray key .pem, even a PRIVATE one, must abort the build too). Poison a
# COPY of the trusted-tools channel with dummy key files: the copy still
# passes source-bundle verification (the trusted channel is not
# signature-checked), is staged into the deb root verbatim, and the build must
# abort with the canonical diagnostic BEFORE any dpkg-deb run, leaving no
# artifact behind (fail closed).
NEG_STAGING="$WORK/neg-keymaterial"
NEG_OUT="$WORK/neg-out"
mkdir -p "$NEG_STAGING" "$NEG_OUT"
copy_tree() {
  # Fast copy for the 100M+ bundle: APFS clone (macOS) -> hardlink (Linux)
  # -> plain copy. Only ever read afterwards; the poison lands in the
  # trusted-tools copy, never in the bundle copy itself.
  if cp -cR "$1" "$2" 2>/dev/null; then return 0; fi
  rm -rf "$2"
  if cp -al "$1" "$2" 2>/dev/null; then return 0; fi
  rm -rf "$2"
  cp -R "$1" "$2"
}
if copy_tree "$BUNDLE" "$NEG_STAGING/bundle"; then
  NEG_TRUSTED_SRC=""
  # Mirror build_deb.sh's trusted-channel lookup (sibling first, then in-bundle).
  if [ -f "$(dirname "$BUNDLE")/trusted-tools/verify_bundle.py" ]; then
    NEG_TRUSTED_SRC="$(dirname "$BUNDLE")/trusted-tools"
  elif [ -f "$BUNDLE/trusted-tools/verify_bundle.py" ]; then
    NEG_TRUSTED_SRC="$BUNDLE/trusted-tools"
  fi
  if [ -n "$NEG_TRUSTED_SRC" ]; then
    cp -R "$NEG_TRUSTED_SRC" "$NEG_STAGING/trusted-tools"
    printf -- '-----BEGIN DUMMY KEY MATERIAL (gate negative case)-----\n' > "$NEG_STAGING/trusted-tools/x.pem"
    printf -- 'dummy key material for the gate negative case\n' > "$NEG_STAGING/trusted-tools/release.udbmcp.pubkey"
    NEG_LOG="$LOG_DIR/deb_build_rejects_key_material.log"
    echo "==> NEGATIVE (build-time): staged-root key material must abort build_deb.sh"
    set +e
    bash "$BUILD_DEB" "$NEG_STAGING/bundle" --pubkey "$PUBKEY" --out "$NEG_OUT" \
      > "$NEG_LOG" 2>&1
    NEG_RC=$?
    set -e
    NEG_FAIL=""
    [ "$NEG_RC" -ne 0 ] || NEG_FAIL="build_deb.sh exited 0 with key material staged (rc=0)"
    grep -q "public key material found in staged deb root" "$NEG_LOG" \
      || NEG_FAIL="$NEG_FAIL canonical diagnostic missing"
    grep -q "x\.pem" "$NEG_LOG" || NEG_FAIL="$NEG_FAIL '*.pem' pattern did not match x.pem"
    grep -q "release\.udbmcp\.pubkey" "$NEG_LOG" \
      || NEG_FAIL="$NEG_FAIL '*pubkey*' pattern did not match release.udbmcp.pubkey"
    [ -z "$(find "$NEG_OUT" -name '*.deb' -type f 2>/dev/null)" ] \
      || NEG_FAIL="$NEG_FAIL a .deb artifact was produced despite the abort"
    if [ -z "$NEG_FAIL" ]; then
      record build_rejects_key_material passed \
        "build_deb.sh aborted (rc=$NEG_RC) with the canonical diagnostic, listing x.pem and release.udbmcp.pubkey, and produced no .deb (log: ${NEG_LOG#$PROJECT/})"
    else
      record build_rejects_key_material failed \
        "poisoned staged root (x.pem + release.udbmcp.pubkey in trusted-tools) did not fail the build correctly: $NEG_FAIL; see ${NEG_LOG#$PROJECT/}"
      exit 1
    fi
  else
    record build_rejects_key_material failed \
      "could not stage the negative case: no trusted-tools copy found for $BUNDLE"
    exit 1
  fi
else
  record build_rejects_key_material failed "could not copy the bundle for the negative case: $BUNDLE"
  exit 1
fi
rm -rf "$NEG_STAGING" "$NEG_OUT"

# --------------------------------------------------------- container gate scripts
# Generated into $WORK and bind-mounted read-only; all in-container paths are
# constants so neither script needs host state. Both write per-check TSV
# records into the mounted evidence dir, which the host merges.

cat > "$WORK/positive.sh" <<'POSITIVE_EOF'
#!/bin/bash
# Positive case: inspect payload -> trust bootstrap -> dpkg -i -> doctor ->
# protocol probe. Records per-check TSV lines to /evidence; exits nonzero on
# any failed check (fail closed).
set -uo pipefail
EV=/evidence
TSV="$EV/positive-checks.tsv"
: > "$TSV"
FAILED=0
DEB=/pkg/universal-db-mcp.deb
BUNDLE_INSTALLED=/usr/share/universal-db-mcp/bundle
VENV=/opt/universal-db-mcp/venv/bin

rec() { # name status detail
  printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$TSV"
  echo "[deb-gate-positive] [$2] $1: $3"
  [ "$2" = "passed" ] || FAILED=1
}

# --- payload inspection (no execution) --------------------------------------
rm -rf /tmp/inspect
mkdir -p /tmp/inspect  # dpkg-deb -R creates the leaf dir but not its parents
if dpkg-deb -R "$DEB" /tmp/inspect > /tmp/extract.log 2>&1; then
  rec payload_extracted passed "dpkg-deb -R extracted the package tree (no execution)"
else
  rec payload_extracted failed "dpkg-deb -R failed: $(tail -c 300 /tmp/extract.log | tr '\n' ' ')"
  exit 1
fi

TT=/tmp/inspect/usr/share/universal-db-mcp/trusted-tools
MISSING=""
[ -f /tmp/inspect/usr/share/universal-db-mcp/bundle/manifest.json ] || MISSING="$MISSING bundle/manifest.json"
[ -f "$TT/verify_bundle.py" ] || MISSING="$MISSING trusted-tools/verify_bundle.py"
[ -f "$TT/install_offline.sh" ] || MISSING="$MISSING trusted-tools/install_offline.sh"
[ -f "$TT/lib/os_packages.sh" ] || MISSING="$MISSING trusted-tools/lib/os_packages.sh"
if [ -z "$MISSING" ]; then
  rec payload_layout passed "signed bundle + trusted-tools (verifier/installer/lib) present at /usr/share/universal-db-mcp/"
else
  rec payload_layout failed "payload incomplete; missing:$MISSING"
fi

# Trust invariant (2): the release pubkey is NEVER shipped inside the package.
# Name patterns mirror build_deb.sh's find_pubkey_material (plus *.key) so the
# scan stays equally strict on the UDBMCP_DEB pre-built-package path, which
# bypasses the builder's staged-root scan.
LEAKS="$(find /tmp/inspect -type f \( -name '*.pem' -o -name '*.pub' -o -name '*.key' -o -name 'release.pub*' -o -name '*pubkey*' \) 2>/dev/null | tr '\n' ' ')"
TEXT_LEAKS="$(grep -rIl -- 'BEGIN PUBLIC KEY\|BEGIN PRIVATE KEY' /tmp/inspect 2>/dev/null | head -3 | tr '\n' ' ')"
if [ -z "$LEAKS" ] && [ -z "$TEXT_LEAKS" ]; then
  rec no_keys_in_package passed "no .pem/.pub/.key/*pubkey*/release.pub* files and no PEM blocks anywhere in the package payload"
else
  rec no_keys_in_package failed "key material found in package payload: files=[$LEAKS] pem-text=[$TEXT_LEAKS]"
fi

# --- interpreter prerequisites the deb's Depends stand for -------------------
# The minimal baseline image ships python3.12 without the python3/python3-venv
# metapackages (a real ubuntu-24.04 target has them); assert the actual
# prerequisites here so any --force-depends below is a documented baseline
# artifact, not a hidden weakening.
if python3 -c 'import sys, ensurepip, venv; assert sys.version_info[:2] == (3, 12), sys.version' > /tmp/prereq.log 2>&1; then
  rec runtime_prereqs passed "CPython 3.12 with ensurepip+venv present"
else
  rec runtime_prereqs failed "interpreter prerequisites missing: $(tail -c 300 /tmp/prereq.log | tr '\n' ' ')"
  exit 1
fi

# --- admin trust bootstrap (equivalent of docs/offline-deployment.md) --------
# The trusted tools come from the mounted trusted channel (/trust), NEVER from
# the package being verified. dpkg's preinst requires exactly these paths.
if install -d -m 755 /usr/local/lib/udbmcp-trust/lib /etc/universal-db-mcp/keys \
   && install -m 644 /trust/verify_bundle.py /usr/local/lib/udbmcp-trust/ \
   && install -m 644 /trust/profiles.py /usr/local/lib/udbmcp-trust/ \
   && install -m 755 /trust/install_offline.sh /usr/local/lib/udbmcp-trust/ \
   && install -m 644 /trust/os_packages.sh /usr/local/lib/udbmcp-trust/lib/ \
   && install -m 644 /pubkey.pem /etc/universal-db-mcp/keys/release.pub.pem; then
  rec trust_bootstrap passed "trusted verifier + installer + lib + release pubkey installed at the documented admin paths (from the trusted channel, not the package)"
else
  rec trust_bootstrap failed "admin trust bootstrap failed (rc=$?): the trusted channel (/trust/*, /pubkey.pem) is incomplete or the mounts are broken; dpkg's preinst requires the verifier + pubkey at the documented admin paths"
  exit 1
fi

# --- dpkg -i -----------------------------------------------------------------
export DEBIAN_FRONTEND=noninteractive
dpkg -i "$DEB" > /tmp/dpkg-install.log 2>&1
rc=$?
if [ "$rc" -ne 0 ] && grep -q "dependency problems" /tmp/dpkg-install.log; then
  # Baseline-image artifact (see runtime_prereqs above): retry with the
  # dependency forcing recorded as its own check.
  echo "[deb-gate-positive] baseline image lacks the python3/python3-venv metapackages; retrying with --force-depends (recorded)"
  dpkg -i --force-depends "$DEB" >> /tmp/dpkg-install.log 2>&1
  rc=$?
  rec dependency_forcing passed "metapackage Depends forced for the minimal baseline image (real ubuntu-24.04 targets satisfy them); log: /evidence/dpkg-install.log"
else
  rec dependency_forcing passed "not needed: dpkg -i resolved Depends without forcing"
fi
cp /tmp/dpkg-install.log "$EV/dpkg-install.log"
if [ "$rc" -eq 0 ]; then
  rec deb_install passed "dpkg -i succeeded: preinst checked trust prerequisites, postinst verified the unpacked payload at configure time (the dpkg-dependent install may be deferred to a root worker; log: /evidence/dpkg-install.log)"
else
  rec deb_install failed "dpkg -i failed (rc=$rc): $(tail -c 500 /tmp/dpkg-install.log | tr '\n' ' ')"
  exit 1
fi

# --- deferred install worker ---------------------------------------------------
# When the unpacked bundle ships os-packages/*.deb (the linux-x86_64 profile
# always does), the postinst cannot run install_offline.sh inside dpkg's
# critical section: install_offline.sh installs the OS-package closure with a
# nested `dpkg -i`, which deadlocks against the frontend lock the outer dpkg
# holds for the whole `dpkg -i` run (including maintainer scripts). The
# postinst instead verifies the payload synchronously (a tampered package
# still fails the configure step — fail closed) and hands the install to a
# detached root worker that waits for the outer dpkg to release its locks,
# then runs install_offline.sh VERBATIM (verify-then-use staging,
# --no-index --require-hashes pip) before installing the unit/config. The
# worker is a child of this container's PID 1: it dies with the container, so
# the gate MUST wait for its status file here — and doctor/probe below need
# the venv it creates.
STATUS=/var/log/universal-db-mcp-install.status
INSTALL_LOG=/var/log/universal-db-mcp-install.log
if [ -f "$STATUS" ]; then
  st=""
  waited=0
  while [ "$waited" -lt 1800 ]; do
    st="$(cat "$STATUS" 2>/dev/null || true)"
    if [ "$st" = "success" ] || [ "$st" = "failed" ]; then break; fi
    sleep 2
    waited=$((waited + 2))
  done
  cp "$INSTALL_LOG" "$EV/deferred-install.log" 2>/dev/null || true
  if [ "$st" = "success" ]; then
    note=""
    # Honest evidence: lib/os_packages.sh may have DEFERRED the bundle's
    # OS-package closure behind a pending marker (its maintainer-script
    # detection is inherited by the worker via DPKG_MAINTSCRIPT_PACKAGE).
    # A leftover marker means the closure was not installed in this container;
    # record it in the evidence either way instead of hiding it.
    if [ -f /run/universal-db-mcp/os-packages.pending ]; then
      note="; NOTE: bundle OS-package closure left PENDING (/run/universal-db-mcp/os-packages.pending) by os_packages.sh maintainer-script detection — not installed in this container"
    fi
    rec deferred_install passed "deferred postinst install completed after dpkg released its locks (waited ${waited}s; log: /evidence/deferred-install.log)${note}"
  else
    rec deferred_install failed "deferred postinst install did not succeed (status='${st:-none}' after ${waited}s): $(tail -c 400 "$INSTALL_LOG" 2>/dev/null | tr '\n' ' ')"
    exit 1
  fi
else
  rec deferred_install passed "not deferred: postinst installed synchronously (bundle ships no os-packages)"
fi

# --- doctor with a generated demo config -------------------------------------
mkdir -p /tmp/demo
cp "$BUNDLE_INSTALLED/config-templates/create_demo.py" \
   "$BUNDLE_INSTALLED/config-templates/config.template.yaml" /tmp/demo/
if "$VENV/python" /tmp/demo/create_demo.py --path /tmp/finlink_demo.db > /tmp/demo.log 2>&1; then
  rec demo_fixture passed "synthetic SQLite demo fixture created at /tmp/finlink_demo.db"
else
  rec demo_fixture failed "create_demo.py failed: $(tail -c 300 /tmp/demo.log | tr '\n' ' ')"
  exit 1
fi

if "$VENV/python" -m universal_db_mcp doctor --config /tmp/demo/config.yaml \
    > "$EV/doctor.json" 2> "$EV/doctor.stderr.txt"; then
  rec doctor passed "doctor passed against the deb-installed venv (config: /tmp/demo/config.yaml)"
else
  rec doctor failed "doctor reported fatal checks: $(tail -c 300 "$EV/doctor.stderr.txt" | tr '\n' ' ')"
fi

# --- protocol probe over stdio (no network) ----------------------------------
if "$VENV/python" "$BUNDLE_INSTALLED/tests/protocol_probe.py" "$VENV/python" /tmp/finlink_demo.db \
    > "$EV/protocol-probe.json" 2> "$EV/protocol-probe.stderr.txt"; then
  rec protocol_probe passed "stdio MCP protocol lifecycle probe passed"
else
  rec protocol_probe failed "protocol probe failed: $(tail -c 300 "$EV/protocol-probe.stderr.txt" | tr '\n' ' ')"
fi

echo "[deb-gate-positive] finished, FAILED=$FAILED"
exit "$FAILED"
POSITIVE_EOF

cat > "$WORK/negative.sh" <<'NEGATIVE_EOF'
#!/bin/bash
# Negative case: repack a COPY of the deb with one tampered wheel inside the
# payload; the trusted verifier AND dpkg -i (postinst) must both fail closed
# with the canonical "signature verification FAILED" diagnostic. The original
# deb is mounted read-only and never modified.
set -uo pipefail
EV=/evidence
TSV="$EV/negative-checks.tsv"
: > "$TSV"
FAILED=0
DEB=/pkg/universal-db-mcp.deb

rec() { # name status detail
  printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$TSV"
  echo "[deb-gate-negative] [$2] $1: $3"
  [ "$2" = "passed" ] || FAILED=1
}

# Admin trust bootstrap (same as the positive case): the tampered package is
# installed against REAL prerequisites, so the failure can only come from the
# payload verification, not from a missing preinst prerequisite.
install -d -m 755 /usr/local/lib/udbmcp-trust/lib /etc/universal-db-mcp/keys
install -m 644 /trust/verify_bundle.py /usr/local/lib/udbmcp-trust/
install -m 644 /trust/profiles.py /usr/local/lib/udbmcp-trust/
install -m 755 /trust/install_offline.sh /usr/local/lib/udbmcp-trust/
install -m 644 /trust/os_packages.sh /usr/local/lib/udbmcp-trust/lib/
install -m 644 /pubkey.pem /etc/universal-db-mcp/keys/release.pub.pem

# --- tamper: extract data payload, flip one wheel byte, refresh SHA256SUMS ---
rm -rf /tmp/tamper /tmp/tampered.deb
mkdir -p /tmp/tamper  # dpkg-deb -R creates the leaf dir but not its parents
if ! dpkg-deb -R "$DEB" /tmp/tamper/tree > /tmp/tamper-extract.log 2>&1; then
  rec tamper_setup failed "dpkg-deb -R of the copy failed: $(tail -c 300 /tmp/tamper-extract.log | tr '\n' ' ')"
  exit 1
fi
W="$(ls /tmp/tamper/tree/usr/share/universal-db-mcp/bundle/wheelhouse/sqlglot-*.whl 2>/dev/null | head -1)"
if [ -z "$W" ]; then
  rec tamper_setup failed "no sqlglot wheel found in the payload wheelhouse"
  exit 1
fi
python3 - "$W" <<'PY'
import hashlib
import sys
from pathlib import Path

wheel = Path(sys.argv[1])
data = bytearray(wheel.read_bytes())
data[200] = data[200] ^ 0xFF  # flip one bit inside the wheel payload
wheel.write_bytes(bytes(data))
# Refresh the wheel's SHA256SUMS line so the tamper survives the integrity
# check and must be caught by the SIGNATURE check (the canonical diagnostic),
# exactly like an attacker who can repack a deb.
sums = wheel.parent.parent / "SHA256SUMS"
rel = "wheelhouse/" + wheel.name
lines = []
for line in sums.read_text().splitlines():
    digest, _, path = line.partition("  ")
    if path == rel:
        line = hashlib.sha256(wheel.read_bytes()).hexdigest() + "  " + rel
    lines.append(line)
sums.write_text("\n".join(lines) + "\n")
print(f"tampered {rel}: one byte flipped, SHA256SUMS line refreshed")
PY
rec wheel_tampered passed "sqlglot wheel byte-flipped inside a repacked COPY of the deb; its SHA256SUMS line refreshed so the rejection must come from the SIGNATURE, not the integrity hash"

# --- the trusted verifier must reject the tampered payload -------------------
TAMPERED_BUNDLE=/tmp/tamper/tree/usr/share/universal-db-mcp/bundle
VOUT="$(python3 /usr/local/lib/udbmcp-trust/verify_bundle.py --bundle "$TAMPERED_BUNDLE" --pubkey /etc/universal-db-mcp/keys/release.pub.pem 2>&1)"
VRC=$?
echo "$VOUT" > "$EV/tamper-verify.log"
if [ "$VRC" -ne 0 ] && echo "$VOUT" | grep -q "signature verification FAILED"; then
  rec tamper_refused_by_verifier passed "trusted verifier rejected the tampered payload with the canonical diagnostic (rc=$VRC)"
else
  rec tamper_refused_by_verifier failed "expected nonzero rc + 'signature verification FAILED', got rc=$VRC: $(echo "$VOUT" | tail -c 300 | tr '\n' ' ')"
fi

# --- repack and install: dpkg must fail at postinst verification -------------
if ! dpkg-deb --root-owner-group --build /tmp/tamper/tree /tmp/tampered.deb > /tmp/repack.log 2>&1; then
  rec tamper_setup failed "dpkg-deb --build of the tampered tree failed: $(tail -c 300 /tmp/repack.log | tr '\n' ' ')"
  exit 1
fi
export DEBIAN_FRONTEND=noninteractive
# --force-depends mirrors the positive case (minimal baseline image lacks the
# python3/python3-venv metapackages); the assertion is about the POSTINST.
dpkg -i --force-depends /tmp/tampered.deb > /tmp/dpkg-tamper.log 2>&1
rc=$?
cp /tmp/dpkg-tamper.log "$EV/dpkg-tamper.log"
if [ "$rc" -ne 0 ] && grep -q "signature verification FAILED" /tmp/dpkg-tamper.log; then
  rec tampered_dpkg_install_fails passed "dpkg -i of the tampered package FAILED (rc=$rc) at postinst verification with the canonical 'signature verification FAILED' diagnostic (fail closed)"
else
  rec tampered_dpkg_install_fails failed "expected nonzero rc + canonical diagnostic; got rc=$rc: $(tail -c 300 /tmp/dpkg-tamper.log | tr '\n' ' ')"
fi

echo "[deb-gate-negative] finished, FAILED=$FAILED"
exit "$FAILED"
NEGATIVE_EOF

cat > "$WORK/negative2.sh" <<'NEGATIVE2_EOF'
#!/bin/bash
# Negative case 2 — WITHOUT the admin trust bootstrap (self-bootstrap hole).
#
# The deb ships a trusted-tools/ copy at
# /usr/share/universal-db-mcp/trusted-tools/ on the SAME channel as the
# payload it would verify. If the package ever bootstrapped — or "completed"
# — /usr/local/lib/udbmcp-trust from that copy, a tampered package could ship
# a verifier that prints PASSED (or an installer that skips verification) and
# have it installed to the root-owned trust path and executed there. This
# case stubs the deb-shipped verifier with exactly such a stub, then requires
# fail-closed behavior with NO admin trust dir and NO pubkey anywhere:
#   - the unpacked postinst run DIRECTLY (postinst is reachable without a
#     preinst run, e.g. `dpkg --configure universal-db-mcp`) must refuse to
#     self-bootstrap: nonzero exit, canonical diagnostic, trust dir still
#     absent, stub never executed;
#   - `dpkg -i` must abort (preinst: trust prerequisites absent);
#   - "bundle verification PASSED" must never appear as a successful
#     verification anywhere.
set -uo pipefail
EV=/evidence
TSV="$EV/negative2-checks.tsv"
: > "$TSV"
FAILED=0
DEB=/pkg/universal-db-mcp.deb
TRUST_DIR=/usr/local/lib/udbmcp-trust

rec() { # name status detail
  printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$TSV"
  echo "[deb-gate-negative2] [$2] $1: $3"
  [ "$2" = "passed" ] || FAILED=1
}

# --- pristine container: no admin bootstrap of any kind ----------------------
if [ ! -e "$TRUST_DIR" ] && [ ! -e /etc/universal-db-mcp/keys/release.pub.pem ]; then
  rec no_admin_bootstrap passed "no admin trust dir and no release pubkey in this container (the point of this case)"
else
  rec no_admin_bootstrap failed "container is not pristine: trust dir or pubkey already present"
fi

# --- tamper: stub the deb-shipped verifier -----------------------------------
rm -rf /tmp/tamper2 /tmp/tampered2.deb
mkdir -p /tmp/tamper2  # dpkg-deb -R creates the leaf dir but not its parents
if ! dpkg-deb -R "$DEB" /tmp/tamper2/tree > /tmp/tamper2-extract.log 2>&1; then
  rec tamper2_setup failed "dpkg-deb -R of the copy failed: $(tail -c 300 /tmp/tamper2-extract.log | tr '\n' ' ')"
  exit 1
fi
V=/tmp/tamper2/tree/usr/share/universal-db-mcp/trusted-tools/verify_bundle.py
if [ -f "$V" ]; then
  cat > "$V" <<'STUB'
#!/bin/sh
echo "bundle verification PASSED"
exit 0
STUB
  rec deb_verifier_stubbed passed "deb-shipped verify_bundle.py replaced by a stub that prints 'bundle verification PASSED' and exits 0 (exactly what a tampered package would ship)"
else
  rec deb_verifier_stubbed failed "deb payload has no trusted-tools/verify_bundle.py to stub"
  exit 1
fi

# --- the unpacked postinst must refuse to self-bootstrap ---------------------
# Run DIRECTLY: this is the dpkg --configure path, which bypasses the preinst.
# The postinst must fail closed on its own — create NOTHING at the trust-dir
# path and never execute the deb-shipped (stubbed) verifier.
export DEBIAN_FRONTEND=noninteractive
PLOG=/tmp/postinst-no-bootstrap.log
if DPKG_MAINTSCRIPT_PACKAGE=universal-db-mcp \
    bash /tmp/tamper2/tree/DEBIAN/postinst configure > "$PLOG" 2>&1; then
  PRC=0
else
  PRC=$?
fi
cp "$PLOG" "$EV/postinst-no-bootstrap.log"
if [ "$PRC" -ne 0 ] \
    && grep -q "trusted tool missing from the admin trust dir" "$PLOG" \
    && [ ! -e "$TRUST_DIR" ]; then
  rec postinst_refuses_self_bootstrap passed "postinst exited rc=$PRC with the canonical 'trusted tool missing from the admin trust dir' diagnostic, created NOTHING at $TRUST_DIR and never ran the stub (fail closed)"
else
  rec postinst_refuses_self_bootstrap failed "expected nonzero rc + canonical diagnostic + no $TRUST_DIR; got rc=$PRC: $(tail -c 300 "$PLOG" | tr '\n' ' ')"
fi
if grep -q "bundle verification PASSED" "$PLOG"; then
  rec stub_verifier_never_ran failed "the stub verifier's output appeared in the postinst run: the package executed its own payload as a verifier"
else
  rec stub_verifier_never_ran passed "the stub verifier never executed during the postinst refusal"
fi

# --- dpkg -i without the admin bootstrap must abort ---------------------------
if ! dpkg-deb --root-owner-group --build /tmp/tamper2/tree /tmp/tampered2.deb > /tmp/repack2.log 2>&1; then
  rec tamper2_setup failed "dpkg-deb --build of the stubbed tree failed: $(tail -c 300 /tmp/repack2.log | tr '\n' ' ')"
  exit 1
fi
dpkg -i --force-depends /tmp/tampered2.deb > /tmp/dpkg-tamper2.log 2>&1
rc=$?
cp /tmp/dpkg-tamper2.log "$EV/dpkg-tamper2.log"
if [ "$rc" -ne 0 ] \
    && grep -q "trusted verifier not found" /tmp/dpkg-tamper2.log \
    && ! grep -q "bundle verification PASSED" /tmp/dpkg-tamper2.log \
    && [ ! -e "$TRUST_DIR" ]; then
  rec tampered2_dpkg_install_fails passed "dpkg -i of the stubbed package FAILED (rc=$rc) with NO admin bootstrap: preinst refuses (trust prerequisites absent), the trust dir was never created and the stub verifier never produced a PASSED line (fail closed)"
else
  rec tampered2_dpkg_install_fails failed "expected nonzero rc + 'trusted verifier not found', no PASSED line and no trust dir; got rc=$rc: $(tail -c 300 /tmp/dpkg-tamper2.log | tr '\n' ' ')"
fi

echo "[deb-gate-negative2] finished, FAILED=$FAILED"
exit "$FAILED"
NEGATIVE2_EOF

cat > "$WORK/negative3.sh" <<'NEGATIVE3_EOF'
#!/bin/bash
# Negative case 3 — TRUNCATED (zero-length) trusted verifier.
#
# python3 on an empty script exits 0 without ever running argparse: a
# trusted-channel copy of verify_bundle.py truncated to 0 bytes would make
# every exit-code-only verifier invocation 'pass' vacuously, and the
# unverified payload would be installed and universal-db-mcp.service enabled.
# The .pkg preinstall guards this exact case with [ ! -s ]; the deb must be
# at least as strict: the preinst refuses an empty verifier outright and the
# postinst's trust-dir completeness gate treats zero-length like missing.
set -uo pipefail
EV=/evidence
TSV="$EV/negative3-checks.tsv"
: > "$TSV"
FAILED=0
DEB=/pkg/universal-db-mcp.deb
TRUST_DIR=/usr/local/lib/udbmcp-trust

rec() { # name status detail
  printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$TSV"
  echo "[deb-gate-negative3] [$2] $1: $3"
  # 'recorded' is informational evidence (either outcome is acceptable), not a
  # failure; only a non-passed CHECK fails the case.
  [ "$2" = "passed" ] || [ "$2" = "recorded" ] || FAILED=1
}

# --- admin trust bootstrap, with the verifier TRUNCATED to zero bytes --------
if install -d -m 755 "$TRUST_DIR/lib" /etc/universal-db-mcp/keys \
   && install -m 644 /trust/verify_bundle.py "$TRUST_DIR/" \
   && install -m 644 /trust/profiles.py "$TRUST_DIR/" \
   && install -m 755 /trust/install_offline.sh "$TRUST_DIR/" \
   && install -m 644 /trust/os_packages.sh "$TRUST_DIR/lib/" \
   && install -m 644 /pubkey.pem /etc/universal-db-mcp/keys/release.pub.pem \
   && : > "$TRUST_DIR/verify_bundle.py"; then
  rec truncated_bootstrap passed "admin bootstrap installed from the trusted channel, then verify_bundle.py truncated to 0 bytes (the damaged-copy scenario)"
else
  rec truncated_bootstrap failed "admin trust bootstrap failed (rc=$?)"
  exit 1
fi
[ -s "$TRUST_DIR/verify_bundle.py" ] && { rec truncated_bootstrap failed "verifier not actually empty"; exit 1; } || true

# --- document the vacuous pass the fix guards against ------------------------
# Empirical baseline: python3 on the empty verifier exits 0 against garbage
# arguments. If this ever changes (python3 refusing empty scripts), the -s
# gates below become redundant — which is fine, but the evidence should say so.
if python3 "$TRUST_DIR/verify_bundle.py" --bundle /nonexistent --pubkey /nonexistent >/dev/null 2>&1; then
  rec vacuous_pass_baseline recorded "confirmed: python3 on the zero-length verifier exits 0 without checking anything (why exit-code-only trust fails closed is required)"
else
  rec vacuous_pass_baseline recorded "python3 no longer exits 0 on an empty script; the -s gates remain as defense in depth"
fi

# --- the unpacked postinst must refuse the zero-length verifier --------------
# Run DIRECTLY (dpkg --configure path, bypasses preinst): the trust-dir
# completeness gate must treat zero-length like missing (fail closed).
rm -rf /tmp/tamper3
mkdir -p /tmp/tamper3  # dpkg-deb -R creates the leaf dir but not its parents
if ! dpkg-deb -R "$DEB" /tmp/tamper3/tree > /tmp/tamper3-extract.log 2>&1; then
  rec tamper3_setup failed "dpkg-deb -R failed: $(tail -c 300 /tmp/tamper3-extract.log | tr '\n' ' ')"
  exit 1
fi
export DEBIAN_FRONTEND=noninteractive
PLOG=/tmp/postinst-empty-verifier.log
if DPKG_MAINTSCRIPT_PACKAGE=universal-db-mcp \
    bash /tmp/tamper3/tree/DEBIAN/postinst configure > "$PLOG" 2>&1; then
  PRC=0
else
  PRC=$?
fi
cp "$PLOG" "$EV/postinst-empty-verifier.log"
if [ "$PRC" -ne 0 ] \
    && grep -q "trusted tool missing from the admin trust dir" "$PLOG" \
    && grep -q "zero-length" "$PLOG"; then
  rec postinst_refuses_empty_verifier passed "postinst exited rc=$PRC with the zero-length trusted-tool diagnostic (fail closed at configure time)"
else
  rec postinst_refuses_empty_verifier failed "expected nonzero rc + zero-length diagnostic; got rc=$PRC: $(tail -c 300 "$PLOG" | tr '\n' ' ')"
fi
if grep -q "bundle verification PASSED" "$PLOG"; then
  rec no_vacuous_pass_postinst failed "a PASSED verdict appeared despite the empty verifier"
else
  rec no_vacuous_pass_postinst passed "no 'bundle verification PASSED' anywhere in the postinst run"
fi

# --- dpkg -i must abort at the preinst ---------------------------------------
dpkg -i --force-depends "$DEB" > /tmp/dpkg-empty.log 2>&1
rc=$?
cp /tmp/dpkg-empty.log "$EV/dpkg-empty.log"
if [ "$rc" -ne 0 ] \
    && grep -q "exists but is EMPTY" /tmp/dpkg-empty.log \
    && ! grep -q "bundle verification PASSED" /tmp/dpkg-empty.log \
    && [ ! -e /opt/universal-db-mcp/venv ] \
    && [ ! -e /etc/systemd/system/universal-db-mcp.service ]; then
  rec empty_verifier_dpkg_install_fails passed "dpkg -i FAILED (rc=$rc) at the preinst's non-empty check: no venv, no unit, no service enabled, no PASSED verdict (fail closed)"
else
  rec empty_verifier_dpkg_install_fails failed "expected nonzero rc + 'exists but is EMPTY' preinst diagnostic, no venv/unit/PASSED; got rc=$rc: $(tail -c 300 /tmp/dpkg-empty.log | tr '\n' ' ')"
fi

echo "[deb-gate-negative3] finished, FAILED=$FAILED"
exit "$FAILED"
NEGATIVE3_EOF
cat > "$WORK/upgrade.sh" <<'UPGRADE_EOF'
#!/bin/bash
# Upgrade case: install -> simulate the previous release's code in the venv
# -> install the same package again -> the code must be replaced and the
# admin's config edit kept; then an OUTDATED trusted installer must be
# refused, and the real one must succeed. Own container (pristine baseline).
set -uo pipefail
EV=/evidence
TSV="$EV/upgrade-checks.tsv"
: > "$TSV"
FAILED=0
DEB=/pkg/universal-db-mcp.deb
VENV=/opt/universal-db-mcp/venv
STATUS=/var/log/universal-db-mcp-install.status
INSTALL_LOG=/var/log/universal-db-mcp-install.log
CONFIG=/etc/universal-db-mcp/config.yaml
TRUST=/usr/local/lib/udbmcp-trust
export DEBIAN_FRONTEND=noninteractive

rec() { # name status detail
  printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$TSV"
  echo "[deb-gate-upgrade] [$2] $1: $3"
  [ "$2" = "passed" ] || FAILED=1
}

install_pkg() { # install_pkg <label> -> 0 on dpkg success + worker success
  local label="$1" rc st waited=0
  rm -f "$STATUS"
  dpkg -i "$DEB" > "/tmp/dpkg-$label.log" 2>&1; rc=$?
  if [ "$rc" -ne 0 ] && grep -q "dependency problems" "/tmp/dpkg-$label.log"; then
    dpkg -i --force-depends "$DEB" >> "/tmp/dpkg-$label.log" 2>&1; rc=$?
  fi
  cp "/tmp/dpkg-$label.log" "$EV/dpkg-upgrade-$label.log"
  [ "$rc" -eq 0 ] || return 1
  if [ -f "$STATUS" ]; then
    st=""
    while [ "$waited" -lt 1800 ]; do
      st="$(cat "$STATUS" 2>/dev/null || true)"
      if [ "$st" = "success" ] || [ "$st" = "failed" ]; then break; fi
      sleep 2; waited=$((waited + 2))
    done
    cp "$INSTALL_LOG" "$EV/deferred-install-upgrade-$label.log" 2>/dev/null || true
    [ "$st" = "success" ] || return 2
  fi
  return 0
}

# --- admin trust bootstrap (from the trusted channel, never the package) ------
if install -d -m 755 "$TRUST/lib" /etc/universal-db-mcp/keys \
   && install -m 644 /trust/verify_bundle.py "$TRUST/" \
   && install -m 644 /trust/profiles.py "$TRUST/" \
   && install -m 755 /trust/install_offline.sh "$TRUST/" \
   && install -m 644 /trust/os_packages.sh "$TRUST/lib/" \
   && install -m 644 /pubkey.pem /etc/universal-db-mcp/keys/release.pub.pem; then
  rec upgrade_trust_bootstrap passed "trusted tools + release pubkey installed at the admin paths"
else
  rec upgrade_trust_bootstrap failed "admin trust bootstrap failed"
  exit 1
fi

# --- first install ------------------------------------------------------------
if install_pkg first; then
  rec upgrade_first_install passed "first dpkg -i + deferred worker succeeded"
else
  rec upgrade_first_install failed "first install failed (rc=$?): $(tail -c 400 "$INSTALL_LOG" 2>/dev/null | tr '\n' ' ')"
  exit 1
fi
PKG_INIT="$(ls -d "$VENV"/lib/python3.*/site-packages/universal_db_mcp/__init__.py 2>/dev/null | head -1)"
if [ -z "$PKG_INIT" ]; then
  rec upgrade_marker_planted failed "installed package not found under $VENV/lib"
  exit 1
fi
# --- simulate the previous release's code + an admin config edit --------------
echo "# STALE-RELEASE-MARKER: code of the previous release" >> "$PKG_INIT"
echo "# ADMIN-EDIT-MARKER: kept across upgrades (dpkg conffile)" >> "$CONFIG"
rec upgrade_marker_planted passed "marker appended to $(basename "$(dirname "$PKG_INIT")")/__init__.py (a wheel-tracked file) and to $CONFIG"

# --- second install of the SAME package -------------------------------------
if install_pkg second; then
  rec upgrade_second_install passed "second dpkg -i (upgrade of the same version) + deferred worker succeeded"
else
  rec upgrade_second_install failed "second install failed (rc=$?): $(tail -c 400 "$INSTALL_LOG" 2>/dev/null | tr '\n' ' ')"
  exit 1
fi
if grep -q "STALE-RELEASE-MARKER" "$PKG_INIT"; then
  rec upgrade_replaces_venv_code failed "the marker survived the upgrade: the venv still runs the previous release's code (pip 'already satisfied'); this is the 2026-09-15 incident"
else
  rec upgrade_replaces_venv_code passed "the upgrade replaced the installed package code (marker gone: --force-reinstall took effect)"
fi
if grep -q "ADMIN-EDIT-MARKER" "$CONFIG"; then
  rec upgrade_keeps_admin_config passed "admin edit in $CONFIG preserved across the upgrade (conffile semantics)"
else
  rec upgrade_keeps_admin_config failed "admin edit in $CONFIG was lost by the upgrade"
fi
# --- the previous release is kept beside the new one, and rollback restores it
PREV="$(dirname "$VENV")/venv.previous"
if [ -d "$PREV" ] && [ -s "$PREV.sha256" ] && grep -q "STALE-RELEASE-MARKER" "$PREV/lib/python3."*"/site-packages/universal_db_mcp/__init__.py"; then
  rec upgrade_keeps_previous_venv passed "venv.previous holds the previous release (marker present) with its integrity manifest"
else
  rec upgrade_keeps_previous_venv failed "no venv.previous with the previous release and a manifest after the upgrade"
fi
ROLLBACK=/usr/share/universal-db-mcp/bundle/operations/rollback_offline.sh
if [ -f "$ROLLBACK" ]; then
  if bash "$ROLLBACK" "$(dirname "$VENV")" > /tmp/rollback.log 2>&1 && grep -q "STALE-RELEASE-MARKER" "$PKG_INIT"; then
    rec rollback_restores_previous_release passed "rollback_offline.sh restored the previous venv (marker back) after verifying its manifest"
  else
    cp /tmp/rollback.log "$EV/rollback-upgrade.log" 2>/dev/null || true
    rec rollback_restores_previous_release failed "rollback did not restore the previous release: $(tail -c 300 /tmp/rollback.log | tr '\n' ' ')"
  fi
else
  rec rollback_restores_previous_release failed "bundle ships no operations/rollback_offline.sh"
fi
if "$VENV/bin/python" -m universal_db_mcp version > /tmp/version.txt 2>&1; then
  rec upgrade_venv_runs passed "upgraded venv runs: $(tr '\n' ' ' < /tmp/version.txt | cut -c1-80)"
else
  rec upgrade_venv_runs failed "upgraded venv does not run: $(tail -c 200 /tmp/version.txt | tr '\n' ' ')"
fi

# --- NEGATIVE: an outdated trusted installer must be refused ------------------
grep -v -- "--force-reinstall" /trust/install_offline.sh > /tmp/install_offline_outdated.sh
if grep -q "PIP_FIND_LINKS" /tmp/install_offline_outdated.sh && ! grep -q -- "--force-reinstall" /tmp/install_offline_outdated.sh; then
  install -m 755 /tmp/install_offline_outdated.sh "$TRUST/install_offline.sh"
  echo "# STALE-RELEASE-MARKER-2" >> "$PKG_INIT"
  rm -f "$STATUS"
  dpkg -i "$DEB" > /tmp/dpkg-outdated.log 2>&1; rc=$?
  cp /tmp/dpkg-outdated.log "$EV/dpkg-upgrade-outdated.log"
  if [ "$rc" -ne 0 ] && grep -q "OUTDATED copy" /tmp/dpkg-outdated.log && [ ! -f "$STATUS" ]; then
    rec upgrade_refuses_outdated_installer passed "dpkg -i aborted at preinst with the OUTDATED diagnostic (rc=$rc); no worker was started"
  else
    rec upgrade_refuses_outdated_installer failed "dpkg -i with an outdated trusted installer did not fail closed (rc=$rc, status file: $([ -f "$STATUS" ] && cat "$STATUS" || echo none))"
  fi
  # recovery: refresh the trusted installer (what the runbook's Step 1 does), upgrade again
  install -m 755 /trust/install_offline.sh "$TRUST/install_offline.sh"
  if install_pkg recovery && ! grep -q "STALE-RELEASE-MARKER-2" "$PKG_INIT"; then
    rec upgrade_after_refresh passed "after refreshing the trusted installer the upgrade succeeded and replaced the code again"
  else
    rec upgrade_after_refresh failed "upgrade after refreshing the trusted installer failed or left the marker"
  fi
else
  rec upgrade_refuses_outdated_installer failed "could not derive an outdated installer copy from /trust/install_offline.sh (no PIP_FIND_LINKS line?)"
fi

# --- NEGATIVE: a pip-running installer without the current format marker is refused too
grep -v "udbmcp-installer-format" /trust/install_offline.sh > /tmp/install_offline_nomarker.sh
if grep -q "PIP_FIND_LINKS" /tmp/install_offline_nomarker.sh && ! grep -q "udbmcp-installer-format" /tmp/install_offline_nomarker.sh; then
  install -m 755 /tmp/install_offline_nomarker.sh "$TRUST/install_offline.sh"
  rm -f "$STATUS"
  dpkg -i "$DEB" > /tmp/dpkg-nomarker.log 2>&1; rc=$?
  cp /tmp/dpkg-nomarker.log "$EV/dpkg-upgrade-nomarker.log"
  if [ "$rc" -ne 0 ] && grep -q "OUTDATED copy" /tmp/dpkg-nomarker.log && grep -q "udbmcp-installer-format" /tmp/dpkg-nomarker.log && [ ! -f "$STATUS" ]; then
    rec upgrade_refuses_unmarked_installer passed "dpkg -i aborted at preinst: installer without the format marker refused (rc=$rc)"
  else
    rec upgrade_refuses_unmarked_installer failed "dpkg -i with a marker-less trusted installer did not fail closed (rc=$rc)"
  fi
  install -m 755 /trust/install_offline.sh "$TRUST/install_offline.sh"
  if install_pkg recovery2; then
    rec upgrade_after_marker_refresh passed "after restoring the marked installer the upgrade succeeded again"
  else
    rec upgrade_after_marker_refresh failed "upgrade after restoring the marked installer failed"
  fi
else
  rec upgrade_refuses_unmarked_installer failed "could not derive a marker-less installer copy from /trust/install_offline.sh"
fi

# --- version ordering: this package must upgrade a legacy 0.1.0~<hash> install
#     and any package with an older build stamp ---------------------------------
NEWVER="$(dpkg-deb -f "$DEB" Version)"
if dpkg --compare-versions "$NEWVER" gt "0.1.0~ffffffffffffffffffffffffffffffffffffffff" \
   && dpkg --compare-versions "$NEWVER" gt "0.1.0+190001010000.g0000000" \
   && ! dpkg --compare-versions "$NEWVER" gt "0.1.0+299912312359.g0000000"; then
  rec upgrade_version_ordering passed "version $NEWVER upgrades a legacy 0.1.0~<hash> install and an older build stamp, and is older than a newer stamp"
else
  rec upgrade_version_ordering failed "version $NEWVER does not order as an upgrade over the legacy scheme / older stamps"
fi

# --- doctor reports the installed release ------------------------------------
if "$VENV/bin/python" -m universal_db_mcp doctor --config /usr/share/universal-db-mcp/bundle/config-templates/config.yaml \
    > "$EV/doctor-upgrade.json" 2> "$EV/doctor-upgrade.stderr.txt" || true; then
  if grep -q '"installed-release"' "$EV/doctor-upgrade.json" && grep -q 'source_rev' "$EV/doctor-upgrade.json"; then
    rec upgrade_doctor_release_line passed "doctor reports the installed release (installed-release check with source_rev)"
  else
    rec upgrade_doctor_release_line failed "doctor output lacks the installed-release line"
  fi
fi

echo "[deb-gate-upgrade] finished, FAILED=$FAILED"
exit "$FAILED"
UPGRADE_EOF
echo "==> POSITIVE case: install + doctor + protocol probe (network: NONE, platform: linux/amd64)"
set +e
docker run --rm --network none --platform linux/amd64 \
  -v "$DEB":"$CONTAINER_DEB":ro \
  -v "$PUBKEY":/pubkey.pem:ro \
  -v "$PROJECT/scripts/verify_bundle.py":/trust/verify_bundle.py:ro \
  -v "$PROJECT/scripts/profiles.py":/trust/profiles.py:ro \
  -v "$PROJECT/scripts/install_offline.sh":/trust/install_offline.sh:ro \
  -v "$PROJECT/scripts/lib/os_packages.sh":/trust/os_packages.sh:ro \
  -v "$EVIDENCE_DIR":/evidence \
  -v "$WORK/positive.sh":/gate/positive.sh:ro \
  "$IMAGE" \
  bash /gate/positive.sh > "$LOG_DIR/positive-container.log" 2>&1
POS_RC=$?
set -e
merge_container_checks "$EVIDENCE_DIR/positive-checks.tsv" "$POS_RC" "positive"
# Keep the per-run TSVs beside the logs for debugging; they are merged already.
mv "$EVIDENCE_DIR/positive-checks.tsv" "$LOG_DIR/positive-checks.tsv" 2>/dev/null || true

# -------------------------------------------------------------- upgrade case
echo "==> UPGRADE case: install over install must replace the venv code; an outdated trusted installer must be refused"
set +e
docker run --rm --network none --platform linux/amd64 \
  -v "$DEB":"$CONTAINER_DEB":ro \
  -v "$PUBKEY":/pubkey.pem:ro \
  -v "$PROJECT/scripts/verify_bundle.py":/trust/verify_bundle.py:ro \
  -v "$PROJECT/scripts/profiles.py":/trust/profiles.py:ro \
  -v "$PROJECT/scripts/install_offline.sh":/trust/install_offline.sh:ro \
  -v "$PROJECT/scripts/lib/os_packages.sh":/trust/os_packages.sh:ro \
  -v "$EVIDENCE_DIR":/evidence \
  -v "$WORK/upgrade.sh":/gate/upgrade.sh:ro \
  "$IMAGE" \
  bash /gate/upgrade.sh > "$LOG_DIR/upgrade-container.log" 2>&1
UPG_RC=$?
set -e
merge_container_checks "$EVIDENCE_DIR/upgrade-checks.tsv" "$UPG_RC" "upgrade"
mv "$EVIDENCE_DIR/upgrade-checks.tsv" "$LOG_DIR/upgrade-checks.tsv" 2>/dev/null || true

# ------------------------------------------------------------- negative case
echo "==> NEGATIVE case: tampered-wheel repack must fail closed at postinst verification"
set +e
docker run --rm --network none --platform linux/amd64 \
  -v "$DEB":"$CONTAINER_DEB":ro \
  -v "$PUBKEY":/pubkey.pem:ro \
  -v "$PROJECT/scripts/verify_bundle.py":/trust/verify_bundle.py:ro \
  -v "$PROJECT/scripts/profiles.py":/trust/profiles.py:ro \
  -v "$PROJECT/scripts/install_offline.sh":/trust/install_offline.sh:ro \
  -v "$PROJECT/scripts/lib/os_packages.sh":/trust/os_packages.sh:ro \
  -v "$EVIDENCE_DIR":/evidence \
  -v "$WORK/negative.sh":/gate/negative.sh:ro \
  "$IMAGE" \
  bash /gate/negative.sh > "$LOG_DIR/negative-container.log" 2>&1
NEG_RC=$?
set -e
merge_container_checks "$EVIDENCE_DIR/negative-checks.tsv" "$NEG_RC" "negative"
mv "$EVIDENCE_DIR/negative-checks.tsv" "$LOG_DIR/negative-checks.tsv" 2>/dev/null || true

# ------------------------------------------------- negative case 2 (no bootstrap)
# Deliberately NO /trust and NO /pubkey mounts: the whole point of this case
# is that the package is installed with no admin bootstrap at all.
echo "==> NEGATIVE case 2: stubbed deb verifier + NO admin bootstrap must fail closed (no self-bootstrap)"
set +e
docker run --rm --network none --platform linux/amd64 \
  -v "$DEB":"$CONTAINER_DEB":ro \
  -v "$EVIDENCE_DIR":/evidence \
  -v "$WORK/negative2.sh":/gate/negative2.sh:ro \
  "$IMAGE" \
  bash /gate/negative2.sh > "$LOG_DIR/negative2-container.log" 2>&1
NEG2_RC=$?
set -e
merge_container_checks "$EVIDENCE_DIR/negative2-checks.tsv" "$NEG2_RC" "negative2"
mv "$EVIDENCE_DIR/negative2-checks.tsv" "$LOG_DIR/negative2-checks.tsv" 2>/dev/null || true

# --------------------------------------------- negative case 3 (empty verifier)
# The trust mounts ARE needed here: the bootstrap succeeds and only the
# verifier copy is truncated afterwards — the failure must come from the
# deb's zero-length guards, not from missing prerequisites.
echo "==> NEGATIVE case 3: zero-length trusted verifier must fail closed (preinst + postinst)"
set +e
docker run --rm --network none --platform linux/amd64 \
  -v "$DEB":"$CONTAINER_DEB":ro \
  -v "$PUBKEY":/pubkey.pem:ro \
  -v "$PROJECT/scripts/verify_bundle.py":/trust/verify_bundle.py:ro \
  -v "$PROJECT/scripts/profiles.py":/trust/profiles.py:ro \
  -v "$PROJECT/scripts/install_offline.sh":/trust/install_offline.sh:ro \
  -v "$PROJECT/scripts/lib/os_packages.sh":/trust/os_packages.sh:ro \
  -v "$EVIDENCE_DIR":/evidence \
  -v "$WORK/negative3.sh":/gate/negative3.sh:ro \
  "$IMAGE" \
  bash /gate/negative3.sh > "$LOG_DIR/negative3-container.log" 2>&1
NEG3_RC=$?
set -e
merge_container_checks "$EVIDENCE_DIR/negative3-checks.tsv" "$NEG3_RC" "negative3"
mv "$EVIDENCE_DIR/negative3-checks.tsv" "$LOG_DIR/negative3-checks.tsv" 2>/dev/null || true

# --------------------------------------------------------------------- summary
if [ "$FAILED" -eq 0 ]; then
  echo "==> deb gate PASSED (package: $DEB)"
else
  echo "==> deb gate FAILED (evidence: $EVIDENCE_JSON)"
  exit 1
fi
