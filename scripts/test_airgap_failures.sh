#!/usr/bin/env bash
# Gate A negative cases: every failure must be prompt, actionable, and free
# of network download attempts. Each case runs in its own --network none
# container against a doctored COPY of the bundle (originals never modified).
#
# A fail_fast case is only credited when the verifier exits nonzero, makes no
# network contact, AND emits that case's expected actionable diagnostic. A
# crash, a key-parse error, or a "signed but no pubkey" refusal is a FAIL,
# not a pass. The release public key is mounted read-only into every
# verification container so authenticity is always enforced (--pubkey).
set -uo pipefail

PROJECT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$PROJECT/out"
WORK="$(mktemp -d)"
IMAGE="udbmcp-baseline:ubuntu24.04-cp312"
BUNDLE_SRC="$(ls -d "$OUT"/bundle/universal-db-mcp-* | head -1)"
EVID="$OUT/airgap-failure-evidence"
mkdir -p "$EVID"
FAILED=0

# Independently distributed release public key (never shipped inside the
# bundle); override with RELEASE_PUBKEY when rotating keys. Without it the
# signed bundle fails closed on "signed but no pubkey", which would make
# every tamper case pass for the wrong reason — so refuse to run instead.
RELEASE_PUBKEY="${RELEASE_PUBKEY:-$OUT/demo-keys/udbmcp-release-demo.pub.pem}"
[ -f "$RELEASE_PUBKEY" ] || {
  echo "release public key not found: $RELEASE_PUBKEY"
  echo "set RELEASE_PUBKEY to the trusted Ed25519 public key PEM and re-run"
  exit 2
}

summary() {
  echo "{"
  echo "  \"gate\": \"A-negative-failure-modes\","
  echo "  \"cases\": [$CASES"
  echo "  ],"
  echo "  \"status\": \"$([ "$FAILED" = 0 ] && echo passed || echo failed)\""
} > "$EVID/results.json"
CASES=""

check() { # name expectation bundle-dir command expected-diagnostic-regex [pubkey-file]
  local name="$1" expect="$2" bundledir="$3" cmd="$4" pattern="${5:-}" keyfile="${6:-$RELEASE_PUBKEY}"
  local out rc passed=false matched=""
  local -a mounts=()
  [ -n "$keyfile" ] && mounts+=( -v "$keyfile":/pubkey.pem:ro )
  out="$(docker run --rm --network none --platform linux/amd64 \
      -v "$bundledir":/bundle:ro "${mounts[@]+"${mounts[@]}"}" -e BUNDLE=/bundle "$IMAGE" \
      bash -c "$cmd" 2>&1)"
  rc=$?
  if [ "$expect" = "fail_fast" ]; then
    # nonzero rc + no network contact + the expected actionable diagnostic;
    # any one missing means the failure was observed for the wrong reason.
    if [ "$rc" -ne 0 ] && ! echo "$out" | grep -qiE "download|fetch|pypi|index" \
        && [ -n "$pattern" ] && echo "$out" | grep -qiE "$pattern"; then
      passed=true
      matched="$(echo "$out" | grep -oiE "$pattern" | head -1)"
    fi
  elif [ "$expect" = "pass" ] && [ "$rc" -eq 0 ]; then
    passed=true
  fi
  echo "{\"case\": \"$name\", \"passed\": $passed, \"exit\": $rc, \"diagnostic\": \"$matched\"}" > "$EVID/$name.json"
  printf '%s' "$out" > "$EVID/$name.output.txt"
  [ "$CASES" = "" ] && CASES="$(cat "$EVID/$name.json")" || CASES="$CASES, $(cat "$EVID/$name.json")"
  if [ "$passed" = true ]; then
    echo "[pass] $name (diagnostic: $matched)"
  else
    echo "[FAIL] $name (rc=$rc, expected diagnostic: ${pattern:-<none specified>})"
    FAILED=1
  fi
}

# --- case 1: tampered wheel -------------------------------------------------
cp -R "$BUNDLE_SRC" "$WORK/tampered"
W=$(ls "$WORK/tampered/wheelhouse"/sqlglot-*.whl | head -1)
printf 'X' | dd of="$W" bs=1 seek=200 conv=notrunc 2>/dev/null
check tampered_wheel fail_fast "$WORK/tampered" \
  "python3 /bundle/installers/verify_bundle.py --bundle /bundle --pubkey /pubkey.pem 2>&1; rc=\$?; echo rc=\$rc; exit \$rc" \
  "tampered artifact"

# --- case 2: missing wheel --------------------------------------------------
cp -R "$BUNDLE_SRC" "$WORK/missing"
rm "$(ls "$WORK/missing/wheelhouse"/sqlglot-*.whl | head -1)"
check missing_wheel fail_fast "$WORK/missing" \
  "python3 /bundle/installers/verify_bundle.py --bundle /bundle --pubkey /pubkey.pem 2>&1; rc=\$?; echo rc=\$rc; exit \$rc" \
  "wheel missing from wheelhouse"

# --- case 3: wrong-ABI wheel substituted ------------------------------------
# sqlglot is a py3-none-any wheel, so retagging it is a no-op; use a platform
# wheel (psycopg_binary cp312 manylinux) and retag it to cp311. The verifier
# must reject the substituted bundle fail-closed: the retagged wheel is not
# covered by SHA256SUMS and the original artifact is missing.
cp -R "$BUNDLE_SRC" "$WORK/abi"
W=$(ls "$WORK/abi/wheelhouse"/psycopg_binary-*.whl | head -1)
V=$(basename "$W")
cp "$W" "$WORK/abi/wheelhouse/$(echo "$V" | sed 's/cp312/cp311/g')"
rm "$W"
check incompatible_abi fail_fast "$WORK/abi" \
  "python3 /bundle/installers/verify_bundle.py --bundle /bundle --pubkey /pubkey.pem 2>&1; rc=\$?; echo rc=\$rc; exit \$rc" \
  "NOT covered by SHA256SUMS"

# --- case 4: signature by untrusted key -------------------------------------
# Sign a doctored SHA256SUMS with a throwaway key; verification against the
# independently distributed release public key must FAIL with an explicit
# untrusted-signature diagnostic. A key-parse error (e.g. feeding a private
# key to --pubkey) proves nothing and is not accepted. If every signer fails
# and the original SIGNATURE survives, the case would be vacuous (the
# verifier passes because the bundle is intact) — so the gate refuses to run
# instead of recording a bogus pass.
sig_sha() { (shasum -a 256 "$1" 2>/dev/null || sha256sum "$1") | awk '{print $1}'; }
cp -R "$BUNDLE_SRC" "$WORK/sig"
ORIG_SIG_SHA="$(sig_sha "$BUNDLE_SRC/SIGNATURE")"
docker run --rm --platform linux/amd64 -v "$WORK/sig":/b alpine/openssl sh -c "openssl genpkey -algorithm ed25519 -out /tmp/k.pem 2>/dev/null && openssl pkeyutl -sign -inkey /tmp/k.pem -rawin -in /b/SHA256SUMS -out /b/SIGNATURE" 2>/dev/null || true
if ! [ -s "$WORK/sig/SIGNATURE" ] || [ "$(sig_sha "$WORK/sig/SIGNATURE")" = "$ORIG_SIG_SHA" ]; then
  # fallback: openssl on host (raw digest, not a pipe — OpenSSL 3 cannot read
  # pkeyutl -rawin from stdin)
  openssl genpkey -algorithm ed25519 -out "$WORK/k.pem" 2>/dev/null
  openssl pkeyutl -sign -inkey "$WORK/k.pem" -rawin -in "$WORK/sig/SHA256SUMS" -out "$WORK/sig/SIGNATURE" 2>/dev/null || true
fi
if ! [ -s "$WORK/sig/SIGNATURE" ] || [ "$(sig_sha "$WORK/sig/SIGNATURE")" = "$ORIG_SIG_SHA" ]; then
  # fallback: python cryptography (works under LibreSSL hosts where pkeyutl
  # lacks Ed25519 support)
  PY_SIGN="$(command -v "$PROJECT/.venv/bin/python" 2>/dev/null || command -v python3)"
  "$PY_SIGN" - "$WORK/sig" <<'PYEOF'
import sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
b = Path(sys.argv[1])
key = Ed25519PrivateKey.generate()
(b / "SIGNATURE").write_bytes(key.sign((b / "SHA256SUMS").read_bytes()))
PYEOF
fi
if ! [ -s "$WORK/sig/SIGNATURE" ] || [ "$(sig_sha "$WORK/sig/SIGNATURE")" = "$ORIG_SIG_SHA" ]; then
  echo "untrusted_signature case: could not produce a foreign signature on this host;"
  echo "running it would be vacuous (the intact bundle verifies legitimately). Aborting."
  exit 2
fi
check untrusted_signature fail_fast "$WORK/sig" \
  "python3 /bundle/installers/verify_bundle.py --bundle /bundle --pubkey /pubkey.pem 2>&1; rc=\$?; echo rc=\$rc; exit \$rc" \
  "signature verification FAILED"

# --- case 5: missing licensed-driver profile blocks readiness ---------------
cp -R "$BUNDLE_SRC" "$WORK/lic"
rm -f "$WORK/lic/wheelhouse"/ibm_db-*.whl
check missing_licensed_driver fail_fast "$WORK/lic" \
  "out=\$(python3 /bundle/installers/verify_bundle.py --bundle /bundle --pubkey /pubkey.pem 2>&1); rc=\$?; echo \"\$out\"; echo verifier_rc=\$rc; echo \"\$out\" | grep -qE 'wheel missing|missing_from_closure' || { echo NO_MISSING_WHEEL_REPORTED; exit 9; }; exit \$rc" \
  "wheel missing|missing_from_closure"

# --- case 6: hostile inherited pip config cannot trigger a download ---------
# The real guarantee: the hash-pinned, --no-index --isolated install IGNORES
# inherited hostile pip config and still completes with zero index contact.
check hostile_pip_env pass "$BUNDLE_SRC" \
  'export PIP_INDEX_URL=https://attacker.invalid/simple PIP_CONFIG_FILE=/etc/pip.conf; python3 -m venv /tmp/v >/tmp/v.log 2>&1 || { cat /tmp/v.log; exit 5; }; /tmp/v/bin/pip install --isolated --disable-pip-version-check --no-index --find-links=/bundle/wheelhouse --only-binary=:all: --require-hashes -r /bundle/requirements/runtime.lock >/tmp/pip.log 2>&1; rc=$?; echo "install_rc=$rc"; grep -c "attacker.invalid" /tmp/pip.log > /tmp/hits || true; echo "download_hits=$(cat /tmp/hits)"; if [ "$(cat /tmp/hits)" != "0" ]; then echo DOWNLOAD_ATTEMPTED; exit 4; fi; tail -2 /tmp/pip.log; exit $rc'

rm -rf "$WORK"
summary
cat "$EVID/results.json"
echo
[ "$FAILED" = 0 ] && echo "failure-mode gate: PASSED" || echo "failure-mode gate: FAILED"
exit "$FAILED"
