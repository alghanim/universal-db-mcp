#!/usr/bin/env bash
# Oracle rows in THICK mode. Thin mode cannot reach Oracle 11.2 at all
# (DPY-3010, below python-oracledb's Thin floor) and an account carrying only
# the 10G verifier is refused on any version, so the probe runs inside a
# no-network container that has the administrator-supplied Instant Client
# (out/oracle-client/, fetched on the staging machine) loaded via ldconfig -
# the same setup the customer runbook prescribes. Staging machine only.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT="$(cd "$HERE/../.." && pwd -P)"
EV="$PROJECT/test-evidence/version-matrix"
mkdir -p "$EV"
NET="udbmcp-vm-oracle"
PW="VmProbe_2026x"
PWDIR="$(mktemp -d)"; printf '%s\n' "$PW" > "$PWDIR/pw"; chmod 600 "$PWDIR/pw"
trap 'rm -rf "$PWDIR"; docker network rm "$NET" >/dev/null 2>&1 || true' EXIT
docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET" >/dev/null
WHEELHOUSE="$(ls -d "$PROJECT"/out/bundle/universal-db-mcp-*-linux-x86_64-*/wheelhouse | head -1)"
CLIENT_STAGE="$PROJECT/out/oracle-client"
[ -f "$CLIENT_STAGE/instantclient-basiclite-linux.x64-19.28.zip" ] || { echo "Instant Client zip missing under out/oracle-client/" >&2; exit 1; }

IMAGES=("gvenzl/oracle-xe:11.2.0.2-slim|XE" "gvenzl/oracle-xe:18.4.0-slim|XEPDB1" "gvenzl/oracle-free:23-slim|FREEPDB1")
[ $# -gt 0 ] && IMAGES=("$@")
for spec in "${IMAGES[@]}"; do
  image="${spec%%|*}"; service="${spec##*|}"
  name="vm-thick-$(echo "$image" | tr '/:.' '---')"
  out="$EV/$(echo "$image" | tr '/:' '__').thick.json"
  echo "==> $image (thick, service $service)"
  docker rm -f "$name" >/dev/null 2>&1 || true
  platform=""; case "$image" in *oracle-xe*) platform="--platform linux/amd64";; esac
  # shellcheck disable=SC2086
  docker run -d --name "$name" $platform --network "$NET" -e "ORACLE_PASSWORD=$PW" "$image" >/dev/null 2>"$EV/$name.start.err" || {
    echo "   start FAILED"; printf '{"label":"%s (thick)","engine":"oracle","status":"not_run","reason":"container start failed"}\n' "$image" > "$out"; continue; }
  # emulated amd64 images on an arm64 host can need well over 25 minutes when
  # the machine is loaded; THICK_READY_SECONDS raises the ceiling
  waited=0; ready=0; ready_max="${THICK_READY_SECONDS:-1500}"
  while [ "$waited" -lt "$ready_max" ]; do
    # grep -c reads the whole stream: with pipefail, grep -q closing the pipe
    # early made `docker logs` exit 141 and readiness was NEVER detected once
    # the log grew past one pipe buffer (11.2 sat "booting" for 30 min, ready)
    if [ "$(docker logs "$name" 2>&1 | grep -c "DATABASE IS READY TO USE" || true)" -gt 0 ]; then ready=1; break; fi
    sleep 10; waited=$((waited + 10))
  done
  [ "$ready" -eq 1 ] || { echo "   readiness TIMEOUT"; printf '{"label":"%s (thick)","engine":"oracle","status":"not_run","reason":"readiness timeout"}\n' "$image" > "$out"; docker rm -f "$name" >/dev/null 2>&1; continue; }
  docker run --rm --platform linux/amd64 --network "$NET" \
    -v "$CLIENT_STAGE":/stage:ro -v "$WHEELHOUSE":/wh:ro -v "$PROJECT/src":/work/src:ro -v "$PROJECT/scripts":/work/scripts:ro \
    -v "$PWDIR":/secrets:ro -v "$EV":/out -w /work -e VM_ORACLE_THICK=1 \
    -e "VM_PROBE_REV=$(git -C "$PROJECT" rev-parse --short HEAD 2>/dev/null || echo unknown)" \
    udbmcp-baseline:ubuntu24.04-cp312 bash -c '
set -e
dpkg -i /stage/libaio1t64_*.deb >/dev/null 2>&1 || true
if ! ldconfig -p | grep -q "libaio.so.1 "; then t=$(ldconfig -p | sed -n "s/.*libaio.so.1t64 (libc6,x86-64) => //p" | head -1); [ -n "$t" ] && ln -sf "$t" "$(dirname "$t")/libaio.so.1"; fi
mkdir -p /opt/oracle && cd /opt/oracle && python3.12 -m zipfile -e /stage/instantclient-basiclite-linux.x64-19.28.zip /opt/oracle/ && chmod -R a+rX /opt/oracle
ls -d /opt/oracle/instantclient_* | head -1 > /etc/ld.so.conf.d/oracle-instantclient.conf && ldconfig
python3.12 -m venv /tmp/v >/dev/null && /tmp/v/bin/pip install --quiet --no-index --find-links /wh --only-binary=:all: oracledb PyYAML pydantic sqlglot mcp >/dev/null
cd /work && /tmp/v/bin/python scripts/version_matrix/probe.py --engine oracle --host '"$name"' --port 1521 --database '"$service"' --user system --password-file /secrets/pw --label "'"$image"' (thick)" --out /out/'"$(basename "$out")"'
' 2>&1 | tail -3
  docker rm -f "$name" >/dev/null 2>&1 || true
done
