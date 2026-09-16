#!/usr/bin/env bash
# SQL Server rows of the version matrix. The probe needs the Microsoft ODBC
# driver, which the staging Mac does not have natively, so it runs inside the
# Gate C client image (udbmcp-test-client, built by test_isolated_integrations.sh
# with msodbcsql18) on a docker network shared with each server container.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT="$(cd "$HERE/../.." && pwd -P)"
EV="$PROJECT/test-evidence/version-matrix"
mkdir -p "$EV"
CLIENT_IMG="udbmcp-test-client:cp312b"
NET="udbmcp-vm-mssql"
PW="VmProbe_2026x"
PWDIR="$(mktemp -d)"; printf '%s\n' "$PW" > "$PWDIR/pw"; chmod 600 "$PWDIR/pw"
trap 'rm -rf "$PWDIR"; docker network rm "$NET" >/dev/null 2>&1 || true' EXIT
docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET" >/dev/null

if ! docker image inspect "$CLIENT_IMG" >/dev/null 2>&1; then
  echo "client image $CLIENT_IMG missing; build it with scripts/test_isolated_integrations.sh first" >&2
  exit 1
fi
if ! docker run --rm --platform linux/amd64 "$CLIENT_IMG" python -c "import pyodbc; assert any('SQL Server' in d for d in pyodbc.drivers())" >/dev/null 2>&1; then
  echo "client image has no SQL Server ODBC driver; SQL Server rows stay not_run" >&2
  exit 1
fi

IMAGES=(
  "mcr.microsoft.com/mssql/server:2017-latest"
  "mcr.microsoft.com/mssql/server:2019-latest"
  "mcr.microsoft.com/mssql/server:2022-latest"
)
for image in "${IMAGES[@]}"; do
  name="vm-$(echo "$image" | tr '/:.' '---')"
  out="$EV/$(echo "$image" | tr '/:' '__').json"
  echo "==> $image"
  docker rm -f "$name" >/dev/null 2>&1 || true
  if ! docker run -d --name "$name" --platform linux/amd64 --network "$NET" \
        -e ACCEPT_EULA=Y -e "MSSQL_SA_PASSWORD=$PW" -e MSSQL_PID=Developer "$image" >/dev/null 2>"$EV/$name.start.err"; then
    echo "   start FAILED: $(tail -c 200 "$EV/$name.start.err")"
    printf '{"label":"%s","engine":"mssql","status":"not_run","reason":"container start failed"}\n' "$image" > "$out"
    continue
  fi
  waited=0; ready=0
  while [ "$waited" -lt 900 ]; do
    for tools in /opt/mssql-tools18/bin/sqlcmd /opt/mssql-tools/bin/sqlcmd; do
      if docker exec "$name" "$tools" -S localhost -U sa -P "$PW" -C -Q "SELECT 1" -b >/dev/null 2>&1 \
         || docker exec "$name" "$tools" -S localhost -U sa -P "$PW" -Q "SELECT 1" -b >/dev/null 2>&1; then ready=1; break; fi
    done
    [ "$ready" -eq 1 ] && break
    sleep 5; waited=$((waited + 5))
  done
  if [ "$ready" -ne 1 ]; then
    echo "   readiness TIMEOUT after ${waited}s"
    printf '{"label":"%s","engine":"mssql","status":"not_run","reason":"readiness timeout %ss"}\n' "$image" "$waited" > "$out"
    docker rm -f "$name" >/dev/null 2>&1 || true
    continue
  fi
  docker run --rm --platform linux/amd64 --network "$NET" \
    -v "$PROJECT/src":/work/src:ro -v "$PROJECT/scripts":/work/scripts:ro -v "$PWDIR":/secrets:ro -v "$EV":/out \
    -w /work "$CLIENT_IMG" python scripts/version_matrix/probe.py --engine mssql --host "$name" --port 1433 \
    --database vm --user sa --password-file /secrets/pw --label "$image" --out "/out/$(basename "$out")" 2>&1 | tail -3
  docker rm -f "$name" >/dev/null 2>&1 || true
done
