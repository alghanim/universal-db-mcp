#!/usr/bin/env bash
# Version matrix: start each server version in a container, seed, probe with
# the udbmcp connectors, record JSON evidence. Staging machine only (pulls
# images). Usage: run.sh [engine ...]   (default: the light engines)
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT="$(cd "$HERE/../.." && pwd -P)"
PY="$PROJECT/.venv/bin/python"
EV="$PROJECT/test-evidence/version-matrix"
mkdir -p "$EV"
PW="VmProbe_2026x"
PWFILE="$(mktemp)"; printf '%s\n' "$PW" > "$PWFILE"; chmod 600 "$PWFILE"
trap 'rm -f "$PWFILE"' EXIT

# engine|image|container port|host port|platform flag|readiness command (runs inside container)|env...
MATRIX_LIGHT=(
  "postgres|postgres:12|5432|55412||pg_isready -U postgres|POSTGRES_PASSWORD=$PW"
  "postgres|postgres:13|5432|55413||pg_isready -U postgres|POSTGRES_PASSWORD=$PW"
  "postgres|postgres:14|5432|55414||pg_isready -U postgres|POSTGRES_PASSWORD=$PW"
  "postgres|postgres:15|5432|55415||pg_isready -U postgres|POSTGRES_PASSWORD=$PW"
  "postgres|postgres:16|5432|55416||pg_isready -U postgres|POSTGRES_PASSWORD=$PW"
  "postgres|postgres:17|5432|55417||pg_isready -U postgres|POSTGRES_PASSWORD=$PW"
  "mysql|mysql:5.7|3306|55357|--platform linux/amd64|mysqladmin ping -uroot -p$PW --silent|MYSQL_ROOT_PASSWORD=$PW"
  "mysql|mysql:8.0|3306|55380||mysqladmin ping -uroot -p$PW --silent|MYSQL_ROOT_PASSWORD=$PW"
  "mysql|mysql:8.4|3306|55384||mysqladmin ping -uroot -p$PW --silent|MYSQL_ROOT_PASSWORD=$PW"
  "mysql|mariadb:10.6|3306|55306||mariadb-admin ping -uroot -p$PW --silent|MARIADB_ROOT_PASSWORD=$PW"
  "mysql|mariadb:11.4|3306|55314||mariadb-admin ping -uroot -p$PW --silent|MARIADB_ROOT_PASSWORD=$PW"
  "clickhouse|clickhouse/clickhouse-server:23.8|8123|55238||clickhouse-client -q 'SELECT 1'|CLICKHOUSE_PASSWORD=$PW"
  "clickhouse|clickhouse/clickhouse-server:24.3|8123|55243||clickhouse-client -q 'SELECT 1'|CLICKHOUSE_PASSWORD=$PW"
  "clickhouse|clickhouse/clickhouse-server:24.8|8123|55248||clickhouse-client -q 'SELECT 1'|CLICKHOUSE_PASSWORD=$PW"
  "clickhouse|clickhouse/clickhouse-server:25.3|8123|55253||clickhouse-client -q 'SELECT 1'|CLICKHOUSE_PASSWORD=$PW"
)
MATRIX_HEAVY=(
  "oracle|gvenzl/oracle-xe:11.2.0.2-slim|1521|55111|--platform linux/amd64|healthcheck.sh|ORACLE_PASSWORD=$PW"
  "oracle|gvenzl/oracle-xe:18.4.0-slim|1521|55118|--platform linux/amd64|healthcheck.sh|ORACLE_PASSWORD=$PW"
  "oracle|gvenzl/oracle-xe:21.3.0-slim|1521|55121|--platform linux/amd64|healthcheck.sh|ORACLE_PASSWORD=$PW"
  "oracle|gvenzl/oracle-free:23-slim|1521|55123||healthcheck.sh|ORACLE_PASSWORD=$PW"
  "db2|icr.io/db2_community/db2:11.5.8.0|50000|55158|--platform linux/amd64 --privileged|su - db2inst1 -c 'db2 connect to vmdb'|LICENSE=accept DB2INST1_PASSWORD=$PW DBNAME=vmdb"
  "db2|icr.io/db2_community/db2:11.5.9.0|50000|55159|--platform linux/amd64 --privileged|su - db2inst1 -c 'db2 connect to vmdb'|LICENSE=accept DB2INST1_PASSWORD=$PW DBNAME=vmdb"
)
# SQL Server needs the ODBC driver on the probe side; run its probe inside the
# Gate C client image (see run_mssql.sh) rather than natively.

user_for() { case "$1" in postgres) echo postgres;; mysql) echo root;; clickhouse) echo default;; oracle) echo system;; db2) echo db2inst1;; esac; }
db_for()   { case "$1" in postgres) echo postgres;; mysql) echo mysql;; clickhouse) echo default;; oracle) echo "$2";; db2) echo vmdb;; esac; }

run_one() {
  local spec="$1"
  IFS='|' read -r engine image cport hport platform ready envs <<<"$spec"
  local name="vm-$(echo "$image" | tr '/:.' '---')"
  local label="$image"
  local out="$EV/$(echo "$image" | tr '/:' '__').json"
  echo "==> $label"
  docker rm -f "$name" >/dev/null 2>&1 || true
  local env_args=()
  for kv in $envs; do env_args+=(-e "$kv"); done
  # shellcheck disable=SC2086
  if ! docker run -d --name "$name" $platform "${env_args[@]}" -p "127.0.0.1:$hport:$cport" "$image" >/dev/null 2>"$EV/$name.start.err"; then
    echo "   start FAILED: $(tail -c 200 "$EV/$name.start.err")"
    printf '{"label":"%s","engine":"%s","status":"not_run","reason":"container start failed"}\n' "$label" "$engine" > "$out"
    return
  fi
  local waited=0 ready_ok=0 max_wait=240
  [ "$engine" = "db2" ] && max_wait=1800
  [ "$engine" = "oracle" ] && max_wait=1200
  # The official mysql/mariadb images start a TEMPORARY server for their
  # init scripts, then restart: a single successful ping can hit the
  # temporary instance and the real one drops the probe's connection
  # ("Lost connection ... during query", seen on mysql:5.7). Require the
  # readiness command to succeed on three consecutive checks 5 s apart.
  local streak=0 need=1
  [ "$engine" = "mysql" ] && need=3
  while [ "$waited" -lt "$max_wait" ]; do
    if docker exec "$name" sh -c "$ready" >/dev/null 2>&1; then
      streak=$((streak + 1))
      if [ "$streak" -ge "$need" ]; then ready_ok=1; break; fi
    else
      streak=0
    fi
    sleep 5; waited=$((waited + 5))
  done
  if [ "$ready_ok" -ne 1 ]; then
    echo "   readiness TIMEOUT after ${waited}s"
    printf '{"label":"%s","engine":"%s","status":"not_run","reason":"readiness timeout %ss"}\n' "$label" "$engine" "$waited" > "$out"
    docker rm -f "$name" >/dev/null 2>&1 || true
    return
  fi
  sleep 3
  local db; db="$(db_for "$engine" "")"
  case "$image" in *oracle-xe:11.2*) db=XE;; *oracle-xe:18*|*oracle-xe:21*) db=XEPDB1;; *oracle-free*) db=FREEPDB1;; esac
  "$PY" "$HERE/probe.py" --engine "$engine" --host 127.0.0.1 --port "$hport" --database "$db" \
     --user "$(user_for "$engine")" --password-file "$PWFILE" --label "$label" --out "$out" 2>&1 | tail -3
  docker rm -f "$name" >/dev/null 2>&1 || true
}

selected=("$@")
[ ${#selected[@]} -eq 0 ] && selected=(light)
for sel in "${selected[@]}"; do
  case "$sel" in
    light) for s in "${MATRIX_LIGHT[@]}"; do run_one "$s"; done ;;
    heavy) for s in "${MATRIX_HEAVY[@]}"; do run_one "$s"; done ;;
    *) for s in "${MATRIX_LIGHT[@]}" "${MATRIX_HEAVY[@]}"; do [[ "$s" == "$sel|"* ]] && run_one "$s"; done ;;
  esac
done
"$PY" - "$EV" <<'PY'
import json, sys, pathlib
ev = pathlib.Path(sys.argv[1])
rows = []
for f in sorted(ev.glob("*.json")):
    d = json.loads(f.read_text())
    if "summary" in d:
        rows.append((d["label"], str(d.get("server_version") or "")[:30], d["summary"]["passed"], ",".join(d["summary"]["failed"]) or "-"))
    else:
        rows.append((d.get("label", f.name), "", 0, d.get("reason", "not_run")))
w = max(len(r[0]) for r in rows) if rows else 10
print(f"{'image':<{w}}  {'server':<30}  passed  failed")
for r in rows:
    print(f"{r[0]:<{w}}  {r[1]:<30}  {r[2]:>6}  {r[3]}")
PY
