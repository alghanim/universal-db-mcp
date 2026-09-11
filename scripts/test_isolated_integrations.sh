#!/usr/bin/env bash
# Gate C orchestrator: internal-network fixture + client isolation.
#
# Docker drops port publishing on --internal networks, so BOTH the fixture
# engines and the pytest client run ON the internal network (no external
# route exists for anyone). The client image is built once on the staging
# machine with the pinned driver wheels; at run time nothing pulls anything.
#
# Light engines (postgres, mysql, clickhouse) are attempted on every run.
# Heavy engines (oracle, mssql, db2) require UDBMCP_TEST_ALLOW_HEAVY=1 —
# they are large images and slow under emulation; unavailable engines are
# recorded blocked. Every engine gets THEMED mock data (scripts/fixtures/seed):
#   postgres=oceanographic buoys, mysql=coffee roastery, clickhouse=telecom
#   call data records, oracle=air travellers, mssql=hospital, db2=ministry
#   of interior civil registry.
set -uo pipefail

PROJECT="$(cd "$(dirname "$0")/.." && pwd)"
EVID="$PROJECT/out/integration-evidence"
SEEDS="$PROJECT/scripts/fixtures/seed"
mkdir -p "$EVID"
NET="udbmcp-internal-test"
CLIENT_IMG="udbmcp-test-client:cp312b"
FAILED=0
CLEANUP=()

cleanup() {
  for n in ${CLEANUP[@]+"${CLEANUP[@]}"}; do
    docker rm -f "udbmcp-fixture-$n" >/dev/null 2>&1 || true
  done
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker network inspect "$NET" >/dev/null 2>&1 || docker network create --internal "$NET" >/dev/null

echo "==> building test-client image (staging only; drivers pinned)"
if ! docker image inspect "$CLIENT_IMG" >/dev/null 2>&1; then
  docker build --platform linux/amd64 -t "$CLIENT_IMG" -f - . <<'DOCKERFILE' || { echo "client image build FAILED"; exit 1; }
FROM python:3.12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends unixodbc curl gnupg ca-certificates \
 && curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor -o /usr/share/keyrings/microsoft-prod.gpg \
 && curl -fsSL https://packages.microsoft.com/config/debian/12/prod.list -o /etc/apt/sources.list.d/mssql-release.list \
 && (apt-get update && ACCEPT_EULA=Y apt-get install -y --no-install-recommends msodbcsql18 || echo "msodbcsql18 unavailable; mssql tests will skip") \
 && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir "psycopg[binary]==3.3.5" "PyMySQL==1.2.0" "clickhouse-connect==1.8.0" \
      "oracledb==4.0.2" "pyodbc==5.3.0" "ibm-db==3.2.9" \
      "PyYAML==6.0.3" "sqlglot==30.18.0" "mcp==2.2.0" pytest==9.1.1
DOCKERFILE
fi

ENV_ARGS=()

run_fixture() { # name image [docker args...]  (docker args precede the image)
  local name="$1" image="$2"; shift 2
  docker rm -f "udbmcp-fixture-$name" >/dev/null 2>&1 || true
  docker run -d --name "udbmcp-fixture-$name" --network "$NET" "$@" "$image" >/dev/null 2>&1 || {
    echo "[fixture $name] start failed"; return 1; }
  CLEANUP+=("$name")
  return 0
}

fixture_up() { # name — true if image exists locally or can be pulled on staging
  local name="$1" image="$2"
  if ! docker image inspect "$image" >/dev/null 2>&1; then
    echo "[fixture $name] image $image not local; pulling on staging machine"
    docker pull "$image" >/dev/null 2>&1 || { echo "[fixture $name] BLOCKED: image unavailable"; return 1; }
  fi
  return 0
}

wait_ready() { # name ready-cmd max-wait-seconds
  local name="$1" cmd="$2" max="${3:-60}" i=0
  until docker exec "udbmcp-fixture-$name" bash -c "$cmd" >/dev/null 2>&1; do
    i=$((i + 1))
    [ "$i" -ge "$max" ] && { echo "[fixture $name] BLOCKED: not ready after ${max}s"; return 1; }
    sleep 1
  done
  echo "[fixture $name] ready after ${i}s"
  return 0
}

# --- PostgreSQL (theme: oceanographic buoy network) ---------------------------
if fixture_up postgres postgres:17 \
   && run_fixture postgres postgres:17 -e POSTGRES_PASSWORD=udbmcp_ro_pw -e POSTGRES_USER=postgres \
   && wait_ready postgres "pg_isready -U postgres" 60; then
  docker exec udbmcp-fixture-postgres psql -U postgres -c \
    "CREATE SCHEMA reporting; CREATE ROLE udbmcp_ro LOGIN PASSWORD 'udbmcp_ro_pw'; GRANT USAGE ON SCHEMA reporting TO udbmcp_ro; CREATE TABLE reporting.demo (id int); GRANT SELECT ON reporting.demo TO udbmcp_ro; CREATE TABLE reporting.secret (s text);" \
    >/dev/null 2>&1 || true
  if docker exec -i udbmcp-fixture-postgres psql -U postgres -v ON_ERROR_STOP=1 < "$SEEDS/pg_ocean_buoys.sql" >/dev/null 2>&1 \
     && docker exec udbmcp-fixture-postgres psql -U postgres -c \
        "GRANT USAGE ON SCHEMA ocean TO udbmcp_ro; GRANT SELECT ON ALL TABLES IN SCHEMA ocean TO udbmcp_ro;" >/dev/null 2>&1; then
    echo "[fixture postgres] themed data seeded (ocean buoys)"
    ENV_ARGS+=(-e UDBMCP_TEST_POSTGRES_HOST=udbmcp-fixture-postgres -e UDBMCP_TEST_POSTGRES_PORT=5432
               -e UDBMCP_TEST_POSTGRES_DB=postgres -e UDBMCP_TEST_POSTGRES_USER=udbmcp_ro
               -e UDBMCP_TEST_POSTGRES_PASSWORD=udbmcp_ro_pw)
  else
    echo "postgres: themed seed failed"
  fi
else
  echo "postgres: blocked"
fi

# --- MySQL (theme: specialty coffee roastery) ---------------------------------
if fixture_up mysql mysql:9 \
   && run_fixture mysql mysql:9 -e MYSQL_ROOT_PASSWORD=root -e MYSQL_DATABASE=testdb \
        -e MYSQL_USER=udbmcp_ro -e MYSQL_PASSWORD=udbmcp_ro_pw \
   && wait_ready mysql "mysql -uudbmcp_ro -pudbmcp_ro_pw -e 'SELECT 1'" 120; then
  if docker exec -i udbmcp-fixture-mysql mysql -uudbmcp_ro -pudbmcp_ro_pw testdb < "$SEEDS/mysql_roastery.sql" >/dev/null 2>&1; then
    echo "[fixture mysql] themed data seeded (roastery batches)"
    ENV_ARGS+=(-e UDBMCP_TEST_MYSQL_HOST=udbmcp-fixture-mysql -e UDBMCP_TEST_MYSQL_PORT=3306
               -e UDBMCP_TEST_MYSQL_DB=testdb -e UDBMCP_TEST_MYSQL_USER=udbmcp_ro
               -e UDBMCP_TEST_MYSQL_PASSWORD=udbmcp_ro_pw)
  else
    echo "mysql: themed seed failed"
  fi
else
  echo "mysql: blocked"
fi

# --- ClickHouse (theme: telecom call data records) ----------------------------
if fixture_up clickhouse clickhouse/clickhouse-server:latest \
   && run_fixture clickhouse clickhouse/clickhouse-server:latest -e CLICKHOUSE_PASSWORD=udbmcp_ro_pw \
   && wait_ready clickhouse "wget -qO- http://localhost:8123/ping | grep -q Ok" 60; then
  if docker exec -i udbmcp-fixture-clickhouse clickhouse-client --password udbmcp_ro_pw --multiquery \
       < "$SEEDS/clickhouse_cdr.sql" >/dev/null 2>&1; then
    echo "[fixture clickhouse] themed data seeded (250k call data records)"
    ENV_ARGS+=(-e UDBMCP_TEST_CLICKHOUSE_HOST=udbmcp-fixture-clickhouse -e UDBMCP_TEST_CLICKHOUSE_PORT=8123
               -e UDBMCP_TEST_CLICKHOUSE_DB=default -e UDBMCP_TEST_CLICKHOUSE_USER=default
               -e UDBMCP_TEST_CLICKHOUSE_PASSWORD=udbmcp_ro_pw)
  else
    echo "clickhouse: themed seed failed"
  fi
else
  echo "clickhouse: blocked"
fi

# --- heavy engines (opt-in: UDBMCP_TEST_ALLOW_HEAVY=1) ------------------------
if [ "${UDBMCP_TEST_ALLOW_HEAVY:-0}" = "1" ]; then

  # Oracle Free (theme: air travellers)
  if fixture_up oracle container-registry.oracle.com/database/free:latest \
     && run_fixture oracle container-registry.oracle.com/database/free:latest \
          -v "$SEEDS":/seed:ro -e ORACLE_PWD=UdbmcpOracle_23ai \
     && wait_ready oracle 'echo "SELECT 1 FROM DUAL;" | sqlplus -S -L system/"UdbmcpOracle_23ai"@localhost:1521/FREEPDB1 >/dev/null' 2400; then
    echo "[fixture oracle] seeding travellers schema (may take a minute under emulation)"
    if docker exec udbmcp-fixture-oracle bash -c 'sqlplus -S /nolog @/seed/oracle_travellers.sql' >/tmp/oracle_seed.log 2>&1; then
      echo "[fixture oracle] themed data seeded (travellers/flights/bookings)"
      ENV_ARGS+=(-e UDBMCP_TEST_ORACLE_HOST=udbmcp-fixture-oracle -e UDBMCP_TEST_ORACLE_PORT=1521
                 -e UDBMCP_TEST_ORACLE_DB=FREEPDB1 -e UDBMCP_TEST_ORACLE_USER=travel
                 -e UDBMCP_TEST_ORACLE_PASSWORD=Travel_Pass_1)
    else
      echo "oracle: themed seed FAILED"; tail -5 /tmp/oracle_seed.log
    fi
  else
    echo "oracle: blocked"
  fi

  # SQL Server 2022 (theme: hospital clinical records)
  if fixture_up mssql mcr.microsoft.com/mssql/server:2022-latest \
     && run_fixture mssql mcr.microsoft.com/mssql/server:2022-latest --platform linux/amd64 \
          -v "$SEEDS":/seed:ro -e ACCEPT_EULA=Y -e MSSQL_SA_PASSWORD=UdbmcpMssql_2022 -e MSSQL_PID=Developer \
     && wait_ready mssql '/opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -P "UdbmcpMssql_2022" -C -Q "SELECT 1" -b' 900; then
    if docker exec udbmcp-fixture-mssql /opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -P "UdbmcpMssql_2022" -C \
         -i /seed/mssql_hospital.sql >/dev/null 2>&1; then
      echo "[fixture mssql] themed data seeded (hospital admissions)"
      ENV_ARGS+=(-e UDBMCP_TEST_MSSQL_HOST=udbmcp-fixture-mssql -e UDBMCP_TEST_MSSQL_PORT=1433
                 -e UDBMCP_TEST_MSSQL_DB=HospitalDB -e UDBMCP_TEST_MSSQL_USER=sa
                 -e UDBMCP_TEST_MSSQL_PASSWORD=UdbmcpMssql_2022)
    else
      echo "mssql: themed seed FAILED"
    fi
  else
    echo "mssql: blocked"
  fi

  # Db2 Community LUW (theme: ministry of interior civil registry)
  if fixture_up db2 icr.io/db2_community/db2:11.5.9.0 \
     && run_fixture db2 icr.io/db2_community/db2:11.5.9.0 --platform linux/amd64 --privileged \
          -v "$SEEDS":/seed:ro -e LICENSE=accept -e DB2INST1_PASSWORD=udbmcp_db2_1 -e DBNAME=testdb \
     && wait_ready db2 'su - db2inst1 -c "db2 connect to testdb >/dev/null && db2 disconnect testdb >/dev/null"' 1800; then
    if docker exec udbmcp-fixture-db2 su - db2inst1 -c 'db2 -tvf /seed/db2_moi.sql' >/tmp/db2_seed.log 2>&1; then
      echo "[fixture db2] themed data seeded (civil registry)"
      # Client-auth probe: the pinned ibm_db 3.2.9 clidriver fails its LOCAL
      # security init under amd64-on-arm64 qemu emulation (SQL30082N reason 17
      # is returned even for a dead port, i.e. before any network exchange),
      # while the server's own clidriver authenticates fine over TCP. Export
      # the fixture env only if the pinned client can truly authenticate;
      # otherwise record Db2 as blocked on the staging host's emulation.
      if docker run --rm --platform linux/amd64 --network "$NET" "$CLIENT_IMG" \
           python -c "import ibm_db; ibm_db.connect('DATABASE=TESTDB;HOSTNAME=udbmcp-fixture-db2;PORT=50000;PROTOCOL=TCPIP;', 'db2inst1', 'udbmcp_db2_1')" >/dev/null 2>&1; then
        echo "[fixture db2] pinned-client authentication probe OK"
        ENV_ARGS+=(-e UDBMCP_TEST_DB2_HOST=udbmcp-fixture-db2 -e UDBMCP_TEST_DB2_PORT=50000
                   -e UDBMCP_TEST_DB2_DB=TESTDB -e UDBMCP_TEST_DB2_USER=db2inst1
                   -e UDBMCP_TEST_DB2_PASSWORD=udbmcp_db2_1)
      else
        echo "db2: BLOCKED - pinned clidriver security init fails under amd64 emulation on this staging host (server verified: started, seeded, local+TCP auth OK via its own clidriver); re-run on a native x86_64 host"
      fi
    else
      echo "db2: themed seed FAILED"; tail -5 /tmp/db2_seed.log
    fi
  else
    echo "db2: blocked"
  fi

else
  echo "oracle/mssql/db2 fixtures: BLOCKED (heavy images; set UDBMCP_TEST_ALLOW_HEAVY=1 to attempt)"
fi

# Classify a pytest run from its exit code AND its summary line. pytest exits
# 0 when every test was skipped, so the exit code alone cannot distinguish a
# real pass from a fully blocked run: the gate requires passed >= 1. Sets
# PASSED / TEST_FAILED / TEST_SKIPPED / TEST_ERRORS (counts, 0 when absent),
# RUN_STATUS ("passed" | "blocked" | "failed") and FAILED (gate outcome; the
# default is fail-closed). Kept as a function so unit tests can exercise the
# summary parsing without docker.
classify_pytest_run() { # rc log-path
  local rc="$1" log="$2" line=""
  PASSED=0; TEST_FAILED=0; TEST_SKIPPED=0; TEST_ERRORS=0
  FAILED=1; RUN_STATUS="blocked"
  line="$(grep -E '[0-9]+ (passed|failed|skipped|error)|no tests ran' "$log" 2>/dev/null | tail -1 || true)"
  if [ -n "$line" ]; then
    [[ "$line" =~ ([0-9]+)\ passed ]] && PASSED="${BASH_REMATCH[1]}"
    [[ "$line" =~ ([0-9]+)\ failed ]] && TEST_FAILED="${BASH_REMATCH[1]}"
    [[ "$line" =~ ([0-9]+)\ skipped ]] && TEST_SKIPPED="${BASH_REMATCH[1]}"
    [[ "$line" =~ ([0-9]+)\ error ]] && TEST_ERRORS="${BASH_REMATCH[1]}"
  fi
  if [ "$rc" -ne 0 ]; then
    RUN_STATUS="failed"
  elif [ "$PASSED" -ge 1 ] && [ "$TEST_FAILED" -eq 0 ] && [ "$TEST_ERRORS" -eq 0 ]; then
    FAILED=0
    RUN_STATUS="passed"
  fi
  # rc == 0 with PASSED == 0 stays blocked/FAILED=1: nothing actually ran.
}

# --- run the real-driver integration tests ON the internal network ------------
docker rm -f udbmcp-test-client >/dev/null 2>&1 || true
docker run --rm --name udbmcp-test-client --platform linux/amd64 \
  --network "$NET" \
  -v "$PROJECT/src":/app/src:ro \
  -v "$PROJECT/tests":/app/tests:ro \
  -v "$PROJECT/pyproject.toml":/app/pyproject.toml:ro \
  -w /app \
  "${ENV_ARGS[@]}" \
  "$CLIENT_IMG" \
  python -m pytest tests/integration/test_connectors.py -rs -v \
  2>&1 | tee "$EVID/integration-run.log" | tail -25
RC=${PIPESTATUS[0]}
classify_pytest_run "$RC" "$EVID/integration-run.log"

echo "gate C: $RUN_STATUS (passed=$PASSED failed=$TEST_FAILED skipped=$TEST_SKIPPED errors=$TEST_ERRORS)"

{
  echo "{"
  echo "  \"gate\": \"C-isolated-integrations\","
  echo "  \"network\": \"docker --internal network; fixtures AND test client attached; no external route\","
  echo "  \"heavy_engines\": \"${UDBMCP_TEST_ALLOW_HEAVY:-0}\","
  echo "  \"exit\": $RC,"
  echo "  \"status\": \"$RUN_STATUS\","
  echo "  \"passed\": $PASSED,"
  echo "  \"failed\": $TEST_FAILED,"
  echo "  \"skipped\": $TEST_SKIPPED,"
  echo "  \"errors\": $TEST_ERRORS"
  echo "}"
} > "$EVID/results.json"

echo "integration evidence: $EVID"
exit "$FAILED"
