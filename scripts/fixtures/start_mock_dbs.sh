#!/usr/bin/env bash
# Persistent themed mock-database fixtures (companion to the Gate C gate,
# which uses --internal networks and tears everything down afterwards).
#
# These run on a normal (non-internal) docker network with ports published
# to host LOOPBACK ONLY, are seeded with themed mock data, and are left
# RUNNING for inspection and manual MCP use.
#
#   postgres    127.0.0.1:5433  (oceanographic buoys)   user udbmcp_ro / udbmcp_ro_pw
#   mysql       127.0.0.1:3307  (coffee roastery)       user udbmcp_ro / udbmcp_ro_pw
#   clickhouse  127.0.0.1:8124  (telecom CDRs)          user default  / udbmcp_ro_pw
#   oracle      127.0.0.1:1522  (air travellers)        user travel   / Travel_Pass_1
#   mssql       127.0.0.1:1434  (hospital)              user udbmcp_ro / UdbmcpReader_2022 (db_datareader + SHOWPLAN)
#   db2         127.0.0.1:50002 (ministry of interior)  user db2inst1 / udbmcp_db2_1
#
# config.mockdbs.yaml takes each user name from UDBMCP_DEMO_<ENGINE>_USER (the
# script ends by printing the exports) and each password from
# out/mockdb-secrets/<engine>.pw, which this script writes.
# SQL Server's sa (UdbmcpMssql_2022) only seeds; the MCP never logs in as it.
# The reader's SHOWPLAN grant lets db_explain read plans; it gives no data access.
set -uo pipefail

PROJECT="$(cd "$(dirname "$0")/../.." && pwd)"
SEEDS="$PROJECT/scripts/fixtures/seed"
SECRETS="$PROJECT/out/mockdb-secrets"
NET="udbmcp-mockdb"

# Password files for the mock configs, 0600: the server refuses secret files
# that group or other can read. Keep them in step with the table above.
write_secret() { # engine password
  (umask 077 && mkdir -p "$SECRETS" && printf '%s' "$2" > "$SECRETS/$1.pw") && chmod 600 "$SECRETS/$1.pw"
}
write_secret pg udbmcp_ro_pw
write_secret mysql udbmcp_ro_pw
write_secret clickhouse udbmcp_ro_pw
write_secret oracle Travel_Pass_1
write_secret mssql UdbmcpReader_2022
write_secret db2 udbmcp_db2_1

docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET" >/dev/null

start() { # name image hostport-spec [docker args...]
  local name="$1" image="$2" ports="$3"; shift 3
  docker rm -f "udbmcp-$name" >/dev/null 2>&1 || true
  docker run -d --name "udbmcp-$name" --network "$NET" -p "127.0.0.1:${ports}" "$@" "$image" >/dev/null || {
    echo "[$name] START FAILED"; return 1; }
  return 0
}

wait_ready() { # name cmd max
  local name="$1" cmd="$2" max="${3:-120}" i=0
  until docker exec "udbmcp-$name" bash -c "$cmd" >/dev/null 2>&1; do
    i=$((i + 1)); [ "$i" -ge "$max" ] && { echo "[$name] not ready after ${max}s"; return 1; }
    sleep 2
  done
  echo "[$name] ready"; return 0
}

# --- PostgreSQL (oceanographic buoys) -----------------------------------------
start postgres-db postgres:17 "5433:5432" -e POSTGRES_PASSWORD=udbmcp_ro_pw -e POSTGRES_USER=postgres \
  && wait_ready postgres-db "pg_isready -U postgres" 60 \
  && docker exec udbmcp-postgres-db psql -U postgres -c \
       "CREATE SCHEMA reporting; CREATE ROLE udbmcp_ro LOGIN PASSWORD 'udbmcp_ro_pw'; GRANT USAGE ON SCHEMA reporting TO udbmcp_ro; CREATE TABLE reporting.demo (id int); GRANT SELECT ON reporting.demo TO udbmcp_ro; CREATE TABLE reporting.secret (s text);" >/dev/null 2>&1
docker exec -i udbmcp-postgres-db psql -U postgres -v ON_ERROR_STOP=1 < "$SEEDS/pg_ocean_buoys.sql" >/dev/null 2>&1 \
  && docker exec udbmcp-postgres-db psql -U postgres -c \
       "GRANT USAGE ON SCHEMA ocean TO udbmcp_ro; GRANT SELECT ON ALL TABLES IN SCHEMA ocean TO udbmcp_ro;" >/dev/null 2>&1 \
  && echo "[postgres-db] seeded (ocean buoys)"

# --- MySQL (coffee roastery) ---------------------------------------------------
start mysql-db mysql:9 "3307:3306" -e MYSQL_ROOT_PASSWORD=root -e MYSQL_DATABASE=testdb \
       -e MYSQL_USER=udbmcp_ro -e MYSQL_PASSWORD=udbmcp_ro_pw \
  && wait_ready mysql-db "mysql -uudbmcp_ro -pudbmcp_ro_pw -e 'SELECT 1'" 120 \
  && docker exec -i udbmcp-mysql-db mysql -uudbmcp_ro -pudbmcp_ro_pw testdb < "$SEEDS/mysql_roastery.sql" >/dev/null 2>&1 \
  && echo "[mysql-db] seeded (roastery batches)"

# --- ClickHouse (telecom call data records) ------------------------------------
start clickhouse-db clickhouse/clickhouse-server:latest "8124:8123" -e CLICKHOUSE_PASSWORD=udbmcp_ro_pw \
  && wait_ready clickhouse-db "wget -qO- http://localhost:8123/ping | grep -q Ok" 60 \
  && docker exec -i udbmcp-clickhouse-db clickhouse-client --password udbmcp_ro_pw --multiquery < "$SEEDS/clickhouse_cdr.sql" >/dev/null 2>&1 \
  && echo "[clickhouse-db] seeded (250k CDRs)"

# --- Oracle Free (air travellers) ----------------------------------------------
start oracle-db container-registry.oracle.com/database/free:latest "1522:1521" \
       -v "$SEEDS":/seed:ro -e ORACLE_PWD=UdbmcpOracle_23ai \
  && wait_ready oracle-db 'echo "SELECT 1 FROM DUAL;" | sqlplus -S -L system/"UdbmcpOracle_23ai"@localhost:1521/FREEPDB1 >/dev/null' 720 \
  && docker exec udbmcp-oracle-db bash -c 'sqlplus -S /nolog @/seed/oracle_travellers.sql' >/dev/null 2>&1 \
  && echo "[oracle-db] seeded (travellers)"

# --- SQL Server 2022 (hospital) ------------------------------------------------
start mssql-db mcr.microsoft.com/mssql/server:2022-latest "1434:1433" --platform linux/amd64 \
       -e ACCEPT_EULA=Y -e MSSQL_SA_PASSWORD=UdbmcpMssql_2022 -e MSSQL_PID=Developer \
  && wait_ready mssql-db '/opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -P "UdbmcpMssql_2022" -C -Q "SELECT 1" -b' 300 \
  && docker cp "$SEEDS/mssql_hospital.sql" udbmcp-mssql-db:/tmp/seed.sql \
  && docker exec udbmcp-mssql-db /opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -P "UdbmcpMssql_2022" -C -i /tmp/seed.sql >/dev/null 2>&1 \
  && docker exec udbmcp-mssql-db /opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -P "UdbmcpMssql_2022" -C -b -d HospitalDB -Q \
       "CREATE LOGIN udbmcp_ro WITH PASSWORD = N'UdbmcpReader_2022'; CREATE USER udbmcp_ro FOR LOGIN udbmcp_ro; ALTER ROLE db_datareader ADD MEMBER udbmcp_ro; GRANT SHOWPLAN TO udbmcp_ro;" >/dev/null 2>&1 \
  && echo "[mssql-db] seeded (hospital admissions; reader login udbmcp_ro)"

# --- Db2 11.5.9 (ministry of interior) ------------------------------------------
# The image's own DBNAME bootstrap can fail its backup step; create the db
# manually if it is missing after the instance is up.
start db2-db icr.io/db2_community/db2:11.5.9.0 "50002:50000" --platform linux/amd64 --privileged \
       -e LICENSE=accept -e DB2INST1_PASSWORD=udbmcp_db2_1 -e DBNAME=testdb
i=0
until docker exec udbmcp-db2-db su - db2inst1 -c 'db2 list database directory' >/dev/null 2>&1; do
  i=$((i + 1)); [ "$i" -ge 400 ] && { echo "[db2-db] instance not up after 800s"; break; }
  sleep 2
done
# Wait until TESTDB is CONNECTABLE: the catalog entry appears before CREATE
# DATABASE finishes, so seeding too early fails with SQL1035N.
i=0
tries=0
until docker exec udbmcp-db2-db su - db2inst1 -c 'db2 connect to testdb; db2 disconnect testdb' >/dev/null 2>&1; do
  i=$((i + 1))
  if [ "$i" -ge 5 ]; then
    echo "[db2-db] TESTDB not connectable; creating manually"
    docker exec udbmcp-db2-db su - db2inst1 -c 'db2 create database testdb' >/dev/null 2>&1
    i=0
    tries=$((tries + 1))
    if [ "$tries" -ge 3 ]; then
      echo "[db2-db] giving up on TESTDB"
      break
    fi
  fi
  sleep 2
done
docker exec udbmcp-db2-db su - db2inst1 -c 'db2 connect to testdb; db2 disconnect testdb' >/dev/null 2>&1 \
  && echo "[db2-db] TESTDB connectable"
docker cp "$SEEDS/db2_moi.sql" udbmcp-db2-db:/tmp/seed.sql \
  && docker exec udbmcp-db2-db su - db2inst1 -c 'db2 -tvf /tmp/seed.sql' >/dev/null 2>&1 \
  && echo "[db2-db] seeded (civil registry)"

echo
echo "=== running themed fixtures ==="
docker ps --filter name=udbmcp- --format "{{.Names}}\t{{.Ports}}\t{{.Status}}"

echo
echo "=== user names config.mockdbs.yaml reads (export before serving) ==="
echo "export UDBMCP_DEMO_PG_USER=udbmcp_ro UDBMCP_DEMO_MYSQL_USER=udbmcp_ro UDBMCP_DEMO_CH_USER=default"
echo "export UDBMCP_DEMO_ORA_USER=travel UDBMCP_DEMO_MSSQL_USER=udbmcp_ro UDBMCP_DEMO_DB2_USER=db2inst1"
