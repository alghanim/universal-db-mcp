# Driver matrix and real integration-test status

`passed` requires a recorded run in `test-evidence/` (see
docs/acceptance-tests.md). Everything else is labeled truthfully.

| Engine | Driver (pinned) | Native components | TLS | Cancel | Explain | Integration status |
| --- | --- | --- | --- | --- | --- | --- |
| SQLite | stdlib `sqlite3` (CPython 3.12) | none | n/a | `interrupt()` (hard) | EXPLAIN / EXPLAIN QUERY PLAN (non-executing) | **passed** — Gate A/B container runs; other capabilities unverified (cancel/explain columns are code-level claims, not recorded in the Gate A/B evidence) |
| PostgreSQL | psycopg 3.3.5 `[binary]` | libpq bundled in wheel | verify-full w/ CA | `connection.cancel()` | EXPLAIN (no ANALYZE) | **passed** (Gate C run: roundtrip, db-side permission denial, themed data — `test-evidence/integration-gateC/`); other capabilities unverified |
| MySQL/MariaDB | PyMySQL 1.2.0 | none (pure Python) | TLS w/ CA (`ssl` dict) | none (documented) | EXPLAIN (no ANALYZE) | **passed** (Gate C run: roundtrip + themed data — `test-evidence/integration-gateC/`); other capabilities unverified |
| ClickHouse | clickhouse-connect 1.8.0 | lz4 + zstd are hard dependencies (in wheelhouse); driver-default lz4 write compression (no `compress` kwarg passed) | HTTPS + CA | `KILL QUERY` by pinned `query_id` (client has no `cancel_query`) | EXPLAIN | **passed** (Gate C run: roundtrip + themed data — `test-evidence/integration-gateC/`); other capabilities unverified |
| Oracle | oracledb 4.0.2 (Thin default; opt-in **Thick** via admin-supplied Instant Client) | none in Thin mode; Instant Client in Thick mode (admin-supplied) | TCPS + wallet (admin-provided) | `connection.cancel()` | unsupported (plan table provisioning required) | **passed** (Gate C run: roundtrip + themed data — `test-evidence/integration-gateC/`); other capabilities unverified |
| SQL Server | pyodbc 5.3.0 + **Microsoft ODBC Driver 18 (admin-supplied OS package)** | unixODBC + driver .deb | Encrypt=yes, CA | none (documented) | unsupported (SHOWPLAN needs separate batch) | **passed** (Gate C run: roundtrip + themed data — `test-evidence/integration-gateC/`); other capabilities unverified |
| IBM Db2 (LUW) | ibm_db 3.2.9 wheel (bundled clidriver) | clidriver in wheel | SSL via cert file | none (documented) | unsupported (explain tables admin-provisioned) | **passed** (direct live run after the 2026-09-15 credential fix: roundtrip + themed data — `test-evidence/integration-db2-credentials-fix/`; Gate C orchestrator not re-run); other capabilities unverified |

Notes:

- **Gate C run (`test-evidence/integration-gateC/`):** 13 tests collected,
  11 passed, 2 skipped — the two skips are the Db2 tests
  (`tests/integration/test_connectors.py`, blocked: pinned `ibm_db` 3.2.9
  clidriver auth failed (`SQL30082N` rc17) under amd64 emulation; that
  attribution was wrong — see the Db2 note below).
  The run therefore covers, per engine: PostgreSQL (roundtrip, db-side
  permission denial, themed data), MySQL, ClickHouse, Oracle, SQL Server
  (roundtrip + themed data each). "Other capabilities unverified" above means
  the matrix's TLS/Cancel/Explain columns for those engines are code-level
  claims, not recorded runs.
- **The Db2 wheel includes `clidriver`; the target never fetches it, and
  `IBM_DB_HOME` is not used to override the bundled driver.** Import alone
  is not a connectivity test; the bundled driver's operation on the target
  is an explicit unverified item until a LUW instance proves it.
- **Oracle Thick mode is opt-in since 2026-09-15** (`options.thick_mode: true`,
  optionally `options.lib_dir`). It exists for accounts carrying only the legacy
  10G password verifier, which Thin mode refuses with `DPY-3015`; see
  `docs/oracle-connect-modes.md`. The Instant Client is Oracle-licensed and
  administrator-supplied, never shipped in our artifacts, and
  `init_oracle_client()` is process-global so the config refuses mixing thick
  and thin oracle connections. Live thick-mode round trip: **passed** against
  an Oracle 18c account carrying only the 10G verifier and against Oracle
  11.2 (`test-evidence/oracle-thick-mode/`), with the administrator-supplied
  Instant Client loaded in a no-network container.
- **Db2 for z/OS and Db2 for i are not implemented**; catalog SQL, licensing,
  and binding requirements differ.
- **Db2 status (root cause corrected 2026-09-15):** Gate C and every
  earlier attempt recorded the pinned `ibm_db` 3.2.9 client failing remote
  password authentication with `SQL30082N reason 17` on every platform.
  The cause was the connector itself (and the Gate C auth probe): both
  passed the username/password as `ibm_db.connect` positional arguments,
  which ibm_db ignores for connection-string DSNs, so no credentials were
  sent. Credentials now travel as `UID`/`PWD` inside the connection string.
  A direct live run of both Db2 integration tests then passed against the
  local Db2 11.5.9 fixture over plaintext TCP with `AUTHENTICATION=SERVER`
  (`test-evidence/integration-db2-credentials-fix/`, including the raw-driver
  reproduction: positional credentials give reason 17, forced SERVER auth
  gives reason 3, in-string credentials connect, a wrong in-string password
  gives reason 24). A `;` in any connection value is refused before
  dialing, because no CLI quoting form carries it. The Gate C orchestrator
  has not been re-run; Db2 TLS and the remaining capabilities stay
  unverified.
- **Db2 read-only tail clauses are accepted** (`WITH UR|CS|RS|RR`,
  `FOR READ ONLY`, `FOR FETCH ONLY`, `OPTIMIZE FOR n ROWS`). They are removed
  before validation only, because sqlglot parses Db2 under the postgres
  grammar and would reject them; the executor sends the original text, so Db2
  still receives the clause. `USE AND KEEP ... LOCKS` is refused: it takes real
  locks rather than stating read intent.
- SQL validation dialects: mssql statements are validated as T-SQL (`tsql`)
  and db2 statements are parsed under the postgres dialect for validation
  (sqlglot has no DB2 dialect); any parse failure is a denial, never approval.
- Metadata connections are pooled per connector (one lock-guarded connection
  with a probe-on-checkout); query connections stay fresh so timeout/poison
  semantics remain exact.
- No extension slots exist for other engines: the connector registry has
  exactly the seven engines above and raises `KeyError` for anything else
  (Trino, DuckDB, and MongoDB are not implemented; adding one means
  implementing a new connector — see docs/adding-connectors.md). No support
  is claimed for any unlisted engine.
- All drivers are lazily imported; an absent wheel cannot break other
  engines. `doctor` names the missing wheel per connection.

## Server version floors (pinned drivers, 2026-09-15 audit)

The driver, not our SQL, is usually the binding constraint. The "tested" column
comes from `test-evidence/version-matrix/` (the exact per-image results, with
the probe revision, are in the ledger's matrix table); everything else is a
documented floor, not a tested one.

| Engine | Documented floor | Tested (version matrix) | Source of the limit |
|---|---|---|---|
| PostgreSQL | 10 | 12, 13, 14, 15, 16, 17 | psycopg 3 supports 10-18. `pg_proc.prokind` is 11+, so `db_list_routines` falls back to a pre-11 query. |
| MySQL / MariaDB | MySQL 5.7, MariaDB 10.3 | MySQL 5.7, 8.0, 8.4; MariaDB 10.6, 11.4 | PyMySQL's stated range. Our catalog SQL uses `information_schema` only. |
| ClickHouse | actively supported releases | 23.8, 24.3, 24.8, 25.3 | clickhouse-connect 1.7.0 removed compatibility branches for servers older than 25.8; the tested older servers pass the probed subset. |
| Oracle | Thin 12.1, Thick 11.2 | Thin: 18.4, 21.3, 23; Thin on 11.2 fails as documented (DPY-3010); Thick: see the ledger table | python-oracledb. Sampling uses `ROWNUM`, not the 12c-only `FETCH FIRST`. |
| SQL Server | 2017 | 2017, 2019, 2022 | Microsoft lists only 2017/2019/2022/2025 for ODBC Driver 18. |
| **IBM Db2 LUW** | **11.1** | 11.5.8, 11.5.9 (11.1: `not_run`) | ibm_db 3.2.7+ bundles clidriver 12.1, which supports LUW 12.1/11.5/11.1 and **drops 10.5**. |

Least-privilege accounts also hit catalog-visibility rules that are not
connection errors:

- **MySQL 8.0:** `information_schema.ROUTINES` shows only rows the account
  defined, unless it holds `SHOW_ROUTINE` (8.0.20+), global `SELECT`, or
  `CREATE/ALTER/EXECUTE ROUTINE`. Without one, `db_list_routines` returns an
  empty list rather than an error, and a reader concludes there are no
  routines. Grant `SHOW_ROUTINE` to the read-only account.
- **Oracle and Db2:** version reporting needs `V$VERSION` and
  `SYSIBMADM.ENV_INST_INFO` respectively. `db_test_connection` no longer fails
  without them; it reports the connection healthy with the version omitted.
- **ClickHouse:** the client reads `system.settings` at connection time. A
  profile that denies it fails during client initialization, before any of our
  code runs, and looks like a connectivity fault.

## Per-platform connector availability (offline bundle wheelhouse)

Platform availability of the connector wheels the offline bundle builder
resolves (cp312 pins, verified against PyPI at plan time). This is a
wheelhouse-availability claim, not a verification claim — the per-engine
integration status in the table above is unaffected.

| Connector | linux | windows | macos arm64 | OS driver prerequisite |
| --- | --- | --- | --- | --- |
| core (mcp/PyYAML/sqlglot) | pure | pure | pure | none |
| postgres (psycopg[binary]) | yes | yes | yes | none |
| mysql (PyMySQL) | pure | pure | pure | none |
| clickhouse-connect | yes | yes | yes | none |
| oracle (oracledb, Thin + opt-in Thick) | yes | yes | yes | thick mode: Instant Client (admin-supplied, not shipped) |
| mssql (pyodbc) | yes (+ .deb closure) | yes | yes | msodbcsql18: .deb shipped in bundle / MSI admin-supplied on Windows / .pkg admin-supplied on macOS |
| db2 (ibm-db) | yes | yes | **yes** (`macosx_14_0_arm64`) | clidriver bundled in wheel; round-trip passed on Db2 11.5.8/11.5.9 (version matrix) and the local 11.5.9 fixture |

Notes on this table:

- **ibm-db on macOS arm64:** the 3.2.9 release ships a `macosx_14_0_arm64`
  wheel, so the connector rides in the macOS wheelhouse. This corrects an
  earlier assumption that Db2 was Linux/Windows-only. The runtime round-trip
  (Gate C) resolved 2026-09-15 (credentials were never sent); see the Db2 status note above
  Linux amd64 — per the Db2 note above; arm64 availability does not change
  that.
- **msodbcsql18 is an OS-level driver, not a Python wheel.** The bundle
  ships the Ubuntu `.deb` closure on Linux; on Windows and macOS the driver
  is an admin-supplied prerequisite (msodbcsql MSI / msodbcsql18.pkg,
  Microsoft EULA applies).
- **Oracle Thick mode needs the Instant Client,** which is admin-supplied
  (Oracle-licensed) and delivered on the trusted channel; `options.lib_dir`
  points at it. `doctor` checks that directory without loading the client.
- The builder fails loud on missing connector wheels (`SystemExit` unless
  `--allow-missing-connectors`, which is refused for signed releases), so
  this table is backstopped if PyPI availability drifts.

## Least-privilege setup (per engine)

Example read-only provisioning (administrator-run; the application never
runs grants):

```sql
-- PostgreSQL
CREATE ROLE udbmcp_ro LOGIN PASSWORD '...';
GRANT CONNECT ON DATABASE finance TO udbmcp_ro;
GRANT USAGE ON SCHEMA reporting TO udbmcp_ro;
GRANT SELECT ON ALL TABLES IN SCHEMA reporting TO udbmcp_ro;
ALTER DEFAULT PRIVILEGES IN SCHEMA reporting GRANT SELECT ON TABLES TO udbmcp_ro;

-- MySQL
CREATE USER 'udbmcp_ro'@'%' IDENTIFIED BY '...';
GRANT SELECT ON reporting.* TO 'udbmcp_ro'@'%';

-- MySQL 8.0: without SHOW_ROUTINE, information_schema.ROUTINES hides rows the
-- account did not define and db_list_routines returns an empty list, silently.
GRANT SHOW_ROUTINE ON *.* TO 'udbmcp_ro'@'%';

-- Db2 LUW (admin)
GRANT CONNECT ON DATABASE TO USER udbmcp_ro;
GRANT SELECT ON SYSIBM.SYSDUMMY1 TO USER udbmcp_ro; -- plus per-table grants
-- Optional: version reporting in db_test_connection reads this admin view.
-- Without it the connection is still reported healthy, with no version.
GRANT EXECUTE ON FUNCTION SYSPROC.ENV_GET_INST_INFO TO USER udbmcp_ro;
-- Explain tables (optional, admin-created under SYSTOOLS) — the app never creates them.

-- Oracle
CREATE USER udbmcp_ro IDENTIFIED BY "...";
GRANT CREATE SESSION TO udbmcp_ro;
GRANT SELECT ON app.customers TO udbmcp_ro;      -- per object
-- Optional: version reporting only. db_test_connection works without it.
GRANT SELECT ON V_$VERSION TO udbmcp_ro;

-- SQL Server
CREATE LOGIN udbmcp_ro WITH PASSWORD = '...';     -- or: FROM WINDOWS (trusted_connection)
USE reporting;
CREATE USER udbmcp_ro FOR LOGIN udbmcp_ro;
ALTER ROLE db_datareader ADD MEMBER udbmcp_ro;
GRANT VIEW DEFINITION TO udbmcp_ro;               -- catalog metadata

-- ClickHouse
CREATE USER udbmcp_ro IDENTIFIED WITH sha256_password BY '...' SETTINGS readonly = 1;
GRANT SELECT ON reporting.* TO udbmcp_ro;
-- The client reads these at connection time; denying them fails client startup
-- before any of our code runs.
GRANT SELECT ON system.settings TO udbmcp_ro;
GRANT SELECT ON system.tables, system.columns TO udbmcp_ro;
```
