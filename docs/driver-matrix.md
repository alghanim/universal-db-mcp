# Driver matrix and real integration-test status

`passed` requires a recorded run in `test-evidence/` (see
docs/acceptance-tests.md). Everything else is labeled truthfully.

| Engine | Driver (pinned) | Native components | TLS | Cancel | Explain | Integration status |
| --- | --- | --- | --- | --- | --- | --- |
| SQLite | stdlib `sqlite3` (CPython 3.12) | none | n/a | `interrupt()` (hard) | EXPLAIN / EXPLAIN QUERY PLAN (non-executing) | **passed** — Gate A/B container runs; other capabilities unverified (cancel/explain columns are code-level claims, not recorded in the Gate A/B evidence) |
| PostgreSQL | psycopg 3.3.5 `[binary]` | libpq bundled in wheel | verify-full w/ CA | `connection.cancel()` | EXPLAIN (no ANALYZE) | **passed** (Gate C run: roundtrip, db-side permission denial, themed data — `test-evidence/integration-gateC/`); other capabilities unverified |
| MySQL/MariaDB | PyMySQL 1.2.0 | none (pure Python) | TLS w/ CA (`ssl` dict) | none (documented) | EXPLAIN (no ANALYZE) | **passed** (Gate C run: roundtrip + themed data — `test-evidence/integration-gateC/`); other capabilities unverified |
| ClickHouse | clickhouse-connect 1.8.0 | lz4 + zstd are hard dependencies (in wheelhouse); driver-default lz4 write compression (no `compress` kwarg passed) | HTTPS + CA | `KILL QUERY` by pinned `query_id` (client has no `cancel_query`) | EXPLAIN | **passed** (Gate C run: roundtrip + themed data — `test-evidence/integration-gateC/`); other capabilities unverified |
| Oracle | oracledb 4.0.2 **Thin only** | none in Thin mode | TCPS + wallet (admin-provided) | `connection.cancel()` | unsupported (plan table provisioning required) | **passed** (Gate C run: roundtrip + themed data — `test-evidence/integration-gateC/`); other capabilities unverified |
| SQL Server | pyodbc 5.3.0 + **Microsoft ODBC Driver 18 (admin-supplied OS package)** | unixODBC + driver .deb | Encrypt=yes, CA | none (documented) | unsupported (SHOWPLAN needs separate batch) | **passed** (Gate C run: roundtrip + themed data — `test-evidence/integration-gateC/`); other capabilities unverified |
| IBM Db2 (LUW) | ibm_db 3.2.9 wheel (bundled clidriver) | clidriver in wheel | SSL via cert file | none (documented) | unsupported (explain tables admin-provisioned) | unverified |

Notes:

- **Gate C run (`test-evidence/integration-gateC/`):** 13 tests collected,
  11 passed, 2 skipped — the two skips are the Db2 tests
  (`tests/integration/test_connectors.py`, blocked: pinned `ibm_db` 3.2.9
  clidriver auth failed (`SQL30082N` rc17) under amd64 emulation — see the
  Db2 Gate C note below).
  The run therefore covers, per engine: PostgreSQL (roundtrip, db-side
  permission denial, themed data), MySQL, ClickHouse, Oracle, SQL Server
  (roundtrip + themed data each). "Other capabilities unverified" above means
  the matrix's TLS/Cancel/Explain columns for those engines are code-level
  claims, not recorded runs.
- **The Db2 wheel includes `clidriver`; the target never fetches it, and
  `IBM_DB_HOME` is not used to override the bundled driver.** Import alone
  is not a connectivity test; the bundled driver's operation on the target
  is an explicit unverified item until a LUW instance proves it.
- **Oracle Thick mode is not implemented** in this build (no Instant Client,
  no silent mode switch).
- **Db2 for z/OS and Db2 for i are not implemented**; catalog SQL, licensing,
  and binding requirements differ.
- **Db2 Gate C status (observed):** the fixture server (Db2 11.5.9 LUW)
  starts, seeds themed data, authenticates locally, and authenticates over
  loopback TCP via its own clidriver. The pinned `ibm_db` 3.2.9 client fails
  REMOTE password authentication over plaintext TCP with `SQL30082N reason
  17` on every platform tried (emulated amd64 container AND native arm64
  macOS), against both Db2 12.1 and 11.5.9 servers. Server-side TCP
  authentication itself is verified working. The documented remediation is a
  TLS connection (the connector supports `SECURITY=SSL` with
  `SSLServerCertificate`), but Gate C's no-TLS fixtures cannot exercise it;
  Db2 live capabilities therefore remain `not verified` until a deployment
  that allows Db2-side TLS (or a server/driver combination that accepts
  plaintext remote passwords) runs the gate.
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
| oracle (oracledb, Thin only) | yes | yes | yes | thick mode: Instant Client (admin-supplied, not shipped) |
| mssql (pyodbc) | yes (+ .deb closure) | yes | yes | msodbcsql18: .deb shipped in bundle / MSI admin-supplied on Windows / .pkg admin-supplied on macOS |
| db2 (ibm-db) | yes | yes | **yes** (`macosx_14_0_arm64`) | clidriver bundled in wheel; round-trip unverified on ALL platforms |

Notes on this table:

- **ibm-db on macOS arm64:** the 3.2.9 release ships a `macosx_14_0_arm64`
  wheel, so the connector rides in the macOS wheelhouse. This corrects an
  earlier assumption that Db2 was Linux/Windows-only. The runtime round-trip
  (Gate C) remains `blocked`/unverified on **all** platforms — including
  Linux amd64 — per the Db2 note above; arm64 availability does not change
  that.
- **msodbcsql18 is an OS-level driver, not a Python wheel.** The bundle
  ships the Ubuntu `.deb` closure on Linux; on Windows and macOS the driver
  is an admin-supplied prerequisite (msodbcsql MSI / msodbcsql18.pkg,
  Microsoft EULA applies).
- **Oracle Thick mode needs the Instant Client,** which is admin-supplied
  and never shipped in the bundle; Thin mode needs no OS driver.
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

-- Db2 LUW (admin)
GRANT CONNECT ON DATABASE TO USER udbmcp_ro;
GRANT SELECT ON SYSIBM.SYSDUMMY1 TO USER udbmcp_ro; -- plus per-table grants
-- Explain tables (optional, admin-created under SYSTOOLS) — the app never creates them.
```
