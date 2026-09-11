# Driver matrix and real integration-test status

`passed` requires a recorded run in `test-evidence/` (see
docs/acceptance-tests.md). Everything else is labeled truthfully.

| Engine | Driver (pinned) | Native components | TLS | Cancel | Explain | Integration status |
| --- | --- | --- | --- | --- | --- | --- |
| SQLite | stdlib `sqlite3` (CPython 3.12) | none | n/a | `interrupt()` (hard) | EXPLAIN / EXPLAIN QUERY PLAN (non-executing) | **passed** — Gate A/B container runs |
| PostgreSQL | psycopg 3.3.5 `[binary]` | libpq bundled in wheel | verify-full w/ CA | `connection.cancel()` | EXPLAIN (no ANALYZE) | unverified (no instance in test env) |
| MySQL/MariaDB | PyMySQL 1.2.0 | none (pure Python) | TLS w/ CA (`ssl` dict) | none (documented) | EXPLAIN (no ANALYZE) | unverified |
| ClickHouse | clickhouse-connect 1.8.0 | optional lz4/zstd not enabled | HTTPS + CA | `cancel_query()` | EXPLAIN | unverified |
| Oracle | oracledb 4.0.2 **Thin only** | none in Thin mode | TCPS + wallet (admin-provided) | `connection.cancel()` | unsupported (plan table provisioning required) | unverified |
| SQL Server | pyodbc 5.3.0 + **Microsoft ODBC Driver 18 (admin-supplied OS package)** | unixODBC + driver .deb | Encrypt=yes, CA | none (documented) | unsupported (SHOWPLAN needs separate batch) | unverified |
| IBM Db2 (LUW) | ibm_db 3.2.9 wheel (bundled clidriver) | clidriver in wheel | SSL via cert file | none (documented) | unsupported (explain tables admin-provisioned) | unverified |

Notes:

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
- Extension points exist for Trino, DuckDB, MongoDB (registry slots only);
  no support is claimed.
- All drivers are lazily imported; an absent wheel cannot break other
  engines. `doctor` names the missing wheel per connection.

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
