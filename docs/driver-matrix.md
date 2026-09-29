# Driver matrix and real integration-test status

`passed` requires a recorded run in `test-evidence/` (see
docs/acceptance-tests.md). Everything else is labeled truthfully.

| Engine | Driver (pinned) | Native components | TLS | Cancel | Explain | Integration status |
| --- | --- | --- | --- | --- | --- | --- |
| SQLite | stdlib `sqlite3` (CPython 3.12) | none | n/a | `interrupt()` (hard) | EXPLAIN / EXPLAIN QUERY PLAN (non-executing) | **passed** — Gate A/B container runs; other capabilities unverified (cancel/explain columns are code-level claims, not recorded in the Gate A/B evidence) |
| PostgreSQL | psycopg 3.3.5 `[binary]` | libpq bundled in wheel | verify-full w/ CA | `cancel_safe()` (1.5 s timeout) with libpq 17 or later; with an older libpq none is sent and `statement_timeout` ends the query; a truncated result sends no cancel | EXPLAIN (no ANALYZE) | **passed** (Gate C run: roundtrip, db-side permission denial, themed data — `test-evidence/integration-gateC/`); other capabilities unverified |
| MySQL/MariaDB | PyMySQL 1.2.0 | none (pure Python) | TLS w/ CA (`ssl` dict) | `KILL QUERY` from a second connection (unverified) | EXPLAIN (no ANALYZE); a TREE or JSON plan of a statement naming a masked column (or `*`, or a NATURAL join) is withheld, FORMAT=TRADITIONAL always returned | **passed** (Gate C run: roundtrip + themed data — `test-evidence/integration-gateC/`); other capabilities unverified |
| ClickHouse | clickhouse-connect 1.8.x (the extra requires `>=1.8,<1.9`) | lz4 + zstd are hard dependencies (in wheelhouse); driver-default lz4 write compression (no `compress` kwarg passed) | HTTPS + CA | `KILL QUERY` by pinned `query_id` (client has no `cancel_query`); also sent when a result is truncated | EXPLAIN under a 1000-row planning read ceiling (see `docs/tools.md`) | **passed** (Gate C run: roundtrip + themed data — `test-evidence/integration-gateC/`); other capabilities unverified |
| Oracle | oracledb 4.0.2 (Thin default; opt-in **Thick** via admin-supplied Instant Client) | none in Thin mode; Instant Client in Thick mode (admin-supplied) | TCPS + wallet (admin-provided) | `connection.cancel()` | EXPLAIN PLAN into the session-private PLAN_TABLE (10g+ public synonym; nothing provisioned), read back through DBMS_XPLAN; never executes | **passed** (Gate C run: roundtrip + themed data — `test-evidence/integration-gateC/`); other capabilities unverified |
| SQL Server | pyodbc 5.3.0 + **Microsoft ODBC Driver 18 (admin-supplied OS package)** | unixODBC + driver .deb | Encrypt=yes, CA | `Cursor.cancel()` (SQLCancel; unverified, seen working live against SQL Server 2022 with ODBC Driver 18) | SET SHOWPLAN_ALL on a private connection (estimated plan, never executes); the account needs the SHOWPLAN permission, named when missing | **passed** (Gate C run: roundtrip + themed data — `test-evidence/integration-gateC/`); other capabilities unverified |
| IBM Db2 (LUW) | ibm_db 3.2.9 wheel (bundled clidriver) | clidriver in wheel | SSL via cert file, host name validated (`SSLClientHostnameValidation=Basic`) | none; the query's own timeout is its CLI `QUERYTIMEOUT`, so the server stops it at that deadline | EXPLAIN PLAN into DBA-provisioned explain tables (session schema, then SYSTOOLS); refused with the SYSINSTALLOBJECTS instruction when absent; writes the plan rows there and deletes them after read-back (the account needs INSERT, SELECT and DELETE on those tables); never executes | **passed** (direct live run after the 2026-09-15 credential fix: roundtrip + themed data — `test-evidence/integration-db2-credentials-fix/`; Gate C orchestrator not re-run); other capabilities unverified |

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
- **Least privilege is the primary control on every engine** (see the
  provisioning SQL at the end). On SQL Server it is mandatory: give the login
  `db_datareader` plus `GRANT SHOWPLAN` (needed by `db_explain`), never
  `db_owner`. SQL Server needs no statement separator, so the guard is what
  stops a smuggled statement; the connector's backstop (describe first,
  explicit rollback, a refusal of a batch that reports several results)
  cannot see DML after `SET NOCOUNT ON`, nor DDL, `WAITFOR` or `COMMIT`, and a
  `COMMIT` in the batch defeats the rollback. For sensitive columns, grant
  column-level SELECT or a view without them: masking protects projected
  values only, and a predicate on a masked column can still infer its values.
- **Connect timeouts.** `connect_timeout_seconds` is rounded up (at least
  1 s) on PostgreSQL, MySQL (which also bounds the handshake read with it) and
  SQL Server; Db2 sends `CONNECTTIMEOUT`; Oracle Thin sends
  `tcp_connect_timeout` (Thick mode with a pass-through descriptor ignores
  it). Every Thin connect first calls `oracledb.enable_thin_mode()`, so a hung
  Oracle listener no longer blocks other Oracle connects, and a process where
  something already enabled Thick mode fails a Thin connection with
  python-oracledb's own error.
- **Residual: an Oracle listener that accepts TCP and never answers.**
  python-oracledb 4.0.2 bounds only the TCP connect (`tcp_connect_timeout`);
  the rest of the Thin handshake has no bound. Measured against such a
  listener, `CONNECT_TIMEOUT`, `TRANSPORT_CONNECT_TIMEOUT`, `RETRY_COUNT=0`,
  `expire_time` and `socket.setdefaulttimeout` all left the connect blocked.
  The executor, not the driver, contains it: the request fails with `TIMEOUT`
  at its deadline, and once the connect has run past
  `max(connect_timeout_seconds, 5 s)` it gives its global token back and takes
  one of 10 stuck-connect slots (at most 9 per database server), while every
  connection to that server is refused with `CONNECTION_ERROR ... is
  unavailable: a connect to its database server did not complete within N s
  ...`. Requests queued behind it on the same connection fail at the first
  request's deadline with `CONNECTION_ERROR: connection is in an uncertain
  state after a previous cancelled query and was discarded`, although no query
  ran. The worker thread stays blocked until the peer closes the socket
  (`docs/architecture.md`, "Stuck connects").
- **Operator guidance for `the limit of 10 pending connects`.** Ten connects
  to database servers accepted TCP or were black-holed and never answered.
  Check the network and the listeners; the refusal lifts as those connects
  return. SQLite connections are unaffected; a PostgreSQL socket directory
  given as the host, and a MySQL `options.unix_socket` (the mysqld behind
  it, whatever the host), count as database servers, and an Oracle
  `options.tns_alias` is keyed on the alias and its `tns_admin`, not the
  configured host (`docs/architecture.md`). If the connects never
  return, restart the server.
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
- **Db2 TLS.** The connector sets `SSLClientHostnameValidation=Basic`: the
  server certificate needs a subjectAltName for the configured host (an IP SAN
  for an IP address), or the connect fails with `SQL20576N`
  (`docs/db2-tls-setup.md`). Before each TLS connect it makes a TCP connect, a
  TLS handshake without verifying the certificate, and sends one DRDA
  `EXCSAT` request with no credentials, all within `connect_timeout_seconds`
  (at least 1 s); the server may log a connection closed after `EXCSAT`. A
  timeout refuses the connect as `CONNECTION_ERROR` with one of three
  messages: `host:port did not accept a TCP connection within N s ...`,
  `... did not complete a TLS handshake within N s ...` or `... did not answer
  DRDA after its TLS handshake within N s ...`; the last two add that the
  connect was not handed to the Db2 client and to check that the port is the
  server's SSL port (`SSL_SVCENAME`). A TLS connection pointed at a plain DRDA
  port, which used to hang for good, now fails that way.
  **Residual:** a peer that answers the probe and then stalls the Db2 client's
  own connect still hangs that connect; only the executor's stuck-connect
  budget bounds it.
- **Db2 value search.** On a Unicode database (code page 1208 or 1200, read
  once per connector; 1208 is the Db2 default) every string column is
  compared as `CAST(<col> AS VARCHAR(32672))`, so a needle longer than a
  column simply does not match. On any other database the column is compared
  as declared, because the server does not yet pass the declared type the
  connector would need for the cast (`VARGRAPHIC(16336)` for a GRAPHIC
  type): a longer needle fails that table with `CLI0109E`. A numeric needle
  outside a column's range fails its chunk (`CLI0111E`) on every database.
- **Dummy tables (owner decision 2026-09-28).** Statements on every
  connection may read Oracle's `DUAL` (bare, or `SYS.DUAL`) and Db2's
  `SYSIBM.SYSDUMMY1` to `SYSDUMMY4`, whatever the allowlists say; nothing else
  in `SYS` or `SYSIBM` opens that way. Db2 binds a bare `SYSDUMMY1` to
  `CURRENT SCHEMA`, so write `SYSIBM.SYSDUMMY1` (a bare one is refused under an
  allowlist with that hint); Db2 LUW 11.5 has only `SYSIBM.SYSDUMMY1`, a view.
  Oracle binds a bare `DUAL` to an object of that name in the session's
  current schema before the PUBLIC synonym, so `db_query` (and every other
  tool that runs a statement) and `db_explain` first check, in the session
  that runs it (one extra round trip), and refuse a bare `DUAL` with
  `AUTHORIZATION_DENIED` when that schema owns any object named `DUAL`, or
  when a logon set the current schema to another schema than the login's;
  the remedy in both messages is `write SYS.DUAL`. `db_validate_query` never
  reaches the database, so it reports such a statement valid. A PUBLIC
  synonym `DUAL` repointed away from `SYS.DUAL` is not checked. The dummy
  tables are listed only where `SYS` or `SYSIBM` is opened, so under
  `default_deny_objects: true` `db_get_table`, `db_list_columns` and
  `db_sample_table` refuse them otherwise; with it false they describe the
  qualified names. The metadata tools refuse a bare `DUAL` in both modes.
- **Db2 read-only tail clauses are accepted** (`WITH UR|CS|RS|RR`,
  `FOR READ ONLY`, `FOR FETCH ONLY`, `OPTIMIZE FOR n ROWS`). They are removed
  before validation only, because sqlglot parses Db2 under the postgres
  grammar and would reject them; the executor sends the original text, so Db2
  still receives the clause. `USE AND KEEP ... LOCKS` is refused: it takes real
  locks rather than stating read intent.
- SQL validation dialects: mssql statements are validated as T-SQL (`tsql`)
  and db2 statements are parsed under the postgres dialect for validation
  (sqlglot has no DB2 dialect); any parse failure is a denial, never approval.
- **Names an engine reads differently are refused** (`POLICY_VIOLATION`), so
  every check sees the name the engine will use. SQL Server: a table, column
  or alias outside printable ASCII, or a quoted name ending in a blank (its
  collation reads such a name as another); an object whose catalog name is
  not ASCII therefore cannot be named in a statement, while `SELECT *` and the
  metadata, sample and profile tools still reach it. Db2: a delimited name
  ending in blanks, which Db2 drops. Oracle: an unquoted name containing `ı`
  or `ſ`, which Oracle upper-cases to `I` or `S` (quote the name to mean it
  exactly). ClickHouse: a quoted identifier containing a backslash, because
  ClickHouse decodes escapes in names (double a backquote inside backquotes
  instead).
- **EXPLAIN ANALYZE is never run, on any engine.** `db_explain` refuses
  `analyze=true` after validating the statement and before any plan is
  requested: `POLICY_VIOLATION` (`EXPLAIN ANALYZE is disabled by policy`)
  while `security.allow_explain_analyze` is false, `VALIDATION_ERROR`
  (`analyze=true is not supported by db_explain ...`) while it is true. A
  connector's own `explain(sql, analyze=True)` raises `db_explain never
  executes the statement; EXPLAIN ANALYZE is not supported`, which
  `db_get_capabilities` also lists for PostgreSQL, MySQL and ClickHouse.
- **Catalog listings** give the database's own objects first, then those of
  opened system schemas or dictionary owners, on all six server engines
  (Oracle decides a dictionary owner as the policy does: `PDBADMIN` is user
  data, `APEX_nnnnnn` a dictionary; Db2 puts `SYSCAT` and `SYSIBM` last).
  The views no statement may read (other sessions' SQL, column statistics,
  stored credentials: `docs/security.md`) are never listed by
  `db_list_tables`, `db_get_catalog`, `db_search_metadata` and the value and
  relationship tools on any engine, nor by `db_list_views` on PostgreSQL,
  Oracle and Db2 or `db_list_synonyms` on Oracle and Db2, with or without an
  allowlist and wherever the schema is opened. The synonym listings also
  leave out a synonym or alias whose chain reaches such a view (Oracle's
  PUBLIC `V$SQL` and `ALL_TAB_HISTOGRAMS`). Oracle's `*_TAB_COLUMNS` and
  Db2's `SYSCAT.COLUMNS`, which a statement may read without their low and
  high values, stay listed. `db_list_views`, `db_list_synonyms` and
  `db_list_routines` still filter by the allowlist only, so without one they
  name the other dictionary objects (PostgreSQL `pg_tables`, Oracle's PUBLIC
  `ALL_USERS`), by name only. On MySQL, `information_schema` `PROCESSLIST`,
  `INNODB_TRX`, `INNODB_LOCKS`, `QUERY_CACHE_INFO`, `INNODB_FT_INDEX_CACHE`,
  `INNODB_FT_INDEX_TABLE` and `COLUMN_STATISTICS`, `sys`
  `innodb_lock_waits` and `schema_table_lock_waits` (with their `x$` twins),
  and `performance_schema` `processlist`, `threads` and
  `events_statements_*` are never listed, whatever is opened, and statements
  naming them are refused.
- **Reading settings.** Every connection holds the server settings that
  decide how a statement is read at the values the SQL guard parses under,
  and fails closed when it cannot: MySQL/MariaDB `sql_mode` without the
  lexing flags and `SET NAMES utf8mb4`, PostgreSQL
  `standard_conforming_strings`, `backslash_quote` and `client_encoding`,
  SQL Server `QUOTED_IDENTIFIER ON`, Db2 `SQL_COMPAT = 'DB2'` (skipped before
  11.1) and five ClickHouse settings where the profile changes them
  (`docs/session-safety.md`).
- **Catalog SQL names its owner.** The connectors' own catalog statements
  name the dictionary they read, so an object of the same name in the
  login's schema cannot stand in for it: Oracle reads `SYS.ALL_*` views
  (the bare-`DUAL` check reads `SYS.ALL_OBJECTS`), its health probe
  `SYS.V_$VERSION` and its plans through `SYS.DBMS_XPLAN` (`PLAN_TABLE`
  stays unqualified, the session's own); PostgreSQL names
  `pg_catalog.<relation>` and `pg_catalog.pg_get_indexdef`. The row-estimate
  label of `db_get_statistics` on Oracle is unchanged
  (`catalog_estimate(all_tables.num_rows)`).
- Metadata connections are pooled per connector (one lock-guarded connection
  with a probe-on-checkout); query connections stay fresh so timeout/poison
  semantics remain exact. Every connector has `close()`, so a discarded
  connector's pooled metadata session is released once its last call returns.
- **SQLite.** Output values are cut to the cell limit inside SQLite, and each
  handle accepts values up to `min(max(16 x max_response_bytes, 16 MiB),
  1,000,000,000 bytes)` (`SQLITE_LIMIT_LENGTH`, 16 MiB by default): a
  statement that builds or reads a longer value fails as `QUERY_ERROR`
  (`string or blob too big: ...`), and a stored value that long cannot be read
  at all. The process-wide `PRAGMA hard_heap_limit` is 32 x that length
  (512 MiB by default), shared by every SQLite handle in the server, the
  metadata cache's included, and only ever lowered; a statement that needs
  more fails as `LIMIT_EXCEEDED` (`... needs more memory than this server lets
  SQLite use (512 MiB, shared by every SQLite handle in the process) ...`).
  Unlike the other engines, a cell cut to `max_cell_bytes` is reported by its
  warning only: `truncated` is true only when the row or byte limit cut the
  result.
- **ClickHouse.** Results stream as column blocks under a wire budget of
  `max(8 MiB, 4 x max_response_bytes)` and an object budget of 4 x that for
  what one block decodes to (32 MiB by default), and are stopped with
  `KILL QUERY` on the pinned `query_id` at the row or byte ceiling
  (`docs/architecture.md`). One input row whose `arrayJoin()` or JOIN
  expansion is past the object budget is refused (`LIMIT_EXCEEDED`), not
  truncated; a `LIMIT` inside the statement returns its first rows. Per-query
  settings only ever tighten the profile (`max_block_size`, `max_result_rows`
  with `result_overflow_mode='break'`; for EXPLAIN `max_rows_to_read` with
  `read_overflow_mode='throw'`), none are sent to `readonly=1` profiles, and
  `max_result_bytes` is never sent (a byte cut under `break` would be silent);
  `send_receive_timeout` is the hard timeout plus 5 s. The byte budget uses a
  seam of clickhouse-connect 1.8; without it, results carry a warning and the
  session report lists the budget as skipped. **The ClickHouse server's own
  memory is bounded only by the account profile:** a guard-accepted statement
  computing very wide rows (`SELECT repeat(col, 700000) FROM <big table>`)
  OOM-killed the test container. Give the MCP account a settings profile with
  `max_memory_usage` and `max_result_bytes` set (the provisioning SQL below
  weighs `readonly = 1` against `readonly = 2`). Value search folds case with
  `lowerUTF8`, so non-ASCII capitals match. The guard follows ClickHouse's
  CTE scope: a bare name counts as a CTE only where ClickHouse binds it (the
  query its WITH heads, the other CTEs of that WITH in either order, and its
  own name only after the first branch of a `WITH RECURSIVE ... UNION ALL`
  body; names compared case-sensitively), and any other bare name gets the
  full table checks. CTEs naming each other in a cycle, `WITH RECURSIVE`
  ahead of a UNION, INTERSECT or EXCEPT whose CTE names itself, and a WITH on
  the parenthesised first operand of a set operation are refused with the
  rewrite to use. So is a CTE body that reads a name from outside itself which
  another CTE elsewhere in the statement also declares, because ClickHouse
  resolves a CTE's body where the CTE is used (give the CTEs distinct names).
  Details: `docs/security.md`.
- **SQL Server metadata.** A bare table or view name resolves where SQL Server
  resolves it (the login's default schema, then `dbo`) for `db_get_table`,
  `db_list_columns`, the index list and the row estimate, which is now per
  schema; the detail's `schema` names the one found. Every query is described
  first (`EXEC sys.sp_describe_first_result_set`, one extra round trip) and
  pooling is off. Catalog statements spell `INFORMATION_SCHEMA` views and
  columns in upper case, so a database with a case-sensitive collation can
  be listed and described (before, every tool failed there with `Invalid
  object name information_schema.*`).
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
| Oracle | Thin 12.1, Thick 11.2 | Thin: 18.4, 21.3, 23 (thin cannot reach 11.2 at all: DPY-3010); Thick: 11.2, 18.4, 23, all 21 checks | python-oracledb. Sampling uses `ROWNUM`, not the 12c-only `FETCH FIRST`. |
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
-- (statements read SYSIBM.SYSDUMMY1 on every connection; SYSIBM stays closed)
-- Optional: version reporting in db_test_connection reads this admin view.
-- Without it the connection is still reported healthy, with no version.
GRANT EXECUTE ON FUNCTION SYSPROC.ENV_GET_INST_INFO TO USER udbmcp_ro;
-- Explain tables (optional, admin-created under SYSTOOLS) — the app never creates them.
-- db_explain writes its plan rows there and deletes them after reading them back,
-- so the login needs INSERT, SELECT and DELETE on those tables, and only there.

-- Oracle
CREATE USER udbmcp_ro IDENTIFIED BY "...";
GRANT CREATE SESSION TO udbmcp_ro;
GRANT SELECT ON app.customers TO udbmcp_ro;      -- per object
-- Optional: version reporting only. db_test_connection works without it.
GRANT SELECT ON V_$VERSION TO udbmcp_ro;
-- db_explain's EXPLAIN PLAN writes only into the session-private PLAN_TABLE
-- (a global temporary table since 10g): no grant, and no rows other sessions see.

-- SQL Server
CREATE LOGIN udbmcp_ro WITH PASSWORD = '...';     -- or: FROM WINDOWS (trusted_connection)
USE reporting;
CREATE USER udbmcp_ro FOR LOGIN udbmcp_ro;
ALTER ROLE db_datareader ADD MEMBER udbmcp_ro;   -- never db_owner
GRANT VIEW DEFINITION TO udbmcp_ro;               -- catalog metadata
GRANT SHOWPLAN TO udbmcp_ro;                      -- db_explain (plans only, no data access)

-- ClickHouse: the profile is what bounds the server's own memory
-- Leave dialect, implicit_select, prefer_column_name_to_alias,
-- enable_global_with_statement and
-- analyzer_compatibility_join_using_top_level_identifier at their defaults
-- (and compatibility unset, or above 21.x): a readonly = 1 profile that
-- changes one refuses every connection, because the MCP server cannot send
-- the default the SQL guard parses under (docs/session-safety.md).
CREATE SETTINGS PROFILE udbmcp_ro_profile SETTINGS readonly = 1,
  max_memory_usage = 4000000000, max_result_bytes = 100000000,   -- size for your server
  max_execution_time = 60;           -- security.hard_query_timeout_seconds
-- readonly = 1 also refuses every setting the MCP server sends per query, and
-- db_test_connection lists them under `skipped`: max_execution_time (hence the
-- profile's own value), the per-query result ceilings (a first block too wide
-- for the stream budget is refused, not fetched again on smaller blocks) and
-- db_explain's 1000-row planning ceiling (every plan then warns that producing
-- it may have read table data). readonly = 2 keeps all three and still refuses
-- writes, but lets a session change any setting a constraint does not pin: the
-- guard refuses SET and SETTINGS, a client holding the credentials would not.
-- Pin the memory bounds with MAX there. The connector's readonly = 2 handling
-- is unit-tested; no fixture in this repository runs such a profile.
--   CREATE SETTINGS PROFILE udbmcp_ro_profile SETTINGS readonly = 2,
--     max_memory_usage = 4000000000 MAX 4000000000,
--     max_result_bytes = 100000000 MAX 100000000;
CREATE USER udbmcp_ro IDENTIFIED WITH sha256_password BY '...' SETTINGS PROFILE 'udbmcp_ro_profile';
GRANT SELECT ON reporting.* TO udbmcp_ro;
-- The client reads these at connection time; denying them fails client startup
-- before any of our code runs.
GRANT SELECT ON system.settings TO udbmcp_ro;
GRANT SELECT ON system.tables, system.columns TO udbmcp_ro;
```
