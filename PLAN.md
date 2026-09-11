# Implementation Plan — Universal Database MCP Server (air-gapped)

Status: in progress. See `IMPLEMENTATION_STATUS.md` for what is actually
implemented and tested versus blocked/not_run.

## Recorded assumptions

- **Target profile (assumption, per spec §3):** Linux x86_64, glibc,
  Ubuntu 24.04, CPython 3.12 (cp312 ABI). Confirmed `ubuntu:24.04` ships
  CPython 3.12 as `python3` (verified during the air-gap test run, see
  test evidence). Other profiles must be added separately.
- **Staging machine:** this macOS development machine is being used as the
  authorized network-connected staging machine for artifact acquisition
  (spec §2.10). Target verification runs inside network-restricted Docker
  containers (`--network none`, or a Docker `--internal` network for the
  isolated-internal-database gate). The dev machine is never bridged into
  production.
- **MCP SDK:** official pinned `mcp` distribution (v2.2.0 at planning
  time), stdio transport first; Streamable HTTP optional with
  authentication. The exact tool-registration API is verified against the
  installed SDK before the server code is finalized.
- **SQL analysis:** `sqlglot` (pinned, pure Python, no transitive runtime
  deps) provides dialect-aware parsing for the safety service. The SQLite
  connector additionally enforces Python's `sqlite3` authorizer hook as a
  runtime backstop. Parser rules are defense-in-depth; read-only database
  accounts remain mandatory.
- **Drivers (pinned at lock time, lazily imported):**
  - SQLite: Python stdlib `sqlite3` (no external driver).
  - PostgreSQL: `psycopg[binary]` 3.x.
  - MySQL/MariaDB: `PyMySQL` (pure Python, TLS via explicit CA file).
  - ClickHouse: `clickhouse-connect`.
  - Oracle: `python-oracledb` Thin mode only (no Instant Client in v1).
  - SQL Server: `pyodbc` + Microsoft ODBC driver delivered as an OS
    package in the bundle (administrator EULA acceptance required).
  - IBM Db2: `ibm_db` manylinux wheel with bundled `clidriver`; no
    `IBM_DB_HOME` fetch path. Db2 Connect licensing is an administrator
    prerequisite the doctor command reports on.
- **Signing:** detached signature of `SHA256SUMS` using an Ed25519 key via
  OpenSSL, verified offline against an independently distributed public
  key. Key distribution/trust assumptions documented in
  `docs/offline-deployment.md`.
- **Env var naming:** `UDBMCP_CONFIG` for the configuration path
  (matches the spec's Claude Code example).
- **Writes:** no write tool in v1; `allow_write_operations` is false and
  the code rejects write attempts regardless of configuration.

## Build order (per spec §15)

1. Scaffold, config, models, security policy, SQLite connector, MCP
   server with the full tool surface, audit, limits, cursors.
2. Unit tests + stdio protocol integration test against SQLite fixtures.
3. Offline bundle: prepare/verify/install scripts, signing, manifest, SBOM.
4. Air-gap gate A+B in Docker (`--network none`): install from bundle only,
   launch, protocol test, SQLite demo, restart. Failure-mode tests
   (tampered artifact, missing wheel, wrong ABI, untrusted signature).
5. Db2 + remaining connectors with truthful capability reporting;
   isolated-internal-network integration tests for whichever engines can
   actually be stood up locally (attempted in this order: PostgreSQL,
   MySQL/MariaDB, ClickHouse, Oracle-free, SQL Server, Db2); everything
   else recorded `blocked`/`not_run`.
6. Container image + compose offline load test; egress observation harness;
   docs; IMPLEMENTATION_STATUS.md kept truthful throughout.

## Honesty rules enforced in this repo

- A gate is `passed` only with machine-readable evidence in
  `test-evidence/` produced by an actual run.
- Mock-only or code-complete-but-untested items are recorded as such in
  `IMPLEMENTATION_STATUS.md` and in connector capability matrices as
  `unverified`.
