# Session safety profile (production reads that cannot hurt production)

Every connection applies a **session safety profile** to the database
session immediately after connecting. The SQL guard decides what an agent may
*send*; this profile decides how the server session *behaves* while it runs.
It exists because an agent that forgets `WITH UR` on Db2, or that runs a long
scan under READ COMMITTED on SQL Server, can hold locks on production tables
and queue behind writers. The profile makes that impossible to forget.

`db_test_connection` applies the profile, then reads back what the server
reports and returns both. Two flags summarize it: `read_only_enforced` means
the engine has a session-wide switch and the SET was accepted;
`read_only_verified` is what the server itself answered (true/false), or
null when the server offers nothing to read back (MariaDB 10.6 and older
expose neither the read-only nor the isolation variable). The read-back is
reported for the operator to compare; the server does not re-check it.

## What is applied, per engine

| Engine | Isolation (read-only default) | Server-side read-only | Lock-wait ceiling | Statement ceiling | Session identity |
|---|---|---|---|---|---|
| **Db2** | `UR` via `SET CURRENT ISOLATION` (**enforced**); a statement may still end in `WITH UR` or `WITH CS`, `WITH RS`/`WITH RR` are refused (they keep locks) | none exists; the SQL guard enforces | `SET CURRENT LOCK TIMEOUT` | CLI `QUERYTIMEOUT` DSN keyword (not listed under `applied`, not read back) | `CLIENTAPPLNAME` (`LIST APPLICATIONS`, `MON_GET_CONNECTION`) |
| **SQL Server** | `READ UNCOMMITTED` via `SET TRANSACTION ISOLATION LEVEL` (**enforced**) | none exists; the SQL guard enforces | `SET LOCK_TIMEOUT` | driver query timeout | `APP=` (`sys.dm_exec_sessions.program_name`) |
| **PostgreSQL** | server default (readers never block writers) | `SET default_transaction_read_only = on` (**enforced**) | `SET lock_timeout` | `SET statement_timeout` | `application_name` (`pg_stat_activity`) |
| **MySQL / MariaDB** | server default (InnoDB consistent reads) | `SET SESSION TRANSACTION READ ONLY` (**enforced**) | `innodb_lock_wait_timeout`, `lock_wait_timeout` | `max_execution_time` (MariaDB: `max_statement_time`) | `program_name` connection attribute |
| **Oracle** | server default (readers never block writers) | none exists; the SQL guard enforces | none exists (`lock_timeout_seconds` reports `null`) | driver `call_timeout` | `module`, `action`, `client_identifier` (`v$session`) |
| **ClickHouse** | not applicable | `readonly=1` pinned on the client after reading the account's server profile (**enforced**): an account already at `readonly=1` or `2` keeps its stricter profile and is reported as such, because such accounts reject `SET` | none exists (`lock_timeout_seconds` reports `null`) | `max_execution_time` (not sent to `readonly=1` accounts, which reject every setting) | `client_name` (`system.query_log`) |
| **SQLite** | not applicable | read-only URI + `PRAGMA query_only` (**enforced**) | `PRAGMA busy_timeout` | policy cancel | not applicable |

**Enforced** means a server that refuses the setting fails the connection
with a clear message instead of silently running at the default level. That
also means an upgrade can turn a previously working connection into a
refused one; `docs/offline-upgrade-rollback.md` lists the cases and the
per-connection opt-outs. The ceilings and the identity are best-effort: an
old server that lacks a variable is recorded under `skipped` in the
`db_test_connection` report.

## The Db2 and SQL Server trade-off

`UR` and `READ UNCOMMITTED` read rows that other transactions have not yet
committed. That is the standard choice for reporting and analysis against a
production system, because the alternative is taking share locks on the
tables being read. If a use case needs committed reads, set the level
explicitly and accept the locking:

```yaml
connections:
  finance_db2:
    type: db2
    # ...
    session:
      isolation: cs            # ur | cs | rs | rr
```

The statement-level `WITH UR` clause still works and still wins for that
statement.

## Configuration

Everything has a default; the block is optional.

```yaml
connections:
  reporting_pg:
    type: postgres
    # ...
    session:
      isolation: null                 # engine-specific; null = safe default
      lock_timeout_seconds: 5         # null = server default
      application_name: udbmcp:reporting_pg
      enforce_read_only: true         # server-side, where the engine supports it
      statement_timeout_from_policy: true   # security.hard_query_timeout_seconds, server-side
```

Valid `isolation` values:

| Engine | Values |
|---|---|
| db2 | `ur`, `cs`, `rs`, `rr` |
| mssql | `read_uncommitted`, `read_committed`, `repeatable_read`, `serializable`, `snapshot` (needs `ALLOW_SNAPSHOT_ISOLATION` on the database) |
| postgres | `read_committed`, `repeatable_read`, `serializable` |
| mysql | `read_uncommitted`, `read_committed`, `repeatable_read`, `serializable` |
| oracle | `read_committed`, `serializable` |

SQL Server only: `options.application_intent: readonly` adds
`ApplicationIntent=ReadOnly`, which routes the connection to a readable
secondary in an Availability Group. Opt-in, because a secondary can lag.

## What `db_test_connection` shows

```json
"session": {
  "engine": "db2",
  "isolation": "ur",
  "lock_timeout_seconds": 5.0,
  "statement_timeout_seconds": 60.0,
  "application_name": "udbmcp:finance_db2",
  "read_only_requested": true,
  "server_read_only_available": false,
  "read_only_enforced": false,
  "applied": ["isolation=ur", "lock_timeout=5s"],
  "skipped": [],
  "server_reports": {"isolation": "ur", "lock_timeout_seconds": "5", "application_name": "udbmcp:finance_db2"}
}
```

`server_reports` is what the database itself answered after the profile was
applied. `read_only_enforced` is true only when the engine has a session-wide
read-only switch AND it was applied; on Oracle, Db2 and SQL Server it is
false by design, and the SQL guard is the write enforcement.

## Evidence

`test-evidence/session-safety/results.txt` (regenerated by
`scripts/live_evidence.py`) records the live read-back on PostgreSQL 17,
MySQL 9.7, ClickHouse 26, Oracle Database Free 23.26 (its banner reads
"Oracle AI Database 26ai Free") and Db2 11.5.9, plus the server-side
refusal of a `CREATE TABLE` sent straight to the connector (the SQL guard
bypassed on purpose) on PostgreSQL, MySQL and ClickHouse, and the `UR`
read-back of a Db2 `db_query`. The SQL Server row in that file is
`healthy=False` on the macOS staging host because the ODBC driver is an
administrator-supplied OS package that is not installed there. SQL Server evidence is the
`session` block of `test-evidence/version-matrix/mcr.microsoft.com_mssql_server_{2017,2019,2022}-latest.json`:
isolation `read_uncommitted`, lock timeout and application name read back
from `sys.dm_exec_sessions`. Not evidenced anywhere: a write refusal on SQL
Server (none exists at session level) and a live fail-closed negative
(unit-tested with driver fakes for PostgreSQL, MySQL, SQL Server and Db2).
