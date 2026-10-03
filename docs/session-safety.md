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
`db_list_connections` shows the same fact per connection without connecting:
`server_read_only_session` is true where the database session refuses writes
(PostgreSQL, MySQL and ClickHouse while `session.enforce_read_only` is on;
always on SQLite, whose connector opens the file read-only whatever the
setting), and false on Oracle, Db2 and SQL Server.

## What is applied, per engine

| Engine | Isolation (read-only default) | Server-side read-only | Lock-wait ceiling | Statement ceiling | Session identity |
|---|---|---|---|---|---|
| **Db2** | `UR` via `SET CURRENT ISOLATION` (**enforced**); a statement may still end in `WITH UR` or `WITH CS`, `WITH RS`/`WITH RR` are refused (they keep locks) | none exists; the SQL guard enforces | `SET CURRENT LOCK TIMEOUT` | CLI `QUERYTIMEOUT` DSN keyword (not listed under `applied`, not read back); Db2 has no out-of-band cancel, so this is what stops a timed-out statement on the server | `CLIENTAPPLNAME` (`LIST APPLICATIONS`, `MON_GET_CONNECTION`) |
| **SQL Server** | `READ UNCOMMITTED` via `SET TRANSACTION ISOLATION LEVEL` (**enforced**) | none exists; the SQL guard enforces, with an explicit rollback of every query as a backstop (see below) | `SET LOCK_TIMEOUT` | driver query timeout; a timed-out statement is also cancelled with `Cursor.cancel()` | `APP=` (`sys.dm_exec_sessions.program_name`) |
| **PostgreSQL** | server default (readers never block writers) | `SET default_transaction_read_only = on` (**enforced**) | `SET lock_timeout` | `SET statement_timeout` | `application_name` (`pg_stat_activity`) |
| **MySQL / MariaDB** | server default (InnoDB consistent reads) | `SET SESSION TRANSACTION READ ONLY` (**enforced**) | `innodb_lock_wait_timeout`, `lock_wait_timeout` | `max_execution_time` (MariaDB: `max_statement_time`) | `program_name` connection attribute |
| **Oracle** | server default (readers never block writers) | none exists; the SQL guard enforces | none exists (`lock_timeout_seconds` reports `null`) | driver `call_timeout` | `module`, `action`, `client_identifier` (`v$session`) |
| **ClickHouse** | not applicable | `readonly=1` pinned on the client after reading the account's server profile (**enforced**): an account already at `readonly=1` or `2` keeps its stricter profile and is reported as such, because such accounts reject `SET` | none exists (`lock_timeout_seconds` reports `null`) | `max_execution_time` (not sent to `readonly=1` accounts, which reject every setting) | `client_name` (`system.query_log`) |
| **SQLite** | not applicable | read-only URI + `PRAGMA query_only` (**enforced**, whatever `enforce_read_only` says) | `PRAGMA busy_timeout` | policy cancel; the process-wide `hard_heap_limit` is listed under `applied` (`hard_heap_limit=512MiB (process-wide)`) | not applicable |

## How the server reads a statement (held on every connection)

The SQL guard parses a statement the way the engine reads it by default. A
few server settings change that reading: under them a string the guard saw
can end early and let the rest run as SQL, or a double-quoted token can be a
string to one and a column to the other. So every connection holds those
settings at the values the guard parses under and checks on the server that
they took.
When a setting cannot be held, the connection is refused, whatever the
`session:` block says (there is no opt-out): `CONNECTION_ERROR: could not set
<what> for the session on connection '<id>' (...); the server would read
statements differently from the SQL guard that checked them, so the
connection is refused`.

| Engine | Held on every connection | How it is checked |
|---|---|---|
| **MySQL / MariaDB** | the session `sql_mode`, computed by the server from its own value without `ANSI`, `ANSI_QUOTES`, `NO_BACKSLASH_ESCAPES`, `PIPES_AS_CONCAT`, `HIGH_NOT_PRECEDENCE`, `ORACLE`, `MSSQL`, `DB2`, `POSTGRESQL` and `MAXDB` (the site's other flags are kept); then `SET NAMES utf8mb4` | the server refuses the next `SET` while one of those flags remains, or while `character_set_client` is not `utf8mb4`. Each refusal names its cause: `an sql_mode without ANSI, ...` or `the utf8mb4 client character set` |
| **PostgreSQL** | `SET standard_conforming_strings = on; SET backslash_quote = safe_encoding`, then `SET client_encoding = 'UTF8'` (before read-only mode) | `SELECT 'udbmcp\'`, which parses only where a backslash is the character it is; a probe that fails unless the server reports `UTF8`; psycopg's own codec must be UTF-8 |
| **SQL Server** | `SET QUOTED_IDENTIFIER ON` | a `RAISERROR` when `SESSIONPROPERTY('QUOTED_IDENTIFIER')` is not 1 |
| **Db2** | `SET SYSIBM.SQL_COMPAT = 'DB2'`, which leaves Netezza mode if a connect procedure set it | the `SET` itself. A release without `SQL_COMPAT` (SQL0206N or SQL0204N) has no Netezza mode to leave, and the report lists `sql_compat (no Netezza mode before Db2 11.1): ...` under `skipped`; any other failure refuses the connection |
| **ClickHouse** | `dialect=clickhouse`, `implicit_select=0`, `prefer_column_name_to_alias=0`, `enable_global_with_statement=1` and `analyzer_compatibility_join_using_top_level_identifier=0`, sent with every request, but only where the account's profile (`system.settings`) reports another value | the driver must keep the setting for its requests, and the profile must allow the change: a profile at `readonly=1`, or a constraint on the setting, refuses the connection. Boolean settings compare by truth value (`1` and `true` are the same) |
| **Oracle, SQLite** | nothing: their string literals and quoted names read one way | |

What an operator notices:

- A MySQL or MariaDB site whose global `sql_mode` (or `init_connect`) sets
  `ANSI`, `ANSI_QUOTES` or `NO_BACKSLASH_ESCAPES` gets the default string,
  quote and `||` semantics on this server's sessions, which is how the guard
  read the statement. A client `init_command` or a proxy that left another
  client character set is put back to `utf8mb4` rather than refused.
- On SQL Server, a DSN with `QuotedId=No` reads `"x"` as an identifier.
- On ClickHouse nothing changes for profiles already at the defaults,
  `readonly=1` ones included. A `readonly=1` profile that sets one of these
  otherwise is refused, and so is a `readonly=1` profile pinned to
  `compatibility` 21.x or older, which reports `enable_global_with_statement`
  as 0. On such a profile the old analyzer in fact reads the CTE the way the
  guard does (checked live), so that refusal is conservative. Put the
  setting back to its default in the profile, or use `readonly = 2`
  (`docs/driver-matrix.md`).

`applied` names what was held (`sql_mode without ...`,
`character_set_client=utf8mb4`, `standard_conforming_strings=on`,
`client_encoding=UTF8`, `quoted_identifier=on`, `sql_compat=DB2`, and on
ClickHouse `<name>=<default>` for each setting sent), and `server_reports`
adds `sql_mode` and `character_set_client` on MySQL and
`standard_conforming_strings` and `client_encoding` on PostgreSQL.

**MariaDB and hidden SQL.** A MariaDB session's READ ONLY transaction is not a
write barrier on its own: `SET STATEMENT ... FOR` inside a statement could lift
it, and an executable comment (`/*M! ... */`) could hide one. The guard refuses
both, and `/*! ... */` too; see `docs/security.md`.

**SQL Server has no session-level write barrier.** The guard is the write
enforcement. The connector rolls back every query explicitly and refuses a
batch that reports more than one result, but that detection cannot see DML
after `SET NOCOUNT ON`, DDL, `WAITFOR` or `COMMIT`, and a `COMMIT` in a batch
defeats the rollback. Give the login `db_datareader` plus `SHOWPLAN`, never
`db_owner`, so a statement that ever got past the guard could not write.

**Dummy tables.** Oracle's `DUAL` (bare or `SYS.DUAL`) and Db2's
`SYSIBM.SYSDUMMY1` to `SYSDUMMY4` hold no data, so statements may read them on
every connection whatever the allowlists open; nothing else of `SYS` or
`SYSIBM` opens, and no one needs to open either for them (see
`docs/security.md`). A bare Db2 `SYSDUMMY1` is `CURRENT SCHEMA`'s: write
`SYSIBM.SYSDUMMY1`. Oracle reads a bare `DUAL` as an object of that name in
the session's current schema before the PUBLIC synonym to `SYS.DUAL`, so
before it runs a statement with a bare `DUAL` (`db_query`, the federated
tools, `db_explain`) the Oracle connector asks the session that will run it,
at the cost of one catalog round trip. The statement is refused
(`AUTHORIZATION_DENIED ...; write SYS.DUAL`) when the current schema owns any
object called `DUAL` (a table, view, private synonym or even an index), or
when a logon set `CURRENT_SCHEMA` to a schema other than the login user's (or
`SYS`), whose private synonyms the account cannot see. The check reads
`SYS.ALL_OBJECTS`, never a bare `ALL_OBJECTS` that the same schema could
shadow, and every catalog statement of the Oracle connector names its
`SYS.ALL_*` view the same way. `SYS.DUAL` is never checked, and
`db_validate_query`, which runs nothing, does not make this check. The
connector's own probes (health check, session read-back) read `SYS.DUAL`.
A statement with a database link (`@` outside string literals, quoted
names, hints and comments, `"DUAL"@lnk` included) is refused before any
session is opened (`docs/tools.md`), so a `DUAL` over a link is never taken
for the local one.

**Enforced** means a server that refuses the setting fails the connection
with a clear message instead of silently running at the default level. That
also means an upgrade can turn a previously working connection into a
refused one; `docs/offline-upgrade-rollback.md` lists the cases and the
per-connection opt-outs. The ceilings and the identity are best-effort: an
old server that lacks a variable is recorded under `skipped` in the
`db_test_connection` report. With `session.enforce_read_only: false` on
PostgreSQL, MySQL, ClickHouse or SQLite, `doctor` reports a `session-<id>`
warning, because only the SQL guard then refuses writes (SQLite still opens
the file read-only).

ClickHouse: a truncated or timed-out query is stopped with `KILL QUERY` on its
pinned `query_id`, which DBAs see in `system.query_log` under the session's
client name. Every request carries `max_memory_usage`
(`options.max_memory_usage`, 2 GiB by default) where the account's profile
accepts settings and sets no lower limit; `db_test_connection` lists it under
`applied` and reads it back. On a `readonly=1` profile, or one whose
constraints refuse them, `db_test_connection` lists `per-query result
ceilings` under `skipped`, and `max_memory_usage` too unless the profile sets
one (then `applied`, marked `(server profile)`); the account's profile
(`max_memory_usage`) is then the only memory bound on the server, and
`doctor --connectivity` reports it FATAL when the profile sets none, unless
`options.memory_limit_from_profile: true` acknowledges it.

Statement ceilings are per call: a tool call's own timeout
(`timeout_seconds`, clamped to `security.hard_query_timeout_seconds`) is what
the engine is asked to enforce where the driver takes a per-statement
timeout, and the executor cancels the statement at that deadline where the
engine has a cancel (see `docs/architecture.md`).

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
The settings held for the guard's reading (above) were checked live on the
loopback fixtures in the 2026-09-29 review, each against a session a site
could hand over: MySQL with `sql_mode` `ANSI,NO_BACKSLASH_ESCAPES` set right
after connect, PostgreSQL with `standard_conforming_strings=off`, SQL Server
through a `QuotedId=No` DSN, Db2 with Netezza mode set after connect, and
ClickHouse with a `prql` dialect and `prefer_column_name_to_alias=1`; each
statement then read as the guard read it. Those runs are in the review's
scratch records, not in `test-evidence/`.
