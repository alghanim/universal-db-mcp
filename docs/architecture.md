# Architecture

```text
Inside the isolated organization network

Claude Code CLI ── inference ──> Internal gateway ──> Self-hosted GLM
       │
       └── MCP (stdio | authenticated HTTP) ──> universal-db-mcp
                               │
                               ├── connectors/  (one per engine, lazy)
                               ├── security/    (policy, SQL guard, cursors)
                               ├── services/    (executor, audit, metadata)
                               └── local state: audit JSONL + metadata cache
```

## Boundaries

- **MCP and inference are separate paths.** This server never calls an LLM,
  never contacts a model registry, telemetry endpoint, or public service.
  The model gateway is a client-side dependency only.
- **Config-declared connections only.** Tool arguments select a connection
  id; they cannot introduce hosts, DSNs, credentials, or file paths.
- **Handlers are thin.** Engine behavior lives in connectors; enforcement
  lives in shared services; the MCP layer only marshals.
- **stdio is not a process boundary.** A stdio server runs as the user
  inside the agent (see `docs/security.md`); only the HTTP service under its
  own account keeps credentials out of the agent's reach.

## Components

| Module | Responsibility |
| --- | --- |
| `config.py` | strict YAML schema, secret resolution to `SecretMark`, audit-path defaults, state-file isolation |
| `security/policy.py` | effective ceilings + object authorization |
| `security/sql_guard.py` | dialect-aware statement validation (sqlglot) |
| `security/cursors.py` | HMAC-bound opaque pagination cursors |
| `security/redact.py` | redaction chokepoint, SQL fingerprints |
| `services/executor.py` | worker-thread execution, deadlines, cancel hooks, poisoning, concurrency accounting |
| `services/audit.py` | JSONL audit with rotation, cross-process lock, fail-closed option |
| `services/metadata.py` | policy-scoped local metadata cache, lexical search |
| `http_protocol.py` | pre-auth limits of the HTTP listener (header deadline, head cap, bearer check on the head) |
| `connectors/*` | per-engine adapters, capability matrices, value caps |
| `diagnostics/doctor.py` | offline artifact/policy checks |

## Execution model

Synchronous drivers run on worker threads via anyio, under a global
concurrency limiter (`security.max_concurrent_queries`) and a per-query
deadline. The module docstring of `services/executor.py` is the reference;
in short:

- **Queueing.** A request first waits on its connection's gate, holding no
  concurrency token, and only then takes a global token. Every wait shares one
  queue budget, `max(timeout x 4, 10 s)`, and ends in `LIMIT_EXCEEDED`
  (`connection '<id>' is busy with earlier requests`, or `query concurrency
  limit reached`). One connection id runs one driver call at a time, across
  rebuilt connector objects too, and an idle connection never waits behind a
  busy one.
- **Per-server share.** A database server is (engine, host, port): the host
  compared case-insensitively and without a trailing dot, a missing port read
  as the port the driver dials (PostgreSQL 5432, MySQL 3306, Oracle 1521, SQL
  Server 1433, Db2 50000, ClickHouse 8123 or 8443 with TLS), and a SQL Server
  `host\INSTANCE` with an explicit port as `host`. Two connections do not
  dial their configured host and port, and are keyed on what they reach
  instead. An Oracle `options.tns_alias` is keyed on the alias (ignoring
  case) and the `tns_admin` directory that resolves it, normalized (`normpath`
  and `normcase`, not through symlinks); in Thick mode without `tls.enabled`,
  where one process-wide directory resolves every alias, on the alias alone
  (with TLS the connection's own `tns_admin` decides the dial and the key
  again). So two
  aliases are two servers, one alias under another `tns_admin` is another
  server, the same alias under several ids is one server, and an alias and a
  host/port connection to the same database are two. A MySQL
  `options.unix_socket` is the mysqld behind that socket (its normalized
  path), whatever the host says; it takes part in the share, the breaker and
  the stuck-connect budget like any server. Only SQLite connections have no
  server. There is no DNS lookup: a host name and its IP address are two
  servers, so use one spelling for all connection ids of a server. A server's calls that hold a global token may
  hold at most `max_concurrent_queries - 1` of them. From a limit of 3 up
  every such call counts, healthy or abandoned: at the default of 4, three
  calls to one server run at once and a fourth waits. At 2 only abandoned
  calls (timed out or cancelled, still running) count; at 1 nothing is set
  aside. Calls to other servers, and SQLite connections, are never held up
  by it. To run N calls to one server in parallel, set
  `max_concurrent_queries` to N + 1.
- **Deadlines and cancel.** When the deadline fires, or the client cancels
  while the driver call runs, the connector is marked poisoned and discarded
  and its cancel hook fires in a separate thread under a hard budget
  (SQLite `interrupt()`, PostgreSQL `cancel_safe` with a 1.5 s timeout on
  libpq 17 or later, Oracle `cancel()`, ClickHouse `KILL QUERY`, MySQL
  `KILL QUERY` from a second connection, SQL Server `Cursor.cancel()`); a
  call the hook cancelled gets 0.2 s to return.
  Engines without a hook are reported as such, and the query may continue
  server-side until the engine's own statement ceiling stops it. A poisoned
  connection is never reused; requests already waiting on it are refused with
  `connection is in an uncertain state after a previous cancelled query and
  was discarded`. On a client cancel the hook and that refusal are new in
  this release: earlier releases already discarded the connection, but only
  for later calls, so the statement ran on and requests queued on it used
  it. Whether the worker is still connecting is recorded before the hook is
  awaited, so a connect hung past its bound is still treated as one (below)
  when a client cancel lands while the deadline's hook runs.
- **Breaker.** While an abandoned call on a connection has not returned, the
  connection fails fast with `CONNECTION_ERROR ... is still recovering ...`;
  after 120 s the message adds that the call may never return (check the
  database and the network, or restart the server). A deadline that catches
  the worker still connecting says the connect had not completed, and blames
  the database only past the connect bound, `max(connect_timeout_seconds,
  5 s)`. A deadline that fires before any worker thread picked the call up is
  `TIMEOUT ... did not start within its deadline`.
- **Stuck connects.** A worker abandoned inside a connect that is still
  connecting past its connect bound holds no database session, so it gives its
  global token back and takes one of 10 stuck-connect slots (10 whatever
  `max_concurrent_queries` is; one server takes at most 9) until the driver
  returns. While it hangs, requests waiting for a token to that server are
  refused at once with `CONNECTION_ERROR ... a connect to its database server
  did not complete within N s ...`; the freed token goes to the next request
  in line for another server or a SQLite connection, and the requests
  waiting for the hung server's share look again (they run if the connect
  completed meanwhile). A connect that completes, while the cancel hook runs
  or before its bound, says nothing about its server: nobody is refused or
  woken, and its connection stays refused by the breaker until its statement
  returns. A connect cut short within its bound (a short deadline, an early
  client cancel) says nothing about its server either, unless it is still
  connecting when it reaches its bound; then it refuses the server's other
  connections like any hung connect. With all 10 slots taken, every
  connection that has a database server is refused with `the limit of 10
  pending connects to database servers that did not answer has been
  reached`, until one parked connect returns. SQLite connections keep
  running; a PostgreSQL socket directory given as the host, and a MySQL
  `options.unix_socket`, are servers like any other. A parked connect that
  connects after all runs its statement in its slot, so at most
  `max_concurrent_queries + 10` driver calls run at once. Parking happens at
  the bound on asyncio: `site-check` and `scripts/live_evidence.py` run each
  call on an event loop of its own, and every request re-arms, on its own
  loop, the at-bound alarm of connects still within their bound, so a
  request waiting there is woken at the bound too; with no request in
  flight, the next one parks the connect. A token a worker hands back after
  its request's loop has closed goes back on the latest request's loop, so a
  request waiting there runs as soon as the abandoned call returns. Residuals:
  once the budget is full, a connect already running that crosses its bound
  keeps its global token until a slot frees. A python-oracledb Thin connect to
  a listener that accepts TCP and never answers has no bound in the driver
  (4.0.2 bounds only the TCP connect), and a Db2 TLS peer that answers the
  connector's liveness probe and then stalls hangs `ibm_db.connect` the same
  way: only this budget contains them, so ten such connects fill it for as
  long as they stay stuck.

## Where the limits apply

Every read asks the driver for at most `max_rows + 1` remaining rows per
fetch, and cuts cells to `security.max_cell_bytes` and the result to
`security.max_response_bytes`. A result cut by any of them is reported
`truncated: true` with `result truncated: limits are rows<=N, bytes<=M`,
except that on SQLite a cut cell is reported by its warning alone. How much
is read before the cut depends on the engine:

- **PostgreSQL**: long values are cut on the server through a derived-table
  rewrite that fails closed. A truncated result sends no cancel: closing the
  named cursor and the rollback end the statement.
- **MySQL/MariaDB**: long values are cut on the server, in the select list or
  with the statement as a derived table (described through the
  prepared-statement protocol, which runs nothing). `UNION`, `DISTINCT` and
  `GROUP BY` derived tables materialise before the first row. A statement
  MySQL takes in neither form is refused (`QUERY_ERROR`), as is, on MariaDB,
  one whose `ORDER BY` the derived table would drop. A `SELECT *` over a join
  whose columns share a name is spelled out as `table.name` columns instead
  (MySQL 5.7 and MariaDB take no derived column list). Where the server will
  not prepare the statement (`1295`, `max_prepared_stmt_count` reached:
  `1461`, a proxy: `1047`), it is not described and runs as written.
- **SQL Server**: `SET TEXTSIZE` bounds text on query connections; every
  query is described first (`EXEC sys.sp_describe_first_result_set`, one
  extra round trip, no extra permission), with an `xml` cast or refusal with guidance.
  pyodbc pooling is off and each connection resets `NOCOUNT`/`TEXTSIZE`.
  Wide text is decoded leniently: `TEXTSIZE` cuts at a byte count, which can
  split a UTF-16 surrogate pair, and the half pair (or an unpaired surrogate
  the value holds) reads as U+FFFD instead of failing the query.
- **Oracle**: LOBs are read partially; whole-decoded types (native JSON,
  LONG, LONG RAW, objects and collections, XMLType in Thick mode) are fetched
  1, 2, 4, 4, ... rows per round trip (at most 4), back to 1 after a cut
  value. A single large native JSON document is still decoded whole by the
  driver (about 8x its text size).
- **Db2**: CLOB, DBCLOB, BLOB and XML columns are cut on the server
  (`SUBSTRING` in `CODEUNITS32`/`OCTETS`, `XMLSERIALIZE`) through a nested
  table expression, at the cost of one extra prepare; a statement Db2 refuses
  in that form is refused. `ORDER BY ORDER OF` keeps the row order only of a
  statement with an `ORDER BY` of its own (Db2 refuses it otherwise,
  `SQLSTATE 428FI`). `CODEUNITS32` on a non-Unicode database is not
  verified.
- **SQLite**: each handle gets `SQLITE_LIMIT_LENGTH = min(max(16 x
  max_response_bytes, 16 MiB), 1,000,000,000 bytes)` (16 MiB by default; the
  upper bound, SQLite's default `SQLITE_MAX_LENGTH`, applies from a
  `max_response_bytes` of about 59.6 MiB). A statement that builds or reads a
  longer value fails with `QUERY_ERROR: string or blob too big: the statement
  builds or reads a value longer than this server lets SQLite handle (N MiB:
  16 x security.max_response_bytes, at least 16 MiB). A stored value that long
  cannot be read at all, not even through length() or substr(); raising
  security.max_response_bytes raises the limit`; where the limit in force is
  SQLite's own ceiling, the text says `(N MiB: SQLite's own ceiling, which no
  setting of this server raises)` and offers no remedy. Output values are cut
  inside SQLite to `max_cell_bytes + 1` by a per-handle function
  (`udbmcp_cut`) in the select list; each query prepares its statement once
  more under `LIMIT 0` first. Left whole: columns the statement compares (in a
  join condition, `WHERE`, `GROUP BY`, `HAVING` or `ORDER BY`), and every
  column of a statement that is not one SELECT, uses `DISTINCT` or a bound
  `LIMIT`, selects `*` over a join, or has a `GROUP BY` or `ORDER BY` term
  that names no column and is not a plain position (SQLite reads `(2)`,
  `+2`, `2 COLLATE x` as a position too). A stored text value that is not valid
  UTF-8 makes the statement run again uncut. Behind that, a process-wide
  `PRAGMA hard_heap_limit` of 32 x `SQLITE_LIMIT_LENGTH` (512 MiB by default),
  shared by every SQLite handle including the metadata cache's and only ever
  lowered, refuses a statement that needs more memory as `LIMIT_EXCEEDED`
  ("the statement needs more memory than this server lets SQLite use (512 MiB,
  shared by every SQLite handle in the process) ..."; for metadata calls
  "reading the database's schema needs more memory ...", for explain "planning
  the statement ..."). A cell cut to `max_cell_bytes` adds its warning but
  leaves `truncated` false. Residuals: shapes the cut cannot reach can use up
  to that 512 MiB before they are refused, and a statement near it can make a
  concurrent metadata-cache write fail, failing that other tool call with
  `INTERNAL_ERROR`.
- **ClickHouse**: results stream as column blocks under a wire budget of
  `max(8 MiB, 4 x max_response_bytes)` and an object budget of 4 x that for
  the Python objects one block decodes to (32 MiB by default). Each column
  read is admitted before the driver allocates for it. A first block over
  either budget is re-run on blocks 1/32 the size, down to one row, so a
  pathological statement can take several seconds before its truncated result
  or refusal (`LIMIT_EXCEEDED: ClickHouse sent a result block of more than N
  MiB ...` or `... that decodes to more than N MiB in memory ...`); on a
  profile that does not accept a smaller `max_block_size` (`readonly = 1`) it
  is refused at once. The rows one input row expands to (`arrayJoin()`, a
  JOIN) cannot be narrowed below one input row, so an expansion past the
  budget is refused, not truncated; a `LIMIT` inside the statement returns its
  first rows. The query is stopped with `KILL QUERY` once a limit is reached.
  The driver sends a statement whose text ends in `LIMIT 0` as a
  columns-only request it reads whole, outside these budgets: unless it is
  one SELECT whose own top-level `LIMIT 0` ends it, the connector appends
  the comment `\n#!''` so it streams like any other (the comment is
  visible in `system.query_log`); `EXPLAIN` always gets it.
  Per-query settings only tighten (`max_block_size`, `max_result_rows` with
  `result_overflow_mode='break'`, none on `readonly=1` profiles);
  `max_result_bytes` is never sent. Without the driver seam this relies on,
  results carry a warning. **The ClickHouse server's own memory is bounded
  only by the account profile:** a guard-accepted statement that computes very
  wide rows (for example `repeat(col, 700000)` over a large table) OOM-killed
  the test container. Give the MCP account a `readonly` profile with
  `max_memory_usage` (and `max_result_bytes` in the profile) set;
  `docs/driver-matrix.md` has the profile and what `readonly = 1` gives up.

## Defense in depth (read-only)

1. **Database privileges**: read-only accounts are mandatory (primary); on
   Db2, `db_explain` also needs INSERT, SELECT and DELETE on the explain
   tables, where it writes, reads back and deletes its own plan rows.
2. **SQL guard**: single-statement, dialect-scoped AST validation; denies
   DML/DDL/TCL/PRAGMA/SET anywhere in the tree including CTEs; denies
   unknown functions and table functions; conservative object resolution
   under default-deny; schema-qualified names under an allowlist.
3. **Engine backstops**: server-side read-only sessions where the engine has
   them (PostgreSQL, MySQL, ClickHouse; SQLite opens `mode=ro` with `PRAGMA
   query_only` and a denying authorizer), explicit rollback on SQL Server.
4. **Policy ceilings**: rows, bytes, cells, timeouts, concurrency, all
   clamped server-side.

## Local state

- Audit log: append-only JSONL, size rotation, cross-process lock sidecar,
  fail-closed by default; defaults to the platform state directory when the
  config leaves it unset. Calls that failed before anything reached a
  database are coalesced (the first 10 of a kind in full per 10 s window,
  then one `tool_call_summary` per kind), and the SQL text it keeps is
  capped per window (`docs/security.md`, Audit). A statement counts as sent
  once the executor's worker thread began its driver call
  (`ExecutionService.run_bounded(..., on_start=...)` runs that hook on the
  worker, never for a call the breaker refused, one given up in line, or
  one timed out or cancelled before a thread picked it up).
- Metadata cache: local SQLite, keyed by connection id, policy fingerprint
  and the connection's target (a digest of engine, host, port, database,
  login and options), TTL-bounded; never stores query results or sampled
  rows; trusted only when its file and directory are private to the
  server's user.
- Both are separate files from any queried SQLite data source and from every
  secret, TLS or Oracle client file.
