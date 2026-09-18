# Security model

## Threat model (abbreviated)

- **The model (LLM) is untrusted input.** Tool arguments are validated,
  clamped, and authorization-checked; nothing in a tool call can weaken
  policy, create connections, reveal credentials, or execute shell.
- **Database content is untrusted.** Table names, comments, rows, and error
  text never alter permissions or instructions; search/metadata output is
  deterministic and scoped.
- **The coding agent shares the OS account in stdio mode.** This is not a
  security boundary (spec §6); use a separate service identity + HTTP mode
  when credentials must be hidden from the agent.
- **Public internet is unreachable** in the target environment; the
  application performs zero network acquisition regardless.

## Secrets

- Referenced only via `username_env`, `password_env`, `password_file`.
- Secret files with group/other read bits are rejected (POSIX).
- Resolved values are wrapped in `SecretMark`: `repr()`, `str()`, and JSON
  serialization yield `<redacted>`.
- Never present in results, errors, logs, DSNs, process args, or the bundle
  manifest.

## Query safety (details in docs/tools.md)

- Exactly one statement; parser failure is a denial, not approval.
- Modifying CTEs inside SELECT are denied (full-AST walk).
- Unknown/dangerous functions and table functions denied; executable
  comments (`/*! ... */`) denied; `SELECT INTO`, ATTACH, PRAGMA, SET denied.
- Objects resolved conservatively against the connection's allowlist;
  unresolvable = denied under `default_deny_objects`.
- Sequence access denied (`NEXT VALUE FOR`, Oracle `NEXTVAL`/`CURRVAL`, Db2
  `NEXTVAL FOR`): a read that advances a sequence is a write. T-SQL table
  hints other than NOLOCK, READUNCOMMITTED, READPAST and NOWAIT denied (they
  take or escalate locks).
- EXPLAIN/SHOW/DESCRIBE via dedicated per-dialect policies only; the
  validated statement text is what reaches the engine.
- Bound parameters via driver facilities; identifiers validated and quoted
  by the adapter.

## Cancellation honesty

Engines with out-of-band cancel report `server_side_cancel: supported`
(SQLite, PostgreSQL, Oracle, ClickHouse) only where the driver actually
provides it. PyMySQL, pyodbc, and ibm_db report unsupported; on timeout the
connection is discarded and the tool output says the query may continue
server-side. The executor never reuses a poisoned connection.

## Audit

Fields: caller identity, connection id, action, timing, row count, policy
outcome, SQL fingerprint (literals removed). The federated tools run several
statements under one request: each statement leaves its own record (action
`<tool>:statement`, the same request id, its connection and fingerprint) in
addition to the tool's own record, so the per-connection trail is as complete
as `db_query`'s. Raw SQL text, parameters, and
rows are stored only when explicitly enabled (off by default). Rotation by
size. `audit_fail_closed: true` (default) means operations fail when the
required audit record cannot be written.

## Transport

- stdio: protocol-only stdout; logs to stderr/files; no TCP listener.
- http: Streamable HTTP with bearer-token authentication (token from a
  local file), loopback bind by default, intended to sit behind an internal
  authenticated reverse proxy. Not exposed publicly. Per-caller
  authorization in HTTP mode is coarse in v1 (single service identity) and
  documented as such.
