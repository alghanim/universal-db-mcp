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

## Components

| Module | Responsibility |
| --- | --- |
| `config.py` | strict YAML schema, secret resolution to `SecretMark` |
| `security/policy.py` | effective ceilings + object authorization |
| `security/sql_guard.py` | dialect-aware statement validation (sqlglot) |
| `security/cursors.py` | HMAC-bound opaque pagination cursors |
| `security/redact.py` | redaction chokepoint, SQL fingerprints |
| `services/executor.py` | worker-thread execution, deadlines, cancel hooks, poisoning |
| `services/audit.py` | JSONL audit with rotation, fail-closed option |
| `services/metadata.py` | policy-scoped local metadata cache, lexical search |
| `connectors/*` | per-engine adapters, capability matrices |
| `diagnostics/doctor.py` | offline artifact/policy checks |

## Execution model

Synchronous drivers run on worker threads via anyio, under a global
concurrency limiter and a per-query deadline. On deadline: the connector's
cancel hook fires (SQLite `interrupt()`, psycopg `cancel()`, oracledb
`cancel()`, clickhouse `cancel_query()`); engines without a hook are
reported as such. After a timeout the connection is poisoned and discarded —
never reused with uncertain state. Fetches run in bounded batches with
row/byte/cell ceilings; truncation stops the cursor, not after full fetch.

## Defense in depth (read-only)

1. **Database privileges** — read-only accounts are mandatory (primary).
2. **SQL guard** — single-statement, dialect-scoped AST validation; denies
   DML/DDL/TCL/PRAGMA/SET anywhere in the tree including CTEs; denies
   unknown functions and table functions; conservative object resolution
   under default-deny.
3. **Engine backstops** — e.g. SQLite opens `mode=ro` with `PRAGMA
   query_only` and a denying authorizer.
4. **Policy ceilings** — rows, bytes, cells, timeouts, concurrency, all
   clamped server-side.

## Local state

- Audit log: append-only JSONL, size rotation, optional fail-closed.
- Metadata cache: local SQLite, keyed by connection + policy fingerprint,
  TTL-bounded; never stores query results or sampled rows.
- Both are separate files from any queried SQLite data source.
