# MCP tool contract

Tool names are stable. All tools return an envelope:
`request_id`, `connection_id`, `engine`, `data`, `warnings`, `elapsed_ms`,
`returned_row_count`, `truncated`, `next_cursor` (fields omitted when not
applicable). Failures surface as MCP tool errors whose message begins with a
stable category:

| Category | Meaning |
| --- | --- |
| `CONFIG_ERROR` | configuration invalid or missing |
| `POLICY_VIOLATION` | statement/policy rejection |
| `VALIDATION_ERROR` | bad tool arguments |
| `CONNECTION_ERROR` | database unreachable/failed |
| `AUTHORIZATION_DENIED` | caller may not see/do this (messages never enumerate alternatives) |
| `TIMEOUT` | deadline exceeded; cancellation semantics stated truthfully |
| `LIMIT_EXCEEDED` | concurrency/queue limits |
| `CAPABILITY_UNSUPPORTED` | engine does not expose this |
| `DRIVER_MISSING` | pinned driver wheel absent from the environment |
| `INTERNAL_ERROR` | bug (redacted one-line scrub) |

## Tools

| Tool | Notes |
| --- | --- |
| `db_list_connections` | configured ids only; no probing |
| `db_test_connection` | sanitized status/version/latency |
| `db_get_capabilities` | implemented vs verified vs permission-dependent |
| `db_list_catalogs` / `db_list_databases` | engine-appropriate; explains otherwise |
| `db_list_schemas` | policy-filtered, paginated |
| `db_list_tables` | kinds filter, search, catalog row estimates marked as estimates |
| `db_get_table` | columns/keys/indexes/definition/estimate |
| `db_list_columns` | paginated |
| `db_list_views` | definitions only where the engine reports them |
| `db_list_synonyms` | targets listed, remote links never traversed |
| `db_list_routines` | metadata only; never executed |
| `db_search_metadata` | deterministic lexical ranking + match reasons |
| `db_get_relationships` | declared FKs; `include_inferred` adds labeled heuristics (no value sampling) |
| `db_get_statistics` | catalog estimates with freshness; no COUNT(*) by default |
| `db_validate_query` | validation without execution + stated limitations |
| `db_query` | validated, bounded read; masking applied |
| `db_sample_table` | default 20 rows; masking/omission policy applied |
| `db_explain` | non-executing plans only |
| `db_get_query_history` | process-scoped, fingerprints only (see the identity note below) |

## Value representation

- Integers with |v| < 2^53: JSON numbers. Larger: **strings** typed
  `bigint` (exact, no float drift).
- `decimal`: **strings** (exact).
- timestamps: ISO 8601 with offset when known.
- binary: `{"$binary_b64": ...}` (`$truncated: true` when cut).
- null: `null`.
- Sensitive columns (name-heuristic patterns, configurable): masked with
  `<masked>` or omitted per `security.mask_action`, in every result path.
  Heuristics are not the security boundary — grants are.

## Pagination

## Caller identity (read before relying on the two notes below)

The server derives one identity per PROCESS (the account it runs as), not one
per request. Under stdio that is exactly the caller, because each agent spawns
its own server. Under HTTP there is a single shared bearer token and a single
service account, so:

* `db_get_query_history` returns the history of the whole process: every
  authenticated caller sees every other caller's request ids, connection ids,
  SQL fingerprints and row counts. It is not caller-scoped under HTTP.
* Cursor binding to "caller identity" is likewise process-scoped, so it cannot
  distinguish two HTTP callers.

Deploy HTTP only where every authorized caller is entitled to the same view,
or give each caller its own listener and token.

## Response size

Each tool result is transmitted twice: once as structured content and once as
a pretty-printed text block (the copy the model reads). `security.max_response_bytes`
bounds the envelope our code builds, so the bytes on the wire are roughly 2.7x
that value for a large result. Size the cap accordingly.

Opaque cursors: HMAC-signed, bound to caller identity + connection id +
operation kind + policy fingerprint + expiry (15 min). Cross-identity or
cross-connection reuse is an authorization denial, not a lookup failure.
