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
| `db_get_query_history` | caller-scoped, fingerprints only |

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

Opaque cursors: HMAC-signed, bound to caller identity + connection id +
operation kind + policy fingerprint + expiry (15 min). Cross-identity or
cross-connection reuse is an authorization denial, not a lookup failure.
