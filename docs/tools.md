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
| `db_list_indexes` | indexes + primary keys of one object or a whole schema; ClickHouse reports sorting keys and skipping indices; system catalogs excluded unless `include_system` or a system schema is named |
| `db_get_catalog` | one-call paged catalog snapshot: columns with declared and portable types, primary/foreign keys, indexes, row estimates, sensitivity hints; no data read; system catalogs (Oracle dictionary views, Db2 SYSCAT, pg_catalog, ...) excluded unless `include_system` or a system schema is named |
| `db_profile_table` | `object_name` accepts `table` or `schema.table` (every tool that names an object does); bounded data profile over the connector's sample (null ratio, distinct, min/max cut to 200 characters, character lengths, top values) + evidence-backed findings; sensitive columns return counts only; a profile whose aggregate row exceeds `security.max_response_bytes` is a `LIMIT` error, never a silent row of nulls |
| `db_search_values` | a value searched across permitted tables of many connections without SQL; the query is literal text (`%`, `_` and `[` are escaped, never wildcards); per-table hits, time budget clamped to the policy, per-table timeout, response byte ceiling, system schemas and sensitive columns excluded; one unreachable connection is a warning, not a failure |
| `db_infer_relationships` | declared foreign keys + inferred join candidates (name/type match, `<table>_id` convention) within and across connections, metadata only |

## Discovery tools for federated work (ETL, documentation, optimization)

The five discovery tools exist so an agent can understand many databases
without hand-written queries, then document or extract from them:

1. `db_get_catalog` per connection gives every permitted table with columns
   in one portable vocabulary (`portable_type`: integer, bigint, decimal,
   float, boolean, string, text, date, time, timestamp, timestamptz, binary,
   json, uuid, enum, other) and a `kind` that says what may be aggregated
   (`lob` marks Oracle/Db2/SQL Server large objects, which are counted
   through `IS NOT NULL` but never aggregated or searched). Declared sizes
   are part of the type on every engine (`varchar(200)`, `NUMBER(12,2)`,
   `nvarchar(max)`), so the oversized-string and integer-range findings
   compare against what the schema really declares.
   An ETL layer creates targets from this; a documentation pass renders it.
2. `db_infer_relationships` across connections proposes joins between
   databases that share keys (a `customer_id` in the CRM and the ERP), with a
   stated confidence; declared foreign keys are reported as facts.
3. `db_profile_table` measures a bounded sample and returns findings the
   agent can turn into recommendations: missing primary key, foreign key
   without an index, nullable columns that are never null, oversized string
   declarations, low-cardinality columns (lookup/enum candidates), natural
   key candidates, integer ranges that fit a smaller type, missing
   statistics. Every finding carries its evidence and says when the sample
   is smaller than the table.
4. `db_search_values` answers "where does this value appear" across
   everything the agent may read, case-insensitively, bounded per table and
   by a time budget, under the session safety profile
   (`docs/session-safety.md`), so a search over production never holds locks
   or runs unbounded.
5. `db_list_indexes` supports the optimization pass directly.

What they never do: read table data for the catalog or inference tools,
return values of columns matching `security.mask_columns`, search or infer
across system catalogs unless asked (`include_system` on `db_search_values`
and `db_infer_relationships`; profiling takes one named object), or run
outside the policy's row, byte and time ceilings
(`security.profile_max_sample_rows`, `security.discovery_time_budget_seconds`
and the query timeout). Evidence status: the findings rules are unit-tested
on a seeded SQLite database; in the live fixture run
(`test-evidence/discovery-tools/`) only ClickHouse held enough rows for the
data-driven rules to fire, and the cross-connection inference produced
same-connection relationships because the fixtures share no keys (the
cross-connection path is unit-tested).

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
