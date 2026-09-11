# Adding a connector

## Contract

Subclass `universal_db_mcp.connectors.base.DatabaseConnector` and implement
the full abstract surface. Non-negotiables:

1. **Lazy driver import** via `driver_helpers.open_module(name, artifact)` —
   an absent wheel raises `DriverUnavailableError` naming the artifact; it
   must never break other engines.
2. **Truthful capabilities** — `supported` only for implemented AND
   integration-proven; `unverified` for implemented-but-unproven;
   `unsupported` for genuinely absent. Never optimistic booleans.
3. **Bounded execution** — fetch in batches honoring
   `spec.max_rows / max_response_bytes / max_cell_bytes`; implement
   `cancel_current()` only if the driver truly supports out-of-band cancel.
4. **No secret leakage** — credentials come from `SecretMark`; never log
   connection objects, DSNs, or raw errors without `scrub_exception`.
5. **Identifier quoting** via `quote_identifier` (engine-correct case
   handling; preserve catalog/schema distinctions).
6. **No side effects for metadata** — never execute routines, never create
   explain tables, never bind packages.

## Registration

Add to `connectors/registry.py` `_LAZY` (module path + class name) and to
`config.ENGINE_TYPES`. Extend the config `ConnectionConfig` validation for
engine-specific fields via `options` (validated, documented).

## Tests

- Unit: connector behavior against a local fixture (see SQLite tests).
- Integration (Gate C): env-gated round-trip in
  `tests/integration/test_connectors.py`; absent fixture => skip with a
  blocked reason, never a vacuous pass.
- Update `docs/driver-matrix.md` and the capability matrix in the same
  change set.

## Extension points (not implemented, no claims)

Trino, DuckDB, MongoDB: reserve the config `type` only after a connector
exists; JDBC-based engines additionally require administrator-provided
local JARs and a declared local JRE (no Maven resolution, ever).
