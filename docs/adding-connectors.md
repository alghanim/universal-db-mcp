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
7. **Typed driver errors** — wrap every driver call in
   `translated_driver_errors()` (`phase="execute"` around statements), so a
   statement the engine rejects is `QUERY_ERROR`, one it cancelled at its time
   limit is `TIMEOUT`, and a lost connection is `CONNECTION_ERROR`, from the
   driver's structured codes, never from message text. A refusal of your own
   is a `ConnectorError` raised without a driver exception (or `from None`):
   its text is shown as written.
8. **Server-side value caps and bounded fetches** — cut long values to
   `max_cell_bytes` on the server where the engine allows it, fetch at most
   `max_rows + 1` rows, and say in `capabilities()` which shapes are read
   whole.
9. **System schemas** — list an engine catalog or dictionary schema only when
   the administrator opened it (`_opened_schemas()`: `allowed_system_schemas`
   and the connection's `allowed_schemas`), after the database's own objects
   (`own_objects_first()`); add the engine's list to
   `discovery/system_schemas.py`, with its views of other sessions' SQL in
   `SESSION_SQL_VIEWS`, its column-statistics views in
   `COLUMN_STATISTICS_VIEWS`, its stored-credential views in
   `CREDENTIAL_VIEWS`, catalogs that carry low and high values in
   `COLUMN_VALUE_COLUMNS`, and any data-free dummy table in
   `DATA_FREE_TABLES`. Leave every view `is_session_sql_view` matches out of
   `list_tables`, `list_views` and `list_synonyms` (a synonym whose chain
   reaches one too: `driver_helpers.synonym_names_refused_view`), and name
   the dictionary in your own catalog SQL (`SYS.ALL_TABLES`,
   `pg_catalog.pg_class`) so an object of the same name in the login's
   schema cannot stand in for it.
10. **`close()`** — release any session kept between calls (a pooled metadata
    connection); the server calls it once a discarded connector's last call
    has returned.
11. **Plans never execute** — `explain()` captures a plan without running the
    statement, and `explain(sql, analyze=True)` raises
    `NotImplementedError(EXPLAIN_ANALYZE_UNSUPPORTED)`. Say in
    `capabilities()` what capturing it writes (Oracle's `PLAN_TABLE`, Db2's
    explain tables).
12. **Connect in `_connect()`** — the executor recognizes a hung connect by
    its worker being inside a method of that name, and keys the database
    server by `(engine, host, port)`: add the driver's default port to
    `_DEFAULT_PORTS` in `services/executor.py`, and key a connection that
    does not dial its configured host and port on what it does reach
    (`_server`: Oracle `tns_alias`, MySQL `unix_socket`).
13. **Hold the guard's reading** — in `_configure_session`, before the
    safety profile, set every session setting under which the server would
    read statement text differently from the SQL guard (string escapes,
    quoted identifiers, the client character set, a dialect switch), check
    on the server that it took, and raise `self._reading_required(what,
    exc)` when it did not (`docs/session-safety.md`). Record each with
    `_session_applied`.
14. **Names the engine binds** — where a name may be a synonym or alias,
    implement `synonym_chains(names)` (the base returns `{}`), matching names
    exactly as the engine looks them up and returning `SynonymTarget(schema,
    name, elsewhere)` for each step; where a bare name binds through a
    session's search path, implement `name_binding()` (the base returns
    `None`) from a new session, never the shared metadata one.

## Registration

Add to `connectors/registry.py` `_LAZY` (module path + class name) and to
`config.ENGINE_TYPES`. Engine-specific fields go in `options`, allowlisted
and typed in `config._ENGINE_OPTIONS` (only options the connector consumes)
and documented. If sqlglot names the dialect differently, map it in the
guard's `_DIALECT_MAP`, and check the guard's engine-specific rules against
a live instance: every check must see the name the engine will read.

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
