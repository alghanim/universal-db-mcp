# MCP tool contract

Tool names are stable. All tools return an envelope:
`request_id`, `connection_id`, `engine`, `data`, `warnings`, `elapsed_ms`,
`returned_row_count`, `truncated`, `next_cursor` (fields omitted when not
applicable). Failures surface as MCP tool errors whose message begins with a
stable category:

| Category | Meaning |
| --- | --- |
| `CONFIG_ERROR` | configuration invalid or missing; also an audit write that failed while `application.audit_fail_closed` is true |
| `POLICY_VIOLATION` | the guard refused the statement or a policy rule refused the request |
| `VALIDATION_ERROR` | bad tool arguments |
| `CONNECTION_ERROR` | the database could not be reached, the connection was lost, or the connection is held back (see below) |
| `QUERY_ERROR` | the statement ran and the engine rejected it: a SQL or data error |
| `AUTHORIZATION_DENIED` | caller may not see/do this (messages never enumerate alternatives) |
| `TIMEOUT` | deadline exceeded, or the engine's statement ceiling stopped the statement; cancellation semantics stated truthfully |
| `LIMIT_EXCEEDED` | concurrency/queue limits, or a response far over `security.max_response_bytes` |
| `CAPABILITY_UNSUPPORTED` | engine does not expose this |
| `DRIVER_MISSING` | pinned driver wheel absent from the environment |
| `INTERNAL_ERROR` | bug (redacted one-line scrub) |

`QUERY_ERROR` and `TIMEOUT` come from the driver's structured codes where it
has them (PostgreSQL SQLSTATE, SQL Server ODBC state, MySQL error numbers,
Oracle `DPY-`/`ORA-` codes, ClickHouse exception codes, SQLite result codes);
only the Db2 driver's message is read, for its trailing SQLSTATE. A statement
the engine cancelled at its time limit is `TIMEOUT` (PostgreSQL 57014, Db2
SQL0952N, SQL Server HYT00, MySQL 3024, MariaDB 1969, Oracle DPY-4024,
ClickHouse 159, a SQLite interrupt). A connector's own refusal keeps the
category it chose: the SQL Server connector's "the batch contained more than
one statement" is a `POLICY_VIOLATION`.

Messages worth recognizing:

- `CONNECTION_ERROR: connection '<id>' is still recovering from a driver call
  that timed out or was cancelled ...`: an earlier call on this connection
  has not returned yet; retry once it has.
- `CONNECTION_ERROR: connection '<id>' is unavailable: a connect to its
  database server did not complete within N s ...` and `... the limit of 10
  pending connects to database servers that did not answer has been reached`:
  database servers accepted or dropped connects and never answered (see
  `docs/architecture.md`, Execution model). SQLite connections, which have
  no database server, keep running.
- `CONNECTION_ERROR: connection is in an uncertain state after a previous
  cancelled query and was discarded; reconnect or restart`: the request was
  already waiting on the connection when an earlier call on it timed out or
  was cancelled (a hung connect included); retry.
- `LIMIT_EXCEEDED: connection '<id>' is busy with earlier requests; retry
  later`: the request waited its whole queue budget behind calls on the same
  connection.
- `LIMIT_EXCEEDED: query concurrency limit reached: this connection's database
  server is at its limit of N calls in flight, counting calls that timed out or
  were cancelled and have not returned yet; retry later` (with
  `security.max_concurrent_queries` of 3 or more, N is that value minus one;
  with 2 it reads `... at its limit of 1 abandoned call ...`), and `query
  concurrency limit reached; retry later` for the global limit.
- `TIMEOUT: ... did not start within its deadline ...`: nothing ran against
  the database, and the connection was kept.

## Error text

Error text is sanitized before it reaches the agent, the audit log or the
query history. Text a connector builds from a driver error has its quoted
fragments, every bare number (positions, line numbers and ports included) and
echoed values replaced by `<redacted>`, so a failing statement cannot be used
to read a masked value through the error. What survives: the exception class,
SQLSTATE/SQLCODE, codes such as `Code: n`, `ORA-nnnnn` or `SQLnnnnN`, bracketed
driver states (`[xxxxx]`), ODBC wrapper names, `LINE n:`, `argument n` and
version strings. PostgreSQL XML errors lose their DETAIL. Names you supplied
(a connection id, an object name) are echoed as their first 64 characters, and
an error's text is capped at 2000 characters. A connector's own refusal that
is not built from a driver error (for example ClickHouse's "more than 8 MiB
... even on 1-row blocks") is shown as written, numbers and quoted names
included, and so is a connector's own diagnostic wrapped like a driver error
(SQL Server: the ODBC driver it needs is not installed, naming the installed
ones). Auth failures: ClickHouse's login is hidden (`DB::Exception:
<redacted>: Authentication failed`); a MySQL 1045 keeps its errno and its
`(using password: YES)` hint. When a connector cannot be built at all, absolute file paths in the
`CONNECTION_ERROR` text (POSIX, Windows drive-letter and UNC) read `<path>`.

## Tools

| Tool | Notes |
| --- | --- |
| `db_list_connections` | configured ids only; no probing, so it answers with every database down. Each entry: engine, host, database (a SQLite file path), `tls_enabled`, `allowed_schemas`, `read_only` (always true: the server's promise) and `server_read_only_session`: true when the database session refuses writes too (PostgreSQL, MySQL and ClickHouse while `session.enforce_read_only` is on; always on SQLite; always false on Oracle, Db2 and SQL Server, where the guard alone refuses writes). `data.audit` is `{path, fail_closed, dropped_records}` for the whole server: the audit log in use (its absolute path is visible to the agent), `application.audit_fail_closed`, and the records lost since startup under `audit_fail_closed: false`. A warning says when `dropped_records` is above 0, or when auditing is off |
| `db_test_connection` | sanitized status/version/latency, the `session` block (`docs/session-safety.md`; its `server_reports` include MySQL's `sql_mode` and `character_set_client` and PostgreSQL's `standard_conforming_strings` and `client_encoding`), and the same `data.audit` block and warnings |
| `db_get_capabilities` | implemented vs verified vs permission-dependent |
| `db_list_catalogs` / `db_list_databases` | engine-appropriate; explains otherwise. On MySQL and ClickHouse `db_list_databases` is filtered by `allowed_schemas`, like `db_list_schemas` |
| `db_list_schemas` | policy-filtered, paginated |
| `db_list_tables` | kinds filter, search, catalog row estimates marked as estimates. On every engine the database's own objects come first, then those of the system schemas or dictionary owners the policy opens: under the default `security.allowed_system_schemas: [information_schema]` that is `information_schema` on PostgreSQL and MySQL (kind `view` on MySQL), SQL Server's `INFORMATION_SCHEMA` views when views are requested, and ClickHouse's `INFORMATION_SCHEMA` and `information_schema`. Oracle decides a dictionary owner as the policy does (`PDBADMIN` is user data, `APEX_nnnnnn` a dictionary); Db2 lists `SYSCAT` and `SYSIBM` last. Oracle `SYS.DUAL` and Db2 `SYSIBM.SYSDUMMY1` are listed only when `SYS` or `SYSIBM` is opened. SQLite's own `sqlite_*` tables and the internal tables of its FTS and R*Tree indexes, the views of other sessions' SQL, of column statistics, of stored credentials and of other objects' definitions (`information_schema.VIEWS`, `ROUTINES`, `COLUMNS`, ...; `docs/security.md`), and a SQL Server `dbo` table named like a compatibility view are never listed, even with `include_system` or with their schema opened |
| `db_get_table` | columns/keys/indexes/definition/estimate. Each column carries `sensitive`; a sensitive column's DEFAULT reads `<masked>`. A definition is withheld (null, with a warning) when a sensitive column has a DEFAULT or the definition names a sensitive column beside a string literal, and is otherwise cut to `security.max_cell_bytes`. A foreign key into a schema the policy hides reads `<not permitted>`. On SQL Server a bare name resolves where SQL Server resolves it (the login's default schema, then `dbo`) and `schema` names the one found. For schema arguments under an allowlist, see Schema arguments below |
| `db_list_columns` | paginated; sensitive DEFAULTs masked; the SQL Server bare-name rule above |
| `db_list_views` | definitions only where the engine reports them, cut to `max_cell_bytes`, and withheld when they name a sensitive column beside a string literal (DDL text is read with a tokenizer under every reading the engine may use, backslash escapes and nested comments or not; a comment counts as a literal, and text no reading can finish is withheld wherever it names a sensitive word). It lists the engine's view catalog within the allowlist, without the system-schema filter of `db_list_tables`: without an allowlist, PostgreSQL, Oracle and Db2 list their dictionary views too, by name only (live on the fixtures: PostgreSQL's `pg_tables` and `pg_roles`, Db2's `SYSCAT.TABLES`). Called without a schema it leaves out the views of a namesake schema (one differing only in case from an allowed one), as `db_list_synonyms` and `db_list_routines` do. It never lists a view of other sessions' SQL, of column statistics, of stored credentials or of other objects' definitions (`pg_stat_activity`, `pg_stats`, `SYSIBMADM.MON_CURRENT_SQL`, `SYSCAT.COLDIST`), with or without an allowlist |
| `db_list_synonyms` | targets listed, remote links never traversed; paged (`next_cursor`). Scoped like `db_list_views`, by the allowlist only: without one, Oracle lists the synonyms `ALL_SYNONYMS` holds, the PUBLIC synonyms for its dictionary views (`ALL_USERS`) included, by name only. On Oracle and Db2 a synonym or alias is left out when its own name, its target, or any synonym or alias further along its chain is a view no statement may read (Oracle's PUBLIC `V$SQL` and `ALL_TAB_HISTOGRAMS`); for a schema, Oracle reads that owner's synonyms and each local synonym they name in turn (`CONNECT BY NOCYCLE`) and lists only the owner's, and Db2 reads every alias and filters by schema |
| `db_list_routines` | metadata only; never executed; paged. Scoped like `db_list_views`, by the allowlist only (without one, Db2 lists the routines of `SYSIBM`, `SYSIBMADM`, `SYSPROC`, `SYSFUN` and its other system schemas too) |
| `db_search_metadata` | deterministic lexical ranking + match reasons |
| `db_get_relationships` | declared FKs; `include_inferred` adds labeled heuristics (no value sampling). A key into a hidden schema reads `to_table: <not permitted>` with no columns |
| `db_get_statistics` | catalog estimates with freshness; no COUNT(*) by default |
| `db_validate_query` | validation without execution + stated limitations; the same refusals the guard gives `db_query` (it runs no statement, so the Oracle bare-`DUAL` session check below is not made). `referenced_objects` names every table the statement reads, as written (a bare `DUAL` is `{schema: null, name: "DUAL"}`; on ClickHouse an `a.b` column that ClickHouse reads as the table `a.b` too). On MySQL and ClickHouse, `SHOW`/`DESCRIBE` verdicts apply the allowlist, qualification, schema-spelling and default-deny rules to the named object, `SHOW TABLES FROM <db>` included (`db_query` still never runs them). The limitations always include `db_explain captures plans without executing the statement: EXPLAIN ANALYZE is not supported`, plus `EXPLAIN ANALYZE is disabled by policy` while `security.allow_explain_analyze` is false, and on MySQL `db_explain returns a TREE or JSON plan only for a statement naming no masked column (MySQL prints the values it reads from const tables into those formats); FORMAT=TRADITIONAL plans are returned for any` |
| `db_query` | validated, bounded read; masking applied (see Masking). `parameters` values must be JSON scalars (string, number, boolean or null) and their names identifiers; anything else is `VALIDATION_ERROR` before anything runs. On MySQL, ClickHouse and PostgreSQL the text the driver formats is exactly the validated statement: only a placeholder outside string literals, quoted names and comments takes a value, a placeholder inside one is plain text, and every other `%` arrives as written; a placeholder count or name that does not match the values, or a named value no placeholder uses, is `VALIDATION_ERROR` (`docs/security.md`, Query safety). `parameters: []` binds nothing (a `LIKE 'a%'` runs as written). A result cut by the row or byte limit carries `truncated: true` and the warning `result truncated: limits are rows<=N, bytes<=M`. A cell cut to `max_cell_bytes` adds a warning of its own (`... exceeded the N byte cell limit and were truncated`), and on every engine but SQLite it also sets `truncated: true` (with the warning above); on SQLite only the row and byte limits set it |
| `db_sample_table` | default 20 rows; masking/omission policy applied; an object whose name holds a control character is refused (`VALIDATION_ERROR`), and such columns are skipped with a warning |
| `db_explain` | non-executing plans only, spelled `EXPLAIN <select>` on every engine: native EXPLAIN on PostgreSQL, MySQL, ClickHouse and SQLite; Oracle through `EXPLAIN PLAN` into the session-private `PLAN_TABLE` (DBMS_XPLAN text plus rows); SQL Server through `SET SHOWPLAN_ALL` on a private connection (needs the SHOWPLAN permission, named when missing); Db2 through `EXPLAIN PLAN` into DBA-provisioned explain tables (session schema or SYSTOOLS; refused with the `SYSINSTALLOBJECTS` instruction when absent; the rows written are read back and deleted again; the account needs INSERT, SELECT and DELETE on the explain tables, and a DELETE that fails is reported as a warning, never hidden). The statement reaches the engine exactly as written (the guard validated that text; Db2 `WITH UR` and `OPTIMIZE FOR n ROWS` survive). `parameters` are refused: a plan is captured for the text as written, so inline the literal values. The plan names every object the engine touches, including the base tables behind a permitted view. On MySQL a TREE or JSON plan of a statement naming a masked column is withheld (see below). Options and ANALYZE: see below |
| `db_get_query_history` | "Redacted operational history of this server process (fingerprints, not raw SQL); under HTTP it holds every client's calls. Not a substitute for the audit log." The result's note reads `operational history of this server process (under HTTP, every client's calls); raw SQL text is not included` (see the identity note below). It lists every call, the refusals the audit log coalesces included |
| `db_list_indexes` | indexes + primary keys of one object or a whole schema; paged; ClickHouse reports sorting keys and skipping indices; system catalogs excluded unless `include_system` or a system schema is named |
| `db_get_catalog` | one-call paged catalog snapshot: columns with declared and portable types, primary/foreign keys, indexes, row estimates, sensitivity hints; no data read; system catalogs (Oracle dictionary views, Db2 SYSCAT, pg_catalog, ...) excluded unless `include_system` or a system schema is named. A page can end early when the discovery time budget runs out (warning, and a cursor that resumes at the first table left out) |
| `db_profile_table` | `object_name` accepts `table` or `schema.table` (every tool that names an object does); bounded data profile over the connector's sample (null ratio, distinct, min/max cut to 200 characters, character lengths, top values) + evidence-backed findings; sensitive columns return counts only; a profile whose aggregate row exceeds `security.max_response_bytes` is a `LIMIT` error, never a silent row of nulls |
| `db_search_values` | a value searched across permitted tables of many connections without SQL (details below) |
| `db_infer_relationships` | declared foreign keys + inferred join candidates (name/type match, `<table>_id` convention) within and across connections, metadata only (details below) |
| `db_review_schema` | optimization review of a schema or whole connection: every permitted table profiled on a bounded sample under one time budget (biggest tables first, paged), findings prioritized by severity with evidence and a suggestion; `sensitive` columns counted only; `recommendations` count against `max_response_bytes` |
| `db_federated_query` | one validated read statement on several connections (or one statement per connection): per-connection results, each guarded, bounded and masked under its own policy, plus a merged view with a leading `connection` column when the column names agree; one failing connection is a warning (a refused statement is reported in that connection's `results[].error` and not run); one time budget; the strictest `max_response_bytes` among the connections binds the whole response, `merged` included (cut with a warning), and each statement runs with what is left of it, so a statement that ran is always reported; every statement leaves its own audit record (`db_federated_query:statement`, same request id, its connection and fingerprint) |
| `db_federated_join` | a client-side hash join of two bounded read results from two connections (or the same one) on key columns: inner or left, row-capped, keys compared as normalised text so `5`, `5.0` and `'5'` from different engines match; `on` lists 1 to 16 `[left, right]` pairs (more is `VALIDATION_ERROR`, a repeated pair counts once); masked values never match; the joined output is bounded by the stricter of the two policies' `max_response_bytes` (a partial join is `truncated` with a warning); either side refused fails the call; each side leaves its own audit record; nothing is written |
| `db_document_schema` | Markdown data dictionary of a schema or whole connection (paged): columns with declared and portable types, nullability, defaults, keys, indexes, comments, declared relationships; metadata only; comments and definitions cut to `max_cell_bytes`; a page can end early on the discovery time budget |

Every tool that takes a list of connections (`db_search_metadata`,
`db_search_values`, `db_infer_relationships`, `db_federated_query`) takes at
most 64 ids and works on a repeated id once. An unknown id is
`AUTHORIZATION_DENIED`. A failing connection, schema or table is a warning,
unless it was the only connection named.

## Statements: object rules

`db_query`, `db_validate_query`, `db_explain`, `db_federated_query` and
`db_federated_join` authorize every table a statement reads:

- **Qualified names under an allowlist.** When a connection's
  `allowed_schemas` is not empty (every engine except SQLite), every table must
  be schema-qualified (database-qualified on MySQL and ClickHouse). An engine
  binds a bare name through its search path, current database or schema, or
  synonyms, so a same-named table elsewhere could be read. The refusal is
  `AUTHORIZATION_DENIED: unqualified table 'buoys' is not permitted: connection
  'mock_pg' allows only schemas [ocean], so every table must name its schema
  (the engine would otherwise choose it); write ocean.buoys`. The suggestion
  spells the schema as the catalog does, and offers every permitted schema that
  holds the table. CTE names, aliases, column references and SQLite are
  unaffected, as are connections without `allowed_schemas`. The metadata,
  sample and profile tools still accept a bare `object_name`: they resolve it
  through the policy-scoped listing and query the qualified object.
- **Schema spelling.** Under an allowlist, a qualified name must name a schema
  spelling the catalog lists, as the engine reads it (quoted exactly, unquoted
  folded: lower case on PostgreSQL, upper case on Oracle and Db2), and one the
  policy admits where the catalog holds the name in several case spellings
  (`docs/security.md`, Object authorization). On MySQL database names are
  case-sensitive on Linux; `information_schema` is accepted in any case on
  MySQL, and as both `INFORMATION_SCHEMA` and `information_schema` on
  ClickHouse. On SQL Server this applies only where names that differ in case
  coexist.
- **Names as the catalog spells them (default-deny).** Under
  `default_deny_objects: true`, on PostgreSQL, Oracle, Db2 and ClickHouse a
  table name reads a listed object only as the catalog spells it (a quoted
  name as written, an unquoted one folded as the engine folds it); any other
  spelling is refused, because the engine would read another object or
  none: `POLICY_VIOLATION: table <written> is not spelled as the catalog
  lists it on connection '<id>' (<catalog spelling>): ..., so it names
  another object than the listed one, or none; write <catalog spelling>`
  (Oracle `TRAVEL."travellers"`, PostgreSQL `ocean."Readings"`, ClickHouse
  `TestDB.cuppings`; ClickHouse's `information_schema` is accepted in either
  case). On SQL
  Server a case variant is accepted only where the database collation
  ignores case. MySQL is unchanged.
- **Bare names where the session binds them (default-deny).** On
  PostgreSQL, Oracle, SQL Server and Db2 a bare table name is accepted only
  when its listed table is in the first schema the session looks bare names
  up in (`docs/security.md`, Object authorization); otherwise
  `POLICY_VIOLATION: the bare name <t> is the listed <s>.<t> only where the
  session looks bare names up in <s> first; on connection '<id>' a bare name
  is looked up in <schema> first (...), where the catalog lists no <t>, so
  the engine reads another object of that name, there or after it (a
  dictionary view, a synonym), or none; write <s>.<t>`. On the fixtures,
  mock_pg's bare `readings` (in `ocean`, with `search_path` `public`) and
  mock_db2's bare `CITIZENS` (in `MOI`, with `CURRENT SCHEMA` `DB2INST1`) are
  refused so, before they reach the engine, which would have failed anyway.
  A bare `pg_` name is refused unless its listed table is `pg_catalog`'s
  (`the bare name <t> is read from pg_catalog first ...`). How each session
  binds names is asked of the database, only for a statement with a bare
  name (or a SQL Server case variant), and kept in memory for 300 s; a
  failed lookup fails the call.
- **Synonyms (without default-deny).** With `default_deny_objects: false`,
  on Oracle, SQL Server and Db2 each table name a statement reads, and each
  name the metadata, sample and profile tools are given, is looked up as a
  synonym (Db2: an alias) by the name the engine looks up, unless it is a
  qualified name the listing holds exactly so; every object its chain names
  is checked as a written reference would be, and one over a database link
  or in another database is refused: `<category>: 'TRAVEL.Bookings' is a
  synonym that reads '...', refused as that is: ...`, with the category of
  the refusal it carries (`POLICY_VIOLATION` for the views no allowlist
  opens, `AUTHORIZATION_DENIED` for a closed schema). The synonym is named
  as the engine looks it up (`OCEAN.W4_SYN` for an unquoted `ocean.w4_syn`).
  This costs one catalog read per statement or object when such names occur,
  and a failed lookup fails the call.
- **SQL Server compatibility views.** `syslogins`, `sysobjects`,
  `sysusers` and the other 35 compatibility views, written under `dbo` or
  bare, are authorized as `sys.<name>` in every tool (`AUTHORIZATION_DENIED:
  'dbo.syslogins' is SQL Server's compatibility view sys.syslogins, ...`).
- **CTE names.** A bare name counts as a CTE only where a CTE the reference
  can see declares it, with each engine's folding (PostgreSQL lower case,
  Oracle and Db2 upper case, SQLite case-insensitive, SQL Server, MySQL and
  ClickHouse exact spelling). Any other bare name is authorized as a table, and
  a refusal then adds `; a CTE of that name elsewhere in the statement does not
  cover this reference`. Spell CTE names consistently and declare them before
  use. ClickHouse binds names its own way (`docs/security.md`, ClickHouse
  CTEs): a CTE's own name reads the table except in the later branches of a
  `WITH RECURSIVE ... UNION ALL` body, so `WITH RECURSIVE payroll AS (SELECT *
  FROM payroll) ...` is checked as a read of the table `payroll`.
- **Refused forms.** A name after `IN` without parentheses reads a table on
  ClickHouse and SQLite: `x IN t`, `x IN db.t`, and any expression there that
  holds a name (`x IN tuple(t)`, `x IN CAST(t AS String)`) are refused with `a
  name after IN without parentheses is not permitted: it reads a table; write
  IN (SELECT <column> FROM <schema>.<table>)`, as is ClickHouse `x IN (t)`
  with a single name, whatever parentheses and aliases wrap it (`x IN ((t AS
  z))`, `(+(t AS z))`, the `NOT IN`, `GLOBAL IN` and `GLOBAL NOT IN` forms:
  `IN (<name>) with a single name is not permitted on ClickHouse ...`). A
  placeholder or a constant there is a value and is accepted: ClickHouse's
  `x IN {ids:Array(UInt64)}`, `IN tuple(1, 2)`, `IN array(1, 2)`, `IN ((1 AS
  z))`, and a driver's `IN %(p)s` (which PostgreSQL and MySQL themselves
  reject). On every engine an `IN` with nothing after it, and `IN` right
  after `IN`, are refused (`IN with nothing after it, or IN right after IN,
  is not permitted ...`): that is how the validator reads ClickHouse's
  function `in(v, t)`, which reads the table `t`. ClickHouse functions that
  read the table or dictionary an argument names are refused by name,
  snake_case spellings included: the `in` family (`notIn`, `globalIn`,
  `nullIn`, `inIgnoreSet`, ...), `joinGet`, `joinGetOrNull`, every `dict*`
  function and `hasColumnInTable` (`function '<name>' is not permitted on
  ClickHouse: it names a table or dictionary in its arguments ...`). A
  ClickHouse `a.b` whose qualifier names no FROM or JOIN item of its query
  (or of an enclosing one) is authorized as the table `a.b`, which ClickHouse
  reads there where a table may stand; one qualified by an `ARRAY JOIN`,
  select or `WITH` alias is refused under an allowlist or default-deny, with
  the hint to name a tuple's element by its index (`a.1`)
  (`docs/security.md`, Query safety). ClickHouse `{name:Identifier}`
  parameters are refused. Server and session variables (`@@datadir`, SQL
  Server's `@@SERVERNAME`) are refused on every engine, and MySQL user
  variables (`@x`, `@x := ...`) too; pass values as parameters. On
  PostgreSQL and Db2 a `U&"..."` identifier is refused (PostgreSQL decodes
  its escapes; `U&'...'` strings are fine), and so is an `@` the validator
  reads as a parameter (the prefix `@ x`, `@@@`, `^@`; write `abs(x)`),
  while `$n` placeholders and the `@>`, `<@`, `@@` and `@?` operators stay
  allowed. On Oracle a database link is refused: an `@` outside a string
  literal, a hint or a double-quoted name (`"DUAL"@lnk`, `t @lnk`,
  `t/**/@lnk`; `POLICY_VIOLATION: database links / remote-object references
  (@link) are not permitted: ...`). `db_query` and `db_explain` check again
  in the connector before any session is opened, and there a statement
  holding an alternative-quoted `q'...'` or `nq'...'` literal and an `@`
  anywhere is refused as a database link too (`POLICY_VIOLATION: database
  links (@link) are not permitted on connection '<id>' ...`). The guard
  refuses such a statement first: the guard cannot parse an
  alternative-quoted `q'...'` or `nq'...'` literal, so a statement holding
  one is refused in every tool, `db_validate_query` included, with or
  without an `@` (`POLICY_VIOLATION: statement could not be parsed under the
  'oracle' dialect ...`); write the string in ordinary quotes (`'it''s'`).
  A `WITH` written after `UNION`, `INTERSECT` or `EXCEPT` and followed by
  further branches without parentheses is refused on every engine (engines
  differ over the branches it covers): write `(WITH ... SELECT ...)` as that
  branch, or the `WITH` ahead of the whole statement.
- **Names the engine reads as other names** (`POLICY_VIOLATION`): on SQL
  Server every table, column and alias must be written in printable ASCII
  without a trailing blank, bracketed or quoted names and string aliases
  included, because the collation reads other spellings as ASCII names (a
  table or column whose catalog name is not ASCII cannot be named in a query;
  `SELECT *` and the metadata, sample and profile tools still reach it); on
  Db2 a delimited name may not end in blanks, which Db2 drops; on Oracle an
  unquoted name may not contain `ı` or `ſ`, which Oracle upper-cases to `I`
  and `S` (quote the name to mean it exactly); on ClickHouse a quoted
  identifier may not contain a backslash, whose escapes ClickHouse decodes
  (double a backquote inside backquotes instead).
- **Dummy tables.** MySQL `FROM DUAL` names no table and is accepted. Oracle
  `DUAL` (bare, `"DUAL"`, `SYS.DUAL` or `"SYS"."DUAL"`) and Db2
  `SYSIBM.SYSDUMMY1` to `SYSDUMMY4` (Db2 LUW 11.5 has only `SYSDUMMY1`, a
  view) hold no data and are readable in statements on every connection,
  whatever the allowlists and `default_deny_objects` say; nothing else of
  `SYS` or `SYSIBM` opens. A bare Db2 `SYSDUMMY1` is `CURRENT SCHEMA`'s, so
  under an allowlist it is refused as unqualified (`... on Db2 it is
  SYSIBM.SYSDUMMY1: write SYSIBM.SYSDUMMY1`). On Oracle, `db_query`, the
  federated tools and `db_explain` first check, in the session that runs the
  statement, that a bare `DUAL` names `SYS.DUAL`: where the session's current
  schema owns any object called `DUAL`, or a logon set `CURRENT_SCHEMA` to a
  schema other than the login's, the statement is refused
  (`AUTHORIZATION_DENIED: a bare DUAL on connection '<id>' ...; write
  SYS.DUAL`). The metadata, sample and profile tools follow the listing: under
  `default_deny_objects: true` they refuse `SYS.DUAL` and `SYSIBM.SYSDUMMY1`
  unless `SYS` or `SYSIBM` is opened; with it false they describe and sample
  the qualified names in catalog case; a bare `DUAL` resolves there only when
  `SYS` is opened.
- **Views of other sessions' SQL** (`pg_stat_activity`, MySQL's
  `PROCESSLIST`, ClickHouse's `system.query_log`, Oracle's `V$SQL`, ...), of
  column statistics (MySQL's `COLUMN_STATISTICS`, `pg_stats`, Oracle's
  `*_HISTOGRAMS`, Db2's `SYSCAT.COLDIST`, ...) and of stored credentials
  (`information_schema.user_mapping_options`, `mysql.user`,
  `sys.sql_logins`, Oracle's database links, ...) are refused on every
  connection, whatever is opened; `docs/security.md` lists them. Oracle's
  `*_TAB_COLUMNS`, `*_TAB_COLS`, `*_NESTED_TABLE_COLS` and `COLS` and Db2's
  `SYSCAT.COLUMNS`, `SYSCAT.SYSCOLUMNS_UNION`, `SYSIBM.SYSCOLUMNS` and
  `SYSIBM.SYSKEYTARGETS` are readable where opened, but not their
  `LOW_VALUE`, `HIGH_VALUE`, `HIGH2KEY` and `LOW2KEY` columns: a statement
  naming one, selecting `*` (outside `COUNT`) or giving the view a column
  list after its alias is refused, and the sample, profile and metadata
  tools refuse these views whole.
- **SQLite.** A statement reads only the tables and views `db_list_tables`
  lists, with or without `default_deny_objects`. `sqlite_schema` and every
  other `sqlite_*` table are refused (`POLICY_VIOLATION`), as are SQLite's
  table-valued functions and eponymous virtual tables (`pragma_table_info`,
  `pragma_database_list`, `dbstat`, `json_each`, ...), which expose DEFAULT
  literals and the database file path. A table created in the last 300 s may
  be refused until the listing refreshes. The metadata and sample tools refuse
  a `sqlite_*` name in any spelling with `AUTHORIZATION_DENIED`.

`docs/security.md` has the full guard rules.

## Schema arguments

Under a connection's `allowed_schemas`, a `schema` argument, or the schema of
a dotted `object_name` such as `"Ocean".secrets`, must not name a case
spelling of an allowed schema that the policy does not admit
(`docs/security.md`, Object authorization). This holds for `db_list_tables`,
`db_list_views`, `db_list_synonyms`, `db_list_routines`, the tools built on
the permitted-table listing (`db_list_indexes`, `db_get_catalog`,
`db_review_schema`, `db_document_schema`) and the object tools
(`db_list_columns`, `db_get_table`, `db_sample_table`, `db_get_statistics`,
`db_profile_table`, `db_get_relationships`). The namesakes come from the whole
schema list `db_list_schemas` reads, so one that holds only a PostgreSQL
partitioned parent or foreign table, or one under a case-sensitive SQL Server
collation, is refused too: `AUTHORIZATION_DENIED: schema '<s>' is not
permitted on connection '<c>': schema names that differ only in case name
different schemas here, and this spelling is not the permitted one; spell it
as db_list_schemas does`. A spelling the catalog does not hold at all is
accepted as before (Oracle `travel` for `TRAVEL`).

## `db_explain` options and ANALYZE

`db_explain` never runs the statement. Accepted options, which are sent to the
engine (none are dropped silently):

| Engine | Accepted |
|---|---|
| PostgreSQL | `(FORMAT TEXT\|XML\|YAML, COSTS, VERBOSE, SETTINGS, SUMMARY, GENERIC_PLAN [boolean])`; `FORMAT JSON` is refused (use YAML or XML for a structured plan) |
| MySQL | `FORMAT=TRADITIONAL\|JSON\|TREE` |
| ClickHouse, Db2 | no option list |

The tool's description reads: "Non-executing query plan for validated SQL.
EXPLAIN ANALYZE (analyze=true) is never run: plans are captured without
executing the statement. On MySQL a TREE or JSON plan of a statement naming a
masked column is not returned (MySQL prints values it reads while planning);
FORMAT=TRADITIONAL is."

`ANALYZE`, `WAL`, `BUFFERS` and `TIMING` are never accepted, on any engine,
and `security.allow_explain_analyze` only picks the refusal. ANALYZE written
in the statement is `POLICY_VIOLATION ... disabled by policy` while the flag
is false (the default) and, with it true, `VALIDATION_ERROR: EXPLAIN option
'ANALYZE' is not supported by db_explain: plans are captured without executing
the statement; use EXPLAIN <statement>` (Oracle and SQL Server have no ANALYZE
form and refuse it as `POLICY_VIOLATION` either way, and SQLite, which cannot
parse it, as a `POLICY_VIOLATION` parse refusal). The `analyze=true`
argument is refused after the statement is validated (which may read the
catalog listing) and before any plan is requested: `POLICY_VIOLATION: EXPLAIN
ANALYZE is disabled by policy` with the flag false, `VALIDATION_ERROR:
analyze=true is not supported by db_explain: plans are captured without
executing the statement; call it without analyze` with it true. The connector
is always asked for a plan without ANALYZE; the `explain` limitation
`db_get_capabilities` reports for PostgreSQL, MySQL and ClickHouse reads
`db_explain never executes the statement; EXPLAIN ANALYZE is not supported.`

**MySQL plans that carry values.** MySQL reads const tables (rows a primary or
unique key equality finds) while it plans, and prints their values into TREE
and JSON plans. When the captured plan is TREE or JSON (a plain EXPLAIN
included, on a server whose `explain_format` is TREE or JSON) and the
statement names an identifier the mask patterns match (a column, alias,
table or `USING` name), selects a `*` other than `COUNT(*)`'s, or joins
`NATURAL`, the plan is withheld: `POLICY_VIOLATION: this plan is not
returned: ... use EXPLAIN FORMAT=TRADITIONAL, which prints no values`.
`FORMAT=TRADITIONAL` plans, MariaDB's tabular EXPLAIN and TREE or JSON plans
of statements naming nothing masked are returned. The built-in mask patterns
always apply, so this holds on every MySQL connection.

**ClickHouse caveat.** ClickHouse evaluates scalar and `IN` subqueries while
it plans, a view's definition included, even under plain EXPLAIN. Every
EXPLAIN is therefore planned under a 1000-row read ceiling (or the profile's
lower one); a statement whose planning would read more is refused as
`CAPABILITY_UNSUPPORTED` (use `db_query`). A JOIN refused on its row estimate
is planned again with `query_plan_optimize_join_order_limit=0`, in written
order, with a warning. On a `readonly=1` profile, or one that refuses the
ceiling, every plan carries a warning that producing it may have read table
data. The statement reaches the engine exactly as written, with no appended
`LIMIT`, and a `db_explain` timeout cancels it.

## Discovery tools for federated work (ETL, documentation, optimization)

The discovery tools exist so an agent can understand many databases
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
6. `db_review_schema` is the optimization pass in one call: the per-table
   profile and findings of `db_profile_table` over every permitted table
   of a schema (or connection), biggest first, under one
   `security.discovery_time_budget_seconds` budget, with a
   `recommendations` list sorted by severity. Its output is a review to
   act on, never a change: nothing in this server changes a database's data
   or schema (Db2's `db_explain` writes and deletes only its own plan rows).
7. `db_document_schema` is the documentation pass in one call: a Markdown
   data dictionary rendered from the same catalog `db_get_catalog` returns,
   page by page, with declared relationships listed per page. No table data
   is read and no row value appears in it; a sensitive column's DEFAULT
   literal is shown as `<masked>` (in `db_get_catalog` and `db_list_columns`
   too), and names or comments from the database are escaped so they cannot
   change the document's structure.
8. `db_federated_query` and `db_federated_join` are the federated read
   pass: the same question asked of every database at once (a customer id
   searched in the CRM, the ERP and the billing system in one call, results
   merged with the connection they came from), and a reconciliation join of
   two result sets across databases computed in the server, bounded and
   masked per connection. They read only; moving or loading data stays
   outside this server by design.

What they never do: read table data for the catalog or inference tools,
return values of columns matching `security.mask_columns`, search or infer
across system catalogs unless asked (`include_system` on `db_search_values`
and `db_infer_relationships`; profiling takes one named object), or run
outside the policy's row, byte and time ceilings
(`security.profile_max_sample_rows`, `security.discovery_time_budget_seconds`
and the query timeout). They walk only the listed tables a named
`db_sample_table` would read: a listed table the policy's object check
refuses (Db2 `SYSIBM.SYSCOLUMNS`, whose `HIGH2KEY`/`LOW2KEY` hold other
columns' values, once `SYSIBM` is opened) is skipped by `db_search_values`,
`db_review_schema`, `db_get_catalog` and `db_document_schema`. Evidence status: the findings rules are unit-tested
on a seeded SQLite database; in the live fixture run
(`test-evidence/discovery-tools/`) only ClickHouse held enough rows for the
data-driven rules to fire, and the cross-connection inference produced
same-connection relationships because the fixtures share no keys (the
cross-connection path is unit-tested).

### `db_search_values` in detail

- The query is literal text (`%`, `_` and `[` are escaped, never wildcards),
  matched case-insensitively. ClickHouse folds with `lowerUTF8`, so non-ASCII
  capitals match (`ZÜRICH`); SQLite folds ASCII letters only. Binary cells (raw bytes,
  ClickHouse `FixedString` returned as `{"$binary_b64": ...}`) are matched as
  UTF-8 text with trailing NULs stripped.
- A table is searched 16 columns per statement, at most 128 searchable
  columns per table; the rest are reported in `tables_partially_searched`
  with a warning. Tables the budget or the byte ceiling never reached are in
  `tables_not_searched`; connections in `connections_not_searched` and
  `connections_failed`. `budget_exhausted` says the time budget ran out.
- Each hit's `row` holds every searched column that matched, the row's key
  columns, and context columns. A row that matches in several column chunks
  is one hit whose `matched_columns` lists every matching column, whenever
  the server can tell it is the same row. Only a unique primary key whose
  columns are all visible identifies a row: a ClickHouse sorting key, or a
  primary key that includes a masked column, does not, and such tables are
  searched as keyless. For a keyless table wider than one chunk, later
  statements also read the table's first 8 visible columns and every column
  earlier hits matched in; a row is folded into an earlier hit only when that
  is certain. Rows that cannot be told apart may therefore appear as separate
  hits, but a hit never mixes two rows.
- Sensitive columns and system schemas are excluded, catalog names holding
  control characters are skipped with a warning, and names containing `%`
  are searched correctly on PostgreSQL, MySQL and ClickHouse.
- Per-table timeout, time budget clamped to the policy, response byte
  ceiling. One unreachable connection is a warning, not a failure; on Db2 a
  `CLI0109E` or on SQLite an out-of-range integer is a per-table warning. On a
  Unicode Db2 database a needle longer than a column simply does not match; on
  a non-Unicode one it still fails that table with `CLI0109E`. On Db2 a
  numeric needle outside a column's range (`CLI0111E`) fails the whole
  statement for that column chunk, its string predicates included.

### `db_infer_relationships` in detail

- Declared foreign keys come first and are never dropped by the caps.
- Inferred candidates: at most 1000 per call and 5 per source column, within
  `max_response_bytes`; `truncated` and `more_available` say when some were
  left out.
- A key shared by more than 3 tables, or a column that is the source table's
  own key, is treated as a convention (a surrogate key) and is not a
  candidate, unless the column is named for the target table (it starts
  with the table's name or its singular and `_`: `customer_id`,
  `customer_no`, `customers_code`).
- It honours `security.discovery_time_budget_seconds` (the smallest across
  the connections read) over its catalog reads and reads at most 50 schemas
  per call; tables whose catalog was not read are left out with a warning,
  and `budget_exhausted` says so.

## Value representation

- Integers with |v| < 2^53: JSON numbers. Larger: **strings** typed
  `bigint` (exact, no float drift).
- `decimal`: **strings** (exact); a value longer than `max_cell_bytes` is
  cut with a warning, like text.
- timestamps: ISO 8601 with offset when known. PostgreSQL `infinity`,
  `-infinity`, BC and year-10000+ dates and timestamps, `time`/`timetz`
  `24:00:00`, interval `infinity` and intervals outside Python's range come
  back as PostgreSQL's own text; a binary-format `timestamptz` is shown in
  UTC (`+00`).
- PostgreSQL `json`, `jsonb` and anonymous records within `max_cell_bytes`
  keep their JSON types (records as arrays); a longer value arrives as its cut
  text, flagged truncated. Arrays come back as PostgreSQL's own JSON text,
  numbers unquoted and exact (`numeric[]` `{1.10,2}` is `[1.10,2]`, `text[]`
  is `["a","b"]`); named composite types as text.
- binary: `{"$binary_b64": ...}` (`$truncated: true` when cut). Oracle BLOBs
  use this form; CLOBs are cut to the cell limit with `truncated: true`; an
  unreadable BFILE is `null` with a warning; VECTOR, object and collection
  values are JSON.
- null: `null`.
- Sensitive columns: masked with `<masked>` or omitted per
  `security.mask_action`, in every result path (see Masking).

## Masking

Sensitive columns are those whose names match `security.mask_columns` (the
built-in patterns plus any you add; matched against the name as written and in
lower and upper case, and, for a name outside ASCII or with blanks around it,
also in its NFKC form stripped: with a pattern `^mrn$`, `ＭＲＮ` and `MRN `
match, and `ſſn` matches the built-in `ssn`; the same match marks `sensitive`
in the metadata tools). Masking follows each output column back to its source
columns on the parsed statement, through aliases, set operations (UNION
branches), column lists, derived tables and CTEs (recursive ones included),
whole-row references, table functions, PostgreSQL attribute notation,
ClickHouse aliases, tuple access and `COLUMNS`/`APPLY`, and SQL Server `FOR
JSON`/`FOR XML` (masked whole when any projection is sensitive or a star is
used). A result position is masked when a sensitive column flows into it,
whatever the output column is called.

It fails closed: when the output cannot be traced (the analysis is bounded at
16 rounds and 2 s; a CTE binding the analysis cannot mirror, such as a CTE
used with another letter case on SQL Server or MySQL, a CTE naming one
declared after it on SQLite or ClickHouse, or a ClickHouse recursion whose
first branch names its own CTE), every column the
statement does not prove clean is masked, with the warning `the result's
columns could not all be traced to their source columns; every column the
statement does not prove clean was masked (fail closed)`. A masked result is
cut again to `max_response_bytes` after masking. In particular:

- PostgreSQL `(expr).*` and ClickHouse `untuple(t)` are traced as a run of
  columns of unknown width, never as one column.
- A statement with Oracle `MATCH_RECOGNIZE` or PostgreSQL `SEARCH`/`CYCLE`
  (whose `ord`/`path` columns carry the BY columns' values) is untraceable:
  every column it does not prove clean is masked.
- A column qualifier the analysis binds to no source (other than on
  ClickHouse), or one two FROM items share in different case (`"A"` and
  `a`) where the engine may bind either, is not proven clean. A PIVOT or
  UNPIVOT alias binds to its FROM item and is traced through it.
- SQLite names an unaliased expression by its text (`upper(x)`) and a second
  column of one name `x:1`: such names, and a name no source outputs, are
  masked when the source may carry a sensitive value.
- Where a star expands to a run of unknown width, each alias the statement
  wrote must be reported by the driver at the position the trace gives it;
  otherwise every column not proven clean is masked (a PostgreSQL alias over
  63 bytes, which the server truncates, included).
- Engines that fold names are traced as they fold (Oracle by Unicode's
  rules), so a CTE decoy in another case does not hide a table.

Definitions (`db_get_table`, `db_list_views`, index definitions) are read
with a tokenizer, so an apostrophe in a quoted name, a comment or a MySQL
`\'` escape cannot shift where a literal begins: a definition is withheld
when any reading the engine may use finds a literal (a comment counts) next
to a sensitive name.

PostgreSQL attribute notation (`b.fn` meaning `fn(b)`): a qualified name is
checked against the base table's catalog columns (one `information_schema`
lookup per table, cached 300 s, at most 16 new lookups per statement). A
qualified name that is not a real column is masked. When the columns cannot
be read, the budget is exceeded, the relation is a materialized view (which
`information_schema` does not list), or a bare name is missing from the
catalog listing (a partitioned parent, a foreign table, a table newer than the
listing), every column named through that qualifier is masked with a warning;
name those columns without the qualifier, or schema-qualify the table.

**Limitation (owner decision):** masking protects projected values only. A
`WHERE`, `ORDER BY`, `GROUP BY` or `JOIN` condition on a masked column is
not masked and can still reveal what the column holds, one guess at a time.
Masking is a heuristic second line, not the security boundary: for columns
that must stay secret, use column-level grants, or a view without them, for
the connection's login.

## Pagination

Opaque cursors: HMAC-signed, bound to caller identity + connection id +
operation kind + policy fingerprint + expiry (15 min). Cross-identity or
cross-connection reuse is an authorization denial, not a lookup failure. The
cursors of `db_list_tables`, `db_list_schemas` and `db_list_views` are also
bound to their filter arguments; reusing one with other filters is
`VALIDATION_ERROR: cursor does not apply to this operation`. A cursor issued
before an upgrade that changes the policy fingerprint is rejected as stale:
list again.

## Response size

`security.max_response_bytes` bounds the data of every paged tool:
`db_list_*`, `db_get_catalog`, `db_document_schema`, `db_review_schema`,
`db_search_values`, the federated tools. A page that reaches it stops with the
warning `response byte ceiling (security.max_response_bytes) reached after K of
N item(s); continue with the cursor`, and the cursor resumes exactly there. A
first entry too large on its own keeps the leading items that fit and is
marked `<part>_truncated` (for example `columns_truncated`). Single-object
tools (`db_get_table`, `db_profile_table`, `db_explain`,
`db_get_query_history`) have a backstop: a response more than 64 KiB over the
ceiling is refused with `LIMIT_EXCEEDED: the response would be N bytes, over
security.max_response_bytes ...; narrow the request`. Warnings are capped at
50 per envelope (the last one reads `K further warning(s) omitted`), each at
most 1000 characters.

Each tool result is transmitted twice: once as structured content and once as
a pretty-printed text block (the copy the model reads), so the bytes on the
wire are roughly 2.7x `max_response_bytes` for a large result. Size the cap
accordingly.

## Caller identity (read before relying on history or cursors)

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
