# Security model

To report a vulnerability, see `SECURITY.md` (GitHub private vulnerability
reporting only).

## Threat model (abbreviated)

- **The model (LLM) is untrusted input.** Tool arguments are validated,
  clamped, and authorization-checked; nothing in a tool call can weaken
  policy, create connections, reveal credentials, or execute shell.
- **Database content is untrusted.** Table names, comments, rows, and error
  text never alter permissions or instructions; search/metadata output is
  deterministic and scoped.
- **The coding agent shares the OS account in stdio mode.** This is not a
  security boundary (spec §6). A stdio registration runs the server as the
  user, inside the agent: an agent tool that can run shell commands or read
  files can read the credentials in `<config dir>/secrets/` (for the per-user
  config, `~/.universal-db-mcp/secrets/`) and connect directly, outside the
  guard, masking and audit. `configure-agents` prints a `NOTICE` saying so
  after each registration, and `add-connection` whenever it writes secret
  files for a config other than the system config, whatever that config's
  transport (naming the account the secret files belong to; the system
  config gets a service-restart hint instead). Give each connection a
  SELECT-only login limited to its `allowed_schemas`, or run the server as a
  service in HTTP mode under a separate account when credentials must be
  hidden from the agent.
- **The database login is the primary control.** Read-only accounts limited
  to the schemas you expose are mandatory; the guard, the session profile and
  masking sit behind them. On SQL Server this is essential: give the login
  `db_datareader` plus `GRANT SHOWPLAN` (for `db_explain`), never `db_owner`
  (see SQL Server below). No tool writes your data, but on two engines
  `db_explain` writes the plan before reading it back. On Db2 it inserts the
  plan rows into the explain tables a DBA provisions, reads them back and
  deletes them, so that login needs INSERT, SELECT and DELETE on those tables
  (and only there); on Oracle it uses the session-private `PLAN_TABLE`, which
  needs no grant.
- **Public internet is unreachable** in the target environment; the
  application performs zero network acquisition regardless.

## Secrets

- Referenced only via `username_env`, `password_env`, `username_file`,
  `password_file` (and for Oracle wallets `options.wallet_password_file` or
  `options.wallet_password_env`). An inline `options.wallet_password` is a
  `CONFIG_ERROR`.
- `*_env` names must be ASCII identifiers (`[A-Za-z_][A-Za-z0-9_]*`).
- POSIX: secret files with group/other read bits are rejected. On macOS an
  extended ACL entry that grants anyone but the file's owner read, write,
  append, writesecurity or chown on a secret file or the HTTP token
  (`-rw-------+` with `everyone allow read`) is rejected too, when `serve`
  reads it and by `doctor` (remedy: `chmod -N <file>`); an ACL that cannot be read is
  rejected. A secret or config file that is not UTF-8 text is a
  `CONFIG_ERROR` that names the file but no byte of it.
- Windows: `serve` and `doctor` check the secret files' and the HTTP token's
  ACLs. The owner must be SYSTEM, Administrators or the service account, and
  no ACE may grant read or write (`FILE_WRITE_DATA`, `FILE_APPEND_DATA`,
  `GENERIC_WRITE`), `WRITE_DAC` or `WRITE_OWNER` to Everyone, Authenticated
  Users, Users, Interactive or another broad group; object and callback ACEs
  are refused. A read grant to the one service account, as the MSI
  provisions, is accepted. Remedy:
  `icacls <file> /inheritance:r /grant:r *S-1-5-18:F *S-1-5-32-544:F <service account>:R`.
  The ACL check is unit-tested with simulated Windows APIs only.
- Resolved values are wrapped in `SecretMark`: `repr()`, `str()`, and JSON
  serialization yield `<redacted>`.
- Never present in results, errors, logs, DSNs, process args, or the bundle
  manifest. Passwords, tokens and wallet passwords are scrubbed wherever they
  appear; auth-failure message shapes are redacted. Usernames are treated as
  identifiers and are not scrubbed from arbitrary text, except in the
  auth-failure shapes: ClickHouse's `DB::Exception: <login>: Authentication
  failed` hides the login. MySQL's `(using password: YES)` is kept, so a 1045
  error keeps its errno and message.
- `add-connection` writes secrets as private files in `<config dir>/secrets/`
  (on Windows with a protected DACL; a pre-created, junctioned or broadly
  readable secrets folder is refused; on macOS an extended ACL the folder
  inherited as it was created is removed, and one an existing folder carries
  is refused when an entry grants anyone but its owner access, inheritable
  entries included: `chmod -N <dir>`; entries that only deny, such as the
  `group:everyone deny delete` macOS puts on home folders, are kept), keeps
  backups of replaced secret files
  (`<name>.username.bak.<stamp>`, `<name>.password.bak.<stamp>`; they hold old
  credentials, so remove them once checked), and as root writes secrets only
  when every directory from `/` to the config's directory is root-owned and
  not group- or other-writable, with no macOS ACL entry that grants another
  account access (the `.deb` and `.pkg` system config qualifies); otherwise
  it refuses and suggests
  `sudo -u <account> udbmcp add-connection ...`.

## Configuration rules

- Unknown fields are rejected. A mapping key given twice is an error, the
  sources of YAML `<<` merges included; a repeated `<<` key is an error too
  (write `<<: [*a, *b]`).
- Connection ids are 1-64 ASCII characters of `[A-Za-z0-9_-]`, not starting
  with `-`; ids that differ only in case are refused, and so are non-string
  YAML keys. `session.application_name` is 1-64 characters of
  `[A-Za-z0-9_.:@-]`.
- There is no write mode. `security.read_only: false`,
  `security.allow_write_operations: true` and a connection's
  `read_only: false` are rejected at load (`read_only=false is not supported
  in v1`).
- Relative paths in the config resolve against the config file's directory,
  not the working directory: `audit_path`, `metadata_cache_path`,
  `http_bearer_token_file`, `username_file`, `password_file`, the `tls`
  files, `options.wallet_password_file` and PostgreSQL `options.passfile`. A
  SQLite `database` (a leading `~` is expanded) and the directory-valued
  Oracle options (`wallet_location`, `tns_admin`, `lib_dir`) are used as
  written, so a relative one follows the server's working directory (`/`
  under the systemd unit): write them absolute. A relative `UDBMCP_HTTP_BEARER_TOKEN_FILE` is relative to the
  service manager's working directory.

## Query safety (details in docs/tools.md)

- Exactly one statement; parser failure is a denial, not approval. An
  unterminated literal, comment or `[identifier]` is a `POLICY_VIOLATION`
  parse denial. Statements over 64 KiB are refused; the pre-parse scans are
  linear, so a 64 KiB statement costs milliseconds. `db_federated_query`
  refuses a statement over 64 KiB, or statements over 256 KiB together,
  before it lexes any of them for their parameters.
- Modifying CTEs inside SELECT are denied (full-AST walk).
- Unknown/dangerous functions and table functions denied; `SELECT INTO`,
  ATTACH, PRAGMA, SET denied.
- Executable comments are denied: MySQL `/*! ... */` and MariaDB
  `/*M! ... */` (`executable comments (/*! ... */, /*M! ... */) are not
  permitted`), as is MariaDB `SET STATEMENT ... FOR`. On MariaDB the session's
  READ ONLY transaction alone is not a write barrier against hidden SQL, since
  a hidden `SET STATEMENT` could lift it; the guard is.
- Comment boundaries: a line comment ended by a bare CR followed by code is
  refused (MySQL, Oracle, Db2, SQLite and ClickHouse continue the comment to
  the LF where the validator would stop at the CR); on MySQL `--` without a
  following space is refused; nested or unterminated block comments are
  refused.
- Sequence access denied (`NEXT VALUE FOR`, Oracle `NEXTVAL`/`CURRVAL`, Db2
  `NEXTVAL FOR`): a read that advances a sequence is a write. T-SQL table
  hints other than NOLOCK, READUNCOMMITTED, READPAST and NOWAIT denied (they
  take or escalate locks), in the legacy form without `WITH` after a table's
  alias too (`FROM t b (TABLOCKX)` is refused: `table hint '<name>' is not
  permitted on a read-only connection ...`). An optimizer hint comment
  (`/*+ ... */`) is inert: its body names no object and calls no function
  (Oracle `INDEX`, `LEADING`, `USE_NL`, MySQL `BKA` are accepted), except the
  MySQL hints that change how the statement runs, `MAX_EXECUTION_TIME`,
  `SET_VAR` and `RESOURCE_GROUP`, which are refused wherever one of those
  words appears in a `/*+ ... */` body, in any letter case, however the rest
  of the body is spelled.
- EXPLAIN/SHOW/DESCRIBE via dedicated per-dialect policies only; the
  validated statement text is what reaches the engine. `db_explain` never runs
  a statement: ANALYZE asked for with `analyze=true`, or written in a
  PostgreSQL, MySQL, ClickHouse or Db2 statement, is `POLICY_VIOLATION` with
  `security.allow_explain_analyze: false` (the default) and
  `VALIDATION_ERROR` with it true; the flag only picks the refusal. Oracle
  and SQL Server have no ANALYZE form and SQLite cannot parse one, so ANALYZE
  written in their statements is `POLICY_VIOLATION` either way.
- Bound parameters via driver facilities (JSON scalars only); identifiers
  validated and quoted by the adapter. On MySQL, ClickHouse (client-side
  binding) and PostgreSQL the driver formats the values into the text with
  Python's `%` operator, which also fills a `%s` inside a string literal or
  a comment, after the guard validated the text. The connectors therefore
  hand the driver exactly the validated statement: only a placeholder in
  code (outside literals, quoted names and comments, as that engine bounds
  them, PostgreSQL `$tag$` quotes and `E'...'` strings and ClickHouse
  heredocs included) takes a value (`sql_guard.bind_text`, at the driver
  boundary; the statement the guard and the audit see is plain SQL). In a
  string literal the DBAPI escape `%%` is one `%`, as it always was
  (`'50%%'`, `DATE_FORMAT(d, '%%Y-%%m')`), and a lone `%` (`LIKE 'a%'`) or
  a placeholder is text; in a quoted name or a comment every `%` arrives as
  written. `%%` in code is `VALIDATION_ERROR` (write the modulo operator as
  one `%`, or `MOD()`), and so is a placeholder glued to a name, a digit or
  a quote (`%ssn`, `%s1`: PostgreSQL's parser and the driver would read it
  differently); put a space or an operator after it. A `:name` placeholder
  straight after an identifier character or a digit is not one (the slice
  `a[1:n]`), and PostgreSQL `ARRAY[%s]` and `ANY(ARRAY[%s])` take values. A
  placeholder count that does not match the values, a `%(name)s` with no
  value, a named value no placeholder uses, or both styles at once is
  `VALIDATION_ERROR` before anything runs. `db_federated_query` hands each
  statement only the named values its own placeholders use (on Oracle
  compared ignoring case, as its driver binds them); a name no statement
  uses is `VALIDATION_ERROR`.
- A name after `IN` without parentheses is refused, since ClickHouse and
  SQLite read it as a table (`x IN t`, `x IN db.t`, and any expression there
  holding a name, such as `x IN tuple(t)`), and so is a string there, which
  SQLite reads as a table name (`x IN 'docs_content'`: `a string after IN
  without parentheses is not permitted ...; write IN ('value', ...)`); on ClickHouse `IN (<single name>)`
  is refused whatever parentheses and aliases wrap the name (`x IN ((t AS
  z))`, `(+(t AS z))`, and the `NOT IN`, `GLOBAL IN` and `GLOBAL NOT IN`
  forms), and so are `{name:Identifier}` parameters. A placeholder or a
  constant other than a string after `IN` is a value and is accepted (ClickHouse's `x IN
  {ids:Array(UInt64)}`, `IN tuple(1, 2)`, `IN ((1 AS z))`, a driver's `IN
  %(p)s`). On every engine an `IN` with nothing after it, and `IN` straight
  after `IN`, are refused: that is how the validator reads ClickHouse's
  function `in(v, t)`, which ClickHouse evaluates as `v IN t`, reading the
  table.
- ClickHouse functions that read the table or dictionary an argument names
  are refused by name (`POLICY_VIOLATION: function '<name>' is not permitted
  on ClickHouse: it names a table or dictionary in its arguments ...`): the
  `in` family (`notIn`, `globalIn`, `nullIn`, `inIgnoreSet`, ...), `joinGet`
  and `joinGetOrNull`, every `dict*` function and `hasColumnInTable`, in
  their snake_case spellings too (`join_get`, `not_in`).
- ClickHouse reads a two-part `a.b` whose qualifier names no table of its
  query as the table `a.b` wherever a table may stand (`in(x, a.b)`), so
  such a column is authorized as a read of that table (default-deny,
  `allowed_schemas`, system schemas, the views below) and listed in
  `referenced_objects`: `SELECT system.one AS x` is refused unless `system`
  is opened. A qualifier binds only to a FROM or JOIN item of its query or
  of an enclosing one; a select alias, a `WITH` value, an `ARRAY JOIN` alias
  or a CTE not in FROM binds nothing. In a CTE body, or a derived table in
  FROM or JOIN, the FROM items of the query that holds it do not bind one
  (`WITH c AS (SELECT system.one AS x) SELECT c.x FROM c, t AS system` reads
  `system.one`); subqueries in expressions, and a scalar `WITH <expr> AS
  name`, still see the enclosing FROM. An `a.b` qualified by an `ARRAY
  JOIN`, select or `WITH` alias is refused under an allowlist or
  default-deny, with the hint to name a tuple's element by its index
  (`a.1`); with neither it is allowed and not reported as a table.
- Server and session variables are refused on every engine (`@@datadir`,
  `@@hostname`, SQL Server's `@@SERVERNAME`: `POLICY_VIOLATION: server and
  session variables (@@name) are not permitted: they read the server's
  configuration and its host (data directory, host name, file paths); the
  server version is reported by db_test_connection`); `version()` stays
  allowed. MySQL user variables are refused too, read or assigned (`@x`,
  `@x := ...`), because one keeps a value on the pooled session from one
  statement to the next, past the masking of the statement that read it.
- On PostgreSQL and Db2 (validated as PostgreSQL), a `U&"..."` identifier is
  refused, because PostgreSQL decodes its Unicode escapes and the validator
  does not (`U&"s\0073n"` names `ssn`); `U&'...'` strings are unaffected.
  Every `@` the validator reads as a parameter is refused there too: the
  prefix absolute-value operator (`@ x`), `@@@` and `^@`, whose operand no
  check would see (write `abs(x)`). `$n` placeholders and the `@>`, `<@`,
  `@@` and `@?` operators stay allowed.
- Oracle database links are refused: any `@` outside a string literal, a
  hint or a double-quoted name (`"T"@lnk`, `t @lnk`, `t/**/@lnk`,
  `col@lnk`, `seq.nextval@lnk`), and anything the validator reads as a
  parameter (`POLICY_VIOLATION: database links / remote-object references
  (@link) are not permitted: ...`, in every tool). `db_query` and
  `db_explain` check this again in the Oracle connector, before any session
  is opened: a statement with an `@` outside literals, quoted names, hints
  and comments, or with an alternative-quoted `q'...'` or `nq'...'` literal
  and an `@` anywhere, or with an `@` in text the tokenizer cannot read, is
  refused (`POLICY_VIOLATION: database links (@link) are not permitted on
  connection ...`).
- Oracle alternative-quoted literals: the guard cannot parse an
  alternative-quoted `q'...'` or `nq'...'` literal, so a statement holding
  one is refused in every tool, `db_validate_query` included, with or
  without an `@` (`POLICY_VIOLATION: statement could not be parsed under the
  'oracle' dialect ...`). Write the string in ordinary quotes, doubling a
  quote inside it (`'it''s'`). The connector's rule above stays behind the
  guard.
- A `WITH` after `UNION`, `INTERSECT` or `EXCEPT` whose query is followed by
  further branches without parentheses is refused on every engine: sqlglot
  applies it to the later branches too, ClickHouse to its own SELECT alone.
  Write `(WITH ... SELECT ...)` as that branch, or the `WITH` ahead of the
  whole statement.
- Names an engine reads as another name are refused, because every check
  compares the name as written: on SQL Server any code token (identifier,
  bracketed or quoted name, keyword, number; a string alias included) outside
  printable ASCII, and a quoted name ending in a blank (string literals,
  comments and whole money or binary literals such as `£1` or `0x1F` are
  exempt); on Db2 a delimited name ending in blanks (`"IBMREQD "`, which Db2
  reads as `IBMREQD`); on Oracle an unquoted name containing `ı` or `ſ`
  (`v$ſql` is `V$SQL`; quote it to mean it exactly); on ClickHouse a
  backquoted or double-quoted identifier containing a backslash, whose
  escapes ClickHouse decodes (`` `on\x65` `` reads `one`; double a backquote
  inside backquotes). A SQL Server table or column whose catalog name is not
  ASCII therefore cannot be named in a statement; `SELECT *` and the
  metadata, sample and profile tools still reach it. An empty quoted name
  (`""`, `[]`, ``` `` ```) as a schema, table or column is refused
  (`"".ALL_USERS`, `[].syslogins` read as a bare name the bare-name rules did
  not see), in statements and in the `object_name` of the metadata tools
  (`VALIDATION_ERROR`, each part must be a non-empty name). On SQLite a bare,
  unqualified `""` is accepted: SQLite reads it as the empty string.
- On Oracle, Db2 and PostgreSQL a CTE name outside ASCII (quoted or not),
  and an unquoted table or schema name outside ASCII, are refused
  (`POLICY_VIOLATION: the CTE name ... is not permitted on <engine>: a CTE
  name must be ASCII here ...`, `the unquoted name ... is not permitted as a
  table or schema name ...; quote the exact name as the catalog spells it
  ("<name>"), or use an ASCII name`). Each of these engines folds such a name
  by rules of its own (Oracle by Unicode's, Db2 by its code page,
  PostgreSQL by the locale), so the validator could not tell whether a FROM
  item names a CTE or a table. A quoted table name is read exactly as
  written and stays allowed, as do columns, aliases and literals outside
  ASCII. ASCII names fold as the engine folds them, and a bare FROM item is
  a CTE's only when the folded names are equal.

### SQL Server (T-SQL) specifics

SQL Server needs no separator between statements in a batch, so the guard
refuses what SQL Server would read as the start of another statement:

- an unquoted T-SQL reserved keyword used as an alias (quote it as `[x]`).
  Five reserved words SQL Server accepts as aliases stay allowed: `DISK`,
  `DUMP`, `LOAD`, `PRECISION` and `SECURITYAUDIT`. `FETCH` is accepted only as
  `ORDER BY ... OFFSET n ROWS FETCH {FIRST|NEXT} n ROWS ONLY`. The rule applies
  to T-SQL only; the other connectors send one statement per call;
- C0 control characters other than tab, LF and CR, the zero-width space and
  the byte-order mark, outside literals, quoted identifiers and comments;
- a money literal (any of SQL Server's 34 currency symbols) or binary literal
  (`0x...`) written directly against more text, for example
  `SELECT $1EXEC sp_who`, `SELECT 0x1DELETE FROM t` or `SELECT $1e5` (which
  SQL Server reads as `$1` aliased `e5`), and any unquoted token
  that contains one of the 33 currency symbols other than `$`, anywhere in the
  token (`SELECT DISTINCT€1EXEC sp_who`, `SELECT ALL£1 AS m`). SQL Server ends
  the identifier at the symbol and runs the rest as a separate statement: live
  on SQL Server 2022, `SET SHOWPLAN_ALL` compiles `SELECT DISTINCT€1EXEC
  sp_who` as a SELECT plus an EXECUTE PROC, and a 316,924-statement
  differential over every BMP code point found no other symbol that splits a
  token. The refusal reads `unquoted '<token>' is not permitted: SQL Server
  splits it at a money or binary literal and would run the rest as a separate
  statement; put spaces around the literal, or quote an identifier as
  [<token>]`. `$` inside a token (`a$1`) stays allowed, as SQL Server reads it
  as an identifier character; `SELECT DISTINCT €1 AS m` and `$1 AS m` are
  fine.

The connector adds a backstop, not a control: every query is described first,
rolled back explicitly, and a batch that reports more than one result is
refused as `POLICY_VIOLATION` ("the batch contained more than one statement").
That detection cannot see DML that follows `SET NOCOUNT ON`, nor DDL,
`TRUNCATE`, `WAITFOR` or `COMMIT`; the rollback undoes the transactional ones,
and a `COMMIT` in the batch defeats it. The guard is what prevents smuggled
statements, and a least-privilege login (`db_datareader` plus `SHOWPLAN`) is
what makes one harmless if it ever got through.

### ClickHouse CTEs

A bare FROM item named like a relation CTE counts as a CTE reference only
where ClickHouse binds it to one (checked live on 26.3): anywhere in the query
whose `WITH` declares it, subqueries and the branches of a set operation that
`WITH` heads included; inside a CTE's body, any other CTE of the same `WITH`,
declared before or after it; and the CTE's own name only in the branches
after the first of a `WITH RECURSIVE` body that is a chain of `UNION ALL`.
Names compare case-sensitively, and `WITH <expression> AS name` or `WITH
(subquery) AS name` names a value, never a table. Every other bare name is a
table and gets every table check (the unqualified-name refusal under an
allowlist, default-deny, system schemas, session views), and
`db_validate_query` reports it as `{schema: null, name: <as written>}`. A
refusal then ends `; a CTE of that name does not cover this reference:
ClickHouse reads the table there (...)`. So `WITH RECURSIVE payroll AS
(SELECT * FROM payroll) SELECT * FROM payroll` reads the table `payroll`: it is
refused under default-deny or an allowlist, and runs, reporting `payroll`,
with neither. A CTE that names one declared after it, or a recursion whose
first branch names its own CTE, passes the guard; when the statement reads a
table with masked columns, masking refuses it (`... cannot be checked for
them: ...`), as on SQLite.

Refused on ClickHouse (`POLICY_VIOLATION`), whatever the policy:

- CTEs of one `WITH` that name each other in a cycle, a recursion through a
  second CTE included (`the CTEs ... name each other ...`): write the
  recursion in its own CTE's `WITH RECURSIVE ... UNION ALL` body, and qualify
  a table named like a CTE with its database;
- `WITH RECURSIVE` ahead of a `UNION`, `INTERSECT` or `EXCEPT` when one of its
  CTEs names itself, since ClickHouse gives the branches after the first a
  copy without RECURSIVE: write `WITH RECURSIVE t AS (...) SELECT ... FROM
  (SELECT ... FROM t UNION ALL SELECT ... FROM t)`;
- a `WITH` declaring a relation CTE on a query in parentheses that is the
  first operand of a set operation (`(WITH t AS (...) SELECT ...) UNION ALL
  SELECT ...`), which ClickHouse applies to the later branches too: write the
  `WITH` ahead of the whole set operation;
- a CTE body that reads a name bound outside the body when another CTE of that
  name is declared elsewhere in the statement, because ClickHouse resolves a
  CTE's body where the CTE is used (`the CTE <c> reads '<n>', which the
  statement declares as a CTE elsewhere as well ...`): give the CTEs distinct
  names. This also refuses some harmless shapes.

A `WITH` heading a set operation without a recursive self-reference, and a
parenthesised set operation carrying its own `WITH`, stay accepted.

### Object authorization

- **Schema allowlist.** A connection's `allowed_schemas` limits every tool to
  those schemas. An empty list is NOT deny-all: it means every schema the
  account can see. Under a non-empty allowlist every table in a statement must
  be schema-qualified (database-qualified on MySQL and ClickHouse), in the
  spelling the catalog lists; see `docs/tools.md` for the refusal and its
  suggestion. Entries match catalog names ignoring case, and a schema the
  catalog holds in one spelling is admitted in any case. Where the catalog
  holds an allowed name in several case spellings (PostgreSQL `ocean` and
  `"Ocean"`, Oracle `TRAVEL` and `"travel"`), an entry in `allowed_schemas` or
  `allowed_system_schemas` written in one case is read as an unquoted name:
  it admits the spelling the engine folds it to (upper case on Oracle and Db2,
  lower case on PostgreSQL, as written elsewhere), or its exact spelling when
  the catalog lacks the folded one. An entry mixing upper and lower case
  (`Ocean`), or one listed beside its folded spelling, admits its exact
  spelling first. So Oracle `[travel]` admits `TRAVEL`, PostgreSQL `[OCEAN]`
  admits `ocean` and `[Ocean]` admits `"Ocean"`; to admit both spellings, list
  both (`[TRAVEL, travel]`, `[ocean, Ocean]`). A quoted namesake written in
  one case (Oracle `"travel"`) cannot be admitted alone while the folded
  schema exists. The other spellings are left out of `db_list_schemas` and
  the table listing, and refused (`AUTHORIZATION_DENIED ... schema names that
  differ only in case name different schemas here`, with a hint in the
  admitted spelling) in statements and in the schema arguments of the
  listing, metadata, sample and profile tools (`docs/tools.md`, Schema
  arguments). Called without a schema, `db_list_views`, `db_list_synonyms`
  and `db_list_routines` leave a namesake's objects out; a declared foreign
  key into a namesake (`db_get_table`, `db_get_relationships`, the catalog
  tools) names its target `<not permitted>`, as one into a schema outside the
  allowlist, and `db_infer_relationships` leaves such a target out. The
  spellings are compared over the whole schema list (`list_schemas`, as
  `db_list_schemas` reads it) as well as the listing, so a namesake that holds
  nothing listed (empty, only foreign tables or partitioned parents) is still
  refused, and a permitted schema that holds nothing listed is not taken for
  a namesake. That list is read only for a connection with an allowlist, once
  per 300 s, and kept in process memory (not in the metadata cache file); if
  it cannot be read, the tool call fails.
- **Default-deny (`default_deny_objects: true`, the default).** Every object a
  statement reads must resolve in the policy-scoped catalog listing;
  unresolvable is denied. On PostgreSQL, Oracle, Db2 and ClickHouse a name
  matches a listed object only as the catalog spells it, a quoted name as
  written and an unquoted one folded as the engine folds it; any other
  spelling is refused (`POLICY_VIOLATION: table X is not spelled as the
  catalog lists it ... write <catalog spelling>`), since the engine would
  read another object, or none (ClickHouse's `information_schema` is
  accepted in either case). On SQL Server a case variant is accepted only
  when the database collation ignores case (the server asks the database).
  On PostgreSQL, Oracle, SQL Server and Db2 a bare name matches only when its
  listed table is in the first schema the session looks bare names up in
  (PostgreSQL: for a `pg_` name `pg_catalog` unless `current_schemas(false)`
  names it, then the path's order; for any other name the first schema of
  the path other than `pg_catalog`. Oracle `CURRENT_SCHEMA`, SQL Server
  `SCHEMA_NAME()`, Db2 `CURRENT SCHEMA`), because elsewhere the engine
  reads that schema's object, a synonym or a dictionary view of the name
  first: `POLICY_VIOLATION: the bare name <t> is the listed <s>.<t> only
  where the session looks bare names up in <s> first; ... a bare name is
  looked up in <schema> first (...) ...; write <s>.<t>`. How a session binds
  names is read from a new session and kept in process memory for 300 s; a
  failed read fails the tool call. MySQL is unchanged.
- **`default_deny_objects: false`.** With a non-empty allowlist, unqualified
  names in the metadata and sample tools still resolve only to permitted
  tables and views (ambiguity and case-only twins are refused), and
  statements still need qualified names. On Oracle, SQL Server and Db2 every
  table name a statement or tool reads is looked up in the catalog as a
  synonym (Db2: an alias), by the name the engine looks up (a quoted name as
  written, an unquoted one folded; a bare one as a synonym of any schema),
  unless it is a qualified name the listing holds exactly so, and each object
  its chain names goes through the checks a written reference gets: the
  views below first, then `allowed_schemas`, the system-schema rule and SQL
  Server's compatibility views. A target over an Oracle database link, or in
  another SQL Server database or linked server, is refused as reading
  outside this connection's database. The refusal reads `'<name>' is a
  synonym that reads '<target>', refused as that is: <that refusal>`. A
  failed lookup fails the tool. So without an allowlist, a bare Oracle
  `ALL_USERS` (a PUBLIC synonym of a `SYS` view) is refused unless `SYS` is
  opened, while bare `DUAL` still reads. Only PostgreSQL still binds a bare
  name the policy does not see: a bare dictionary name such as `pg_roles`
  binds to `pg_catalog`, which PostgreSQL searches ahead of the
  `search_path` schemas unless `search_path` names it, and stays readable
  although `pg_catalog` is closed (the system-schema check sees only the
  objects the policy lists, and it lists a system schema's objects only
  where that schema is opened). Of those names only the views no statement
  may read (below) are refused. Keep
  `default_deny_objects: true`, or set `allowed_schemas`, to close that.
- **SQL Server compatibility views.** SQL Server reads the 38 compatibility
  views (`syslogins`, `sysobjects`, `syscomments`, `sysusers`, ...) under
  `dbo` and bare ahead of any other object of the name, so in every tool
  they are authorized as `sys.<name>`: refused as a system schema unless
  `sys` is opened, and the credential ones always. A `dbo` user table with
  one of those names, which the engine never reads by that name, is left out
  of the table listing and the tools built on it (catalog tools, value
  search, relationship inference).
- **System schemas.** A system schema is readable only when
  `security.allowed_system_schemas`, or the connection's `allowed_schemas`,
  names it; this applies whatever `allowed_schemas` is. `db_list_tables`,
  `db_search_metadata` and the catalog tools list only the system schemas it
  opens on every engine; `db_list_views`, `db_list_synonyms` and
  `db_list_routines` apply it only under an allowlist (without one,
  PostgreSQL, Oracle and Db2 list dictionary objects there too, by name
  only, but never one of the views below that no statement may read;
  `docs/tools.md`). The default is `[information_schema]`,
  which lists and opens `information_schema` on PostgreSQL and MySQL, SQL
  Server's `INFORMATION_SCHEMA` views and ClickHouse's `INFORMATION_SCHEMA` and
  `information_schema`. The lists (`src/universal_db_mcp/discovery/system_schemas.py`):
  PostgreSQL `pg_catalog`, `information_schema`, `pg_toast`; MySQL `mysql`,
  `sys`, `performance_schema`, `information_schema`; SQL Server `sys`,
  `information_schema` and the fixed database roles; Db2 `SYSIBM`, `SYSCAT`,
  `SYSSTAT`, `SYSPROC`, `SYSIBMADM`, `SYSFUN`, `SYSTOOLS`, `NULLID`, `SQLJ`,
  `SYSPUBLIC`, `SYSIBMINTERNAL`, `SYSIBMTS`; ClickHouse `system`,
  `information_schema`; Oracle every Oracle-maintained owner through 23ai plus
  the 9i-11g owners (`WKSYS`, `WK_TEST`, `WKPROXY`, `DMSYS`, `TSMSYS`, `ODM`,
  `ODM_MTR`, `MTSSYS`, ..., and the 9i JServer and trace owners
  `AURORA$JIS$UTILITY$`, `AURORA$ORB$UNAUTHENTICATED`, `OSE$HTTP$ADMIN`,
  `TRACESVR`), `APEX_PUBLIC_USER`, `FLOWS_FILES`, and every owner matching
  `APEX_nnnnnn` or `FLOWS_nnnnnn` (six digits). `PDBADMIN` is skipped by
  discovery but not refused. A site with an application schema of one of
  these names must list it in `allowed_schemas`; a site that reads APEX
  metadata names the exact owner (for example `APEX_050000`). A schema is
  recognised as a system schema in any spelling that folds to a listed name
  (full-width letters, `ı`, marks and surrounding blanks included), while
  `allowed_system_schemas` opens only the spelling written, so such a
  variant stays refused. `allowed_system_schemas` is one list for every
  engine: naming `sys` to open SQL Server's catalog views or Oracle's `SYS`
  dictionary also opens MySQL's `sys` schema, whose `statement_analysis` and
  `statements_with_*` views show normalized statement digests (literals
  replaced by `?`), not other sessions' literal SQL.
- **Dummy tables (owner decision).** Oracle `DUAL` and Db2
  `SYSIBM.SYSDUMMY1` to `SYSDUMMY4` hold no data and are readable in
  statements on every connection, whatever the allowlists and
  `default_deny_objects` say. Oracle accepts `DUAL`, `dual`, `"DUAL"`,
  `SYS.DUAL`, `sys.dual` and `"SYS"."DUAL"`; Db2 `SYSIBM.SYSDUMMYn` unquoted
  in any case or quoted in upper case. Nothing else of `SYS` or `SYSIBM`
  opens, and a quoted lower-case `"sys".DUAL` or `"dual"`, `SYSIBM.SYSDUMMY5`,
  `SYS.DUAL` on another engine and `DUAL@link` stay refused. A bare Db2
  `SYSDUMMY1` is `CURRENT SCHEMA`'s: write `SYSIBM.SYSDUMMY1` (under an
  allowlist the bare name is refused as unqualified). The guard takes a bare
  Oracle `DUAL` for the PUBLIC synonym to `SYS.DUAL`, but Oracle reads an
  object called `DUAL` in the session's current schema first, so the Oracle
  connector checks that session before it runs such a statement
  (`docs/session-safety.md`); a PUBLIC synonym `DUAL` that an administrator
  repointed elsewhere is not checked. In the metadata, sample and profile
  tools these tables follow the listing (`docs/tools.md`, Statements).
- **Views of other sessions' SQL.** Some dictionary views show other
  sessions' statements as they were sent (text with its literals, bind
  values, plan predicates, the error text a failed statement quotes) or the
  values those sessions hold (locked keys, user variables), and would hand
  back a masked column's value from someone else's `WHERE` clause or
  `INSERT`. They are refused on every connection, whatever
  `allowed_system_schemas` or `allowed_schemas` opens: `POLICY_VIOLATION:
  '<name>' shows other sessions' SQL or the values it carries (statement text,
  literals, bind values, error text, locked keys), which would hand back
  values column masking hides: it is not readable on any connection, whatever
  security.allowed_system_schemas allows`. The check comes before any other
  table verdict in every statement tool and in `SHOW`/`DESCRIBE` validation,
  and applies to the metadata, sample and profile tools. The views are left
  out of the table listing that `db_list_tables`, `db_search_metadata`, the
  catalog tools, value search and relationship inference share, on
  connections with or without an allowlist and wherever the schema is
  opened. The view and synonym listings leave them out too: `db_list_views`
  on PostgreSQL, Oracle and Db2 (MySQL's and SQL Server's view listings
  never reach a system schema, and ClickHouse lists views through its table
  listing), and `db_list_synonyms` on
  Oracle and Db2, which also leave out a synonym or alias whose own name,
  target, or any synonym or alias further along its chain is such a view
  (Oracle's `V$SQL` through its PUBLIC synonym). Names match in any spelling an engine
  reads as the listed one (`information_schema.proceſſlist` too):
  - MySQL/MariaDB: `information_schema` `PROCESSLIST`, `INNODB_TRX`,
    `INNODB_LOCKS`, `QUERY_CACHE_INFO`, `INNODB_FT_INDEX_CACHE` and
    `INNODB_FT_INDEX_TABLE` (the indexed words of any table);
    `performance_schema` `processlist`, `threads`, `events_statements_*`,
    `prepared_statements_instances`, `data_locks`,
    `user_variables_by_thread` and `error_log`; `sys` `processlist`,
    `session`, `innodb_lock_waits` and `schema_table_lock_waits` (and their
    `x$` twins); `mysql.general_log` and `mysql.slow_log`.
  - PostgreSQL: `pg_stat_activity`, bare or in `pg_catalog`;
    `pg_stat_statements`, `pg_stat_monitor`, `pg_qualstats*`,
    `pg_show_plans` (every running statement's plan with its literals) and
    `pg_store_plans*` in any schema.
  - ClickHouse: `system.processes`, `query_cache`, `asynchronous_inserts`,
    `mutations`, `distributed_ddl_queue`, `errors` and `zookeeper` (a
    replicated table's queue entries hold block ids and mutation SQL), and
    the logs `query_log`, `query_thread_log`, `query_views_log`, `text_log`,
    `error_log`, `opentelemetry_span_log`, `asynchronous_insert_log`,
    `crash_log` and `zookeeper_log`, with or without the `_N` suffix an
    upgrade leaves.
  - Oracle, in any schema or bare: the `V$`, `GV$`, `V_$` and `GV_$`
    spellings of `SESSION`, `SQL`, `SQLAREA`, `SQLAREA_PLAN_HASH`, `SQLTEXT`,
    `SQLTEXT_WITH_NEWLINES`, `SQLSTATS`, `SQLSTATS_PLAN_HASH`, `OPEN_CURSOR`,
    `SQL_MONITOR`, `ALL_SQL_MONITOR`, `RECENT_SQL_MONITOR`,
    `SQL_PLAN_MONITOR`, `ALL_SQL_PLAN_MONITOR`, `SQL_BIND_CAPTURE`,
    `ALL_SQL_BIND_CAPTURE`, `SQL_PLAN`, `SQL_PLAN_STATISTICS_ALL`,
    `SQL_HISTORY`, `ADVISOR_CURRENT_SQLPLAN`, `DB_OBJECT_CACHE`,
    `SQL_SHARED_MEMORY`, `UNIFIED_AUDIT_TRAIL`, `XML_AUDIT_TRAIL`,
    `LOGMNR_CONTENTS`, `DIAG_TRACE_FILE_CONTENTS`, `DIAG_ALERT_EXT` (the
    alert log; ORA- messages quote the failing statement),
    `RESULT_CACHE_OBJECTS` (the cached statements), `DIAG_SQL_TRACE_RECORDS`
    and `DIAG_OPT_TRACE_RECORDS`; `FLASHBACK_TRANSACTION_QUERY`;
    `DBA_HIST_`/`CDB_HIST_` `SQLTEXT`, `SQLBIND`, `SQL_PLAN`, `SQLSTAT`,
    `REPORTS` and `REPORTS_DETAILS`; `AWR_ROOT_`/`AWR_PDB_`/`AWR_CDB_`
    `SQLTEXT`, `SQLBIND`, `SQL_PLAN` and `SQLSTAT`; `UNIFIED_AUDIT_TRAIL` and
    `CDB_UNIFIED_AUDIT_TRAIL`; `DBA_`/`CDB_` `FGA_AUDIT_TRAIL`,
    `COMMON_AUDIT_TRAIL`, `SQL_PLAN_BASELINES`, `SQL_PROFILES`, `SQL_PATCHES`
    and `SQL_QUARANTINE`; `DBA_`/`CDB_`/`USER_` `AUDIT_TRAIL`,
    `AUDIT_OBJECT`, `AUDIT_STATEMENT`, `AUDIT_EXISTS`, `SQLTUNE_BINDS`,
    `SQLTUNE_PLANS`, `ADVISOR_SQLW_STMTS`, `ADVISOR_SQLA_WK_STMTS`,
    `ADVISOR_SQLPLANS`, `ADVISOR_OBJECTS`, `OUTLINES`, `RESUMABLE`,
    `CQ_NOTIFICATION_QUERIES` and `PARALLEL_EXECUTE_TASKS`;
    `DBA_`/`CDB_`/`ALL_`/`USER_` `SQLSET_STATEMENTS`, `SQLSET_BINDS` and
    `SQLSET_PLANS`; and the base tables `AUD$`, `FGA_LOG$`, `AUD$UNIFIED`,
    `SQL$TEXT`, `SQLOBJ$PLAN`, `WRH$_SQLTEXT`, `WRH$_SQLSTAT`,
    `WRH$_SQL_PLAN` and `WRI$_SQLSET_STATEMENTS`, `_BINDS`, `_PLANS` and
    `_PLAN_LINES`. Also `ALL_OUTLINES`, `OL$` and `KU$_OUTLINE_VIEW`; the
    `DBA_`/`CDB_` `AUTOSQLSET_` and `AUTOSTS_` `SQLTEXT`, `SQLPLAN` and
    `SQLSTAT` views and the `SWR$_` tables; the `AWR_BASE_*` and `*_APP_SQLSTAT`
    views, `DBA_HIST_APP_SQLSTAT`, `DBA_AWRAPP_SQLSTAT` and the `WRH$` and
    `WRHS$` SQL tables (`*_BL` included); the SQL tuning set, advisor and
    automatic materialized view `WRI$` tables and `AC_VER$_SQL*`; the
    workload capture and replay views and the `WRR$` tables; the SQL
    Firewall views, `FW$SQL_LOG` and `SQL_LOG$`; the lockdown errors and
    `LOCKDOWN_ERROR$`, the SQL error mitigations and `DIAG$_SQL_ERROR`; the
    SQL translations and `SQLTXL_SQL$`; the WI statements and
    `WI$_STATEMENT`; `DV$ENFORCEMENT_AUDIT`, `DV$CONFIGURATION_AUDIT`,
    `DBA_DV_SIMULATION_LOG` and `SIMULATION_LOG$`; `MGMT_BASELINE_SQL`,
    `MGMT_RESPONSE_BASELINE`, `MVIEW$_ADV_WORKLOAD` and `_PRETTY`; the `V$`
    and `GV$` `ALL_SQL_PLAN`, `MAPPED_SQL`, `SQL_LOCAL_LAST_EXEC`,
    `SQL_REDIRECTION`, `SQL_TESTCASES`, `FLASHBACK_TXN_MODS` and
    `UNIFIED_AUDIT_TRAIL_TBL`; and `FGA_LOG$FOR_EXPORT*`,
    `SQL$TEXT_DATAPUMP*`, `SQLOBJ$AUXDATA*`, `SQLOBJ$PLAN_DATAPUMP*`,
    `PDB_SYNC_STMT$`, `DBMS_PARALLEL_EXECUTE_TASK$` and
    `DATA_PUMP_XPL_TABLE$`. `V$PQ_SESSTAT` and
    `V$ALL_ACTIVE_SESSION_HISTORY` stay readable where `SYS` is opened.
  - SQL Server: `sys.dm_exec_sessions`, `dm_exec_requests`,
    `dm_exec_connections`, `dm_exec_requests_history`,
    `dm_exec_distributed_request_steps`, `dm_exec_distributed_sql_requests`,
    `dm_pdw_exec_requests`, `dm_pdw_request_steps`, `dm_pdw_sql_requests`,
    `query_store_query_text`, `query_store_plan`, `dm_xe_session_targets`,
    and the base tables `plan_persist_query_text` and `plan_persist_plan`
    (admin connection only); `sysprocesses` and `syscacheobjects`, bare or
    in `sys` or `dbo`.
  - Db2: `SYSIBMADM.MON_CURRENT_SQL`, `MON_PKG_CACHE_SUMMARY`,
    `MON_LOCKWAITS`, `LONG_RUNNING_SQL`, `SNAPDYN_SQL`, `SNAPSTMT`,
    `SNAPSUBSECTION`, `TOP_DYNAMIC_SQL` and `QUERY_PREP_COST`;
    `EXPLAIN_STATEMENT`, `EXPLAIN_PREDICATE`, `ADVISE_WORKLOAD` and
    `ADVISE_MQT` in any schema (`db_explain` still reads its own explain
    tables).

  The rest of an opened system schema stays readable
  (`information_schema.TABLES`, `pg_catalog.pg_class`, `system.tables`,
  `SYS.ALL_TABLES`, `SYS.V_$VERSION`, `sys.tables`,
  `SYSIBMADM.ENV_INST_INFO`), and so do these names in a user schema, except
  those matched in any schema above. On MySQL, ClickHouse and
  Db2 a bare `processlist` or `query_log` binds to the connection's database
  or schema and is an ordinary table.
- **Column statistics.** Histograms, most-common values and low and high
  keys are taken from the columns' data, so a view of them hands back what
  masking hides (live: MySQL's `information_schema.COLUMN_STATISTICS`
  returned a masked column's values from its histogram under the default
  `allowed_system_schemas`). They are refused to every tool, whatever
  `allowed_system_schemas` or `allowed_schemas` opens, and left out of the
  same listings as the views above: `POLICY_VIOLATION: '<name>' holds column
  statistics (histogram buckets, most common values, low and high values)
  taken from the columns' data, which would hand back values column masking
  hides: it is not readable on any connection, whatever
  security.allowed_system_schemas allows`. MySQL
  `information_schema.COLUMN_STATISTICS`, `mysql.column_stats` and
  `mysql.column_statistics`; PostgreSQL `pg_stats`, `pg_stats_ext`,
  `pg_stats_ext_exprs`, `pg_statistic` and `pg_statistic_ext_data`, bare or
  in `pg_catalog`; Oracle, bare or under `SYS` or `PUBLIC`, the
  `ALL_`/`DBA_`/`CDB_`/`USER_` `TAB_`, `PART_` and `SUBPART_` `HISTOGRAMS`
  (`ALL_TAB_HISTOGRAMS`, ...)
  and `COL_STATISTICS`, `COL_PENDING_STATS`, `TAB_HISTGRM_PENDING_STATS`
  and `HISTOGRAMS` views, `HISTGRM$`, `HIST_HEAD$`, `FINALHIST$`,
  `WRI$_OPTSTAT_HISTHEAD_HISTORY` and `WRI$_OPTSTAT_HISTGRM_HISTORY`,
  `SQT_TAB_COL_STATISTICS`, the export views `EXU8ASC`, `EXU8ASCU`,
  `EXU10ASC`, `EXU10ASCU`, `EXU8HST` and `EXU8HSTU`, the `KU$_*HISTGRM*` and
  `COL_STATS*_VIEW` views, `V$`/`GV$` `IM_COL_CU` and `IM_IMECOL_CU`, and
  the `DBA_`, `CDB_` and `USER_COMPARISON` views (`SCAN_VALUES` and
  `ROW_DIF` included) with `COMPARISON$`, `COMPARISON_SCAN_VAL$` and
  `COMPARISON_ROW_DIF$`; SQL Server `sys.column_store_segments`,
  `sys.dm_db_stats_histogram` and `sys.syscscolsegments`; Db2 `SYSCAT` and
  `SYSSTAT` `COLDIST` and `COLGROUPDIST`, `SYSSTAT.COLUMNS` and the
  `SYSIBM` statistics tables (`SYSCOLDIST`, `SYSCOLGROUPDIST`,
  `SYSCOLSTATS`, `SYSCOLDISTSTATS`, `SYSKEYTGTDIST`, `SYSKEYTGTDISTSTATS`,
  `SYSKEYTARGETSTATS`). An Oracle user table of one of these names in an
  application schema (`APP.USER_HISTOGRAMS`, `APP.COMPARISON$`) is an
  ordinary table; `"PUBLIC".ALL_HISTOGRAMS` and `SYS.*` stay refused.
- **Column catalogs that carry low and high values.** Oracle's
  `ALL_`/`DBA_`/`CDB_`/`USER_` `TAB_COLUMNS`, `TAB_COLS` and
  `NESTED_TABLE_COLS`, and `COLS` (bare, `SYS` or `PUBLIC`), hold
  `LOW_VALUE` and `HIGH_VALUE`; Db2's `SYSCAT.COLUMNS`,
  `SYSCAT.SYSCOLUMNS_UNION`, `SYSIBM.SYSCOLUMNS` and `SYSIBM.SYSKEYTARGETS`
  hold `HIGH2KEY` and `LOW2KEY`. A statement may read them where the policy
  opens them, but not those columns: one that names `LOW_VALUE`,
  `HIGH_VALUE`, `HIGH2KEY` or `LOW2KEY`, selects `*` (other than inside
  `COUNT`), or gives the view a column list after its alias (which renames
  the columns by position) is refused with `POLICY_VIOLATION: '<name>'
  carries each column's low and high values (...), which would hand back
  values column masking hides: name the columns you need, without those,
  without * and without a column list after its alias (which renames them
  by position)`. `db_sample_table`, `db_profile_table`, `db_get_table`,
  `db_list_columns` and the other tools that read an object whole refuse
  these views whole; they stay listed. The rule also holds for a CTE named
  like one of them (`WITH cols AS (...) SELECT * FROM cols` on Oracle),
  because the engine reads the catalog wherever no CTE in reach declares the
  name; that refusal ends `; a CTE of the name '<name>' does not change this
  ...: give the CTE another name`. `... SELECT n FROM cols` and `SELECT
  COUNT(*) ...` stay allowed. A user table such as `TRAVEL.COLS` is an
  ordinary table. MySQL's `information_schema.STATISTICS` is read the same
  way without its `EXPRESSION` column (a functional index's SQL with its
  literals). A statement that reads one of these views and has a `NATURAL`
  join or a ClickHouse `COLUMNS(...)` matcher anywhere is refused too, since
  those read columns the statement does not name (a `NATURAL` join with a
  derived table of a string column named `EXPRESSION` was a blind equality
  oracle on another schema's index literals): `... this statement shape
  cannot be checked for those columns: it has a NATURAL join ...; select the
  columns you need explicitly and join with ON (or USING with named
  columns)`.
- **Stored credentials.** Views and tables of password hashes, or of the
  passwords and connection details a database keeps for other servers, are
  refused to every tool whatever `allowed_system_schemas` or
  `allowed_schemas` opens, and left out of the same listings as the views
  above: `POLICY_VIOLATION: '<name>' holds stored credentials
  (password hashes, or the passwords and connection details the database
  keeps for other servers), which are not catalog metadata: it is not
  readable on any connection, whatever security.allowed_system_schemas
  allows`. Under the default `[information_schema]` that includes
  PostgreSQL's `information_schema.user_mapping_options`,
  `foreign_server_options`, `foreign_data_wrapper_options`,
  `foreign_table_options`, `column_options` and their `_pg_*` base views,
  and `pg_user_mappings`, `pg_foreign_server`, `pg_foreign_data_wrapper`,
  `pg_foreign_table`, `pg_authid`, `pg_shadow`, `pg_subscription` and
  `pg_hba_file_rules` (bare or in `pg_catalog`); MySQL `mysql.user`,
  `global_priv`, `password_history`, `servers` and `slave_master_info`, and
  `performance_schema.replication_connection_configuration`; Oracle `USER$`,
  `LINK$`, `DEFAULT_PWD$`, the credential and verifier tables, the
  `*_DB_LINKS` views and `V$`/`GV$DATABASE_LINK`; SQL Server
  `sys.sql_logins`, `servers`, `linked_logins`, `remote_logins` and their
  base tables, and `sysservers` and `sysoledbusers` bare, in `sys` or in
  `dbo`; Db2's user, server and wrapper option catalogs; ClickHouse
  `system.named_collections`. Some of these were refused before as a closed
  system schema (`AUTHORIZATION_DENIED`, for example Oracle `SYS.USER$`,
  MySQL `mysql.user`, SQL Server `sys.sql_logins`) and are now refused
  earlier as credentials. `information_schema.foreign_tables` stays
  readable; residual: `pg_attribute.attfdwoptions` is readable once
  `pg_catalog` is opened.
- **Object definitions.** The `information_schema` views that carry other
  objects' SQL and literals (view and routine bodies, trigger statements,
  event bodies, check clauses, the DEFAULT expressions of columns,
  parameters, attributes and domains, a masked column's default literal
  among them) hand back the definitions of every schema the account sees,
  allowlisted or not. They are refused to every tool and left out of the
  same listings as the views above: `POLICY_VIOLATION: '<name>' carries the
  definitions of every schema's objects (...), which would hand back values
  column masking hides: it is not readable on any connection;
  db_list_columns and db_list_views describe the objects this connection may
  read`. MySQL `information_schema` `VIEWS`, `ROUTINES`, `COLUMNS`,
  `TRIGGERS`, `EVENTS`, `CHECK_CONSTRAINTS`, `INNODB_COLUMNS`, and MySQL 9's
  `LIBRARIES` and `JSON_DUALITY_VIEW_TABLES`; PostgreSQL `VIEWS`,
  `ROUTINES`, `COLUMNS`, `TRIGGERS`, `CHECK_CONSTRAINTS`, `PARAMETERS`,
  `ATTRIBUTES` and `DOMAINS`; ClickHouse `VIEWS` and `COLUMNS` (either
  spelling of `information_schema`); SQL Server `VIEWS`, `ROUTINES`,
  `ROUTINE_COLUMNS`, `COLUMNS`, `CHECK_CONSTRAINTS` and `DOMAINS`. The views
  that hold names only (`TABLES`, `SCHEMATA`, `KEY_COLUMN_USAGE`, ...) stay
  readable. `information_schema.STATISTICS` on MySQL and ClickHouse lists
  the indexes, and its `EXPRESSION` holds a functional index's SQL with its
  literals: it is read like the column catalogs above, without that column
  (naming `EXPRESSION`, `*` outside `COUNT` or a column list after the alias
  is refused, and the tools that read an object whole refuse it).
- **Known gap (pending an owner decision).** Under the default
  `[information_schema]`, `db_query` can read the names-only
  `information_schema` views (`TABLES`, `SCHEMATA`, `KEY_COLUMN_USAGE`, ...)
  about schemas outside a connection's `allowed_schemas` (names of tables and
  columns, not their data or definitions), although the metadata tools
  refuse those schemas, and `information_schema.PARTITIONS` (a partition's
  bounds). The credential and definition views above stay refused there.
  Remove `information_schema` from `allowed_system_schemas` where that
  matters.
- **SQLite.** Statements and the metadata tools reach only the tables and views
  `db_list_tables` lists. SQLite's own catalog (`sqlite_schema` and every other
  `sqlite_*` table), which holds the full DDL including sensitive DEFAULT
  literals, is never listed and never readable (`POLICY_VIOLATION` for
  statements, `AUTHORIZATION_DENIED` for the metadata and sample tools),
  whatever `default_deny_objects` says; so are SQLite's eponymous virtual
  tables (`pragma_*`, `dbstat`, `json_each`), which expose DEFAULT literals and
  the database file path. The internal (shadow) tables of FTS3/4/5 and
  R*Tree indexes hold the indexed values under generic column names (`c0`,
  `c1ssn`), where masking by name cannot apply: they are not listed, have no
  columns or detail, and a statement that reads one (a `FROM` or `JOIN`
  item, as a name, a quoted string or a quoted identifier, its quote
  characters doubled or not (`FROM 'notes''s_content'`), in a subquery
  too, or the table of `x IN table`) is refused (`QUERY_ERROR: '<name>' is
  an internal table of a full-text or R*Tree index ...`); query the index's
  own table. A shadow table is one SQLite marks so, or, where the build
  lacks the virtual table's module, a table named `<virtual table>_<suffix>`
  with a suffix of that module (an unknown module keeps every such name
  back; the virtual table's definition is read with its comments skipped,
  so a comment between its name and `USING` hides no module). Other tables are ordinary, whatever their names, and a literal,
  alias or column of a shadow table's name refuses nothing; a statement
  that cannot be parsed has every word with a `_` checked as a table.
  Residual: a view the database owner creates over a shadow table is an
  ordinary view and readable.
- `SHOW`/`DESCRIBE` are validated by `db_validate_query` on MySQL and
  ClickHouse under the same allowlist, qualification, schema-spelling and
  default-deny rules (`SHOW TABLES FROM <db>` included), and never executed
  by `db_query`.

## Masking

Masking replaces the values of columns whose names match
`security.mask_columns` (built-in patterns plus your additions) with
`<masked>`, or omits them (`mask_action: omit`). When a statement reads a
table with such a column (or one whose columns the catalog does not list),
each output value is mapped to its source columns by position, so aliases,
UNION branches, CTE and derived column lists, joins and subqueries do not
unmask a column. Only statement shapes the analysis fully understands are
accepted; every other one is refused before it runs (`POLICY_VIOLATION:
this statement reads a table with masked columns, and its shape cannot be
checked for them: <construct>. ...`), and a result whose columns are not the
ones the analysis placed returns no rows (owner decision 2026-10-03: refuse
what cannot be proven, instead of tracing each exotic shape). A name outside
ASCII or with blanks around it is also matched in its NFKC form, stripped
(`ＭＲＮ` and `MRN ` as `MRN`). `docs/tools.md` (Masking) lists the accepted
shapes and the refused constructs.

Plans can carry values too. MySQL reads const tables while it plans and
prints their values into TREE and JSON plans, so `db_explain` withholds such a
plan (`POLICY_VIOLATION: this plan is not returned ...`) when the statement
names a column, alias, table or `USING` name the mask patterns match, selects
a `*` other than `COUNT(*)`'s, or joins `NATURAL`; `FORMAT=TRADITIONAL` plans
print no values and are always returned (`docs/tools.md`, `db_explain`).

**Limitation (owner decision):** masking protects projected values only. A
`WHERE`, `ORDER BY`, `GROUP BY` or `JOIN` condition on a masked column is not
masked and can still reveal its values by inference. Masking is a heuristic
second line, never the security boundary: for columns that must stay secret,
use column-level grants, or a view without them, for the connection's login.
Driver error text is sanitized so an error cannot echo a masked value (see
`docs/tools.md`, Error text).

## Cancellation honesty

Engines with out-of-band cancel report `server_side_cancel` as `supported`
only where the driver provides it and it is verified: SQLite `interrupt()`,
PostgreSQL (`cancel_safe`, libpq 17 or later; with an older libpq no cancel is
sent and the server's `statement_timeout` ends the query), Oracle
`connection.cancel()`, ClickHouse `KILL QUERY`. MySQL (`KILL CONNECTION`
from a second connection, which ends the query's session whatever it is
doing, so a cancel that finds it between two statements is not lost) and
SQL Server (`Cursor.cancel()`, SQLCancel) are `unverified`. A MySQL cancel
that comes before the session's id is known is remembered and the run stops
before its first statement; a PostgreSQL run that was cancelled stops
before its next `FETCH`. Db2 has no cancel; a query's own timeout is its CLI
`QUERYTIMEOUT`, so the server stops it at that deadline. SQLite's cancel
interrupts every open handle of the connector, and again every 20 ms until
they are all closed, because `interrupt()` reaches only a statement already
running; it also sets a flag that each handle's opening and every step of
the query check. So a deadline that fires while the statement is being
described or rewritten stops it before it starts, and a connector once
cancelled refuses its later calls (the executor discards it); metadata calls
are interrupted the same way. There is no progress handler: one called into
Python every few thousand steps of every statement. On SQL Server
and Oracle a deadline that fires before the statement starts (while it
connects or is described) stops it before it is sent. On a timeout the
connection is discarded and the tool output says whether the query may
continue server-side. The executor never reuses a poisoned connection.

## Audit

Every tool call leaves a record: caller identity, connection id, action,
timing, row count, outcome and error category, SQL fingerprint (literals
removed). Raw SQL text, parameters, and rows are stored only when explicitly
enabled (`audit_sql_text`, `audit_parameter_values`, `audit_result_rows`; off
by default).

- **Where.** `application.audit_path`. When a config file leaves it unset, the
  default is the platform state directory, never "off": a config in
  `/etc/universal-db-mcp` audits to `/var/log/universal-db-mcp/audit.jsonl`,
  the Windows machine-wide config in `%ProgramData%\UniversalDB MCP` audits to
  `%ProgramData%\UniversalDB MCP\logs\audit.jsonl`, and any other config to
  `~/.universal-db-mcp/audit.jsonl` (directory created 0700). A config reached
  through a symlink to or from the system directory counts as the system
  config, and on macOS and Windows the directory is matched ignoring case
  (`/ETC/Universal-DB-MCP/config.yaml` is the system config there). The load
  fails with `application.audit_path is not set and the per-user default
  cannot be derived (...)` when there is no usable home (none, `HOME` empty
  or `/`, a drive root, or relative): set `application.audit_path`. `serve` prints one stderr line naming the default
  it chose, and doctor names it too.
- **Outcome.** `allow`, `deny`, `error` or `cancelled`, following the error
  category: `error` for `CONNECTION_ERROR`, `QUERY_ERROR`, `INTERNAL_ERROR`
  and `TIMEOUT` (the executor's deadline or the engine's statement ceiling);
  `deny` for `POLICY_VIOLATION`, `AUTHORIZATION_DENIED`, `VALIDATION_ERROR`,
  `LIMIT_EXCEEDED`, `CONFIG_ERROR`, `CAPABILITY_UNSUPPORTED` and
  `DRIVER_MISSING`. A connector's own refusal is audited as `deny`.
- **One record per call, one per statement sent.** A statement counts as
  sent once the executor's worker thread has begun its driver call (a worker
  that started and then failed to connect included); `db_test_connection`'s
  health check, `db_explain`'s EXPLAIN and the value-search, sample and
  profile statements count the same way. Every statement that was sent has
  its own `<tool>:statement` record (same request id, its connection and
  fingerprint), written in full whatever its outcome and never coalesced:
  `db_query`, `db_federated_query`, `db_federated_join`, `db_search_values`
  (whose record carries `connection_ids`), `db_sample_table`,
  `db_profile_table` and `db_review_schema`. A statement cancelled while its
  driver call ran writes one with outcome `cancelled`; in a tool that runs
  several statements, one cancelled before it was sent writes one too
  (`cancelled`, no text). A call that failed (`deny` or `error`) before it
  sent anything to a database writes ONE record, coalesced below: an unknown
  connection id, invalid parameters, a guard refusal, the executor's
  `LIMIT_EXCEEDED` and breaker refusals, the SDK's unknown-tool and
  invalid-argument refusals. For `db_query` that is the `db_query` record,
  with no `db_query:statement` record for a statement that never ran. A
  catalog read that decided a refusal does not count as sending, and a
  metadata call that failed (a `CONNECTION_ERROR` from `db_list_tables`)
  carries no statement and is coalesced by its exact kind even when its
  catalog read reached the database. Allowed and cancelled calls are always
  written in full. Statement records are fail-closed too.
- **Coalescing refusals.** Refusals go through `AuditLog.record_refusal`,
  grouped by kind: exact repeats of (caller, action, outcome, category,
  connection id, SQL fingerprint), where every unknown tool name counts as
  the action `<unknown tool>`. In each 10 s window the log writes in full
  the first 10 of each kind, and at most 64 full records across all kinds;
  the rest are counted into one `tool_call_summary` record per kind: `{ts,
  event: "tool_call_summary", caller, caller_uid (POSIX), action, outcome,
  category, count, first_ts, last_ts, connection_ids, sql_fingerprints}`
  (up to 8 distinct ids and fingerprints; `sql_fingerprints` omitted when
  there is none). At most 64 kinds are tracked per window; the others share
  the action `<other kinds>` with a null category, in one summary for each
  outcome coalesced (`deny` and `error`), so a flood spread over every kind
  still writes at most 64 full records and 66 summaries per window. The
  caller gets its refusal every time, and
  `db_get_query_history` still lists every call. Summaries are written when
  their window closes (a daemon timer), with the next record if that comes
  first, and at normal interpreter exit. A process ended by a signal loses
  the counts of the window still open; that includes the HTTP server on
  SIGTERM, since uvicorn re-raises the signal after its shutdown. A write
  of summaries alone never creates a missing audit directory, and when it
  fails it keeps them for the next record: it raises nothing and adds
  nothing to `dropped_records`. A refusal whose full record cannot be
  written fails the call closed, as before, and does not use up its kind's
  allowance, so under fail-closed every such call keeps being refused while
  the log is broken; a refusal that is only counted needs no write.
- **SQL text (`audit_sql_text: true`).** A statement's `sql_text` (redacted)
  is kept only in a record of a statement that was sent, whatever its
  outcome. A statement never sent, every `db_validate_query` call and every
  refusal before execution included, leaves no `sql_text` and no
  `sql_text_truncated`: its record carries `sql_fingerprint`, `sql_len` and
  `sql_sha256` (the SHA-256 of the whole unredacted statement). `db_query`
  keeps its text once: `db_query:statement` holds `sql_text`, and the
  `db_query` record (same request id) carries `sql_fingerprint` and
  `sql_len`, with neither `sql_text` nor `sql_sha256`. `db_explain`'s one
  record keeps the text whenever EXPLAIN was sent, MySQL's TREE/JSON plan
  refusal included. A record that keeps its text carries `sql_sha256` only
  for a statement over 64 KiB, as before. The text written is capped per
  window: every record keeps the head and the tail of its `sql_text`, 1024
  bytes each as serialized JSON, and a text of 2 KiB or less (or only a
  little longer) is written whole; beyond those ends, the records of one
  10 s window share 1 MiB of SQL text (charged on the serialized line, so
  non-ASCII text costs its escaped size, and refunded when the write fails,
  never from a later window). Past that budget, or where the whole line
  would exceed 128 KiB, a record keeps `sql_text` (the head), adds
  `sql_text_tail` and `sql_text_omitted`, `{"reason": "per-window text
  budget spent" | "longer than one record holds (128 KiB)", "chars":
  <characters left out>, "sha256": ..., "len": ...}` (the digest and length
  of the whole redacted text), and keeps the `sql_text_truncated`, `sql_sha256` and
  `sql_len` it had. A text cut for the 128 KiB line is charged nothing. The trade-off: once the budget is spent each statement record still
  carries up to about 2 KiB of text ends and a marker of about 170 bytes.
  With `audit_sql_text` off nothing changes: the fingerprint, plus `sql_len`
  over 64 KiB.
- **Caller.** The OS account of the effective UID (Windows: the process
  token's `DOMAIN\name`), never `USER`/`LOGNAME`, falling back to `uid:<n>`;
  POSIX records also carry `caller_uid`.
- **Bounded fields.** A connection id longer than 64 characters that is not
  configured is recorded as `<unknown>` with `connection_id_sha256` and
  `connection_id_len`. Oversized SQL is fingerprinted as its 64 KiB prefix with
  `sql_len`. No record exceeds 128 KiB: longer string values other than the
  SQL text become `{"sha256", "len"}` markers. Warnings are recorded as
  returned (driver-derived ones are already sanitized).
- **Refused before the tool runs.** Calls the MCP SDK refuses (an unknown
  tool, invalid arguments, a list over its maximum length) are audited as
  `deny`/`VALIDATION_ERROR` with the action (up to 128 characters), `reason`,
  `arguments_sha256` and `invalid_arguments`, and coalesced like every other
  refusal; argument values are never recorded.
- **Stopping a stdio server.** On SIGTERM, in-flight calls are cancelled and
  audited as `cancelled`, and the process exits 0 about 3 s later (the
  executor's 2 s cancel-hook budget plus 1 s to write the `cancelled`
  records, so a blocked hook no longer loses them) even when
  stdin stays open; once the handler has run, a second SIGTERM ends it at
  once. The SIGTERM handler also arms a 5 s kernel alarm (`SIGALRM`), which
  ends the process when a cancel hook this SIGTERM fired blocks while
  holding the interpreter. A driver call, or a cancel hook fired earlier by
  a deadline or a client cancel, that holds the interpreter when SIGTERM
  arrives keeps the handler from running until it returns, so neither the
  alarm nor a second SIGTERM stops the process meanwhile; the supervisor's
  SIGKILL (systemd, launchd, `docker stop`, the MCP client) is then the
  backstop.
- **Fail closed.** `audit_fail_closed: true` (default) refuses the call with
  `CONFIG_ERROR: audit log write to '<path>' failed and
  application.audit_fail_closed=true; operation refused (...)` when its record
  cannot be written. With `false`, the call goes ahead unaudited, the loss is
  counted in `dropped_records` (shown by `db_list_connections` and
  `db_test_connection`, with a warning) and reported on stderr at most once a
  minute (`... N audit record(s) dropped so far`).
- **Local filesystem, one lock.** Several server processes may share one
  audit path (every stdio client spawns its own server), so rotation and
  append are serialized across processes by an exclusive lock on
  `<audit_path>.lock` (0600, empty, never a symlink; the directory must be
  writable by the server's user). The path must be a plain file on a local
  filesystem with file locking: the log and its lock may not be symlinks or
  hard links. A record waits at most 10 s for the log (its in-process lock,
  then the file lock); after one record gave up, the next ones wait at most
  1 s until one gets the lock again. While another process holds the lock,
  the first refused call (one record) fails after about 10 s with `audit lock
  held by another process for more than 10 s`; the first call whose
  statement ran writes two records, so it fails after about 11 s with `audit
  lock held by another process for more than 1 s, after an earlier record
  gave up waiting 10 s`, the text of every record that waits only the
  shorter wait. Later calls fail after about 1 s (2 s with two records). The
  thread lock's message is worded the same way (`audit log held by another
  thread of this process for more than ...`). On filesystems whose file
  identities are unstable (some network or FUSE mounts) the errors are
  `audit lock file keeps changing (50 reopen attempts)` or `audit file keeps appearing and disappearing (50
  attempts ...)`. Each is an audit write failure: refused when fail-closed,
  dropped when fail-open. A root run (for example `sudo site-check`) against
  the service's audit directory hands the files it creates to the directory's
  owner; prefer `sudo -u <service account> udbmcp site-check`.
- Rotation by size (`audit_max_bytes`, `audit_max_backups`). Rotation first
  moves the log to `<audit_path>.rotating`, then shifts the backups below the
  first free slot down by one (a missing backup takes the shift) and moves
  the staged log to `<audit_path>.1`; the oldest generation is replaced only
  once the log itself has moved. A rotation that fails part-way (a reader
  holding the log open on Windows, `EACCES`, `ENOSPC`) loses no generation
  and is finished by the next record. A log loosened while the server keeps
  it open (`chmod 644`) is set back to 0600 before the next record is
  appended. On macOS the log and its lock are not written (an audit write
  failure, so `audit_fail_closed` applies) while an extended ACL entry lets
  another account read, change, delete or re-permission them (`-rw-------+`
  with `everyone allow read`, or `allow delete`), or while the directory's
  ACL lets another account add, delete or rename files there, rewrite its
  ACL or owner, or carries an inheritable (`file_inherit`) entry that would
  give every new file (each rotation creates one) such a right. A read-only
  directory entry (`list`, `search`, the read rights) is accepted, as mode
  0750 is. The refusal names every path to clear in one command, the
  directory first: `chmod -N <dir> <log> <lock> <backups>`. Doctor reports
  this, for the rotated backups and the directory too, as `audit-path-acl`,
  with the same command.

## Local state files

- **Metadata cache trust.** The cached catalog listings are the guard's
  permitted-object set, so the cache file must be owned by the server's user,
  have no group or other bits, not be a symlink or hard link, and sit in a
  directory owned by that user or root with no group or other write bit
  (sticky directories such as `/tmp` included); on macOS the same ACL rules
  as for the audit log apply to the file, its sidecars and the directory
  (doctor: `metadata-cache-acl`). A cache directory reached through a
  symlink is checked where it leads, and accepted. Otherwise caching is
  disabled with a stderr line (live catalog reads; nothing fails). A check
  that cannot run right now (out of file descriptors or memory: `EMFILE`,
  `ENFILE`, `ENOMEM`, `EINTR`, `EAGAIN`) makes that one lookup a miss and
  the next one checks again; it does not disable the cache (doctor warns:
  re-run). Future-dated entries
  are ignored; lists are cached whole or not at all (up to about 500k objects
  or 64 MiB); SQLite errors while running are cache misses; a non-SQLite file
  at the path still fails startup. Doctor reports `metadata-cache-perms`.
  Entries are keyed on the connection id, the policy fingerprint and the
  connection's target: a 32-hex SHA-256 prefix of its engine type, family,
  host, port, database (a SQLite path resolved as the connector resolves
  it), `username_env`, `username_file`, the resolved username and every
  connection option but `wallet_password`. Pointing an id at another
  database, host, port, login, `tns_alias`, `tns_admin`, `sid`, service or
  `unix_socket`, or sharing one cache file between configs whose targets
  differ, reads a separate entry; entries in the older key form are never
  read again and age out with the TTL.
- **Isolation.** The audit log, its `.lock`, its rotated backups
  `<audit_path>.1..N`, the rotation staging name `<audit_path>.rotating`
  (reserved: no other file may use it), and the metadata cache with its `-wal`, `-shm` and
  `-journal` files must each be separate from every file the server reads:
  secrets, TLS files, the bearer token, SQLite data sources, a PostgreSQL
  `options.passfile`. Paths are compared by realpath (case-folded on macOS and
  Windows) and by inode, so symlinks, hard links and case variants count.
- **Oracle client files.** No state file may be `tnsnames.ora`, `sqlnet.ora`,
  `ldap.ora`, `oraaccess.xml`, `ewallet.pem`, `cwallet.sso` or `ewallet.p12`
  in `options.tns_admin` or `options.wallet_location`; other files there
  are fine (so `TNS_ADMIN=$HOME` with the per-user audit default works). No
  state file may sit directly in `options.lib_dir` or in
  `lib_dir/network/admin`, whatever its name; deeper paths are fine (so
  `lib_dir=$HOME` works with the per-user default). With a full Oracle Client
  (`lib_dir` is `ORACLE_HOME/lib`, `ORACLE_HOME\bin` on Windows), those seven
  client file names are also refused in `lib_dir/../network/admin`. A
  symlink or hard link to one of those files in `tns_admin`,
  `wallet_location` or `lib_dir/../network/admin` counts as that file. In
  `lib_dir` and `lib_dir/network/admin` (the Instant Client's default
  `TNS_ADMIN`) the rule is by directory: a symlink into them is refused,
  but a hard link elsewhere to a file in those two directories is not
  refused at load; on POSIX the audit log and the metadata cache refuse to
  use a file with a second hard link when they open it.

## Transport

- **stdio:** protocol-only stdout; logs to stderr/files; no TCP listener. Not a
  security boundary (see the threat model).
- **HTTP:** Streamable HTTP with bearer-token authentication, loopback bind
  by default, intended to sit behind an internal authenticated reverse proxy
  and never exposed publicly. Per-caller authorization is coarse in v1 (single
  service identity; see `docs/tools.md`, Caller identity).
  - The token file must hold at least 32 characters of UTF-8 (a leading BOM
    is ignored), or `serve` refuses to start with a `CONFIG_ERROR`; generate
    one with `python3 -c 'import secrets; print(secrets.token_hex(32))'`.
  - Before authentication a client can cost little: a complete request head
    must arrive within the header deadline (10 s, `UDBMCP_HTTP_HEADER_TIMEOUT`),
    a head of more than 100 header lines or 16 KiB is answered 431, and the
    token is checked on the request head, so a request without it gets 401
    with `Connection: close` before its body is parsed (what it still sends is
    drained for at most 2 s or 16 MiB). Pre-auth protocol warnings are rate
    limited, with a `suppressed N pre-auth protocol warnings` line.
  - `serve` raises its own open-file soft limit, and the service definitions
    set 65536 descriptors (systemd `LimitNOFILE`, launchd `NumberOfFiles`,
    compose `ulimits: nofile`). There is no connection cap by design.
    **Residual:** an idle connection holds a descriptor until the header
    deadline, so a local client that sustains about (descriptor limit /
    deadline) new connections per second, about 6.5k/s with 65536 and 10 s,
    can still exhaust descriptors. Where the limit cannot be raised (a manual
    start in a restricted shell, a container without the compose ulimits),
    lower the deadline or put a proxy in front. A proxied deployment should set
    nginx `client_header_timeout` and `limit_conn`.
  - `UDBMCP_HTTP_LOG_FILE` sends the listener's log to a size-bounded file
    (5 MiB x 3); ERROR records also go to stderr, so service managers still
    show startup failures such as a port in use. With it set (the macOS
    LaunchDaemon sets it), `serve` first empties its stdout and stderr where
    either is a regular file over 5 MiB, with one link and owned by the
    process's effective account, and writes `universal-db-mcp: emptied this
    file at N bytes (cap 5242880)` there; each ERROR record to such a stderr
    empties it first when it is over 5 MiB. So launchd's `server.log` and
    `server.err.log` stay under 5 MiB plus one record without any root job
    rotating them. Pipes, sockets, terminals, and a file with a second link
    or another owner are only appended to.

## Release integrity

- A release bundle carries `SHA256SUMS` and an Ed25519 signature over it. The
  site's trusted copy of `verify_bundle.py` (in its trust directory) refuses a
  bundle unless the signature verifies against the independently distributed
  release public key (`--pubkey`), every file matches its checksum, and the
  bundle is not an older release than the installed one (`release_seq`;
  `--allow-downgrade` overrides it with a loud warning). It reads each file
  once, never through a link at any path component, and checks the
  signature over exactly the `SHA256SUMS` bytes it parsed. A bundle holding
  a symlink, FIFO, socket, device or Windows junction anywhere is refused
  (`FAIL: not a regular file or directory in the bundle: <rel> ...`), and so
  is one whose `SHA256SUMS` or `SIGNATURE` has a second hard link (copy a
  bundle plainly, never with `cp -al` or `rsync --link-dest`). The
  installers then verify a private, root-only copy of the bundle again and
  use only that copy (`docs/offline-deployment.md`).
- Without `--installed-manifest`, run on the install target (the bundle's
  profile matches this machine and `--allow-platform-mismatch` is not given),
  it compares with this platform's installed release:
  `/opt/universal-db-mcp/manifest.json` on Linux,
  `/usr/local/universal-db-mcp/manifest.json` on macOS, `<Program
  Files>\UniversalDB MCP\manifest.json` on Windows (absent: nothing installed
  yet). A `.pkg` or `.msi` built before this check, whose install script calls
  the trusted verifier without that option, is therefore refused as a
  downgrade once the trust directory holds this release's verifier; to install
  one on purpose, an administrator moves that manifest aside first. A macOS
  `.pkg` is refused only in its postinstall, after the Installer has written
  its payload: re-install the current release's `.pkg` to restore it. Release
  gates on a build machine pass `--no-installed-manifest`.
- Container mode: `load_images_offline.sh` keeps a release record,
  `/var/lib/universal-db-mcp/release.json` (`UDBMCP_RELEASE_RECORD`, an
  absolute path, overrides it). It refuses an older bundle, or an unreadable
  record, before loading anything (`--allow-downgrade` or
  `UDBMCP_ALLOW_DOWNGRADE=1` overrides), and records the loaded release only
  after every image has loaded. The record and its directory must be root's
  alone, and so must every directory above them (a root-owned sticky
  directory such as `/tmp` is accepted there); on a host where the native
  package owns `/var/lib/universal-db-mcp`, point `UDBMCP_RELEASE_RECORD` at
  a root-only path.
- Release sticks are ordered too. Every stick carries
  `trust-bootstrap-linux/RELEASE`, its Linux bundle's `release_seq`, on its
  signed list. `bootstrap.sh` records the release whose tools it installed
  in `/usr/local/lib/udbmcp-trust/RELEASE` and refuses a stick whose
  `RELEASE` is lower, or a stick with no `RELEASE` once one is recorded,
  unless given `--allow-downgrade`, and a malformed `RELEASE` always. Residual: until this
  release's `bootstrap.sh` has recorded a release (`nothing recorded yet`),
  any genuinely signed stick is accepted, and a site whose installed
  bootstrap predates this release records nothing on its first upgrade
  (`docs/site-upgrade-runbook.md`, step 1). `docs/offline-upgrade-rollback.md`
  has the procedures.
