# Troubleshooting

## Doctor is the first stop

```bash
/opt/universal-db-mcp/venv/bin/python -m universal_db_mcp doctor --config /etc/universal-db-mcp/config.yaml
```

Checks (offline, no credentials): platform/Python match, wheel imports,
config validity, secret references, secret-file permissions (ACLs on
Windows), CA files, SQLite data files, the audit path (including a real lock
probe on its `.lock` sidecar and whether the log or lock is a symlink or hard
link), the metadata cache path and its permissions (`metadata-cache-perms`),
on macOS the access control lists of the audit log, its lock and rotated
backups, the metadata cache with its sidecars, and their directories
(`audit-path-acl`, `metadata-cache-acl`, fatal when an entry grants another
account access; remedy `chmod -N <path>`),
the bearer token, per-connection driver availability and session profile
(`session-<id>`), the installed release (`installed-release`) and the venv's
interpreter (`venv-interpreter`). When `application.audit_path` is unset,
doctor names the default it resolves to.

Doctor never stops on a path the current user may not inspect:

| Check | Meaning |
|---|---|
| `config` fatal: `config file '<path>' cannot be inspected by this user (...); run doctor as an administrator or as the account the server runs as` | `--config` (or `UDBMCP_CONFIG`) is in a folder this user cannot search. |
| `connection-<id>-files` fatal with the same text | a CA file, SQLite file, `tns_admin`, `lib_dir` or wallet cannot be inspected; the other checks still run. |
| `service-bearer-token` warning: `... may be present but is not verifiable by this user ...; run doctor as an administrator to check it` | normal for a non-admin on an MSI host, or a non-root user next to `/etc/universal-db-mcp/http-token`. |
| `http-bearer-token` fatal: `bearer token file '<path>' cannot be inspected by this user` | a configured `http_bearer_token_file` this user cannot read. |
| `doctor` fatal: `stopped before every check ran: ...` | another probe failed (an OS error, or anything else); the JSON report is still printed, never a traceback. |
| `connection-<id>-file` fatal: `data file '<path>' starts with a ~user that names no account on this machine ...` | a SQLite `database` path such as `~nobody/x.db`; `serve` refuses it as `CONNECTION_ERROR` too. Use an absolute path. |
| Windows, machine-wide config: `audit-path` / `metadata-cache-path` warning ending `unverified: the service account needs write access to '<dir>' ...` | doctor cannot evaluate NTFS ACLs for another account; expected, not an error. |
| Windows: `'<path>' absent and its directory '<logs>' does not exist: ... repair or reinstall the MSI` | the default audit folder `%ProgramData%\UniversalDB MCP\logs` is missing; a dedicated service account cannot create it. |
| `session-<id>` warning with `enforce_read_only=false` | on PostgreSQL, MySQL, ClickHouse or SQLite only the SQL guard refuses writes for that connection. |
| `audit-path` / `metadata-cache-path` fatal: `'<path>' is writable but its directory '<dir>' is not: ...` | the file exists and is writable, but the server also writes beside it: rotation renames the log at `audit_max_bytes`, SQLite creates its `-wal`/`-journal` files. Make the directory writable by the server's account. |
| `connection-<id>-secret-perms` or `http-bearer-token` fatal: `... is exposed to other local users: an access control list entry grants read to ...` | macOS: an extended ACL (`ls -le` shows `+`) opens the file beyond its 0600 mode; `serve` refuses it too. Remove it with `chmod -N <file>`. |
| `config` or `connection-<id>-secrets` fatal: `... is not valid UTF-8 text` | the config or a secret file is not UTF-8; the report names the file, never a byte of it. |
| `connection-<id>-reachable` fatal: `cannot reach <host>:<port>: ...` for a host such as `db..example.com` | a host name with an empty or over-long label; doctor reports it instead of stopping. |
| `audit-path` reports `'<path>.lock' cannot be opened (...)` (or the log's path) | the lock or the log became a symlink or another non-regular file after doctor's first check: the probe opens it without following a link (`O_NOFOLLOW`, `O_NONBLOCK`). Replace it with the regular file the server creates. |

## Authentication failures by engine

Every row below was a real dead end before the 2026-09-15 audit: the message
named the wrong component, or no config could express the deployment. Symptoms
are quoted as the driver reports them.

| Symptom | What it really means | Fix |
| --- | --- | --- |
| Oracle `DPY-3015: password verifier type 0x939 is not supported` | The server authenticated the session with the legacy 10G verifier; thin mode implements 11G/12C only. Either the account carries only `10G` (`dba_users.password_versions`), or `sec_case_sensitive_logon` is FALSE, which forces the 10G path even for an account holding `10G 11G 12C` (seen at a site on 12c). | DBA: `ALTER USER <u> IDENTIFIED BY <pw>` (and `sec_case_sensitive_logon` must not be FALSE). Or set `options.thick_mode: true` with an administrator-supplied Instant Client. See `docs/oracle-connect-modes.md`. |
| Oracle `ORA-00933` from `db_sample_table` on an old server | `FETCH FIRST` is 12c syntax. | Fixed: sampling uses `ROWNUM`. Upgrade to a build after 2026-09-15. |
| Oracle connect works but `db_test_connection` says unhealthy | The account cannot read `V$VERSION`. | Fixed: liveness no longer needs it; the version is reported as unavailable. |
| Db2 `SQL30082N ... reason "17" (UNSUPPORTED FUNCTION)` | The server refused the security mechanism. Historically this was our own bug (credentials were never sent, fixed in 854b50d). On a current build it is a genuine mismatch. | `db2 get dbm cfg \| grep -E 'AUTHENTICATION\|SRVCON_AUTH\|ALTERNATE_AUTH_ENC'`, then set `options.authentication` (`SERVER`, `SERVER_ENCRYPT`, `SERVER_ENCRYPT_AES`, `KERBEROS`, `GSSPLUGIN`, `TOKEN`, `CERTIFICATE`). |
| Db2 connects nowhere on a 10.5 server | The bundled clidriver is 12.1, which dropped Db2 LUW 10.5. | Upgrade the server, or use a build pinned to ibm_db 3.2.6 or earlier. |
| Db2 over TLS: `SQL20576N` reason 1 | The connector sets `SSLClientHostnameValidation=Basic`; the server certificate's subjectAltName does not match the configured `host`. | Reissue the certificate with a SAN for the host the client dials (an IP SAN for an IP address). See `docs/db2-tls-setup.md`. |
| Db2 over TLS: `host:port did not accept a TCP connection within N s (connect_timeout_seconds)` | The host, the port or a firewall. | Check the address and the network path. |
| Db2 over TLS: `host:port did not complete a TLS handshake within N s ...` | Usually the configured port is not the server's SSL port (`SSL_SVCENAME`), or the server is unresponsive. | Point `port` at `SSL_SVCENAME`. |
| Db2 over TLS: `host:port did not answer DRDA after its TLS handshake within N s ...` | A TLS proxy, or the Db2 instance behind it, is not answering. | Check the proxy and the instance. The probe runs before each connect; a peer that answers it and then stalls the real connect is not caught, and the executor's stuck-connect budget contains that connect instead. |
| MySQL `AttributeError: ... scramble_old_password` | The account uses the pre-4.1 `mysql_old_password` plugin. | Fixed: a clear message now names the plugin. DBA: move the account to `caching_sha2_password`. |
| MariaDB `RuntimeError: 'pynacl' package is required for ed25519_password` | The account uses `client_ed25519`. | Fixed: PyNaCl ships in the bundle from 2026-09-15. Older bundles cannot install it offline. |
| MySQL `db_list_routines` returns an empty list | MySQL 8.0 hides `information_schema.ROUTINES` rows from accounts without `SHOW_ROUTINE`. | `GRANT SHOW_ROUTINE ON *.* TO '<user>'@'%';` |
| ClickHouse authenticates by certificate and ignores the password | With a client certificate the driver takes the mutual-TLS path. | Fixed: a configured password now forces `tls_mode=strict`. |
| ClickHouse opaque protocol error | Port 9000/9440 is the native TCP protocol; this client speaks HTTP. | Use 8123, or 8443 with `tls.enabled`. Now refused at config time. |
| SQL Server `Login failed for user ''` | No SQL login configured; the site uses Windows/Kerberos only. | `options.trusted_connection: true`, with `/etc/krb5.conf` and a ticket (`kinit`) before the service starts. There is no NTLM fallback on Linux. |
| SQL Server connect timeout to a named instance | The port was appended, sending the client to the default instance. | Fixed: `host\INSTANCE` with no `port` keeps the instance. SQL Server Browser must be reachable on UDP 1434. |
| SQL Server "names a CA that is NOT installed in the OS trust store" although it is | The trust store is a hashed directory rather than a bundle. | Fixed: the check now scans the CApath too. |
| PostgreSQL Kerberos-only site cannot connect | GSSAPI options were unreachable. | `options.gssencmode: require` and `options.krbsrvname`. |
| `connections: <engine> needs username_env or username_file` | Omitting the username does not send "no credential": PostgreSQL and MySQL send the service account's OS user, ClickHouse sends `default`. | Set the username, or `options.os_authentication: true` to choose the implicit identity deliberately. |
| SQLite `file is not a database`, or `db_test_connection` unhealthy with the ENCRYPTED hint | Often an encrypted database (SQLCipher/SEE), which the standard-library driver cannot open. Every open reads the database header, so this is reported on every platform, Ubuntu 24.04's SQLite 3.45 included. | Decrypt it, or use a build with an encryption extension. Not shipped here. |
| `CONNECTION_ERROR: could not apply the session read-only mode / isolation ... on connection '<id>'` | The session safety profile is fail-closed for read-only (PostgreSQL, MySQL) and isolation (Db2, SQL Server) and the server refused the SET. | Check the server version (MySQL < 5.6.5 has no READ ONLY transactions) and any pooler in between; opt out per connection with `session.enforce_read_only: false` or `session.isolation: cs`/`read_committed`. See `docs/offline-upgrade-rollback.md`. |
| `CONNECTION_ERROR: could not set <what> for the session on connection '<id>' (...); the server would read statements differently from the SQL guard that checked them, so the connection is refused` | The connection could not hold a setting that decides how the server reads statement text at the value the SQL guard parses under (`docs/session-safety.md`): MySQL/MariaDB `an sql_mode without ANSI, ANSI_QUOTES, ...` or `the utf8mb4 client character set`; PostgreSQL `standard_conforming_strings on` or `the UTF8 client encoding`; SQL Server `QUOTED_IDENTIFIER ON`; Db2 `SQL_COMPAT 'DB2'`; ClickHouse `<name>=<default>`, typically a `readonly=1` profile (or a constraint) that sets `dialect`, `implicit_select`, `prefer_column_name_to_alias`, `enable_global_with_statement` or `analyzer_compatibility_join_using_top_level_identifier` otherwise, `compatibility` 21.x or older included. There is no opt-out. | A proxy or pooler that rejects session `SET`s: connect directly. ClickHouse: put the setting back to its default in the account's profile, or use `readonly = 2` (`docs/driver-matrix.md`). |
| Every `db_*` call fails `CONFIG_ERROR: ... requires TLS` right after adding a connection | `security.require_remote_tls` is on and the connection has no `tls:` block. | Add `tls.enabled` with a `ca_file`. Re-running `udbmcp add-connection --name <id> --tls-ca-file <path>` does this safely: a re-run updates the connection in place and keeps its `allowed_schemas`, `session`, `options`, timeouts and client certificates (see `add-connection` below). |

## Common failures

| Symptom | Cause | Fix |
| --- | --- | --- |
| `CONFIG_ERROR: ...` on start | config missing/invalid; unknown fields and duplicate YAML keys rejected. A YAML error gives the parser's reason and the line and column, never the file's text (it may hold a secret); a file that is not UTF-8 is named with the line | fix YAML at that line and column; see config.example.yaml |
| `CONFIG_ERROR: ... read_only=false is not supported in v1 ...` | a connection sets `read_only: false` (or `security.read_only: false`); v1 is read-only | remove the key; every connection is read-only |
| `CONFIG_ERROR: connection id '<id>' must be 1-64 chars of [A-Za-z0-9_-], not starting with '-'` | ids starting with `-` or with non-ASCII characters are refused since this release | rename the connection (and its secret files) |
| `CONFIG_ERROR: application.audit_path is not set and the per-user default cannot be derived (...)` | no usable home directory (none, `HOME` empty or `/`, a drive root, relative) | set `application.audit_path` |
| `CONFIG_ERROR: the bearer token in <path> must be at least 32 characters ...` | an HTTP token shorter than 32 characters, or not UTF-8 | `python3 -c 'import secrets; print(secrets.token_hex(32))'` into the token file |
| `DRIVER_MISSING: '<engine>' connector requires the pinned driver wheel ...` | optional connector wheel not installed | install from bundle wheelhouse only (`--no-index`); never pip from network |
| `AUTHORIZATION_DENIED: unqualified table '<t>' is not permitted: connection '<id>' allows only schemas [...]` | the connection has `allowed_schemas`, so every table in a statement must name its schema (its database on MySQL and ClickHouse) | write the qualified name the message suggests, e.g. `ocean.buoys`; `db_list_connections` shows each connection's allowlist |
| the same, ending `on Db2 it is SYSIBM.SYSDUMMY1: write SYSIBM.SYSDUMMY1` | Db2 binds a bare `SYSDUMMY1` to `CURRENT SCHEMA`, not to the dummy table | write `SYSIBM.SYSDUMMY1`. Oracle `DUAL`/`SYS.DUAL` and Db2 `SYSIBM.SYSDUMMY1`..`4` are readable in statements on every connection; that rule opens nothing else in `SYS` or `SYSIBM` |
| `AUTHORIZATION_DENIED: schema 'x' is not permitted ...` or `... schema names that differ only in case ...` | a schema outside the allowlist, or a spelling of an allowed schema the policy does not admit. Where the catalog holds one name in several spellings (`TRAVEL` and `"travel"`), an entry admits the spelling the engine folds it to (upper case on Oracle and Db2, lower case on PostgreSQL); an entry mixing upper- and lower-case letters admits its exact spelling first | write the spelling the message names. To admit a quoted namesake as well, the administrator lists both spellings (`['TRAVEL', 'travel']`) |
| `POLICY_VIOLATION: object 'x' could not be resolved ...` (statements) or `AUTHORIZATION_DENIED: object 'x' could not be resolved ...` (metadata and sample tools) | default-deny object policy: the name is not in the policy-scoped catalog listing (a new table appears after up to 300 s) | qualify with an allowed schema, or have the admin extend `allowed_schemas` |
| `POLICY_VIOLATION: ... not permitted` | guard denied the statement (DML, unknown function, multi-statement, reserved keyword alias on SQL Server, a name after `IN` without parentheses, ...) | use a read statement with permitted objects and bound parameters; the message names the construct and, where there is one, the fix. A placeholder or constant after `IN` (ClickHouse `IN {ids:Array(UInt64)}`) is accepted |
| `POLICY_VIOLATION: '<name>' shows other sessions' SQL or the values it carries (statement text, literals, bind values, error text, locked keys) ...` | a view of other sessions' statements or their values (`pg_stat_activity`, MySQL `PROCESSLIST`, Oracle `V$SQL`, ClickHouse `system.query_log`, SQL Server `sys.dm_exec_requests`, ...) is refused on every connection and left out of `db_list_tables`, the catalog tools, and the view and synonym listings of PostgreSQL, Oracle and Db2; `allowed_system_schemas` cannot open it | none: it would hand back values masking hides. The full list is in `docs/security.md` |
| `POLICY_VIOLATION: '<name>' holds column statistics (histogram buckets, most common values, low and high values) ...` or `... holds stored credentials (password hashes, or the passwords and connection details the database keeps for other servers) ...` | a column-statistics view (MySQL `COLUMN_STATISTICS`, `pg_stats`, Oracle `*_HISTOGRAMS`, Db2 `SYSCAT.COLDIST`, ...) or a credential view (`information_schema.user_mapping_options`, `mysql.user`, `sys.sql_logins`, Oracle `*_DB_LINKS`, ...), refused on every connection whatever is opened. Some of them were `AUTHORIZATION_DENIED` as a closed system schema before | none; the lists are in `docs/security.md` |
| `POLICY_VIOLATION: '<name>' carries the definitions of every schema's objects (view and routine bodies, trigger statements, check clauses, DEFAULT expressions with their literals) ...` | an `information_schema` definition view (`VIEWS`, `ROUTINES`, `COLUMNS`, `TRIGGERS`, `CHECK_CONSTRAINTS`, ...; per engine in `docs/security.md`), which covers schemas outside the allowlist too | `db_list_columns` and `db_list_views` describe the objects the connection may read; `information_schema.TABLES` and the other names-only views stay readable |
| `VALIDATION_ERROR: the statement has N placeholder(s) outside string literals, quoted names and comments but M positional value(s) were supplied ...` or `... parameter(s) [...] were supplied but no %(name)s placeholder ... uses them ...` | MySQL, ClickHouse or PostgreSQL: a placeholder inside a literal or comment is text, so the values do not match the placeholders in code | put each placeholder outside quotes (`WHERE name = %s`, not `'%s'`), one value per placeholder |
| `VALIDATION_ERROR: '%%' outside a string literal is not supported with bound parameters ...` | MySQL, ClickHouse or PostgreSQL with `parameters`: `%%` in code (in a string literal it is one `%`) | write the modulo operator as one `%`, or `MOD()` |
| `VALIDATION_ERROR: placeholder %s is directly followed by '<c>' ...` | a placeholder glued to a name, digit or quote (`%ssn`), which PostgreSQL's parser and the driver read differently | put a space or an operator after it |
| `VALIDATION_ERROR: parameter(s) [...] were supplied but no statement's placeholders ... use them` | `db_federated_query`: each statement gets only the named values its placeholders use, and a name none uses is refused | drop the unused name |
| `QUERY_ERROR: '<name>' is an internal table of a full-text or R*Tree index ...` | SQLite: a shadow table of an FTS or R*Tree index, which holds the indexed values under generic column names | query the index's own (virtual) table |
| `POLICY_VIOLATION: '<name>' carries each column's low and high values (...): name the columns you need, without those, without * and without a column list after its alias ...` | Oracle `*_TAB_COLUMNS`/`COLS` or Db2 `SYSCAT.COLUMNS` read with `LOW_VALUE`, `HIGH_VALUE`, `HIGH2KEY` or `LOW2KEY`, with `*` (outside `COUNT`) or with a column list after the alias; the sample, profile and metadata tools refuse these views whole. Ending `; a CTE of the name '<name>' does not change this ...`: a CTE named like one of these views | name the columns you need; rename such a CTE |
| `POLICY_VIOLATION: table <t> is not spelled as the catalog lists it on connection '<id>' (<spelling>): ...` | default-deny on PostgreSQL, Oracle, Db2 or ClickHouse: a quoted name in another case than the catalog's, or an unquoted one the engine folds to another (on SQL Server, a case variant under a case-sensitive collation) | write the spelling the message gives |
| `POLICY_VIOLATION: the bare name <t> is the listed <s>.<t> only where the session looks bare names up in <s> first; ... a bare name is looked up in <schema> first ...` or `the bare name <t> is read from pg_catalog first ...` | default-deny on PostgreSQL, Oracle, SQL Server or Db2: the engine would read another object of that name (a dictionary view, a synonym) before the listed table | write `<s>.<t>` as the message says |
| `<category>: '<name>' is a synonym that reads '<target>', refused as that is: ...` (Db2: `an alias`; the category is the carried refusal's) | with `default_deny_objects: false`, the synonym or alias chain on Oracle, SQL Server or Db2 reaches an object a statement could not name directly, or one over a database link or in another database (`... reads only this connection's database`) | read the target by a name the policy allows, or have the administrator open it |
| `POLICY_VIOLATION: database links / remote-object references (@link) are not permitted: ...` (the guard, in every statement tool) or `POLICY_VIOLATION: database links (@link) are not permitted on connection '<id>' ...` (the Oracle connector's check in `db_query` and `db_explain`) | Oracle: an `@` outside string literals, quoted names, hints and comments; in the connector's check also any `@` in a statement holding a `q'...'` or `nq'...'` literal | remove the link; to read another database, configure a connection to it |
| `POLICY_VIOLATION: statement could not be parsed under the 'oracle' dialect ...` | SQL the guard cannot parse; on Oracle that includes every alternative-quoted `q'...'` or `nq'...'` literal, in every tool, `db_validate_query` included | write the string in ordinary quotes, doubling a quote inside it (`'it''s'`) |
| `POLICY_VIOLATION: server and session variables (@@name) are not permitted ...` / `user variables (@name) are not permitted on MySQL ...` / `the identifier U&"..." is not permitted ...` / `'@' is not permitted on PostgreSQL outside the operators @>, <@, @@ and @? ...` | `@@name` on any engine; MySQL `@x` or `@x := ...`; a PostgreSQL or Db2 Unicode-escape identifier; the PostgreSQL prefix `@` (absolute value), `@@@` or `^@` | the server version is in `db_test_connection`; pass values as parameters; write the name itself; write `abs(x)` |
| ClickHouse: `IN with nothing after it, or IN right after IN, ...`, `function '<name>' is not permitted on ClickHouse: it names a table or dictionary ...`, `IN (<name>) with a single name ...`, or a refusal ending `name a tuple's element by its index (a.1)` | the function form `in(v, t)`, `joinGet`, `dict*`, `hasColumnInTable`, an `IN` over one wrapped name, or an `a.b` ClickHouse would read as the table `a.b` | `x IN (SELECT <column> FROM <db>.<table>)` or a JOIN; `a.1` for a tuple element; qualify a column with its table's alias |
| `POLICY_VIOLATION: a WITH after UNION, INTERSECT or EXCEPT is not permitted without parentheses around its query ...` | a `WITH` inside a set operation with more branches after it; engines differ over the branches it covers | write `(WITH ... SELECT ...)` as that branch, or put the `WITH` ahead of the whole statement |
| `POLICY_VIOLATION: the name '...' is not permitted on SQL Server: its collation reads a name outside printable ASCII, or with a trailing blank, as another ...` | a table, column or alias with a character outside printable ASCII, or a quoted name ending in a blank | write the name in printable ASCII. An object whose catalog name is not ASCII cannot be named in a statement; `SELECT *` still returns such a column, and the metadata, sample and profile tools accept any name |
| `POLICY_VIOLATION: the delimited name '...' is not permitted on Db2, which drops the blanks at its end ...` | a quoted Db2 name ending in blanks | write the name without them |
| `POLICY_VIOLATION: the unquoted name '...' is not permitted on Oracle, which upper-cases its ı or ſ to an ASCII letter ...` | an unquoted Oracle name containing a dotless ı or a long ſ | write the ASCII letter, or quote the name to mean it exactly |
| `POLICY_VIOLATION: the quoted identifier ... is not permitted: ClickHouse decodes backslash escapes in a quoted identifier ...` | a ClickHouse backquoted or double-quoted name containing a backslash | write the name without escape sequences; a backquote inside backquotes is doubled (` `` `) |
| ClickHouse: `the CTEs <names> name each other ...`, `WITH RECURSIVE ahead of a UNION, INTERSECT or EXCEPT recurses only in the first branch ...`, `a WITH in parentheses at the start of a UNION, INTERSECT or EXCEPT ...`, or `the CTE <c> reads '<n>', which the statement declares as a CTE elsewhere as well: ... which resolves a CTE's body where the CTE is used ...` | ClickHouse binds these names to other CTEs, or to tables, than the statement appears to say | each message gives the rewrite: a recursion in its own `WITH RECURSIVE ... UNION ALL` body, the set operation in a subquery, the `WITH` ahead of the whole set operation, distinct CTE names |
| a table refusal ending `; a CTE of that name does not cover this reference: ClickHouse reads the table there (...)` | ClickHouse reads that name as a table, for example a CTE naming itself without `WITH RECURSIVE ... UNION ALL`, or in the first branch of the recursion; names are case-sensitive | qualify the table with its database, or rename the CTE |
| `AUTHORIZATION_DENIED: a bare DUAL on connection '<id>' names <SCHEMA>.DUAL ...` / `... is looked up in the session's current schema <SCHEMA>, set at logon ...` | Oracle (`db_query`, `db_explain` and the other tools that run a statement): the login schema owns an object named `DUAL`, or a logon trigger set `CURRENT_SCHEMA` to another schema. `db_validate_query` does not detect this | write `SYS.DUAL` |
| `POLICY_VIOLATION: this plan is not returned: MySQL reads const tables ...` | `db_explain` on MySQL: a TREE or JSON plan (a plain `EXPLAIN` too where `explain_format` is TREE or JSON) of a statement naming a masked column, selecting `*` or joining NATURAL; MySQL prints the values it read while planning into those formats | `EXPLAIN FORMAT=TRADITIONAL <statement>` |
| `db_explain` with `analyze=true`: `POLICY_VIOLATION: EXPLAIN ANALYZE is disabled by policy`, or, with `security.allow_explain_analyze: true`, `VALIDATION_ERROR: analyze=true is not supported by db_explain ...` | `db_explain` never executes the statement; the setting only picks the refusal | call it without `analyze` |
| `QUERY_ERROR: ...` | the statement ran and the engine rejected it (SQL or data error); the text is sanitized | fix the statement |
| `TIMEOUT: ... the statement exceeded its time limit and the database cancelled it (... SQL0952N / HYT00 / 3024 ...)` | the per-query or hard statement ceiling fired on the server | narrow the query or raise the call's `timeout_seconds` within `security.hard_query_timeout_seconds`. SQL Server `HY008 Operation canceled` after a TIMEOUT is the cancel hook working |
| `TIMEOUT: ... the connect had not completed when the deadline fired, N s after it started ...` | the database or the network did not answer the connect (named as such only past `max(connect_timeout_seconds, 5 s)`) | check the listener and the network |
| `TIMEOUT: ... did not start within its deadline ...` | every worker thread was busy; nothing ran and the connection was kept | retry later |
| `TIMEOUT` + "the driver exposes no cancellation hook" | the engine path cannot cancel out-of-band | the connection was discarded; the engine's statement ceiling (Db2 `QUERYTIMEOUT`, the session ceilings) stops the query; see docs/driver-matrix.md |
| `CONNECTION_ERROR: connection '<id>' is still recovering from a driver call that timed out or was cancelled ...` | an abandoned call on this connection has not returned | retry after it returns; past 120 s the message says to check the database and network or restart the server |
| `CONNECTION_ERROR: connection is in an uncertain state after a previous cancelled query and was discarded; reconnect or restart` | a deadline or client cancel discarded the connection; requests queued behind a connect that hung get it too, although no query was cancelled | retry; the next call builds a new connection |
| `CONNECTION_ERROR: connection '<id>' is unavailable: a connect to its database server did not complete within N s ...` | a connect to the same database server (engine, host and port; for an Oracle `tns_alias` the alias and its `tns_admin`, for a MySQL `unix_socket` the socket) is still hanging past `max(connect_timeout_seconds, 5 s)`. On Oracle Thin, python-oracledb 4.0.2 bounds only the TCP connect (`tcp_connect_timeout`; the DSN's connect and transport timeouts, `RETRY_COUNT=0` and `expire_time` do not bound the handshake), so a listener that accepts and never answers hangs it until the peer closes. The executor releases the request at its deadline and parks such a connect in the stuck-connect budget (10 slots, at most 9 per server) | check the listener and the network; the refusal lifts when that connect returns |
| `CONNECTION_ERROR: ... the limit of 10 pending connects to database servers that did not answer has been reached` | ten connects to database servers accepted TCP or were black-holed and never answered | check the network and the listeners; the refusal lifts as those connects return; SQLite connections are unaffected (a MySQL `options.unix_socket` connection is a server like any other); if they never return, restart the server |
| `LIMIT_EXCEEDED: query concurrency limit reached: this connection's database server is at its limit of N calls in flight ...` | one database server may hold `max_concurrent_queries - 1` tokens (from a limit of 3 up, healthy calls count) | raise `security.max_concurrent_queries` by one per extra parallel call wanted on that server. Connection ids that name one server by host name in some places and by IP address in others count as different servers: use one spelling |
| `LIMIT_EXCEEDED: the response would be N bytes, over security.max_response_bytes ...` | a single-object result far over the ceiling | narrow the request (one object, fewer columns, a smaller page) |
| `LIMIT_EXCEEDED: ClickHouse sent a result block of more than N MiB ...` / `... that decodes to more than N MiB in memory ...` | one row, or the rows one input row expands to, exceeds the stream or object budget | select fewer or narrower columns, add a LIMIT |
| SQLite `QUERY_ERROR: string or blob too big: the statement builds or reads a value longer than this server lets SQLite handle (N MiB: 16 x security.max_response_bytes, at least 16 MiB) ...` | the statement builds or reads a value longer than `SQLITE_LIMIT_LENGTH`, `min(max(16 x max_response_bytes, 16 MiB), 1,000,000,000 bytes)`; a stored value that long cannot be read at all, not even through `length()` or `substr()` | build shorter values, or raise `security.max_response_bytes`. When the text says `(N MiB: SQLite's own ceiling, which no setting of this server raises)`, the limit is SQLite's and cannot be raised here |
| SQLite `LIMIT_EXCEEDED: ... needs more memory than this server lets SQLite use (512 MiB, shared by every SQLite handle in the process) ...` | the process-wide SQLite heap limit | sort, group or compare shorter values (`substr()` cuts a long one), or fewer rows |
| `AUTHORIZATION_DENIED: cursor ... not issued to this caller` / `VALIDATION_ERROR: cursor does not apply to this operation` | cursor reuse across identities/policy, or with other filter arguments; cursors from before an upgrade are stale | re-run the listing to get a fresh cursor |
| `CONFIG_ERROR: audit log write to '<path>' failed and application.audit_fail_closed=true; operation refused (...)` | the audit path is unwritable, full, or its lock is held | restore write access to `application.audit_path` (and its directory for the `.lock` sidecar); see the next rows |
| `... audit lock held by another process for more than 10 s` / `... for more than 1 s, after an earlier record gave up waiting 10 s` / `... audit log held by another thread of this process ...` | another server process is suspended mid-append or stuck in fsync on a dead mount. Each record waits at most 10 s; once one gives up, later records of that process wait at most 1 s until the lock is free again. A refused call writes one record, so the first takes about 10 s (`10 s` text); a call whose statement ran writes two, so it takes about 11 s and shows the `1 s, after an earlier record gave up waiting 10 s` text; later calls take about 1 or 2 s | find the hung `udbmcp` process or the dead mount, or move `audit_path` to local disk |
| audit log shows `"event": "tool_call_summary"` records | repeats of one refusal kind (caller, action, outcome, category, connection id, fingerprint) past the first 10 in a 10 s window, or past 64 full records in the window, are counted into one summary per kind (`docs/security.md`, Audit); every call is still refused, and `db_get_query_history` lists each one | none: `count`, `first_ts` and `last_ts` say how many and when. A process killed by a signal (an HTTP service on SIGTERM included) loses the counts of its last open window |
| `... audit lock file keeps changing (50 reopen attempts)` / `... audit file keeps appearing and disappearing ...` | the audit path is on a network or FUSE filesystem with unstable file identities | move `audit_path` to a local filesystem |
| root-owned `audit.jsonl` or `audit.jsonl.lock` in `/var/log/universal-db-mcp` | an older release's root `site-check` or `doctor` created them | upgrading hands them back to the service account (deb, pkg, `install_offline.sh`, `upgrade_offline.sh`); otherwise `chown` them to the service account; run site checks as `sudo -u <service account>` |
| stderr `universal-db-mcp: metadata cache disabled (every lookup reads the live catalog): ...` | the cache file or its directory is not private to the server's user (group/other bits, another owner, a symlink or hard link, a sticky shared directory such as `/tmp`) | `chown` the file to the service user and `chmod 600`, or move it to a private directory; nothing fails meanwhile |
| doctor: secret file unsafe permissions | group/world bits on password file (Windows: a broad group's read or write ACE) | `chmod 600 /run/secrets/<file>`; on Windows `icacls <file> /inheritance:r /grant:r *S-1-5-18:F *S-1-5-32-544:F <service account>:R` |
| Db2: bundled clidriver missing on import | wrong-profile wheel installed | reinstall from this bundle's wheelhouse; verify profile matches (linux-x86_64-cp312) |
| SQL Server: ODBC Driver not installed | admin-supplied OS package absent | install from bundle `os-packages/` after EULA acceptance |
| `could not apply the session read-only mode ... refusing to run at the server's default level` | the server refused the read-only setting the profile requires (MySQL `SET SESSION TRANSACTION READ ONLY`, PostgreSQL `default_transaction_read_only`, ClickHouse `readonly`) | fix the account or, if the server truly cannot support it, set `connections.<id>.session.enforce_read_only: false` and rely on the SQL guard alone (documented risk) |
| Db2: `WITH RS` / `WITH RR` refused | those isolation clauses hold locks for the statement; the session runs at `UR` for exactly that reason | end the statement in `WITH UR` (or `WITH CS`), or drop the clause |
| ClickHouse: `Cannot modify 'readonly' setting in readonly mode` (old builds) | the account's server profile is already `readonly=1/2` | fixed: the client reads `server_settings` first and keeps the stricter profile; `db_test_connection` reports `read_only (server profile readonly=N)` |
| `.deb`/`.pkg`/MSI install or `load_images_offline.sh`: `trusted verifier ... is an OUTDATED copy (no --installed-manifest option)`, possibly after `unrecognized arguments: --installed-manifest` | the trust dir holds a verifier from before this release | refresh the trusted tools from the release stick (`docs/site-upgrade-runbook.md`, step 1), or copy this release's `verify_bundle.py` and `profiles.py` into the trust dir |
| release gate or build script: `unrecognized arguments: --no-installed-manifest` | the gate ran a verifier older than this release (for example an older bundle's `trusted-tools/` copy) | run it with this release's `verify_bundle.py` |
| install: `FAIL: rollback refused: this bundle is an OLDER release than the one installed ...` | anti-rollback: the bundle's `release_seq` is lower than the installed one. After `release order: no --installed-manifest given; checking this machine's installed release <path>`, the caller named no installed manifest (a manual check, or a `.pkg` or `.msi` built before this release) and the verifier, on the install target, checked this platform's own record | install the newer release; for an intended downgrade see the runbook (`--allow-downgrade`, `UDBMCP_ALLOW_DOWNGRADE=1`, or the macOS flag file). An older installer that cannot pass the override is refused until an administrator moves the named manifest aside |
| macOS: the refusal above adds `such a .pkg is refused only after the Installer has written its payload ...` | a `.pkg` built before this release has no release check in its preinstall, so its bundle folder, share scripts and LaunchDaemon plist were written before its postinstall refused it | re-install the current release's `.pkg` to restore them |
| `load_images_offline.sh`: `FAIL: this bundle is an OLDER release than the one whose images this host last loaded (release record <path>), or that record is unreadable ...` | container-mode anti-rollback against the loader's release record | load a newer bundle; an intended downgrade passes `--allow-downgrade` (or `UDBMCP_ALLOW_DOWNGRADE=1`) |
| `load_images_offline.sh`: `FAIL: the release record <record> orders the releases this host loads, and <path> is not root's alone ...`, or `UDBMCP_RELEASE_RECORD (...) must be an absolute path` | the record, its directory, or a directory above it is not a real root-owned directory or file that group and others cannot write (a root-owned sticky directory such as `/tmp` is accepted above the record's directory) | `sudo chown root <path>; sudo chmod go-w <path>`. When the path belongs to `udbmcp` (a native install on the same host owns `/var/lib/universal-db-mcp`), leave it and set an absolute `UDBMCP_RELEASE_RECORD` in a root-only directory, e.g. `/var/lib/udbmcp-images/release.json` |
| `bootstrap.sh`: `FAIL: <name> is not a regular file; ... The stick changed while it was read.`, `FAIL: <path> is in the private copy of the stick but not on its signed SHA256SUMS.`, `FAIL: <deb> could not be copied from the stick ...` or `FAIL: a package copied from the stick does not match its signed SHA256SUMS ...` | the stick changed between its check and the private copy | get the stick again from the release administrator; nothing was installed, and the checked copies of an earlier run stay in `/var/cache/udbmcp-trust` |
| `bootstrap.sh`: `FAIL: this stick is release N, OLDER than release M whose trust tools are installed.` or `FAIL: this stick names no release, OLDER than ...` | the trust dir records release M (`/usr/local/lib/udbmcp-trust/RELEASE`) and the stick's signed `trust-bootstrap-linux/RELEASE` is lower, or absent | use the newer stick. An intended downgrade re-runs the printed command with `--allow-downgrade` |
| `bootstrap.sh`: `FAIL: trust-bootstrap-linux/RELEASE on this stick is not a release number ...` or `FAIL: /usr/local/lib/udbmcp-trust/RELEASE cannot be read as a release number ...` | a malformed release number on the stick, or a damaged record | get the stick again; for a damaged record, re-run with `--allow-downgrade` after checking the stick is the one you mean to install |
| verifier: `FAIL: not a regular file or directory in the bundle: <rel> (a link, a FIFO or a device) ...`, `FAIL: SHA256SUMS cannot be used: SHA256SUMS has N links ...`, `... changed while the bundle was verified`, or `FAIL: the bundle cannot be listed: <path>: <reason>; nothing in it was checked` | the bundle holds a symlink, FIFO, socket, device or junction; its `SHA256SUMS` or `SIGNATURE` is hard-linked (a copy made with `cp -al` or `rsync --link-dest`); a file changed while it was read; or a directory cannot be listed (a missing bundle path included). A name with a control character is shown as its escape (`x\ny`) | copy the bundle again, plainly (`cp -R`, no links), from your trusted channel |
| installers: `FAIL: the private copy of the bundle would be made in <base>, and <dir> is not root's alone ...` | `UDBMCP_STAGING_DIR` (default `/var/tmp`) or a directory above it is not a real root-owned directory that group and others cannot write (or a root-owned sticky one) | point `UDBMCP_STAGING_DIR` at a directory root alone can write, or fix the owner and mode it names |
| installers: `NOTE: TMPDIR (<value>) is not root's alone; root's temporary files are not made there` (also `TEMP`, `TMP`) | `sudo -E` or `su` kept a temporary directory another account can change; it is unset for the run | informational; nothing to do |
| installers: `FAIL: the private copy of the bundle could not be made in <dir>. ...`, `FAIL: the private copy holds what is not a regular file or directory ...` or `FAIL: the private copy is not root's alone ...` | the copy failed (space), or the bundle holds a link, FIFO or device, or the copy ended up writable by another account | free space, or copy the bundle again from the trusted channel |
| `load_images_offline.sh`: `The images are loaded, but the record was not written.`, or `WARNING: the release record <path> is below <dir>, a directory every account can write ...` | the release record's directory changed after the images were loaded; or the record sits under `/tmp`-like storage that boot may empty | check who can write the record's directory, then load again; keep the record in a root-only persistent directory (`UDBMCP_RELEASE_RECORD=/var/lib/udbmcp-images/release.json`) |
| MSI install, repair or upgrade: `The process cannot access the file '...\manifest.json.previous'` (or `.kept`) `because it is being used by another process` | a process holds the installed-release record's rollback copy or its marker open; the record is left unchanged | find and close it (Sysinternals `handle.exe`) or reboot, then rerun. A `.previous` or `.kept` file left after a successful install is harmless: delete it once nothing holds it, and never copy it over `manifest.json` |
| MSI: `python interpreter: <problem>. ... An owner counts as an administrator here only as SYSTEM, Administrators, TrustedInstaller or a direct member of the local Administrators group ...` | a file of the base interpreter is owned by an administrator only through a domain group (for example after an elevated `pip install` into it) | add that account to the local Administrators group itself and rerun; never re-own files a non-admin could have written |

## `add-connection`

- Re-running it for an existing name updates that connection in place: it
  changes only the fields it sets and keeps `allowed_schemas`, `session`,
  `options`, timeouts and client certificates; an omitted `--port` keeps the
  existing port. Changing the engine needs `--replace`, which rewrites the
  whole block. A credential re-add replaces both `username_env` and
  `password_env`. The JSON result lists `action`, `preserved_fields`,
  `changed_fields`, `dropped_fields`, `warnings`, `notices`, `secrets_dir` and
  `service_restart`.
- The rewrite drops comments after the config's leading header. Interactive
  runs ask first; `--json` and flag runs refuse unless
  `--accept-comment-loss` is given (the `<config>.bak.<stamp>` backup keeps
  them).
- The config is replaced atomically. A symlinked config is edited through
  the link (the target is replaced, the link kept); the file keeps its mode
  and group, and its owner when run as root. A config in a group this user
  is not in, whose mode gives that group access of its own (0640), is refused
  rather than rewritten into another group (the service would lose read
  access at its next start): run as a member of that group or as root. A
  change that turns TLS off prints a warning. A relative `tls.ca_file`
  already in the config is offered resolved against the config's directory,
  as the server reads it.
- On macOS the secrets directory must carry no extended ACL entry that
  grants anyone but its owner access, inheritable entries included (one
  inherited as the wizard creates it is removed; one an existing directory
  carries is refused: `chmod -N <dir>`), since every secret file created in
  it would inherit it. Entries that only deny (`group:everyone deny delete`,
  which macOS puts on home folders) are fine. A `UDBMCP_CONFIG` starting
  with a `~user` that names no
  account is a `CONFIG_ERROR`.
- Backups: `<config>.bak.<stamp>` beside the config, created with the
  config's permission bits only (setuid, setgid and sticky are never copied;
  run as root, the backup is root-owned and loses group and other write
  too), and `<name>.username.bak.<stamp>` /
  `<name>.password.bak.<stamp>` in the secrets directory. They hold old
  credentials; remove them once you have checked the result. A failed run
  leaves the config and the secrets unchanged.
- Connection names are 1-64 ASCII letters, digits, `_` or `-`, starting with
  a letter or `_`. `--read-write` is refused (`CONFIG_ERROR: read_only: false
  is not supported (v1 is read-only)`), and the wizard no longer asks
  "Read-only connection?".
- As root, secrets are written only when every directory from `/` to the
  config's directory is root-owned and not group- or other-writable (on
  macOS, with no ACL entry that grants another account access; deny-only
  entries are fine); the `.deb` and `.pkg` system config qualifies, and the
  service account then owns the secrets (the command to restart the service
  is printed).
  Otherwise the run exits 1 naming the directory and suggesting
  `sudo -u <account> udbmcp add-connection ...`.

## `configure-agents`

It refuses (`refusing to write: <reason>`, status
`unknown_state_fail_closed`) rather than override protection: a harness config
that is read-only, owned by another user, hard-linked, in a directory the user
cannot write, or behind a user's symlink under `sudo`; one whose access control
list differs from the one its directory gives every new file (an ACL of its
own: `... has an access control list other than the one its directory gives
every new file ...`; or none in a directory with a default ACL or
`file_inherit` entries: `... has no access control list, but its directory
gives every new file one ...`); for a non-root run, one in a group the user
is not in whose mode gives that group access of its own (0640, 0660) where
the replacement would change its group (`... belongs to group <gid>, which
this user is not in ...`: `chgrp` it to a group you are in, or add the
printed block by hand); a config with a different `universal-db` entry; a
harness whose config appeared while it ran. Nothing is backed up or written
then, and the output shows the reason and this tool's own entry in the file,
never its other servers' entries. A config whose ACL is exactly the inherited
one is written and keeps it. The fixes and exit codes are in `docs/claude-code-integration.md`. A
registered interpreter that cannot `import universal_db_mcp.server` in
isolated mode is refused with
`CONFIG_ERROR: <python> -I cannot import universal_db_mcp.server (...)`:
install the package and its dependencies into a virtual environment.

## Log locations

- stdio mode: application logs on stderr; MCP protocol on stdout (never
  mix).
- HTTP service: systemd journal (`journalctl -u universal-db-mcp`). With
  `UDBMCP_HTTP_LOG_FILE` set (the macOS LaunchDaemon sets
  `/var/log/universal-db-mcp/http.log`), the listener's log goes to that
  size-bounded file (5 MiB x 3), and ERROR records (a port already in use, an
  ASGI exception) also go to stderr. On macOS launchd writes the daemon's
  stdout and stderr to `/Library/Logs/universal-db-mcp/server.log` and
  `server.err.log` (startup output and those errors). `serve` empties
  either at startup when it is over 5 MiB, and `server.err.log` again before
  an ERROR record once it is over 5 MiB (`universal-db-mcp: emptied this
  file at N bytes (cap 5242880)`), so no root job rotates them. It empties
  only a file `_udbmcp` owns with one link: one launchd recreated as root
  (after an administrator deleted it) grows until the next `.pkg` install
  hands it back. An upgrade leaves the
  old `server.log` and `server.err.log` in `/var/log/universal-db-mcp`, no
  longer written, and any `*.log.N.bz2` archives there. Under a pre-auth
  flood the log carries `suppressed N pre-auth protocol warnings` lines.
- `serve` prints one stderr line when `application.audit_path` is unset,
  naming the default it audits to.
- Audit JSONL: `application.audit_path`; metadata cache:
  `application.metadata_cache_path`.

## Reporting a failure honestly

If a gate cannot run in your environment, record it `blocked`/`not_run`
with the reason in IMPLEMENTATION_STATUS.md. Do not upgrade a claim without
a recorded run in `test-evidence/`. Security issues go through `SECURITY.md`,
never a public issue.
