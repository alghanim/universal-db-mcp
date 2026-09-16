# Troubleshooting

## Doctor is the first stop

```bash
/opt/universal-db-mcp/venv/bin/python -m universal_db_mcp doctor --config /etc/universal-db-mcp/config.yaml
```

Checks (offline, no credentials): platform/Python match, wheel imports,
config validity, secret references, secret-file permissions, CA files,
SQLite data files, writable audit/cache paths, per-connection driver
availability.

## Authentication failures by engine

Every row below was a real dead end before the 2026-09-15 audit: the message
named the wrong component, or no config could express the deployment. Symptoms
are quoted as the driver reports them.

| Symptom | What it really means | Fix |
| --- | --- | --- |
| Oracle `DPY-3015: password verifier type 0x939 is not supported` | The account carries only the legacy 10G verifier. Thin mode supports 11G/12C. | DBA: `ALTER USER <u> IDENTIFIED BY <pw>` (and `sec_case_sensitive_logon` must not be FALSE). Or set `options.thick_mode: true` with an administrator-supplied Instant Client. See `docs/oracle-connect-modes.md`. |
| Oracle `ORA-00933` from `db_sample_table` on an old server | `FETCH FIRST` is 12c syntax. | Fixed: sampling uses `ROWNUM`. Upgrade to a build after 2026-09-15. |
| Oracle connect works but `db_test_connection` says unhealthy | The account cannot read `V$VERSION`. | Fixed: liveness no longer needs it; the version is reported as unavailable. |
| Db2 `SQL30082N ... reason "17" (UNSUPPORTED FUNCTION)` | The server refused the security mechanism. Historically this was our own bug (credentials were never sent, fixed in 854b50d). On a current build it is a genuine mismatch. | `db2 get dbm cfg | grep -E 'AUTHENTICATION|SRVCON_AUTH|ALTERNATE_AUTH_ENC'`, then set `options.authentication` (`SERVER`, `SERVER_ENCRYPT`, `SERVER_ENCRYPT_AES`, `KERBEROS`, `GSSPLUGIN`, `TOKEN`, `CERTIFICATE`). |
| Db2 connects nowhere on a 10.5 server | The bundled clidriver is 12.1, which dropped Db2 LUW 10.5. | Upgrade the server, or use a build pinned to ibm_db 3.2.6 or earlier. |
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
| SQLite `file is not a database` | Often an encrypted database (SQLCipher/SEE), which the standard-library driver cannot open. | Decrypt it, or use a build with an encryption extension. Not shipped here. |
| `CONNECTION_ERROR: could not apply the session read-only mode / isolation ... on connection '<id>'` | The session safety profile is fail-closed for read-only (PostgreSQL, MySQL) and isolation (Db2, SQL Server) and the server refused the SET. | Check the server version (MySQL < 5.6.5 has no READ ONLY transactions) and any pooler in between; opt out per connection with `session.enforce_read_only: false` or `session.isolation: cs`/`read_committed`. See `docs/offline-upgrade-rollback.md`. |
| Every `db_*` call fails `CONFIG_ERROR: ... requires TLS` right after adding a connection | `security.require_remote_tls` is on and the connection has no `tls:` block. | Add `tls.enabled` with a `ca_file`. `udbmcp add-connection --tls-ca-file <path>` does this, and the wizard now warns when the policy would refuse. |

## Common failures

| Symptom | Cause | Fix |
| --- | --- | --- |
| `CONFIG_ERROR: ...` on start | config missing/invalid; unknown fields rejected | fix YAML; see config.example.yaml |
| `DRIVER_MISSING: '<engine>' connector requires the pinned driver wheel ...` | optional connector wheel not installed | install from bundle wheelhouse only (`--no-index`); never pip from network |
| `AUTHORIZATION_DENIED: object 'x' could not be resolved` | default-deny object policy | qualify with an allowed schema, or have the admin extend `allowed_schemas` |
| `POLICY_VIOLATION: ... not permitted` | guard denied the statement (DML, unknown function, multi-statement, ...) | use a read statement with permitted objects and bound parameters |
| `TIMEOUT` + "driver exposes no cancellation hook" | engine (MySQL/SQL Server/Db2 path) cannot cancel out-of-band | the connection was discarded; verify server-side session is gone per docs/driver-matrix.md |
| `AUTHORIZATION_DENIED: cursor ... not issued to this caller` | cursor reuse across identities/policy | re-run the listing to get a fresh cursor |
| audit `AuditWriteFailure` / operations refused | `audit_fail_closed=true` and audit path unwritable | restore write access to `application.audit_path` |
| doctor: secret file unsafe permissions | group/world bits on password file | `chmod 600 /run/secrets/<file>` |
| Db2: bundled clidriver missing on import | wrong-profile wheel installed | reinstall from this bundle's wheelhouse; verify profile matches (linux-x86_64-cp312) |
| SQL Server: ODBC Driver not installed | admin-supplied OS package absent | install from bundle `os-packages/` after EULA acceptance |
| `could not apply the session read-only mode ... refusing to run at the server's default level` | the server refused the read-only setting the profile requires (MySQL `SET SESSION TRANSACTION READ ONLY`, PostgreSQL `default_transaction_read_only`, ClickHouse `readonly`) | fix the account or, if the server truly cannot support it, set `connections.<id>.session.enforce_read_only: false` and rely on the SQL guard alone (documented risk) |
| Db2: `WITH RS` / `WITH RR` refused | those isolation clauses hold locks for the statement; the session runs at `UR` for exactly that reason | end the statement in `WITH UR` (or `WITH CS`), or drop the clause |
| ClickHouse: `Cannot modify 'readonly' setting in readonly mode` (old builds) | the account's server profile is already `readonly=1/2` | fixed: the client reads `server_settings` first and keeps the stricter profile; `db_test_connection` reports `read_only (server profile readonly=N)` |

## Log locations

- stdio mode: application logs on stderr; MCP protocol on stdout (never
  mix).
- Audit JSONL: `application.audit_path`; metadata cache:
  `application.metadata_cache_path`.

## Reporting a failure honestly

If a gate cannot run in your environment, record it `blocked`/`not_run`
with the reason in IMPLEMENTATION_STATUS.md. Do not upgrade a claim without
a recorded run in `test-evidence/`.
