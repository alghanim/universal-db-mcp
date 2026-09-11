# Troubleshooting

## Doctor is the first stop

```bash
/opt/universal-db-mcp/venv/bin/python -m universal_db_mcp doctor --config /etc/universal-db-mcp/config.yaml
```

Checks (offline, no credentials): platform/Python match, wheel imports,
config validity, secret references, secret-file permissions, CA files,
SQLite data files, writable audit/cache paths, per-connection driver
availability.

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

## Log locations

- stdio mode: application logs on stderr; MCP protocol on stdout (never
  mix).
- Audit JSONL: `application.audit_path`; metadata cache:
  `application.metadata_cache_path`.

## Reporting a failure honestly

If a gate cannot run in your environment, record it `blocked`/`not_run`
with the reason in IMPLEMENTATION_STATUS.md. Do not upgrade a claim without
a recorded run in `test-evidence/`.
