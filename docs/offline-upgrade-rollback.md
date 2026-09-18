# Offline upgrade and rollback runbook

## Upgrade

Sites installed from the **.deb** upgrade with `dpkg -i` of the new package
(the command-by-command procedure, including the mandatory trust-tools
refresh and the deferred-install status check, is `docs/site-upgrade-runbook.md`,
shipped on the release stick as `UPGRADE-README.md`). Since 2026-09-18 the
trusted installer builds the new venv beside the running one and switches
with two renames, so a `.deb` upgrade also leaves `venv.previous` and its
integrity manifest behind and `rollback_offline.sh` works there too. The
procedure below is the bundle-level path for hosts installed directly from
a signed bundle.

```bash
# 1. acquire the NEW signed bundle (staging) and transfer into the air gap
# 2. preflight + install (atomic venv switch, config/state backup first)
#    Run the TRUSTED copy of the script (shipped in the release's
#    trusted-tools/ directory, same channel as the release public key).
#    The bundle's operations/ copy CANNOT be used: it refuses to run from
#    inside the bundle being verified, and the bundle ships no lib/ helper
#    beside it. Requires the trust bootstrap (trusted verifier installed at
#    /usr/local/lib/udbmcp-trust) from docs/offline-deployment.md.
sudo env UDBMCP_RELEASE_PUBKEY=/etc/universal-db-mcp/keys/release.pub.pem \
  bash <trusted-channel>/upgrade_offline.sh <new-bundle-dir> /opt/universal-db-mcp
# 3. validate (doctor has no default config path and sudo strips
#    UDBMCP_CONFIG, so pass --config explicitly)
sudo -u udbmcp /opt/universal-db-mcp/venv/bin/python -m universal_db_mcp doctor \
  --config /etc/universal-db-mcp/config.yaml
sudo systemctl restart universal-db-mcp
```

Properties:

- The old venv is preserved at `/opt/universal-db-mcp/venv.previous`, together
  with a SHA256 integrity manifest at `/opt/universal-db-mcp/venv.previous.sha256`,
  recorded BEFORE the rename (an upgrade interrupted between the two
  operations still leaves a verifiable tree).
- Configuration and metadata cache are backed up to
  `/var/backups/universal-db-mcp/pre-upgrade-<ts>/`.
- An upgrade killed BETWEEN the two venv switch renames (the only window with
  no venv in place) is recovered automatically: the script's exit trap
  restores `venv.previous`, so the service can start again without manual
  help. An upgrade killed EARLIER (during pip, before any switch) leaves the
  running venv untouched and its timestamped `venv.new-*` directory behind;
  re-running the script discards stale `venv.new-*` directories before
  building the new one, so no manual cleanup is needed. (Concurrent upgrades
  are not supported — the script assumes any pre-existing `venv.new-*` is
  debris from an earlier failed attempt.)
- Dependencies are installed ONLY from the new bundle's hashed wheelhouse.
- `upgrade_offline.sh` REQUIRES `UDBMCP_RELEASE_PUBKEY` and verifies the new
  bundle's signature before touching anything. `rollback_offline.sh` does NOT
  verify a bundle signature — the original signed bundle is not present on
  the host at rollback time, so no check on that path can re-anchor the
  payload to the bundle signature; its guarantee is the integrity-manifest
  gate described below.

## Behavior changes on upgrade: the session safety profile (2026-09-16)

Every connection now applies a session safety profile right after it
connects (`docs/session-safety.md`). The defaults change what an EXISTING
deployment does after this upgrade, and two of them are fail-closed, so a
connection that worked before can be refused afterwards until the config
says otherwise. Read this before upgrading a production site.

| Engine | New default behavior | Fails closed if the server refuses it |
|---|---|---|
| Db2 (read-only connections) | `SET CURRENT ISOLATION = UR` | yes |
| SQL Server (read-only connections) | `SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED` | yes |
| PostgreSQL | `SET default_transaction_read_only = on` | yes |
| MySQL / MariaDB | `SET SESSION TRANSACTION READ ONLY` | yes |
| ClickHouse | `readonly=1` pinned on the client after reading the account's server profile; accounts already at `readonly=1`/`2` keep their stricter profile | yes, only when a writable account refuses the setting (never for read-only profiles) |
| all | lock-wait ceiling 5 s; statement ceiling = `security.hard_query_timeout_seconds`; a named session | no (best-effort, recorded as `skipped`) |

What changes for an existing deployment, precisely:

1. **Scope.** Every connection with `read_only: true` (the default) gets the
   profile with no config change.
2. **Fail-closed settings.** PostgreSQL and MySQL/MariaDB server-side
   read-only, and Db2/SQL Server isolation. A refusal surfaces as
   `CONNECTION_ERROR: could not apply the session <setting> on connection
   '<id>' ...; refusing to run at the server's default level`. None of these
   statements needs a privilege on a supported version; the realistic
   refusals are a MySQL older than 5.6.5 or MariaDB older than 10.0 (no
   `READ ONLY` transactions) and a proxy that rejects session `SET`s.
3. **Semantics.** Db2 `UR` and SQL Server `READ UNCOMMITTED` return rows
   other transactions have not committed. Consumers who need committed reads
   (finance reconciliation, audit) must set `session.isolation: cs` /
   `read_committed` and accept the locking that comes with it.
4. **New server-side timeouts.** Statements are now cancelled by the server
   at `security.hard_query_timeout_seconds` (`statement_timeout`,
   `max_execution_time` / `max_statement_time`, `QUERYTIMEOUT`,
   `call_timeout`, the ODBC query timeout), and a 5 s lock ceiling means a
   PostgreSQL `SELECT` queued behind an `ACCESS EXCLUSIVE` lock (an `ALTER`,
   a `VACUUM FULL`) errors instead of waiting.
5. **Connection poolers.** Behind PgBouncer in transaction/statement mode or
   ProxySQL multiplexing, a session `SET` lands on one backend while later
   statements run on another: the profile reports `read_only_enforced: true`
   but is not in effect. Use session pooling, or point the server at the
   database directly.
6. **Read-back gaps.** MariaDB 10.6 and older cannot read back the
   read-only or isolation variables (`read_only_verified: null`).
7. **Session identity.** Sessions now appear as `udbmcp:<connection id>` in
   `pg_stat_activity`, `v$session`, `sys.dm_exec_sessions` and Db2
   `LIST APPLICATIONS`; monitoring allowlists may need the new name.
8. **Tool output.** `db_test_connection` gained a `session` block.

Before upgrading, run the new build's `udbmcp doctor` against the current
config: it prints the resolved profile per connection (`session-<id>`
checks) so you can see which connection will run at which level. After
upgrading, `db_test_connection` returns `session.server_reports`, what the
server itself answered.

Opt-outs, per connection, when a site needs the old behavior:

```yaml
connections:
  finance_db2:
    session:
      isolation: cs               # keep committed reads (and the share locks that come with them)
      enforce_read_only: false    # do not ask the server for a read-only session
      lock_timeout_seconds: null  # server default instead of 5 s
      statement_timeout_from_policy: false
```

The SQL guard remains the write enforcement in every configuration; these
settings only change what the server session does around it.

Other behavior changes in the same release (2026-09-16):

- **Db2 `WITH RS` / `WITH RR` are refused** on read-only connections
  (`POLICY_VIOLATION`): both hold locks for the statement, which is exactly
  what the `UR` session exists to prevent. `WITH UR`, `WITH CS`,
  `FOR READ ONLY`/`FOR FETCH ONLY` and `OPTIMIZE FOR n ROWS` are accepted
  and stripped before the guard parses the statement.
- **Whole-connection `db_get_catalog` and `db_list_indexes` hide system
  catalogs** (Oracle dictionary views and `SYS*` owners, Db2 `SYSCAT`/`SYSIBM`,
  `pg_catalog`, `information_schema`, ClickHouse `system`, ...) unless
  `include_system: true` or a system schema is named explicitly. A tool
  consumer that relied on those objects appearing in the first page must
  now ask for them.
- **`object_name` accepts `schema.table`** everywhere (a relaxation: those
  names were denied before). A three-part `db.schema.table` name and a
  `schema` argument that disagrees with the qualified name are validation
  errors.
- **`lock_timeout_seconds` reads back `null` on Oracle and ClickHouse**,
  where no session-level lock-wait ceiling exists; previously the configured
  number was echoed although nothing enforced it.

## Rollback

```bash
sudo bash <bundle>/operations/rollback_offline.sh /opt/universal-db-mcp
sudo systemctl restart universal-db-mcp
```

Restores the previous venv. The venv swap is always performed; restoring the
latest config/state backup OVERWRITES live state (which may hold post-upgrade
edits made after that backup was taken), so it requires the explicit
`--restore-config` flag. Without it the script reports the existing backup
and leaves the live configuration untouched (venv-only rollback). With it,
the backup is validated through the restored venv before anything is
displaced, and the live configuration is moved aside (never deleted) to
`/var/backups/universal-db-mcp/pre-rollback-<ts>/`:

```bash
sudo bash <bundle>/operations/rollback_offline.sh /opt/universal-db-mcp --restore-config
```

Trust discipline (fail closed): rollback executes `venv.previous` (the doctor
validation) only after re-hashing the tree against an integrity manifest,
with two references, strongest first:

1. the EXTERNAL anchor `/etc/universal-db-mcp/venv-rollback.sha256` — outside
   the swap tree, written by a previous verified rollback, authoritative when
   present (a writer of `venv.previous` cannot regenerate it there);
2. failing that, the co-located `/opt/universal-db-mcp/venv.previous.sha256`
   recorded by `upgrade_offline.sh` BEFORE the demote rename — a weaker
   fallback that closes drift/corruption/interrupted-upgrade cases only,
   since it shares a writable root with the tree it authenticates.

A missing or mismatched manifest aborts the rollback BEFORE any rename and
BEFORE anything under the tree is executed; `venv.previous` is preserved for
analysis. Recover by re-running `upgrade_offline.sh` (which rebuilds both the
venv and its manifest) or by reinstalling from the signed bundle. If the
external anchor is present but stale (it describes a release that is no longer
the demoted `venv.previous` — note `upgrade_offline.sh` never writes it), the
co-located manifest still describes that tree; after confirming out of band
that `venv.previous` is the legitimate demoted release, re-run
`rollback_offline.sh` with the explicit `--re-anchor` opt-in to re-verify
against the co-located manifest (which shares the tree's writable root — the
documented residual) and rewrite the external anchor on success.

## Importing security fixes

Security updates enter the air gap the same way as releases: a refreshed
signed bundle built on the staging machine with re-scanned SBOM/vulnerability
data. Record the scan date; do not assume offline scan databases stay
current. Never "hotfix" dependencies inside the air gap by downloading.

## Evidence expectations

Record upgrade/rollback exercises (success + deliberate-interruption) in
`test-evidence/` per docs/acceptance-tests.md §G.
