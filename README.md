# universal-db-mcp

Read-only, air-gap-deployable MCP server for databases. Claude Code (or any
MCP client) can discover and query administrator-declared connections;
the server never calls an LLM, never installs anything at runtime, and never
requires public internet access.

**Status:** see `IMPLEMENTATION_STATUS.md` for exactly what is implemented,
tested, and blocked. Verified claims are limited to what gates in
`test-evidence/` actually demonstrate.

## Quick start (development)

```bash
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -e '.[dev]'
.venv/bin/python examples/sqlite-demo/create_demo.py   # synthetic fixture
UDBMCP_CONFIG=examples/sqlite-demo/config.yaml .venv/bin/python -m universal_db_mcp serve --transport stdio
```

To register the server with your agents, run `.venv/bin/udbmcp configure-agents`
(see `docs/claude-code-integration.md`). It writes the launch command with
`python -I` (isolated mode), so the package and its dependencies must be
installed in a virtual environment, as above; `pip install --user` or
`PYTHONPATH`-only setups are refused. It registers the system config
(`/etc/universal-db-mcp/config.yaml`, on Windows
`%ProgramData%\UniversalDB MCP\config.yaml`) when your user can read it,
otherwise the per-user `~/.universal-db-mcp/config.yaml`; export an absolute
`UDBMCP_CONFIG` first to choose another. The `.deb` ships the system config
readable by every user, so on a `.deb` host make it `root:udbmcp` 0640 first
(`docs/claude-code-integration.md`).

## Quick start (air-gapped target)

See `docs/offline-deployment.md`, and `docs/site-upgrade-runbook.md` for a
site that installs from a release stick. Short version:

```bash
# staging machine (authorized for network): the bundle is signed with the release
# key (docs/offline-build.md; scripts/package/release_usb.sh builds a whole stick)
python scripts/prepare_offline_bundle.py --profile linux-x86_64-ubuntu24.04-cp312 --out out/bundle \
  --signing-key udbmcp-release.pem

# target machine (offline), after the trust bootstrap in docs/offline-deployment.md,
# which installs the public key once its fingerprint matches one received out of band:
sudo UDBMCP_RELEASE_PUBKEY=/etc/universal-db-mcp/keys/release.pub.pem \
  bash /usr/local/lib/udbmcp-trust/install_offline.sh out/bundle/universal-db-mcp-*/ /opt/universal-db-mcp
# the installer does not create the config: start from the bundle's template, readable by the service only
sudo install -m 640 -o root -g udbmcp out/bundle/universal-db-mcp-*/config-templates/config.yaml /etc/universal-db-mcp/config.yaml
sudo -u udbmcp /opt/universal-db-mcp/venv/bin/python -m universal_db_mcp doctor --config /etc/universal-db-mcp/config.yaml
```

The installers refuse a bundle whose signed `release_seq` is older than the
installed release unless you ask for the downgrade: `--allow-downgrade` for
the scripts, `UDBMCP_ALLOW_DOWNGRADE=1` for the `.deb`, a one-shot flag file
the `.pkg` names, and `UDBMCP_ALLOW_DOWNGRADE=1` for one of this release's
MSIs after uninstalling the newer one (Windows Installer refuses any older
MSI over a newer install; `docs/offline-deployment.md`). In container mode,
`scripts/load_images_offline.sh` keeps a root-owned release record
(`/var/lib/universal-db-mcp/release.json`) and refuses an older bundle the
same way. On the install target the trusted verifier compares with the
installed release even when an installer does not ask it to, so once the
site's trust directory holds this release's verifier, a `.pkg` or `.msi`
built before this check is refused too (an old `.pkg` only after the macOS
Installer has written its files: re-install the current `.pkg` then).

## Security model in brief

Details and limitations: `docs/security.md`.

- **The database login is the primary control.** Give every connection a
  SELECT-only login limited to the schemas you list in `allowed_schemas`.
  The one exception is Db2's `db_explain`, which writes its plan rows into
  the explain tables a DBA provisions, reads them back and deletes them:
  that login also needs INSERT, SELECT and DELETE on those tables, and only
  there (Oracle's plans go to the session-private `PLAN_TABLE`, which needs
  no grant).
  Column-level grants or views are the real protection for sensitive columns.
- **The SQL guard** parses every statement with the connection's dialect and
  accepts one read statement only; anything it cannot parse is refused. Under
  a non-empty `allowed_schemas`, every table in a statement must be
  schema-qualified (database-qualified on MySQL and ClickHouse), because the
  engine would otherwise choose the schema:
  `SELECT * FROM ocean.buoys`, not `SELECT * FROM buoys`. The data-free
  dummy tables are readable in statements on every connection: Oracle's
  `SYS.DUAL` (and a bare `DUAL` where the session resolves it to
  `SYS.DUAL`) and Db2's `SYSIBM.SYSDUMMY1` to `SYSDUMMY4`; nothing else in
  `SYS` or `SYSIBM` opens with them. Views that show other sessions' SQL
  (process lists, statement caches, audit trails), column statistics
  (histograms, low and high values) or stored credentials (password hashes,
  the logins kept for foreign servers and database links) are refused on
  every connection, whatever `allowed_system_schemas` opens. Under
  default-deny (the default), a table name must be spelled as the catalog
  spells it on PostgreSQL, Oracle, Db2 and ClickHouse, and a bare name must
  be in the first schema the session looks bare names up in on PostgreSQL,
  Oracle, SQL Server and Db2.
  `db_list_connections` shows each connection's `allowed_schemas`. The
  metadata, sample and profile tools still accept a bare `object_name`.
- **Plans, never executions.** `db_explain` plans the statement without
  running it (ClickHouse, which evaluates subqueries while it plans, does so
  under a 1000-row read ceiling where the account's profile accepts one, and
  otherwise warns). EXPLAIN ANALYZE is refused whatever
  `security.allow_explain_analyze` says: for `analyze=true`, and for ANALYZE
  written in a PostgreSQL, MySQL, ClickHouse or Db2 statement, the flag only
  chooses the refusal (`POLICY_VIOLATION` while off, `VALIDATION_ERROR` while
  on); Oracle and SQL Server have no ANALYZE form and SQLite cannot parse
  one, so ANALYZE in their statements is `POLICY_VIOLATION` either way. On
  MySQL, a TREE or JSON plan of a statement that names a masked column,
  selects `*` or joins NATURAL is withheld, because MySQL prints the values
  it reads while planning; `FORMAT=TRADITIONAL` plans are returned.
- **Server-side read-only sessions** (on by default) on PostgreSQL,
  MySQL/MariaDB, ClickHouse and SQLite; Db2 at `UR` and SQL Server at
  `READ UNCOMMITTED` so reads take no share locks. There is no write mode:
  `security.read_only: false`, `allow_write_operations: true` and a
  connection's `read_only: false` are rejected when the config loads. Every
  connection also holds the settings that decide how its server reads a
  statement (MySQL `sql_mode`, PostgreSQL `standard_conforming_strings`,
  SQL Server `QUOTED_IDENTIFIER`, ...) at the values the guard parsed
  under, or is refused (`docs/session-safety.md`).
- **Bounded, masked, audited results.** Row, byte, cell and time ceilings;
  sensitive columns masked by where each output value comes from; driver
  error text sanitized; every call audited (repeats of one refusal are
  counted into summary records, and the SQL text kept per window is capped),
  by default to the platform's state directory (`/var/log/universal-db-mcp/audit.jsonl` for the service's
  config, `%ProgramData%\UniversalDB MCP\logs\audit.jsonl` for the Windows
  service's, `~/.universal-db-mcp/audit.jsonl` for a per-user config).
- **stdio is not a security boundary.** A stdio registration runs the server
  as your user inside the agent, so an agent that can run shell commands or
  read files can read the credentials in `~/.universal-db-mcp/secrets/` and
  connect directly, outside the guard. Use SELECT-only logins, or run the
  server in HTTP mode under a separate service account.

## Documentation map

| Document | Purpose |
| --- | --- |
| `docs/architecture.md` | components, data flow, process boundaries, execution limits |
| `docs/security.md` | threat model, policy, masking, audit, secrets, TLS |
| `docs/tools.md` | MCP tool contract (29 `db_*` tools incl. discovery, review, documentation and federated reads for ETL/docs/optimization) |
| `SECURITY.md` | how to report a vulnerability, supported versions, how fixes reach an air-gapped site |
| `site/index.html` | Product landing page, published to GitHub Pages by `.github/workflows/pages.yml` (enable once: Settings > Pages > Source: GitHub Actions). Self-contained: fonts in `site/fonts/` under the SIL Open Font License, social preview `site/og.png`. `tests/unit/test_landing_page.py` re-runs every guard verdict it shows and ties its figures to the tool registry and the evidence |
| `scripts/package/release_usb.sh` | Builds a release for the air-gapped site from the current commit (`UDBMCP_RELEASE_KEY` and `UDBMCP_PUBKEY` are required, or `--demo` for the demo key pair; the public key's fingerprint is printed and shipped as `RELEASE-KEY-FINGERPRINT.txt`): signed bundles, .deb + .pkg through their gates, and the `dist/usb-ubuntu-<sha7>/` folder (trust bootstrap, Oracle client, runbook, `SHA256SUMS` and its signature `SHA256SUMS.sig`) |
| `docs/site-upgrade-runbook.md` | Step-by-step upgrade in place or erase-and-reinstall on the air-gapped Ubuntu site, with the behaviour changes of this release (also shipped on the USB folder as `UPGRADE-README.md`) |
| `docs/session-safety.md` | what every connection does to the server session so agent reads cannot hurt production (Db2 UR, server-side read-only, ceilings) |
| `docs/oracle-connect-modes.md` | Oracle thick mode (legacy password verifiers), SID and TNS alias connections, TLS |
| `docs/db2-tls-setup.md` | Db2 TLS enablement runbook |
| `docs/driver-matrix.md` | per-engine driver/native-dep/test-status matrix |
| `docs/offline-build.md` | Stage A: bundle preparation on the staging machine |
| `docs/offline-deployment.md` | Stage B: install inside the air gap |
| `docs/offline-upgrade-rollback.md` | upgrade/rollback runbook |
| `docs/claude-code-integration.md` | registering the server with Claude Code and other agents (`configure-agents`), internal gateway setup |
| `docs/acceptance-tests.md` | release gates and how to run them |
| `docs/adding-connectors.md` | how to add an engine adapter |
| `docs/troubleshooting.md` | common failures and doctor output |
| `IMPLEMENTATION_STATUS.md` | honest implemented/tested/blocked ledger |
| `scripts/version_matrix/` | per-server-version compatibility runs; results in `test-evidence/version-matrix/` |

## Development and CI

`.github/workflows/ci.yml` runs on every push to `main` and every pull
request (ubuntu-24.04, CPython 3.12): the unit suite, `ruff check src tests
scripts`, `mypy --strict src`, `prepare_offline_bundle.py --check-locks`, and
`pip-audit` over the `uv.lock` export, CI's hash-pinned pip
(`.github/ci-pip-requirements.txt`) and every shipped lock. Each commit on
`main` gets its own result; a newer push to a pull request cancels the older
run. The unit suite also runs the MSI custom-action tests under the runner's
PowerShell 7 (`pwsh`), and in CI it fails rather than skip them when `pwsh`
is missing (elsewhere they skip without it). Actions are pinned to commit
SHAs, and `tests/unit/test_hardening_2026_09_27_ci_hygiene.py` pins them too,
so a Dependabot bump of `actions/checkout` or `astral-sh/setup-uv` fails
until the new commit is reviewed and `_SETUP_ACTIONS` updated. The same test
keeps the pytest options in `pyproject.toml` (`[tool.pytest.ini_options]`,
output flags only), keeps `.github/ci-pip-requirements.txt` to comment lines
and one `pip==` pin with its sha256 hashes, in printable ASCII with no
coding declaration (pip and pip-audit honour one; uv does not), and keeps the
tree free of symlinks, compiled files, tool caches, `.pyi` stubs and package
archives (`.whl`, `.egg`, `.zip`, sdists). Every Python source under `src/`,
`tests/` and `scripts/` is UTF-8. `conftest.py` files and the other non-test
modules under `tests/` define no pytest hooks or `collect_ignore`, skip or
xfail nothing, declare no autouse fixtures, import no test module, no
`_pytest` and none of the import and exec machinery (`importlib`, `runpy`,
`builtins`, `pydoc`, `pickle`, `shelve`, frame `f_builtins`, ...), end no
run early (`SystemExit`, `quit`), store no attribute named `obj`, `_obj`,
`runtest` or `function` (how pytest runs a test), and write to no module's
namespace (`setattr`, `globals()`,
`monkeypatch.setattr`); a test module that needs to skip its
tests does so itself. Code outside `tests/` imports no pytest and declares
no autouse fixture. The test is a tripwire, not a sandbox: it runs inside
the pytest run it guards, so a change that stops it being collected switches
it off, and changes to conftests, test helpers and CI files still need a
reviewer. To match CI locally after `uv sync`, run
`uv pip install --python .venv/bin/python --require-hashes -r .github/ci-pip-requirements.txt`
(the bundle-builder tests skip without pip). After a Dependabot bump of
`requirements/runtime.in`, refresh and review the locks
(`docs/offline-build.md`).

## Reporting a vulnerability

Please report security issues privately through GitHub private vulnerability
reporting, never in a public issue. `SECURITY.md` says what to include and
how fixes reach air-gapped sites. The project is maintained by the
universal-db-mcp maintainers and publishes no e-mail address: the one in the
`.deb`'s Maintainer field, which Debian requires, is a placeholder under the
reserved `.invalid` domain and reaches no one.

## License

Apache-2.0. See `LICENSE` and `NOTICE`. Both ship in the wheel and in the
offline bundle's `licenses/` directory; the `.deb` states the license in its
DEP-5 `/usr/share/doc/universal-db-mcp/copyright` file, with `NOTICE` beside
it. Third-party components keep their own licenses: the bundle lists them in
`sbom/cyclonedx.json`, and each wheel in its `wheelhouse/` carries its license
files.
