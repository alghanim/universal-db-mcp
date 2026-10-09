<h1 align="center">universal-db-mcp</h1>

<p align="center">
  <a href="https://github.com/alghanim/universal-db-mcp/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/alghanim/universal-db-mcp/ci.yml?branch=main&label=CI"></a>
  <a href="LICENSE"><img alt="license: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-4c1"></a>
  <a href="pyproject.toml"><img alt="python: 3.12" src="https://img.shields.io/badge/python-3.12-3776ab"></a>
  <a href="docs/tools.md"><img alt="MCP: 29 tools" src="https://img.shields.io/badge/MCP-29%20tools-6f42c1"></a>
  <a href="#what-it-does"><img alt="databases: 8" src="https://img.shields.io/badge/databases-8-e67e22"></a>
  <a href="#how-it-keeps-the-databases-safe"><img alt="access: read-only" src="https://img.shields.io/badge/access-read--only-0e8a7d"></a>
  <a href="#install-on-an-air-gapped-site"><img alt="install: offline-ready" src="https://img.shields.io/badge/install-offline--ready-5b5bd6"></a>
</p>

<p align="center">
  <a href="#quick-start-development">Quick start</a> ·
  <a href="docs/tools.md">Tools</a> ·
  <a href="docs/security.md">Security model</a> ·
  <a href="#install-on-an-air-gapped-site">Air-gapped install</a> ·
  <a href="#documentation-map">Docs</a> ·
  <a href="https://alghanim.github.io/universal-db-mcp/">Landing page</a> ·
  <a href="SECURITY.md">Report a vulnerability</a>
</p>

A read-only, air-gap-deployable [MCP](https://modelcontextprotocol.io) server
for databases. Claude Code, or any MCP client, can discover, document,
profile, search and query the database connections an administrator declares,
and nothing else. The server never writes to a database, never calls an LLM,
never installs anything at runtime, and never needs public internet access.

**Status:** hardened through a production security review and three follow-up
code reviews (2026-09/10). `IMPLEMENTATION_STATUS.md` is the honest ledger of
what is implemented, what is verified and how, and what is still open; claims
here are limited to what its gates and `test-evidence/` demonstrate.

## What it does

**Engines** (each version below passes the version matrix,
`scripts/version_matrix/`, results in `test-evidence/version-matrix/`):

| Engine | Verified versions |
| --- | --- |
| PostgreSQL | 12, 13, 14, 15, 16, 17 |
| MySQL / MariaDB | MySQL 5.7, 8.0, 8.4; MariaDB 10.6, 11.4 |
| ClickHouse | 23.8, 24.3, 24.8, 25.3 |
| Oracle | 18c, 21c, 23 (thin mode); 11g, 18c, 23 (thick mode, for legacy password verifiers) |
| SQL Server | 2017, 2019, 2022 |
| Db2 | 11.5.8, 11.5.9 |
| SQLite | the CPython build's SQLite |

**29 tools** (`docs/tools.md` is the contract):

- **Connections:** `db_list_connections`, `db_test_connection`, `db_get_capabilities`.
- **Catalog:** `db_list_catalogs`, `db_list_databases`, `db_list_schemas`,
  `db_list_tables`, `db_get_table`, `db_list_columns`, `db_list_views`,
  `db_list_synonyms`, `db_list_routines`, `db_list_indexes`,
  `db_get_relationships`, `db_get_statistics`, `db_search_metadata`,
  `db_get_catalog`.
- **Reading data:** `db_validate_query`, `db_query`, `db_sample_table`,
  `db_explain` (plans, never executions), `db_get_query_history`.
- **Discovery, review and documentation:** `db_profile_table`,
  `db_search_values` (find a value across tables and connections without
  writing SQL), `db_infer_relationships`, `db_review_schema` (prioritized
  optimization findings), `db_document_schema` (Markdown data dictionary).
- **Federated reads:** `db_federated_query` (one statement, or one per
  connection, merged) and `db_federated_join` (a bounded hash join across two
  connections).

## How it keeps the databases safe

Defence in depth; details and limitations in `docs/security.md` and
`docs/session-safety.md`.

1. **The database login is the primary control.** Give every connection a
   SELECT-only login limited to the schemas you list in `allowed_schemas`.
   The one exception is Db2's `db_explain`, which writes its plan rows into
   the explain tables a DBA provisions, reads them back and deletes them:
   that login also needs INSERT, SELECT and DELETE on those tables, and only
   there (Oracle's plans go to the session-private `PLAN_TABLE`, which needs
   no grant). Column-level grants or views are the real protection for
   sensitive columns.
2. **Read-only sessions.** On by default and enforced by the server itself on
   PostgreSQL, MySQL/MariaDB, ClickHouse and SQLite; Db2 runs at `UR` and SQL
   Server at `READ UNCOMMITTED`, so reads take no share locks. There is no
   write mode: `security.read_only: false`, `allow_write_operations: true` and
   a connection's `read_only: false` are rejected when the config loads. Every
   session is also pinned to the settings that decide how its server lexes a
   statement (MySQL `sql_mode`, PostgreSQL `standard_conforming_strings`, SQL
   Server `QUOTED_IDENTIFIER`, ...), so the server reads exactly what the
   guard parsed.
3. **The SQL guard** parses every statement in the connection's dialect and
   accepts one read statement only; anything it cannot parse is refused.
   Under a non-empty `allowed_schemas`, every table must be schema-qualified
   (`SELECT * FROM ocean.buoys`, not `SELECT * FROM buoys`), because the
   engine would otherwise choose the schema. On Oracle, Db2 and PostgreSQL,
   CTE names and unquoted table names must be ASCII. Views that show other
   sessions' SQL, column statistics or stored credentials are refused whatever
   `allowed_system_schemas` opens; Oracle's `SYS.DUAL` and Db2's
   `SYSIBM.SYSDUMMY1` to `SYSDUMMY4` are always readable. Bound parameters
   reach the driver exactly as validated.
4. **Masking that refuses what it cannot prove.** Columns matching the
   sensitive patterns (built in, plus `security.mask_columns`) are masked by
   where each output value comes from. A statement over a table with masked
   columns is accepted only in shapes the analysis fully proves (columns,
   expressions, aggregates, window functions, joins, CTEs, subqueries,
   unions, `*` over listed tables); anything else is refused before it runs,
   with the construct named. Predicates are not masked: a `WHERE` on a masked
   column can still narrow results.
5. **Bounded, sanitized, audited.** Row, byte, cell and time ceilings; a
   per-query memory cap on ClickHouse (2 GiB by default,
   `options.max_memory_usage`); size caps checked before any parsing; driver
   error text sanitized. Every call is audited, by default to the platform's
   state directory (`/var/log/universal-db-mcp/audit.jsonl` for the service's
   config, `%ProgramData%\UniversalDB MCP\logs\audit.jsonl` on Windows,
   `~/.universal-db-mcp/audit.jsonl` for a per-user config).
6. **stdio is not a security boundary.** A stdio registration runs the server
   as your user inside the agent, so an agent that can run shell commands or
   read files can read the credentials in `~/.universal-db-mcp/secrets/` and
   connect directly, outside the guard. Use SELECT-only logins, or run the
   server in HTTP mode (bearer token, behind your reverse proxy) under a
   separate service account.

## Quick start (development)

```bash
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -e '.[dev]'
.venv/bin/python examples/sqlite-demo/create_demo.py   # synthetic fixture
UDBMCP_CONFIG=examples/sqlite-demo/config.yaml .venv/bin/python -m universal_db_mcp serve --transport stdio
```

Register the server with your agents with `.venv/bin/udbmcp configure-agents`
(Claude Code, Claude Desktop, Cursor, VS Code, Cline and others;
`docs/claude-code-integration.md`). It writes the launch command with
`python -I` (isolated mode), so the package and its dependencies must be
installed in a virtual environment, as above; `pip install --user` or
`PYTHONPATH`-only setups are refused. It registers the system config
(`/etc/universal-db-mcp/config.yaml`, on Windows
`%ProgramData%\UniversalDB MCP\config.yaml`) when your user can read it,
otherwise the per-user `~/.universal-db-mcp/config.yaml`; export an absolute
`UDBMCP_CONFIG` first to choose another. The `.deb` ships the system config
readable by every user, so on a `.deb` host make it `root:udbmcp` 0640 first
(`docs/claude-code-integration.md`).

`udbmcp add-connection` adds a connection interactively and stores its
secrets with private permissions; `udbmcp doctor` checks a config, its
secrets and (with `--connectivity`) every database.

## A minimal connection

```yaml
connections:
  sales:
    type: postgres
    host: pg.example.internal
    port: 5432
    database: sales
    username_file: /etc/universal-db-mcp/secrets/sales.user   # 0600, owned by the service account
    password_file: /etc/universal-db-mcp/secrets/sales.pw
    allowed_schemas: [reporting]
    tls:
      enabled: true
      ca_file: /etc/universal-db-mcp/ca/internal-ca.pem
```

`config.example.yaml` documents every setting, per engine.

## Install on an air-gapped site

| Artifact | Platform | Status |
| --- | --- | --- |
| `.deb` | Ubuntu 24.04 x86-64 | release gate: install, upgrade, rollback and refusal cases with no network |
| `.pkg` | macOS arm64 | release gate passes; unsigned (no Developer ID yet) |
| `.msi` | Windows x64 | compiles with WiX and its custom actions are tested under PowerShell; never run on a Windows host yet |
| offline bundle | any of the above | signed with the release key; `scripts/install_offline.sh` |

See `docs/offline-deployment.md`, and `docs/site-upgrade-runbook.md` for a
site that installs from a release stick (`scripts/package/release_usb.sh`
builds one). Short version:

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

Nothing from a bundle or stick runs before its Ed25519 signature is checked
against the installed release key. The installers refuse a bundle whose
signed `release_seq` is older than the installed release unless you ask for
the downgrade: `--allow-downgrade` for the scripts, `UDBMCP_ALLOW_DOWNGRADE=1`
for the `.deb`, a one-shot flag file the `.pkg` names, and
`UDBMCP_ALLOW_DOWNGRADE=1` for one of this release's MSIs after uninstalling
the newer one (Windows Installer refuses any older MSI over a newer install).
In container mode, `scripts/load_images_offline.sh` keeps a root-owned release
record (`/var/lib/universal-db-mcp/release.json`) and refuses an older bundle
the same way.

## Verification

- **Tests:** over 12,000 unit tests, run by GitHub Actions CI on
  ubuntu-24.04 and locally on macOS; ruff and `mypy --strict` clean.
  `IMPLEMENTATION_STATUS.md` (section 3f) records the latest counts.
- **Real databases:** the version matrix above, and
  `scripts/live_evidence.py` against the mock databases of
  `scripts/fixtures/start_mock_dbs.sh` (`docs/mock-environment.md`).
- **Packages:** the `.deb` and `.pkg` release gates and the offline upgrade
  gate (`docs/acceptance-tests.md`).
- **Supply chain:** pinned, hash-checked locks for every platform, checked
  with pip-audit.

Not yet verified anywhere: the MSI on a real Windows host and a real macOS
Installer run of the `.pkg`.

## Development

```bash
.venv/bin/python -m pytest -o addopts='' -q tests                 # the whole suite
UDBMCP_LIVE_FIXTURES=1 UDBMCP_DOCKER_TESTS=1 \
  .venv/bin/python -m pytest -o addopts='' -q tests               # plus the live-database and container tests
.venv/bin/ruff check src tests scripts && .venv/bin/mypy --strict src
```

Tests that use the local mock databases run only with
`UDBMCP_LIVE_FIXTURES=1`, so a package gate never waits on a paused or absent
database; the real-`dpkg` container sequences run only with
`UDBMCP_DOCKER_TESTS=1`. The bundle-builder tests need pip in the venv: after
`uv sync`, run
`uv pip install --python .venv/bin/python --require-hashes -r .github/ci-pip-requirements.txt`.

**CI.** `.github/workflows/ci.yml` is a GitHub Actions workflow (ubuntu-24.04,
CPython 3.12): the unit suite (including the MSI custom-action tests under
`pwsh`), ruff, `mypy --strict`, `prepare_offline_bundle.py --check-locks`, and
pip-audit over every lock. Actions are pinned to commit SHAs. It runs on
every pull request and every push to `main`, in two jobs at once: the slowest
installer and packaging test files run in `installer-tests`, and `checks`
runs the rest and every other check. `.github/workflows/audit.yml` runs the
same pip-audit every week, so a new advisory fails a run between commits too.
Dependabot proposes grouped updates monthly.
`tests/unit/test_hardening_2026_09_27_ci_hygiene.py` guards the CI setup
itself (pinned actions, pytest options, the two jobs together running every
test once, no skips or hooks hidden in conftests or helpers, no compiled or
symlinked files in the tree); it is a tripwire, not a sandbox, so changes to
conftests, test helpers and CI files still need a reviewer. After a
Dependabot bump of `requirements/runtime.in`, refresh and review the locks
(`docs/offline-build.md`).

## Documentation map

| Document | Purpose |
| --- | --- |
| `docs/architecture.md` | components, data flow, process boundaries, execution limits |
| `docs/security.md` | threat model, policy, masking, audit, secrets, TLS |
| `docs/tools.md` | the MCP tool contract (29 `db_*` tools) |
| `docs/session-safety.md` | what every connection does to the server session so agent reads cannot hurt production |
| `docs/driver-matrix.md` | per-engine drivers, native dependencies, provisioning SQL, test status |
| `docs/oracle-connect-modes.md` | Oracle thick mode (legacy password verifiers), SID and TNS alias connections, TLS |
| `docs/db2-tls-setup.md` | Db2 TLS enablement runbook |
| `docs/claude-code-integration.md` | registering the server with Claude Code and other agents, internal gateway setup |
| `docs/offline-build.md` | Stage A: bundle preparation on the staging machine |
| `docs/offline-deployment.md` | Stage B: install inside the air gap (`.deb`, `.pkg`, `.msi`, bundle, containers) |
| `docs/offline-upgrade-rollback.md` | upgrade and rollback |
| `docs/site-upgrade-runbook.md` | step-by-step site upgrade, with this release's behaviour changes (shipped on the stick as `UPGRADE-README.md`) |
| `docs/acceptance-tests.md` | release gates and how to run them |
| `docs/mock-environment.md` | the local mock databases used for live evidence |
| `docs/adding-connectors.md` | how to add an engine adapter |
| `docs/troubleshooting.md` | common failures and `doctor` output |
| `IMPLEMENTATION_STATUS.md` | the implemented / verified / open ledger |
| `SECURITY.md` | how to report a vulnerability, supported versions, how fixes reach an air-gapped site |
| `site/index.html` | the product landing page, published by `.github/workflows/pages.yml` (`tests/unit/test_landing_page.py` re-runs every guard verdict it shows) |

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
