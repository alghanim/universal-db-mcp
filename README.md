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

## Quick start (air-gapped target)

See `docs/offline-deployment.md`. Short version:

```bash
# staging machine (authorized for network):
python scripts/prepare_offline_bundle.py --profile linux-x86_64-ubuntu24.04-cp312 --out out/bundle

# target machine (offline):
scripts/install_offline.sh out/bundle/universal-db-mcp-*/ /opt/universal-db-mcp
/opt/universal-db-mcp/venv/bin/python -m universal_db_mcp doctor
```

## Documentation map

| Document | Purpose |
| --- | --- |
| `docs/architecture.md` | components, data flow, process boundaries |
| `docs/security.md` | threat model, policy, secrets, TLS |
| `docs/tools.md` | MCP tool contract (29 `db_*` tools incl. discovery, review, documentation and federated reads for ETL/docs/optimization) |
| `site/index.html` | Product landing page, published to GitHub Pages by `.github/workflows/pages.yml` (enable once: Settings > Pages > Source: GitHub Actions). Self-contained: fonts in `site/fonts/` under the SIL Open Font License, social preview `site/og.png`. `tests/unit/test_landing_page.py` re-runs every guard verdict it shows and ties its figures to the tool registry and the evidence |
| `scripts/package/release_usb.sh` | Builds a release for the air-gapped site from the current commit (`UDBMCP_RELEASE_KEY` and `UDBMCP_PUBKEY` are required, or `--demo` for the demo key pair; the public key's fingerprint is printed and shipped as `RELEASE-KEY-FINGERPRINT.txt`): signed bundles, .deb + .pkg through their gates, and the `dist/usb-ubuntu-<sha7>/` folder (trust bootstrap, Oracle client, runbook, SHA256SUMS) |
| `docs/site-upgrade-runbook.md` | Step-by-step upgrade in place or erase-and-reinstall on the air-gapped Ubuntu site (also shipped on the USB folder as `UPGRADE-README.md`) |
| `docs/session-safety.md` | what every connection does to the server session so agent reads cannot hurt production (Db2 UR, server-side read-only, ceilings) |
| `docs/oracle-connect-modes.md` | Oracle thick mode (legacy password verifiers), SID and TNS alias connections, TLS |
| `docs/db2-tls-setup.md` | Db2 TLS enablement runbook |
| `docs/driver-matrix.md` | per-engine driver/native-dep/test-status matrix |
| `docs/offline-build.md` | Stage A: bundle preparation on the staging machine |
| `docs/offline-deployment.md` | Stage B: install inside the air gap |
| `docs/offline-upgrade-rollback.md` | upgrade/rollback runbook |
| `docs/claude-code-integration.md` | Claude Code + internal gateway setup |
| `docs/acceptance-tests.md` | release gates and how to run them |
| `docs/adding-connectors.md` | how to add an engine adapter |
| `docs/troubleshooting.md` | common failures and doctor output |
| `IMPLEMENTATION_STATUS.md` | honest implemented/tested/blocked ledger |
| `scripts/version_matrix/` | per-server-version compatibility runs; results in `test-evidence/version-matrix/` |
