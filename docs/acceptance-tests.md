# Acceptance tests and release gates

Status ledger: `IMPLEMENTATION_STATUS.md`. Machine-readable evidence:
`test-evidence/`. States: `passed`, `failed`, `skipped`, `blocked`, `not_run`.

| Gate | What it proves | How to run | Current status |
| --- | --- | --- | --- |
| A: clean offline install | install/launch/demo/restart from bundle only, network blocked at OS layer | `scripts/test_airgap.sh` | passed (see evidence; amd64-emulation caveat recorded) |
| A-negative | tampered/missing/ABI-mismatch/untrusted-signature/missing-driver all fail fast (verifier's real exit status); hostile-pip: hash-pinned `--no-index --isolated` install succeeds under a hostile `PIP_INDEX_URL` with zero index contact | `scripts/test_airgap_failures.sh` | passed |
| B: no-network protocol | real stdio MCP lifecycle, tools, errors, shutdown, no external deps | inside `test_airgap.sh` (protocol_probe.py) | passed |
| C: isolated internal DBs | real drivers against internal fixtures, no public route | `scripts/test_isolated_integrations.sh` | engine-dependent; see IMPLEMENTATION_STATUS.md |
| D: egress observation | process-level observation of DNS/connect attempts incl. blocked ones | `scripts/observe_egress.sh` | harness provided; requires strace-capable Linux host for a full run |
| E: query/authz security | the spec §14-E battery | `pytest tests/unit tests/integration` + fixture-based denial tests | unit/integration portions passed; DB-side permission denial covered in Gate C fixtures |
| F: client/model end-to-end | pinned Claude Code + internal gateway + GLM, egress blocked | manual, org-specific | not_run (requires organization's client/gateway) |
| G: upgrade/rollback | local-bundle upgrade, interruption, rollback, state preservation, refusal of an older release | `scripts/package/test_upgrade_offline.sh` (drives `upgrade_offline.sh` / `rollback_offline.sh` with ephemeral keys only; `UDBMCP_RELEASE_KEY` is not read) | upgrade + rollback passed in a `docker --network none` container (2026-09-12T11:22:01Z, 23/23 checks; evidence: `out/package-evidence/upgrade/`, machine-readable `results.json`); the `downgrade_refused` check (an older bundle over a newer install must be refused with `rollback refused` and leave the installed manifest unchanged) was added in the 2026-09-27 review and has not been part of a recorded gate run yet; `not_run`: systemd stop/start (no systemd as PID 1 in the container — exercise on a systemd target before release) and the deliberate-interruption sub-case |
| Windows MSI | install, service, doctor, stdio probe, tamper, ACL, token squat, anti-rollback (the release record written, and no rollback copy or marker left beside it), launch conditions, account keeping on repair | `scripts/test_package_msi.ps1` on a real Windows host | `not_run`: no Windows host; the MSI has never been compiled (see `docs/offline-deployment.md`) |
| Container loader release record | `load_images_offline.sh` refuses an older bundle, and a record that is not root's alone, and records the loaded release | `tests/unit/test_hardening_2026_09_27_packaging.py` (the real loader, with a mock `docker`) | unit tests pass; `not_run` on a real container host |
| CI | unit suite (including the MSI custom-action tests under the runner's PowerShell 7: in CI the suite fails, rather than skips them, when `pwsh` is missing), `ruff check src tests scripts`, `mypy --strict src`, `prepare_offline_bundle.py --check-locks`, `pip-audit` over the `uv.lock` export, CI's pinned pip and every shipped lock | `.github/workflows/ci.yml` on push to main and on pull requests (ubuntu-24.04, CPython 3.12) | workflow passes `actionlint` and its steps were replayed locally (arm64 Debian with pwsh 7.4, not the runner image); no run on GitHub has been observed yet |

The recorded runs above, and everything in `test-evidence/` and
`out/package-evidence/`, predate the 2026-09-27/28 review, its fixes and the
2026-09-29 convergence wave (session settings pinned for the guard, new
refusals, audit coalescing, installer staging): re-run
the gates, `scripts/live_evidence.py`, the version matrix and
`scripts/http_client_evidence.py` before a release (`IMPLEMENTATION_STATUS.md`,
§3f).

## Gate C manual procedure (heavy engines)

Oracle/SQL Server/Db2 fixtures need large images and, for Db2, license
acceptance and privileged mode. On the staging machine:

```bash
UDBMCP_TEST_ALLOW_HEAVY=1 bash scripts/test_isolated_integrations.sh
# or follow docs/offline-deployment.md to run fixtures on the internal
# network and export UDBMCP_TEST_<ENGINE>_* env vars before running pytest.
```

Unavailable enterprise instances must be recorded `blocked`/`not_run`.
Mocks do not prove production compatibility.

## Gate D notes

`--network none` proves the absence of successful egress but does not
observe attempts. Use `observe_egress.sh` (strace-based) or your endpoint
detection platform; validate the observation harness itself; a test FAILS
on any unapproved outbound attempt even if the firewall blocked it.

## Adding evidence

Each gate run must write JSON into `test-evidence/<gate>/` — no claims
without a recorded run.

## Discovery, session safety and version matrix (added 2026-09-16)

| Run | Command | Pass criterion | Evidence |
|---|---|---|---|
| Session safety | `test-evidence/session-safety/results.txt` is produced by `scripts/live_evidence.py --config config.mockdbs.yaml` against the local fixtures (export the `UDBMCP_DEMO_*_USER` values `scripts/fixtures/start_mock_dbs.sh` prints; SQL Server connects as the `udbmcp_ro` reader) | every engine `healthy=True` with a `server_reports` block; PostgreSQL, MySQL and ClickHouse refuse `CREATE TABLE`; a Db2 `db_query` reads back `UR` | `test-evidence/session-safety/` |
| Scale | `scripts/scale_evidence.py --config config.scale.yaml` against the `scaledb` database on the PostgreSQL fixture (2,002 tables, a 901-column table, 2,000,000 rows) | every tool answers within its budget; the search reports `tables_not_searched`; the profile warns about its column cap | `test-evidence/scale/` |
| HTTP over TLS | `scripts/http_client_evidence.py` (nginx TLS terminator in Docker, the MCP SDK's streamable HTTP client); the config copy it serves keeps the original's relative paths, so it works with `config.mockdbs.yaml` | initialize, 29 tools, a tool call succeed with the token; wrong or missing token is HTTP 401 before any tool runs | `test-evidence/http-transport/` |
| Site check | `universal_db_mcp site-check --config <config> --out <private dir>/report.json` on any host, run as the account the server runs as (`--out` is written mode 0600, never over an existing file and never through a symlink; `--force` replaces only a regular file you own; write into a `mktemp -d` directory, not a fixed `/tmp` path) | every step ok per connection (explain may be skipped on Db2 without explain tables); the report holds no row value | the JSON report |
| Discovery tools | `scripts/live_evidence.py` runs `db_get_catalog`, `db_list_indexes`, `db_profile_table`, `db_review_schema`, `db_document_schema`, `db_infer_relationships`, `db_search_values` through `build_server` against the local fixtures | no tool raises on any fixture engine; search completes within its budget | `test-evidence/discovery-tools/` |
| Version matrix | `scripts/version_matrix/run.sh light\|heavy`, `run_mssql.sh`, `run_oracle_thick.sh`; table via `summarize.py` | per image: every check `passed` or `skipped` with a stated design reason; any `failed` is recorded as such in the ledger, never as `not_run` | `test-evidence/version-matrix/*.json` (`probe_rev` names the probe revision) |
