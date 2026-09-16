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
| G: upgrade/rollback | local-bundle upgrade, interruption, rollback, state preservation | `scripts/upgrade_offline.sh` / `rollback_offline.sh` | upgrade + rollback passed in a `docker --network none` container (2026-09-12T11:22:01Z, 23/23 checks; evidence: `out/package-evidence/upgrade/`, machine-readable `results.json`); `not_run`: systemd stop/start (no systemd as PID 1 in the container — exercise on a systemd target before release) and the deliberate-interruption sub-case |

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
| Session safety | `test-evidence/session-safety/results.txt` is produced by `scripts/live_evidence.py --config config.mockdbs.yaml` against the local fixtures | every engine `healthy=True` with a `server_reports` block; PostgreSQL, MySQL and ClickHouse refuse `CREATE TABLE`; a Db2 `db_query` reads back `UR` | `test-evidence/session-safety/` |
| Discovery tools | `scripts/live_evidence.py` runs `db_get_catalog`, `db_list_indexes`, `db_profile_table`, `db_infer_relationships`, `db_search_values` through `build_server` against the local fixtures | no tool raises on any fixture engine; search completes within its budget | `test-evidence/discovery-tools/` |
| Version matrix | `scripts/version_matrix/run.sh light|heavy`, `run_mssql.sh`, `run_oracle_thick.sh`; table via `summarize.py` | per image: every check `passed` or `skipped` with a stated design reason; any `failed` is recorded as such in the ledger, never as `not_run` | `test-evidence/version-matrix/*.json` (`probe_rev` names the probe revision) |
