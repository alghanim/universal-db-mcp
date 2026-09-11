# Implementation status (honest ledger)

Last updated: 2026-09-11 (second production-readiness review + fix pass:
4 reproduced P0 defects and 36 reproduced P1 defects fixed across the
codebase, gates and bundle re-run green — see §1c; the 2026-09-08
ledger-honesty revision and its residual P1 disclosure in §1b remain in
force).
Every `passed` claim below points at machine-readable evidence in
`test-evidence/`. Claims without evidence are labeled `unverified`,
`blocked`, or `not_run`.

## 1. Implemented AND verified (evidence recorded)

| Item | Evidence |
| --- | --- |
| SQLite MCP server, full 20-tool surface, read-only, bounded execution | `test-evidence/airgap-gateAB/protocol-probe.json` (real stdio MCP session: initialize, 20 tools listed, discovery, query, masking, write denial, sample, capabilities, explain, history) |
| Gate B — no-network protocol test (pinned MCP SDK client, no npm/browser) | same, run inside `docker --network none` container |
| Gate A — clean offline installation from bundle only (verify → install → doctor → demo → restart) | `test-evidence/airgap-gateAB/airgap-test-results.json`, `doctor.json` (run 2026-09-08T13:30Z; **caveat:** amd64 userland under Docker Desktop emulation on the staging host; artifacts are genuine x86_64) |
| Gate A-negative — tampered wheel, missing wheel, wrong-ABI wheel, untrusted signature, missing licensed driver, hostile inherited pip config: all fail fast with no download attempts; each fail_fast case requires nonzero exit AND its expected actionable diagnostic (a classifier that credited any nonzero exit was fixed 2026-09-11); the untrusted-signature case now fails closed if no foreign signature can be produced (a vacuous pass with the original trusted SIGNATURE still in place was reproduced and fixed), and the verifier emits the canonical `signature verification FAILED` diagnostic on every rejection path including OpenSSL-3-only hosts — re-run 2026-09-11: **6/6 passed** | `test-evidence/airgap-failure-modes/results.json` + per-case `*.json` and `*.output.txt` |
| Gate C — real-driver integration on a Docker `--internal` network (fixtures AND client attached; no external route), each engine carrying DISTINCT themed mock data: PostgreSQL (oceanographic buoys; health, query, schemas, **DB-side permission-denial proof**), MySQL (coffee roastery), ClickHouse (250k telecom call data records), **Oracle (air travellers — passed)**, **SQL Server (hospital admissions — passed)** — re-run 2026-09-11 with heavy fixtures enabled: **11 passed, 0 failed, 2 skipped**; IBM Db2 fixture starts, seeds, and authenticates over loopback TCP with its own clidriver, but the pinned `ibm_db` client fails under amd64 emulation on this staging host (server verified up to TCP auth) → recorded `blocked`; TLS is the documented remediation but the no-TLS fixtures cannot exercise it | `test-evidence/integration-gateC/integration-run.log`, `results.json` |
| Unit battery: SQL guard (modify-CTE, multi-statement, SELECT INTO, executable comments, unknown/dangerous functions, table functions, ATTACH/PRAGMA, dblink/`@`-refs, locking clauses, SETTINGS args, SHOW allowlists, EXPLAIN policies, object resolution), executor deadline/poison semantics + driver-timeout discrimination, byte/cell truncation reporting, masking omit, parameter-injection-as-data, metadata prompt-injection inertness, cursor kind/policy rebinding, config strictness/edge cases, secrets/`SecretMark`, redaction, fingerprints, audit fail-closed/rotation, metadata cache scoping, SQLite read-only backstop + limits, catalog-SQL placeholder safety (postgres `%` escaping in parametrized queries) — plus the P0/P1 regression batteries added by the 2026-09-08 and 2026-09-11 hardening passes (CTE-alias shadowing, unqualified-name re-authorization, NaN clamps, installer trust boundary, gate-script fail-closed guards, verifier canonical diagnostics, ledger-vs-code drift) | `pytest tests/unit` — **202 tests passing** (recorded 2026-09-11) |
| Static quality | `mypy --strict src`: 0 issues in 30 files; `ruff check src tests`: clean (both re-run after every hardening change) |
| Offline bundle builder/verifier: hashed runtime.lock (42 wheels incl. all vendor drivers: ibm_db 3.2.9, oracledb 4.0.2, pyodbc 5.3.0, psycopg 3.3.5, PyMySQL 1.2.0, clickhouse-connect 1.8.0), CycloneDX SBOM, manifest with administrator-supplied prerequisites, detached Ed25519 signing support | rebuilt 2026-09-08 with hardened scripts (`dist/udbmcp-bundle/...`); verifier runs recorded in Gate A/B and A-negative evidence |

## 1b. Production-readiness hardening pass (2026-09-08)

A multi-agent adversarial review (140 reviewer/verifier agents) produced 85
confirmed findings: 1×P0, 38×P1, 46×P2. Fixes applied across:

- **Security core:** SQL guard denies `@`-database links, locking clauses
  (`FOR UPDATE` et al.) and `SETTINGS`-style statement args; dialect map
  (mssql→T-SQL, db2→postgres) with any parse failure a denial; input size
  and parse-recursion caps.
- **Tool layer:** uniform error envelopes with elapsed timing; audit writes
  off the event loop with fail-closed classification; TLS enforcement for
  remote connections (`require_tls`); poisoned-connector recovery via fresh
  instance; schema checks before privileged metadata paths.
- **Executor:** deadline delivery fixed (`abandon_on_cancel=True`) —
  previously timeouts could never fire while a worker thread ran; driver
  `TimeoutError` is now discriminated from the executor deadline and does
  not poison the connection (unit-tested both ways).
- **Connectors:** pooled, probe-on-checkout metadata connections;
  per-connector execution serialization so cancel hooks are exact; health
  output scrubbed of credentials; driver-derived column type labels;
  non-finite float sentinels; postgres driver errors wrapped as typed
  `ConnectorError`; Oracle TCPS/wallet requirement; ClickHouse TLS port
  precedence; MSSQL ODBC connection-string escaping.
- **Config/doctor/scripts/packaging:** per-engine option allowlists, state
  path isolation from SQLite sources, mask-regex validation; doctor
  file-writability probes and opt-in real connectivity checks; HTTP bearer
  auth via constant-time comparison with empty-token rejection; bundle
  constraint generation fixed for current pip (extras stripped from
  `-c` constraints); signed-without-pubkey and unlisted-file verify
  failures; install/upgrade/rollback/load-image scripts hardened; image
  HEALTHCHECK.

The full confirmed-finding list (severity-ranked) is archived at
`docs/review-findings-2026-09-08.json`. Most security- and
correctness-relevant findings are reflected above; the following
confirmed finding is explicitly **NOT applied** and remains open in the
code as of this ledger revision:

- **Residual P1 (archive indices 15 and 23): `tls.verify_server=false`
  is still accepted for remote engines, yielding unverified TLS.**
  `TlsConfig` validation (src/universal_db_mcp/config.py) requires
  `tls.ca_file` only when `verify_server=true`, so the combination
  `tls.enabled: true, verify_server: false` passes config validation;
  doctor does not warn about it; and every remote connector honors the
  flag by downgrading to unverified TLS (postgres `sslmode="require"`,
  mssql `TrustServerCertificate=yes`, clickhouse `verify=False`, mysql
  `check_hostname=False`). This contradicts the spec's "never disable
  certificate/hostname verification" posture. Remediation (not yet
  implemented) is to reject `verify_server=false` at config validation
  for non-sqlite engines — or require an explicit acknowledgement flag —
  and/or have doctor emit a warning check for it. Until that lands,
  administrators must keep `verify_server: true` (the default) and
  provision the internal CA into `tls.ca_file`. A regression test in
  `tests/unit/test_hardening_gates.py` gates this ledger against the
  actual code behavior so the disclosure cannot silently drift.

Residual lower-priority polish items also remain in that archive list
and are intentionally not claimed as applied.

## 1c. Second review + fix pass (2026-09-11)

A second multi-agent adversarial review (8 dimension finders, 3-lens
skeptic verification per finding) plus a reproduce-then-fix fan-out
(22 file-scoped fixers, disjoint ownership) processed the confirmed
defects:

- **4 P0 defects reproduced and fixed** (each with a regression test):
  CTE-alias shadowing of qualified table names in the SQL guard;
  unqualified-name resolution bypassing the schema allowlist; NaN/inf
  timeouts/row-limits bypassing policy clamps; the offline installer
  verifying a bundle with a verifier shipped inside that same bundle
  (self-verification attack) — fixed via a `trusted-tools/` directory
  distributed OUTSIDE the bundle and a trust boundary in
  install/upgrade scripts.
- **36 P1 defects reproduced (0 refuted) and fixed across 22 files**,
  including: schema=None policy leaks and broken capability keys in the
  list tools; audit records dropped on cancellation (now shielded +
  connector poisoned) and racy audit rotation; column-mask bypass via
  aliasing (source-column taint analysis over the parsed AST); PyMySQL
  `%`-format and double-quote identifier defects plus shared-connection
  thread-safety (MySQL); psycopg `with conn:` closing the pooled
  metadata connection and cross-request spurious cancels (Postgres);
  `fetch_tuple`-returns-False catalog crashes and FK query syntax
  (Db2); unfiltered foreign-key catalog queries and silently ignored
  `tls.ca_file` (MSSQL); 3-part cross-database catalog references now
  denied for non-sqlite dialects; secret-echoing config error messages;
  EULA env dropped by sudo; upgrade/rollback doctor without a config
  path; Gate C all-skipped-run misread as a pass; gate bootstrap
  building an unsigned bundle while enforcing a pubkey; honesty fixes
  in the Db2 TLS runbook and this ledger. 36 accompanying regression
  tests were added (unit battery now 202).
- Two gate-harness defects found and fixed during the re-verification
  round itself: the A-negative `untrusted_signature` case could pass
  vacuously when every signer failed silently (now aborts exit 2), and
  `verify_bundle.py` printed a non-canonical diagnostic on the
  OpenSSL-3-only rejection path.
- Gates re-run green 2026-09-11 against the rebuilt, re-signed bundle:
  bundle verification PASSED (91 artifacts, 42 wheels, 11 OS packages),
  Gate A+B PASSED (offline install + no-network protocol probe +
  restart), Gate A-negative 6/6, Gate C 11 passed / 0 failed / 2
  skipped with the heavy engines (Oracle, MSSQL) exercised live.

## 2. Implemented, NOT verified (code-complete, honest capability state)

- **Oracle connector** (python-oracledb Thin only): full module, catalog
  queries, cancel hook; every live capability reported `unverified`. No
  Oracle instance was available. Thick mode deliberately not implemented.
- **SQL Server connector** (pyodbc + admin-supplied ODBC Driver 18):
  full module incl. driver-presence detection; capabilities `unverified`.
- **IBM Db2 LUW connector** (ibm_db wheel with bundled clidriver):
  full module; capabilities `unverified`. Import was not exercised on a
  target (an import alone is not a connectivity test). z/OS and Db2 for i
  are NOT implemented (config rejects them).
- **Additional metadata paths for pg/mysql/clickhouse** (tables/columns/
  views/routines/FKs/statistics/inference): implemented per documented
  catalog SQL; only the round-trip subset listed in Gate C was exercised.
- **HTTP transport** (authenticated Streamable HTTP via bearer token file):
  implemented; no automated test exercised it end-to-end → `unverified`.
- **Cursor-scoped pagination on remote engines**, masking on remote result
  paths, explain on remote engines: unit-tested with SQLite; remote runs
  `unverified` until Gate C round 2.

## 3. Missing artifacts / blocked items (cannot be produced here)

| Artifact | Status | Who supplies |
| --- | --- | --- |
| Microsoft ODBC Driver 18 `.deb` (SQL Server) | SHIPPED for the target profile (ubuntu 24.04 amd64): `msodbcsql18` + `unixodbc` debs staged in bundle `os-packages/` with recorded hashes (shipped; bundle rebuilt and Gate A/B re-run passed (11-package ODBC dependency closure dpkg-installed inside the no-network container)). EULA note: installing the package constitutes accepting the Microsoft ODBC driver EULA, so the EULA acceptance remains an administrative decision recorded at install time | DBA/IT after EULA acceptance |
| Db2 Connect client licensing (z/OS/i via gateway) | not redistributable; doctor reports | IBM entitlement holder |
| Oracle wallets / TNS / internal CA certificates | deployment inputs | administrators |
| Bundle signing key pair | supported end-to-end (sign + offline verify + failure test); not generated in this environment | organization key ceremony |
| Db2 remote password authentication for the pinned `ibm_db` client | `blocked` here — the client fails plaintext remote password auth (SQL30082N reason 17) against both Db2 12.1 and 11.5.9 servers on every platform tried, while server-side TCP auth is verified via the server's own clidriver; the connector's TLS path (`SECURITY=SSL` + `SSLServerCertificate`) is the documented remediation but needs Db2-side TLS to exercise | DBA/infrastructure owners |

## 4. Gates NOT run (recorded truthfully)

- **Gate D (egress observation):** harness provided
  (`scripts/observe_egress.sh`, strace-based, self-validating); NOT run —
  requires a Linux host with ptrace permitted. The `--network none` Gate
  A/B runs prove no successful egress but do not observe attempts.
- **Gate F (Claude Code + internal gateway + GLM end-to-end):** `not_run` —
  requires the organization's pinned client version and internal model
  gateway. Integration guide + `.mcp.json` provided. Any client startup/
  auth blocker must be reported against the client, not this server.
- **Gate G (upgrade/rollback exercise):** scripts provided
  (`upgrade_offline.sh`, `rollback_offline.sh` with atomic venv switch,
  backups, interruption recovery); exercise not performed here → `not_run`.
- **Gate C round 2:** the DB-side permission-denial proof is **passed**
  for PostgreSQL, and Oracle + SQL Server round-trips over themed fixture
  data are **passed** through the real connectors. IBM Db2 remains
  `blocked` on this staging host: the fixture server is verified up to
  seeding (local + TCP auth via its own clidriver), but the pinned
  pinned client cannot complete remote plaintext password authentication
  (documented in docs/driver-matrix.md). The full metadata
  battery per engine remains `blocked` on fixtures.

## 5. Assumptions recorded

- Target profile linux-x86_64 / Ubuntu 24.04 / CPython 3.12 / cp312 ABI
  (spec default, confirmed against `ubuntu:24.04` + baseline image with
  python3.12). Other profiles must be built separately; nothing here claims
  multi-platform support.
- This macOS machine acted as the authorized staging machine (spec §2.10);
  it is not a production target.
- `ubuntu:24.04` ships no Python; the bundle therefore ships a baseline
  image artifact (OS + CPython 3.12 only) loaded via `docker load`.

## 6. Verification commands

```bash
.venv/bin/python -m pytest tests/unit tests/integration -q   # 202 unit + 11 env-gated C
.venv/bin/python -m mypy src && .venv/bin/ruff check src tests
bash scripts/test_airgap.sh              # Gates A + B (docker, --network none)
bash scripts/test_airgap_failures.sh     # Gate A negative cases (real exit codes)
bash scripts/test_isolated_integrations.sh  # Gate C (pulls fixtures on staging)
```

A release is air-gap ready for the profile `linux-x86_64-ubuntu24.04-cp312`
with connector set {sqlite, postgres, mysql, clickhouse} per the evidence
above. Oracle/MSSQL/Db2 remain code-complete-but-unverified until their
gates run against real instances.
