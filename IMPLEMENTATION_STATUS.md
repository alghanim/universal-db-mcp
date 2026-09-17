# Implementation status (honest ledger)

Last updated: 2026-09-16 (native-packages §1d records the honest
per-platform status of the .deb / .pkg / .msi packages derived from the
signed offline bundle: the Ubuntu .deb no-network gate was re-run and
**PASSED** end-to-end (latest recorded run 2026-09-12T12:28:29Z, 29/29
checks) — positive install, doctor, stdio protocol probe, the
wheel-tamper negative, the key-material build refusal, and the
postinst self-bootstrap refusal all green with evidence; the
macOS .pkg was built and its payload verified natively on this arm64
host — the full 23-check gate was re-run and recorded **green**
(latest recorded run 2026-09-12T12:38:10Z, status `passed`, 23/23
checks: the executed tamper negative (all three tamper checks), the
unit suite, payload signature verification, and the rest), the full
`installer` run is `not_run`, and the .pkg is
**UNSIGNED** (no developer signing identity); the Windows .msi was
**NOT built** — the Phase-0 toolchain IS installed and a build-only
run is recorded (bundle verification, staging, harvest, xmllint and a
real `wix` invocation all passed; the compile fails closed on the
WiX-on-Unix WIX0389 limitation), no `.msi` artifact exists, and the
Windows runtime/install gate is `not_run`; the
2026-09-11 second production-readiness review + fix pass (§1c) and the
2026-09-08 ledger-honesty revision with its residual P1 disclosure in
§1b remain in force).
Every `passed` claim below points at machine-readable evidence in
`test-evidence/`. Claims without evidence are labeled `unverified`,
`blocked`, or `not_run`.

## 1. Implemented AND verified (evidence recorded)

| Item | Evidence |
| --- | --- |
| SQLite MCP server, full tool surface (20 at that run; 25 since 2026-09-16), read-only, bounded execution | `test-evidence/airgap-gateAB/protocol-probe.json` (real stdio MCP session: initialize, 20 tools listed, discovery, query, masking, write denial, sample, capabilities, explain, history) |
| Gate B — no-network protocol test (pinned MCP SDK client, no npm/browser) | same, run inside `docker --network none` container |
| Gate A — clean offline installation from bundle only (verify → install → doctor → demo → restart) | `test-evidence/airgap-gateAB/airgap-test-results.json`, `doctor.json` (run 2026-09-08T13:30Z; **caveat:** amd64 userland under Docker Desktop emulation on the staging host; artifacts are genuine x86_64) |
| Gate A-negative — tampered wheel, missing wheel, wrong-ABI wheel, untrusted signature, missing licensed driver, hostile inherited pip config: all fail fast with no download attempts; each fail_fast case requires nonzero exit AND its expected actionable diagnostic (a classifier that credited any nonzero exit was fixed 2026-09-11); the untrusted-signature case now fails closed if no foreign signature can be produced (a vacuous pass with the original trusted SIGNATURE still in place was reproduced and fixed), and the verifier emits the canonical `signature verification FAILED` diagnostic on every rejection path including OpenSSL-3-only hosts — re-run 2026-09-11: **6/6 passed** | `test-evidence/airgap-failure-modes/results.json` + per-case `*.json` and `*.output.txt` |
| Gate C — real-driver integration on a Docker `--internal` network (fixtures AND client attached; no external route), each engine carrying DISTINCT themed mock data: PostgreSQL (oceanographic buoys; health, query, schemas, **DB-side permission-denial proof**), MySQL (coffee roastery), ClickHouse (250k telecom call data records), **Oracle (air travellers — passed)**, **SQL Server (hospital admissions — passed)** — re-run 2026-09-11 with heavy fixtures enabled: **11 passed, 0 failed, 2 skipped**; IBM Db2 recorded `blocked` in that run. **Root cause corrected 2026-09-15:** the connector and the Gate C auth probe passed credentials as `ibm_db.connect` positional arguments, which ibm_db ignores for connection-string DSNs, so no credentials were ever sent (SQL30082N reason 17; reason 3 PASSWORD MISSING under forced SERVER auth). After the fix, a direct live run of both Db2 integration tests (roundtrip + civil-registry themed data) **passed** against the local Db2 11.5.9 fixture; the Gate C orchestrator itself has not been re-run | `test-evidence/integration-gateC/integration-run.log`, `results.json`, `test-evidence/integration-db2-credentials-fix/` |
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
confirmed finding was, at the time of the 2026-09-08 revision,
explicitly **NOT applied** and disclosed as open. **RESOLVED
2026-09-11**: `TlsConfig` now rejects `verify_server=false` outright at
config validation (verified: validation error "tls.verify_server=false
is not permitted"), so unverified TLS can no longer be configured for
any engine; the §1c P2 fan-out landed this fix and its regression
coverage. The original disclosure is kept below for the record:

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
  OpenSSL-3-only rejection path. A third harness defect — the A-negative
  `results.json` writer emitting malformed JSON — was reproduced from the
  committed evidence, fixed (json-module assembly), and the gate re-run
  green with machine-valid output. Two further packaging regressions
  were caught by re-running the gates against the final bundle and
  fixed: the bundle builder omitted `lib/os_packages.sh` from
  `trusted-tools/` (every install aborted after verification), and the
  installer's exec-if-executable verifier contract broke on noexec bind
  mounts (rc=126 after `[ -x ]` succeeded) — python-file verifiers now
  always run via python3.
- The full 405-agent review completed (2026-09-11): 92 confirmed
  findings (1×P0, 8×P1, 52×P2, 31×P3), 40 refuted, 9 critic gaps —
  archived at `docs/review-findings-2026-09-11.json`. Reconciliation:
  the P0 and five P1 findings it lists were judged against pre-fix
  cached verdicts; re-running their repros against the current tree
  DENIES all of them (CTE-shadowed qualified reference, unqualified
  resolver bypass, cross-catalog reference — all rejected).
- **P2 tier (2026-09-11, same day): 49 of 52 confirmed P2 findings
  fixed** by a reproduce-then-fix fan-out (54 reproduction skeptics, 6
  file-scoped fixer groups) plus a 6-fixer residual wave for the
  findings no group owned, including 3 critic-verified gaps. Highlights:
  parenthesized EXPLAIN options now accepted (ANALYZE/WAL still gated);
  driver auth-failure usernames redacted (registered-secret registry +
  keyword backstop); audit/metadata-cache files created 0600 with
  systemd UMask=0077; baseline image digest-pinned and file-based
  signing everywhere; driver exceptions wrapped as ConnectorError on
  every engine; MySQL truncation no longer drains the result set;
  system schemas excluded from MySQL/Db2 catalogs; ClickHouse nullable
  inversion fixed and query cancellation implemented via KILL QUERY;
  postgres FK catalog query rewritten with bound schema/table;
  bearer-token file permission-checked with CONFIG_ERROR on failure;
  verify_server=false now rejected at config validation (closing the
  §1b residual P1 — the disclosure above is now historical, kept for
  the record); mask_columns merges (never replaces) the built-in
  patterns with boundary-anchored defaults; oracle thick_mode/TLS
  wallet validation at config time; state-path overlap checked by
  realpath; installer dpkg idempotency/staging/privilege fixes;
  upgrade now installs new os-packages; rollback never deletes the
  live config; Gate B probe requires POLICY_VIOLATION; the [oracle]
  extra pin now matches the vendored wheel. The 3 remaining P2s
  (sql_guard.py #0 verdict reconciliation, evidence-freshness claims
  resolved by the same-day evidence refresh, and the ledger-pointer
  item fixed in this revision) are recorded in the archive, not
  dropped. **31 P3 findings and any residual polish items remain
  recorded in `docs/review-findings-2026-09-11.json` and are
  intentionally not claimed as applied.**
- Gates re-run green 2026-09-11 against the rebuilt, re-signed bundle:
  bundle verification PASSED (91 artifacts, 42 wheels, 11 OS packages),
  Gate A+B PASSED (offline install + no-network protocol probe +
  restart), Gate A-negative 6/6 with valid machine-readable evidence,
  Gate C 11 passed / 0 failed / 2 skipped with the heavy engines
  (Oracle, MSSQL) exercised live.
- **Live agent-consumption test (2026-09-11/12): 49/60 checks passed.**
  Eight parallel agents drove the real stdio server with
  `config.mockdbs.yaml` against the running mock containers as genuine
  tool calls. The 11 failures triaged as: 6 environmental (MSSQL ODBC
  Driver 18 absent on the macOS staging host — the error text now points
  the operator at `options.odbc_driver` as designed; Db2 clidriver auth
  under emulation; one test-spec column-name mismatch the server
  rejected cleanly), 1 unexercisable (cursor pagination: fixtures sit
  below the 50-row page size — known), and **3 real bugs, fixed and
  live re-verified**: (1) bound parameters were impossible end-to-end —
  the guard parsed `%s` as modulo and PyMySQL rejected `?`/`:name`; the
  guard now masks pyformat placeholders outside string literals for
  validation (no bypass — the masked AST takes the identical
  authorization walk) and a shared `translate_paramstyle` rewrites
  markers onto each driver's spelling after validation; (2)
  `db_search_metadata` aborted the whole call on one dead connection —
  Db2's raw ibm_db exceptions on the catalog paths are now wrapped as
  ConnectorError and the tool degrades with a per-connection warning;
  (3) cell truncation was silent on the remote query paths (cell cut to
  `max_cell_bytes` with `truncated=false`) — postgres/mysql/_and the
  other engines_ now report `truncated=true` plus a warning naming the
  truncated columns. SQLite's generic (unnamed) truncation warning and
  `db_explain` ignoring its `parameters` argument are recorded in the
  review archive as residual polish, not claimed as fixed.

## 1d. Native packages (.deb / .pkg / .msi)

All three package types derive from the ONE signed offline bundle (one
signing ceremony, three artifacts) and preserve the trust model on every
platform: no package executes payload before a trusted-channel
`verify_bundle.py --pubkey` run has passed, the release pubkey is never
shipped inside any package (administrators distribute it out-of-band),
every venv build runs `pip --no-index --require-hashes` with
`PIP_CONFIG_FILE` neutralized, and every verification failure fails
closed.

| Package | Status | What was and was not verified |
| --- | --- | --- |
| Ubuntu `.deb` (linux-x86_64-ubuntu24.04-cp312) | full no-network gate **PASSED** 2026-09-12 (re-run green after the same-day positive-path failure; latest recorded run 2026-09-12T12:28:29Z) | `scripts/package/test_package_deb.sh` mirrors Gates A/B: sign → `dpkg-deb` build inside the baseline container → install under `docker --network none` → doctor with demo config → stdio protocol probe, plus a negative case (a tampered wheel repacked into the deb must fail closed at postinst verification with the canonical diagnostic). Evidence (`out/package-evidence/deb/results.json`, 2026-09-12T12:28:29Z, status `passed`, 29/29 checks): **positive path** — `dpkg -i` succeeded (preinst checked trust prerequisites only; postinst re-verified the unpacked payload through the existing `install_offline.sh` — no installer fork — at configure time: 91 artifacts, 42 pinned wheels, 11/11 bundle OS packages hash-checked, `signature: verified`); the dpkg-dependent install (venv, wheelhouse, bundle OS packages, service enable) then completed in a background worker after dpkg released its locks (20 s wait, `deferred-install.log`); doctor passed (12/12 checks, 0 fatal) against the deb-installed venv and the stdio MCP protocol probe passed inside the same no-network container. The minimal baseline image carries no `python3`/`python3-venv` .debs (its CPython 3.12 is installed outside dpkg), so the gate configures the package with forced dependencies — real ubuntu-24.04 targets satisfy the declared `Depends` normally. **Negative path** — a byte-flipped sqlglot wheel inside a repacked deb (its SHA256SUMS line refreshed so the rejection must come from the SIGNATURE, not the integrity hash) is rejected by the trusted verifier with the canonical `signature verification FAILED` diagnostic, and `dpkg -i` of the tampered package fails closed at postinst verification. Two further fail-closed negatives recorded in the same run: the builder refuses to build when public-key material is staged into the package root (`build_rejects_key_material`), and with no admin trust dir provisioned the postinst refuses to self-bootstrap a verifier from the package's own `trusted-tools/` copy — a stub verifier planted in the package is never executed and `dpkg -i` of that package fails closed (`no_admin_bootstrap`, `deb_verifier_stubbed`, `postinst_refuses_self_bootstrap`, `stub_verifier_never_ran`, `tampered2_dpkg_install_fails`). **`systemctl enable --now` under a real systemd PID 1: `not_run`** — the gate container runs without systemd; the unit is installed and the enable is guarded so container installs still succeed, but no host with PID 1 = systemd was exercised. Version provenance: the package version embeds the signed manifest's source revision — `0.1.0~30f94799…` (the release commit hash) — so the artifact is tied to the exact source state that was signed. |
| macOS `.pkg` (macos-arm64-cp312) | built + payload verified natively on this arm64 staging host; **package is UNSIGNED** (no developer signing identity); the full 23-check gate was re-run and recorded **green** (latest recorded run 2026-09-12T12:38:10Z, status `passed`, 23/23 checks — closing the earlier 11:17:20Z 22/23 run whose single failed check was `unit_suite`, a transient race with concurrent edits, both affected tests passing on re-run); full `installer` run `not_run` | `scripts/package/test_package_pkg.sh`: the signed macos-arm64-cp312 bundle is built and re-verified by the trusted verifier before packaging; the wheelhouse is fully resolved **including the `ibm-db` `macosx_14_0_arm64` wheel**; the package payload is proven to be the signed bundle (`pkgutil --expand-full`, then the trusted verifier run against the expanded payload); and an executed tamper negative: a byte-flipped wheel inside a repacked COPY of the `.pkg` is rejected by the trusted verifier with the canonical FAIL diagnostic (`tamper_copy`, `wheel_tampered`, `tampered_payload_rejected` all passed). Evidence (`out/package-evidence/pkg/results.json`): the latest recorded run (2026-09-12T12:38:10Z) recorded status `passed` with 23/23 checks — `pkg_built`, `payload_signature_verified` (trusted verifier accepted the expanded payload), `no_keys_in_payload`, install-script hardening, all plist checks (incl. `launchd_label_consistency`), the executed tamper negative, and the native unit suite green for the on-disk package (`dist/universal-db-mcp-0.1.0-macos-arm64.pkg`, 12:35Z rebuild, `out/package-evidence/pkg/build-20260912T123541Z.log`, sha256 `16fa8266…`). History: an earlier same-day run (10:47:30Z) recorded 20/20 green before the tamper checks were added; the 11:17:20Z run added the first executed tamper negative (all three tamper checks passed) but failed `unit_suite` alone — two `tests/unit/test_hardening_gates.py` rollback tests raced with concurrent edits to `scripts/rollback_offline.sh` at gate time and both pass on re-run (verified after the rollback integrity-manifest behavior landed) — and the owed full re-run has since been recorded green as described above. An earlier same-day run (09:56Z) also passed all of its checks. preinstall validates trust prerequisites only (trusted verifier + admin pubkey, else exit with bootstrap instructions); postinstall re-verifies the payload, builds the venv with the same hostile-pip neutralization, and bootstraps the LaunchDaemon. **Honesty caveat recorded per the build log's explicit WARNING:** the `.pkg` is **UNSIGNED** — no Apple Developer ID signing identity is configured on this host, so Gatekeeper/`installer` will not attribute the package to a developer; product signing is an organizational key-ceremony step, not performed here. **The full `installer` run and the launchd daemon start: `not_run`** (opt-in behind `UDBMCP_PKG_INSTALL=1`, off by default). Documented delta: macOS has no ProtectSystem-equivalent; the plist otherwise mirrors the systemd unit line-for-line. |
| Windows `.msi` (win_amd64) | **NOT built** (no `.msi` artifact exists); install gate `not_run` | The plan-Phase-0 prerequisites **ARE installed** on this staging host (user-local .NET 8 SDK `8.0.425` + the `wix` global dotnet tool, `6.0.2`; `wix` 7.0.0 was refused fail-closed at the OSMF-EULA gate, and `wix` 4.0.5/5.0.2/6.0.2 all behave identically below), and `scripts/package/build_msi.sh` was executed end-to-end against a freshly built, SIGNED `windows-x86_64-cp312` bundle (release 0.1.0, 42 wheels, no missing connectors; `out/bundle-windows/universal-db-mcp-0.1.0-windows-x86_64-cp312` with `SIGNATURE` + `SHA256SUMS`). Every first-party build step ran and passed: trusted-channel `verify_bundle.py --pubkey` verification (79 artifacts, signature verified, 42 pinned requirements), payload staging with a no-key-material scan, deterministic harvest, `xmllint` validation, and a real `wix build` that reached full authoring validation. The compile itself fails closed with 15× **WIX0389** (WiX-on-Unix rejects every `Directory/@Name` — a toolchain limitation, not an authoring defect: these are the ONLY remaining errors), so **no MSI was produced**, and MSI compilation therefore requires a **Windows** staging host. Evidence: `out/package-evidence/msi/results.json` + `out/package-evidence/msi/build-msi-build-only.log`. The stray 12-byte `universal-db-mcp-1.2.3-win-x86_64.msi` placeholder (literal `FAKE` after the OLE magic; its 1.2.3 version matched nothing in the signed manifest release 0.1.0, and it was not produced by `build_msi.sh`) was deleted from `dist/`; no `*.msi` exists there now. Delivered authoring, exercised as far as a Unix host allows: `scripts/package/build_msi.sh` + `packaging/msi/udbmcp.wxs` with the deferred, `Impersonate="no"` custom actions — trusted `verify_bundle.py` against the installed bundle with the admin pubkey, venv build `--no-index --require-hashes` with hostile pip env neutralized, doctor smoke, `sc.exe` service registration — implemented by `packaging/msi/custom/{verify,venv,doctor,service,uninstall}.ps1`, staged and wired by `build_msi.sh` via `-define CustomActionScriptsDir=…`. No Windows machine was available, so once built the install gate must be exercised on the target OS before anything is claimed: service behavior, the admin-supplied msodbcsql MSI, and NTFS ACL behavior remain unexercised — the ledger records **no pass for any Windows runtime step**. The gate script **`scripts/test_package_msi.ps1` is delivered** for a real Windows machine (msiexec with `/l*v`, `sc.exe query`, doctor, stdio protocol probe, tamper negative case, evidence JSON). |

## 2. Implemented, NOT verified (code-complete, honest capability state)

- **Oracle connector** (python-oracledb Thin only): full module, catalog
  queries, cancel hook. Gate C round-trips (health, SELECT, themed
  travellers data) **passed** against the live Oracle fixture
  (2026-09-11); the remaining capability surface (catalog batteries,
  explain, remote cancel) is `unverified`. Thick mode is opt-in since 2026-09-15
  (`options.thick_mode`, admin-supplied Instant Client) because Thin mode
  refuses accounts carrying only the legacy 10G verifier (`DPY-3015`). The
  thick-mode round trip is now **passed (live)**: against an Oracle 18c XE
  account built to carry ONLY the 10G verifier, Thin fails with exactly
  `DPY-3015 ... 0x939` and Thick connects and queries with an
  administrator-supplied Instant Client 19.28 loaded through `ldconfig`, with
  no server-side change between the runs; Thick also reaches an 11.2 server
  that Thin cannot reach at all (`test-evidence/oracle-thick-mode/`).
  Service-name, legacy SID and tnsnames alias connect forms were verified
  live against Oracle 23ai (`test-evidence/oracle-connect-modes/`).
- **SQL Server connector** (pyodbc + admin-supplied ODBC Driver 18):
  full module incl. driver-presence detection. Gate C round-trips
  **passed** against the live HospitalDB fixture (2026-09-11); the
  remaining capability surface is `unverified`.
- **IBM Db2 LUW connector** (ibm_db wheel with bundled clidriver):
  full module; live round-trip + themed data **passed** in a direct run
  against the local Db2 11.5.9 fixture after the 2026-09-15
  credential-passing fix (`test-evidence/integration-db2-credentials-fix/`). The earlier
  `blocked` record was the connector's own bug, not the client library or
  emulation. Gate C orchestrator not re-run; the TLS path and the remaining
  capability surface are `unverified`. z/OS and Db2 for i are NOT implemented (config rejects
  them).
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
| Db2 remote password authentication for the pinned `ibm_db` client | **resolved 2026-09-15** — the long-recorded block (SQL30082N reason 17 on every platform) was the connector passing credentials positionally, which ibm_db ignores for connection-string DSNs; credentials now travel as `UID`/`PWD` inside the connection string and a direct live run passed (`test-evidence/integration-db2-credentials-fix/`). A `;` in any connection value is refused before dialing (no CLI quoting form carries it). Db2-side TLS is optional in-transit hardening, not a login remediation | DBA/infrastructure owners (TLS only) |

## 3b. Connector audit, 2026-09-15 (auth, versions, connection strings)

Triggered by two live customer blockers (Db2 credentials never sent; an Oracle
account carrying only the 10G verifier). Three parallel audits reviewed every
connector against the installed driver sources and vendor docs. Fixed in this
pass, each with regression tests:

- **Silently dropped credentials:** clickhouse skipped Basic auth whenever a
  client certificate was configured; a password without a username
  authenticated as `default`; postgres/mysql substituted the service account's
  OS user when the username was omitted. All now explicit or refused.
- **Connection-string injection:** mssql doubled `}` as if ODBC had an escape
  (it has none, so credentials truncated and an injected `Encrypt=no` could
  win); oracle interpolated host/database/sid into a connect descriptor, where
  `?ssl_server_dn_match=false` defeated this build's own refusal to disable
  certificate verification. Both refuse such values now; encryption keywords
  are emitted first as defense in depth.
- **A TLS bypass introduced earlier the same day:** the new oracle `tns_alias`
  path returned before the TLS branch. It now requires the alias descriptor to
  select TCPS and carries the wallet.
- **Unreachable deployments:** SQL Server Windows/Kerberos auth and named
  instances, Db2 authentication mechanisms, PostgreSQL GSSAPI, MySQL over a
  Unix socket. All expressible now.
- **Misleading failures:** oracle/db2 health checks demanded administrative
  views a least-privilege account cannot read; `FETCH FIRST` broke sampling on
  the Oracle 11.2 servers Thick mode reaches; PostgreSQL 10 lost
  `db_list_routines` to `prokind`; MySQL legacy auth surfaced as an
  AttributeError; a ClickHouse native port gave protocol garbage; an encrypted
  SQLite file read as corruption; the mssql CA check called an installed CA
  missing on hashed trust stores.
- **Onboarding:** `add-connection` never asked about TLS and its live test
  bypassed the server's require_tls gate, so it reported success for a
  connection every later call would refuse. It now prompts, accepts
  `--tls-ca-file`, and previews the policy verdict.
- **Wheelhouse:** PyNaCl (MariaDB `client_ed25519`) and an explicit
  `cryptography` pin (MySQL 8 `caching_sha2_password`, previously transitive
  through oracledb only).

Server version floors are documented in `docs/driver-matrix.md`; note that the
pinned ibm_db bundles clidriver 12.1, which **drops Db2 LUW 10.5**. None of the
floors were exercised against an old server: the fixtures pin newest releases,
so those rows are documented, not tested.

## 3c. MCP surface audit, 2026-09-15 (protocol, transports, packaging)

Fixed in this pass, each with a regression test:

- **HTTP was unusable off loopback.** The ASGI app was built without the bind
  host, so the SDK auto-enabled DNS-rebinding protection pinned to loopback and
  answered `421 Invalid Host header` to every client connecting by hostname,
  including the documented cross-machine deployment. Nothing had ever started
  the HTTP transport in a test; `tests/unit/test_http_transport.py` now drives
  initialize end to end (hostname client, bearer auth, 401 cases) and pins the
  SDK behavior the fix exists for.
- **The metadata cache never hit across restarts.** `policy_fingerprint` called
  `model_dump` on a dataclass, so every call fell back to `repr()`, whose
  frozenset order varies per process. It now normalizes fields (sorted sets,
  full regex patterns) and refuses an unsupported object loudly.
- **Tools advertised nothing about being read-only,** so a conformant client
  had to treat all 20 as destructive. They now carry read-only annotations.
- **`udbmcp version` reported `mcp-sdk unknown`** (the package defines no
  `__version__`); it now reads the installed distribution metadata.
- **Error classification:** a `KeyError` from driver code was reported to the
  model as its own validation error and audited as a deny (`ObjectNotFound`
  now carries that meaning); an unimplemented capability surfaced as
  `INTERNAL_ERROR` instead of `CAPABILITY_UNSUPPORTED`; a huge JSON integer
  raised `OverflowError` inside the row-limit clamp.
- **Packaging:** the macOS postinstall was the only verifier call site that
  trusted an exit code; a `.deb` upgrade kept a pre-HTTP (stdio) unit on hosts
  installed before the shipped-unit hash record existed; two status-file
  ordering bugs let the deferred-install guard refuse the install that had just
  succeeded; `upgrade_offline.sh` skipped the venv mode normalization whose
  absence caused the live 203/EXEC failure; the shipped template referenced a
  demo database no installer created, making doctor fatally unhealthy on every
  clean install; the MSI wrote service environment variables in a form Windows
  ignores and did not allow same-version upgrades.
- **VS Code could never be configured** when `mcp.json` lacked a `servers` key.
- **doctor no longer claims** "safe permissions" for a token file it skipped
  checking on Windows.

Known and NOT fixed here, now documented rather than implied away:

| Item | State |
|---|---|
| Windows service registration | `blocked`: a bare interpreter registered with `sc.exe` cannot answer the service control dispatcher, so the service would fail with error 1053. A service wrapper is required; none is bundled. The whole Windows install path remains `not_run`. |
| HTTP caller identity | Process-scoped, not per request: `db_get_query_history` and cursor identity binding cannot separate two HTTP callers. Documented in `docs/tools.md`. |
| Response size | Every result is transmitted twice (structured + pretty-printed text), so wire bytes are ~2.7x `security.max_response_bytes`. Documented in `docs/tools.md`. |
| Client adapters | stdio only; an HTTP registration is written by hand. Adapters also do not propagate `*_env` credential variable names into the harness environment. |
| Container mode | Needs `http_host: 0.0.0.0` and a token file owned by the image's udbmcp UID; both are documented in `packaging/compose.offline.yaml`, neither is exercised by a gate. |

## 3d. Production session safety, discovery tools, version matrix (2026-09-16)

- **Session safety profile** (`docs/session-safety.md`): applied to every
  server session right after connect and read back for
  `db_test_connection`. Db2 runs at `UR` and SQL Server at
  `READ UNCOMMITTED` for read-only connections, enforced (a refusing server
  fails the connection); PostgreSQL, MySQL, ClickHouse and SQLite refuse
  writes server-side; lock waits and statement time are capped; sessions are
  named for DBAs. Live evidence in `test-evidence/session-safety/`: five
  engines read back, three engines refuse `CREATE TABLE` server-side, and a
  `db_query` on Db2 with no `WITH UR` in its text reads back
  `CURRENT ISOLATION = UR`. SQL Server: applied by the connector, verified
  only where the version matrix can run it (`not_run` natively: no ODBC
  driver on the staging host).
- **Discovery tools** (`docs/tools.md`): `db_list_indexes`,
  `db_get_catalog`, `db_profile_table`, `db_search_values`,
  `db_infer_relationships`, backed by new connector methods on all seven
  engines (index listing, schema-wide bulk columns, engine-native limit and
  placeholder builders) and a portable type vocabulary. Live evidence in
  `test-evidence/discovery-tools/` on PostgreSQL, MySQL, ClickHouse, Oracle
  and Db2, including cross-connection inference and a value search across
  four engines in ~4 s. Two defects found and fixed by that live run:
  ClickHouse rejects `lower()`/`length()` on UUID and Enum (now cast), and
  system catalogs were being searched (now excluded by default).
- **Correctness pass (2026-09-16, commit 5d8ec4e)**: an adversarial review
  of the two batches above produced 20 findings, all applied and pinned by
  `tests/unit/test_correctness_review_2026_09.py`; the regenerated live
  evidence (`scripts/live_evidence.py`, now the recorded generator for
  `test-evidence/session-safety/` and `test-evidence/discovery-tools/`)
  then exposed five more defects that only real servers show, all fixed:
  `schema.table` object names were denied on every engine ("qualify it
  with an allowed schema" for an already qualified name), Db2 `SUBSTR`
  raised SQL0138N on values shorter than the cut, ClickHouse rejected
  `substring` on an Enum, Oracle rejected `COUNT(clob)`, and PostgreSQL's
  `reltuples = -1` (never analyzed) was reported as a size. Whole-connection
  catalog and index listings now hide system catalogs unless
  `include_system` (an Oracle page was 50 dictionary views). ClickHouse
  accounts whose server profile is already read-only are kept and reported
  instead of failing every query with "cannot modify readonly". The Db2
  guard refuses `WITH RS`/`WITH RR` (statement-scoped locks) and accepts
  `WITH UR`/`WITH CS`. Evidence status of the session file after this pass:
  five engines healthy with read-back, PostgreSQL/MySQL/ClickHouse refuse a
  `CREATE TABLE` sent straight to the connector, Db2 reads back `UR` and a
  lock timeout of 5 from its own connection and accepts a statement ending
  in `WITH UR`; SQL Server is `healthy=False` natively (no ODBC driver on
  the staging Mac) and proven only by the container matrix.
- **Version matrix** (`scripts/version_matrix/`, evidence in
  `test-evidence/version-matrix/`): a probe that seeds a themed schema on
  any server version and drives every connector capability (22 checks:
  seed, health, schemas, tables, columns, bulk columns, indexes, index on a
  foreign key, primary key, foreign keys, views, routines, statistics,
  counted query, bounded sample, profile aggregate, top values, value
  search, EXPLAIN, session read-back, composite unique index, list_columns
  count). Final run on 2026-09-16 at commits 5d8ec4e..02f7e46 (the only
  source difference between those commits is the LIKE escape helper, which
  the probe does not exercise); `summarize.py` output, unedited:

  | Engine | Image | Server reports | Checks | Result | Session |
  |---|---|---|---|---|---|
  | clickhouse | `clickhouse/clickhouse-server:23.8` | 23.8.16.16 | 19/22 | passed (skipped: composite_unique_index, get_foreign_keys, list_routines) | default/server-ro |
  | clickhouse | `clickhouse/clickhouse-server:24.3` | 24.3.18.7 | 19/22 | passed (skipped: composite_unique_index, get_foreign_keys, list_routines) | default/server-ro |
  | clickhouse | `clickhouse/clickhouse-server:24.8` | 24.8.14.39 | 19/22 | passed (skipped: composite_unique_index, get_foreign_keys, list_routines) | default/server-ro |
  | clickhouse | `clickhouse/clickhouse-server:25.3` | 25.3.14.14 | 19/22 | passed (skipped: composite_unique_index, get_foreign_keys, list_routines) | default/server-ro |
  | oracle | `gvenzl/oracle-free:23-slim` | Oracle AI Database 26ai Free Relea | 21/22 | passed (skipped: explain) | default/guard-ro |
  | oracle | `gvenzl/oracle-free:23-slim (thick)` | Oracle AI Database 26ai Free Relea | 21/22 | passed (skipped: explain) | default/guard-ro |
  | oracle | `gvenzl/oracle-xe:11.2.0.2-slim (thick)` | Oracle Database 11g Express Editio | 21/22 | passed (skipped: explain) | default/guard-ro |
  | oracle | `gvenzl/oracle-xe:18.4.0-slim` | Oracle Database 18c Express Editio | 21/22 | passed (skipped: explain) | default/guard-ro |
  | oracle | `gvenzl/oracle-xe:18.4.0-slim (thick)` | Oracle Database 18c Express Editio | 21/22 | passed (skipped: explain) | default/guard-ro |
  | oracle | `gvenzl/oracle-xe:21.3.0-slim` | Oracle Database 21c Express Editio | 21/22 | passed (skipped: explain) | default/guard-ro |
  | db2 | `icr.io/db2_community/db2:11.5.8.0` | DB2 v11.5.8.0 | 21/22 | passed (skipped: explain) | ur/guard-ro |
  | db2 | `icr.io/db2_community/db2:11.5.9.0` | DB2 v11.5.9.0 | 21/22 | passed (skipped: explain) | ur/guard-ro |
  | mysql | `mariadb:10.6` | 10.6.28-MariaDB-ubu2204 | 22/22 | passed | default/server-ro |
  | mysql | `mariadb:11.4` | 11.4.13-MariaDB-ubu2404 | 22/22 | passed | default/server-ro |
  | mssql | `mcr.microsoft.com/mssql/server:2017-latest` | Microsoft SQL Server 2017 (RTM-CU3 | 21/22 | passed (skipped: explain) | read_uncommitted/guard-ro |
  | mssql | `mcr.microsoft.com/mssql/server:2019-latest` | Microsoft SQL Server 2019 (RTM-CU3 | 21/22 | passed (skipped: explain) | read_uncommitted/guard-ro |
  | mssql | `mcr.microsoft.com/mssql/server:2022-latest` | Microsoft SQL Server 2022 (RTM-CU2 | 21/22 | passed (skipped: explain) | read_uncommitted/guard-ro |
  | mysql | `mysql:5.7` | 5.7.44 | 22/22 | passed | default/server-ro |
  | mysql | `mysql:8.0` | 8.0.46 | 22/22 | passed | default/server-ro |
  | mysql | `mysql:8.4` | 8.4.11 | 22/22 | passed | default/server-ro |
  | postgres | `postgres:12` | PostgreSQL 12.22 (Debian 12.22-1.p | 22/22 | passed | default/server-ro |
  | postgres | `postgres:13` | PostgreSQL 13.23 (Debian 13.23-1.p | 22/22 | passed | default/server-ro |
  | postgres | `postgres:14` | PostgreSQL 14.24 (Debian 14.24-1.p | 22/22 | passed | default/server-ro |
  | postgres | `postgres:15` | PostgreSQL 15.19 (Debian 15.19-1.p | 22/22 | passed | default/server-ro |
  | postgres | `postgres:16` | PostgreSQL 16.13 (Debian 16.13-1.p | 22/22 | passed | default/server-ro |
  | postgres | `postgres:17` | PostgreSQL 17.9 (Debian 17.9-1.pgd | 22/22 | passed | default/server-ro |

  Reading the table: "skipped" is a capability the engine does not have or
  the build disables on purpose, never a failed check: ClickHouse has no
  foreign keys, routines or unique indexes; Oracle EXPLAIN PLAN needs a
  provisioned plan table and is disabled; SQL Server and Db2 EXPLAIN are not
  implemented in this build. Oracle 11.2 exists only as a thick-mode row
  because python-oracledb's thin mode cannot connect to that server version
  at all (DPY-3010); the thick rows ran the same probe inside a no-network
  container with the administrator-supplied Instant Client. The SQL Server
  rows were re-run on 2026-09-17 at 332b7e2 (identical connector source)
  after the runner learned to pass the revision into the Gate C client
  container (VM_PROBE_REV); they pass 21/22 with the stamp. A version not
  listed here is `not_run`, not "works".

- **Schema-wide review and documentation (2026-09-17)**: two tools on top
  of the same building blocks, taking the surface to 27: `db_review_schema`
  runs the per-table profile and findings over every permitted table of a
  schema or connection (biggest tables first, one
  `security.discovery_time_budget_seconds` budget shared fairly across the
  page, paged by cursor) and returns findings prioritized by severity, each
  with evidence and a suggestion; `db_document_schema` renders a Markdown
  data dictionary from the catalog (declared and portable types, keys,
  indexes, comments, declared relationships) page by page, metadata only.
  Unit-tested on the seeded SQLite database (`tests/unit/test_discovery_tools.py`,
  `tests/unit/test_data_dictionary.py`); live in
  `test-evidence/discovery-tools/results.txt`: the review reported
  unindexed foreign keys on the Db2 and Oracle fixtures, missing statistics
  on Db2/MySQL/PostgreSQL and enum candidates on ClickHouse, and the
  dictionary rendered every fixture schema without a column value in it.
  The 25-tool pins (protocol probe, stdio integration test, agent
  descriptions) were moved to 27.
- **Security review and hardening (2026-09-17)**: `/security-review` (two
  independent identification passes, four candidates verified one by one)
  found no HIGH or MEDIUM vulnerability in the session's changes; every
  candidate was a false positive under the review's rules. The hardening
  it recommended was applied anyway in commit e980058: a sensitive
  column's DEFAULT literal is `<masked>` in `db_get_catalog`,
  `db_list_columns` and the data dictionary; `db_review_schema` and
  `db_document_schema` are bounded by `security.max_response_bytes` and
  resume exactly where a page stopped (time or bytes), one unreadable
  table is a warning; quoted object names keep their dots; every name and
  comment in the data dictionary is escaped; the evidence script's write
  probe runs only where the health check proved server-side read-only and
  drops its table if a server ever accepts it; the trust bootstrap
  (`packaging/trust-bootstrap-linux/bootstrap.sh`, now in the repository)
  prints the release-key fingerprint and refuses to replace a different
  installed key without `--rotate-key`.
- **Release artifacts (built from commit e980058; this note was added in
  the following docs-only commit)**: signed bundles for
  `linux-x86_64-ubuntu24.04-cp312` and `macos-arm64-cp312` with
  `source_rev = e980058...`, signed with the demo release key the user's
  site already trusts. Gates run on 2026-09-17: `test_package_deb.sh`
  PASSED (key-material rejection, no-network install with the 27-tool
  protocol probe, tamper and zero-length-verifier negatives; evidence
  `out/package-evidence/deb/`), `test_package_pkg.sh` PASSED (payload
  identity, tampered payload rejected, native unit suite; evidence
  `out/package-evidence/pkg/`). Artifacts and SHA-256:
  `dist/universal-db-mcp_0.1.0~e980058889c42138bb26dd0b6e352f96239e890f_amd64.deb`
  `48719f76b8e66e4b09160e8aecff50e71a93505ef854ec7594aa09f82a9f537b`;
  `dist/universal-db-mcp-0.1.0-macos-arm64.pkg`
  `b2b16c18287f0bbdfdc419f91776a0f86a20968280c66522e191d98584488f7b`.
  USB folder for the Ubuntu site: `dist/usb-ubuntu-e980058/` (the .deb,
  `trust-bootstrap-linux/` with the key-rotation guard, `oracle-instantclient/`
  with Ubuntu 24.04's `unzip`, `UPGRADE-README.md` = the site runbook,
  `SHA256SUMS`, 12 files verified). It supersedes every earlier
  `usb-ubuntu-*` folder. Unchanged caveat: a .deb version of `0.1.0~<sha>`
  sorts lexically, so `dpkg -i` prints a downgrade warning when the new
  hash sorts lower; the runbook says to use `dpkg -i`, never `apt`.

## 4. Gates not (fully) run (recorded truthfully)

- **Gate D (egress observation):** harness provided
  (`scripts/observe_egress.sh`, strace-based, self-validating); NOT run —
  requires a Linux host with ptrace permitted. The `--network none` Gate
  A/B runs prove no successful egress but do not observe attempts.
- **Gate F (Claude Code + internal gateway + GLM end-to-end):** `not_run` —
  requires the organization's pinned client version and internal model
  gateway. Integration guide + `.mcp.json` provided. Any client startup/
  auth blocker must be reported against the client, not this server.
- **Gate G (upgrade/rollback exercise):** upgrade + rollback **passed** in a
  `docker --network none` container (2026-09-12T11:22:01Z, 23/23 checks,
  evidence: `out/package-evidence/upgrade/`) — install v1 → verified
  re-signed v2 → `upgrade_offline.sh` → doctor + protocol probes on v1/v2 →
  `rollback_offline.sh` → protocol probe post-rollback, with msodbcsql18
  OS-package state checked before/after. Remaining sub-cases recorded
  truthfully as `not_run`: systemd stop/start (the container gate has no
  systemd as PID 1; the scripts' guarded systemctl calls are no-ops there —
  exercise on a real systemd target before release) and the
  deliberate-interruption sub-case (interruption recovery is implemented in
  `upgrade_offline.sh`/`rollback_offline.sh` but was not exercised in the
  recorded run).
- **Gate C round 2:** the DB-side permission-denial proof is **passed**
  for PostgreSQL, and Oracle + SQL Server round-trips over themed fixture
  data are **passed** through the real connectors. IBM Db2 was `blocked`
  in that run; the cause was the connector never sending credentials,
  fixed 2026-09-15 (section 3), and Db2 11.5.8/11.5.9 now pass the version
  matrix (section 3d). The full metadata battery per engine is covered by
  the version matrix's probed subset, not by Gate C.

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
with connector set {sqlite, postgres, mysql, clickhouse, oracle, mssql, db2}
per the evidence above (Gate C round-trips passed for six; Db2 verified by
the 2026-09-15 live run and the version matrix, sections 3 and 3d).
