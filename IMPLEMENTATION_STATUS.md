# Implementation status (honest ledger)

Last updated: 2026-09-28. The 2026-09-27 production/security review (95
findings) and its fixes, the final round of 2026-09-28 included, are in §3f,
with the residuals that remain open, what could not be verified on this Mac,
and the owner actions. The project is licensed under Apache-2.0 (`LICENSE`,
`NOTICE`); vulnerability reports go through `SECURITY.md`. Earlier sections
are kept as they were recorded, with dated corrections where §3f found them
wrong. Before that: 2026-09-16 (native-packages §1d records the honest
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
  connector poisoned) and racy audit rotation (**correction 2026-09-27:**
  serialized between threads only; processes sharing one audit path raced
  until the cross-process lock of §3f, F24); column-mask bypass via
  aliasing (source-column taint analysis over the parsed AST; **correction
  2026-09-27:** masking stayed name-based for UNION branches, CTE column
  lists and unaliased expressions, the critical finding F01 of §3f); PyMySQL
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
  parenthesized EXPLAIN options now accepted (ANALYZE/WAL still gated;
  **correction 2026-09-28:** with `allow_explain_analyze: true` the guard let
  `EXPLAIN ANALYZE` through; ANALYZE is never run now, §3f);
  driver auth-failure usernames redacted (registered-secret registry +
  keyword backstop); audit/metadata-cache files created 0600 with
  systemd UMask=0077; baseline image digest-pinned and file-based
  signing everywhere; driver exceptions wrapped as ConnectorError on
  every engine (**correction 2026-09-27:** not on PostgreSQL metadata
  paths nor Db2/SQLite query execution until F17 of §3f); MySQL truncation
  no longer drains the result set; system schemas excluded from MySQL/Db2
  catalogs (**correction 2026-09-27:** the Db2 exclusion never shipped in
  `list_tables`; F26 of §3f); ClickHouse nullable
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
| Ubuntu `.deb` (linux-x86_64-ubuntu24.04-cp312) | full no-network gate **PASSED** 2026-09-12 (re-run green after the same-day positive-path failure; latest recorded run 2026-09-12T12:28:29Z) | `scripts/package/test_package_deb.sh` mirrors Gates A/B: sign → `dpkg-deb` build inside the baseline container → install under `docker --network none` → doctor with demo config → stdio protocol probe, plus a negative case (a tampered wheel repacked into the deb must fail closed at postinst verification with the canonical diagnostic). Evidence (`out/package-evidence/deb/results.json`, 2026-09-12T12:28:29Z, status `passed`, 29/29 checks): **positive path** — `dpkg -i` succeeded (preinst checked trust prerequisites only; postinst re-verified the unpacked payload through the existing `install_offline.sh` — no installer fork — at configure time: 91 artifacts, 42 pinned wheels, 11/11 bundle OS packages hash-checked, `signature: verified`); the dpkg-dependent install (venv, wheelhouse, bundle OS packages, service enable) then completed in a background worker after dpkg released its locks (20 s wait, `deferred-install.log`); doctor passed (12/12 checks, 0 fatal) against the deb-installed venv and the stdio MCP protocol probe passed inside the same no-network container. The minimal baseline image carries no `python3`/`python3-venv` .debs (its CPython 3.12 is installed outside dpkg), so the gate configures the package with forced dependencies — real ubuntu-24.04 targets satisfy the declared `Depends` normally. **Negative path** — a byte-flipped sqlglot wheel inside a repacked deb (its SHA256SUMS line refreshed so the rejection must come from the SIGNATURE, not the integrity hash) is rejected by the trusted verifier with the canonical `signature verification FAILED` diagnostic, and `dpkg -i` of the tampered package fails closed at postinst verification. Two further fail-closed negatives recorded in the same run: the builder refuses to build when public-key material is staged into the package root (`build_rejects_key_material`), and with no admin trust dir provisioned the postinst refuses to self-bootstrap a verifier from the package's own `trusted-tools/` copy — a stub verifier planted in the package is never executed and `dpkg -i` of that package fails closed (`no_admin_bootstrap`, `deb_verifier_stubbed`, `postinst_refuses_self_bootstrap`, `stub_verifier_never_ran`, `tampered2_dpkg_install_fails`). **Upgrade path (added 2026-09-18; latest run at 1617401: 50/51 gate checks passed, the rest `recorded`)** — in its own container the gate installs, plants a marker in a wheel-tracked file of the installed venv (the previous release's code) and an admin edit in `/etc/universal-db-mcp/config.yaml`, installs the same package again and proves the marker is gone (`upgrade_replaces_venv_code`: the trusted installer's `--force-reinstall` replaced the code; the 2026-09-15 site incident would fail this check) while the admin edit survives (`upgrade_keeps_admin_config`); then a trusted installer WITHOUT `--force-reinstall` is refused at preinst with the OUTDATED diagnostic and no worker starts (`upgrade_refuses_outdated_installer`), and after refreshing the trusted installer the upgrade succeeds again (`upgrade_after_refresh`); doctor's `installed-release` line is present. Added later the same day: the upgrade keeps `venv.previous` with its integrity manifest and `rollback_offline.sh` restores it (marker back: `upgrade_keeps_previous_venv`, `rollback_restores_previous_release`); a trusted installer without the `udbmcp-installer-format: 3` marker (4 since the 2026-10-02 review fixes) is refused at preinst too (`upgrade_refuses_unmarked_installer`, `upgrade_after_marker_refresh`); and `dpkg --compare-versions` proves the `<release>+<build stamp>.g<sha7>` version upgrades a legacy `0.1.0~<hash>` install and any older build stamp (`upgrade_version_ordering`). Still simulated: both installs use the same package. **`systemctl enable --now` under a real systemd PID 1: `not_run`** — the gate container runs without systemd; the unit is installed and the enable is guarded so container installs still succeed, but no host with PID 1 = systemd was exercised. Version provenance: the package version embeds the signed manifest's build stamp and source revision — `0.1.0+<YYYYMMDDHHMM>.g<sha7>` — so the artifact is tied to the exact source state that was signed and every build sorts after the previous one. |
| macOS `.pkg` (macos-arm64-cp312) | built + payload verified natively on this arm64 staging host; **the current package (built from 6edc579) was installed on this host by the user on 2026-09-18 with `sudo installer -pkg ... -target /` over the 2026-09-14 install (94069c3)**: `installer: The upgrade was successful`; per `/var/log/install.log` the preinstall found the trust prerequisites, the postinstall re-verified the unpacked payload with the trusted verifier (`integrity: 83 artifacts checked, full coverage verified`, `signature: verified against provided public key`), force-reinstalled the application wheel into the existing venv (site-packages dated 19:39, the new code present), left `/etc/universal-db-mcp/config.yaml` and the token untouched, and re-bootstrapped the LaunchDaemon; after `launchctl kickstart -k` the service runs as `_udbmcp` (new PID) on 127.0.0.1:8765 (HTTP 401 without a token) and its doctor reports `installed-release ... source_rev 6edc5795...` and `venv-interpreter` ok. Not observed: Gatekeeper prompting, since the command-line installer was used; **package is UNSIGNED** (no developer signing identity); the full 23-check gate was re-run and recorded **green** (latest recorded run 2026-09-12T12:38:10Z, status `passed`, 23/23 checks — closing the earlier 11:17:20Z 22/23 run whose single failed check was `unit_suite`, a transient race with concurrent edits, both affected tests passing on re-run); full `installer` run `not_run` | `scripts/package/test_package_pkg.sh`: the signed macos-arm64-cp312 bundle is built and re-verified by the trusted verifier before packaging; the wheelhouse is fully resolved **including the `ibm-db` `macosx_14_0_arm64` wheel**; the package payload is proven to be the signed bundle (`pkgutil --expand-full`, then the trusted verifier run against the expanded payload); and an executed tamper negative: a byte-flipped wheel inside a repacked COPY of the `.pkg` is rejected by the trusted verifier with the canonical FAIL diagnostic (`tamper_copy`, `wheel_tampered`, `tampered_payload_rejected` all passed). Evidence (`out/package-evidence/pkg/results.json`): the latest recorded run (2026-09-12T12:38:10Z) recorded status `passed` with 23/23 checks — `pkg_built`, `payload_signature_verified` (trusted verifier accepted the expanded payload), `no_keys_in_payload`, install-script hardening, all plist checks (incl. `launchd_label_consistency`), the executed tamper negative, and the native unit suite green for the on-disk package (`dist/universal-db-mcp-0.1.0-macos-arm64.pkg`, 12:35Z rebuild, `out/package-evidence/pkg/build-20260912T123541Z.log`, sha256 `16fa8266…`). History: an earlier same-day run (10:47:30Z) recorded 20/20 green before the tamper checks were added; the 11:17:20Z run added the first executed tamper negative (all three tamper checks passed) but failed `unit_suite` alone — two `tests/unit/test_hardening_gates.py` rollback tests raced with concurrent edits to `scripts/rollback_offline.sh` at gate time and both pass on re-run (verified after the rollback integrity-manifest behavior landed) — and the owed full re-run has since been recorded green as described above. An earlier same-day run (09:56Z) also passed all of its checks. preinstall validates trust prerequisites only (trusted verifier + admin pubkey, else exit with bootstrap instructions); postinstall re-verifies the payload, builds the venv with the same hostile-pip neutralization, and bootstraps the LaunchDaemon. **Honesty caveat recorded per the build log's explicit WARNING:** the `.pkg` is **UNSIGNED** — no Apple Developer ID signing identity is configured on this host, so Gatekeeper/`installer` will not attribute the package to a developer; product signing is an organizational key-ceremony step, not performed here. **The full `installer` run and the launchd daemon start: done on this host by the user on 2026-09-18 (see the status column); the gate itself still does not run them** (opt-in behind `UDBMCP_PKG_INSTALL=1`, off by default). Documented delta: macOS has no ProtectSystem-equivalent; the plist otherwise mirrors the systemd unit line-for-line. |
| Windows `.msi` (win_amd64) | **NOT built on this host, and cannot be**: the signed `windows-x86_64-cp312` bundle IS built (`out/bundle-windows`, source_rev at HEAD) but the WiX Toolset refuses to compile on macOS (v4.0.6 and v6.0.2: `WIX0389 Directory/@Name is not a relative path` for every directory, with `warning WIX0000: The WiX Toolset only supports Windows`; v7.0.0 additionally requires accepting the OSMF EULA, which is not mine to accept). The MSI needs a Windows build host; install gate `not_run` | The plan-Phase-0 prerequisites **ARE installed** on this staging host (user-local .NET 8 SDK `8.0.425` + the `wix` global dotnet tool, `6.0.2`; `wix` 7.0.0 was refused fail-closed at the OSMF-EULA gate, and `wix` 4.0.5/5.0.2/6.0.2 all behave identically below), and `scripts/package/build_msi.sh` was executed end-to-end against a freshly built, SIGNED `windows-x86_64-cp312` bundle (release 0.1.0, 42 wheels, no missing connectors; `out/bundle-windows/universal-db-mcp-0.1.0-windows-x86_64-cp312` with `SIGNATURE` + `SHA256SUMS`). Every first-party build step ran and passed: trusted-channel `verify_bundle.py --pubkey` verification (79 artifacts, signature verified, 42 pinned requirements), payload staging with a no-key-material scan, deterministic harvest, `xmllint` validation, and a real `wix build` that reached full authoring validation. The compile itself fails closed with 15× **WIX0389** (WiX-on-Unix rejects every `Directory/@Name` — a toolchain limitation, not an authoring defect: these are the ONLY remaining errors), so **no MSI was produced**, and MSI compilation therefore requires a **Windows** staging host. Evidence: `out/package-evidence/msi/results.json` + `out/package-evidence/msi/build-msi-build-only.log`. The stray 12-byte `universal-db-mcp-1.2.3-win-x86_64.msi` placeholder (literal `FAKE` after the OLE magic; its 1.2.3 version matched nothing in the signed manifest release 0.1.0, and it was not produced by `build_msi.sh`) was deleted from `dist/`; no `*.msi` exists there now. Delivered authoring, exercised as far as a Unix host allows: `scripts/package/build_msi.sh` + `packaging/msi/udbmcp.wxs` with the deferred, `Impersonate="no"` custom actions — trusted `verify_bundle.py` against the installed bundle with the admin pubkey, venv build `--no-index --require-hashes` with hostile pip env neutralized, doctor smoke, `sc.exe` service registration — implemented by `packaging/msi/custom/{verify,venv,doctor,service,uninstall}.ps1`, staged and wired by `build_msi.sh` via `-define CustomActionScriptsDir=…`. No Windows machine was available, so once built the install gate must be exercised on the target OS before anything is claimed: service behavior, the admin-supplied msodbcsql MSI, and NTFS ACL behavior remain unexercised — the ledger records **no pass for any Windows runtime step**. The gate script **`scripts/test_package_msi.ps1` is delivered** for a real Windows machine (msiexec with `/l*v`, `sc.exe query`, doctor, stdio protocol probe, tamper negative case, evidence JSON). |

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
  select TCPS and carries the wallet. (**Correction 2026-09-27:** that check
  used its own `tnsnames.ora` parser, which disagreed with the driver's, so an
  `IFILE` override or a column-0 continuation could dial plaintext; the alias
  is now resolved with python-oracledb's own reader and the checked descriptor
  is dialed, F31 of §3f.)
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
- **Package guard against outdated trusted tools (2026-09-18, commit
  d76c6c9)**: `preinst` and `postinst` refuse a trusted installer that
  runs pip without `--force-reinstall` (any copy from before 2026-09-15),
  naming the stick's trust bootstrap as the fix; the runbook's mandatory
  Step 1 is now enforced by the package. `doctor` reports an
  `installed-release` line (release, `source_rev`, build time) from the
  installed manifest. The release procedure is
  `scripts/package/release_usb.sh` (previously outside the repository).
- **Release artifacts (built from commit 1617401; this note was added in
  the following docs-only commit)**: signed bundles for
  `linux-x86_64-ubuntu24.04-cp312` and `macos-arm64-cp312` with
  `source_rev = 1617401995aa330934d40700ed0ff5f7e3df7728`, signed with the demo release key the user's site is
  anchored on (the stick's `RELEASE-KEY-FINGERPRINT.txt` carries the key's
  SHA-256 `ac11a6ad3432dde771ae620b1a1f5b7b726e1e79c6f8b072146fb22001ef5298`
  and says so). Gates run on 2026-09-18 by `scripts/package/release_usb.sh
  --demo`: `test_package_deb.sh` PASSED (50/51 checks passed, the rest
  `recorded`: key-material rejection, no-network install with the 29-tool
  protocol probe, tamper and zero-length-verifier negatives, and the upgrade
  case: code replaced, admin config kept, `venv.previous` kept and restored
  by `rollback_offline.sh`, an installer without `--force-reinstall` and an
  installer without the format marker both refused at preinst, recovery
  after refreshing the trusted installer, version ordering, doctor's
  `installed-release` line; evidence `out/package-evidence/deb/`),
  `test_package_pkg.sh` PASSED (23/23: payload identity, tampered
  payload rejected, native unit suite; evidence `out/package-evidence/pkg/`).
  Artifacts and SHA-256: `dist/universal-db-mcp_0.1.0+202609200401.g1617401_amd64.deb` `a11e646c157a39806e5a795b78460351ab7bc4ac6865465b53eb1af83741597f`;
  `dist/universal-db-mcp-0.1.0-macos-arm64.pkg` `ff0472e64b95032a161d213c8cb45a960ef87223ff7170931cda24dde44b9bec`. USB folder for the Ubuntu site: `dist/usb-ubuntu-1617401/` (the
  .deb, `trust-bootstrap-linux/` with the key-rotation guard,
  `oracle-instantclient/` with Ubuntu 24.04's `unzip`, `UPGRADE-README.md` =
  the site runbook, `RELEASE-KEY-FINGERPRINT.txt`, `SHA256SUMS`, 13 files
  verified). It supersedes every earlier `usb-ubuntu-*` folder. The package
  version `0.1.0+<build stamp>.g<sha7>` rises with every build, so `dpkg -i`
  no longer prints a downgrade warning; the runbook still says `dpkg -i`,
  never `apt`.

## 3e. Program to raise every area to 9/10 (2026-09-18)

Requested after the honest 7/10 assessment. What was done, with evidence:

- **Plans on Oracle, SQL Server and Db2** (commit f5b733f): `db_explain`
  captures plans without executing on all seven engines now. Live: Oracle
  Free 23 (`DBMS_XPLAN` text + rows) and Db2 11.5.9 (operators, costs,
  accessed objects, rows deleted after read-back) on the fixtures; the
  matrix `explain` check passes on Oracle 18.4/21.3/23 thin, 11.2/18.4/23
  thick, SQL Server 2017/2019/2022 and Db2 11.5.8/11.5.9 (22/22 each).
  Db2 needs DBA-provisioned explain tables (the probe provisions them on
  the test container; a site without them gets the exact
  `SYSINSTALLOBJECTS` instruction, nothing is created). SQL Server needs
  the SHOWPLAN permission, named when missing.
- **Federated reads** (commit 1a66c3c, 29 tools): `db_federated_query`
  (one statement on many connections, or one per connection, merged by
  shape, each guarded/bounded/masked under its own policy) and
  `db_federated_join` (client-side hash join of two guarded result sets,
  inner/left, row-capped, numeric keys normalised, masked values never
  match). Unit-tested on two SQLite connections; live across the
  PostgreSQL, MySQL and ClickHouse fixtures and a same-connection join.
  Moving or loading data stays outside this server by design.
- **Scale evidence** (commit cf98ecb, `test-evidence/scale/results.txt`):
  2,002 tables, a 901-column table and a 2,000,000-row table on the
  PostgreSQL fixture. Catalog paged to the end in 2.5 s, 100-table review
  in 1.1 s, 500-table search in 3 s, 50,000-row profile in 0.1 s. Two
  silent limits found and made explicit: the search now reports
  `tables_not_searched` (a needle in table 1,700 of 2,002 was "no hits"
  before) and the profile warns when its 60-column cap applied.
- **Monotonic package versions** (commit e736e81):
  `<release>+<build stamp>.g<rev7>` from the signed manifest; apt can
  upgrade, a legacy `0.1.0~<hash>` install upgrades cleanly (`~` sorts
  first); proven with `dpkg --compare-versions` in the deb gate.
- **Real rollback on the .deb path** (commit 2848942): the trusted
  installer builds the new venv beside the running one and switches with
  two renames (venv.previous + integrity manifest, interrupt-safe); venvs
  are created with `--copies` so the rollback verifier's symlink rule
  holds. The deb gate installs, plants a marker, upgrades, asserts the
  previous release is kept, runs `rollback_offline.sh` and asserts the
  marker is back; all green.
- **HTTP over TLS with a real client** (`test-evidence/http-transport/`):
  the MCP SDK's streamable HTTP client through an nginx TLS terminator,
  initialize + 29 tools + a call, HTTP 401 for wrong/missing tokens before
  any tool runs; the reverse-proxy `Host` rule is documented.
- **MySQL `NO_BACKSLASH_ESCAPES`**: LIKE escaping verified under that
  mode (`test-evidence/session-safety/mysql-no-backslash-escapes.txt`).
- **Site check**: `universal_db_mcp site-check` runs the agent's tools
  read-only on every connection and writes a value-free JSON report for
  the first run at the site (runbook step); the report is written mode
  0600 and never over an existing file (`--force`).
- **Reviews of the program (2026-09-18)**: a correctness review and a
  security review of the commits above (f5b733f..cd81c8e), both by
  independent reviewers with the code in front of them; the security
  review confirmed no vulnerability and listed hardening items. Every
  finding was applied and pinned by
  `tests/unit/test_review_fixes_2026_09_18.py`: join keys longer than 28
  digits were rounded by `Decimal.normalize()` and `-0` did not equal `0`;
  `db_explain` silently dropped `parameters` (now refused) and re-rendered
  the AST, which lost Db2 `WITH UR`/`OPTIMIZE FOR` (the validated text is
  sent as written on every engine); the value search did not name the
  connections the budget never reached (`connections_not_searched`,
  `connections_failed`); `db_federated_join` output had no byte ceiling
  (now the stricter of the two policies); `db_federated_query` could run a
  statement and drop its result after the fact (each statement now runs
  with what is left of the shared ceiling and is always reported); the
  federated tools left one audit record for many statements (one record
  per statement now, same request id); the guard accepted `NEXT VALUE
  FOR`, Oracle `NEXTVAL`/`CURRVAL` and every T-SQL table hint (only
  NOLOCK, READUNCOMMITTED, READPAST, NOWAIT remain); a failed Db2 explain
  cleanup was swallowed (a warning now; the explain-table grants
  documented); `release_usb.sh` defaulted to the demo key (a key
  pair or `--demo` is now explicit, the fingerprint is printed and shipped
  as `RELEASE-KEY-FINGERPRINT.txt`); the trusted installer carries a
  format marker (`udbmcp-installer-format: 3`, now 4) that preinst/postinst
  require of any pip-running copy (deb gate case added); `live_evidence.py`
  implied DDL consent from a config file name (flag always required);
  `http_client_evidence.py` could leak its server and proxy on a failure
  (cleanup always runs, unique container name, stderr to a file); the
  copied interpreter of a `--copies` venv is documented and `doctor`
  compares it with its base (`venv-interpreter`).
- **Not raised from here, stated plainly**: the site's own confirmation
  (only your run can give it; the site-check exists to make that run
  structured), the Windows MSI (WiX does not compile on macOS, see §1d),
  Apple signing of the .pkg (no identity), and Oracle 12c (no
  redistributable image; expected to work, `not_run`). The .pkg built from
  6edc579 was installed on this Mac by the user afterwards (§1d macOS row):
  a real `installer` upgrade, payload re-verified, service restarted on the
  new build.

## 3f. Production/security review 2026-09-27

A multi-dimension production and security review of HEAD c9490d8 (each
candidate checked by separate reproduction, reachability and mitigation
passes, plus five gap probes: live guard claims, SQL Server live through the
msodbc image, guard parse cost, HTTP pre-auth resources, the MSI custom
actions) confirmed **95 findings: 1 critical, 14 high, 42 medium, 38 low**
(ids F01-F95 below; the finding list itself is not archived in the
repository). Its verdict was "not production-ready". The fixes were
implemented by eleven file-scoped code groups, reviewed in up to three rounds
each, then an
integration wave closed what those reviews and a triage of every group's
open items left, an owner decision on unqualified table names was
implemented and reviewed twice, a final round (2026-09-28) closed what the
integration reviews found and implemented the owner's decisions of that day,
reviewed again group by group, and a docs stage followed. A convergence wave
(2026-09-29, below) then fixed the remaining findings by class, attacked the
result again in three re-attack rounds, and ended with this docs stage. The groups
checked their changes live against the loopback fixtures (PostgreSQL,
MySQL, ClickHouse, Oracle Free 23, Db2 11.5.9, and SQL Server 2022 through
the msodbc container); those runs are in the session's scratch records, not
in `test-evidence/` (see "Not verified" below).

**Owner decisions (2026-09-27, binding):** Apache-2.0 license; unqualified
table names refused when `allowed_schemas` is set; a connection-level
`read_only: false` rejected at config load; `audit_path` defaults to the
platform state directory; the macOS `.pkg` requires a root-owned Python;
vulnerability disclosure through GitHub private vulnerability reporting only
(`SECURITY.md`); masking of columns used only in predicates is a documented
limitation; git history is the owner's job.

**Owner decisions (2026-09-28, binding):** Oracle `DUAL` (bare or
`SYS.DUAL`) and Db2 `SYSIBM.SYSDUMMY1` to `SYSDUMMY4` hold no data and are
readable whatever the allowlists open (a bare `DUAL` where it names
`SYS.DUAL`; see the residuals); nothing else in `SYS` or `SYSIBM` opens. Run
on the install target without `--installed-manifest`, `verify_bundle.py`
compares with the platform's installed manifest, so a `.pkg` or `.msi` built
before this release, whose scripts name no manifest, is still refused as a
downgrade; release gates pass `--no-installed-manifest`. Container hosts
keep a root-owned release record, `/var/lib/universal-db-mcp/release.json`,
that `load_images_offline.sh` compares and updates after a successful load,
with the same `--allow-downgrade` override as the `.deb` and `.pkg`. The
maintainer identity is `universal-db-mcp maintainers` with no published
address (Debian's Maintainer field requires one, so the `.deb` carries the
reserved, non-routable `maintainers@universal-db-mcp.invalid`) and no
repository URL until the GitHub repository exists. Driver error text keeps
redacting quoted fragments. The ClickHouse memory ceiling is a documented
account-profile requirement, not a new option.

**What was fixed** (every item has regression tests in
`tests/unit/test_hardening_2026_09_27_*.py`,
`tests/unit/test_hardening_2026_09_28_final_guard_server.py`,
`tests/unit/test_hardening_2026_09_28_converge_*.py`,
`tests/unit/test_hardening_2026_09_28_credential_views.py` and
`tests/unit/test_hardening_2026_09_29_*.py`; behaviour for operators is in
`docs/site-upgrade-runbook.md`, "Behaviour changes in this release"):

- **Masking (F01, the critical finding).** Masking was decided by output
  column name, so UNION branches, CTE column lists, unaliased expressions and
  whole-row casts returned masked columns on every engine. It now follows
  each output position to its source columns (set operations, CTEs recursive
  ones included, derived tables, whole-row references, PostgreSQL attribute
  notation checked against catalog columns, ClickHouse aliases and tuple
  access, SQL Server `FOR JSON`/`FOR XML`) and fails closed, masking every
  unproven column, when it cannot trace a statement. A name outside ASCII or
  with blanks around it is also matched in its NFKC form, stripped (`ＭＲＮ`,
  `MRN `). On MySQL a TREE or JSON `db_explain` plan of a statement that
  names a masked column, selects `*` or joins NATURAL is withheld, because
  MySQL prints the const-table values it read while planning into those
  formats; `FORMAT=TRADITIONAL` plans are returned.
- **SQL guard (F02, F03, F04, F06, F20, F25, F87, F89-F91).** T-SQL:
  unquoted reserved keywords as aliases, statement separators (control
  characters, zero-width space, BOM), fused money/binary literals (`$1e5`)
  and currency symbols anywhere in a token are refused, because SQL Server
  would run the rest as another statement; every SQL Server name must be
  printable ASCII without a trailing blank, because its collations read other
  spellings as another name. Db2 delimited names may not end in blanks and
  Oracle unquoted names may not contain `ı` or `ſ` (each engine reads them as
  another name), and ClickHouse quoted identifiers may not contain a
  backslash (ClickHouse decodes escapes in them). MariaDB `/*M! ... */` and
  `SET STATEMENT` are refused. Comment-boundary differentials (bare CR, MySQL
  `--`, nested block comments) are refused. The Db2 read-tail regex is linear
  (a 64 KiB statement took about 25 s before). EXPLAIN options are an
  allowlist and ANALYZE is never run: `allow_explain_analyze` only picks the
  refusal for `analyze=true` and for ANALYZE in a PostgreSQL, MySQL,
  ClickHouse or Db2 statement (`POLICY_VIOLATION` while false,
  `VALIDATION_ERROR` while true); Oracle and SQL Server have no ANALYZE form
  and SQLite cannot parse one, so ANALYZE in their text is
  `POLICY_VIOLATION` either way. Unterminated literals are a policy denial, not an internal error. A name
  after `IN` without parentheses (`x IN t`, which ClickHouse and SQLite read
  as a table) and ClickHouse `{name:Identifier}` are refused; placeholders
  and constants after `IN` (ClickHouse `IN {ids:Array(UInt64)}`) stay
  accepted. CTE references are scope- and case-folding-aware per engine. On
  ClickHouse (live, 26.3) a bare name counts as a CTE only where ClickHouse
  binds it to one, and CTEs that name each other in a cycle, WITH RECURSIVE
  ahead of a set operation, a WITH on a parenthesised first operand and a CTE
  body reading a name another CTE declares elsewhere are refused; on every
  engine a WITH after UNION, INTERSECT or EXCEPT followed by further branches
  without parentheses is refused.
- **Qualified names (F05, F06, owner decision).** Under a non-empty
  `allowed_schemas`, statements must schema-qualify every table (the engine
  would otherwise bind a bare name through its search path), with the schema
  spelled as the catalog lists it; metadata tools resolve bare names only
  inside the allowlist. Schemas whose names differ only in case are told
  apart against the full schema list (`list_schemas`, read only under an
  allowlist and kept in memory for 300 s): an entry admits the spelling the
  engine folds it to (a mixed-case entry its exact spelling first), and the
  other spellings are refused in statements, `SHOW TABLES FROM`, the
  metadata, sample and profile tools, and hidden from the schema and table
  listings (not from the view, synonym and routine listings; see the
  residuals). Verified live on PostgreSQL and ClickHouse.
- **System schemas and SQLite catalog (F20, F21, F25, F26).**
  `allowed_system_schemas` governs the guard and every engine's table
  listing (the view, synonym and routine listings apply the allowlist only;
  see the residuals) (Oracle's list extended to the 9i-11g and APEX owners, and the 9i
  JServer and trace owners); SQLite's `sqlite_*` catalog and virtual tables
  are unreadable; `db_list_databases` is filtered; FK targets in hidden
  schemas read `<not permitted>`. Views of other sessions' SQL, bind values
  and audit records (`SESSION_SQL_VIEWS` in `discovery/system_schemas.py`:
  MySQL's processlist and InnoDB transaction, lock and full-text views,
  PostgreSQL's `pg_stat_activity` and statement-statistics extensions,
  ClickHouse's query logs, Oracle's `V$SQL` family, AWR and audit trails, SQL
  Server's `dm_exec_*`, Db2's `SYSIBMADM` monitors and explain tables) are
  refused on every connection whatever `allowed_system_schemas` opens, in
  every spelling the engines fold to them, and left out of the table
  listing that `db_list_tables`, the catalog and search tools, value search
  and relationship inference share, and (from the convergence wave) of
  `db_list_views` on PostgreSQL, Oracle and Db2 and `db_list_synonyms` on
  Oracle and Db2; MySQL's connector never lists the `information_schema`,
  `sys` and `performance_schema` ones.
  Statements read Oracle `DUAL` and `SYS.DUAL` and Db2
  `SYSIBM.SYSDUMMY1`-`4` whatever the allowlists open (owner decision
  2026-09-28); they are listed only where `SYS` or `SYSIBM` is opened, and
  under `default_deny_objects` the metadata tools follow the listing. Every
  server engine lists the database's own
  objects before those of opened system schemas. **Correction to §1c:** the
  Db2 system-schema exclusion recorded there never shipped in `list_tables`;
  it does now.
- **Denial of service in one call (F07, F08, F09, F11, F12, F39, F40, F84).**
  ClickHouse streams under a wire and an object budget and is stopped with
  `KILL QUERY`; value caps are applied on the server on
  PostgreSQL, MySQL, SQL Server, Oracle and Db2 and inside SQLite (with a
  process-wide heap limit); connection lists are capped at 64 and
  de-duplicated; the executor no longer leaks concurrency tokens, queues
  behind the connection gate before the global limiter, holds calls to one
  database server to `max_concurrent_queries - 1` global tokens (from a limit
  of 3; at 2 only abandoned calls count), refuses a connection while a driver
  call abandoned on it has not returned, and parks hung connects in a
  10-slot budget.
- **Tool behaviour (F41, F42, F60, F66, F95).** Value search reads every
  searchable column in chunks and merges a row matched in several chunks;
  schema-wide listings assign columns and keys to tables by exact name;
  parameters must be JSON scalars; list cursors are bound to their filters;
  the truncation warning no longer claims limits were applied server-side.
- **HTTP transport (F13, F57, F69, F92).** Header deadline, head-size cap
  (431), bearer check on the request head (401 before the body), rate-limited
  pre-auth logging, a bounded log file, a raised descriptor limit, and a
  bearer token of at least 32 UTF-8 characters.
- **Errors, limits and audit (F16, F17, F18, F22, F23, F24, F67, F68, F71,
  F72, F86).** Driver error text is sanitized and statement errors are
  `QUERY_ERROR`; every driver exception is wrapped (**correction to §1c**: the
  "wrapped on every engine" claim there was not true for PostgreSQL metadata
  paths and Db2/SQLite query execution until F17); `max_response_bytes` is
  enforced by every pager with a backstop; audit fields are bounded; every
  statement of the discovery and federated tools is audited; the audit log is
  serialized across processes by a lock sidecar (**correction to §1c**: the
  rotation fix recorded there was between threads only) with bounded waits;
  SDK-refused calls are audited; the audit path defaults to the platform
  state directory; stdio SIGTERM leaves `cancelled` records.
- **Connectors (F10, F19, F30-F36, F37 in part, F38, F75, F76, F82, F83, F85,
  F88).** ClickHouse quoting; PostgreSQL infinity/BC dates and JSON types;
  Oracle alias TLS resolved with python-oracledb's own reader (**correction
  to §3b**: the TCPS gate recorded there used its own `tnsnames.ora` parser,
  which disagreed with the driver), Thick-mode TLS with DN matching and
  `cwallet.sso`, LOB caps, `enable_thin_mode()` before every Thin connect (a
  hung listener no longer blocks the other Oracle connects), a bare `DUAL`
  checked in the session that runs it and the connector's own probes on
  `SYS.DUAL`; Db2 host-name validation and a bounded TLS liveness probe; SQL
  Server explicit rollback and `Cursor.cancel()`; connect timeouts honoured;
  every connector has `close()`.
- **Config and state files (F27-F29, F51, F52, F70, F73, F74).** Duplicate YAML
  keys refused; `read_only: false` refused; the metadata cache trusted only
  when private; Windows ACL checks for secrets and the token; relative paths
  resolved against the config directory; inline Oracle wallet passwords
  refused; state files kept apart from secrets and Oracle client files (for a
  full Oracle Client, `lib_dir/../network/admin` too); the system config
  recognised case-insensitively on macOS and Windows; with `audit_path`
  unset, a home directory that is the filesystem root or relative fails
  config load.
- **CLI and agents (F43-F50, F58, F77-F79, F81).** `add-connection` updates in
  place, writes atomically with backups that carry only the config's
  permission bits, refuses unsafe root writes; `configure-agents` registers
  `python -I`, writes atomically with private backups, refuses configs it
  would have to override or could not replace faithfully (another owner, a
  group it would change, hard links, an access control list other than the
  one its directory gives every new file), names launches without `-I` also
  inside shell command lines, and exits 2 when a harness failed closed and
  `--agent` names it or `--yes` asks for a write; `site-check --out` never
  follows a symlink; both commands print the stdio credential notice.
- **Packaging and supply chain (F14, F15, F53-F56, F59, F61, F63, F64, F93,
  F94).** The release stick's file list is signed (`SHA256SUMS.sig`) and the
  installed `bootstrap.sh` checks it with the installed key before anything
  from the stick runs, stages its copy under `/var/tmp`, refuses a stick that
  changes while it is read, and copies the stick's packages into root-only
  `/var/cache/udbmcp-trust`, re-checked, for `dpkg -i`; every installer
  refuses an older `release_seq` unless told otherwise (deb, tarball, `.pkg`
  flag file, MSI property and record, and the container loader's release
  record); on the install target `verify_bundle.py` compares with the
  platform's installed manifest by default (release gates pass
  `--no-installed-manifest`); the MSI's ProductVersion follows `release_seq`,
  and its rollback copy of the release record no longer outlives the install;
  the macOS `.pkg` runs only a root-owned CPython; root-side Python runs
  isolated; the container loader is a trusted tool; Stage A downloads only
  hash-locked dependencies with a pinned build backend; the MSI protects
  `%ProgramData%\UniversalDB MCP` and its token, keeps the service account
  across repairs (a virtual `NT SERVICE\` account included), and creates
  `logs\` for a dedicated account; LICENSE/NOTICE ship in the wheel, the
  bundle and the `.deb`, and the wheel, the `.deb` and the MSI name
  `universal-db-mcp maintainers`; CI (`.github/workflows/ci.yml`: unit suite,
  ruff, mypy, lock check, pip-audit, SHA-pinned actions; in CI the MSI
  custom-action tests fail rather than skip without pwsh) and a tree-hygiene
  gate exist.
- **Docs (F65, F80, the docs stages).** `SECURITY.md`; the Claude Code guide
  rewritten around `configure-agents`; the site runbook checks the stick
  signature with the host's openssl before running anything from it; the
  behaviour changes documented for upgrading sites; the landing page's claims
  qualified (stdio, masking, the tamper story, the plan rows `db_explain`
  writes on Db2 and Oracle). A last review of the documents against the code
  narrowed what they claimed: the view, synonym and routine listings (below),
  the engines on which `allow_explain_analyze` picks the refusal, the Db2
  explain-table grants (INSERT, SELECT and DELETE), a README quick start that
  signs the bundle its installer verifies, the bearer-token length `doctor`
  does not check, and the MSI downgrade rule; the site and this ledger give
  one test count. The convergence wave's docs stage brought every document
  to that wave's code: the settings each connector holds for the guard, the
  new refusals and the views they cover, the listings, the audit's
  coalescing and text budget, the executor's server keys, the ordered
  sticks, the installers' private copy and the macOS log files
  (`tests/unit/test_hardening_2026_09_27_docs.py`, convergence section). A
  review of that stage narrowed its claims again: a bare PostgreSQL
  dictionary name no system-schema rule closes, what a client cancel
  changed, the summaries an audit window can write, the Oracle
  `q'...'` literals the guard cannot parse and its own database-link text,
  the Instant Client files a hard link can still reach, the MSI's
  `NT SERVICE\` names, the modes of the installers' private copy, what the
  upgrade backs up at `metadata.sqlite`, the ClickHouse settings
  `config.example.yaml` names and the site's test-count date (same file,
  convergence fix-up section).

**Convergence wave (2026-09-29).** The working tree then held three
hardening waves. This one closed the long tail by fixing each class of
defect a finding belonged to rather than its repro, then attacked the
result in three re-attack rounds, each followed by a fix-up and a review of
the fix-up; the groups checked the fixes live on the loopback fixtures
(session scratch records, not `test-evidence/`). What it changed, by class:

- **The server reads a statement differently from the guard.** Every
  connection now holds, and checks on the server, the settings that decide
  how statement text is read, and is refused otherwise ("... the server
  would read statements differently from the SQL guard that checked them"):
  MySQL/MariaDB `sql_mode` without the ten lexing flags, then `SET NAMES
  utf8mb4` (live: under a site `sql_mode` of `ANSI,NO_BACKSLASH_ESCAPES` a
  literal the guard saw as one string read `information_schema.PROCESSLIST`);
  PostgreSQL `standard_conforming_strings`, `backslash_quote` and a UTF8
  client encoding (live: under `SJIS` the guard's `¥` was a backslash to the
  server); SQL Server `QUOTED_IDENTIFIER ON`; Db2 `SQL_COMPAT = 'DB2'`; five
  ClickHouse reading settings where the profile changes them (live:
  `prefer_column_name_to_alias=1` changed an aliased value). The guard's
  side of the same class: PostgreSQL and Db2 `U&"..."` identifiers (live:
  a masked column returned unmasked through `U&"sea_temp_\0063"`), `@` read
  as a parameter, `@@` variables on every engine and MySQL user variables.
- **A table read the guard never saw.** ClickHouse's function `in(v, t)`,
  which sqlglot reads as an `IN` with nothing after it (live: `SELECT 1 IN
  in(0, system.one)` read a closed system schema under `[telecom]`), the
  functions that name a table or dictionary, `IN` over a wrapped single
  name, and an `a.b` ClickHouse reads as a table (authorized as that
  table, with CTE bodies and derived tables not seeing the outer FROM);
  Oracle database links in every spelling, in the guard and again in the
  connector before any session opens (live: `"DUAL"@lnk` reached the
  engine as a link read, ORA-02019); the bare-`DUAL` check and all Oracle
  catalog SQL reading `SYS.ALL_*` (a login schema's own `ALL_OBJECTS` had
  hidden its `DUAL`), PostgreSQL catalog SQL naming `pg_catalog`.
- **Dictionary views that hand back masked values or secrets.** Column
  statistics (live: MySQL's `information_schema.COLUMN_STATISTICS` returned
  a masked value from a histogram under the default configuration), the low
  and high values of column catalogs (Oracle `*_TAB_COLUMNS`/`COLS`, Db2
  `SYSCAT.COLUMNS`), stored credentials in `CREDENTIAL_VIEWS`, and more
  Oracle and SQL Server views of other sessions' SQL, refused to every tool
  and left out of the table, view and synonym listings; Oracle's
  column-statistics and column-catalog names now match only bare, `SYS` or
  `PUBLIC` names, so an application table such as `TRAVEL.COLS` reads
  again.
- **A listed name the engine binds to another object.** Under default-deny
  a name must be spelled as the catalog spells it and a bare one must be in
  the session's first schema; without default-deny, synonym and alias
  chains go through every check a written name gets; SQL Server's
  compatibility views are `sys.<name>` everywhere.
- **Cheap calls that fill the audit trail.** A refused `db_query` wrote two
  records with up to 64 KiB of text each (about 132 KiB), so a token holder
  could rotate the 300 MiB trail away with calls that reached no database.
  Now a refusal is one record, repeats are coalesced into
  `tool_call_summary` records, a statement never sent keeps no text, and the
  text a window writes past each record's 1 KiB head and tail is capped at
  1 MiB. The metadata cache is keyed on what a connection reaches (a
  re-pointed id served the old database's table list for up to 300 s).
- **Which database server a connection is.** An Oracle `tns_alias` is keyed
  on the alias and its `tns_admin` (live: a dead listener behind one alias
  refused a healthy database behind another alias with the same
  placeholder host), a MySQL `unix_socket` on its socket; a statement
  counts as sent once the executor's worker begins its driver call.
- **Root acting on paths another account controls.** The verifier reads
  each bundle file once, never through a link, and refuses links, FIFOs,
  devices and a hard-linked `SHA256SUMS` or `SIGNATURE` (a symlinked
  `SHA256SUMS` in the staging copy was read twice); the installers' private
  copy keeps none of the bundle's owners or group and other bits (only the
  owner bits of each mode carry over), under a staging base and
  temporary directories root alone can change, with the verifier's output
  never in a temporary file; the `.deb`'s unit-hash record is root-only;
  `rollback_offline.sh --restore-config` never writes through a link;
  `bootstrap.sh` orders sticks by `trust-bootstrap-linux/RELEASE` and swaps
  in its checked `.deb` copies only after every check; the container
  loader creates its record directory before it verifies; the `.pkg`
  builds its app in `/var/tmp` and ships no newsyslog rule.

Re-attack rounds and results. Round 1 confirmed two findings: PostgreSQL
FDW and dblink stored credentials readable through `information_schema`
under the production defaults (`user_mapping_options`,
`foreign_server_options`), fixed by `CREDENTIAL_VIEWS` (extended in its
fix-up to the foreign-table and column options, `pg_hba_file_rules`,
MySQL's replication connection configuration and Oracle's
`V$DATABASE_LINK`, with synonym chains looked up without default-deny);
and `cp -a BUNDLE/. STAGING/` giving the private staging directory the
bundle directory's owner and mode, fixed by the copy at
`<base>/udbmcp-*.XXXXXX/bundle`. Round 2 confirmed two: under default-deny
the guard approved a name found in the listing while the engine read
another, unlisted object (a case variant, or a bare name bound to a
dictionary view first), fixed by the catalog-spelling and name-binding
checks; and without default-deny synonym and alias targets were checked
only against the never-readable lists, fixed by checking each chain step as
a written reference. Round 3 confirmed one: the macOS newsyslog rule let a
compromised `_udbmcp` account drive root's newsyslog into chmod and chown of
arbitrary files through planted archive symlinks, fixed by removing the
rule and moving launchd's output files to root-only `/Library/Logs`. All
five are fixed; each fix-up was reviewed again.

Corrections to this wave's earlier reports: the guard's value-column rule
did not hold through the server's CTE probe on the non-ClickHouse engines
(a live leak on Oracle) and cost quadratic CPU (5,500 references took 70 s,
now 0.24 s), and the empty-`IN`, Oracle-parameter and ClickHouse-qualifier
checks it called independent now are, each pinned by its own test;
"refused" first left out the executor's `LIMIT_EXCEEDED` refusals, and "one
`:statement` record per statement" was not literal, both now true as
described in `docs/security.md`, Audit; discarding a connection after a
client cancel is not new, since the committed release already did so (the
server's `poisoned_connectors`, for later calls only): what is new is that
the executor poisons it at once, so requests already queued on it are
refused, and fires the engine's cancel hook as on a deadline; a connect cut
short within its bound says nothing about its server unless it is still
connecting at its bound. Live listing counts on
the fixtures with no allowlist (2026-09-29): PostgreSQL's `db_list_views`
126 views (143 before), Oracle's `db_list_synonyms` 13,324 synonyms (13,583
before), Db2's `db_list_views` 269; none of them names a view
`is_session_sql_view` matches (they still name other dictionary views; see
the residuals).

**Residuals that remain open** (documented, not fixed):

- **Masking of predicate-only columns** (owner decision): a `WHERE`,
  `ORDER BY`, `GROUP BY` or `JOIN` on a masked column can still reveal its
  values. Column grants or views are the control.
- **`information_schema` beyond the allowlist** (pending an owner decision):
  under the default `allowed_system_schemas: [information_schema]`, `db_query`
  can read the names-only views (`TABLES`, `SCHEMATA`, `KEY_COLUMN_USAGE`,
  ...) about schemas outside a connection's `allowed_schemas`, and
  `information_schema.PARTITIONS` (a partition's bounds), so
  `allowed_schemas` does not scope catalog names. The credential views are
  refused since the convergence wave, and since the code review the
  definition views (`VIEWS`, `ROUTINES`, `COLUMNS`, `TRIGGERS`, `EVENTS`,
  `CHECK_CONSTRAINTS`, `PARAMETERS`, `ATTRIBUTES`, `DOMAINS`, MySQL
  `INNODB_COLUMNS`, per engine: `docs/security.md`, Object definitions),
  which handed back other schemas' view SQL and a masked column's DEFAULT
  literal.
- **Bare dictionary names without an allowlist:** with
  `default_deny_objects: false` and no `allowed_schemas`, PostgreSQL's bare
  `pg_roles` binds to `pg_catalog` and stays readable although `pg_catalog`
  is closed: the guard checks a bare name in the schemas the policy-scoped
  listing places it in, and that listing holds a system schema's objects
  only where the schema is opened (live on mock_pg, 2026-09-29: `SELECT
  rolname FROM pg_roles` valid, `pg_catalog.pg_roles` refused); of the bare
  names, only the views `is_session_sql_view` matches are refused there. On
  Oracle, SQL Server and Db2 each name is looked up as a synonym (Db2: an
  alias) and its chain checked, so a bare `ALL_USERS` is refused unless
  `SYS` is opened; that lookup matches a bare name against synonyms of that
  name in any schema, which is conservative, and costs one catalog read per
  statement or object with such names.
- **Values that masking cannot see, still readable:** the bounds of a
  table's partitions hold values of the partitioning column and are not
  refused: Oracle's `*_TAB_PARTITIONS`, `*_TAB_SUBPARTITIONS`,
  `*_IND_PARTITIONS` and `*_IND_SUBPARTITIONS` (`HIGH_VALUE`), Db2's
  `SYSCAT.DATAPARTITIONS` and `SYSIBM.SYSDATAPARTITIONS`, MySQL's
  `information_schema.PARTITIONS` (`PARTITION_DESCRIPTION`), PostgreSQL's
  `pg_class.relpartbound`, SQL Server's `sys.partition_range_values` and
  ClickHouse's `system.parts` (`partition`, `min_date`, ...), each where its
  system schema is opened (the comment on `COLUMN_VALUE_COLUMNS` records
  them). PostgreSQL's `pg_attribute.attfdwoptions` stays readable once
  `pg_catalog` is opened (the comment on `CREDENTIAL_VIEWS`).
- **Guard assumptions:** a bare Oracle `DUAL` is taken for the PUBLIC
  synonym (owner decision): `db_query` and `db_explain` refuse it where the
  session's current schema owns an object named `DUAL` or the logon changed
  `CURRENT_SCHEMA` (write `SYS.DUAL`), `db_validate_query` (guard only)
  reports it valid, and a PUBLIC synonym an administrator repointed is not
  checked. The ClickHouse CTE refusals are broader than ClickHouse needs
  (each names its rewrite). A SQL Server table or column whose name is not
  printable ASCII cannot be named in a statement (`SELECT *` and the
  metadata, sample and profile tools still reach it). A SQL Server schema
  namesake under a case-sensitive collation is covered by a unit test only.
  Refusals broader than the engine needs, each by design: a ClickHouse
  `readonly=1` profile pinned to `compatibility` 21.x or older is refused,
  although its old analyzer reads the CTE as the guard does (live); on
  Oracle the guard cannot parse an alternative-quoted `q'...'` or `nq'...'`
  literal, so a statement holding one is refused in every tool as a parse
  error, `@` or not (write the string in ordinary quotes; the connector's
  rule refusing such a literal with an `@` anywhere stays behind the
  guard); a CTE named like a value-column catalog (Oracle `cols`) is
  refused where the statement names a low or high value column, uses `*`
  outside `COUNT` or a column list after the reference's alias.
  `allowed_system_schemas` is one list for every engine, so naming `sys` for
  SQL Server or Oracle also opens MySQL's `sys`, whose `statement_analysis`
  and `statements_with_*` show normalized statement digests.
- **SQL Server backstop:** the multi-statement detection cannot see DML after
  `SET NOCOUNT ON`, DDL, `WAITFOR` or `COMMIT`; the guard and a
  least-privilege login are the controls.
- **HTTP pre-auth:** about 6.5k sustained connects per second can still
  exhaust 65536 descriptors at the 10 s header deadline; no connection cap by
  design.
- **Executor:** the owner has not confirmed that healthy calls to one server
  are held to `max_concurrent_queries - 1` (pinned by tests); once the
  stuck-connect budget is full, connects already running keep their tokens
  past their bound; a host name and its IP address count as two servers, and
  so do an Oracle `tns_alias` and a host/port connection to one database,
  two aliases for one listener, or a symlinked and a real `tns_admin` or
  socket path; up to `max_concurrent_queries + 10` driver calls can run at
  once.
- **Audit coalescing:** a process ended by a signal loses the refusal counts
  of its open 10 s window, the HTTP service on SIGTERM included (uvicorn
  re-raises the signal after its shutdown, so no exit handler runs); a
  summary is written only by the process that counted it, with its next
  record, its timer or its normal exit. Once the per-window text budget is
  spent, each statement record still carries up to about 2 KiB of text ends
  and a marker of about 170 bytes.
- **Unbounded connects (F37 stays open; only its driver-mode lock was
  fixed):** python-oracledb 4.0.2 bounds only the TCP connect of a Thin
  connect (`tcp_connect_timeout`; its connect, transport and expire timeouts
  were measured without effect), so a listener that accepts TCP and never
  answers holds the connect, and a Db2 TLS peer that answers the liveness
  probe and then stalls the client's connect does the same. Only the
  executor's stuck-connect budget bounds them (10 slots, at most 9 per
  server, after `max(connect_timeout_seconds, 5 s)`); requests queued on the
  same connection fail at the first one's deadline with the misleading text
  "connection is in an uncertain state after a previous cancelled query".
- **Engine memory:** ClickHouse server memory is bounded only by the account
  profile's `max_memory_usage`, a documented requirement (owner decision
  2026-09-28; a guard-accepted `repeat(col, 700000)` OOM-killed the fixture
  container; superseded 2026-10-03: the connector now sends a per-query
  limit, and only `readonly=1` accounts rely on the profile, see the third
  code review below); one row whose `arrayJoin()` or JOIN expansion
  decodes past the object budget is refused, not truncated (a `LIMIT` in the
  statement is the remedy), and clickhouse-connect 1.8's Variant, Dynamic,
  JSON and geometry readers were not measured one by one. SQLite shapes the
  in-engine cut cannot reach can use up to 512 MiB of heap before refusal, a
  process-wide limit the metadata cache shares (a `MemoryError` in a
  concurrent cache write fails that call with `INTERNAL_ERROR`). One large
  Oracle native JSON document is decoded whole (about 8x its size); Db2
  `CODEUNITS32` on a non-Unicode database is unverified.
- **Value search on Db2:** a needle longer than a column still fails a
  non-Unicode database's table (CLI0109E) until the server passes declared
  types, and a numeric needle outside a column's range fails its chunk
  (CLI0111E).
- **View, synonym and routine listings:** `db_list_views`,
  `db_list_synonyms` and `db_list_routines` filter by the policy only under
  an allowlist (`_scope_listing` in `server.py`), by schema and ignoring
  case. Without `allowed_schemas` they return the connector's catalog,
  dictionaries included; under it they also keep the system schemas
  `allowed_system_schemas` opens (since the code review no longer the case
  namesakes of an allowed schema). Since the convergence wave the connectors leave out every view
  `is_session_sql_view` matches (other sessions' SQL, column statistics,
  stored credentials), and a synonym or alias whose chain reaches one, from
  PostgreSQL's, Oracle's and Db2's view listings and Oracle's and Db2's
  synonym listings. Live on the fixtures (2026-09-29, no allowlist):
  PostgreSQL's `db_list_views` names 126 views, `pg_catalog.pg_tables` and
  `pg_roles` among them but no longer `pg_stat_activity`, `pg_stats` or
  `information_schema.user_mapping_options`; Oracle's `db_list_synonyms`
  names 13,324 synonyms, the PUBLIC `ALL_USERS` and `ALL_TAB_COLUMNS` among
  them but no longer `V$SQL`, `V$SESSION`, `ALL_TAB_HISTOGRAMS` or the
  `*_DB_LINKS` views; Db2's `db_list_views` names 269 views, `SYSCAT.TABLES`
  and `SYSCAT.COLUMNS` among them but no longer `MON_CURRENT_SQL` or
  `COLDIST`; Db2's `db_list_routines` still names the `SYSIBM`,
  `SYSIBMADM`, `SYSPROC` and `SYSFUN` routines. They are names only (no
  statement reads a view the policy refuses); an allowlist that does not
  open the view's system schema leaves it out.
- **Engine differences:** on SQLite a cell cut to `max_cell_bytes` is
  reported by its warning only (`truncated` stays false unless the row or
  byte limit cut the result); the other engines also set `truncated`.
- **Error text usability (F16, owner decision 2026-09-28):** identifiers the
  caller wrote also read `<redacted>` in driver errors, because keeping them
  would reopen a value oracle.
- **Anti-rollback gaps:** a `.pkg` or MSI built before this release passes no
  manifest to the site's trusted verifier, so it is refused only once the
  site's trust directory holds this release's `verify_bundle.py`, whose
  default on the install target compares with the installed manifest; until
  then it can replace a newer install. Such a `.pkg` is refused in its
  postinstall, after the Installer has written its bundle folder, share
  scripts and LaunchDaemon plist, which it does not put back (re-install the
  current `.pkg`). MSIs now take their ProductVersion from `release_seq`, so
  Windows Installer's `MajorUpgrade` refuses an older MSI, the 0.1.0 ones
  included, over a newer install, and after an uninstall the kept record
  `C:\Program Files\UniversalDB MCP\manifest.json` refuses it through the
  trusted verifier (neither seen on Windows). On container hosts the record
  `/var/lib/universal-db-mcp/release.json` protects from the first load by
  this release's loader on, and a host that also runs the native package,
  whose `/var/lib/universal-db-mcp` belongs to `udbmcp`, must point
  `UDBMCP_RELEASE_RECORD` at a root-only path. Release sticks are ordered by
  `trust-bootstrap-linux/RELEASE` once this release's `bootstrap.sh` has
  recorded one in `/usr/local/lib/udbmcp-trust/RELEASE`; until then
  (`nothing recorded yet`: the first upgrade, which runs an earlier
  release's bootstrap, unless it is run a second time as the runbook says)
  any genuinely signed stick is accepted, though its payload's
  `release_seq` is still refused. The site trusts the demo release key, so
  anyone holding it can mint a higher `release_seq` or `RELEASE` (owner key
  rotation).
- **Trust anchor:** a first install trusts the stick's key only through the
  out-of-band fingerprint comparison; the `.deb` is not debsig-signed and the
  `.pkg` is unsigned; `bootstrap.sh` copies and re-checks the stick's `.deb`
  files only: the Oracle Instant Client zip is copied and checked against a
  re-verified `SHA256SUMS` by the runbook's own commands, by hand
  (`docs/site-upgrade-runbook.md`, Oracle thick mode).
- **Supply chain (F56, F59):** lock hashes are whatever the index advertised at
  `--refresh-locks` time (review the lock diff); `pip` and `uv` on the staging
  host are not hash-pinned; uv does not hash-check build dependencies
  (`build-constraint-dependencies` pins their versions only); the manifest's
  `build_tools` are not verified; a source install into an environment with
  older transitive packages can keep them.
- **Windows:** the service is expected to fail with error 1053 (§3c, no
  service wrapper); an administrator-re-owned token with an SY/BA-only DACL is
  indistinguishable from a legitimate one; service-account files directly in
  the config folder block an upgrade until moved under `logs\`; a local user
  holding the release record's rollback copy or marker open can make an
  install fail (not lower the record), and with rollback disabled a copy can
  outlive its install; an interpreter owned by an administrator only through
  a domain group is refused; explicit (non-inherited) ACEs on agent configs
  are not checked, and the secret ACL check accepts a read grant to one other
  account (the service account).
- **`.deb` system config readable by every user (F80):** the conffile
  arrives `root:root` 0644, so `configure-agents` registers
  `/etc/universal-db-mcp/config.yaml` for a user on a fresh `.deb` host, and
  that stdio server refuses every call (it cannot write the service's audit
  log). Documented: the admin runs `chown root:udbmcp` and `chmod 640` first
  (`docs/claude-code-integration.md`); postinst and `configure-agents` do not
  handle it yet.
- **macOS launchd output files:** `serve` empties `server.log` and
  `server.err.log` in `/Library/Logs/universal-db-mcp` only when `_udbmcp`
  owns them with one link; if an administrator deletes one, launchd
  recreates it as root and it grows uncapped until the next `.pkg` install
  hands it back. The old `server.log`, `server.err.log` and `*.log.N.bz2`
  archives in `/var/log/universal-db-mcp` are left in place after an
  upgrade.
- **Other:** NFSv4 ACLs on agent configs are not detected; a `HOME` of
  `/..` (or `/tmp/..`) still derives a per-user audit default at the
  filesystem root (contrived: real service accounts get `/` or an empty
  `HOME`, both refused); `sudo
  configure-agents` does not cover a directory swapped for a symlink between
  check and write, and can print its credential notice and env-secret warning
  for the system config root reads rather than the per-user config it
  registered; launch recognition misses an interpreter named only through a
  shell variable (`"$0"`, `sh -c 'exec "$@"'` with separate args), one whose
  file name does not look like python, `python -m runpy` and PowerShell
  `-EncodedCommand`; on macOS the secret rename goes through the path after a
  device/inode check (no `renameat`); SQLite value search folds ASCII only; a
  ClickHouse catalog name containing `{name:Type}` fails that table's value
  search (a warning); `db_list_connections`/`db_test_connection` show the
  agent the absolute audit path (pending an owner decision); the guard's own
  table list is CTE-scope-aware on ClickHouse only (every server statement
  path compensates on the other engines); the stdio SIGTERM hard exit (5 s)
  covers only a cancel hook that SIGTERM fired, so a driver call or an earlier
  cancel hook holding the interpreter delays the stop until it returns or the
  supervisor's SIGKILL ends it; the repository's
  `examples/claude-code/.mcp.json` (not in the bundle) still shows a
  registration without `-I` that points at the system config, where
  `configure-agents` writes the right one; `upgrade_offline.sh` runs its two
  `doctor` checks without `-I` (with `PYTHON*` unset and `/` as the working
  directory); the CI hygiene gate runs inside the pytest run it guards, so a
  change that stops it being collected turns it off (conftests, test helpers
  and CI files still need a reviewer).

**Not verified on this Mac** (all `not_run`):

- **Windows:** no MSI has been built on Windows (WiX on Unix, §1d; since
  the code review the `.wxs` compiles and links with WiX 4.0.6 on this Mac
  apart from the Unix-host artefacts) and no Windows runtime step has run; the custom actions ran only under
  PowerShell 7 on POSIX with Windows APIs stubbed. Not seen on Windows:
  Windows Installer running the commit action `CommitReleaseRecordCA` after
  a successful install, real sharing violations on the release record's
  rollback copy, Windows PowerShell 5.1 running the scripts, the service
  manager accepting `NT SERVICE\udbmcp` with the derived SID, the registered
  account read back by AppSearch, and the older-MSI refusals above.
  `scripts/test_package_msi.ps1` (with the new checks `programdata_acl`,
  `token_squat_doctor`, `token_squat_refused`,
  `installed_manifest_recorded`, `rollback_refused`, `folder_squat_refused`,
  `launch_conditions`, `repair_keeps_account`) has not run. Windows
  secret-ACL and wizard DACL behaviour is verified only against mocked
  pywin32.
- **GitHub Actions:** neither the CI workflow nor the job-scoped Pages
  workflow has run on GitHub; the workflows pass `actionlint` and CI's
  install was replayed locally in Ubuntu 24.04 and Debian containers. On
  2026-09-29 the whole `checks` job (`uv sync --locked --all-extras`, the
  hashed pip install, `pytest tests/unit`, ruff, `mypy --strict src`,
  `--check-locks`, pip-audit over every lock) was replayed as a non-root
  user in a `linux/amd64` Debian 12 container with pwsh 7.4.6, so the MSI
  custom-action tests ran under x86_64 pwsh: ruff, mypy and the lock check
  clean, pip-audit "No known vulnerabilities found" for every lock, and the
  unit suite green once three tests stopped assuming that a SQLite build
  with dbstat lets the connector read it (SQLite 3.40's dbstat constructor
  makes an internal `UPDATE sqlite_master` check that the connector's
  read-only authorizer denies, so row estimates are None there by design;
  3.45 on Ubuntu 24.04 is not affected; `tests/unit/helpers_sqlite.py`).
  Unconfirmed: the `GITHUB_ACTIONS`-only pip and pwsh probes, a result for
  every push to `main`, and Dependabot's pickup of the `/.github` pip entry.
- **Apple signing:** the `.pkg` is unsigned (no Developer ID identity). The
  convergence wave's postinstall steps (the newsyslog rule removed,
  `/Library/Logs/universal-db-mcp` provisioned, the app assembled in
  `/var/tmp`) have not run under a real `sudo installer`; they are
  unit-tested.
- **The Ubuntu site:** the upgrade, the stick signature check with the site's
  installed key, `dpkg -i` from bootstrap's checked copies in
  `/var/cache/udbmcp-trust`, the site's own databases, and the `.deb` under
  a real systemd PID 1. The container loader's release record ran only with
  `docker` stubbed. The convergence wave's installer changes (the release
  order of sticks, the staged `.deb` swap, the root-only staging base and
  temporary directories, the private copy, the `.deb`'s unit-hash record)
  are exercised by the unit suite's script runs on this Mac, where the cases
  that need root or a second account skip, not on the site.
- **Recorded evidence predates this review.** `test-evidence/` (session
  safety, discovery tools, version matrix, HTTP transport) and the package
  gate results under `out/package-evidence/` were produced on 2026-09-12 to
  2026-09-20, before these fixes. `scripts/live_evidence.py` was re-run on
  2026-09-29 against the loopback fixtures: PostgreSQL, MySQL, ClickHouse,
  Oracle and Db2 give the recorded catalog, profile, review, federated and
  inference results, and PostgreSQL, MySQL and ClickHouse refuse a write
  with the guard bypassed (SQL Server skipped: no ODBC driver on this Mac).
  On 2026-10-03, at commit 5627468 (the code-review fixes plus a gate fix
  that keeps the gates' demo database out of world-writable `/tmp`, which the
  hardened metadata cache rightly refuses), `scripts/package/release_usb.sh
  --demo` ran clean: deb gate 50 passed + 1 recorded, pkg gate 23 passed,
  stick signature verified (demo key; not for a site).
  `scripts/package/test_upgrade_offline.sh` passed, `downgrade_refused`,
  rollback and the post-rollback probe included, and
  `scripts/http_client_evidence.py` passed (29 tools over TLS through nginx;
  wrong or missing token refused with 401; `test-evidence/http-transport/`
  refreshed). The version matrix was re-run the same day: 26 of 26 rows
  pass (PostgreSQL 12-17, MySQL 5.7/8.0/8.4, MariaDB 10.6/11.4, ClickHouse
  23.8-25.3, Oracle 18.4/21.3/23 thin and 11.2/18.4/23 thick, SQL Server
  2017/2019/2022, Db2 11.5.8/11.5.9; `test-evidence/version-matrix/`). Two
  harness fixes were needed: the Oracle probe seeded into `SYSTEM`, which the
  connector now leaves out of its listings as Oracle-maintained, so it seeds
  an ordinary `VM` schema; and the SQL Server and Oracle-thick runners no
  longer go on when `docker network create` fails (a host whose address pools
  are exhausted pre-creates the network with an explicit `--subnet`).

**Owner actions:**

- Git history and authorship (F62): placeholder author on every commit,
  earlier internal branding in history; decide squash or rewrite before any
  public push. The packages already name `universal-db-mcp maintainers`
  (`pyproject.toml`, `packaging/deb/control`, `build_deb.sh`, the MSI's
  Manufacturer).
- Generate a production Ed25519 release key offline, rotate the site to it
  with `bootstrap.sh --rotate-key` after an out-of-band fingerprint check,
  and retire the demo-signed artifacts (F55); sign the `.pkg` once a
  Developer ID identity exists.
- Create the GitHub repository, enable GitHub private vulnerability
  reporting (and secret scanning) on it (`SECURITY.md` points reporters
  there), and add the repository URL where it is left out today:
  `[project.urls]` in `pyproject.toml` and the site's `git clone
  <repository-url>` line (the site derives its links on `*.github.io` only).
- Run `uv sync --locked --all-extras` on the dev `.venv` while no test run
  is in flight: it has uvicorn 0.52.4 and no PyNaCl, where `uv.lock` pins
  0.53.0 and 1.6.2.
- Decide the pending items above: `information_schema` beyond the
  allowlist, the per-server share rule, exposing the audit path to agents,
  and the publishing gate (hold the push until the evidence re-runs, or label
  the Windows MSI and the unsigned `.pkg` experimental).

**Test status after this review:** `11393 passed, 250 skipped, 1 xfailed`
(0 failed; the xfail keeps the stdio SIGTERM limit above visible) for the
whole suite (`.venv/bin/python -m pytest -o addopts='' -q tests`) on this Mac
on 2026-09-29, after the convergence wave (2026-09-28: 9306 passed, 247
skipped) and the final checks (a Thick-mode TLS alias keyed on its own
`tns_admin` in the executor; the SQLite dbstat test assumption above);
`mypy --strict src` clean; `ruff check src tests scripts` clean. The 250
skips are the pwsh-driven MSI custom-action tests (no pwsh on this Mac; they
ran in the Linux replay above), the integration tests that need
`UDBMCP_TEST_*_HOST`, and single Windows- or Linux-only cases.

**Code review (2026-09-29 to 2026-10-02).** A `/code-review` at maximum
effort over this branch confirmed 73 findings and rated 6 more plausible;
all 79 are fixed, with regression tests in `tests/unit/test_cr_fix_*.py`.
By area (operator-visible behaviour in `docs/security.md`, `docs/tools.md`,
`docs/architecture.md`, `docs/claude-code-integration.md`,
`docs/offline-deployment.md`):

- **Bound parameters (two critical).** PyMySQL, clickhouse-connect's
  client-side binding and psycopg filled a `%s` inside a string literal or
  comment after validation, so a value could close the literal and become
  SQL (a `UNION` over a denied table, live). The driver now gets exactly the
  validated text (`sql_guard.bind_text`, each engine's own literal and
  comment rules, PostgreSQL `$tag$` quotes included); placeholder/value
  mismatches are `VALIDATION_ERROR`; PostgreSQL `parameters: []` binds
  nothing.
- **Guard and catalog views.** `information_schema` definition views
  refused and unlisted (other schemas' view SQL and DEFAULT literals, live);
  new session-SQL views (Oracle `V$DIAG_ALERT_EXT`, `V$RESULT_CACHE_OBJECTS`,
  ClickHouse `system.zookeeper(_log)`, PostgreSQL `pg_show_plans`,
  `pg_store_plans`); SQL Server legacy table hints without `WITH` held to
  the allowlist; optimizer hints inert except MySQL `MAX_EXECUTION_TIME`,
  `SET_VAR`, `RESOURCE_GROUP`; empty quoted names refused; Oracle CTE names
  folded by Unicode, PostgreSQL/Db2 under both foldings.
- **Masking.** `(expr).*`/`untuple`, case-variant and unbindable
  qualifiers, PIVOT/UNPIVOT aliases, SQLite engine-made names,
  `MATCH_RECOGNIZE`, `SEARCH`/`CYCLE`, aliases the driver reports
  elsewhere, decoy CTEs over a row function; DDL read with a tokenizer;
  namesake schemas left out of the listings and FK targets; discovery tools
  read only what `check_object` permits (Db2 `SYSIBM.SYSCOLUMNS`);
  `db_federated_join` `on` capped at 16 pairs; SQLite FTS/R*Tree shadow
  tables hidden and refused.
- **Connectors.** ClickHouse `LIMIT 0` statements stream under the budgets;
  Db2 `ORDER OF` only with an own `ORDER BY` (Db2 refuses it otherwise,
  428FI, which refused every LOB statement without one); MySQL 5.7/MariaDB star-over-join cut and prepare
  1461/1047; SQL Server half surrogate pairs; SQLite constant `GROUP BY`
  terms, `data_version`, a cancel that cannot be lost; SQL Server and Oracle
  deadlines before the statement starts; PostgreSQL 10 routine fallback
  (25P02); ClickHouse login and MySQL 1045 error text; a lone surrogate no
  longer drops the audit record; `customer_no`-style inferred links.
- **Config, audit, doctor.** Audit rotation never loses a generation
  (`<audit_path>.rotating`), no double-counted coalescer restore, a loosened
  log re-tightened to 0600; macOS ACLs on secrets and the token refused;
  non-UTF-8 files give a byte-free `CONFIG_ERROR`; `doctor` checks state
  directories, survives bad host names, expands `~` SQLite paths;
  `wallet_password_env` warned; stdio SIGTERM grace 3 s.
- **CLI, agents, wizard.** Fail-closed output shows only this tool's entry;
  as root a user's symlink or foreign hard link is not read; no machine
  paths added to a project `.mcp.json`; seeding failure is exit 1; `dsh`
  and `~user` overrides fail closed cleanly; the wizard refuses a group
  change it cannot keep and strips or refuses secrets-directory ACLs; the
  macOS Configure app's dialogs compile (it did nothing before).
- **MSI.** The `.wxs` compiles with WiX 4.0.6 (WIX0012 fixed);
  `SetPowerShellExe` before `InstallInitialize` (every uninstall and upgrade
  failed with 1721); `config.yaml` `Permanent`; `CheckFoldersCA` refuses
  writable or movable install/config folders and junctions; a failed repair
  keeps the service; an account claimed without a `logs\` grant is refused;
  the gate runs every check past `service_running`.
- **Packaging.** Installer format marker 4; `.deb` downgrade and
  outdated-verifier refusals in `preinst` (nothing unpacked), `abort-*`
  restarts the service; equal `release_seq` with another `source_rev`
  refused everywhere; `.pkg` declares the arm64 host and its scripts re-run
  natively, the verifier judges the hardware architecture; a failed
  manifest publish fails install/upgrade (it was skipped silently under
  sudo); rollback raises the anti-rollback record after an intended
  downgrade; `--restore-config` keeps the live `keys/` and `http-token`; the
  image loader uses the operator's docker daemon; the bootstrap test hook is
  refused as root; the deb gate's `no_keys_in_package` matches key material,
  not the verifier's PEM parser (it failed every run, so `release_usb.sh`
  aborted).

Still open after the review: an
Oracle Thin connect to a listener that never answers (F37); ClickHouse
server memory is bounded only by the account profile; the `.pkg`
`hostArchitectures` and native re-run need a real `sudo installer` on Apple
silicon and an Intel Mac to confirm; masking of predicate-only columns
(owner decision, unchanged); a view the database owner creates over an
SQLite shadow table is an ordinary, readable view.

**Test status after the code-review fixes:** `11804 passed, 267 skipped, 1 xfailed`
(0 failed) for the whole suite on this Mac on 2026-10-02; `mypy --strict src` and
`ruff check src tests scripts` clean. The CI job replayed on `linux/amd64`
(Debian 12, pwsh 7.4.6, non-root): 12009 passed, 37 skipped, 1 xfailed and 2
failed. Both were FTS tests that assumed SQLite 3.40 can build FTS tables under
the connector's read-only authorizer; they now probe it
(`tests/unit/helpers_sqlite.py::connector_reads_fts`) and the affected files
pass there (492 passed, 3 skipped); the no-leak assertions hold on both builds.
The same replay's pip-audit flagged `pyjwt 2.14.0` (PYSEC-2026-4141, a
transitive dependency of mcp the server does not use): `requirements/runtime.in`
now carries the floor `pyjwt>=2.15.0`, and `uv.lock` and the three profile locks
pin 2.15.1; `--check-locks` and pip-audit over every lock are clean.
`scripts/live_evidence.py` re-run on 2026-10-02 gives the recorded results
(the SQL Server driver diagnostic now names the driver instead of
`<redacted>`).

**Second code review (2026-10-03).** A second `/code-review` at maximum
effort, over the fixes commit (33a8477) and its follow-ups, confirmed 15
ranked findings and about 25 more. Among them: a security regression in the Oracle CTE fold (the
guard folded CTE names by Unicode upper case while the server's masking
backstop still compared `str.lower()`, so `WITH σ AS (... SELECT ssn ...)
SELECT * FROM ς` returned SSNs in clear; both now use one `cte_key`); a
regression of `'%%'` semantics (bound parameters made the DBAPI escape two
`%`, so `'50%%' = %s` compared differently); quadratic regexes (ClickHouse
login redaction and the `LIMIT 0` probe, live stalls of seconds from one
`db_query`); and a SQLite progress handler that slowed every statement next
to busy Python threads 25-250x. All are fixed, with regression tests in
`tests/unit/test_cr2_*.py`; operator-visible behaviour is in
`docs/security.md`, `docs/tools.md`, `docs/architecture.md`,
`docs/troubleshooting.md`, `docs/claude-code-integration.md`,
`docs/offline-deployment.md` and `docs/site-upgrade-runbook.md`:

- **Bound parameters.** `%%` in a string literal is one `%` again; `%%` in
  code and placeholders glued to a name, digit or quote are
  `VALIDATION_ERROR`; `a[1:n]` is no `:name` placeholder; PostgreSQL
  `ARRAY[%s]` binds again; `db_federated_query` hands each statement only
  the names it uses.
- **Guard and catalog views.** MySQL `STATISTICS.EXPRESSION`, `LIBRARIES`,
  `JSON_DUALITY_VIEW_TABLES` and SQL Server `ROUTINE_COLUMNS` refused;
  MySQL session hints refused however the hint body is spelled; SQLite
  `""` accepted again; name caches bounded.
- **Masking.** Wrapped or aliased stars, parenthesised joins and table
  functions of unproven width are runs of unknown width; spare CTEs are no
  qualifier sources; SQLite renamed aliases fail closed; SQLite view
  definitions judged by the view's own scopes (`db_list_views` and
  `db_get_table` agree, without listing every column of the schema); MySQL
  backtick names take no backslash escapes; PostgreSQL 63-byte alias cut
  accepted.
- **Connectors.** MySQL cancels with `KILL CONNECTION` and remembers an
  early cancel; PostgreSQL stops before the next `FETCH`; SQLite interrupts
  every handle until closed, with no progress handler, hides only real
  shadow tables and refuses a statement only when it reads one; SQLite and
  MySQL keep an output named by position in `GROUP BY`/`ORDER BY` whole
  under any spelling of the integer, and SQLite cuts the other outputs
  again under `random()`, `NULL` or a constant there; MySQL 5.7/MariaDB
  `o.*, c.*` over a join cut in place; metadata calls stay fast on
  thousands of SQLite tables;
  ClickHouse streams whenever `LIMIT` is in the text or a bound value;
  error text capped at 16 KiB before redaction.
- **Config, CLI, doctor.** YAML and decode errors carry no file content;
  macOS ACLs refused only when they grant access (wizard, root walk), and
  on the audit log, its lock and the metadata cache; doctor gains
  `audit-path-acl` and `metadata-cache-acl` and never ends in a traceback;
  `configure-agents` seeds a missing per-user config on a re-run; as root
  it reads no harness config the home owner may not read.
- **Packaging.** A refused `.deb` upgrade keeps the old `postinst` from
  spawning a worker, `preinst`/`postinst` refuse while another deferred
  install runs, `abort-*` without a venv records `failed`; the installer
  carries format lines 4 and 3 (package rollback works again); `bootstrap.sh`
  refuses an equal `RELEASE` whose tools differ; the verifier refuses an
  x86_64-only interpreter for the arm64 profile; the image loader under
  `sudo` loads into `SUDO_USER`'s daemon. MSI: `RegisterServiceCA` updates
  an existing service in place and never deletes it (the repair window is
  closed); an Administrators-member gMSA is kept; gate checks
  `folder_squat_refused`, `launch_conditions` and `repair_keeps_account`
  record and go on.

Residuals still open: clickhouse-connect's own regexes can still take
seconds on 60 KiB of adversarial whitespace or comments; on MySQL a
deadline that fires while a request is still queued behind another on the
same connection can cancel the request that is running (PostgreSQL guards
this, MySQL does not yet); MariaDB's `*_VARIABLES` views (not
verified live); on SQLite, `rowid` (or `oid`, `_rowid_`) returns the value
of a sensitive `INTEGER PRIMARY KEY` it aliases unmasked; on PostgreSQL a
cancel that lands just before a `FETCH` lets that one `FETCH` run, bounded
by `statement_timeout`; ClickHouse over-masks a clean `b.tariff` in some
statements (fails safe); and an earlier release's `postinst`, which dpkg
runs to undo a refused upgrade, may still reinstall that release
synchronously when its bundle has no OS packages.

**Test status after the second code-review fixes:** `12185 passed, 288 skipped, 1 xfailed`
(0 failed) for the whole suite on this Mac on 2026-10-03, run with
`UDBMCP_DOCKER_TESTS=1` so the container tests (the real dpkg sequences)
ran too; `mypy --strict src`, `ruff check src tests scripts` and
`--check-locks` clean.
Release-level re-checks at 2140348/4c93b02 (2026-10-03): `scripts/live_evidence.py`
gives the same results as the previous run; the version matrix for the
engines this round changed passes (PostgreSQL 12-17, MySQL 5.7/8.0/8.4,
MariaDB 10.6/11.4, ClickHouse 23.8-25.3); `release_usb.sh --demo`: deb gate
and pkg gate PASSED, stick signature verified; the offline upgrade gate
PASSED; the CI job replayed on `linux/amd64` (Debian 12, pwsh) passed ruff,
mypy, `--check-locks` and pip-audit on every lock, and its unit run (12386
passed) found one more test that assumed SQLite 3.40 can run FTS under the
connector's authorizer; it now probes it (`connector_reads_fts`).

**Third code review (2026-10-04).** A third `/code-review` at maximum
effort, over the second round's fixes (`9c457ec..0ad054b`), confirmed 15
ranked findings and about 20 more, each reproduced by an independent
verifier. As in the two reviews before it, most were the previous round's
fixes opening the next leak, chiefly in the positional masking analysis
(a ClickHouse CTE aliased or `SEMI`-joined returned SSNs in clear; `(expr).*`
inside `VALUES`, parenthesized joins with derived tables, SQLite `:1`
aliases) and in the identifier-folding models; besides those, a quadratic
lexer pass in `db_federated_query` that held the event loop for seconds
before the size check, a `NATURAL` join turning MySQL's
`STATISTICS.EXPRESSION` into an equality oracle, and a review probe that
OOM-killed the ClickHouse fixture.

**Owner decisions (2026-10-03, binding):** (1) masking refuses what it
cannot prove: over a table with (or possibly with) a masked column, only
statement shapes the analysis fully understands run, every other one is
refused before execution with the construct to avoid, and no special case
is traced for an exotic shape; (2) on Oracle, Db2 and PostgreSQL a CTE name
outside ASCII and an unquoted table or schema name outside ASCII are
refused instead of modelling each engine's case folding (the Unicode
folding model is deleted; ASCII folding stays exact); (3) ClickHouse gets a
default per-query memory cap, with `readonly=1` accounts checked by doctor.

What was fixed, by area (regression tests in `tests/unit/test_cr3_*.py`;
operator-visible behaviour in `docs/tools.md` (Masking), `docs/security.md`,
`docs/architecture.md`, `docs/driver-matrix.md`, `docs/session-safety.md`,
`docs/troubleshooting.md`, `docs/claude-code-integration.md`,
`docs/offline-deployment.md` and `docs/site-upgrade-runbook.md`):

- **Masking, redesigned.** A positive list of proven shapes (plain SELECT
  lists over tables, views, subqueries and CTEs; inner, outer and cross
  joins; set operations; recursive CTEs as `anchor UNION recursive branch`)
  and a `POLICY_VIOLATION` (`... its shape cannot be checked for them:
  <construct>`) for the rest: `VALUES`, `UNNEST`, `LATERAL`/`APPLY`, `ARRAY
  JOIN`, `SEMI`/`ANTI`/`ASOF` joins, `PIVOT`, `MATCH_RECOGNIZE`,
  `SEARCH`/`CYCLE`, `FOR JSON`/`XML`, `(expr).*`, `untuple`, `COLUMNS()`,
  star modifiers, wrapped or aliased stars, a star over `USING`/`NATURAL`,
  alias column lists on base tables, unbindable or ambiguous qualifiers,
  names spelled otherwise than the catalog's, SQLite rename-prone aliases,
  forward, shadowed or self CTE references, unknown sources and over-deep
  statements. A post-run layout check refuses a result whose width or names
  differ. Columns come from per-table catalog lookups (300 s cache, at most
  64 uncached per statement); a table the catalog lists no columns for is
  treated as possibly masked; synonyms are followed; PostgreSQL
  materialized views are listed (`pg_attribute`) and masked exactly;
  ClickHouse `*` leaves out `MATERIALIZED`/`ALIAS`/`EPHEMERAL` columns
  (`db_list_columns` and `db_get_table` report `default_kind`); a subquery
  in an output expression counts every column its clauses read; SQLite
  `rowid` (and `oid`, `_rowid_`, MySQL `_rowid`) counts as every column of
  its table, which closes the second review's `INTEGER PRIMARY KEY`
  residual.
- **Names.** Non-ASCII CTE names and unquoted non-ASCII table and schema
  names refused on Oracle, Db2 and PostgreSQL; `cte_key` is one ASCII rule.
- **Guard.** A `NATURAL` join or ClickHouse `COLUMNS()` in a statement
  reading a value-column catalog view refused; `x IN 'string'` refused; an
  engine error over 16 KiB keeps a redacted 4 KiB head (it collapsed to the
  type name); the comment lexer is linear (`--` lines and nested `/*`).
- **Federated.** 64 KiB per statement and 256 KiB together, checked before
  any lexing; Oracle bind names match ignoring case.
- **ClickHouse memory.** `options.max_memory_usage` (default 2 GiB, at least
  1 MiB) and `options.memory_limit_from_profile`; the limit is sent with
  every request where the profile accepts settings; `MEMORY_LIMIT_EXCEEDED`
  is `LIMIT_EXCEEDED`, a constraint refusal (452) `CONFIG_ERROR`; the
  session readback includes it; `doctor --connectivity` logs in to
  ClickHouse and is FATAL for a `readonly=1` profile with no limit of its
  own, unless acknowledged.
- **Connectors.** MySQL treats only integer literals and bound integer-like
  parameters as `GROUP BY`/`ORDER BY` positions (`RAND()`, `NULL`,
  `COUNT(*)` cut in place again). SQLite cuts cells in pure SQL (no Python
  function per row, no uncut re-run); its shadow-table prefilter handles
  doubled quotes, `IN 'table'` and comments in virtual-table definitions;
  name caches are bounded by characters stored as well as entries.
- **State files, config, CLI.** macOS audit and cache ACL rules cover
  delete and attribute rights and inheritable directory entries, accept
  read-only directory entries, and name one `chmod -N <dir> <files>`
  remedy; a cache directory reached through a symlink is accepted; a
  transient `EMFILE` no longer disables the cache; YAML tag conversion
  errors give line and column without the value; `sudo configure-agents`
  walks the path component by component with `O_NOFOLLOW` (refusing a
  user's symlink to another account's file); `dsh` seeds only the config a
  registration names.
- **Packaging.** `.deb`: the unwind holder moved to the new package's
  `postrm abort-upgrade`, so it also covers an unpack that fails after
  `preinst` passed; `postinst abort-*` leaves a running deferred install
  alone. MSI: `BuildVenvCA` stops the service and moves the old venv to
  `venv.previous-<guid>` (refused while something runs from it), with
  `RollbackBuildVenvCA` and `CommitBuildVenvCA`; an account change grants
  the new account, switches, then revokes the old one, rotating the token
  after the switch and clearing the stored password when switching to a
  gMSA or virtual account; every install sets the default service DACL and
  SID type `unrestricted`, and an in-place update resets type, error
  control, dependencies and display name; a service marked for deletion is
  reported as it is; an Administrators-member account counts only through
  the registration's Modify grant; a leftover `.gate-backup` stops the
  gate.

Measured outcome: a live sweep of all three reviews' masking repros on the
loopback fixtures gave 166 refused, 48 masked and 0 leaks, and the
everyday-query corpora (49 + 20 + 18 statements) mask exactly, unrefused.

Residuals still open: the MSI behaviours only a Windows host can show
(moving the venv while a file in it is open or mapped; `sdset`, `depend=`
and `sidtype` on a service running as a virtual account; clearing the LSA
secret on a switch to a gMSA or virtual account), with the rest of the MSI
still never run on Windows; ClickHouse `readonly=1` accounts rely on the
profile's own limit (doctor checks it, the connector cannot send one);
masking still does not cover predicate-only use of a masked column
(`WHERE`, `ORDER BY`, `GROUP BY`, `JOIN`: inference stays possible);
clickhouse-connect's own regexes can still take seconds on adversarial
whitespace or comments near the 64 KiB cap; an earlier release's
`postinst`, run to undo a failed upgrade, may still reinstall that release
synchronously when its bundle has no OS packages; and on MySQL a deadline
that fires while a request is still queued behind another on the same
connection can cancel the request that is running.

**Test status after the third code-review fixes:** `12548 passed, 331 skipped, 1 xfailed`
(0 failed) for the whole suite on this Mac on 2026-10-04 with
`UDBMCP_DOCKER_TESTS=1`; `mypy --strict src`, `ruff check src tests scripts` and
`--check-locks` clean. The skips are the pwsh-executed MSI tests (no pwsh on
this Mac; they pass in the Linux image), the integration tests that need
`UDBMCP_TEST_*_HOST`, and single OS-specific cases.

## 4. Gates not (fully) run (recorded truthfully)

- **Gate D (egress observation):** harness provided
  (`scripts/observe_egress.sh`, strace-based, self-validating); NOT run —
  requires a Linux host with ptrace permitted. The `--network none` Gate
  A/B runs prove no successful egress but do not observe attempts.
- **Gate F (Claude Code + internal gateway + GLM end-to-end):** `not_run` —
  requires the organization's pinned client version and internal model
  gateway. Integration guide provided (`docs/claude-code-integration.md`,
  registration through `udbmcp configure-agents`). Any client startup/
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
.venv/bin/python -m pytest -o addopts='' -q tests   # the whole suite (§3f records the latest count)
.venv/bin/python -m mypy --strict src && .venv/bin/ruff check src tests scripts   # what CI runs
bash scripts/test_airgap.sh              # Gates A + B (docker, --network none)
bash scripts/test_airgap_failures.sh     # Gate A negative cases (real exit codes)
bash scripts/test_isolated_integrations.sh  # Gate C (pulls fixtures on staging)
```

A release is air-gap ready for the profile `linux-x86_64-ubuntu24.04-cp312`
with connector set {sqlite, postgres, mysql, clickhouse, oracle, mssql, db2}
per the evidence above (Gate C round-trips passed for six; Db2 verified by
the 2026-09-15 live run and the version matrix, sections 3 and 3d).
