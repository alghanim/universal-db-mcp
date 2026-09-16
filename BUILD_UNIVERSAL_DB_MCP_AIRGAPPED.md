# Build a Universal Database MCP Connector — Air-Gapped Deployment Required

## 0. Your assignment

You are a senior backend, database, security, and release engineer. Implement a maintainable Universal Database MCP Server in this repository. Produce working code, tests, deployment scripts, and operator documentation—not merely an architecture proposal.

The user will use Claude Code CLI with an internally hosted model identified by the user as `glm5.3-flash`. Treat the model name and gateway configuration as deployment inputs. The database MCP server must be model-agnostic and must not call any LLM itself.

**Air-gapped deployment is a release-blocking requirement, not an optional feature.** The application must be installable, startable, operable, upgradable, and recoverable using approved local artifacts with no public internet connectivity.

This specification supersedes earlier, weaker requirements such as “works offline after dependencies are installed.” Both dependency installation and application operation must have a verified offline path.

Implement incrementally. Record reasonable assumptions and proceed rather than stopping for routine clarification. Never invent dependency versions, checksums, database capabilities, successful test results, or proprietary driver availability. When an artifact or database is unavailable, implement everything independently possible and record the specific unverified item.

## 1. Architecture and boundaries

Use this separation:

```text
Inside the isolated organization network

Claude Code CLI ── inference ──> Internal compatible gateway ──> Self-hosted GLM
       │
       └── MCP ──> Universal Database MCP Server ──> Approved database servers
                         │
                         └── Local configuration, audit log, metadata cache
```

MCP traffic and model inference are separate paths. The MCP server must not depend on Claude Code, Anthropic, Z.ai, LiteLLM, a model registry, GPU libraries, embeddings, or any hosted control plane.

“Air-gapped” does not mean disconnecting the application from its databases. Explicitly approved internal database, DNS, identity, certificate, and observability services may be used. Public endpoints, including public DNS resolvers, must not be required. Internal services must not silently proxy requests to the public internet.

Start with local `stdio` MCP transport for Claude Code. Also provide an optional authenticated internal Streamable HTTP deployment. Follow the protocol revision actually supported by the pinned SDK and client, rather than copying assumptions from a different MCP revision. [R8]

Do not build a web UI, model-serving stack, arbitrary shell-execution tool, or autonomous SQL-generation service as part of this project.

## 2. Non-negotiable air-gap requirements

1. No public network access during target installation, first start, ordinary operation, restart, upgrade, rollback, health checks, or tests advertised as offline.
2. No runtime dependency installation, package resolution against registries, automatic driver downloads, model downloads, plugin discovery against the internet, update checks, telemetry export, crash uploads, or cloud licensing checks introduced by this application.
3. No `pip install` from public indexes, `uvx`, `npx`, `curl | sh`, `wget`, package-manager repository access, `docker pull`, GitHub downloads, or equivalent bootstrap behavior in runtime entry points.
4. A disconnected installation must not rely on a developer machine’s package cache, container cache, existing virtual environment, globally installed driver, or undocumented operating-system library.
5. Missing dependencies must produce a bounded, actionable error naming the missing local artifact. Do not download a replacement or retry a public endpoint.
6. All direct and transitive runtime dependencies must be pinned and accounted for. Deliver platform-specific wheels and native dependencies or explicitly declare and verify an approved platform baseline.
7. Bundle integrity and authenticity verification must work offline. Checksums alone are not proof of publisher authenticity.
8. Telemetry must be absent or disabled by default across the application and its dependencies. Optional metrics must be local or explicitly internal only.
9. Public URLs in documentation are references for the staging environment, never runtime fallback endpoints.
10. Internet access during artifact acquisition is allowed only on a separate, explicitly authorized staging machine. Never bridge that machine into production as an internet relay.
11. Prove the offline behavior in clean, network-restricted environments. Environment variables or a README claim are not sufficient evidence.
12. Do not label an incomplete bundle or mock-only connector as production-ready.

## 3. Platform and technology

Use Python, typed models, and a pinned stable official MCP Python SDK or a justified, pinned FastMCP distribution. Distinguish standalone FastMCP from similarly named APIs bundled in other packages. Use SQLAlchemy where useful and native drivers where necessary. Use pytest, ruff, and mypy for development.

Planning default: Linux x86_64, glibc, CPython 3.12, with Ubuntu 24.04 as the initial candidate distribution. This is an assumption, not a statement about the user's infrastructure. Confirm the selected native drivers support the target before freezing it. Record the exact distribution release, architecture, Python patch version, ABI, driver versions, and OS prerequisites in the release profile. Add other profiles separately; do not claim one bundle supports every Linux distribution or CPU architecture.

Provide two independent deployment modes:

- **Native:** a newly created virtual environment installed entirely from a local bundle. Docker is not required.
- **Container:** a prebuilt OCI-compatible application image delivered as an archive, with a verified load-and-start procedure and no registry access.

Separate development/build dependencies from runtime dependencies. Prefer wheels on target; compilation, source distribution builds, and native toolchain bootstrapping belong in a controlled build environment. Do not copy a virtual environment between mismatched machines. Wheel bundles can be platform-specific. [R1]

Use bounded execution for synchronous database drivers. Do not put blocking calls directly on the MCP event loop. Implement connection-pool, worker, cancellation, and shutdown limits.

## 4. Repository layout

Create a structure similar to:

```text
universal-db-mcp/
  pyproject.toml
  README.md
  .gitignore
  .env.example
  config.example.yaml
  IMPLEMENTATION_STATUS.md
  src/universal_db_mcp/
    __main__.py
    server.py
    config.py
    models/
    tools/
    services/
    connectors/
      base.py
      registry.py
      db2.py
      oracle.py
      mssql.py
      postgres.py
      clickhouse.py
      mysql.py
      sqlite.py
    security/
    audit/
    diagnostics/
  requirements/
    runtime-<profile>.lock
    development-<profile>.lock
    build-<profile>.lock
  profiles/
  scripts/
    prepare_offline_bundle.py
    verify_bundle.py
    install_offline.sh
    load_images_offline.sh
    doctor.sh
    test_airgap.sh
    upgrade_offline.sh
    rollback_offline.sh
  packaging/
    Dockerfile
    compose.offline.yaml
    systemd/
    network-policy/
  examples/
    claude-code/
    sqlite-demo/
  tests/
    unit/
    integration/
    security/
    airgap/
  docs/
    architecture.md
    security.md
    tools.md
    adding-connectors.md
    offline-build.md
    offline-deployment.md
    offline-upgrade-rollback.md
    driver-matrix.md
    claude-code-integration.md
    acceptance-tests.md
    troubleshooting.md
    references.md
```

Keep MCP handlers thin. Database-specific behavior belongs in connectors; policy enforcement belongs in shared services. Optional adapters must load lazily so an absent Oracle driver does not break SQLite or PostgreSQL.

## 5. Database scope and driver packaging

Implement initial adapters for IBM Db2, Oracle, Microsoft SQL Server, PostgreSQL, ClickHouse, MySQL/MariaDB, and SQLite. Prioritize Db2 and use SQLite as the always-available local reference implementation. Keep extension points for Trino, DuckDB, MongoDB, and other engines without claiming unimplemented support.

For each adapter, maintain a matrix of engine family/version, Python driver/version, native libraries, authentication options, TLS support, cancellation support, explain behavior, metadata capabilities, license prerequisites, and real integration-test status.

### IBM Db2

Use an appropriate verified IBM driver path. Distinguish Db2 LUW from Db2 for z/OS and Db2 for i. Do not reuse LUW catalog SQL or assume identical licensing and native-client requirements across these families.

Inspect the exact `ibm_db` artifact selected. IBM documents prebuilt wheels that include `clidriver`, while source-install paths can have different native-client/download behavior. Do not assume that setting `IBM_DB_HOME` overrides a bundled wheel's driver. [R3]

Package a verified wheel with its required native components, or build against an approved local client in the build environment and bundle the resulting artifacts. The target must never fetch `clidriver`. Detect required Db2 Connect/client licensing and report missing prerequisites; do not redistribute licenses without authorization.

Document any administrator-side package binding or explain-table provisioning required by the selected path. Do not automatically bind packages, create explain tables, or grant permissions using the read-only MCP identity.

### Oracle

Prefer `python-oracledb` Thin mode where the target database and required features support it. Thin mode does not require Oracle Client libraries. Thick mode requires an explicitly packaged/preinstalled compatible client and its native dependencies. Do not silently switch modes or download Instant Client. [R4]

Account for local wallets, TNS configuration, certificate chains, authentication, and version compatibility. Keep wallets and private keys outside distributable artifacts.

### SQL Server

For a `pyodbc` implementation, account for both the Python wheel and the selected Microsoft ODBC driver, driver manager, and OS dependencies. Prepare platform-specific packages before transfer. Microsoft provides packages for offline installation; the application must not add Microsoft's public repository on target. [R5]

Document required license/EULA acceptance as an administrator-controlled installation step. Do not silently accept agreements on the user's behalf.

### Other engines

Choose maintained, pinned drivers and verify their actual native dependency requirements. Do not assume a package is self-contained from its name. Package compression, TLS, authentication, and other optional libraries actually enabled by the selected connector profile.

SQLite must operate on explicitly configured files opened read-only. Disable extension loading and arbitrary database attachment. Keep the application's writable audit/cache database separate from queried SQLite data sources.

### Shared requirements

No runtime JDBC/ODBC driver marketplace or Maven resolution. Future JDBC support must use administrator-provided local JARs and a declared local JRE. Validate all native-library dependencies in the clean target test. A Python import alone is not a complete connectivity test.

## 6. Configuration, identities, and secrets

Connections are administrator-declared, named profiles. MCP tool arguments may select a connection ID, never introduce a host, DSN, connection string, driver path, credential, arbitrary URL, or local database path.

Use validated YAML configuration with environment/file secret references. Reject unknown or unsafe fields. Support a secret-provider interface, but require no Vault, Kubernetes, or external identity service for the basic deployment.

Example shape; implement and document the final schema consistently:

```yaml
application:
  airgapped: true
  transport: stdio
  metadata_cache_path: /var/lib/universal-db-mcp/metadata.sqlite
  audit_path: /var/log/universal-db-mcp/audit.jsonl
  telemetry_enabled: false

security:
  read_only: true
  allow_write_operations: false
  default_max_rows: 1000
  hard_max_rows: 10000
  max_response_bytes: 1048576
  default_query_timeout_seconds: 30
  hard_query_timeout_seconds: 60
  max_concurrent_queries: 4
  require_remote_tls: true
  default_deny_objects: true
  audit_sql_text: false
  audit_parameter_values: false
  audit_result_rows: false

connections:
  finance_db2:
    type: db2
    family: luw
    host: db2.internal.example
    port: 50001
    database: FINANCE
    username_env: FINANCE_DB2_USER
    password_file: /run/secrets/finance_db2_password
    tls:
      enabled: true
      verify_server: true
      ca_file: /etc/universal-db-mcp/certs/internal-ca.pem
    allowed_schemas: [REPORTING]
    read_only: true
```

Addresses, ports, paths, and schema names above are examples, not actual infrastructure. Generate working synthetic SQLite examples separately.

Do not expose secrets through results, stack traces, diagnostics, SQLAlchemy representations, DSNs, logs, process arguments, source control, or bundle manifests. Reject unsafe secret-file ownership/permissions where supported. Do not log raw connection objects.

For stdio, associate authority with the local OS/service identity. For shared HTTP, authenticate callers and enforce server-side authorization by caller, connection, schema, object, and permitted operation. Never trust an identity supplied as an ordinary tool argument.

**Important isolation boundary:** a stdio MCP process launched by a coding agent under the same OS account is not a secure boundary against that agent's shell access to the account's files/environment. When database credentials must be inaccessible to the coding agent, deploy MCP under a separate service identity on an internal host and expose only authenticated MCP access. Never claim output redaction alone solves this.

## 7. Connector abstraction and capability reporting

Define a typed `DatabaseConnector` interface covering connection lifecycle, health, catalogs/databases/schemas, tables/views/materialized views, columns, keys, indexes, constraints, synonyms/aliases, routines, query execution, cancellation, explain, sampling, statistics, and metadata search.

Return capability states such as `supported`, `unsupported`, `permission_denied`, and `unverified`, not just optimistic booleans. Include mode-specific limitations and required privileges. Separate adapter implementation support from what the actual connection permits.

Do not implement database-specific catalog semantics by guessing. Preserve identifier case, quoting, catalog/schema distinctions, and connection provenance. Separate declared relationships from heuristic relationships.

Pool connections with bounded size, connection timeout, query timeout, and safe reset. Reapply required session policy when a connection is created or checked out. Discard connections whose cancellation/transaction state is uncertain.

## 8. MCP tool surface

Use explicit, bounded input schemas and documented structured output schemas. Tool names must remain stable. No tool may weaken security policy, create connections, reveal credentials, install packages, or run a shell.

Implement:

| Tool | Purpose and essential inputs |
| --- | --- |
| `db_list_connections` | Authorized connection IDs, engine types, cached health, capabilities; do not probe every server automatically. |
| `db_test_connection` | Bounded health test of one configured connection; sanitized status/version/latency. |
| `db_get_capabilities` | Actual connector/connection capability matrix and limitations. |
| `db_list_catalogs` / `db_list_databases` | Engine-appropriate discovery without inventing separate concepts. |
| `db_list_schemas` | Connection, optional catalog, search, page size/cursor. |
| `db_list_tables` | Connection, optional schema, search, object kinds, pagination. |
| `db_get_table` | Qualified object; columns, keys, constraints, indexes, comments, partitioning and row estimates when available. |
| `db_list_columns` | Qualified object and bounded pagination. |
| `db_list_views` | View/materialized-view metadata; definitions only where authorized. |
| `db_list_synonyms` | Synonyms/aliases, target object and link metadata; no automatic traversal of remote links. |
| `db_list_routines` | Functions/procedures and authorized metadata; never execute them for discovery. |
| `db_search_metadata` | Query, authorized connections/object types/schemas, result cap; deterministic ranked matches with reasons. |
| `db_get_relationships` | Declared foreign keys plus separately labeled optional inferences. |
| `db_get_statistics` | Bounded catalog statistics by default; exact counts/profiling require explicit requests and policy. |
| `db_validate_query` | Dialect-aware policy validation without execution; limitations stated. |
| `db_query` | Connection, SQL, bound parameters, requested row limit and timeout within server ceilings. |
| `db_sample_table` | Qualified object, approved columns, small limit; masking/omission policy enforced. |
| `db_explain` | Validated SQL and parameters; non-executing plan only unless separately authorized and supported. |
| `db_get_query_history` | Caller-scoped, redacted operational history; not unrestricted access to audit logs. |

Addendum (2026-09-16), discovery tools for federated ETL, documentation and
optimization. Same rules as above; none reads data except `db_profile_table`
and `db_search_values`, which run bounded under the session safety profile:

| Tool | Purpose and essential inputs |
| --- | --- |
| `db_list_indexes` | Indexes and primary keys of one object or a whole schema; ClickHouse reports sorting keys and skipping indices. |
| `db_get_catalog` | One-call paged catalog snapshot: columns with portable types, primary/foreign keys, indexes, row estimates, sensitivity hints. |
| `db_profile_table` | Bounded sample profile (null ratio, distinct, min/max, lengths, top values) plus evidence-backed optimization findings; sensitive columns return counts only. |
| `db_search_values` | A value searched across permitted tables of many connections without SQL; per-table hits, time budget, system schemas and sensitive columns excluded. |
| `db_infer_relationships` | Declared foreign keys plus inferred join candidates within and across connections, from metadata only. |

Metadata responses must be paginated and bounded. Bind opaque cursors to identity, connection, policy, and expiration. Do not reveal unauthorized objects through counts, search, suggestions, cache hits, or error messages.

Return ordinary tool output with fields appropriate to the operation, including `request_id`, `connection_id`, `engine`, `data`, `warnings`, `elapsed_ms`, `returned_row_count`, and `truncated` when applicable. Query results also include typed column metadata. Preserve decimals and large integers without silently losing precision; define representations for timestamps, binary data, LOBs, and nulls.

Application/tool failures must use the pinned MCP SDK's documented error semantics as well as a stable structured error category. Do not merely return a success-shaped object containing an error string. Keep stdout protocol-only in stdio mode; send logs to stderr or local files. [R8]

## 9. Query safety and permission boundaries

Read-only database accounts and engine-enforced restrictions are mandatory for production. Parser rules are additional protection, not a substitute for database privileges.

Implement a dialect-aware safety service, with these requirements:

- Accept only a single permitted statement. Inspect all nested CTEs and subqueries. Do not allow a modifying CTE just because the outer statement is `SELECT`.
- Reject DML, DDL, transaction-control statements, privilege changes, procedural blocks, side-effecting calls, executable comments, and unapproved session settings. Ordinary comments are not automatically malicious.
- A statement beginning with `SELECT` is not automatically safe. Reject or tightly allowlist functions, table functions, external resources, file access, remote URLs, cross-server features, extension loading, export commands, `SELECT INTO`, and dialect-specific escape paths.
- Validate `EXPLAIN`, `SHOW`, and `DESCRIBE` through dedicated adapter policies; do not allow every command with those prefixes.
- Resolve object access conservatively. CTE aliases, views, synonyms, dynamic schema paths, and database links must not bypass policy. Deny unresolved or unsupported syntax rather than treating a parser failure as approval.
- Bind values using the driver's parameter facilities. Validate identifiers against metadata and quote them with the appropriate adapter. Never interpolate arbitrary values or identifiers into SQL.
- Enforce hard limits server-side regardless of model-supplied arguments. Bound rows, result bytes, cell size, query duration, connection time, queue time, concurrency, and metadata traversal.
- Fetch in bounded batches. Do not fetch the entire result before truncation. Cancel/close the remaining operation safely when limits are reached.
- A client-side timeout alone does not prove the database query stopped. Implement and test driver/server cancellation and document any residual limitations. Do not advertise hard cancellation where unsupported.
- Reject attempts to relax these controls through SQL, connection parameters, query settings, hints, or tool inputs.

Do not blanket-deny all system schemas: approved introspection may need system catalogs. Implement least-privilege metadata queries and distinguish those from arbitrary user access to sensitive catalogs.

Provide database-specific least-privilege setup guidance and isolated test fixtures. The application must never run privilege-granting setup automatically against production.

No general write tool is required in v1. Keep writes disabled. Any future write capability requires a separate reviewed design, database permissions, out-of-band administrator authorization, and an auditable approval mechanism—not a natural-language request or a model-controlled flag.

Treat text found in table rows, names, comments, view definitions, and errors as untrusted data. It cannot change tool permissions, network policy, credentials, or instructions. SQL execution can also cause the database server itself to access other systems; constrain these engine-side capabilities and network routes rather than relying only on the MCP host firewall.

## 10. Exploration, sampling, statistics, and plans

Search names and comments deterministically without requiring embeddings. Rank lexical matches and explain matching reasons; scores are ranking scores, not calibrated probabilities. Include source connection and exact qualified object names.

Metadata cache must be local, permission-scoped, size-limited, versioned, and time-bounded. Include retrieval timestamps. Do not persist sampled rows or full query results by default. Authorization changes must invalidate or restrict cached entries.

For relationships, return confirmed foreign keys as confirmed metadata. Any name/type-based inference must include `inferred: true`, reasons, and uncertainty. Do not sample sensitive values to infer joins without explicit authorization.

Default sampling limit: 20 rows. Return no credential material. Sensitive-column names are useful heuristics, not the sole security boundary. Prefer database-side restricted views and column grants. Enforce configured masking/omission in all result paths, not just sampling, and explain limitations for expressions and aliases.

Avoid `COUNT(*)`, full scans, expensive random sorting, and full-column profiling by default. Mark catalog estimates as estimates with freshness metadata. Distinguish unsupported, unavailable, and permission-denied results.

`EXPLAIN ANALYZE` and similar execution-capable operations remain disabled by default. Some engines' explain paths may write plan metadata or require setup. Report this and refuse when incompatible with policy; never silently create objects or weaken read-only mode. Normalize only what the actual plan supports, preserve redacted raw output, and do not invent optimization findings.

## 11. Offline artifact preparation and release bundle

Implement a deliberate two-stage workflow.

### Stage A — approved artifact acquisition and preparation

On a separate staging machine, resolve and pin dependencies, acquire approved upstream artifacts, verify available upstream signatures/checksums, build wheels, construct images, run scans, and assemble the transfer bundle. Network-enabled acquisition must be an explicitly selected operation, not a side effect of installation or startup.

Produce a complete runtime lock for each supported profile and connector selection. Include exact versions and hashes for every installed wheel, including the application wheel. For locally built wheels, lock the hashes of the wheels actually delivered, not only the source archive. Pip's hash mode requires the complete dependency set to be pinned and hashed. [R2]

Include all native runtime dependencies and local OS packages needed beyond the documented target baseline. Record the dependency closure, not just top-level packages. Include vendor artifacts only when transfer and redistribution are authorized; otherwise require administrator-supplied artifacts to complete the bundle. An incomplete licensed-driver profile cannot pass readiness checks.

Build deployment images before transfer. Export them with their layers, metadata, pinned references, and an expected local image identity; importing an archive must not require contacting its original registry. [R6]

Deliver a bundle shaped like:

```text
universal-db-mcp-<release>-<profile>/
  manifest.json
  SHA256SUMS
  SIGNATURE
  VERIFY.txt
  requirements/runtime.lock
  wheelhouse/
  native-drivers/
  os-packages/
  images/
  installers/
  config-templates/
  licenses/
  sbom/
  docs/
  tests/
  test-evidence/
```

Manifest fields must include release/version, source revision, target profile, exact dependencies, artifact sizes/hashes, native-library prerequisites, selected connectors, omitted optional components, applicable licenses, image identity, build tools, and verification instructions. Never insert real secrets, production data, private keys, or access tokens.

Provide an SBOM in a standard format, with license/provenance information and locally usable vulnerability-scan output. Record scan date and database freshness. Do not claim an offline vulnerability database is current indefinitely.

Use an organization-approved detached signature scheme that verifies offline against an independently trusted public key. Do not depend on online transparency logs, external timestamp services, or public key discovery during verification. Document key distribution and trust assumptions.

### Stage B — installation inside the air gap

Validate the bundle before installation. Check profile compatibility, artifact integrity/authenticity, native prerequisites, available storage, file permissions, and required driver licensing. Fail before partially changing the deployment when possible.

Create a new virtual environment on the target. The final tested installer should use the equivalent of:

```bash
PIP_CONFIG_FILE=/dev/null \
PIP_DISABLE_PIP_VERSION_CHECK=1 \
"$VENV/bin/python" -m pip --isolated --disable-pip-version-check install \
  --no-index \
  --no-cache-dir \
  --find-links="$BUNDLE/wheelhouse" \
  --only-binary=:all: \
  --require-hashes \
  -r "$BUNDLE/requirements/runtime.lock"
```

Validate these options against the pinned pip version and test with hostile inherited index/proxy configuration. The lock must not contain network URLs or VCS references. Include the application wheel in the lock; do not end with `pip install .` or an editable install that can trigger a source build.

Installing OS/native packages must use only included packages or an explicitly approved disconnected repository, with public repositories disabled. Missing transitive OS packages must fail with an exact manifest, not trigger `apt update`, `dnf` downloads, or an equivalent repair.

For containers, deliver tested image-load commands and `compose.offline.yaml` using `pull_policy: never`, no runtime `build:` directive, and an image identity validated after import. An absent image must fail locally. [R7]

Record prerequisite container-engine versions and either provide authorized offline engine installers or explicitly treat them as part of the verified platform baseline. Do the same for CPython, venv support, and package installation tools.

Offline source rebuilds are a separate profile: include build dependencies, toolchain/base images, local sources, and native development packages. Prevent BuildKit frontends, base-image resolution, remote caches, or build backends from reaching public services. A build network flag alone is not proof that every build-related process stayed offline.

## 12. Runtime hardening, operations, and recovery

Provide a `doctor` command that checks installed artifacts and effective policy without downloading anything. It must detect missing drivers/libraries, unsupported target profile, unsafe file permissions, absent internal CA files, missing secret references, unreachable configured databases, and disabled/unsupported capabilities. Local prerequisite checks must not require working database credentials.

Run under a dedicated non-root account. Restrict filesystem access; use a read-only container root filesystem where practical, explicit writable audit/cache locations, resource limits, and graceful shutdown. Do not mount a Docker socket into the service.

Enforce egress with administrator-managed host/container network controls, not merely an application hostname check. Allow only documented internal destinations and ports; account for DNS, TLS, failover nodes, and authentication. Block public resolvers, proxy escapes, and unapproved destinations. Document traffic by process/service.

Use verified TLS with internal CA trust. Do not solve certificate problems by disabling certificate or hostname checks. Identify CRL/OCSP, identity, or other certificate-validation dependencies and provide an approved internal/offline path when required by organizational policy.

For HTTP mode, require authentication, authorization, request-size/time limits, Origin validation appropriate to the pinned MCP specification, and restrictive bind defaults. Do not require a public OAuth provider. Local mode must not expose a TCP listener unnecessarily.

Audit connection ID, authenticated caller, action, timing, row count, policy outcome, and a redacted query fingerprint. Do not store raw SQL literals, bound values, rows, passwords, or tokens by default. Configure local rotation, retention, disk-pressure behavior, and optional explicitly internal export. State whether inability to write required audit records causes operations to fail closed.

Implement versioned upgrades and rollback with local signed bundles, preflight, backups of configuration/local state, compatible migrations, and recovery after interrupted installation. Never automatically update production dependencies. Document the process for importing security fixes and refreshed vulnerability data into the isolated environment.

## 13. Claude Code CLI and self-hosted model integration

Deliver a separate integration guide. Do not couple server correctness to a particular LLM or claim that using a custom base URL automatically guarantees air-gapped client operation.

Provide a local `.mcp.json` example launching the installed executable directly, with no `uvx`, `npx`, or network package resolver:

```json
{
  "mcpServers": {
    "universal-db": {
      "type": "stdio",
      "command": "/opt/universal-db-mcp/venv/bin/python",
      "args": ["-m", "universal_db_mcp", "serve", "--transport", "stdio"],
      "env": {
        "UDBMCP_CONFIG": "/etc/universal-db-mcp/config.yaml"
      }
    }
  }
}
```

Implement the CLI/config names above or update the example to match the actual implementation. Validate it using the pinned Claude Code release. Use local secret references, not committed credentials. Include an authenticated internal HTTP alternative for separate-service deployments. [R9]

Claude Code's gateway path must support the API format it actually sends. For `ANTHROPIC_BASE_URL`, validate Anthropic Messages compatibility, streaming, tool definitions, tool-call/result round trips, error handling, and model routing. An OpenAI-compatible chat endpoint alone does not demonstrate that compatibility; use an internal translating gateway when needed. [R10]

Document these settings as a starting point, then verify them against the exact client version:

```bash
# Values and credentials are supplied by the organization's operator.
export ANTHROPIC_BASE_URL="https://llm-gateway.internal.example"
export ANTHROPIC_MODEL="glm5.3-flash"
export CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1
# Set the credential variable required by the local gateway securely.
```

Route all model selections, including auxiliary/fast-model paths and fallback behavior, to approved local models or disable the unsupported paths. Do not hard-code a public provider fallback. Verify the gateway itself has no cloud dependency or public fallback.

Anthropic documents nonessential traffic outside the gateway route and provides the disabling variable above; not every feature-specific request is covered by it. Therefore disable unneeded web search/fetch, external MCP servers, marketplace access, remote-control features, and other network-capable features using supported settings for the pinned client. Preserve security checks for any functionality kept enabled. Confirm behavior with network monitoring. [R11]

Document separate client installation artifacts, gateway dependencies, authentication requirements, and permitted use. Do not bypass licensing or fabricate credentials. If the selected client version cannot complete its required startup/authentication offline, report an end-to-end deployment blocker; do not conceal it as an MCP-server issue.

Do not bundle GLM weights, GPU runtimes, or model-serving software in the connector runtime. The existing internal model service is a separately managed dependency for the client, not for the MCP server.

## 14. Required tests and release gates

Implement automated tests and store machine-readable results. Distinguish `passed`, `failed`, `skipped`, `blocked`, and `not_run`.

### A. Clean offline installation

Use a fresh target VM/container matching the declared baseline, with empty package caches and no undeclared native clients. Make only the bundle and required approved baseline available. Block outbound networking at the OS/network layer. Verify installation, first launch, restart, and the local SQLite demo.

Test missing wheels, missing OS/native libraries, incompatible architecture/Python ABI, tampered artifacts, untrusted signatures, missing images, and missing licensed drivers. Each must fail promptly and actionably without a network download attempt.

### B. No-network protocol test

With networking completely disabled, run the actual stdio MCP server and a locally installed protocol client against synthetic SQLite fixtures. Test the revision-appropriate protocol lifecycle, tool discovery, tool execution, structured results/errors, pagination, cancellation, and clean shutdown.

No browser-based inspector, npm download, or external test dependency is allowed. Ship required test tools in the test profile.

### C. Isolated internal-database integration

On a network with no public route but explicitly permitted internal fixture endpoints, test each implemented connector's real driver, authentication, TLS, discovery, views/synonyms where applicable, parameters, queries, estimates, explain limitations, cancellation, and reconnection behavior.

This is different from disabling all networking: remote databases must remain reachable. Do not use container `network_mode: none` as the production example for remote database connections.

Preload test images rather than allowing a test-container framework to pull them. Do not download database images or accept vendor agreements automatically during offline tests. Unavailable enterprise database instances must be marked `not_run`/`blocked`; mocks do not prove production compatibility.

### D. Egress observation

Observe the application process tree and native libraries with suitable host/network tooling. Record DNS queries, attempted connections, and blocked traffic as well as successful traffic. A test must fail on an unapproved outbound attempt even if a firewall blocked it.

Do not rely only on monkeypatching Python sockets; native drivers and child processes may bypass that. Validate the observation harness itself. Include startup, idle periods, errors, reconnects, first use of each adapter, health checks, and shutdown. Keep captured data synthetic or sanitized.

### E. Query and authorization security

Test modifying CTEs, multiple statements, dialect-specific executable comments, side-effecting functions, external table functions, file access, remote links, `SELECT INTO`, disallowed objects, quoted identifiers, views/synonym bypasses, unsafe query settings, driver cancellation, oversized rows, result-byte limits, injection in parameters, and metadata-based prompt injection.

Verify a database-side permission denial even when parser protection is bypassed in a controlled test fixture. Verify authorization isolation for connection listing, cached metadata, cursors, history, and results. Confirm secrets never appear in tool responses or diagnostic outputs.

### F. Client/model end-to-end qualification

Separately test the exact Claude Code version, local gateway version/configuration, and configured `glm5.3-flash` endpoint with public egress blocked. Ask the agent to list a configured database, inspect a table, and run a small authorized read query through MCP.

Verify real tool calling, usable results, model fallback routing, streaming, and absence of public network attempts. A successful raw HTTP request to the model is not a substitute for this test. Record this qualification separately from MCP-server offline compliance.

### G. Upgrade and rollback

Using only local release bundles, exercise installation, a version upgrade, deliberate interruption/failure, rollback, state/configuration preservation, and restart. No external registry, index, signing service, or identity service may be unexpectedly required.

## 15. Deliverables and implementation order

Deliver working source code; pinned locks; native and container deployment scripts; an offline bundle builder/verifier; profile and driver matrices; synthetic demo fixtures; tests; security documentation; least-privilege database setup guidance; Claude Code examples; and offline installation, troubleshooting, upgrade, and rollback runbooks.

Implement in this order:

1. Establish the target profile, threat model, dependency strategy, local SQLite MCP path, and a clean offline installation test.
2. Implement shared policy, structured schemas, authorization boundaries, logging/redaction, limits, and metadata services.
3. Implement Db2 early, then the remaining required adapters with truthful capability reporting and integration tests.
4. Complete the native/container bundles, signatures, SBOM, egress tests, and operational runbooks.
5. Qualify the exact Claude Code/local gateway/model chain separately.

Update `IMPLEMENTATION_STATUS.md` after each phase. Clearly separate implemented behavior, tested behavior, unsupported capabilities, missing vendor artifacts, and tests awaiting internal infrastructure. Do not stop at stubs or a README while claiming completion.

A release is **air-gap ready for a named profile and connector set** only when that exact profile installs from its verified local bundle and passes the relevant offline/runtime/security gates. Full client qualification additionally requires the client/model test. There is no blanket “works with every database and model” certification.

Start by inspecting the repository, writing a brief implementation plan and recorded assumptions, then implement the first working, tested slice immediately.

## Reference notes for the implementer

These are primary documentation starting points checked while preparing this specification on 2026-09-08. Obtain approved copies during staging; never fetch them automatically inside the isolated environment. Match documentation to the actual pinned versions. The requirements above are engineering requirements, not claims that the project has already been built or validated.

- **[R1]** PyPA pip, Repeatable Installs: `https://pip.pypa.io/en/stable/topics/repeatable-installs/`
- **[R2]** PyPA pip, Secure installs: `https://pip.pypa.io/en/stable/topics/secure-installs/`
- **[R3]** IBM Python Db2 driver installation: `https://github.com/ibmdb/python-ibmdb/blob/master/INSTALL.md`
- **[R4]** Oracle python-oracledb installation and Thin/Thick modes: `https://python-oracledb.readthedocs.io/en/latest/user_guide/installation.html`
- **[R5]** Microsoft ODBC driver offline packages: `https://learn.microsoft.com/en-us/sql/connect/odbc/download-odbc-driver-for-sql-server?view=sql-server-ver17`
- **[R6]** Docker image archive operations: `https://docs.docker.com/reference/cli/docker/image/save/` and `https://docs.docker.com/reference/cli/docker/image/load/`
- **[R7]** Docker Compose pull policy: `https://docs.docker.com/reference/compose-file/services/`
- **[R8]** MCP transport documentation; choose a mutually supported revision: `https://modelcontextprotocol.io/specification/2026-07-28/basic/transports` and `https://modelcontextprotocol.io/specification/2025-11-25/basic/transports`
- **[R9]** Claude Code MCP configuration: `https://code.claude.com/docs/en/mcp`
- **[R10]** Claude Code gateway compatibility: `https://code.claude.com/docs/en/llm-gateway-protocol`
- **[R11]** Claude Code gateway setup and nonessential traffic: `https://code.claude.com/docs/en/llm-gateway-connect`
