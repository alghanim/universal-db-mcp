# Agent connection quickstart (air-gapped workflow)

End-to-end: build and sign the release bundle on the staging machine, move it
across the air gap, verify and install it on the target, point it at the
internal databases, and connect an agent. The themed mock-database fixtures
(`scripts/fixtures/start_mock_dbs.sh`) stand in for the internal databases.

## 1. Staging machine (has the source and a network)

```bash
# one-time: release key pair (in production this is the organization's key
# ceremony; the public key is distributed to the air-gapped side out of band)
openssl genpkey -algorithm ed25519 -out release-key.pem
openssl pkey -in release-key.pem -pubout -out udbmcp-release.pub.pem

# build + sign the offline bundle (hashed runtime.lock, wheelhouse, SBOM)
python -m venv .venv && .venv/bin/pip install -e . build
.venv/bin/python scripts/prepare_offline_bundle.py \
    --out dist/udbmcp-bundle --signing-key release-key.pem
```

Transfer the bundle directory (and separately, over a different trusted
channel, `udbmcp-release.pub.pem`) to the air-gapped target.

## 2. Air-gapped target: verify and install

Install the trusted tools and the public key first, from the release's
`trusted-tools/` directory, never from the bundle's own `installers/`
reference copies (`docs/offline-deployment.md`, "Trust bootstrap"). Then:

```bash
sudo python3 -I /usr/local/lib/udbmcp-trust/verify_bundle.py \
    --bundle universal-db-mcp-0.1.0-linux-x86_64-ubuntu24.04-cp312 \
    --pubkey /etc/universal-db-mcp/keys/release.pub.pem   # FAILS CLOSED on any mismatch
sudo UDBMCP_RELEASE_PUBKEY=/etc/universal-db-mcp/keys/release.pub.pem \
    bash /usr/local/lib/udbmcp-trust/install_offline.sh \
    universal-db-mcp-0.1.0-linux-x86_64-ubuntu24.04-cp312 /opt/universal-db-mcp
```

On the install target the verifier also compares the bundle with the
installed release (`/opt/universal-db-mcp/manifest.json`, when present) and
refuses an older one. The installer verifies the bundle again, refuses an
older release than the installed one, and runs pip with `--no-index
--require-hashes --only-binary=:all:` against the bundle wheelhouse only; a
hostile inherited pip config cannot cause a download (proven in the Gate
A-negative evidence).

## 3. Configure connections (secrets never in the config file)

The tarball installer does not create the config; put the bundle's template
in place, readable by the service account only:

```bash
sudo install -m 640 -o root -g udbmcp \
    universal-db-mcp-0.1.0-linux-x86_64-ubuntu24.04-cp312/config-templates/config.yaml \
    /etc/universal-db-mcp/config.yaml
```

`/etc/universal-db-mcp/config.yaml` — connection block pattern (see
`config.mockdbs.yaml` in the repository for a complete worked example):

```yaml
security:
  read_only: true
  require_remote_tls: true     # set false ONLY if the air-gapped DBs have no TLS
connections:
  finance_pg:
    type: postgres
    host: db.internal.example
    port: 5432
    database: finance
    username_env: FINANCE_PG_USER          # resolved from the process environment
    password_file: /run/secrets/finance_pg_password   # 0600 file
    allowed_schemas: [reporting]           # agents then write reporting.<table>
```

With `allowed_schemas` set, every table in an agent's statement must be
schema-qualified (`SELECT * FROM reporting.orders`); a bare name is refused
with the qualified name to use. Without an allowlist, under the default
`default_deny_objects: true`, a bare name is refused too where the session
looks bare names up in another schema first (on the loopback fixtures,
mock_pg's bare `readings`, which lives in `ocean` while the `search_path` is
`public`, and mock_db2's bare `CITIZENS` in `MOI`), and a name must be
spelled as the catalog spells it. Give the login SELECT on those schemas
only.

Validate before serving:

```bash
sudo -u udbmcp /opt/universal-db-mcp/venv/bin/python -m universal_db_mcp \
    doctor --config /etc/universal-db-mcp/config.yaml --connectivity
```

## 4. Connect the agent

**stdio (agent and server on the same machine):** run
`udbmcp configure-agents` as the user who runs the agent
(`docs/claude-code-integration.md`). For Claude Code it writes
`~/.claude.json`:

```json
{
  "mcpServers": {
    "universal-db": {
      "type": "stdio",
      "command": "/opt/universal-db-mcp/venv/bin/python",
      "args": ["-I", "-m", "universal_db_mcp", "serve", "--transport", "stdio"],
      "env": { "UDBMCP_CONFIG": "/home/<you>/.universal-db-mcp/config.yaml" }
    }
  }
}
```

The server runs as your user, so it reads your per-user config, not the
service's `/etc/universal-db-mcp/config.yaml`, whose audit log only the
service account can write. The `.pkg`, and the tarball steps here and in
`docs/offline-deployment.md`, leave that file unreadable to other users; the
`.deb` ships it `root:root` 0644, so on a `.deb` host run
`sudo chown root:udbmcp /etc/universal-db-mcp/config.yaml &&
sudo chmod 640 /etc/universal-db-mcp/config.yaml` before `configure-agents`,
or it registers the service's file. `-I` keeps the open project's files off
the server's import path. A connection whose credentials come from `username_env` or
`password_env` needs those variables in the harness's own environment;
`configure-agents` names such connections. The agent process launches the
server as a child; stdout is protocol-only.
Every tool call is guard-checked (dialect-aware SQL validation, read-only
enforcement), row/byte/time bounded, and audited.

**HTTP (agent and server on different machines, credentials hidden from the
agent):** run the server as a service (the bundle's
`operations/universal-db-mcp.service`) with `transport: http`, a
`http_bearer_token_file`, and an internal reverse proxy in front; the agent
registers:

```json
{
  "mcpServers": {
    "universal-db": {
      "type": "http",
      "url": "http://udbmcp.internal.example:8765/mcp",
      "headers": { "Authorization": "Bearer <contents of /etc/universal-db-mcp/http-token>" }
    }
  }
}
```

The `headers` entry is mandatory: the listener answers 401 to every request
without it, and the bare `WWW-Authenticate: Bearer` challenge sends
spec-conformant clients into OAuth discovery, so the client reports an
authentication or OAuth failure rather than a missing header. Clients take a
literal `headers` object; there is no separate secret store to read it from.

Note also that `application.http_host` decides which `Host` values the
transport accepts, not just the bind address. Binding loopback and connecting
by hostname is answered `421 Invalid Host header`.

`udbmcp configure-agents` writes stdio registrations only; an HTTP
registration is written by hand, as above.

## 5. Smoke-test exactly like an agent

```bash
.venv/bin/python scripts/demo_agent_probe.py config.mockdbs.yaml
```

The probe is an MCP client over the pinned SDK: it initializes the server,
lists the 29 tools, and runs one themed query per configured engine. On a
healthy deployment it reports `status: passed`; per-engine `KNOWN-BLOCKED`
entries name the specific missing administrator prerequisite (e.g. the SQL
Server ODBC driver package). A login failure (`Login failed`, 18456, SQLSTATE
28000, Db2 `USERNAME AND/OR PASSWORD INVALID`) counts as `FAILED`.

For the local fixtures, `scripts/fixtures/start_mock_dbs.sh` starts the
containers, writes their passwords to `out/mockdb-secrets/*.pw` (0600) and
prints the `UDBMCP_DEMO_*_USER` exports to use; `config.mockdbs.yaml` takes
each user name from those variables, and its paths are relative to the file
itself (the repository root), so it works from any checkout and any working
directory. The SQL Server fixture's reader login is `udbmcp_ro`
(`db_datareader` plus `SHOWPLAN`, so `db_explain` works); `sa` only seeds.
The probe defaults to those users and honours exported values. Fixtures
created before the reader login existed must be recreated with the script.

> **SQL Server driver note:** the `KNOWN-BLOCKED` SQL Server entry means the
> ODBC Driver 18 package is absent on the machine running the probe. On the
> demo Mac it can be installed directly with the two brew commands:
>
> ```bash
> brew tap microsoft/mssql-release https://github.com/Microsoft/homebrew-mssql-release
> HOMEBREW_NO_AUTO_UPDATE=1 brew install msodbcsql18
> ```
>
> (Homebrew supplies `unixodbc` as a dependency of `msodbcsql18`.) In the
> air gap the driver is not an administrator errand: the `msodbcsql18` +
> `unixodbc` debs ship in the bundle `os-packages/` (staged and wired;
> included in the next bundle build) and the offline installer installs
> them automatically — see `docs/offline-deployment.md`.

## 6. Connecting the DeepSeek harness (`dsh`)

The harness ships `@deepseek-ai/dsh-mcp-client`, a bridge that registers MCP
tools as native harness tools under `mcp__<serverName>__<tool>` names. Add a
row to the home-level patch layer `$DSH_HOME/cordis.patch.yml` (default
`~/.dsh/cordis.patch.yml`, applied over every profile); new rows must use the
`insert:` form — a plain `- id:` entry is an override and fails with
`entry not found`:

```yaml
- insert:
    - id: mcp-universal-db
      name: '@deepseek-ai/dsh-mcp-client'
      config:
        serverName: udb
        transport: stdio
        command: /opt/universal-db-mcp/venv/bin/python
        args: ['-I', '-m', 'universal_db_mcp', 'serve', '--transport', 'stdio']
        env:
          UDBMCP_CONFIG: /home/<you>/.universal-db-mcp/config.yaml
          # username_env values for each connection (the bridge scrubs
          # ambient secret-looking env names; pass them explicitly):
          FINANCE_PG_USER: udbmcp_ro
        failOnStartupError: true
```

`udbmcp configure-agents --agent dsh` writes this row for you. A row with
this id that starts the server without `-I` (also through a wrapper or a
shell command line), or several rows with this id, are refused (fail closed):
keep one row whose args start with `-I`. Only the exact row an earlier
release of this tool wrote is upgraded in place. The patch file's line
endings (LF or CRLF) are kept.

Verify the row composes without booting the agent:

```bash
dsh --profile headless --dump-config | grep mcp-universal-db
```

Then run a real agent turn (uses one model request; the model calls
`mcp__udb__db_query` like any native tool):

```bash
dsh --profile headless "Use mcp__udb__db_query on connection mock_pg to count rows in ocean.readings"
```

Every harness-driven call lands in the server's audit JSONL like any other
client. For the `web` profile the same home patch applies; restart `dsh web`
so the new patch layer is loaded, and the tools appear in sessions.
