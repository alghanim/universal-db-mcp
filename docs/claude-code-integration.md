# Claude Code CLI integration (internal model gateway)

This server is model-agnostic: it never calls an LLM. Claude Code is the
client; the internal model gateway is a separate, independently managed
dependency of the client — never of this server.

## 1. MCP server registration (air-gapped local mode)

`~/.mcp.json` (or project `.mcp.json`):

```json
{
  "mcpServers": {
    "universal-db": {
      "type": "stdio",
      "command": "/opt/universal-db-mcp/venv/bin/python",
      "args": ["-m", "universal_db_mcp", "serve", "--transport", "stdio"],
      "env": { "UDBMCP_CONFIG": "/etc/universal-db-mcp/config.yaml" }
    }
  }
}
```

- Launches the installed executable directly; no `uvx`, `npx`, or network
  package resolver.
- The process runs as the invoking OS user. **Isolation boundary:** a stdio
  MCP process launched by the coding agent shares that account's file and
  environment access. When database credentials must be hidden from the
  agent, deploy the server under a separate service identity on an internal
  host and use the authenticated HTTP mode instead. Output redaction is not
  a substitute for this.

## 2. Internal model gateway (client side, operator-supplied)

```bash
# Values and credentials are supplied by the organization's operator.
export ANTHROPIC_BASE_URL="https://llm-gateway.internal.example"
export ANTHROPIC_MODEL="glm5.3-flash"
export CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1
# Set the credential variable required by the local gateway securely.
```

Requirements on the gateway path (validate against the pinned client
version; a bare OpenAI-compatible chat endpoint does NOT prove this):

- Anthropic Messages API compatibility, including streaming, tool
  definitions, and tool-call/result round trips.
- All model-selection paths (auxiliary/fast-model routes, fallbacks) resolve
  to approved internal models or are disabled.
- No cloud dependency and no public fallback in the gateway itself.

## 3. Offline hardening of the client

`CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` covers documented nonessential
traffic but not every feature request. For the pinned client also disable,
via supported settings:

- web search / fetch tools
- external MCP servers and marketplace access
- remote-control and other network-capable features

Confirm with network monitoring on a representative session (Gate D/E
harness). Preserve security checks for anything left enabled.

## 4. End-to-end qualification (Gate F)

Record separately from MCP-server offline compliance. With public egress
blocked, ask the agent to: list a configured database, inspect one table,
run one small authorized read query through MCP. Verify real tool calling,
usable results, streaming, fallback routing, and the absence of public
network attempts. A raw HTTP call to the model is not a substitute.

If the pinned client cannot complete startup/authentication offline, record
an end-to-end deployment blocker — it is a client/gateway issue, not an
MCP-server defect, and must not be concealed.

## Status in this build

The MCP-server side (stdio registration above) is implemented and covered by
the Gate B protocol probe. Gate F end-to-end qualification has NOT been run
in this environment — it requires the organization's pinned Claude Code
version and internal gateway. See IMPLEMENTATION_STATUS.md.
