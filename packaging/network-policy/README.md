# Network policy guidance (administrator-managed)

Application-level hostname checks are NOT the enforcement point. Enforce
egress with host/container controls. Documented traffic for this service:

| From | To | Port | Purpose |
| --- | --- | --- | --- |
| universal-db-mcp | approved database servers | engine ports (e.g. 5432, 3306, 8123, 1521, 1433, 50000-50001) | TLS database connections |
| universal-db-mcp | internal DNS | 53 | resolving approved database hosts only |
| internal clients | universal-db-mcp (http mode) | 8765 | authenticated MCP (behind reverse proxy) |

Blocked by policy:

- public DNS resolvers
- all public IP space (deny-by-default egress; allowlist internal CIDRs)
- package registries, vendor update endpoints (the app never contacts them,
  but the network must also deny them defense-in-depth)
- container engine socket access (never mounted)

Example nftables shape (administrator adapts):

```text
add rule inet filter output oifname "eth0" ip daddr { approved-db-cidrs } tcp dport { db-ports } accept
add rule inet filter output oifname "eth0" ip daddr { dns-server } udp dport 53 accept
add rule inet filter output oifname "eth0" drop
```

For Gate D observation, see `scripts/observe_egress.sh` and
docs/acceptance-tests.md §D.
