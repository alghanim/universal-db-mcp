import sys
sys.path.insert(0, "src")
from universal_db_mcp.config import ConnectionConfig, ResolvedConnection, SecurityConfig
from universal_db_mcp.connectors.oracle import OracleConnector
from universal_db_mcp.security.policy import EffectivePolicy

SP = "/private/tmp/claude-501/-Users-ag-work-Projects-universalDB-MCP/79f568f7-b5dc-4ffc-9aaf-933230e6f531/scratchpad"
TRAVEL_PW = "out/mockdb-secrets/oracle.pw"

def check(label, user, pwfile, database, options):
    import os
    os.environ["UDBMCP_LIVE_USER"] = user
    cfg = ConnectionConfig.model_validate({
        "type": "oracle", "host": "127.0.0.1", "port": 1522, "database": database,
        "username_env": "UDBMCP_LIVE_USER", "password_file": pwfile, "options": options,
    })
    r = ResolvedConnection("live", cfg)
    c = OracleConnector(r, EffectivePolicy.build(SecurityConfig(), r))
    h = c.health_check()
    print(f"[{label}] healthy={h.healthy} version={h.server_version} detail={(h.detail or '')[:110]}")

check("service-name form", "travel", TRAVEL_PW, "FREEPDB1", {})
check("tns alias form", "travel", TRAVEL_PW, "unused", {"tns_alias": "PRODDB", "tns_admin": SP + "/tns"})
check("legacy SID form", "system", SP + "/ora_system.pw", "unused", {"sid": "FREE"})
