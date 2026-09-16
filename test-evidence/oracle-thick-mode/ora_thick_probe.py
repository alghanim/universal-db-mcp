"""One mode per process: python-oracledb cannot switch to Thick mode after a
Thin connection has been made in the same interpreter (DPY-2019)."""
import os
import sys

sys.path.insert(0, "/src")
from universal_db_mcp.config import ConnectionConfig, ResolvedConnection, SecurityConfig
from universal_db_mcp.connectors.base import QuerySpec
from universal_db_mcp.connectors.oracle import OracleConnector
from universal_db_mcp.security.policy import EffectivePolicy

os.environ.setdefault("ORA_USER", "APP10G")
mode = sys.argv[1]
options = {"thick_mode": True} if mode == "thick" else {}

cfg = ConnectionConfig.model_validate({
    "type": "oracle",
    "host": os.environ.get("ORA_HOST", "udbmcp-ora11"),
    "port": 1521,
    "database": os.environ.get("ORA_SERVICE", "XE"),
    "username_env": "ORA_USER",
    "password_file": "/secrets/app10g.pw",
    "options": options,
})
resolved = ResolvedConnection("ora", cfg)
conn = OracleConnector(resolved, EffectivePolicy.build(SecurityConfig(), resolved))
health = conn.health_check()
print(f"[{mode.upper()}] healthy={health.healthy}")
if health.detail:
    print(f"[{mode.upper()}] detail: {health.detail[:200]}")
if health.healthy:
    out = conn.execute_query(QuerySpec(sql="SELECT COUNT(*) FROM app_rows", max_rows=5))
    print(f"[{mode.upper()}] query rows={out.rows}")
