"""Engine catalogs and system schemas that discovery skips by default.

Value search and relationship inference walk every permitted table; without
this list they spend their budget on SYSIBM, pg_catalog or CTXSYS and report
"relationships" between catalog views. Callers can still name a system
schema explicitly.
"""

from __future__ import annotations

SYSTEM_SCHEMAS: dict[str, frozenset[str]] = {
    "postgres": frozenset({"pg_catalog", "information_schema", "pg_toast"}),
    "mysql": frozenset({"mysql", "sys", "performance_schema", "information_schema"}),
    "mssql": frozenset({"sys", "information_schema", "guest", "db_owner", "db_accessadmin",
                        "db_securityadmin", "db_ddladmin", "db_backupoperator", "db_datareader",
                        "db_datawriter", "db_denydatareader", "db_denydatawriter"}),
    "oracle": frozenset({"sys", "system", "ctxsys", "mdsys", "xdb", "outln", "dbsnmp", "appqossys",
                         "ordsys", "orddata", "ordplugins", "wmsys", "olapsys", "lbacsys", "dvsys",
                         "audsys", "gsmadmin_internal", "ojvmsys", "dbsfwuser", "ggsys", "remote_scheduler_agent",
                         "sysbackup", "sysdg", "syskm", "sysrac", "sys$umf", "dip", "anonymous", "xs$null",
                         "apex_public_user", "flows_files", "pdbadmin"}),
    "db2": frozenset({"sysibm", "syscat", "sysstat", "sysproc", "sysibmadm", "sysfun", "systools",
                      "nullid", "sqlj", "syspublic"}),
    "clickhouse": frozenset({"system", "information_schema"}),
    "sqlite": frozenset(),
}

SYSTEM_TABLE_PREFIXES: dict[str, tuple[str, ...]] = {
    "sqlite": ("sqlite_",),
    "oracle": ("dr$", "sys_", "bin$", "mlog$", "rupd$"),
    "postgres": ("pg_",),
}


def is_system_object(engine: str, schema: str | None, table: str) -> bool:
    if schema and schema.lower() in SYSTEM_SCHEMAS.get(engine, frozenset()):
        return True
    low = table.lower()
    return any(low.startswith(p) for p in SYSTEM_TABLE_PREFIXES.get(engine, ()))
