"""Session safety profile: resolved, per-connection server-session settings.

The SQL guard decides what an agent may SEND; this decides how the server
session BEHAVES while it runs: isolation that does not lock production
tables, a ceiling on lock waits and statement time, a name DBAs can see, and
server-side read-only wherever the engine offers it. Connectors apply the
profile immediately after connecting and read it back for db_test_connection,
so the protection is verified, not assumed.
"""

from __future__ import annotations

import dataclasses
import re
from typing import Any

from universal_db_mcp.config import ResolvedConnection
from universal_db_mcp.security.policy import EffectivePolicy

# Engines with a SESSION-level read-only switch. Oracle only has per-transaction
# SET TRANSACTION READ ONLY (which does not stop DDL), Db2 has none, and SQL
# Server's ApplicationIntent only routes Availability Group connections.
SERVER_READ_ONLY_AVAILABLE: dict[str, bool] = {
    "postgres": True,
    "mysql": True,
    "clickhouse": True,
    "sqlite": True,
    "oracle": False,
    "db2": False,
    "mssql": False,
}

# Read-only connections on lock-taking engines default to the non-locking level.
READ_ONLY_DEFAULT_ISOLATION: dict[str, str] = {"db2": "ur", "mssql": "read_uncommitted"}

_UNSAFE = re.compile(r"[^A-Za-z0-9_.:@-]")


@dataclasses.dataclass(frozen=True)
class SessionProfile:
    engine: str
    connection_id: str
    isolation: str | None
    lock_timeout_seconds: float | None
    statement_timeout_seconds: float | None
    application_name: str
    enforce_read_only: bool
    server_read_only_available: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "engine": self.engine,
            "isolation": self.isolation,
            "lock_timeout_seconds": self.lock_timeout_seconds,
            "statement_timeout_seconds": self.statement_timeout_seconds,
            "application_name": self.application_name,
            "read_only_requested": self.enforce_read_only,
            "server_read_only_available": self.server_read_only_available,
        }


def resolve_session(connection: ResolvedConnection, policy: EffectivePolicy) -> SessionProfile:
    cfg = connection.config
    s = cfg.session
    engine = cfg.type
    isolation = s.isolation
    if isolation is None and cfg.read_only:
        isolation = READ_ONLY_DEFAULT_ISOLATION.get(engine)
    name = s.application_name or f"udbmcp:{connection.name}"
    # A connection id is free text in the config; the DSN keywords it lands
    # in are not.
    name = _UNSAFE.sub("_", name)[:64]
    lock_timeout = s.lock_timeout_seconds
    if engine in ("oracle", "clickhouse"):
        lock_timeout = None  # no session-level lock-wait ceiling exists on these engines
    return SessionProfile(
        engine=engine,
        connection_id=connection.name,
        isolation=isolation,
        lock_timeout_seconds=lock_timeout,
        statement_timeout_seconds=(
            float(policy.hard_query_timeout_seconds) if s.statement_timeout_from_policy else None
        ),
        application_name=name,
        enforce_read_only=bool(s.enforce_read_only and cfg.read_only),
        server_read_only_available=SERVER_READ_ONLY_AVAILABLE.get(engine, False),
    )
