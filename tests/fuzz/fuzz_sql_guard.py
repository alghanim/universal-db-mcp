#!/usr/bin/env python3
"""Coverage-guided fuzzing of the SQL guard with Atheris.

The guard decides what an agent's SQL may do. Whatever text arrives, in any
of the seven dialects, it must either accept one read statement or refuse
with a ToolFailure; any other exception is a defect, and so is an input it
takes more than a few seconds over. Atheris mutates the seed corpus towards
new code paths and stops at the first such input, printing it.

An input is one byte choosing the engine, one choosing validate_select or
validate_explain, then the SQL as UTF-8 (tests/fuzz/corpus holds seeds).

    python tests/fuzz/fuzz_sql_guard.py <corpus-copy> -max_total_time=300 -timeout=10

Atheris has Linux wheels only; .github/workflows/fuzz.yml runs this weekly.
tests/unit/test_fuzz_harness.py runs check() over the seeds in the unit suite.
"""

from __future__ import annotations

import sys
from typing import Any

from universal_db_mcp.config import ConnectionConfig, SecurityConfig
from universal_db_mcp.errors import ToolFailure
from universal_db_mcp.security.policy import EffectivePolicy
from universal_db_mcp.security.sql_guard import SqlGuard

ENGINES = ("postgres", "mysql", "clickhouse", "oracle", "mssql", "db2", "sqlite")
MAX_SQL_BYTES = 8192


def _policy(engine: str) -> EffectivePolicy:
    # A connection limited to schema 'sales', default-deny off: the guard's
    # full parse and walk run on every input instead of stopping at the list.
    body: dict[str, Any] = {"type": engine, "database": "d", "username_env": "U", "allowed_schemas": ["sales"]}
    if engine != "sqlite":
        body["host"] = "h"
    resolved = type("R", (), {"config": ConnectionConfig.model_validate(body), "name": "fuzz"})()
    return EffectivePolicy.build(SecurityConfig(default_deny_objects=False), resolved)


POLICIES = {engine: _policy(engine) for engine in ENGINES}


def decode(data: bytes) -> tuple[str, bool, str]:
    """(engine, whether to validate as EXPLAIN, sql) from one fuzz input."""
    engine = ENGINES[data[0] % len(ENGINES)] if data else ENGINES[0]
    explain = len(data) > 1 and data[1] % 2 == 1
    return engine, explain, data[2 : 2 + MAX_SQL_BYTES].decode("utf-8", "replace")


def check(data: bytes) -> None:
    """The property: the guard accepts or refuses; it never fails otherwise."""
    engine, explain, sql = decode(data)
    guard = SqlGuard(engine, POLICIES[engine], None)  # a fresh guard: no state carried between inputs
    try:
        (guard.validate_explain if explain else guard.validate_select)(sql)
    except ToolFailure:
        pass


def main() -> None:
    import atheris

    atheris.instrument_all()
    atheris.Setup(sys.argv, check)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
