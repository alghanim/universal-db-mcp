"""Db2 read-only tail clauses (WITH UR and friends).

sqlglot has no Db2 dialect, so Db2 statements are validated under the postgres
grammar. `SELECT ... WITH UR` - the standard Db2 reporting idiom that avoids
lock waits - is not postgres syntax, so it failed to parse and every such
query was denied. The clause is read-only by construction: it selects an
isolation level, it cannot write.

The guard validates the statement WITHOUT the tail and the executor sends the
ORIGINAL text (server.py builds QuerySpec(sql=sql)), so Db2 still receives the
clause. What must NOT be allowed is `USE AND KEEP ... LOCKS`, which acquires
write-intent locks.
"""

from __future__ import annotations

import pytest

from universal_db_mcp.config import ConnectionConfig, SecurityConfig
from universal_db_mcp.errors import ToolFailure
from universal_db_mcp.security.policy import EffectivePolicy
from universal_db_mcp.security.sql_guard import SqlGuard


def _guard(engine: str = "db2") -> SqlGuard:
    body = {"type": engine, "database": "d", "username_env": "U"}
    if engine != "sqlite":
        body["host"] = "h"
    cfg = ConnectionConfig.model_validate(body)
    policy = EffectivePolicy.build(
        SecurityConfig(default_deny_objects=False), type("R", (), {"config": cfg, "name": "c"})()
    )
    return SqlGuard(engine, policy, None)


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT * FROM APP.CUSTOMERS WITH UR",
        "select * from app.customers with ur",
        "SELECT * FROM APP.CUSTOMERS WITH CS",
        "SELECT * FROM APP.CUSTOMERS WITH RS",
        "SELECT * FROM APP.CUSTOMERS WITH RR",
        "SELECT * FROM APP.CUSTOMERS FOR READ ONLY",
        "SELECT * FROM APP.CUSTOMERS FOR FETCH ONLY WITH UR",
        "SELECT * FROM APP.CUSTOMERS OPTIMIZE FOR 100 ROWS WITH UR",
        "SELECT * FROM APP.CUSTOMERS FETCH FIRST 10 ROWS ONLY WITH UR",
        "SELECT * FROM APP.CUSTOMERS WITH UR;",
    ],
)
def test_db2_read_only_tail_clauses_are_allowed(sql: str) -> None:
    result = _guard().validate_select(sql)
    assert result.kind == "select"


def test_locking_clause_is_still_refused() -> None:
    with pytest.raises(ToolFailure, match="lock"):
        _guard().validate_select(
            "SELECT * FROM APP.CUSTOMERS WITH RR USE AND KEEP EXCLUSIVE LOCKS"
        )


def test_multi_statement_with_a_trailing_isolation_clause_is_still_refused() -> None:
    with pytest.raises(ToolFailure):
        _guard().validate_select("SELECT 1 FROM SYSIBM.SYSDUMMY1; DROP TABLE APP.CUSTOMERS WITH UR")


def test_the_clause_is_not_accepted_on_other_engines() -> None:
    """It is Db2 syntax; on postgres it is a typo the guard should still catch."""
    with pytest.raises(ToolFailure):
        _guard("postgres").validate_select("SELECT * FROM public.customers WITH UR")


def test_write_statement_with_a_tail_clause_is_still_refused() -> None:
    with pytest.raises(ToolFailure):
        _guard().validate_select("DELETE FROM APP.CUSTOMERS WITH UR")
