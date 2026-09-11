"""Hardening regressions from the production-readiness review.

Covers: Oracle DB links, locking reads, ClickHouse SETTINGS, sqlite
main./temp. default-deny bypass, engine->dialect mapping (mssql/db2),
statement size cap, and RecursionError handling."""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from universal_db_mcp.errors import ToolFailure
from universal_db_mcp.security.sql_guard import SqlGuard, StaticResolver


@dataclass
class FakePolicy:
    connection_id: str = "c1"
    engine: str = "sqlite"
    allowed_schemas: frozenset = frozenset({"reporting"})
    default_deny_objects: bool = True
    allowed_system_schemas: frozenset = frozenset({"information_schema"})
    allow_explain_analyze: bool = False
    calls: list = field(default_factory=list)

    def check_object(self, schema, name):  # noqa: ANN001
        self.calls.append((schema, name))
        if schema is None:
            return
        if not self.allowed_schemas:
            return  # empty allowlist = unrestricted, mirroring EffectivePolicy
        if schema.lower() not in {s.lower() for s in self.allowed_schemas}:
            raise ToolFailure("AUTHORIZATION_DENIED", f"schema '{schema}' is not permitted")


DENIED_CASES = [
    # Oracle DB links: unqualified, schema-qualified, and inside subqueries
    ("oracle", "SELECT * FROM customers@prod_link"),
    ("oracle", "SELECT * FROM reporting.customers@prod_link"),
    ("oracle", "SELECT * FROM (SELECT * FROM customers@prod_link) x"),
    # Locking reads are side effects, not reads (all dialect variants)
    ("mysql", "SELECT * FROM customers FOR UPDATE"),
    ("mysql", "SELECT * FROM customers FOR UPDATE NOWAIT"),
    ("postgres", "SELECT * FROM customers FOR SHARE"),
    ("postgres", "SELECT * FROM customers FOR NO KEY UPDATE"),
    ("postgres", "SELECT * FROM customers FOR KEY SHARE"),
    ("oracle", "SELECT * FROM customers FOR UPDATE WAIT 5"),
    # ClickHouse SETTINGS relax engine-side limits
    ("clickhouse", "SELECT * FROM customers SETTINGS max_result_rows=0"),
    ("clickhouse", "SELECT * FROM customers SETTINGS max_memory_usage=100000000000"),
    # sqlite default-deny bypass via main./temp. qualification (empty resolver)
    ("sqlite", "SELECT * FROM main.secret_table"),
    ("sqlite", "SELECT * FROM temp.secret_table"),
]


@pytest.mark.parametrize("engine,sql", DENIED_CASES)
def test_denied(engine: str, sql: str) -> None:
    policy = FakePolicy(engine=engine)
    resolver = StaticResolver({(None, "customers")} | {("main", "customers"), ("main", "temp_dummy")})
    guard = SqlGuard(engine, policy, resolver)  # type: ignore[arg-type]
    with pytest.raises(ToolFailure, match="POLICY_VIOLATION"):
        guard.validate_select(sql)


ALLOWED_CASES = [
    ("sqlite", "SELECT * FROM customers"),
    ("sqlite", "SELECT * FROM main.customers"),
    ("sqlite", "SELECT * FROM sqlite_schema"),
    # engine -> dialect mapping keeps mssql/db2 usable
    ("mssql", "SELECT 1"),
    ("db2", "SELECT 1 FROM SYSIBM.SYSDUMMY1"),
]


@pytest.mark.parametrize("engine,sql", ALLOWED_CASES)
def test_allowed(engine: str, sql: str) -> None:
    policy = FakePolicy(engine=engine, allowed_schemas=frozenset())
    objects = {
        ("main", "customers"),
        (None, "customers"),
        ("main", "sqlite_schema"),
        (None, "sqlite_schema"),
        ("sysibm", "sysdummy1"),
    }
    guard = SqlGuard(engine, policy, StaticResolver(objects))  # type: ignore[arg-type]
    assert guard.validate_select(sql).kind == "select"


def test_unknown_dialect_parse_failure_is_policy_denial_not_internal() -> None:
    # 'db2' maps to postgres internally, so simulate a truly unknown engine
    # string through the guard constructor path used by tests.
    policy = FakePolicy(engine="db2")
    guard = SqlGuard("nosuchdialect", policy, StaticResolver(set()))  # type: ignore[arg-type]
    with pytest.raises(ToolFailure, match="could not be parsed"):
        guard.validate_select("SELECT 1")


def test_oversized_statement_rejected_with_validation_category() -> None:
    policy = FakePolicy(engine="sqlite")
    guard = SqlGuard("sqlite", policy, StaticResolver({(None, "customers")}))  # type: ignore[arg-type]
    big = f"SELECT * FROM customers WHERE a IN ({','.join(str(i) for i in range(30000))})"
    with pytest.raises(ToolFailure, match="VALIDATION_ERROR"):
        guard.validate_select(big)


def test_deep_nesting_yields_policy_denial_not_recursion_error() -> None:
    policy = FakePolicy(engine="postgres")
    guard = SqlGuard("postgres", policy, StaticResolver({(None, "t")}))  # type: ignore[arg-type]
    sql = "SELECT * FROM t WHERE " + "(" * 200 + "a=1" + ")" * 200
    with pytest.raises(ToolFailure) as exc:
        guard.validate_select(sql)
    assert "POLICY_VIOLATION" in str(exc.value)
