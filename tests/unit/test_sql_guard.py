"""Security battery for the SQL guard (spec §9/§14-E cases)."""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from universal_db_mcp.errors import ToolFailure
from universal_db_mcp.security.sql_guard import SqlGuard, StaticResolver


@dataclass
class FakePolicy:
    """Minimal stand-in with the guard-relevant surface."""

    connection_id: str = "c1"
    engine: str = "sqlite"
    # 'main' is where make_guard's resolver puts the objects: the guard
    # re-authorizes the schema an unqualified name binds to
    allowed_schemas: frozenset = frozenset({"reporting", "main"})
    default_deny_objects: bool = True
    allowed_system_schemas: frozenset = frozenset({"information_schema"})
    allow_explain_analyze: bool = False
    calls: list = field(default_factory=list)

    def check_object(self, schema, name):  # noqa: ANN001
        self.calls.append((schema, name))
        if schema is None or not self.allowed_schemas:
            return  # an empty allowlist leaves user schemas unrestricted, as in EffectivePolicy
        if schema.lower() not in {s.lower() for s in self.allowed_schemas}:
            raise ToolFailure("AUTHORIZATION_DENIED", f"schema '{schema}' is not permitted")


def make_guard(engine: str = "sqlite", objects=("customers", "accounts", "v_accounts")):
    policy = FakePolicy(engine=engine)
    resolver = StaticResolver({(None, o) for o in objects} | {("main", o) for o in objects})
    return SqlGuard(engine, policy, resolver)  # type: ignore[arg-type]


ALLOWED = [
    "SELECT * FROM customers",
    "select id from main.customers where id = ?",
    "SELECT full_name FROM customers WHERE customer_id = :cid",
    "SELECT * FROM customers ORDER BY created_at LIMIT 10",
    "WITH big AS (SELECT * FROM customers) SELECT count(*) FROM big",
    "SELECT * FROM v_accounts",
    "(SELECT 1)",
    "SELECT * FROM customers -- ordinary comment",
    "SELECT * FROM customers /* block comment */ WHERE 1=1",
]

DENIED = [
    # DML / DDL / txn / session
    "INSERT INTO customers VALUES (1)",
    "UPDATE customers SET full_name = 'x'",
    "DELETE FROM customers",
    "DROP TABLE customers",
    "CREATE TABLE t (a int)",
    "ALTER TABLE customers ADD COLUMN x int",
    "ATTACH DATABASE 'evil.db' AS evil",
    "PRAGMA journal_mode=WAL",
    "BEGIN",
    "COMMIT",
    "VACUUM",
    "GRANT SELECT ON customers TO someone",
    # multiple statements
    "SELECT 1; DROP TABLE customers",
    # modifying CTE inside a SELECT
    "WITH x AS (INSERT INTO customers VALUES (1)) SELECT * FROM x",
    "WITH x AS (DELETE FROM customers) SELECT * FROM x",
    "WITH x AS (UPDATE customers SET full_name='x') SELECT * FROM x",
    # SELECT INTO
    "SELECT * INTO newt FROM customers",
    # dangerous / unknown functions
    "SELECT load_extension('x')",
    "SELECT readfile('/etc/passwd')",
    "SELECT writefile('/tmp/x', 'y')",
    "SELECT definitely_not_a_function(1)",
    # table functions / dynamic tables
    "SELECT * FROM pragma_table_info('customers')",
    # executable comments
    "SELECT /*!50000 * */ FROM customers",
    # parser failures are denials, not approvals
    "SELEC * FORM customers",
    "]]] garbage ((( ",
    # unresolvable object under default-deny
    "SELECT * FROM secret_table",
    # quoted identifier for unresolvable object
    'SELECT * FROM "Secret Table"',
]


@pytest.mark.parametrize("sql", ALLOWED)
def test_allowed(sql: str) -> None:
    guard = make_guard()
    result = guard.validate_select(sql)
    assert result.kind == "select"


@pytest.mark.parametrize("sql", DENIED)
def test_denied(sql: str) -> None:
    guard = make_guard()
    with pytest.raises(ToolFailure) as exc:
        guard.validate_select(sql)
    assert "POLICY_VIOLATION" in str(exc.value), sql


def test_disallowed_schema_denied() -> None:
    policy = FakePolicy(allowed_schemas=frozenset({"reporting"}))
    resolver = StaticResolver({("reporting", "invoices")})
    guard = SqlGuard("postgres", policy, resolver)  # type: ignore[arg-type]
    with pytest.raises(ToolFailure, match="not permitted"):
        guard.validate_select("SELECT * FROM secret_schema.invoices")


def test_allowed_schema_passes_policy_check() -> None:
    policy = FakePolicy(allowed_schemas=frozenset({"reporting"}))
    resolver = StaticResolver({("reporting", "invoices")})
    guard = SqlGuard("postgres", policy, resolver)  # type: ignore[arg-type]
    result = guard.validate_select("SELECT * FROM reporting.invoices")
    assert ("reporting", "invoices") in policy.calls or result.tables


def test_explain_sqlite_ok() -> None:
    guard = make_guard()
    assert guard.validate_explain("EXPLAIN QUERY PLAN SELECT * FROM customers").kind == "explain"
    assert guard.validate_explain("EXPLAIN SELECT * FROM customers").kind == "explain"


def test_explain_hidden_dml_denied() -> None:
    guard = make_guard()
    with pytest.raises(ToolFailure):
        guard.validate_explain("EXPLAIN INSERT INTO customers VALUES (1)")
    with pytest.raises(ToolFailure):
        guard.validate_explain("EXPLAIN QUERY PLAN ATTACH DATABASE 'x' AS y")


def test_show_allowlist_mysql() -> None:
    guard = make_guard("mysql", objects=("t1",))
    assert guard.validate_show("SHOW TABLES").kind == "show"
    assert guard.validate_show("DESCRIBE main.t1").kind == "show"
    with pytest.raises(ToolFailure):
        # under an allowlist the object is named with its schema, as in a query
        guard.validate_show("DESCRIBE t1")
    with pytest.raises(ToolFailure):
        guard.validate_show("SHOW GRANTS FOR 'x'@'%'")
    with pytest.raises(ToolFailure):
        guard.validate_show("SHOW VARIABLES LIKE 'general_log%'")


def test_postgres_show_setting_only() -> None:
    guard = make_guard("postgres")
    assert guard.validate_show("SHOW work_mem").kind == "show"
    with pytest.raises(ToolFailure):
        guard.validate_show("SHOW ALL")


def test_sqlite_show_unsupported() -> None:
    guard = make_guard("sqlite")
    with pytest.raises(ToolFailure) as exc:
        guard.validate_show("SHOW TABLES")
    assert "CAPABILITY_UNSUPPORTED" in str(exc.value)


def test_explain_analyze_policy_gate_postgres() -> None:
    guard = make_guard("postgres")
    with pytest.raises(ToolFailure, match="disabled"):
        guard.validate_explain("EXPLAIN ANALYZE SELECT * FROM customers")


def test_resolver_none_means_deny_under_default_deny() -> None:
    policy = FakePolicy()
    guard = SqlGuard("sqlite", policy, StaticResolver(set()))  # type: ignore[arg-type]
    with pytest.raises(ToolFailure, match="could not be resolved"):
        guard.validate_select("SELECT * FROM customers")
