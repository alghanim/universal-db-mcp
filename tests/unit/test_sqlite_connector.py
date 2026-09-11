"""SQLite connector behavior: read-only, authorizer backstop, limits, metadata."""

from __future__ import annotations

import sqlite3

import pytest

from universal_db_mcp.connectors.base import QuerySpec
from universal_db_mcp.connectors.registry import build_connector


@pytest.fixture()
def connector(app_ctx, demo_policy):
    return build_connector(app_ctx.resolved["demo_sqlite"], demo_policy)


def test_health(connector) -> None:
    h = connector.health_check()
    assert h.healthy
    assert h.server_version


def test_query_basic(connector) -> None:
    out = connector.execute_query(
        QuerySpec(sql="SELECT customer_id, full_name FROM customers ORDER BY customer_id", max_rows=5)
    )
    assert [c[0] for c in out.columns] == ["customer_id", "full_name"]
    assert len(out.rows) == 5
    assert out.rows[0][0] == 1


def test_row_limit_truncates(connector) -> None:
    out = connector.execute_query(QuerySpec(sql="SELECT customer_id FROM customers", max_rows=3))
    assert out.truncated
    assert len(out.rows) == 3


def test_named_parameters(connector) -> None:
    out = connector.execute_query(
        QuerySpec(sql="SELECT full_name FROM customers WHERE customer_id = :cid", parameters={"cid": 2})
    )
    assert out.rows == [["User 1"]]


def test_bigint_preserved(connector) -> None:
    out = connector.execute_query(QuerySpec(sql="SELECT balance_cents FROM accounts WHERE account_id = 1"))
    assert out.rows[0][0] == str(2**60)  # exact, out of JSON-safe range -> string
    assert out.columns[0][1] == "bigint"


def test_metadata(connector) -> None:
    tables = connector.list_tables(None, {"table", "view"}, None)
    names = {t.name for t in tables}
    assert {"customers", "accounts", "v_accounts"} <= names
    cols = connector.list_columns("main", "customers")
    assert [c.name for c in cols][:2] == ["customer_id", "full_name"]
    fks = connector.get_foreign_keys("main", "accounts")
    assert fks and fks[0].ref_table == "customers"
    views = connector.list_views("main")
    assert any(v.name == "v_accounts" and v.definition for v in views)


def test_capabilities_truthful(connector) -> None:
    caps = connector.capabilities()
    assert caps.get("list_synonyms").value == "unsupported"
    assert caps.get("explain_analyze").value == "unsupported"


def test_missing_file_names_artifact(app_ctx, demo_policy, tmp_path) -> None:
    from universal_db_mcp.config import ResolvedConnection

    cfg = app_ctx.resolved["demo_sqlite"].config.model_copy(update={"database": str(tmp_path / "nope.db")})
    conn = build_connector(ResolvedConnection("demo_sqlite", cfg), demo_policy)
    # health_check reports; it does not raise. The detail must name the artifact.
    h = conn.health_check()
    assert not h.healthy
    assert "nope.db" in (h.detail or "")
    # while a direct open does raise, naming the missing local file
    with pytest.raises(FileNotFoundError, match="nope.db"):
        conn._open()


def test_write_denied_by_readonly_handle(connector) -> None:
    # The guard denies INSERT earlier; this proves the engine layer refuses
    # too (authorizer + read-only handle) even if SQL reached the driver.
    spec = QuerySpec(sql="CREATE TABLE hack (x int)")
    with pytest.raises(sqlite3.Error):
        connector.execute_query(spec)
