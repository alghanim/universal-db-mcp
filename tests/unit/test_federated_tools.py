"""db_federated_query and db_federated_join on two SQLite connections."""
from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from universal_db_mcp.config import load_resolved
from universal_db_mcp.server import AppContext, _join_key, build_server


def _seed(path: Path, *, crm: bool) -> None:
    c = sqlite3.connect(path)
    if crm:
        c.executescript(
            """
            CREATE TABLE customers (id INTEGER PRIMARY KEY, name TEXT, ssn TEXT, region TEXT);
            INSERT INTO customers VALUES (1, 'Ada', '111-11-1111', 'north'), (2, 'Bo', '222-22-2222', 'south'),
                                         (3, 'Cy', '333-33-3333', 'north');
            CREATE TABLE sites (code TEXT, region TEXT);
            INSERT INTO sites VALUES ('N1', 'north');
            """
        )
    else:
        c.executescript(
            """
            CREATE TABLE customers (id INTEGER PRIMARY KEY, name TEXT, ssn TEXT, region TEXT);
            INSERT INTO customers VALUES (9, 'Zed', '999-99-9999', 'east');
            CREATE TABLE orders (order_id INTEGER PRIMARY KEY, customer_id REAL, total REAL);
            INSERT INTO orders VALUES (10, 1.0, 5.5), (11, 1.0, 7.0), (12, 3.0, 1.0), (13, 42.0, 9.9);
            """
        )
    c.commit()
    c.close()


@pytest.fixture
def server(tmp_path: Path) -> Any:
    crm, erp = tmp_path / "crm.db", tmp_path / "erp.db"
    _seed(crm, crm=True)
    _seed(erp, crm=False)
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "application:\n  transport: stdio\n"
        f"  audit_path: {tmp_path / 'audit.jsonl'}\n"
        f"  metadata_cache_path: {tmp_path / 'cache.sqlite'}\n"
        "security:\n  mask_columns: ['(?i)ssn']\n"
        f"connections:\n  crm:\n    type: sqlite\n    database: {crm}\n  erp:\n    type: sqlite\n    database: {erp}\n",
        encoding="utf-8",
    )
    app_cfg, resolved = load_resolved(cfg)
    return build_server(AppContext(app_cfg, resolved))


def _call(server: Any, name: str, args: dict[str, Any]) -> dict[str, Any]:
    result = asyncio.run(server.call_tool(name, args))
    assert result.structured_content is not None
    return result.structured_content


def test_federated_query_merges_matching_shapes_and_masks_per_connection(server: Any) -> None:
    env = _call(server, "db_federated_query", {"sql": "SELECT id, name, ssn FROM customers ORDER BY id"})
    data = env["data"]
    assert data["connections_run"] == 2 and data["connections_failed"] == 0
    merged = data["merged"]
    assert merged["columns"] == ["connection", "id", "name", "ssn"]
    assert [r[0] for r in merged["rows"]] == ["crm", "crm", "crm", "erp"]
    assert all(r[3] == "<masked>" for r in merged["rows"]), "masking applies before merging"
    assert "111-11-1111" not in str(env)


def test_federated_query_per_connection_statements_and_one_failure(server: Any) -> None:
    env = _call(
        server, "db_federated_query",
        {"queries": {"crm": "SELECT code, region FROM sites", "erp": "SELECT nope FROM orders"}},
    )
    data = env["data"]
    assert data["connections_run"] == 1 and data["connections_failed"] == 1
    failed = next(r for r in data["results"] if r["connection"] == "erp")
    assert "error" in failed and any("erp" in w for w in env["warnings"])
    assert data["merged"]["rows"] == [["crm", "N1", "north"]]
    with pytest.raises(Exception, match="either sql"):
        _call(server, "db_federated_query", {})
    with pytest.raises(Exception, match="unknown connections"):
        _call(server, "db_federated_query", {"sql": "SELECT 1", "connections": ["ghost"]})


def test_federated_query_reports_differing_shapes_without_a_merge(server: Any) -> None:
    env = _call(
        server, "db_federated_query",
        {"queries": {"crm": "SELECT id FROM customers", "erp": "SELECT order_id, total FROM orders"}},
    )
    assert env["data"]["merged"] is None and any("column names differ" in w for w in env["warnings"])


def test_federated_join_matches_int_and_real_keys_across_connections(server: Any) -> None:
    env = _call(
        server, "db_federated_join",
        {
            "left": {"connection": "crm", "sql": "SELECT id, name, region FROM customers"},
            "right": {"connection": "erp", "sql": "SELECT order_id, customer_id, total FROM orders"},
            "on": [["id", "customer_id"]],
        },
    )
    data = env["data"]
    assert data["columns"] == [
        "left.id", "left.name", "left.region", "right.order_id", "right.customer_id", "right.total",
    ]
    assert sorted(r[3] for r in data["rows"]) == [10, 11, 12]  # 1.0 and 3.0 in the ERP match 1 and 3 in the CRM
    assert data["matched_left_rows"] == 2 and data["unmatched_left_rows"] == 1 and data["truncated"] is False
    left = _call(
        server, "db_federated_join",
        {
            "left": {"connection": "crm", "sql": "SELECT id, name FROM customers"},
            "right": {"connection": "erp", "sql": "SELECT order_id, customer_id FROM orders"},
            "on": [["id", "customer_id"]], "join": "left",
        },
    )["data"]
    assert len(left["rows"]) == 4 and any(r[2] is None for r in left["rows"])
    capped = _call(
        server, "db_federated_join",
        {
            "left": {"connection": "crm", "sql": "SELECT id FROM customers"},
            "right": {"connection": "erp", "sql": "SELECT customer_id FROM orders"},
            "on": [["id", "customer_id"]], "max_rows": 1,
        },
    )["data"]
    assert len(capped["rows"]) == 1 and capped["truncated"] is True


def test_federated_join_never_matches_masked_keys(server: Any) -> None:
    env = _call(
        server, "db_federated_join",
        {
            "left": {"connection": "crm", "sql": "SELECT id, ssn FROM customers"},
            "right": {"connection": "erp", "sql": "SELECT id, ssn FROM customers"},
            "on": [["ssn", "ssn"]],
        },
    )
    assert env["data"]["rows"] == [] and any("masked" in w for w in env["warnings"])
    with pytest.raises(Exception, match="no column"):
        _call(
            server, "db_federated_join",
            {"left": {"connection": "crm", "sql": "SELECT id FROM customers"},
             "right": {"connection": "erp", "sql": "SELECT order_id FROM orders"}, "on": [["id", "nope"]]},
        )


@pytest.mark.parametrize(
    ("a", "b"),
    [(5, 5.0), (5, "5"), ("5.00", 5), (True, 1), ("A-1 ", "A-1"), (0.5, "0.50")],
)
def test_join_keys_normalise_numbers_by_value(a: Any, b: Any) -> None:
    assert _join_key(a, False) == _join_key(b, False)


def test_join_keys_keep_text_distinct_unless_case_insensitive() -> None:
    assert _join_key("Ada", False) != _join_key("ada", False)
    assert _join_key("Ada", True) == _join_key("ada", True)
    assert _join_key("007", False) == _join_key(7, False)
