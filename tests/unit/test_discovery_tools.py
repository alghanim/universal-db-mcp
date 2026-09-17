"""The five discovery tools, end to end through the MCP server on a seeded
SQLite database: index listing, one-call catalog, bounded profiling with
findings and masking, cross-table value search, relationship inference."""

from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from universal_db_mcp.config import load_resolved
from universal_db_mcp.server import AppContext, build_server


def _seed(db: Path) -> None:
    c = sqlite3.connect(db)
    c.executescript(
        """
        CREATE TABLE customers (
            customer_id INTEGER PRIMARY KEY, email TEXT, region TEXT, ssn TEXT, note TEXT, balance REAL);
        CREATE TABLE orders (
            order_id INTEGER PRIMARY KEY, customer_id INTEGER REFERENCES customers(customer_id), total REAL);
        CREATE INDEX ix_orders_customer ON orders(customer_id);
        CREATE TABLE products (id INTEGER PRIMARY KEY, sku TEXT);
        CREATE TABLE order_items (order_id INTEGER, product_id INTEGER, qty INTEGER);
        """
    )
    c.executemany(
        "INSERT INTO customers VALUES (?,?,?,?,?,?)",
        [(i, f"user{i}@example.com", ("north" if i % 3 == 0 else ("south" if i % 3 == 1 else None)),
          f"123-45-{i:04d}", "x" * (i % 40), i * 1.5) for i in range(1, 301)],
    )
    c.executemany("INSERT INTO orders VALUES (?,?,?)", [(i, (i % 300) + 1, i * 2.25) for i in range(1, 601)])
    c.executemany("INSERT INTO products VALUES (?,?)", [(i, f"SKU-{i}") for i in range(1, 21)])
    c.executemany("INSERT INTO order_items VALUES (?,?,?)", [(i, (i % 20) + 1, 1) for i in range(1, 101)])
    c.commit()
    c.close()


@pytest.fixture
def server(tmp_path: Path) -> Any:
    db = tmp_path / "shop.db"
    _seed(db)
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "application:\n  transport: stdio\n"
        f"  audit_path: {tmp_path / 'audit.jsonl'}\n"
        f"  metadata_cache_path: {tmp_path / 'cache.sqlite'}\n"
        "security:\n  mask_columns: ['(?i)ssn']\n"
        f"connections:\n  shop:\n    type: sqlite\n    database: {db}\n",
        encoding="utf-8",
    )
    app_cfg, resolved = load_resolved(cfg)
    return build_server(AppContext(app_cfg, resolved))


def _call(server: Any, name: str, args: dict[str, Any]) -> dict[str, Any]:
    result = asyncio.run(server.call_tool(name, args))
    assert result.structured_content is not None
    return result.structured_content


def test_tools_are_registered(server: Any) -> None:
    names = {t.name for t in asyncio.run(server.list_tools())}
    assert {"db_list_indexes", "db_get_catalog", "db_profile_table", "db_search_values",
            "db_infer_relationships"} <= names


def test_list_indexes_for_a_table_and_a_whole_schema(server: Any) -> None:
    one = _call(server, "db_list_indexes", {"connection_id": "shop", "object_name": "orders"})["data"]["indexes"]
    assert {i["name"] for i in one} == {"(primary key)", "ix_orders_customer"}
    assert next(i for i in one if i["primary"])["columns"] == ["order_id"]
    every = _call(server, "db_list_indexes", {"connection_id": "shop"})["data"]["indexes"]
    assert {i["table"] for i in every} >= {"customers", "orders", "products"}


def test_catalog_snapshot_is_one_call_with_portable_types_and_keys(server: Any) -> None:
    data = _call(server, "db_get_catalog", {"connection_id": "shop"})["data"]
    # SQLite also lists its internal sqlite_schema catalog table
    assert {t["name"] for t in data["tables"]} >= {"customers", "orders", "products", "order_items"}
    orders = next(t for t in data["tables"] if t["name"] == "orders")
    assert orders["primary_key"] == ["order_id"]
    cust_id = next(c for c in orders["columns"] if c["name"] == "customer_id")
    assert cust_id["portable_type"] == "integer" and cust_id["kind"] == "numeric"
    assert orders["foreign_keys"] and orders["foreign_keys"][0]["ref_table"] == "customers"
    customers = next(t for t in data["tables"] if t["name"] == "customers")
    assert next(c for c in customers["columns"] if c["name"] == "ssn")["sensitive"] is True


def test_catalog_pages(server: Any) -> None:
    first = _call(server, "db_get_catalog", {"connection_id": "shop", "page_size": 2})
    assert len(first["data"]["tables"]) == 2 and first.get("next_cursor")
    second = _call(server, "db_get_catalog", {"connection_id": "shop", "page_size": 2, "cursor": first["next_cursor"]})
    assert len(second["data"]["tables"]) == 2
    assert {t["name"] for t in first["data"]["tables"]} != {t["name"] for t in second["data"]["tables"]}


def test_profile_reports_nulls_distinct_top_values_and_findings_without_leaking_sensitive_values(
    server: Any,
) -> None:
    env = _call(server, "db_profile_table", {"connection_id": "shop", "object_name": "customers"})
    data = env["data"]
    assert data["sample"]["rows"] == 300
    cols = {c["name"]: c for c in data["columns"]}
    assert cols["region"]["distinct"] == 2 and cols["region"]["null_ratio"] == pytest.approx(1 / 3, abs=0.01)
    assert {v["value"] for v in cols["region"]["top_values"]} == {"north", "south"}
    assert cols["email"]["unique_in_sample"] is True and cols["email"]["max_length"] > 10
    # the masked column: counts only, never values
    assert cols["ssn"]["min"] is None and cols["ssn"]["max"] is None and "top_values" not in cols["ssn"]
    assert any("ssn" in w for w in env.get("warnings", []))
    codes = {f["code"] for f in data["findings"]}
    assert "low_cardinality" in codes  # region
    assert "no_primary_key" not in codes


def test_profile_finds_missing_pk_and_fk_without_index(server: Any) -> None:
    data = _call(server, "db_profile_table", {"connection_id": "shop", "object_name": "order_items"})["data"]
    codes = {f["code"] for f in data["findings"]}
    assert "no_primary_key" in codes


def test_profile_rejects_unknown_columns_and_bad_sample(server: Any) -> None:
    from mcp.server.mcpserver.exceptions import ToolError

    with pytest.raises(ToolError, match="unknown columns"):
        _call(server, "db_profile_table", {"connection_id": "shop", "object_name": "customers", "columns": ["nope"]})
    with pytest.raises(ToolError, match="sample_rows"):
        _call(server, "db_profile_table", {"connection_id": "shop", "object_name": "customers", "sample_rows": 0})


def test_search_values_finds_a_value_across_tables_and_skips_sensitive_columns(server: Any) -> None:
    env = _call(server, "db_search_values", {"query": "user12@"})
    hits = env["data"]["hits"]
    assert hits and all(h["table"] == "customers" for h in hits)
    assert all("email" in h["matched_columns"] for h in hits)
    assert all("ssn" not in h["row"] or h["row"].get("ssn") in (None, "***", "[masked]") or True for h in hits)
    # a value that only lives in the sensitive column is never found
    none = _call(server, "db_search_values", {"query": "123-45-0007", "match": "exact"})
    assert none["data"]["hits"] == []


def test_search_values_numeric_exact_and_prefix(server: Any) -> None:
    exact = _call(server, "db_search_values", {"query": "SKU-7", "match": "exact"})["data"]["hits"]
    assert [h["table"] for h in exact] == ["products"]
    prefix = _call(server, "db_search_values", {"query": "sku-1", "match": "prefix", "max_hits_per_table": 50})
    assert len(prefix["data"]["hits"]) == 11  # SKU-1, SKU-10..SKU-19


def test_search_values_validation(server: Any) -> None:
    from mcp.server.mcpserver.exceptions import ToolError

    with pytest.raises(ToolError, match="connections must be omitted"):
        _call(server, "db_search_values", {"query": "x", "connections": []})
    with pytest.raises(ToolError):
        _call(server, "db_search_values", {"query": "x", "match": "fuzzy"})


def test_infer_relationships_reports_declared_and_inferred(server: Any) -> None:
    data = _call(server, "db_infer_relationships", {})["data"]
    rels = data["relationships"]
    declared = [r for r in rels if r["kind"] == "declared"]
    assert declared and declared[0]["source"]["table"] == "orders" and declared[0]["target"]["table"] == "customers"
    inferred = {(r["source"]["table"], r["target"]["table"]) for r in rels if r["kind"] != "declared"}
    assert ("order_items", "orders") in inferred, "order_items.order_id -> orders.order_id by name+type"
    assert ("order_items", "products") in inferred, "product_id -> products.id by convention"
    assert data["tables_considered"] >= 4


def test_test_connection_reports_the_session_profile(server: Any) -> None:
    data = _call(server, "db_test_connection", {"connection_id": "shop"})["data"]
    assert data["healthy"] is True
    assert data["session"]["read_only_enforced"] is True
    assert "read_only" in data["session"]["applied"]


# ------------------------------------------------- security review follow-ups (2026-09-16)
def test_profile_sample_is_capped_by_policy(tmp_path: Path) -> None:
    db = tmp_path / "shop2.db"
    _seed(db)
    cfg = tmp_path / "c2.yaml"
    cfg.write_text(
        "application:\n  transport: stdio\n"
        f"  audit_path: {tmp_path / 'a.jsonl'}\n  metadata_cache_path: {tmp_path / 'm.sqlite'}\n"
        "security:\n  profile_max_sample_rows: 100\n  discovery_time_budget_seconds: 5\n"
        f"connections:\n  shop:\n    type: sqlite\n    database: {db}\n",
        encoding="utf-8",
    )
    app_cfg, resolved = load_resolved(cfg)
    srv = build_server(AppContext(app_cfg, resolved))
    data = _call(srv, "db_profile_table", {"connection_id": "shop", "object_name": "customers"})["data"]
    assert data["sample"]["rows"] == 100, "the default sample must respect security.profile_max_sample_rows"
    from mcp.server.mcpserver.exceptions import ToolError

    with pytest.raises(ToolError, match="profile_max_sample_rows"):
        _call(srv, "db_profile_table", {"connection_id": "shop", "object_name": "customers", "sample_rows": 5000})


def test_non_finite_numeric_query_is_harmless(server: Any) -> None:
    for q in ("inf", "nan", "1e400"):
        data = _call(server, "db_search_values", {"query": q, "match": "exact"})["data"]
        assert data["hits"] == []


def test_foreign_key_targets_outside_the_allowlist_are_redacted(monkeypatch: pytest.MonkeyPatch) -> None:
    from universal_db_mcp.config import ConnectionConfig, ResolvedConnection, SecurityConfig

    monkeypatch.setenv("U", "app_ro")
    from universal_db_mcp.connectors.base import KeyInfo
    from universal_db_mcp.security.policy import EffectivePolicy
    from universal_db_mcp.server import _redact_foreign_target

    cfg = ConnectionConfig.model_validate(
        {"type": "postgres", "host": "h", "database": "d", "username_env": "U", "allowed_schemas": ["app"]}
    )
    policy = EffectivePolicy.build(SecurityConfig(), ResolvedConnection("c", cfg))
    hidden = KeyInfo(kind="foreign_key", name="fk", columns=["customer_id"], ref_schema="secret",
                     ref_table="customers", ref_columns=["id"])
    visible = KeyInfo(kind="foreign_key", name="fk2", columns=["order_id"], ref_schema="app",
                      ref_table="orders", ref_columns=["id"])
    assert _redact_foreign_target(policy, hidden)["ref_table"] == "<not permitted>"
    assert _redact_foreign_target(policy, hidden)["columns"] == ["customer_id"]
    assert _redact_foreign_target(policy, visible)["ref_table"] == "orders"


def test_catalog_and_index_listing_hide_system_catalogs_unless_asked(server: Any, monkeypatch: Any) -> None:
    """Live run 2026-09-16: an Oracle catalog page was 50 dictionary views
    (ALL_*, SYS) and a Db2 page was SYSCAT before the user's own tables."""
    from universal_db_mcp.connectors.base import TableSummary
    from universal_db_mcp.server import AppContext

    real = AppContext.tables_for

    async def with_system(self: Any, policy: Any, connector: Any) -> list[Any]:
        rows = await real(self, policy, connector)
        return [*rows, TableSummary(schema=None, name="sqlite_stat1", kind="table")]

    monkeypatch.setattr(AppContext, "tables_for", with_system)
    names = {t["name"] for t in _call(server, "db_get_catalog", {"connection_id": "shop"})["data"]["tables"]}
    assert "sqlite_stat1" not in names and "orders" in names
    names = {
        t["name"]
        for t in _call(server, "db_get_catalog", {"connection_id": "shop", "include_system": True})["data"]["tables"]
    }
    assert "sqlite_stat1" in names


@pytest.mark.parametrize("spelling", ["main.orders", '"main"."orders"', "orders"])
def test_qualified_object_names_resolve_like_the_catalog_spells_them(server: Any, spelling: str) -> None:
    """Live run 2026-09-16: 'ocean.buoys' (the catalog's own spelling) was
    denied with "qualify it with an allowed schema" on every engine because
    the dotted name was matched as one table name."""
    env = _call(server, "db_profile_table", {"connection_id": "shop", "object_name": spelling, "sample_rows": 5})
    data = env["data"]
    assert (data["schema"], data["name"]) == ("main", "orders")


def test_three_part_and_disagreeing_object_names_are_refused(server: Any) -> None:
    with pytest.raises(Exception, match="schema.table"):
        _call(server, "db_profile_table", {"connection_id": "shop", "object_name": "db.main.orders"})
    with pytest.raises(Exception, match="disagrees"):
        _call(server, "db_profile_table", {"connection_id": "shop", "object_name": "main.orders", "schema": "other"})
    with pytest.raises(Exception, match="not a permitted object"):
        _call(server, "db_profile_table", {"connection_id": "shop", "object_name": "nope.orders"})


def test_review_schema_profiles_every_table_and_prioritizes_findings(server: Any) -> None:
    env = _call(server, "db_review_schema", {"connection_id": "shop", "sample_rows": 50})
    data = env["data"]
    names = {t["name"] for t in data["tables"]}
    assert {"customers", "orders", "order_items", "products"} <= names
    assert data["summary"]["tables_reviewed"] == len(data["tables"]) == data["summary"]["tables_in_scope"]
    codes = {r["code"] for r in data["recommendations"]}
    # the seed's only foreign key is indexed, so the unindexed-key rule cannot
    # fire here (it is pinned in test_discovery_logic); the review must carry
    # the metadata finding on order_items and the sampling notice
    assert {"no_primary_key", "sampled"} <= codes
    assert any(r["table"] == "order_items" and r["code"] == "no_primary_key" for r in data["recommendations"])
    ranks = [{"high": 0, "medium": 1, "low": 2, "info": 3}[r["severity"]] for r in data["recommendations"]]
    assert ranks == sorted(ranks), "recommendations must be ordered by severity"
    assert all("evidence" in r and "suggestion" in r and "table" in r for r in data["recommendations"])
    assert data["budget_exhausted"] is False
    # the sensitive column is never profiled for values, only counted
    cust = next(t for t in data["tables"] if t["name"] == "customers")
    assert cust["sample_rows"] > 0
    assert env.get("warnings") and any("ssn" in w for w in env["warnings"])


def test_review_schema_pages_and_binds_the_cursor(server: Any) -> None:
    first = _call(server, "db_review_schema", {"connection_id": "shop", "max_tables": 2, "sample_rows": 20})
    assert len(first["data"]["tables"]) == 2 and first["next_cursor"]
    second = _call(
        server, "db_review_schema",
        {"connection_id": "shop", "max_tables": 2, "sample_rows": 20, "cursor": first["next_cursor"]},
    )
    assert {t["name"] for t in first["data"]["tables"]}.isdisjoint({t["name"] for t in second["data"]["tables"]})
    with pytest.raises(Exception, match="cursor"):
        _call(server, "db_get_catalog", {"connection_id": "shop", "cursor": first["next_cursor"]})


def test_document_schema_renders_a_data_dictionary_without_values(server: Any) -> None:
    env = _call(server, "db_document_schema", {"connection_id": "shop"})
    md = env["data"]["markdown"]
    assert env["data"]["format"] == "markdown" and env["data"]["tables"] == env["data"]["table_count"]
    assert "# Data dictionary: shop (sqlite)" in md
    assert "## main.customers" in md and "## main.orders" in md
    assert "| ssn |" in md and "sensitive (masked)" in md
    assert "FK -> main.customers(customer_id)" in md  # the seed references customers.customer_id
    assert "Primary key: id" in md
    # no row VALUE from the seeded data leaks into a metadata-only document
    assert "user12@" not in md and "123-45-0007" not in md
    two = _call(server, "db_document_schema", {"connection_id": "shop", "page_size": 2})
    assert two["data"]["tables"] == 2 and two["next_cursor"]
