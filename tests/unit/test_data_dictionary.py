"""render_data_dictionary: pure rendering of catalog entries into Markdown."""
from __future__ import annotations

from universal_db_mcp.discovery.document import render_data_dictionary, render_table


def _entry() -> dict:
    return {
        "schema": "sales", "name": "orders", "kind": "table", "row_estimate": 12000,
        "row_estimate_source": "catalog_estimate", "comment": "one row per | order",
        "primary_key": ["id"],
        "columns": [
            {"name": "id", "data_type": "integer", "portable_type": "integer", "kind": "numeric",
             "nullable": False, "default": None, "comment": None, "in_primary_key": True, "sensitive": False},
            {"name": "customer_id", "data_type": "integer", "portable_type": "integer", "kind": "numeric",
             "nullable": True, "default": None, "comment": "buyer", "in_primary_key": False, "sensitive": False},
            {"name": "card_number", "data_type": "varchar(20)", "portable_type": "string", "kind": "string",
             "nullable": True, "default": "''", "comment": None, "in_primary_key": False, "sensitive": True},
        ],
        "indexes": [
            {"name": "pk", "columns": ["id"], "unique": True, "primary": True, "kind": "btree", "definition": None,
             "schema": "sales", "table": "orders"},
            {"name": "ix_orders_customer", "columns": ["customer_id"], "unique": False, "primary": False,
             "kind": "btree", "definition": None, "schema": "sales", "table": "orders"},
        ],
        "foreign_keys": [
            {"kind": "foreign_key", "name": "fk_orders_customer", "columns": ["customer_id"],
             "ref_schema": "sales", "ref_table": "customers", "ref_columns": ["id"],
             "source_schema": "sales", "source_table": "orders"},
        ],
    }


def test_table_section_carries_keys_indexes_and_masks_nothing_but_values() -> None:
    md = render_table(_entry())
    assert md.startswith("## sales.orders")
    assert "~12,000 rows (catalog_estimate)" in md
    assert "one row per \\| order" in md  # pipes are escaped inside Markdown tables
    assert "| id | integer | integer/numeric | no |  | PK |  |" in md
    assert "| customer_id | integer | integer/numeric | yes |  | FK -> sales.customers(id) | buyer |" in md
    assert "| card_number | varchar(20) | string/string | yes | '' |  | sensitive (masked) |" in md
    assert "Primary key: id" in md
    assert "- fk_orders_customer: (customer_id) -> sales.customers(id)" in md
    assert "- ix_orders_customer (customer_id)" in md and "- pk (" not in md


def test_dictionary_head_and_relationship_list() -> None:
    md = render_data_dictionary("crm", "postgres", [_entry()], schema="sales")
    assert md.startswith("# Data dictionary: crm (postgres), schema `sales`")
    assert "no table data was read" in md
    assert "## Declared relationships on this page" in md
    assert "- sales.orders(customer_id) -> sales.customers(id)" in md


def test_redacted_target_and_unknown_rows_render_honestly() -> None:
    e = _entry()
    e["row_estimate"] = None
    e["foreign_keys"][0].update({"ref_schema": "<not permitted>", "ref_table": "<not permitted>", "ref_columns": []})
    md = render_table(e)
    assert "row count unknown" in md
    assert "FK -> <not permitted>.<not permitted>" in md
