"""Profiling math and relationship inference (pure logic, no database)."""

from __future__ import annotations

from universal_db_mcp.connectors.base import ColumnInfo, IndexInfo, KeyInfo
from universal_db_mcp.discovery.inference import TableFacts, TableRef, infer_relationships
from universal_db_mcp.discovery.profile import (
    aggregate_select_list,
    build_profiles,
    findings_for_table,
    wants_top_values,
)


def _col(name: str, dtype: str, nullable: bool = True) -> ColumnInfo:
    return ColumnInfo(schema="s", table="t", name=name, data_type=dtype, nullable=nullable)


def test_select_list_aggregates_only_safe_kinds() -> None:
    cols = [_col("id", "integer"), _col("note", "varchar(4000)"), _col("doc", "jsonb"), _col("img", "bytea")]
    select, layout = aggregate_select_list(cols, "postgres", lambda n: f'"{n}"', "LENGTH")
    assert select.startswith("COUNT(*)")
    assert 'COUNT(DISTINCT "id")' in select and 'MAX(LENGTH("note"))' in select
    assert 'DISTINCT "doc"' not in select and 'MIN("img")' not in select, "json/binary get COUNT only"
    measures = {(c, m) for c, m in layout}
    assert ("doc", "non_null") in measures and ("doc", "distinct") not in measures


def test_profiles_are_rebuilt_from_the_single_row() -> None:
    cols = [_col("id", "integer", nullable=False), _col("note", "varchar(4000)")]
    select, layout = aggregate_select_list(cols, "postgres", lambda n: n, "LENGTH")
    #            count, id:non_null, distinct, min, max, note:non_null, distinct, min, max, max_length
    row = (1000, 1000, 1000, 1, 1000, 900, 12, "a", "z", 17)
    total, profiles = build_profiles(cols, "postgres", layout, row)
    assert total == 1000
    assert profiles["id"].unique_in_sample is True and profiles["id"].null_ratio == 0
    assert profiles["note"].null_ratio == 0.1 and profiles["note"].max_length == 17
    assert wants_top_values(profiles["note"]) and not wants_top_values(profiles["id"])


def test_findings_flag_missing_pk_fk_without_index_and_oversized_strings() -> None:
    cols = [_col("customer_id", "bigint", nullable=True), _col("note", "varchar(4000)")]
    select, layout = aggregate_select_list(cols, "postgres", lambda n: n, "LENGTH")
    row = (5000, 5000, 4000, 1, 90000, 5000, 3, "a", "c", 20)
    _, profiles = build_profiles(cols, "postgres", layout, row)
    findings = findings_for_table(
        sample_size=5000, row_estimate=1_000_000, columns=cols, profiles=profiles, indexes=[],
        foreign_keys=[KeyInfo(kind="foreign_key", name="fk_c", columns=["customer_id"], ref_table="customers")],
        stats={"row_estimate_source": "catalog_estimate", "stats_time": None},
    )
    codes = {f.code for f in findings}
    assert {"no_primary_key", "foreign_key_without_index", "oversized_string", "nullable_never_null",
            "low_cardinality", "integer_range_fits_smaller_type", "statistics_missing", "sampled"} <= codes
    assert all(f.evidence for f in findings)


def test_small_samples_do_not_produce_data_findings() -> None:
    cols = [_col("x", "integer")]
    select, layout = aggregate_select_list(cols, "postgres", lambda n: n, "LENGTH")
    _, profiles = build_profiles(cols, "postgres", layout, (5, 5, 5, 1, 5))
    findings = findings_for_table(sample_size=5, row_estimate=5, columns=cols, profiles=profiles,
                                  indexes=[IndexInfo(name="pk", columns=["x"], unique=True, primary=True)],
                                  foreign_keys=[], stats=None)
    assert findings == []


def _facts(conn: str, table: str, cols: list[tuple[str, str]], pk: str | None, fks: list[KeyInfo] | None = None,
           engine: str = "postgres") -> TableFacts:
    ref = TableRef(conn, "s", table)
    return TableFacts(
        ref=ref, engine=engine,
        columns=[ColumnInfo(schema="s", table=table, name=n, data_type=t) for n, t in cols],
        indexes=[IndexInfo(name="pk", columns=[pk], unique=True, primary=True)] if pk else [],
        foreign_keys=fks or [],
    )


def test_inference_reports_declared_then_name_and_pattern_matches_across_connections() -> None:
    customers = _facts("crm", "customers", [("customer_id", "integer"), ("name", "text")], "customer_id")
    orders = _facts("erp", "orders", [("order_id", "integer"), ("customer_id", "bigint"), ("total", "numeric")],
                    "order_id", engine="oracle")
    products = _facts("erp", "products", [("id", "integer"), ("sku", "text")], "id")
    items = _facts("erp", "order_items", [("order_id", "integer"), ("product_id", "integer")], None,
                   fks=[KeyInfo(kind="foreign_key", name="fk_o", columns=["order_id"], ref_table="orders",
                                ref_columns=["order_id"])])
    rels = infer_relationships([customers, orders, products, items])
    kinds = {(r.kind, r.source.table, r.target.table) for r in rels}
    assert ("declared", "order_items", "orders") in kinds
    assert ("inferred_name_type", "orders", "customers") in kinds, "same column name across connections"
    assert ("inferred_name_pattern", "order_items", "products") in kinds, "product_id -> products.id"
    declared = next(r for r in rels if r.kind == "declared")
    assert declared.confidence == 1.0
    cross = next(r for r in rels if r.source.table == "orders" and r.target.table == "customers")
    assert cross.confidence < 0.8, "cross-connection matches carry less confidence"


def test_generic_key_names_are_not_matched() -> None:
    a = _facts("x", "a", [("id", "integer"), ("name", "text")], "id")
    b = _facts("x", "b", [("id", "integer"), ("name", "text")], "id")
    assert infer_relationships([a, b]) == []
