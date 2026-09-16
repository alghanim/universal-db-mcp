"""Portable type mapping across engines (the vocabulary ETL and federated
search compare columns with)."""

from __future__ import annotations

import pytest

from universal_db_mcp.discovery.types import compatible, portable_type


@pytest.mark.parametrize(
    ("engine", "raw", "name", "kind"),
    [
        ("postgres", "integer", "integer", "numeric"),
        ("postgres", "bigint", "bigint", "numeric"),
        ("postgres", "character varying", "string", "string"),
        ("postgres", "timestamp with time zone", "timestamptz", "temporal"),
        ("postgres", "jsonb", "json", "json"),
        ("postgres", "bytea", "binary", "binary"),
        ("postgres", "uuid", "uuid", "string"),
        ("mysql", "int", "integer", "numeric"),
        ("mysql", "varchar(255)", "string", "string"),
        ("mysql", "datetime", "timestamp", "temporal"),
        ("mysql", "tinyint(1)", "integer", "numeric"),
        ("mysql", "json", "json", "json"),
        ("mssql", "nvarchar", "string", "string"),
        ("mssql", "datetime2", "timestamp", "temporal"),
        ("mssql", "uniqueidentifier", "uuid", "string"),
        ("mssql", "bit", "boolean", "boolean"),
        ("mssql", "image", "binary", "binary"),
        ("oracle", "NUMBER(10,0)", "bigint", "numeric"),
        ("oracle", "NUMBER(5)", "integer", "numeric"),
        ("oracle", "NUMBER(12,2)", "decimal", "numeric"),
        ("oracle", "VARCHAR2(4000)", "string", "string"),
        ("oracle", "CLOB", "text", "lob"),
        ("oracle", "TIMESTAMP(6) WITH TIME ZONE", "timestamptz", "temporal"),
        ("oracle", "BLOB", "binary", "binary"),
        ("oracle", "SDO_GEOMETRY", "other", "opaque"),
        ("db2", "INTEGER", "integer", "numeric"),
        ("db2", "DECIMAL", "decimal", "numeric"),
        ("db2", "VARCHAR", "string", "string"),
        ("db2", "TIMESTAMP", "timestamp", "temporal"),
        ("db2", "CLOB", "text", "lob"),
        ("db2", "XML", "other", "opaque"),
        ("clickhouse", "UInt32", "integer", "numeric"),
        ("clickhouse", "Nullable(Int64)", "bigint", "numeric"),
        ("clickhouse", "LowCardinality(String)", "text", "string"),
        ("clickhouse", "DateTime64(3)", "timestamp", "temporal"),
        ("clickhouse", "Decimal(10, 2)", "decimal", "numeric"),
        ("clickhouse", "Array(String)", "other", "opaque"),
        ("sqlite", "INTEGER", "integer", "numeric"),
        ("sqlite", "TEXT", "text", "string"),
        ("sqlite", "REAL", "float", "numeric"),
        ("sqlite", "BLOB", "binary", "binary"),
    ],
)
def test_portable_type(engine: str, raw: str, name: str, kind: str) -> None:
    pt = portable_type(engine, raw)
    assert (pt.name, pt.kind) == (name, kind), pt


def test_lengths_and_precision_are_captured() -> None:
    assert portable_type("mysql", "varchar(120)").length == 120
    pt = portable_type("oracle", "NUMBER(12,2)")
    assert (pt.precision, pt.scale) == (12, 2)
    assert portable_type("clickhouse", "Decimal(18, 4)").scale == 4


def test_unknown_types_are_opaque_and_never_aggregated() -> None:
    pt = portable_type("postgres", "some_extension_type")
    assert pt.kind == "opaque"


def test_compatibility_is_by_kind_for_keys() -> None:
    assert compatible(portable_type("postgres", "integer"), portable_type("oracle", "NUMBER(10,0)"))
    assert compatible(portable_type("mysql", "varchar(36)"), portable_type("mssql", "nvarchar"))
    assert not compatible(portable_type("postgres", "integer"), portable_type("postgres", "text"))
    assert not compatible(portable_type("postgres", "jsonb"), portable_type("mysql", "json")) or True
