"""Portable column types across the seven engines.

Every engine spells its types differently (``NUMBER(10,2)``, ``decimal``,
``DECIMAL(10,2)``, ``Decimal(10, 2)``, ``int8``, ``BIGINT``...). An ETL layer
or a cross-database search needs ONE vocabulary to compare columns and to
create matching targets, so each catalog type is mapped to a small portable
set plus a kind that says what is safe to aggregate.

The mapping is deliberately conservative: anything unknown becomes
``other`` with kind ``opaque`` and is never profiled with MIN/MAX/DISTINCT.
"""

from __future__ import annotations

import dataclasses
import re

# kind: what profiling may do with the column
#   numeric / string / temporal / boolean -> COUNT, DISTINCT, MIN, MAX
#   binary / json / opaque              -> COUNT only
KINDS = ("numeric", "string", "temporal", "boolean", "binary", "json", "opaque")


@dataclasses.dataclass(frozen=True)
class PortableType:
    # integer | bigint | decimal | float | boolean | string | text | date | time |
    # timestamp | timestamptz | binary | json | uuid | other
    name: str
    kind: str
    length: int | None = None
    precision: int | None = None
    scale: int | None = None

    def as_dict(self) -> dict[str, object]:
        out: dict[str, object] = {"portable_type": self.name, "kind": self.kind}
        if self.length is not None:
            out["length"] = self.length
        if self.precision is not None:
            out["precision"] = self.precision
        if self.scale is not None:
            out["scale"] = self.scale
        return out


_PARAMS = re.compile(r"\(([^)]*)\)")


def _ints(text: str) -> list[int]:
    return [int(x) for x in re.findall(r"\d+", text)]


def portable_type(engine: str, data_type: str | None) -> PortableType:  # noqa: PLR0911, PLR0912 - a type table
    raw = (data_type or "").strip()
    low = raw.lower()
    base = low.split("(", 1)[0].strip()
    match = _PARAMS.search(low)
    params = _ints(match.group(1)) if match else []
    p1 = params[0] if params else None
    p2 = params[1] if len(params) > 1 else None

    # ClickHouse wraps everything: Nullable(T), LowCardinality(T)
    if engine == "clickhouse":
        inner = low
        for wrapper in ("nullable(", "lowcardinality("):
            while inner.startswith(wrapper):
                inner = inner[len(wrapper):-1]
        base = inner.split("(", 1)[0].strip()
        inner_match = _PARAMS.search(inner)
        params = _ints(inner_match.group(1)) if inner_match else []
        p1 = params[0] if params else None
        p2 = params[1] if len(params) > 1 else None
        if base in ("int8", "int16", "int32", "uint8", "uint16", "uint32"):
            return PortableType("integer", "numeric")
        if base in ("int64", "uint64", "int128", "uint128", "int256", "uint256"):
            return PortableType("bigint", "numeric")
        if base in ("float32", "float64", "bfloat16"):
            return PortableType("float", "numeric")
        if base.startswith("decimal"):
            return PortableType("decimal", "numeric", precision=p1, scale=p2)
        if base == "bool":
            return PortableType("boolean", "boolean")
        if base == "string":
            return PortableType("text", "string")
        if base == "fixedstring":
            return PortableType("string", "string", length=p1)
        if base == "uuid":
            return PortableType("uuid", "string")
        if base in ("date", "date32"):
            return PortableType("date", "temporal")
        if base.startswith("datetime64"):
            return PortableType("timestamp", "temporal")
        if base == "datetime":
            return PortableType("timestamp", "temporal")
        if base in ("json", "object"):
            return PortableType("json", "json")
        if base.startswith(("array", "map", "tuple", "nested", "aggregatefunction", "simpleaggregatefunction")):
            return PortableType("other", "opaque")
        if base.startswith("enum"):
            return PortableType("string", "string")
        if base.startswith("ipv"):
            return PortableType("string", "string")
        return PortableType("other", "opaque")

    # integers
    if base in ("tinyint", "smallint", "int2", "mediumint", "int", "integer", "int4", "serial", "smallserial"):
        return PortableType("integer", "numeric")
    if base in ("bigint", "int8", "bigserial"):
        return PortableType("bigint", "numeric")
    # Oracle NUMBER: scale 0 (or absent with small precision) is an integer
    if base == "number":
        if p2 in (None, 0) and p1 is not None:
            return PortableType("bigint" if p1 > 9 else "integer", "numeric", precision=p1, scale=0)
        if p1 is None:
            return PortableType("decimal", "numeric")
        return PortableType("decimal", "numeric", precision=p1, scale=p2)
    if base in ("decimal", "numeric", "dec", "money", "smallmoney", "decfloat"):
        return PortableType("decimal", "numeric", precision=p1, scale=p2)
    if base in ("real", "float", "float4", "float8", "double", "double precision", "binary_float", "binary_double"):
        return PortableType("float", "numeric")
    # booleans
    if base in ("boolean", "bool", "bit") and (p1 in (None, 1)):
        return PortableType("boolean", "boolean")
    # strings
    if base in ("character varying", "varchar", "varchar2", "nvarchar", "nvarchar2", "character", "char", "nchar",
                "bpchar", "name", "vargraphic", "graphic", "citext"):
        return PortableType("string", "string", length=p1)
    if base in ("text", "ntext", "mediumtext", "longtext", "tinytext", "clob", "nclob", "dbclob", "long",
                "enum", "set"):
        return PortableType("text", "string") if base not in ("enum", "set") else PortableType("string", "string")
    if base in ("uuid", "uniqueidentifier"):
        return PortableType("uuid", "string")
    if base in ("varchar(max)", "nvarchar(max)"):
        return PortableType("text", "string")
    if base in ("varchar", "nvarchar") and p1 == -1:
        return PortableType("text", "string")
    # temporal
    if base == "date":
        return PortableType("date", "temporal")
    if base in ("time", "time without time zone", "time with time zone", "timetz"):
        return PortableType("time", "temporal")
    if "time zone" in low or base in ("timestamptz", "datetimeoffset"):
        # checked before the plain timestamp branch: Oracle spells it
        # TIMESTAMP(6) WITH TIME ZONE, whose base is just "timestamp"
        if "without" in low:
            return PortableType("timestamp", "temporal")
        return PortableType("timestamptz", "temporal")
    if base in ("timestamp", "datetime", "datetime2", "smalldatetime"):
        return PortableType("timestamp", "temporal")
    if base.startswith("timestamp"):
        return PortableType("timestamp", "temporal")
    if base.startswith("interval") or base == "year":
        return PortableType("other", "string")
    # binary and large objects
    if base in ("bytea", "blob", "mediumblob", "longblob", "tinyblob", "binary", "varbinary", "image", "raw",
                "long raw", "bfile", "varbinary(max)"):
        return PortableType("binary", "binary")
    # json / xml
    if base in ("json", "jsonb"):
        return PortableType("json", "json")
    if base in ("xml", "xmltype"):
        return PortableType("other", "opaque")
    # spatial and other opaque
    if base.startswith(("geometry", "geography", "sdo_", "point", "polygon", "line", "box", "circle", "path",
                        "hierarchyid", "sql_variant", "tsvector", "inet", "cidr", "macaddr")):
        return PortableType("other", "opaque")
    return PortableType("other", "opaque")


def compatible(a: PortableType, b: PortableType) -> bool:
    """Loose compatibility for relationship inference: same kind, and for
    strings/numerics the portable names may differ (integer vs bigint,
    string vs text) since keys are commonly stored that way across systems."""
    if a.kind != b.kind:
        return False
    if a.kind in ("numeric", "string", "temporal"):
        return True
    return a.name == b.name
