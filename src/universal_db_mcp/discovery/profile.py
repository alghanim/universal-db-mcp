"""Bounded data profiling and optimization findings.

Profiles are computed over a SAMPLE (the connector's own bounded sample
query, i.e. the first N rows in storage order) with portable SQL aggregates,
and every query runs through the same executor, policy ceilings and session
safety profile as db_query. What is aggregated depends on the column's
portable kind: opaque, binary and json columns get a null count only, so a
CLOB, an XML column or a geometry never reaches MIN/MAX/DISTINCT.

The findings are deliberately mechanical and evidence-carrying: the agent
turns them into recommendations; this module never invents a number.
"""

from __future__ import annotations

import dataclasses
from typing import Any

from universal_db_mcp.connectors.base import ColumnInfo, IndexInfo, KeyInfo
from universal_db_mcp.discovery.types import PortableType, portable_type

AGGREGATABLE_KINDS = ("numeric", "string", "temporal", "boolean")
LOW_CARDINALITY_MAX = 50  # distinct values at or below this get top-values
TOP_VALUES = 5


@dataclasses.dataclass
class ColumnProfile:
    name: str
    data_type: str
    portable: PortableType
    nullable: bool | None
    non_null: int | None = None
    null_ratio: float | None = None
    distinct: int | None = None
    min: Any = None
    max: Any = None
    max_length: int | None = None
    top_values: list[dict[str, Any]] | None = None
    unique_in_sample: bool | None = None

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "name": self.name,
            "data_type": self.data_type,
            **self.portable.as_dict(),
            "nullable": self.nullable,
            "non_null": self.non_null,
            "null_ratio": self.null_ratio,
            "distinct": self.distinct,
            "min": self.min,
            "max": self.max,
            "max_length": self.max_length,
            "unique_in_sample": self.unique_in_sample,
        }
        if self.top_values is not None:
            out["top_values"] = self.top_values
        return out


def aggregate_select_list(
    columns: list[ColumnInfo], engine: str, quote: Any, length_fn: str
) -> tuple[str, list[tuple[str, str]]]:
    """Return (select list, [(column, measure), ...]) in output order.

    ``COUNT(*)`` comes first; each aggregatable column contributes COUNT,
    COUNT(DISTINCT), MIN and MAX; string columns add MAX(LENGTH); every other
    column contributes COUNT only.
    """
    parts = ["COUNT(*)"]
    layout: list[tuple[str, str]] = [("*", "count")]
    for col in columns:
        q = quote(col.name)
        pt = portable_type(engine, col.data_type)
        parts.append(f"COUNT({q})")
        layout.append((col.name, "non_null"))
        if pt.kind in AGGREGATABLE_KINDS:
            parts.append(f"COUNT(DISTINCT {q})")
            layout.append((col.name, "distinct"))
            parts.append(f"MIN({q})")
            layout.append((col.name, "min"))
            parts.append(f"MAX({q})")
            layout.append((col.name, "max"))
            if pt.kind == "string":
                parts.append(f"MAX({length_fn}({q}))")
                layout.append((col.name, "max_length"))
    return ", ".join(parts), layout


def build_profiles(
    columns: list[ColumnInfo], engine: str, layout: list[tuple[str, str]], row: list[Any] | tuple[Any, ...]
) -> tuple[int, dict[str, ColumnProfile]]:
    """Turn the single aggregate row back into per-column profiles."""
    values = dict(zip([f"{c}\x00{m}" for c, m in layout], row, strict=False))
    total = int(values.get("*\x00count") or 0)
    profiles: dict[str, ColumnProfile] = {}
    for col in columns:
        prof = ColumnProfile(
            name=col.name,
            data_type=col.data_type,
            portable=portable_type(engine, col.data_type),
            nullable=col.nullable,
        )
        nn = values.get(f"{col.name}\x00non_null")
        if nn is not None:
            prof.non_null = int(nn)
            prof.null_ratio = round(1 - (prof.non_null / total), 4) if total else None
        d = values.get(f"{col.name}\x00distinct")
        if d is not None:
            prof.distinct = int(d)
            prof.unique_in_sample = bool(prof.non_null) and prof.distinct == prof.non_null
        prof.min = _plain(values.get(f"{col.name}\x00min"))
        prof.max = _plain(values.get(f"{col.name}\x00max"))
        ml = values.get(f"{col.name}\x00max_length")
        if ml is not None:
            prof.max_length = int(ml)
        profiles[col.name] = prof
    return total, profiles


def _plain(value: Any) -> Any:
    if value is None or isinstance(value, (int, float, str, bool)):
        return value if not isinstance(value, str) else value[:200]
    return str(value)[:200]


def wants_top_values(prof: ColumnProfile) -> bool:
    return (
        prof.portable.kind in AGGREGATABLE_KINDS
        and prof.distinct is not None
        and 0 < prof.distinct <= LOW_CARDINALITY_MAX
    )


# ------------------------------------------------------------------ findings
@dataclasses.dataclass
class Finding:
    code: str
    severity: str  # info | low | medium | high
    column: str | None
    evidence: str
    suggestion: str

    def as_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


def findings_for_table(  # noqa: PLR0912 - a rule table
    *,
    sample_size: int,
    row_estimate: int | None,
    columns: list[ColumnInfo],
    profiles: dict[str, ColumnProfile],
    indexes: list[IndexInfo],
    foreign_keys: list[KeyInfo],
    stats: dict[str, Any] | None,
) -> list[Finding]:
    out: list[Finding] = []
    has_pk = any(i.primary for i in indexes)
    indexed_leading = {(i.columns[0].lower()) for i in indexes if i.columns}

    if columns and not has_pk:
        out.append(Finding(
            "no_primary_key", "high", None,
            "no primary key (or ClickHouse sorting key) is declared",
            "declare a primary key; replication, upserts and change capture depend on one",
        ))
    for fk in foreign_keys:
        if fk.columns and fk.columns[0].lower() not in indexed_leading:
            out.append(Finding(
                "foreign_key_without_index", "medium", fk.columns[0],
                f"foreign key {fk.name or ''} on ({', '.join(fk.columns)}) has no index whose leading column matches",
                "add an index on the foreign key columns; joins and parent deletes scan the table otherwise",
            ))
    if stats and stats.get("stats_time") is None and stats.get("row_estimate_source", "").startswith("catalog"):
        out.append(Finding(
            "statistics_missing", "low", None, "the catalog carries no statistics timestamp",
            "run the engine's statistics collection so the optimizer has cardinalities",
        ))
    meaningful = sample_size >= 100
    for col in columns:
        prof = profiles.get(col.name)
        if prof is None or prof.non_null is None:
            continue
        if meaningful and prof.non_null == 0:
            out.append(Finding(
                "column_all_null", "low", col.name, f"all {sample_size} sampled rows are NULL",
                "confirm the column is used; drop it or stop reading it in extracts",
            ))
            continue
        if meaningful and col.nullable and prof.null_ratio == 0:
            out.append(Finding(
                "nullable_never_null", "info", col.name,
                f"declared nullable but none of {sample_size} sampled rows is NULL",
                "consider NOT NULL if the application guarantees a value; it simplifies joins and targets",
            ))
        if (
            prof.portable.kind == "string" and prof.portable.length and prof.max_length is not None
            and meaningful and prof.portable.length >= 100 and prof.max_length * 4 < prof.portable.length
        ):
            out.append(Finding(
                "oversized_string", "info", col.name,
                f"declared length {prof.portable.length}, longest sampled value {prof.max_length}",
                "size the target column to the observed maximum with headroom in the ETL layer",
            ))
        if meaningful and prof.distinct is not None and 1 < prof.distinct <= 20 and prof.non_null >= 100:
            out.append(Finding(
                "low_cardinality", "info", col.name,
                f"{prof.distinct} distinct values across {prof.non_null} sampled rows",
                "candidate for a lookup/dimension table or an enum; a bitmap or filtered index if often filtered",
            ))
        if (
            meaningful and prof.unique_in_sample and not has_pk and prof.portable.kind in ("numeric", "string")
            and prof.null_ratio == 0
        ):
            out.append(Finding(
                "unique_candidate", "medium", col.name,
                f"all {prof.non_null} sampled non-null values are distinct",
                "candidate natural key; verify uniqueness on the full table before relying on it",
            ))
        if prof.portable.name == "bigint" and isinstance(prof.max, int) and isinstance(prof.min, int):
            if -2_147_483_648 <= prof.min and prof.max <= 2_147_483_647 and meaningful:
                out.append(Finding(
                    "integer_range_fits_smaller_type", "info", col.name,
                    f"sampled range {prof.min}..{prof.max} fits a 32-bit integer",
                    "an ETL target may use a 32-bit integer if the source is bounded; confirm on the full table",
                ))
    if row_estimate and sample_size and sample_size < row_estimate:
        out.append(Finding(
            "sampled", "info", None,
            f"profile is based on {sample_size} rows of an estimated {row_estimate} (first rows in storage order)",
            "treat ratios as indicative; re-profile with a larger sample for decisions",
        ))
    return out
