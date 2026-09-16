"""Relationship inference across connections, from metadata only.

Declared foreign keys are reported as-is. Beyond them, a column that shares
its name (case-insensitive) with a primary or unique key column of another
table, with a compatible portable type, is an inferred candidate - the
``customer_id -> customers.customer_id`` convention, plus the
``customer_id -> customers.id`` variant. Nothing here reads table data; a
candidate is a hint with a stated confidence, never a fact.
"""

from __future__ import annotations

import dataclasses
from typing import Any

from universal_db_mcp.connectors.base import ColumnInfo, IndexInfo, KeyInfo
from universal_db_mcp.discovery.types import compatible, portable_type


@dataclasses.dataclass(frozen=True)
class TableRef:
    connection: str
    schema: str | None
    table: str

    def as_dict(self) -> dict[str, Any]:
        return {"connection": self.connection, "schema": self.schema, "table": self.table}


@dataclasses.dataclass
class Relationship:
    kind: str  # declared | inferred_name_type | inferred_name_pattern
    confidence: float
    source: TableRef
    source_columns: list[str]
    target: TableRef
    target_columns: list[str]
    evidence: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "confidence": self.confidence,
            "source": self.source.as_dict(),
            "source_columns": self.source_columns,
            "target": self.target.as_dict(),
            "target_columns": self.target_columns,
            "evidence": self.evidence,
        }


@dataclasses.dataclass
class TableFacts:
    ref: TableRef
    engine: str
    columns: list[ColumnInfo]
    indexes: list[IndexInfo]
    foreign_keys: list[KeyInfo]


_GENERIC_KEY_NAMES = {"id", "key", "code", "name", "type", "status", "value", "uid", "pk"}


def infer_relationships(tables: list[TableFacts], *, cross_connection: bool = True) -> list[Relationship]:
    out: list[Relationship] = []
    # declared
    for t in tables:
        for fk in t.foreign_keys:
            if not fk.ref_table:
                continue
            out.append(Relationship(
                kind="declared", confidence=1.0, source=t.ref, source_columns=list(fk.columns),
                target=TableRef(t.ref.connection, fk.ref_schema or t.ref.schema, fk.ref_table),
                target_columns=list(fk.ref_columns), evidence=f"foreign key {fk.name or ''}".strip(),
            ))
    # key columns: single-column primary/unique keys per table
    keyed: list[tuple[TableFacts, str, Any]] = []
    for t in tables:
        for idx in t.indexes:
            if (idx.primary or idx.unique) and len(idx.columns) == 1:
                col = next((c for c in t.columns if c.name.lower() == idx.columns[0].lower()), None)
                if col is not None:
                    keyed.append((t, col.name, portable_type(t.engine, col.data_type)))
    declared_pairs = {
        (r.source.connection, r.source.schema, r.source.table, tuple(c.lower() for c in r.source_columns))
        for r in out
    }
    for t in tables:
        for col in t.columns:
            cname = col.name.lower()
            if cname in _GENERIC_KEY_NAMES:
                continue
            ctype = portable_type(t.engine, col.data_type)
            for kt, kcol, ktype in keyed:
                if kt.ref == t.ref:
                    continue
                if not cross_connection and kt.ref.connection != t.ref.connection:
                    continue
                if not compatible(ctype, ktype):
                    continue
                key = (t.ref.connection, t.ref.schema, t.ref.table, (cname,))
                if key in declared_pairs:
                    continue
                kname = kcol.lower()
                if cname == kname:
                    out.append(Relationship(
                        kind="inferred_name_type", confidence=0.8 if kt.ref.connection == t.ref.connection else 0.6,
                        source=t.ref, source_columns=[col.name], target=kt.ref, target_columns=[kcol],
                        evidence=f"same column name '{col.name}' as the key of {kt.ref.table}, compatible types",
                    ))
                elif kname == "id" and cname == f"{_singular(kt.ref.table.lower())}_id":
                    out.append(Relationship(
                        kind="inferred_name_pattern", confidence=0.6 if kt.ref.connection == t.ref.connection else 0.4,
                        source=t.ref, source_columns=[col.name], target=kt.ref, target_columns=[kcol],
                        evidence=f"'{col.name}' follows the <table>_id convention for {kt.ref.table}.id",
                    ))
    out.sort(key=lambda r: (-r.confidence, r.source.connection, r.source.table, r.source_columns))
    return out


def _singular(name: str) -> str:
    if name.endswith("ies"):
        return name[:-3] + "y"
    if name.endswith("ses"):
        return name[:-2]
    if name.endswith("s") and not name.endswith("ss"):
        return name[:-1]
    return name
