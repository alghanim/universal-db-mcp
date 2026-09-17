"""Render a data dictionary (Markdown) from catalog entries.

Input is the list of table entries ``_catalog_tables`` produces for
``db_get_catalog``: metadata only, foreign-key targets outside the allowlist
already redacted, the ``sensitive`` flag already computed. Nothing here
reads table data, and no column VALUE ever appears in the output.
"""
from __future__ import annotations

from typing import Any


def _cell(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).replace("\r", " ").replace("\n", " ").strip()
    return text.replace("|", "\\|")


def _qualified(schema: str | None, name: str) -> str:
    return f"{schema}.{name}" if schema else name


def _rows_text(table: dict[str, Any]) -> str:
    est = table.get("row_estimate")
    if est is None:
        return "row count unknown"
    src = table.get("row_estimate_source") or ""
    approx = "" if src == "exact" else "~"
    return f"{approx}{est:,} rows" + (f" ({src})" if src and src != "exact" else "")


def _key_cell(col: dict[str, Any], fk_by_column: dict[str, list[str]]) -> str:
    parts: list[str] = []
    if col.get("in_primary_key"):
        parts.append("PK")
    for target in fk_by_column.get(col["name"], []):
        parts.append(f"FK -> {target}")
    return ", ".join(parts)


def render_table(table: dict[str, Any]) -> str:
    """One table section: heading, comment, column table, keys, indexes."""
    lines: list[str] = []
    kind = table.get("kind") or "table"
    lines.append(f"## {_qualified(table.get('schema'), table['name'])}")
    lines.append("")
    lines.append(f"*{kind}, {_rows_text(table)}*")
    if table.get("comment"):
        lines.append("")
        lines.append(_cell(table["comment"]))
    fk_by_column: dict[str, list[str]] = {}
    for fk in table.get("foreign_keys") or []:
        target = _qualified(fk.get("ref_schema"), fk.get("ref_table") or "?")
        ref_cols = fk.get("ref_columns") or []
        for i, c in enumerate(fk.get("columns") or []):
            tgt = f"{target}({ref_cols[i]})" if i < len(ref_cols) else target
            fk_by_column.setdefault(c, []).append(tgt)
    lines.append("")
    lines.append("| Column | Declared type | Portable | Nullable | Default | Key | Notes |")
    lines.append("|---|---|---|---|---|---|---|")
    for col in table.get("columns") or []:
        notes: list[str] = []
        if col.get("sensitive"):
            notes.append("sensitive (masked)")
        if col.get("comment"):
            notes.append(_cell(col["comment"]))
        nullable = col.get("nullable")
        lines.append(
            "| "
            + " | ".join(
                [
                    _cell(col["name"]),
                    _cell(col.get("data_type")),
                    f"{_cell(col.get('portable_type'))}/{_cell(col.get('kind'))}",
                    "" if nullable is None else ("yes" if nullable else "no"),
                    _cell(col.get("default")),
                    _key_cell(col, fk_by_column),
                    "; ".join(notes),
                ]
            )
            + " |"
        )
    pk = table.get("primary_key")
    lines.append("")
    lines.append(f"Primary key: {', '.join(pk) if pk else 'none'}")
    fks = table.get("foreign_keys") or []
    if fks:
        lines.append("")
        lines.append("Foreign keys:")
        for fk in fks:
            lines.append(
                f"- {_cell(fk.get('name') or '(unnamed)')}: ({', '.join(fk.get('columns') or [])}) -> "
                f"{_qualified(fk.get('ref_schema'), fk.get('ref_table') or '?')}"
                f"({', '.join(fk.get('ref_columns') or [])})"
            )
    idx = [i for i in (table.get("indexes") or []) if not i.get("primary")]
    if idx:
        lines.append("")
        lines.append("Indexes:")
        for i in idx:
            flags = [f for f in ("unique" if i.get("unique") else "", i.get("kind") or "") if f]
            lines.append(
                f"- {_cell(i.get('name'))} ({', '.join(i.get('columns') or [])})"
                + (f" [{', '.join(flags)}]" if flags else "")
            )
    return "\n".join(lines)


def render_data_dictionary(
    connection_id: str, engine: str, tables: list[dict[str, Any]], *, schema: str | None = None
) -> str:
    """The Markdown data dictionary for one page of catalog entries."""
    scope = f"schema `{schema}`" if schema else "all permitted schemas"
    head = [
        f"# Data dictionary: {connection_id} ({engine}), {scope}",
        "",
        "Generated from catalog metadata only; no table data was read. "
        "Row counts are the engine's estimates unless marked exact. "
        "\"sensitive\" is a column-name heuristic (security.mask_columns), not a data classification.",
        "",
        f"Tables on this page: {len(tables)}",
        "",
    ]
    sections = [render_table(t) for t in tables]
    rels: list[str] = []
    for t in tables:
        for fk in t.get("foreign_keys") or []:
            rels.append(
                f"- {_qualified(t.get('schema'), t['name'])}({', '.join(fk.get('columns') or [])}) -> "
                f"{_qualified(fk.get('ref_schema'), fk.get('ref_table') or '?')}"
                f"({', '.join(fk.get('ref_columns') or [])})"
            )
    tail = ["", "## Declared relationships on this page", ""] + (rels or ["- none"])
    return "\n".join(head) + "\n\n".join(sections) + "\n" + "\n".join(tail) + "\n"
