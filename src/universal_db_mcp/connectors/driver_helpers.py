"""Shared driver plumbing: lazy imports that name the missing artifact, and
value adaptation helpers common to remote connectors."""

from __future__ import annotations

import base64
import math
from typing import Any

from universal_db_mcp.connectors.base import DriverUnavailableError


def open_module(module_name: str, artifact: str) -> Any:
    """Import an optional driver module or raise the standardized
    'missing local artifact' error. Never downloads."""
    try:
        import importlib

        return importlib.import_module(module_name)
    except ImportError as exc:
        raise DriverUnavailableError(module_name, artifact) from exc


def cell_truncated_json(raw: Any, max_cell_bytes: int) -> tuple[list[Any], list[str], bool]:
    """Adapt one driver row to JSON-safe values with per-cell truncation.

    Decimal -> string (exact), big ints -> string, datetime/date/time -> ISO
    strings, bytes -> base64 dict, None -> None."""
    vals: list[Any] = []
    labels: list[str] = []
    truncated = False
    for v in raw:
        adapted, label, tr = _adapt_one(v, max_cell_bytes)
        vals.append(adapted)
        labels.append(label)
        truncated = truncated or tr
    return vals, labels, truncated


def _adapt_one(v: Any, max_cell_bytes: int) -> tuple[Any, str, bool]:
    if v is None:
        return None, "null", False
    if isinstance(v, bool):
        return v, "boolean", False
    if isinstance(v, int):
        if abs(v) < 2**53:
            return v, "integer", False
        return str(v), "bigint", False
    if isinstance(v, float):
        if not math.isfinite(v):
            # inf/NaN are invalid JSON (RFC 8259); exact sentinel strings.
            return ("$nan" if math.isnan(v) else ("$inf" if v > 0 else "-$inf")), "real", False
        return v, "real", False
    if isinstance(v, str):
        data = v.encode("utf-8", errors="replace")
        if len(data) > max_cell_bytes:
            return data[:max_cell_bytes].decode("utf-8", errors="ignore"), "text", True
        return v, "text", False
    if isinstance(v, (bytes, bytearray, memoryview)):
        raw = bytes(v)
        if len(raw) > max_cell_bytes:
            return {"$binary_b64": base64.b64encode(raw[:max_cell_bytes]).decode(), "$truncated": True}, "blob", True
        return {"$binary_b64": base64.b64encode(raw).decode()}, "blob", False
    if isinstance(v, (int,)) is False and hasattr(v, "isoformat"):
        # datetime.datetime / date / time
        return v.isoformat(), "datetime" if hasattr(v, "year") and hasattr(v, "hour") else "date", False
    # Decimal and other fixed-precision types: exact string form
    return str(v), "decimal", False
