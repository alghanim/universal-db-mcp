"""Shared driver plumbing: lazy imports that name the missing artifact, and
value adaptation helpers common to remote connectors."""

from __future__ import annotations

import base64
import json
import math
from collections.abc import Iterator
from contextlib import contextmanager
from decimal import Decimal
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from pathlib import PurePath
from typing import Any
from uuid import UUID

from universal_db_mcp.connectors.base import ConnectorError, DriverUnavailableError
from universal_db_mcp.security.redact import scrub_exception


def open_module(module_name: str, artifact: str) -> Any:
    """Import an optional driver module or raise the standardized
    'missing local artifact' error. Never downloads."""
    try:
        import importlib

        return importlib.import_module(module_name)
    except ImportError as exc:
        raise DriverUnavailableError(module_name, artifact) from exc


@contextmanager
def translated_driver_errors() -> Iterator[None]:
    """Wrap a driver call so raw driver exceptions become ``ConnectorError``.

    Only PostgreSQL wrapped its driver errors; on every other engine a
    database-side permission denial, missing table or connect failure
    surfaced as ``INTERNAL`` instead of ``CONNECTION``. ``ConnectorError``
    (and its ``DriverUnavailableError`` subclass) pass through untouched —
    messages must already be sanitized.
    """
    try:
        yield
    except ConnectorError:
        raise
    except Exception as exc:  # noqa: BLE001 - deliberately broad: driver boundary
        raise ConnectorError(scrub_exception(exc)) from exc


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
    if isinstance(v, (dict, list, tuple)):
        # psycopg (json/jsonb, arrays), clickhouse-connect (Array/Tuple/Map):
        # the Python repr is NOT JSON (single quotes); emit real JSON so the
        # value round-trips for the consuming agent.
        try:
            data = json.dumps(v, default=str).encode("utf-8", errors="replace")
        except (TypeError, ValueError):
            data = str(v).encode("utf-8", errors="replace")
        label = "json" if isinstance(v, dict) else "array"
        if len(data) > max_cell_bytes:
            return data[:max_cell_bytes].decode("utf-8", errors="ignore"), label, True
        return data.decode("utf-8"), label, False
    if isinstance(v, (UUID, IPv4Address, IPv6Address, IPv4Network, IPv6Network, PurePath)):
        return str(v), "text", False
    if isinstance(v, Decimal):
        # Exact string form for fixed-precision values.
        return str(v), "decimal", False
    # Unknown driver-specific objects (e.g. LOB wrappers): string form with
    # the honest generic label — never a fabricated type.
    return str(v), "text", False
