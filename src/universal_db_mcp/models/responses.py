"""Structured tool-output envelope.

Every tool returns an :class:`Envelope`. Tool failures raise
:class:`universal_db_mcp.errors.ToolFailure`, which the MCP layer converts
into a protocol-level tool error carrying a stable category prefix.

Value representation rules (documented in docs/tools.md):

- integers with abs(value) < 2**53 are JSON numbers; larger are emitted as
  strings tagged by the column type (``bigint``) so no precision is lost.
- ``decimal`` values are always strings (exact representation preserved).
- timestamps are ISO 8601 strings with UTC offset when known.
- binary/LOB data is ``{"$binary": "<base64>"}`` truncated per
  ``max_cell_bytes`` policy.
- null is ``null``.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ColumnMeta(BaseModel):
    name: str
    type: str  # engine-reported or adapted type label


class QueryData(BaseModel):
    columns: list[ColumnMeta] = Field(default_factory=list)
    rows: list[list[Any]] = Field(default_factory=list)


class Envelope(BaseModel):
    """Common response shape. Fields that do not apply to a tool are omitted
    (not emitted as null)."""

    request_id: str
    connection_id: str | None = None
    engine: str | None = None
    data: Any = None
    warnings: list[str] = Field(default_factory=list)
    elapsed_ms: int | None = None
    returned_row_count: int | None = None
    truncated: bool | None = None
    next_cursor: str | None = None


# Stable error categories (prefix in tool-error messages; see docs/tools.md).
class ErrorCategory:
    CONFIG = "CONFIG_ERROR"
    POLICY = "POLICY_VIOLATION"
    VALIDATION = "VALIDATION_ERROR"
    CONNECTION = "CONNECTION_ERROR"
    QUERY = "QUERY_ERROR"  # the statement ran and the engine rejected it (data or SQL error)
    AUTHZ = "AUTHORIZATION_DENIED"
    TIMEOUT = "TIMEOUT"
    LIMIT = "LIMIT_EXCEEDED"
    CAPABILITY = "CAPABILITY_UNSUPPORTED"
    DRIVER_MISSING = "DRIVER_MISSING"
    INTERNAL = "INTERNAL_ERROR"
