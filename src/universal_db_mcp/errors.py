"""Stable, structured tool failures.

Every controlled failure raises :class:`ToolFailure` with one of the stable
categories from ``models.responses.ErrorCategory``. The MCP layer converts
these into protocol tool errors whose message begins with ``<CATEGORY>:`` so
clients and tests can match on them. Messages are redacted and never contain
credentials, DSNs, or raw SQL text of denied statements.
"""

from __future__ import annotations

from universal_db_mcp.models.responses import ErrorCategory
from universal_db_mcp.security.redact import redact_text


class ToolFailure(Exception):
    def __init__(self, category: str, message: str) -> None:
        self.category = category
        super().__init__(f"{category}: {redact_text(message)}")


class ConfigError(ToolFailure):
    def __init__(self, message: str) -> None:
        super().__init__(ErrorCategory.CONFIG, message)
