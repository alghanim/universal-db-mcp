"""Capability model: truthful states, never optimistic booleans."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class CapabilityState(StrEnum):
    SUPPORTED = "supported"
    UNSUPPORTED = "unsupported"
    PERMISSION_DENIED = "permission_denied"
    UNVERIFIED = "unverified"  # implemented against the documented API but not
    # proven against a real instance of the target engine.
    NOT_IMPLEMENTED = "not_implemented"


class Limitation(BaseModel):
    """A documented restriction that applies to a capability or connection."""

    scope: str  # e.g. "explain", "cancel", "metadata"
    detail: str
    state: CapabilityState = CapabilityState.UNSUPPORTED


class CapabilityMatrix(BaseModel):
    """What this connector *implementation* supports, independent of what a
    given connection permits. Connection-level permission differences are
    reported per-call as ``permission_denied`` or via warnings."""

    engine: str
    engine_family: str | None = None
    driver: str
    capabilities: dict[str, CapabilityState] = Field(default_factory=dict)
    limitations: list[Limitation] = Field(default_factory=list)
    required_privileges: list[str] = Field(default_factory=list)
    unverified_items: list[str] = Field(default_factory=list)

    def get(self, name: str) -> CapabilityState:
        return self.capabilities.get(name, CapabilityState.NOT_IMPLEMENTED)

    def to_public(self) -> dict[str, Any]:
        return {
            "engine": self.engine,
            "engine_family": self.engine_family,
            "driver": self.driver,
            "capabilities": {k: v.value for k, v in self.capabilities.items()},
            "limitations": [lim.model_dump() for lim in self.limitations],
            "required_privileges": self.required_privileges,
            "unverified_items": self.unverified_items,
        }


# Capability names used across connectors (single vocabulary).
class Cap:
    CONNECT = "connect"
    HEALTH = "health"
    LIST_CATALOGS = "list_catalogs"
    LIST_SCHEMAS = "list_schemas"
    LIST_TABLES = "list_tables"
    GET_TABLE = "get_table"
    LIST_COLUMNS = "list_columns"
    LIST_VIEWS = "list_views"
    LIST_SYNONYMS = "list_synonyms"
    LIST_ROUTINES = "list_routines"
    SEARCH_METADATA = "search_metadata"
    RELATIONSHIPS = "relationships"
    INFERRED_RELATIONSHIPS = "inferred_relationships"
    STATISTICS = "statistics"
    QUERY = "query"
    PARAMETERS = "parameters"
    CANCEL = "cancel"
    SERVER_SIDE_CANCEL = "server_side_cancel"
    EXPLAIN = "explain"
    EXPLAIN_ANALYZE = "explain_analyze"
    SAMPLE = "sample"
    TLS = "tls"
