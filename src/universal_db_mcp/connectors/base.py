"""Connector abstraction.

Connectors own all database-specific behavior. MCP handlers never touch a
driver directly. Synchronous drivers are always driven through the bounded
executor (worker threads + deadlines), never on the MCP event loop.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from universal_db_mcp.config import ResolvedConnection
from universal_db_mcp.models.capabilities import CapabilityMatrix
from universal_db_mcp.security.policy import EffectivePolicy


class ConnectorError(Exception):
    """Database-layer error. Message must already be sanitized (no DSN,
    credentials, or raw connection dumps)."""


class DriverUnavailableError(ConnectorError):
    """The optional driver module/wheel for this engine is not installed.
    The message names the missing local artifact; callers map this to
    DRIVER_MISSING."""

    def __init__(self, engine: str, artifact: str) -> None:
        self.engine = engine
        self.artifact = artifact
        super().__init__(
            f"'{engine}' connector requires the pinned driver wheel "
            f"'{artifact}', which is not installed in this environment; "
            f"install it from the offline bundle wheelhouse (no network)"
        )


@dataclass
class TableSummary:
    schema: str | None
    name: str
    kind: str  # table | view | materialized_view | foreign_table | alias
    row_estimate: int | None = None
    row_estimate_source: str | None = None  # 'catalog_estimate' | 'exact' | ...
    comment: str | None = None


@dataclass
class ColumnInfo:
    schema: str | None
    table: str
    name: str
    data_type: str
    nullable: bool | None = None
    default: str | None = None
    comment: str | None = None
    ordinal: int | None = None


@dataclass
class KeyInfo:
    kind: str  # primary_key | foreign_key | unique | check
    name: str | None
    columns: list[str]
    ref_schema: str | None = None
    ref_table: str | None = None
    ref_columns: list[str] = field(default_factory=list)
    source_schema: str | None = None  # schema of the table carrying the key
    source_table: str | None = None  # table carrying the key (FK listings)


@dataclass
class IndexInfo:
    name: str | None
    columns: list[str]
    unique: bool = False
    definition: str | None = None


@dataclass
class ViewInfo:
    schema: str | None
    name: str
    kind: str  # view | materialized_view
    definition: str | None = None
    definition_state: str = "not_requested"  # available | unavailable | permission_denied | not_supported


@dataclass
class SynonymInfo:
    schema: str | None
    name: str
    target_schema: str | None
    target_name: str
    target_kind: str | None = None  # table | view | synonym | remote


@dataclass
class RoutineInfo:
    schema: str | None
    name: str
    kind: str  # function | procedure
    argument_types: list[str] = field(default_factory=list)
    return_type: str | None = None


@dataclass
class QuerySpec:
    sql: str
    parameters: Sequence[Any] | dict[str, Any] | None = None
    max_rows: int = 1000
    max_response_bytes: int = 1_048_576
    max_cell_bytes: int = 8192
    timeout_seconds: float = 30.0


@dataclass
class QueryOutcome:
    columns: list[tuple[str, str]]  # (name, adapted type label)
    rows: list[list[Any]]
    truncated: bool
    rows_seen: int  # rows fetched before truncation decision
    elapsed_ms: int
    warnings: list[str] = field(default_factory=list)


@dataclass
class HealthInfo:
    healthy: bool
    server_version: str | None = None
    latency_ms: int | None = None
    detail: str | None = None
    checked_at: float = field(default_factory=time.time)


class DatabaseConnector(ABC):
    """One instance per configured connection. Implementations must be
    thread-safe for concurrent execute_query calls or serialize internally."""

    engine: str = "abstract"

    def __init__(self, connection: ResolvedConnection, policy: EffectivePolicy) -> None:
        self.connection = connection
        self.policy = policy

    @abstractmethod
    def capabilities(self) -> CapabilityMatrix: ...

    @abstractmethod
    def health_check(self) -> HealthInfo: ...

    @abstractmethod
    def list_schemas(self, catalog: str | None, search: str | None) -> list[str]: ...

    @abstractmethod
    def list_tables(self, schema: str | None, kinds: set[str], search: str | None) -> list[TableSummary]: ...

    def get_table(self, schema: str | None, name: str) -> dict[str, Any]:
        """Default composition from primitive metadata calls; engines with
        richer detail override this. Unknown objects raise LookupError."""
        cols = self.list_columns(schema, name)
        if not cols:
            raise LookupError(f"table '{schema}.{name}' not found or not visible")
        return {
            "schema": schema,
            "name": name,
            "columns": [c.__dict__ for c in cols],
            "foreign_keys": [fk.__dict__ for fk in self.get_foreign_keys(schema, name)],
            "statistics": self.get_statistics(schema, name),
            "note": "composed from catalog metadata; no table data was read",
        }

    @abstractmethod
    def list_columns(self, schema: str | None, table: str) -> list[ColumnInfo]: ...

    @abstractmethod
    def list_views(self, schema: str | None) -> list[ViewInfo]: ...

    @abstractmethod
    def list_synonyms(self, schema: str | None) -> list[SynonymInfo]: ...

    @abstractmethod
    def list_routines(self, schema: str | None) -> list[RoutineInfo]: ...

    @abstractmethod
    def get_foreign_keys(self, schema: str | None, table: str | None) -> list[KeyInfo]: ...

    @abstractmethod
    def get_statistics(self, schema: str | None, table: str) -> dict[str, Any]: ...

    @abstractmethod
    def execute_query(self, spec: QuerySpec) -> QueryOutcome: ...

    @abstractmethod
    def explain(self, sql: str, analyze: bool) -> dict[str, Any]: ...

    def list_catalogs(self) -> list[str] | None:
        """Engines without catalogs return None (tool reports 'not applicable')."""
        return None

    def quote_identifier(self, name: str) -> str:
        return '"' + name.replace('"', '""') + '"'

    def build_sample_query(self, schema: str | None, table: str, columns: list[str] | None, limit: int) -> str:
        """Engine-correct bounded sample query. Identifiers must be validated
        and quoted here; ``limit`` is a server-clamped integer, never user
        text. Engines with non-LIMIT syntax override this."""
        cols = ", ".join(self.quote_identifier(c) for c in columns) if columns else "*"
        qualified = (
            f"{self.quote_identifier(schema)}.{self.quote_identifier(table)}"
            if schema
            else self.quote_identifier(table)
        )
        return f"SELECT {cols} FROM {qualified} LIMIT {int(limit)}"
