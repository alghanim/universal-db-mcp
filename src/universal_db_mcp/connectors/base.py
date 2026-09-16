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
from universal_db_mcp.security.session import SessionProfile, resolve_session


class ConnectorError(Exception):
    """Database-layer error. Message must already be sanitized (no DSN,
    credentials, or raw connection dumps)."""


class ObjectNotFound(LookupError):
    """A requested schema/table/view does not exist or is not visible.

    A dedicated type so the server can distinguish it from the KeyError and
    IndexError that driver and catalog code raise on internal defects; both
    are LookupError subclasses.
    """


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
    primary: bool = False  # the table's primary key (ClickHouse: its sorting key)
    kind: str | None = None  # btree | hash | clustered | nonclustered | sorting_key | skipping:<type> | ...
    schema: str | None = None  # set on schema-wide listings
    table: str | None = None


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
    session: dict[str, Any] | None = None  # the applied session safety profile, read back


class DatabaseConnector(ABC):
    """One instance per configured connection. Implementations must be
    thread-safe for concurrent execute_query calls or serialize internally."""

    engine: str = "abstract"

    def __init__(self, connection: ResolvedConnection, policy: EffectivePolicy) -> None:
        self.connection = connection
        self.policy = policy
        # Session safety profile (isolation, lock/statement ceilings, app
        # name, server-side read-only). Applied by each connector right after
        # connecting; the outcome is recorded here and read back for
        # db_test_connection.
        self.session_profile: SessionProfile = resolve_session(connection, policy)
        self.session_status: dict[str, list[str]] = {"applied": [], "skipped": []}

    # ---- session profile bookkeeping --------------------------------------

    def _session_reset(self) -> None:
        self.session_status = {"applied": [], "skipped": []}

    def _session_applied(self, what: str) -> None:
        self.session_status["applied"].append(what)

    def _session_skipped(self, what: str, exc: BaseException) -> None:
        self.session_status["skipped"].append(f"{what}: {type(exc).__name__}: {str(exc)[:80]}")

    def _session_required(self, what: str, exc: BaseException) -> ConnectorError:
        """A setting that IS the production-safety promise did not take."""
        return ConnectorError(
            f"could not apply the session {what} on connection '{self.connection.name}' "
            f"({type(exc).__name__}: {str(exc)[:120]}); refusing to run at the server's default "
            "level. Adjust connections.<id>.session in the config if this server cannot support it"
        )

    def session_report(self, readback: dict[str, Any] | None = None) -> dict[str, Any]:
        """Profile + what was applied/skipped + optional values read back."""
        report = self.session_profile.as_dict()
        report["applied"] = list(self.session_status["applied"])
        report["skipped"] = list(self.session_status["skipped"])
        # enforced: the engine has a session switch and the SET was accepted.
        report["read_only_enforced"] = bool(
            self.session_profile.enforce_read_only
            and self.session_profile.server_read_only_available
            and any(a.startswith("read_only") for a in self.session_status["applied"])
        )
        # verified: the SERVER read back a read-only value (True/False), or
        # None when it offers nothing to read back (e.g. MariaDB <= 10.6).
        verified: bool | None = None
        if readback and "read_only" in readback:
            verified = str(readback["read_only"]).strip().lower() in ("on", "1", "true", "yes")
        elif readback and "readonly" in readback:
            verified = str(readback["readonly"]).strip() == "1"
        elif readback and "query_only" in readback:
            verified = str(readback["query_only"]).strip() in ("1", "on")
        report["read_only_verified"] = verified
        if readback:
            report["server_reports"] = readback
        return report

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
        richer detail override this. Unknown objects raise ObjectNotFound."""
        cols = self.list_columns(schema, name)
        if not cols:
            raise ObjectNotFound(f"table '{schema}.{name}' not found or not visible")
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

    # ---- discovery surface (indexes, bulk columns, profiling helpers) ------

    def list_indexes(self, schema: str | None, table: str | None) -> list[IndexInfo]:
        """Indexes (and primary keys) of one table, or of a whole schema when
        ``table`` is None. Engines override; the default reports nothing
        rather than guessing."""
        return []

    def list_all_columns(self, schema: str | None) -> list[ColumnInfo]:
        """Every column of every table in ``schema`` - ONE catalog query on
        engines that override this; the default composes per-table calls."""
        out: list[ColumnInfo] = []
        for t in self.list_tables(schema, {"table", "view"}, None):
            out.extend(self.list_columns(t.schema, t.name))
        return out

    def length_function(self) -> str:
        """SQL function returning a string's character length."""
        return "LENGTH"

    def text_expression(self, quoted_column: str, portable_name: str) -> str:
        """``quoted_column`` as something LOWER()/LIKE accept. Plain strings
        pass through; engines whose UUID or enum types reject string
        functions override this with a cast."""
        return quoted_column

    def placeholder(self, index: int) -> str:
        """Driver-native positional placeholder for tool-generated SQL
        (1-based ``index``). Agent SQL is never rewritten; this is only for
        statements this server builds itself."""
        return "?"

    def pack_parameters(self, values: list[Any]) -> Any:
        """Shape the values for ``execute_query`` to match ``placeholder``."""
        return list(values)

    def build_search_query(
        self, schema: str | None, table: str, select_columns: list[str], where_sql: str, limit: int
    ) -> str:
        """Bounded ``SELECT cols FROM table WHERE <where_sql>``."""
        cols = ", ".join(self.quote_identifier(c) for c in select_columns) if select_columns else "*"
        qualified = (
            f"{self.quote_identifier(schema)}.{self.quote_identifier(table)}"
            if schema
            else self.quote_identifier(table)
        )
        return f"SELECT {cols} FROM {qualified} WHERE {where_sql} LIMIT {int(limit)}"

    def build_top_values_query(self, sample_sql: str, column: str, limit: int) -> str:
        """Most frequent values of ``column`` over a bounded sample subquery."""
        q = self.quote_identifier(column)
        return (
            f"SELECT {q} AS v, COUNT(*) AS cnt FROM ({sample_sql}) s "
            f"WHERE {q} IS NOT NULL GROUP BY {q} ORDER BY cnt DESC LIMIT {int(limit)}"
        )

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
