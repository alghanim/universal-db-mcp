"""Connector abstraction.

Connectors own all database-specific behavior. MCP handlers never touch a
driver directly. Synchronous drivers are always driven through the bounded
executor (worker threads + deadlines), never on the MCP event loop.
"""

from __future__ import annotations

import math
import threading
import time
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, NamedTuple

from universal_db_mcp.config import ResolvedConnection
from universal_db_mcp.models.capabilities import CapabilityMatrix
from universal_db_mcp.security.policy import EffectivePolicy
from universal_db_mcp.security.session import SessionProfile, resolve_session


class ConnectorError(Exception):
    """Database-layer error. Message must already be sanitized (no DSN,
    credentials, or raw connection dumps).

    ``category`` names the ErrorCategory value to report when it is not a
    connection failure. It is only set when given: the server reads it with
    getattr and a CONNECTION_ERROR default.
    """

    def __init__(self, *args: object, category: str | None = None) -> None:
        super().__init__(*args)
        if category is not None:
            self.category = category


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


# explain(sql, analyze=True) on every engine: no setting enables it
# (security.allow_explain_analyze only picks how the server refuses it).
EXPLAIN_ANALYZE_UNSUPPORTED = "db_explain never executes the statement; EXPLAIN ANALYZE is not supported"


def own_objects_first(
    tables: list[TableSummary], system_schemas: Iterable[str] | Callable[[str | None], bool]
) -> list[TableSummary]:
    """``tables`` with those in the engine's ``system_schemas`` (catalog
    views an administrator opened; security.allowed_system_schemas lists
    information_schema by default) after the database's own, each part in
    the order the catalog gave it: a listing's first page shows user data,
    not the views MySQL and ClickHouse sort first. ``system_schemas`` names
    them, or tells one where no list can (Oracle's APEX_nnnnnn owners)."""
    if callable(system_schemas):
        is_system = system_schemas
        return sorted(tables, key=lambda t: is_system(t.schema))
    system = {s.lower() for s in system_schemas}
    return sorted(tables, key=lambda t: (t.schema or "").lower() in system)



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


class SynonymTarget(NamedTuple):
    """What a synonym (Db2: an alias) names: a schema (None where the
    catalog keeps none) and a name, and where they are not this database's,
    the database link (Oracle) or the other database, server first where one
    is named (SQL Server), that reads them."""

    schema: str | None
    name: str
    elsewhere: str | None = None


@dataclass(frozen=True, slots=True)
class NameBinding:
    """How this connection's sessions look up a table name a statement
    writes: the schemas a bare name is looked up in, first to last, and
    whether names compare ignoring case (on SQL Server the database
    collation decides; the other engines' rules are fixed)."""

    bare_schemas: tuple[str, ...]
    ignores_case: bool = False


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
        # Per-thread: a metadata connect on one thread must not interleave
        # its applied/skipped lists with a health check on another.
        self._session_tls = threading.local()
        # Per-thread too: the timeout of the one query a connect on this
        # thread opens its connection for (see _query_connect).
        self._query_tls = threading.local()

    # ---- session profile bookkeeping --------------------------------------

    @property
    def session_status(self) -> dict[str, list[str]]:
        status = getattr(self._session_tls, "status", None)
        if status is None:
            status = {"applied": [], "skipped": []}
            self._session_tls.status = status
        return status

    def _session_reset(self) -> None:
        self._session_tls.status = {"applied": [], "skipped": []}

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

    def _reading_required(self, what: str, exc: BaseException) -> ConnectorError:
        """A setting that decides how the server reads statement text could
        not be held at the value the SQL guard parses under. The guard's
        reading of a statement (its tables, columns and string literals)
        would then not be the server's."""
        return ConnectorError(
            f"could not set {what} for the session on connection '{self.connection.name}' "
            f"({type(exc).__name__}: {str(exc)[:160]}); the server would read statements differently from "
            "the SQL guard that checked them, so the connection is refused"
        )

    @contextmanager
    def _query_connect(self, timeout_seconds: float) -> Iterator[None]:
        """Mark a connect on this thread as opening the connection of one
        query, so ``_statement_ceiling`` follows that query's timeout."""
        self._query_tls.timeout = timeout_seconds
        try:
            yield
        finally:
            self._query_tls.timeout = None

    def _statement_ceiling(self) -> int | None:
        """Whole seconds for a driver-side statement ceiling: the policy's hard
        timeout, or the shorter timeout of the query being connected for
        (``_query_connect``), so the server stops the statement when the
        caller's deadline does. None when the session profile applies no
        server-side ceiling."""
        hard = self.session_profile.statement_timeout_seconds
        if not hard:
            return None
        query_timeout = getattr(self._query_tls, "timeout", None)
        return int(math.ceil(min(hard, query_timeout) if query_timeout else hard))

    def _opened_schemas(self) -> frozenset[str]:
        """Schemas the administrator opened, case-folded: the server's
        security.allowed_system_schemas and this connection's allowed_schemas.
        A catalog listing that leaves the engine's system schemas out keeps
        these, because the resolver permits only objects list_tables returns;
        leaving them out made the allowance inert."""
        return self.policy.allowed_system_schemas | self.policy.allowed_schemas

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
            verified = str(readback["readonly"]).strip() in ("1", "2")  # 2 = server profile, stricter
        elif readback and "query_only" in readback:
            verified = str(readback["query_only"]).strip() in ("1", "on")
        report["read_only_verified"] = verified
        if readback:
            report["server_reports"] = readback
        return report

    def close(self) -> None:  # noqa: B027 - a no-op default, not an abstract method
        """Release the sessions this connector keeps between calls (a pooled
        metadata connection or client). The server calls it once a discarded
        connector's worker has returned. Safe to call more than once; a
        later metadata call reconnects. The default keeps none."""

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

    def synonym_chains(
        self, names: Sequence[tuple[str | None, str]]
    ) -> dict[tuple[str | None, str], list[SynonymTarget]]:
        """Of ``names`` (schema, None for a bare name, and name, as the
        engine looks them up: a quoted name as written, an unquoted one
        folded), each that names a synonym (Db2: an alias), matched as the
        engine matches names (TRAVEL."Bookings" is not TRAVEL.BOOKINGS on
        Oracle), with the objects it names in turn to the end of its chain,
        as the catalog spells them, and the database link or other database
        of one that is not this database's (driver_helpers.synonym_chains).
        An engine without synonyms has none."""
        return {}

    def name_binding(self) -> NameBinding | None:
        """How a session of this connection binds the names a statement
        writes, asked of the database: where default-deny resolves a bare
        name to a listed table, the engine reads that table only if its
        schema is the first one the session looks bare names up in (the
        server checks). None on an engine that binds a bare name only within
        the connection's own database, whose tables and views the listing
        holds (MySQL, ClickHouse, SQLite)."""
        return None

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

    def length_expression(self, quoted_column: str) -> str:
        """Character (not byte) length of a string column."""
        return f"LENGTH({quoted_column})"

    def substring_expression(self, quoted_column: str, chars: int) -> str:
        """The first ``chars`` characters of a string column."""
        return f"SUBSTR({quoted_column}, 1, {int(chars)})"

    LIKE_ESCAPE = "!"  # a backslash literal is spelled differently on MySQL and old PostgreSQL

    def escape_like(self, needle: str) -> str:
        """Make %, _ and the escape character literal in a LIKE value."""
        e = self.LIKE_ESCAPE
        return needle.replace(e, e + e).replace("%", e + "%").replace("_", e + "_")

    def like_predicate(self, expression: str, placeholder: str) -> str:
        return f"{expression} LIKE {placeholder} ESCAPE '{self.LIKE_ESCAPE}'"

    def text_expression(self, quoted_column: str, portable_name: str, declared_type: str | None = None) -> str:
        """``quoted_column`` as something LOWER()/LIKE accept. Plain strings
        pass through; engines whose UUID or enum types reject string
        functions override this with a cast. ``declared_type`` is the
        column's catalog type when the caller has it (Db2 casts character and
        graphic columns differently)."""
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
