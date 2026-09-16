"""MCP server wiring: the full tool surface + shared services.

Handlers stay thin. All database work runs through the bounded executor
(worker threads + deadlines); policy lives in EffectivePolicy; dialect-aware
SQL validation lives in SqlGuard; audit/redaction wrap every call.

Stdout is protocol-only (stdio transport); application logs go to stderr.
"""

from __future__ import annotations

import dataclasses
import functools
import getpass
import json
import math
import os
import sqlite3
import sys
import time
from collections import deque
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Any, Literal

import anyio
from mcp.server.mcpserver import MCPServer

# mcp 2.x: ToolError is the documented way to surface a deliberate failure
# message to the client; any other exception is masked as UnexpectedToolError
# with a generic message (verified against the pinned SDK source).
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import CallToolResult, TextContent, ToolAnnotations
from sqlglot import exp

from universal_db_mcp.config import AppConfig, ResolvedConnection
from universal_db_mcp.connectors import registry
from universal_db_mcp.connectors.base import (
    ConnectorError,
    DatabaseConnector,
    DriverUnavailableError,
    KeyInfo,
    ObjectNotFound,
    QuerySpec,
)
from universal_db_mcp.discovery.inference import TableFacts, TableRef, infer_relationships
from universal_db_mcp.discovery.profile import (
    TOP_VALUES,
    aggregate_select_list,
    build_profiles,
    findings_for_table,
    wants_top_values,
)
from universal_db_mcp.discovery.system_schemas import is_system_object
from universal_db_mcp.discovery.types import portable_type
from universal_db_mcp.errors import ToolFailure
from universal_db_mcp.models.capabilities import Cap, CapabilityState
from universal_db_mcp.models.responses import Envelope, ErrorCategory
from universal_db_mcp.security.cursors import CursorCodec, policy_fingerprint
from universal_db_mcp.security.policy import EffectivePolicy
from universal_db_mcp.security.redact import (
    new_request_id,
    redact_text,
    redact_value,
    scrub_exception,
    sql_fingerprint,
)
from universal_db_mcp.security.sql_guard import SqlGuard, StaticResolver, sqlglot_dialect
from universal_db_mcp.services.audit import AuditLog, AuditWriteFailure
from universal_db_mcp.services.executor import ExecutionService
from universal_db_mcp.services.metadata import MetadataCache, rank_search

_PAGE_SIZE = 50
_SEARCH_CAP = 25

_DISCOVERY_MAX_SCHEMAS = 20
_PROFILE_MAX_COLUMNS = 60
_PROFILE_DEFAULT_SAMPLE = 10_000
_PROFILE_MAX_TOP_COLUMNS = 20
_SEARCH_MAX_SELECT = 8
_DISCOVERY_INFER_MAX_TABLES = 500
_HISTORY_CAP = 200
_INFER_MAX_TABLES = 50  # bounds metadata traversal for inference
_META_TIMEOUT = 15.0


def _process_identity() -> str:
    """Audit identity of this process. ``getpass.getuser()`` RAISES (KeyError
    on 3.12, OSError on 3.13+, ImportError without ``pwd``) when the UID has no
    passwd entry - the normal state inside a container running as an unmapped
    UID - and the CLI reported that as CONFIG_ERROR, blaming the config file.
    The numeric UID is a truthful identity for the audit trail in that case."""
    try:
        user = getpass.getuser()
    except (KeyError, OSError, ImportError):
        user = ""
    if user:
        return user
    getuid = getattr(os, "getuid", None)  # absent on Windows
    return f"uid:{getuid()}" if getuid is not None else "unknown"


class AppContext:
    """Process-wide services shared by all tools."""

    def __init__(self, cfg: AppConfig, resolved: dict[str, ResolvedConnection]) -> None:
        self.cfg = cfg
        self.resolved = resolved
        self.connectors: dict[str, DatabaseConnector] = {}
        self.policies: dict[str, EffectivePolicy] = {}
        self.executor = ExecutionService(cfg.security.max_concurrent_queries)
        # Connector object ids that were in use when a request was cancelled
        # (client disconnect): their driver state is uncertain, so they are
        # discarded exactly like executor-poisoned connections.
        self.poisoned_connectors: set[int] = set()
        self.audit = AuditLog(
            path=cfg.application.audit_path,
            max_bytes=cfg.application.audit_max_bytes,
            max_backups=cfg.application.audit_max_backups,
            fail_closed=cfg.application.audit_fail_closed,
        )
        self.cache = MetadataCache(path=cfg.application.metadata_cache_path, ttl_seconds=300.0)
        self.cursors = CursorCodec()
        self.identity = _process_identity()
        self.history: deque[dict[str, Any]] = deque(maxlen=_HISTORY_CAP)

    def connection(self, connection_id: str) -> tuple[DatabaseConnector, EffectivePolicy]:
        if connection_id not in self.resolved:
            raise ToolFailure(
                ErrorCategory.AUTHZ if self.resolved else ErrorCategory.CONFIG,
                f"connection '{connection_id}' is not available to this caller",
            )
        policy = self._policy_for(connection_id)
        if policy.require_tls and not self.resolved[connection_id].config.tls.enabled:
            raise ToolFailure(
                ErrorCategory.CONFIG,
                f"connection '{connection_id}' requires TLS "
                f"(security.require_remote_tls=true) but tls.enabled=false; "
                f"plaintext connections to remote databases are refused",
            )
        existing = self.connectors.get(connection_id)
        if existing is not None and (
            self.executor.is_poisoned(existing) or id(existing) in self.poisoned_connectors
        ):
            # A discarded connection recovers by building a fresh instance;
            # the executor's poison set is keyed by object identity.
            del self.connectors[connection_id]
        if connection_id not in self.connectors:
            try:
                self.connectors[connection_id] = registry.build_connector(self.resolved[connection_id], policy)
            except DriverUnavailableError:
                raise
            except Exception as exc:
                raise ToolFailure(ErrorCategory.CONNECTION, scrub_exception(exc)) from exc
        return self.connectors[connection_id], policy

    def _policy_for(self, connection_id: str) -> EffectivePolicy:
        if connection_id not in self.policies:
            self.policies[connection_id] = EffectivePolicy.build(self.cfg.security, self.resolved[connection_id])
        return self.policies[connection_id]

    def guard(self, policy: EffectivePolicy, objects: set[tuple[str | None, str]] | None = None) -> SqlGuard:
        if objects is not None:
            return SqlGuard(policy.engine, policy, StaticResolver(objects))
        raise ValueError("internal: guards require a prefetched object set")

    async def tables_for(self, policy: EffectivePolicy, connector: DatabaseConnector) -> list[Any]:
        """Permitted table/view summaries, cached and policy-scoped.

        Cache I/O runs off the event loop (a busy/locked SQLite cache file
        must not freeze every session), and any cache failure is a miss,
        never a failed tool call."""
        fp = policy_fingerprint(policy)
        try:
            cached = await anyio.to_thread.run_sync(self.cache.get_tables, policy.connection_id, fp)
        except sqlite3.Error as exc:
            print(
                f"universal-db-mcp: metadata cache read failed (treated as a miss): {exc}",
                file=sys.stderr,
            )
            cached = None
        if cached is not None:
            return list(cached)
        kinds = {"table", "view", "materialized_view"}
        tables = await run_meta(self, policy.connection_id, lambda c: c.list_tables(None, kinds, None))
        # Connectors return the whole catalog; the policy scope is applied HERE
        # so that every consumer (object resolution, the guard's live resolver,
        # relationship inference) only ever sees permitted schemas.
        if policy.allowed_schemas:
            tables = [
                t for t in tables if policy.schema_allowed(t.schema) or policy.system_schema_allowed(t.schema)
            ]
        try:
            await anyio.to_thread.run_sync(self.cache.put_tables, policy.connection_id, fp, tables)
        except sqlite3.Error as exc:
            print(
                f"universal-db-mcp: metadata cache write failed (entry skipped): {exc}",
                file=sys.stderr,
            )
        return list(tables)

    def record_history(self, record: dict[str, Any]) -> None:
        self.history.append({"identity": self.identity, **record})


class _LiveResolver:
    """Resolves unqualified object names against a prefetched (policy-scoped)
    object list. Unknown => False (deny). Constructed via ``await guard_for``."""

    def __init__(self, tables: list[Any]) -> None:
        self._names = {t.name.lower() for t in tables}
        self._qualified = {((t.schema or "").lower(), t.name.lower()) for t in tables if t.schema}
        # bare name -> the schemas it lives in (lets the guard re-authorize the
        # schema an unqualified reference actually binds to)
        self._schemas_of: dict[str, set[str]] = {}
        for t in tables:
            self._schemas_of.setdefault(t.name.lower(), set()).add((t.schema or "").lower())

    def resolve(self, schema: str | None, name: str) -> bool:
        if schema is None:
            return name.lower() in self._names
        return (schema.lower(), name.lower()) in self._qualified

    def schemas_for(self, name: str) -> set[str]:
        return set(self._schemas_of.get(name.lower(), set()))


async def guard_for(app: AppContext, connector: DatabaseConnector, policy: EffectivePolicy) -> SqlGuard:
    """Build a SqlGuard with a prefetched, policy-scoped object resolver."""
    tables = await app.tables_for(policy, connector)
    return SqlGuard(policy.engine, policy, _LiveResolver(tables))


# --------------------------------------------------------------------- helpers


@asynccontextmanager
async def tool_span(
    app: AppContext,
    tool: str,
    connection_id: str | None = None,
    sql: str | None = None,
) -> AsyncIterator[dict[str, Any]]:
    """Request lifecycle: timing, audit, structured error mapping, history."""
    start = time.monotonic()
    request_id = new_request_id()
    state: dict[str, Any] = {"request_id": request_id, "start": start, "row_count": None, "warnings": []}
    outcome = "allow"
    category = None
    try:
        yield state
    except ToolFailure as exc:
        outcome, category = "deny", exc.category
        raise ToolError(str(exc)) from exc
    except DriverUnavailableError as exc:
        outcome, category = "deny", ErrorCategory.DRIVER_MISSING
        raise ToolError(f"{ErrorCategory.DRIVER_MISSING}: {exc}") from exc
    except ConnectorError as exc:
        outcome, category = "error", ErrorCategory.CONNECTION
        raise ToolError(f"{ErrorCategory.CONNECTION}: {scrub_exception(exc)}") from exc
    except ObjectNotFound as exc:
        # Only a genuine "that object is not there" is the caller's problem.
        # This used to catch bare LookupError, whose subclasses KeyError and
        # IndexError are raised by driver and catalog code: a server-side bug
        # was reported to the model as ITS invalid arguments and audited as a
        # policy deny.
        outcome, category = "deny", ErrorCategory.VALIDATION
        raise ToolError(f"{ErrorCategory.VALIDATION}: {redact_text(str(exc))}") from exc
    except NotImplementedError as exc:
        # A capability the connector declares unsupported (db_get_capabilities
        # already says so); reporting it as INTERNAL_ERROR invited bug reports
        # for a documented limitation.
        outcome, category = "deny", ErrorCategory.CAPABILITY
        raise ToolError(f"{ErrorCategory.CAPABILITY}: {redact_text(str(exc))}") from exc
    except anyio.get_cancelled_exc_class():
        # Cancellation (client disconnect, shutdown) is not an error: it is a
        # request that happened and must still leave an audit trail below.
        outcome, category = "cancelled", None
        raise
    except AuditWriteFailure:
        raise
    except Exception as exc:  # noqa: BLE001
        outcome, category = "error", ErrorCategory.INTERNAL
        raise ToolError(f"{ErrorCategory.INTERNAL}: {scrub_exception(exc)}") from exc
    finally:
        elapsed = int((time.monotonic() - start) * 1000)
        fp = sql_fingerprint(sql) if sql else None
        record = {
            "request_id": request_id,
            "action": tool,
            "connection_id": connection_id,
            "outcome": outcome,
            "elapsed_ms": elapsed,
            "sql_fingerprint": fp,
            "row_count": state.get("row_count"),
        }
        if category:
            record["category"] = category
        if state.get("warnings"):
            record["warnings"] = state["warnings"][:5]
        audit_record = {
            "event": "tool_call",
            "caller": app.identity,
            **redact_value(record),
        }
        if sql is not None and app.cfg.security.audit_sql_text:
            # Even when raw SQL text is explicitly enabled by policy it must
            # pass through the redaction chokepoint: credential-shaped
            # literals (password=..., api_key=..., driver URLs) are scrubbed.
            audit_record["sql_text"] = redact_text(sql)
        if outcome == "cancelled":
            # A query may have been in flight when the request was cancelled;
            # the worker thread cannot be interrupted, so the connector's
            # driver state is unknown and the connection must be discarded.
            conn_obj = state.get("connector")
            if conn_obj is not None:
                app.poisoned_connectors.add(id(conn_obj))
        # The write is awaited inside a shielded scope: under an active outer
        # cancellation every unprotected await raises immediately (anyio
        # cancel-scope semantics), which used to drop the audit record of a
        # query that actually ran and defeated audit_fail_closed.
        with anyio.CancelScope(shield=True):
            try:
                # fsync + rotation are blocking; never run them on the event loop
                await anyio.to_thread.run_sync(app.audit.record, audit_record)
            except AuditWriteFailure as audit_exc:
                app.record_history({**record, "ts": _now()})
                raise ToolError(f"{ErrorCategory.CONFIG}: {audit_exc}") from audit_exc
        app.record_history({**record, "ts": _now()})


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def _compact_result(data: dict[str, Any]) -> CallToolResult:
    """One compact JSON text block plus the same dict as structured content."""
    text = json.dumps(data, separators=(",", ":"), ensure_ascii=False, default=str)
    return CallToolResult(content=[TextContent(type="text", text=text)], structured_content=data)


def _envelope(
    st: dict[str, Any], connection_id: str | None, engine: str | None, data: Any, **kw: Any
) -> dict[str, Any]:
    env = Envelope(
        request_id=st["request_id"],
        connection_id=connection_id,
        engine=engine,
        data=data,
        elapsed_ms=int((time.monotonic() - st["start"]) * 1000),
        **kw,
    )
    return env.model_dump(exclude_none=True)


async def run_meta(app: AppContext, connection_id: str, fn: Callable[[DatabaseConnector], Any]) -> Any:
    """Run a metadata operation through the bounded executor."""
    connector, _ = app.connection(connection_id)
    return await app.executor.run_bounded(
        connector, fn, _META_TIMEOUT, description=f"metadata lookup on '{connection_id}'"
    )


async def run_query(
    app: AppContext,
    connection_id: str,
    spec: QuerySpec,
    description: str,
) -> Any:
    connector, policy = app.connection(connection_id)
    return await app.executor.run_bounded(
        connector,
        lambda c: c.execute_query(spec),
        spec.timeout_seconds,
        description=description,
    )


def _page(
    app: AppContext,
    items: list[Any],
    cursor: str | None,
    *,
    kind: str,
    connection_id: str,
    policy: EffectivePolicy,
    page_size: int,
) -> tuple[list[Any], str | None]:
    """Opaque, identity/policy/expiry-bound pagination."""
    offset = 0
    if cursor:
        body = app.cursors.decode(
            cursor,
            expect_identity=app.identity,
            expect_connection=connection_id,
            expect_kind=kind,
            policy_fingerprint=policy_fingerprint(policy),
        )
        offset = int(body.get("offset", 0))
    window = items[offset : offset + page_size]
    next_cursor = None
    if offset + page_size < len(items):
        next_cursor = app.cursors.encode(
            {
                "offset": offset + page_size,
                "identity": app.identity,
                "connection_id": connection_id,
                "kind": kind,
                "policy": policy_fingerprint(policy),
            }
        )
    return window, next_cursor


def _sensitive_output_names(policy: EffectivePolicy, ast: exp.Expression) -> frozenset[str]:
    """Lowercased output names that expose a sensitive source column, even
    under an alias or through a derived table / CTE. A projection's emitted
    name is tainted when the expression behind it references a sensitive
    column or a name that is already tainted; the fixpoint follows alias
    chains across scopes (``SELECT password AS p``, ``SELECT p FROM
    (SELECT password AS p ...) sub``, CTEs). Unaliased expressions are
    covered by the output-name heuristics on the driver-reported name."""
    if not policy.sensitive_patterns:
        return frozenset()

    def sensitive(name: str) -> bool:
        return any(pat.search(name) for pat in policy.sensitive_patterns)

    tainted: set[str] = set()
    projections = [p for sel in ast.find_all(exp.Select) for p in sel.expressions]
    for _ in range(len(projections) + 1):
        grew = False
        for proj in projections:
            out = proj.alias_or_name
            if not out or out.lower() in tainted:
                continue
            refs = [c.name for c in proj.find_all(exp.Column)]
            if any(sensitive(r) or r.lower() in tainted for r in refs):
                tainted.add(out.lower())
                grew = True
        if not grew:
            break
    return frozenset(tainted)


def _mask_columns(
    policy: EffectivePolicy,
    columns: list[tuple[str, str]],
    sensitive_names: frozenset[str] | None = None,
) -> set[int]:
    """Indices of columns to mask/omit: output-name heuristics plus the
    guard-derived names that expose a sensitive source column (aliasing a
    sensitive column does not launder it past policy)."""
    extra = sensitive_names or frozenset()
    hit: set[int] = set()
    for i, (name, _t) in enumerate(columns):
        if name.lower() in extra:
            hit.add(i)
            continue
        for pat in policy.sensitive_patterns:
            if pat.search(name):
                hit.add(i)
                break
    return hit


def _apply_masking(
    policy: EffectivePolicy,
    columns: list[tuple[str, str]],
    rows: list[list[Any]],
    state: dict[str, Any],
    sensitive_names: frozenset[str] | None = None,
) -> tuple[list[tuple[str, str]], list[list[Any]]]:
    hit = _mask_columns(policy, columns, sensitive_names)
    if not hit:
        return columns, rows
    if policy.mask_action == "omit":
        keep = [i for i in range(len(columns)) if i not in hit]
        cols = [columns[i] for i in keep]
        rws = [[row[i] if i < len(row) else None for i in keep] for row in rows]
        state["warnings"].append(
            "sensitive column(s) omitted by policy; column-name heuristics are "
            "not the security boundary — database grants are"
        )
        return cols, rws
    cols = list(columns)
    for i in hit:
        cols[i] = (cols[i][0], f"{cols[i][1]} (masked)")
        for row in rows:
            if i < len(row):
                row[i] = "<masked>"
    state["warnings"].append(
        "sensitive column(s) masked by policy heuristics; this is not the security boundary — database grants are"
    )
    return cols, rows


def _require_engine(app: AppContext, connection_id: str) -> tuple[DatabaseConnector, EffectivePolicy]:
    return app.connection(connection_id)


def _scope_listing(policy: EffectivePolicy, schema: str | None, items: list[Any]) -> list[Any]:
    """Policy scope for schema-less catalog listings (views/synonyms/routines).
    With an explicit schema the caller was authorized via ``check_object``
    before the listing; without one, items living in schemas the connection is
    not permitted to see are dropped here — the same rule ``tables_for``
    applies to tables — instead of leaking whatever the database login sees."""
    if schema is not None or not policy.allowed_schemas:
        return items
    return [i for i in items if policy.schema_allowed(i.schema) or policy.system_schema_allowed(i.schema)]


def _capability_unavailable(state: CapabilityState) -> bool:
    """True when the connector declares a capability cannot be served.
    SUPPORTED runs; UNVERIFIED — implemented against the documented API but
    not yet proven against a live instance — also runs, because every remote
    connector ships UNVERIFIED until proven and gating on SUPPORTED would
    disable view/routine/synonym listing for all of them. UNSUPPORTED,
    NOT_IMPLEMENTED (including an undeclared key), and PERMISSION_DENIED
    refuse with a truthful capability error."""
    return state in (
        CapabilityState.UNSUPPORTED,
        CapabilityState.NOT_IMPLEMENTED,
        CapabilityState.PERMISSION_DENIED,
    )


# ------------------------------------------------------------------ the server


def build_server(app: AppContext) -> MCPServer:
    mcp = MCPServer(
        name="universal-db-mcp",
        version=_version(),
        instructions=(
            "Read-only database access via administrator-declared connections. "
            "Start with db_list_connections. Tool arguments accept only "
            "configured connection ids; host/DSN/credentials are never accepted. "
            "Writes are not supported in v1."
        ),
    )

    # Every tool here reads: without annotations a conformant client must treat
    # them as destructive (readOnlyHint defaults false, destructiveHint true)
    # and prompt for approval on something as harmless as db_list_connections.
    read_only_annotations = ToolAnnotations(
        read_only_hint=True,
        destructive_hint=False,
        idempotent_hint=True,
        open_world_hint=False,
    )

    def register(name: str, description: str, handler: Callable[..., Any]) -> None:
        # Every result is transmitted twice: as structuredContent AND as the
        # text block the model actually reads. Left to the SDK, that text is
        # pretty-printed (indent=2) - ~1.7x the compact size on every call -
        # so the handler is wrapped to emit one compact text block itself.
        # functools.wraps keeps the handler's signature/annotations visible,
        # so the SDK still validates arguments and derives the output schema
        # from the original ``dict[str, Any]`` return; a CallToolResult passes
        # through convert_result with structured_content validated against it.
        @functools.wraps(handler)
        async def compact(*args: Any, **kwargs: Any) -> CallToolResult:
            data = await handler(*args, **kwargs)
            return _compact_result(data)

        mcp.tool(
            name=name,
            description=description,
            structured_output=True,
            annotations=read_only_annotations,
        )(compact)

    # ---- discovery ---------------------------------------------------------

    async def db_list_connections() -> dict[str, Any]:
        async with tool_span(app, "db_list_connections") as st:
            conns = []
            for name, rc in sorted(app.resolved.items()):
                conns.append(
                    {
                        "connection_id": name,
                        "engine": rc.config.type,
                        "family": rc.config.family,
                        "host": rc.config.host,
                        "database": rc.config.database,
                        "tls_enabled": rc.config.tls.enabled,
                        "read_only": True,
                        "allowed_schemas": sorted(rc.config.allowed_schemas),
                    }
                )
            st["row_count"] = len(conns)
            return _envelope(st, None, None, {"connections": conns})

    register(
        "db_list_connections",
        "List database connections available to this caller (ids, engines, "
        "TLS, allowed schemas). Does not probe servers.",
        db_list_connections,
    )

    async def db_test_connection(connection_id: str) -> dict[str, Any]:
        async with tool_span(app, "db_test_connection", connection_id) as st:
            connector, policy = _require_engine(app, connection_id)
            health = await app.executor.run_bounded(
                connector,
                lambda c: c.health_check(),
                15.0,
                description=f"health check on '{connection_id}'",
            )
            data = {
                "healthy": health.healthy,
                "server_version": health.server_version,
                "latency_ms": health.latency_ms,
            }
            if health.detail:
                data["detail"] = health.detail
            if health.session:
                # The session safety profile as the SERVER reported it back
                # (isolation, ceilings, read-only, identity): verified, not assumed.
                data["session"] = health.session
            return _envelope(st, connection_id, policy.engine, data)

    register(
        "db_test_connection",
        "Bounded health test of one configured connection: sanitized status, server version, latency.",
        db_test_connection,
    )

    async def db_get_capabilities(connection_id: str) -> dict[str, Any]:
        async with tool_span(app, "db_get_capabilities", connection_id) as st:
            connector, policy = _require_engine(app, connection_id)
            matrix = connector.capabilities()
            return _envelope(st, connection_id, policy.engine, matrix.to_public())

    register(
        "db_get_capabilities",
        "Capability matrix and limitations for one connection: what the "
        "connector implements vs what is verified, permission-dependent, or "
        "unsupported.",
        db_get_capabilities,
    )

    # ---- catalogs/schemas ----------------------------------------------------

    async def db_list_catalogs(connection_id: str) -> dict[str, Any]:
        async with tool_span(app, "db_list_catalogs", connection_id) as st:
            connector, policy = _require_engine(app, connection_id)
            catalogs = await run_meta(app, connection_id, lambda c: c.list_catalogs())
            if catalogs is None:
                return _envelope(
                    st,
                    connection_id,
                    policy.engine,
                    {"catalogs": []},
                    warnings=[f"engine '{policy.engine}' has no catalog level; use db_list_schemas"],
                )
            return _envelope(st, connection_id, policy.engine, {"catalogs": catalogs})

    register(
        "db_list_catalogs",
        "List catalogs (top-level namespaces) where the engine has them; reports not-applicable otherwise.",
        db_list_catalogs,
    )

    async def db_list_databases(connection_id: str) -> dict[str, Any]:
        async with tool_span(app, "db_list_databases", connection_id) as st:
            connector, policy = _require_engine(app, connection_id)
            if policy.engine in ("mysql", "clickhouse"):
                schemas = await run_meta(app, connection_id, lambda c: c.list_schemas(None, None))
                return _envelope(
                    st,
                    connection_id,
                    policy.engine,
                    {"databases": schemas, "note": "schemas and databases are the same concept on this engine"},
                )
            warnings = [
                f"engine '{policy.engine}' does not expose cross-database "
                f"listing; the connection targets one database; use db_list_schemas"
            ]
            return _envelope(st, connection_id, policy.engine, {"databases": []}, warnings=warnings)

    register(
        "db_list_databases",
        "List databases for engines where that concept exists; otherwise "
        "explains how this engine organizes namespaces.",
        db_list_databases,
    )

    async def db_list_schemas(
        connection_id: str,
        catalog: str | None = None,
        search: str | None = None,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        async with tool_span(app, "db_list_schemas", connection_id) as st:
            connector, policy = _require_engine(app, connection_id)
            schemas = await run_meta(app, connection_id, lambda c: c.list_schemas(catalog, search))
            visible = [
                s
                for s in schemas
                if policy.schema_allowed(s) or policy.system_schema_allowed(s) or not policy.allowed_schemas
            ]
            window, next_cursor = _page(
                app,
                visible,
                cursor,
                kind="schemas",
                connection_id=connection_id,
                policy=policy,
                page_size=_PAGE_SIZE,
            )
            st["row_count"] = len(window)
            return _envelope(
                st,
                connection_id,
                policy.engine,
                {"schemas": window},
                next_cursor=next_cursor,
                returned_row_count=len(window),
                truncated=next_cursor is not None,
            )

    register(
        "db_list_schemas",
        "List schemas visible to policy on a connection (search + bounded pagination).",
        db_list_schemas,
    )

    # ---- tables / objects -----------------------------------------------------

    async def db_list_tables(
        connection_id: str,
        schema: str | None = None,
        search: str | None = None,
        object_kinds: list[str] | None = None,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        async with tool_span(app, "db_list_tables", connection_id) as st:
            connector, policy = _require_engine(app, connection_id)
            if schema is not None:
                policy.check_object(schema, "*")
            if object_kinds is not None and not object_kinds:
                # `x or default` made an explicit [] mean "every kind"; None
                # is the default, an empty list is a caller mistake.
                raise ToolFailure(ErrorCategory.VALIDATION, "object_kinds must be omitted or non-empty")
            kinds = set(object_kinds) if object_kinds is not None else {"table", "view", "materialized_view"}
            unknown = kinds - {"table", "view", "materialized_view", "foreign_table", "alias"}
            if unknown:
                raise ToolFailure(ErrorCategory.VALIDATION, f"unknown object kinds: {sorted(unknown)}")
            tables = await app.tables_for(policy, connector)
            tables = [t for t in tables if t.kind in kinds]
            if schema is not None:
                tables = [t for t in tables if t.schema and t.schema.lower() == schema.lower()]
            elif policy.allowed_schemas:
                tables = [t for t in tables if t.schema and t.schema.lower() in policy.allowed_schemas]
            if search:
                tables = [t for t in tables if search.lower() in t.name.lower()]
            window, next_cursor = _page(
                app,
                tables,
                cursor,
                kind="tables",
                connection_id=connection_id,
                policy=policy,
                page_size=_PAGE_SIZE,
            )
            st["row_count"] = len(window)
            return _envelope(
                st,
                connection_id,
                policy.engine,
                {
                    "tables": [
                        {
                            "schema": t.schema,
                            "name": t.name,
                            "kind": t.kind,
                            "row_estimate": t.row_estimate,
                            "row_estimate_source": t.row_estimate_source,
                        }
                        for t in window
                    ]
                },
                next_cursor=next_cursor,
                returned_row_count=len(window),
                truncated=next_cursor is not None,
            )

    register(
        "db_list_tables",
        "List tables/views/materialized views visible to policy (search, "
        "kinds, bounded pagination, catalog row estimates marked as estimates).",
        db_list_tables,
    )

    async def db_get_table(connection_id: str, object_name: str, schema: str | None = None) -> dict[str, Any]:
        async with tool_span(app, "db_get_table", connection_id) as st:
            connector, policy = _require_engine(app, connection_id)
            schema2, name = await _resolve_object(app, connector, policy, schema, object_name)
            st["row_count"] = 1
            detail = await run_meta(app, connection_id, lambda c: c.get_table(schema2, name))
            return _envelope(st, connection_id, policy.engine, detail)

    register(
        "db_get_table",
        "Detail for one table or view: columns, keys, indexes, definition, "
        "row estimate (marked as estimate when from the catalog).",
        db_get_table,
    )

    async def db_list_columns(
        connection_id: str,
        object_name: str,
        schema: str | None = None,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        async with tool_span(app, "db_list_columns", connection_id) as st:
            connector, policy = _require_engine(app, connection_id)
            schema2, name = await _resolve_object(app, connector, policy, schema, object_name)
            cols = await run_meta(app, connection_id, lambda c: c.list_columns(schema2, name))
            window, next_cursor = _page(
                app,
                cols,
                cursor,
                kind=f"columns:{schema2}.{name}".lower(),
                connection_id=connection_id,
                policy=policy,
                page_size=_PAGE_SIZE,
            )
            st["row_count"] = len(window)
            return _envelope(
                st,
                connection_id,
                policy.engine,
                {"columns": [c.__dict__ for c in window]},
                next_cursor=next_cursor,
                returned_row_count=len(window),
                truncated=next_cursor is not None,
            )

    register(
        "db_list_columns",
        "List columns of one table or view with bounded pagination.",
        db_list_columns,
    )

    async def db_list_views(connection_id: str, schema: str | None = None, cursor: str | None = None) -> dict[str, Any]:
        async with tool_span(app, "db_list_views", connection_id) as st:
            connector, policy = _require_engine(app, connection_id)
            if _capability_unavailable(connector.capabilities().get(Cap.LIST_VIEWS)):
                raise ToolFailure(ErrorCategory.CAPABILITY, f"engine '{policy.engine}' does not expose view listing")
            if schema is not None:
                policy.check_object(schema, "*")
            views = await run_meta(app, connection_id, lambda c: c.list_views(schema))
            views = _scope_listing(policy, schema, views)
            window, next_cursor = _page(
                app,
                views,
                cursor,
                kind="views",
                connection_id=connection_id,
                policy=policy,
                page_size=_PAGE_SIZE,
            )
            st["row_count"] = len(window)
            return _envelope(
                st,
                connection_id,
                policy.engine,
                {"views": [v.__dict__ for v in window]},
                next_cursor=next_cursor,
                returned_row_count=len(window),
                truncated=next_cursor is not None,
            )

    register(
        "db_list_views",
        "List views and materialized views; definitions included only where the engine reports them.",
        db_list_views,
    )

    async def db_list_synonyms(connection_id: str, schema: str | None = None) -> dict[str, Any]:
        async with tool_span(app, "db_list_synonyms", connection_id) as st:
            connector, policy = _require_engine(app, connection_id)
            if _capability_unavailable(connector.capabilities().get(Cap.LIST_SYNONYMS)):
                raise ToolFailure(
                    ErrorCategory.CAPABILITY,
                    f"engine '{policy.engine}' has no synonyms/aliases concept",
                )
            if schema is not None:
                policy.check_object(schema, "*")
            syns = await run_meta(app, connection_id, lambda c: c.list_synonyms(schema))
            syns = _scope_listing(policy, schema, syns)
            st["row_count"] = len(syns)
            return _envelope(st, connection_id, policy.engine, {"synonyms": [s.__dict__ for s in syns]})

    register(
        "db_list_synonyms",
        "List synonyms/aliases and their target objects; remote links are reported, never traversed.",
        db_list_synonyms,
    )

    async def db_list_routines(connection_id: str, schema: str | None = None) -> dict[str, Any]:
        async with tool_span(app, "db_list_routines", connection_id) as st:
            connector, policy = _require_engine(app, connection_id)
            if _capability_unavailable(connector.capabilities().get(Cap.LIST_ROUTINES)):
                raise ToolFailure(
                    ErrorCategory.CAPABILITY,
                    f"engine '{policy.engine}' does not expose stored "
                    f"routines, or they are not implemented in this build",
                )
            if schema is not None:
                policy.check_object(schema, "*")
            routines = await run_meta(app, connection_id, lambda c: c.list_routines(schema))
            routines = _scope_listing(policy, schema, routines)
            st["row_count"] = len(routines)
            return _envelope(st, connection_id, policy.engine, {"routines": [r.__dict__ for r in routines]})

    register(
        "db_list_routines",
        "List functions/procedures (metadata only; routines are never executed for discovery).",
        db_list_routines,
    )

    # ---- search / relationships / stats ---------------------------------------

    async def db_search_metadata(
        query: str,
        connections: list[str] | None = None,
        object_types: list[str] | None = None,
        result_cap: int = _SEARCH_CAP,
    ) -> dict[str, Any]:
        async with tool_span(app, "db_search_metadata") as st:
            if not query or len(query) > 200:
                raise ToolFailure(ErrorCategory.VALIDATION, "query must be 1-200 characters")
            cap = min(max(result_cap, 1), _SEARCH_CAP)
            if connections is not None and not connections:
                raise ToolFailure(ErrorCategory.VALIDATION, "connections must be omitted or non-empty")
            conn_ids = list(connections) if connections is not None else sorted(app.resolved.keys())
            for cid in conn_ids:
                if cid not in app.resolved:
                    raise ToolFailure(ErrorCategory.AUTHZ, f"connection '{cid}' is not available to this caller")
            if object_types is not None and not object_types:
                raise ToolFailure(ErrorCategory.VALIDATION, "object_types must be omitted or non-empty")
            types = set(object_types or ["table", "view", "materialized_view"])
            items: list[tuple[str, str, str, str]] = []
            warnings: list[str] = []
            for cid in conn_ids:
                try:
                    connector, policy = _require_engine(app, cid)
                    if policy.allowed_schemas:
                        conn_tables = [
                            t
                            for t in await app.tables_for(policy, connector)
                            if t.schema and t.schema.lower() in policy.allowed_schemas
                        ]
                    else:
                        conn_tables = await app.tables_for(policy, connector)
                except (ToolFailure, ConnectorError, DriverUnavailableError) as exc:
                    # A missing driver, an unreachable engine or a metadata
                    # timeout on one connection must not abort the
                    # cross-connection search — unless the caller explicitly
                    # named exactly that one connection.
                    if connections is not None and len(conn_ids) == 1:
                        raise
                    warnings.append(f"connection '{cid}' skipped: {scrub_exception(exc)}")
                    continue
                items.extend((cid, t.schema or "", t.name, t.kind) for t in conn_tables if t.kind in types)
            ranked = rank_search(query, items, cap)
            st["row_count"] = len(ranked)
            if warnings:
                st["warnings"].extend(warnings)
            return _envelope(
                st,
                None,
                None,
                {"matches": ranked, "note": "scores are lexical ranking scores, not probabilities"},
                warnings=warnings,
            )

    register(
        "db_search_metadata",
        "Deterministic lexical metadata search across authorized connections "
        "with ranked matches and match reasons (no embeddings).",
        db_search_metadata,
    )

    async def db_get_relationships(
        connection_id: str,
        object_name: str,
        schema: str | None = None,
        include_inferred: bool = False,
    ) -> dict[str, Any]:
        async with tool_span(app, "db_get_relationships", connection_id) as st:
            connector, policy = _require_engine(app, connection_id)
            schema2, name = await _resolve_object(app, connector, policy, schema, object_name)
            fks = await run_meta(app, connection_id, lambda c: c.get_foreign_keys(schema2, name))
            confirmed = [
                {
                    "relationship": "declared_foreign_key",
                    "inferred": False,
                    "from_table": f"{schema2}.{name}",
                    "from_columns": fk.columns,
                    "to_table": f"{fk.ref_schema}.{fk.ref_table}" if fk.ref_schema else fk.ref_table,
                    "to_columns": fk.ref_columns,
                    "constraint_name": fk.name,
                }
                for fk in fks
            ]
            inferred: list[dict[str, Any]] = []
            warnings: list[str] = []
            if include_inferred:
                if connector.capabilities().get(Cap.INFERRED_RELATIONSHIPS) == CapabilityState.UNSUPPORTED:
                    warnings.append(f"name-based inference is not supported for engine '{policy.engine}'")
                else:
                    inferred = await _infer_relationships(app, connector, policy, schema2, name)
                    warnings.append(
                        "inferred relationships are name-based heuristics with uncertainty; values were never sampled"
                    )
            st["row_count"] = len(confirmed) + len(inferred)
            return _envelope(
                st,
                connection_id,
                policy.engine,
                {"declared": confirmed, "inferred": inferred},
                warnings=warnings,
            )

    register(
        "db_get_relationships",
        "Declared foreign keys for one object; optionally name-based "
        "inferences labeled inferred=true with reasons and uncertainty.",
        db_get_relationships,
    )

    async def db_get_statistics(connection_id: str, object_name: str, schema: str | None = None) -> dict[str, Any]:
        async with tool_span(app, "db_get_statistics", connection_id) as st:
            connector, policy = _require_engine(app, connection_id)
            schema2, name = await _resolve_object(app, connector, policy, schema, object_name)
            stats = await run_meta(app, connection_id, lambda c: c.get_statistics(schema2, name))
            st["row_count"] = 1
            return _envelope(st, connection_id, policy.engine, stats)

    register(
        "db_get_statistics",
        "Bounded catalog statistics for one object. Estimates carry freshness "
        "metadata; exact counts/profiling are not run by default.",
        db_get_statistics,
    )

    # ---- query path -------------------------------------------------------------

    async def db_validate_query(
        connection_id: str, sql: str, operation: Literal["query", "explain"] = "query"
    ) -> dict[str, Any]:
        async with tool_span(app, "db_validate_query", connection_id, sql=sql) as st:
            connector, policy = _require_engine(app, connection_id)
            guard = await guard_for(app, connector, policy)
            result = await anyio.to_thread.run_sync(guard.validate_any, sql, operation)
            st["row_count"] = 0
            return _envelope(
                st,
                connection_id,
                policy.engine,
                {
                    "valid": True,
                    "statement_kind": result.kind,
                    "referenced_objects": [
                        {"schema": r.schema, "name": r.name, "catalog": r.catalog} for r in result.tables
                    ],
                    "limitations": _validate_limitations(policy),
                },
            )

    register(
        "db_validate_query",
        "Dialect-aware policy validation without execution: statement kind, resolved objects, and stated limitations.",
        db_validate_query,
    )

    async def db_query(
        connection_id: str,
        sql: str,
        parameters: list[Any] | dict[str, Any] | None = None,
        max_rows: int | None = None,
        timeout_seconds: float | None = None,
    ) -> dict[str, Any]:
        async with tool_span(app, "db_query", connection_id, sql=sql) as st:
            connector, policy = _require_engine(app, connection_id)
            guard = await guard_for(app, connector, policy)
            validated = await anyio.to_thread.run_sync(guard.validate_select, sql)
            row_limit = policy.clamp_row_limit(max_rows)
            timeout = policy.clamp_timeout(timeout_seconds)
            spec = QuerySpec(
                sql=sql,
                parameters=parameters,
                max_rows=row_limit,
                max_response_bytes=policy.max_response_bytes,
                max_cell_bytes=policy.max_cell_bytes,
                timeout_seconds=timeout,
            )
            st["connector"] = connector  # discarded if the request is cancelled mid-query
            outcome = await run_query(app, connection_id, spec, f"query on '{connection_id}'")
            sensitive = _sensitive_output_names(policy, validated.ast)
            columns, rows = _apply_masking(policy, outcome.columns, outcome.rows, st, sensitive_names=sensitive)
            st["row_count"] = len(rows)
            data = {
                "columns": [{"name": n, "type": t} for n, t in columns],
                "rows": rows,
            }
            warnings = list(outcome.warnings) + st["warnings"]
            if outcome.truncated:
                warnings.append(
                    f"result truncated: limits are rows<={row_limit}, "
                    f"bytes<={policy.max_response_bytes}; fetch limits applied "
                    f"server-side, not after full retrieval"
                )
            return _envelope(
                st,
                connection_id,
                policy.engine,
                data,
                warnings=warnings,
                returned_row_count=len(rows),
                truncated=outcome.truncated,
            )

    register(
        "db_query",
        "Execute one validated, bounded read statement with optional bound "
        "parameters; row/byte/timeout ceilings are enforced server-side.",
        db_query,
    )

    async def db_sample_table(
        connection_id: str,
        object_name: str,
        schema: str | None = None,
        columns: list[str] | None = None,
        limit: int | None = None,
    ) -> dict[str, Any]:
        async with tool_span(app, "db_sample_table", connection_id) as st:
            connector, policy = _require_engine(app, connection_id)
            schema2, name = await _resolve_object(app, connector, policy, schema, object_name)
            row_limit = policy.clamp_sample_limit(limit)
            allowed_cols = {c.name for c in await run_meta(app, connection_id, lambda c: c.list_columns(schema2, name))}
            if columns:
                bad = [c for c in columns if c not in allowed_cols]
                if bad:
                    raise ToolFailure(ErrorCategory.VALIDATION, f"unknown columns: {bad}")
            # Engine-correct syntax built by the connector; identifiers are
            # validated + quoted there and the limit is a server-clamped int.
            sql = connector.build_sample_query(schema2, name, columns, row_limit)
            spec = QuerySpec(
                sql=sql,
                parameters=None,
                max_rows=row_limit,
                max_response_bytes=policy.max_response_bytes,
                max_cell_bytes=policy.max_cell_bytes,
                timeout_seconds=policy.clamp_timeout(None),
            )
            st["connector"] = connector  # discarded if the request is cancelled mid-query
            outcome = await run_query(app, connection_id, spec, f"sample on '{connection_id}'")
            columns2, rows = _apply_masking(policy, outcome.columns, outcome.rows, st)
            st["row_count"] = len(rows)
            return _envelope(
                st,
                connection_id,
                policy.engine,
                {"columns": [{"name": n, "type": t} for n, t in columns2], "rows": rows},
                warnings=st["warnings"],
                returned_row_count=len(rows),
                truncated=outcome.truncated,
            )

    register(
        "db_sample_table",
        "Small bounded sample (default 20 rows) of one permitted object with masking/omission policy applied.",
        db_sample_table,
    )

    async def db_explain(
        connection_id: str,
        sql: str,
        analyze: bool = False,
        parameters: list[Any] | dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        async with tool_span(app, "db_explain", connection_id, sql=sql) as st:
            connector, policy = _require_engine(app, connection_id)
            guard = await guard_for(app, connector, policy)
            result = await anyio.to_thread.run_sync(guard.validate_explain, sql)
            if analyze and result.kind == "explain" and not policy.allow_explain_analyze:
                raise ToolFailure(ErrorCategory.POLICY, "EXPLAIN ANALYZE is disabled by policy")
            st["connector"] = connector  # ANALYZE executes; discarded on cancellation
            plan = await app.executor.run_bounded(
                connector,
                lambda c: c.explain(result.ast.sql(dialect=sqlglot_dialect(policy.engine)), analyze),
                policy.clamp_timeout(None),
                description=f"explain on '{connection_id}'",
            )
            st["row_count"] = 1
            return _envelope(
                st,
                connection_id,
                policy.engine,
                {
                    "plan": plan,
                    "raw_preserved": True,
                    "note": "raw plan output is preserved; no optimization findings are invented",
                },
            )

    register(
        "db_explain",
        "Non-executing query plan for validated SQL. Execution-capable explain variants stay disabled by default.",
        db_explain,
    )

    async def db_get_query_history(limit: int = 20) -> dict[str, Any]:
        async with tool_span(app, "db_get_query_history") as st:
            n = min(max(limit, 1), 100)
            mine = [h for h in reversed(app.history) if h.get("identity", app.identity) == app.identity]
            data = []
            for h in mine[:n]:
                data.append(
                    {
                        "request_id": h.get("request_id"),
                        "connection_id": h.get("connection_id"),
                        "action": h.get("action"),
                        "outcome": h.get("outcome"),
                        "elapsed_ms": h.get("elapsed_ms"),
                        "sql_fingerprint": h.get("sql_fingerprint"),
                        "row_count": h.get("row_count"),
                    }
                )
            st["row_count"] = len(data)
            return _envelope(
                st,
                None,
                None,
                {"history": data, "note": "caller-scoped operational history; raw SQL text is not included"},
            )

    register(
        "db_get_query_history",
        "Caller-scoped, redacted operational history (fingerprints, not raw SQL). Not a substitute for the audit log.",
        db_get_query_history,
    )


    # ---- discovery: indexes, catalog snapshot, profiling, value search, inference

    def _meta_call(method: str, *args: Any) -> Callable[[DatabaseConnector], Any]:
        """A typed thunk for run_meta: ``connector.<method>(*args)``."""

        def call(c: DatabaseConnector) -> Any:
            return getattr(c, method)(*args)

        return call

    def _sensitive(policy: EffectivePolicy, name: str) -> bool:
        return any(p.search(name) for p in policy.sensitive_patterns)

    async def _permitted_tables(
        app_: AppContext,
        connector: DatabaseConnector,
        policy: EffectivePolicy,
        schema: str | None,
        include_system: bool = True,
    ) -> list[Any]:
        tables = await app_.tables_for(policy, connector)
        if schema is not None:
            if not (policy.schema_allowed(schema) or policy.system_schema_allowed(schema)):
                raise ToolFailure(
                    ErrorCategory.AUTHZ, f"schema '{schema}' is not permitted on connection '{policy.connection_id}'"
                )
            tables = [t for t in tables if (t.schema or "").lower() == schema.lower()]
        elif not include_system:
            # A whole-connection listing is for the agent's own tables; Oracle's
            # dictionary views and Db2's SYSCAT would otherwise fill the first
            # pages (an explicitly named schema is always honoured)
            tables = [t for t in tables if not is_system_object(policy.engine, t.schema, t.name)]
        return tables

    async def db_list_indexes(
        connection_id: str,
        object_name: str | None = None,
        schema: str | None = None,
        include_system: bool = False,
    ) -> dict[str, Any]:
        async with tool_span(app, "db_list_indexes", connection_id) as st:
            connector, policy = _require_engine(app, connection_id)
            if object_name:
                schema2, name = await _resolve_object(app, connector, policy, schema, object_name)
                indexes = await run_meta(app, connection_id, lambda c: c.list_indexes(schema2, name))
            else:
                tables = await _permitted_tables(app, connector, policy, schema, include_system)
                permitted = {((t.schema or "").lower(), t.name.lower()) for t in tables}
                all_schemas = sorted({t.schema for t in tables if t.schema})
                schemas = all_schemas[:_DISCOVERY_MAX_SCHEMAS]
                if len(all_schemas) > _DISCOVERY_MAX_SCHEMAS:
                    st["warnings"].append(
                        f"only the first {_DISCOVERY_MAX_SCHEMAS} of {len(all_schemas)} schemas were listed; "
                        "pass schema to see the rest"
                    )
                indexes = []
                for sch in schemas:
                    found = await run_meta(app, connection_id, _meta_call("list_indexes", sch, None))
                    indexes.extend(i for i in found if ((i.schema or "").lower(), (i.table or "").lower()) in permitted)
            data = [dataclasses.asdict(i) for i in indexes]
            st["row_count"] = len(data)
            return _envelope(st, connection_id, policy.engine, {"indexes": data})

    register(
        "db_list_indexes",
        "Indexes and primary keys of one permitted object, or of every permitted table in a schema "
        "(ClickHouse: sorting keys and data-skipping indices).",
        db_list_indexes,
    )

    async def db_get_catalog(
        connection_id: str,
        schema: str | None = None,
        include_indexes: bool = True,
        include_system: bool = False,
        cursor: str | None = None,
        page_size: int = 50,
    ) -> dict[str, Any]:
        async with tool_span(app, "db_get_catalog", connection_id) as st:
            connector, policy = _require_engine(app, connection_id)
            size = max(1, min(int(page_size), 200))
            tables = await _permitted_tables(app, connector, policy, schema, include_system)
            tables = sorted(tables, key=lambda t: ((t.schema or "").lower(), t.name.lower()))
            page, next_cursor = _page(
                app, tables, cursor, kind=f"catalog:{schema or '*'}:{int(include_indexes)}:{int(include_system)}",
                connection_id=connection_id, policy=policy, page_size=size,
            )
            by_schema: dict[str | None, dict[str, Any]] = {}
            for sch in sorted({t.schema for t in page}, key=lambda x: x or ""):
                cols = await run_meta(app, connection_id, _meta_call("list_all_columns", sch))
                idx = (
                    await run_meta(app, connection_id, _meta_call("list_indexes", sch, None))
                    if include_indexes else []
                )
                fks = await run_meta(app, connection_id, _meta_call("get_foreign_keys", sch, None))
                by_schema[sch] = {"columns": cols, "indexes": idx, "fks": fks}
            out_tables: list[dict[str, Any]] = []
            for t in page:
                sch = t.schema
                bag = by_schema.get(sch, {"columns": [], "indexes": [], "fks": []})
                key = ((sch or "").lower(), t.name.lower())
                cols = [c for c in bag["columns"] if ((c.schema or sch or "").lower(), c.table.lower()) == key]
                idx = [i for i in bag["indexes"] if ((i.schema or sch or "").lower(), (i.table or "").lower()) == key]
                fks = [
                    k for k in bag["fks"]
                    if ((k.source_schema or sch or "").lower(), (k.source_table or "").lower()) == key
                ]
                pk = next((i.columns for i in idx if i.primary), None)
                fk_data = [_redact_foreign_target(policy, k) for k in fks]
                out_tables.append({
                    "schema": sch,
                    "name": t.name,
                    "kind": t.kind,
                    "row_estimate": t.row_estimate,
                    "row_estimate_source": t.row_estimate_source,
                    "comment": t.comment,
                    "primary_key": pk,
                    "columns": [
                        {
                            "name": c.name,
                            "data_type": c.data_type,
                            **portable_type(policy.engine, c.data_type).as_dict(),
                            "nullable": c.nullable,
                            "default": c.default,
                            "comment": c.comment,
                            "in_primary_key": bool(pk and c.name in pk),
                            "sensitive": _sensitive(policy, c.name),
                        }
                        for c in cols
                    ],
                    "indexes": [dataclasses.asdict(i) for i in idx],
                    "foreign_keys": fk_data,
                })
            st["row_count"] = len(out_tables)
            return _envelope(
                st, connection_id, policy.engine,
                {
                    "tables": out_tables,
                    "table_count": len(tables),
                    "note": (
                        "column 'sensitive' is a name heuristic from security.mask_columns, "
                        "not a data classification"
                    ),
                },
                next_cursor=next_cursor,
            )

    register(
        "db_get_catalog",
        "One-call catalog snapshot of the permitted tables of a connection (paged): columns with "
        "portable types, primary keys, foreign keys, indexes and row estimates. No table data is read.",
        db_get_catalog,
    )

    async def db_profile_table(
        connection_id: str,
        object_name: str,
        schema: str | None = None,
        columns: list[str] | None = None,
        sample_rows: int | None = None,
        include_top_values: bool = True,
    ) -> dict[str, Any]:
        async with tool_span(app, "db_profile_table", connection_id) as st:
            connector, policy = _require_engine(app, connection_id)
            schema2, name = await _resolve_object(app, connector, policy, schema, object_name)
            all_cols = await run_meta(app, connection_id, lambda c: c.list_columns(schema2, name))
            if columns is not None and not columns:
                raise ToolFailure(ErrorCategory.VALIDATION, "columns must be omitted or non-empty")
            if columns:
                known = {c.name for c in all_cols}
                bad = [c for c in columns if c not in known]
                if bad:
                    raise ToolFailure(ErrorCategory.VALIDATION, f"unknown columns: {bad}")
                all_cols = [c for c in all_cols if c.name in set(columns)]
            all_cols = all_cols[:_PROFILE_MAX_COLUMNS]
            cap = int(policy.profile_max_sample_rows)
            requested = min(_PROFILE_DEFAULT_SAMPLE, cap) if sample_rows is None else int(sample_rows)
            if requested < 1 or requested > cap:
                raise ToolFailure(
                    ErrorCategory.VALIDATION,
                    f"sample_rows must be 1-{cap} (security.profile_max_sample_rows)",
                )
            # One call issues up to 1 + top-values statements; all of them share
            # one wall-clock budget so a wide table cannot turn into twenty
            # near-timeout scans (security.discovery_time_budget_seconds).
            deadline = time.monotonic() + float(policy.discovery_time_budget_seconds)

            def _remaining() -> float:
                return min(policy.clamp_timeout(None), max(1.0, deadline - time.monotonic()))
            omit = policy.mask_action == "omit"
            sensitive = {c.name for c in all_cols if _sensitive(policy, c.name)}
            if omit:
                all_cols = [c for c in all_cols if c.name not in sensitive]
            # sensitive columns are profiled for nulls/distinct only: no values leave the database
            profiled = [c for c in all_cols if c.name not in sensitive]
            null_only = [c for c in all_cols if c.name in sensitive]
            sample_sql = connector.build_sample_query(schema2, name, [c.name for c in all_cols], requested)
            select_list, layout = aggregate_select_list(
                profiled, policy.engine, connector.quote_identifier,
                connector.length_expression, connector.substring_expression,
            )
            for c in null_only:
                select_list += f", COUNT({connector.quote_identifier(c.name)})"
                layout.append((c.name, "non_null"))
            spec = QuerySpec(
                # identifiers come from the catalog and are quoted by the connector;
                # the sample subquery is the connector's own bounded builder
                sql=f"SELECT {select_list} FROM ({sample_sql}) s",  # noqa: S608
                parameters=None,
                max_rows=1,
                max_response_bytes=policy.max_response_bytes,
                max_cell_bytes=policy.max_cell_bytes,
                timeout_seconds=_remaining(),
            )
            st["connector"] = connector
            outcome = await run_query(app, connection_id, spec, f"profile of '{connection_id}'")
            if outcome.truncated or not outcome.rows:
                # an aggregate row cut by the byte ceiling would silently become
                # a profile full of None with a clean warning list
                raise ToolFailure(
                    ErrorCategory.LIMIT,
                    "the profile's aggregate row exceeds security.max_response_bytes; profile fewer "
                    "columns (the columns argument) or raise the ceiling",
                )
            row = outcome.rows[0]
            total, profiles = build_profiles(all_cols, policy.engine, layout, row)
            top_done = 0
            if include_top_values:
                for c in profiled:
                    prof = profiles[c.name]
                    if not wants_top_values(prof) or top_done >= _PROFILE_MAX_TOP_COLUMNS:
                        continue
                    if time.monotonic() >= deadline:
                        st["warnings"].append(
                            "discovery time budget exhausted before every low-cardinality column got top values"
                        )
                        break
                    tv_spec = QuerySpec(
                        sql=connector.build_top_values_query(sample_sql, c.name, TOP_VALUES),
                        parameters=None,
                        max_rows=TOP_VALUES,
                        max_response_bytes=policy.max_response_bytes,
                        max_cell_bytes=policy.max_cell_bytes,
                        timeout_seconds=_remaining(),
                    )
                    tv = await run_query(app, connection_id, tv_spec, f"top values on '{connection_id}'")
                    prof.top_values = [{"value": r[0], "count": r[1]} for r in tv.rows]
                    top_done += 1
            indexes = await run_meta(app, connection_id, lambda c: c.list_indexes(schema2, name))
            fks = await run_meta(app, connection_id, lambda c: c.get_foreign_keys(schema2, name))
            try:
                stats = await run_meta(app, connection_id, lambda c: c.get_statistics(schema2, name))
            except (ConnectorError, ToolFailure):
                stats = None
            row_estimate = stats.get("row_estimate") if isinstance(stats, dict) else None
            findings = findings_for_table(
                sample_size=total, row_estimate=row_estimate, columns=all_cols, profiles=profiles,
                indexes=indexes, foreign_keys=fks, stats=stats if isinstance(stats, dict) else None,
            )
            if sensitive:
                st["warnings"].append(
                    "sensitive column(s) profiled for null ratio only (values never returned): "
                    + ", ".join(sorted(sensitive))
                )
            st["row_count"] = total
            if total == 0:
                st["warnings"].append(
                    "the sample returned no rows (empty table, or the account cannot read it): "
                    "column measures are absent and only metadata findings apply"
                )
            return _envelope(
                st, connection_id, policy.engine,
                {
                    "schema": schema2,
                    "name": name,
                    "sample": {
                        "rows": total,
                        "requested": requested,
                        "method": "first rows in storage order (the connector's bounded sample query)",
                    },
                    "row_estimate": row_estimate,
                    "columns": [profiles[c.name].as_dict() for c in all_cols],
                    "primary_key": next((i.columns for i in indexes if i.primary), None),
                    "findings": [f.as_dict() for f in findings],
                },
                warnings=st["warnings"],
            )

    register(
        "db_profile_table",
        "Bounded data profile of one permitted table (null ratio, distinct, min/max, string lengths, "
        "top values for low-cardinality columns) plus evidence-backed optimization findings. "
        "Runs over a sample under the session safety profile; sensitive columns return counts only.",
        db_profile_table,
    )

    async def db_search_values(
        query: str,
        connections: list[str] | None = None,
        schemas: list[str] | None = None,
        match: Literal["contains", "exact", "prefix"] = "contains",
        max_hits_per_table: int = 5,
        max_tables: int = 100,
        time_budget_seconds: float = 30.0,
        per_table_timeout_seconds: float = 10.0,
        include_system: bool = False,
    ) -> dict[str, Any]:
        async with tool_span(app, "db_search_values") as st:
            if not query or len(query) > 200:
                raise ToolFailure(ErrorCategory.VALIDATION, "query must be 1-200 characters")
            if connections is not None and not connections:
                raise ToolFailure(ErrorCategory.VALIDATION, "connections must be omitted or non-empty")
            if schemas is not None and not schemas:
                raise ToolFailure(ErrorCategory.VALIDATION, "schemas must be omitted or non-empty")
            per_table = max(1, min(int(max_hits_per_table), 50))
            table_cap = max(1, min(int(max_tables), 500))
            budget = max(1.0, min(float(time_budget_seconds), 300.0))
            per_table_timeout = max(1.0, min(float(per_table_timeout_seconds), 120.0))
            byte_ceiling: int | None = None
            hit_bytes = 0
            conn_ids = list(connections) if connections is not None else sorted(app.resolved.keys())
            for cid in conn_ids:
                if cid not in app.resolved:
                    raise ToolFailure(ErrorCategory.AUTHZ, f"connection '{cid}' is not available to this caller")
            wanted_schemas = {s.lower() for s in schemas} if schemas else None
            numeric: int | float | None = None
            try:
                numeric = int(query) if query.lstrip("-").isdigit() else float(query)
            except ValueError:
                numeric = None
            if isinstance(numeric, float) and not math.isfinite(numeric):
                numeric = None  # nan/inf never match a column; keep the string predicates only
            needle = query.lower()
            deadline = time.monotonic() + budget
            hits: list[dict[str, Any]] = []
            warnings: list[str] = []
            searched = skipped = 0
            exhausted = False
            for cid in conn_ids:
                if time.monotonic() > deadline:
                    exhausted = True
                    break
                try:
                    connector, policy = _require_engine(app, cid)
                    tables = await app.tables_for(policy, connector)
                except Exception as exc:  # noqa: BLE001 - one dead connection must not end the search
                    if connections is not None and len(conn_ids) == 1:
                        raise
                    warnings.append(f"connection '{cid}' skipped: {scrub_exception(exc)}")
                    continue
                # the policy's discovery budget and byte ceiling bind the whole search
                budget = min(budget, float(policy.discovery_time_budget_seconds))
                deadline = min(deadline, time.monotonic() + budget)
                byte_ceiling = (
                    policy.max_response_bytes if byte_ceiling is None
                    else min(byte_ceiling, policy.max_response_bytes)
                )
                tables = [t for t in tables if t.kind == "table"]
                if wanted_schemas is not None:
                    tables = [t for t in tables if (t.schema or "").lower() in wanted_schemas]
                elif not include_system:
                    tables = [t for t in tables if not is_system_object(policy.engine, t.schema, t.name)]
                columns_by_schema: dict[str | None, list[Any]] = {}
                for t in tables:
                    if searched >= table_cap:
                        break
                    if time.monotonic() > deadline:
                        exhausted = True
                        break
                    if t.schema not in columns_by_schema:
                        try:
                            columns_by_schema[t.schema] = await run_meta(
                                app, cid, _meta_call("list_all_columns", t.schema)
                            )
                        except (ToolFailure, ConnectorError) as exc:
                            warnings.append(f"{cid}.{t.schema}: columns unavailable: {scrub_exception(exc)}")
                            columns_by_schema[t.schema] = []
                    cols = [c for c in columns_by_schema[t.schema] if c.table.lower() == t.name.lower()]
                    preds: list[str] = []
                    params: list[Any] = []
                    matched_cols: list[str] = []
                    for c in cols:
                        if _sensitive(policy, c.name):
                            continue
                        pt = portable_type(policy.engine, c.data_type)
                        q = connector.quote_identifier(c.name)
                        if pt.kind == "string":
                            expr = f"LOWER({connector.text_expression(q, pt.name)})"
                            if match == "exact":
                                params.append(needle)
                                preds.append(f"{expr} = {connector.placeholder(len(params))}")
                            else:
                                # %, _ (and [ on SQL Server) in the query are DATA, not wildcards
                                escaped = connector.escape_like(needle)
                                params.append(f"{escaped}%" if match == "prefix" else f"%{escaped}%")
                                preds.append(connector.like_predicate(expr, connector.placeholder(len(params))))
                            matched_cols.append(c.name)
                        elif pt.kind == "numeric" and numeric is not None and match == "exact":
                            params.append(numeric)
                            preds.append(f"{q} = {connector.placeholder(len(params))}")
                            matched_cols.append(c.name)
                    if not preds:
                        skipped += 1
                        continue
                    select_cols = [c.name for c in cols if not _sensitive(policy, c.name)][:_SEARCH_MAX_SELECT]
                    sql = connector.build_search_query(t.schema, t.name, select_cols, " OR ".join(preds), per_table)
                    spec = QuerySpec(
                        sql=sql,
                        parameters=connector.pack_parameters(params),
                        max_rows=per_table,
                        max_response_bytes=policy.max_response_bytes,
                        max_cell_bytes=policy.max_cell_bytes,
                        timeout_seconds=min(
                            policy.clamp_timeout(None), per_table_timeout, max(1.0, deadline - time.monotonic())
                        ),
                    )
                    searched += 1
                    try:
                        outcome = await run_query(app, cid, spec, f"value search on '{cid}'")
                    except (ToolFailure, ConnectorError) as exc:
                        warnings.append(f"{cid}.{t.schema}.{t.name}: {scrub_exception(exc)}")
                        continue
                    if not outcome.rows:
                        continue
                    columns2, rows = _apply_masking(policy, outcome.columns, outcome.rows, st)
                    names = [n for n, _t in columns2]
                    for row in rows:
                        where = [
                            n for n, v in zip(names, row, strict=False)
                            if n in matched_cols and v is not None and _value_matches(v, needle, numeric, match)
                        ]
                        if not where:
                            continue  # the server matched on a masked or unlisted column; not a hit we can show
                        hit = {
                            "connection": cid, "schema": t.schema, "table": t.name,
                            "matched_columns": where, "row": dict(zip(names, row, strict=False)),
                        }
                        hit_bytes += len(json.dumps(hit, default=str))
                        if byte_ceiling is not None and hit_bytes > byte_ceiling:
                            warnings.append(
                                "response byte ceiling reached (security.max_response_bytes); results are partial"
                            )
                            exhausted = True
                            break
                        hits.append(hit)
                    if exhausted:
                        break
            st["row_count"] = len(hits)
            if exhausted:
                warnings.append(f"time budget of {budget:.0f}s exhausted; results are partial")
            if warnings:
                st["warnings"].extend(warnings)
            return _envelope(
                st, None, None,
                {
                    "query": query, "match": match, "hits": hits,
                    "tables_searched": searched, "tables_skipped_no_candidate_columns": skipped,
                    "budget_exhausted": exhausted,
                    "note": "contains/prefix matching is case-insensitive on string columns; numeric columns "
                    "match only with match=exact and a numeric query; sensitive columns are never searched",
                },
                warnings=st["warnings"],
            )

    register(
        "db_search_values",
        "Search a value across the permitted tables of one or more connections without writing SQL: "
        "bounded per-table hits, a time budget, session-safe reads, sensitive columns excluded.",
        db_search_values,
    )

    async def db_infer_relationships(
        connections: list[str] | None = None,
        schemas: list[str] | None = None,
        cross_connection: bool = True,
        include_system: bool = False,
    ) -> dict[str, Any]:
        async with tool_span(app, "db_infer_relationships") as st:
            if connections is not None and not connections:
                raise ToolFailure(ErrorCategory.VALIDATION, "connections must be omitted or non-empty")
            if schemas is not None and not schemas:
                raise ToolFailure(ErrorCategory.VALIDATION, "schemas must be omitted or non-empty")
            conn_ids = list(connections) if connections is not None else sorted(app.resolved.keys())
            for cid in conn_ids:
                if cid not in app.resolved:
                    raise ToolFailure(ErrorCategory.AUTHZ, f"connection '{cid}' is not available to this caller")
            wanted = {s.lower() for s in schemas} if schemas else None
            facts: list[TableFacts] = []
            warnings: list[str] = []
            policies: dict[str, EffectivePolicy] = {}
            for cid in conn_ids:
                try:
                    connector, policy = _require_engine(app, cid)
                    tables = await app.tables_for(policy, connector)
                except Exception as exc:  # noqa: BLE001 - one dead connection must not end inference
                    if connections is not None and len(conn_ids) == 1:
                        raise
                    warnings.append(f"connection '{cid}' skipped: {scrub_exception(exc)}")
                    continue
                policies[cid] = policy
                tables = [t for t in tables if t.kind == "table"]
                if wanted is not None:
                    tables = [t for t in tables if (t.schema or "").lower() in wanted]
                elif not include_system:
                    tables = [t for t in tables if not is_system_object(policy.engine, t.schema, t.name)]
                if len(facts) + len(tables) > _DISCOVERY_INFER_MAX_TABLES:
                    warnings.append(
                        f"connection '{cid}': table limit {_DISCOVERY_INFER_MAX_TABLES} reached; narrow with schemas"
                    )
                    tables = tables[: max(0, _DISCOVERY_INFER_MAX_TABLES - len(facts))]
                per_schema: dict[str | None, tuple[list[Any], list[Any], list[Any]]] = {}
                for sch in sorted({t.schema for t in tables}, key=lambda x: x or ""):
                    try:
                        cols = await run_meta(app, cid, _meta_call("list_all_columns", sch))
                        idx = await run_meta(app, cid, _meta_call("list_indexes", sch, None))
                        fks = await run_meta(app, cid, _meta_call("get_foreign_keys", sch, None))
                    except (ToolFailure, ConnectorError) as exc:
                        warnings.append(f"{cid}.{sch}: metadata unavailable: {scrub_exception(exc)}")
                        cols, idx, fks = [], [], []
                    per_schema[sch] = (cols, idx, fks)
                for t in tables:
                    cols, idx, fks = per_schema.get(t.schema, ([], [], []))
                    key = t.name.lower()
                    facts.append(TableFacts(
                        ref=TableRef(cid, t.schema, t.name), engine=policy.engine,
                        columns=[c for c in cols if c.table.lower() == key],
                        indexes=[i for i in idx if (i.table or "").lower() == key],
                        foreign_keys=[k for k in fks if (k.source_table or "").lower() == key],
                    ))
            rels = infer_relationships(facts, cross_connection=cross_connection)
            rels = [
                r for r in rels
                if r.target.connection not in policies
                or r.target.schema is None
                or policies[r.target.connection].schema_allowed(r.target.schema)
                or policies[r.target.connection].system_schema_allowed(r.target.schema)
            ]
            st["row_count"] = len(rels)
            if warnings:
                st["warnings"].extend(warnings)
            return _envelope(
                st, None, None,
                {
                    "relationships": [r.as_dict() for r in rels],
                    "tables_considered": len(facts),
                    "note": "declared = foreign keys from the catalogs; inferred = name/type heuristics with a stated "
                    "confidence, no data was read",
                },
                warnings=st["warnings"],
            )

    register(
        "db_infer_relationships",
        "Declared foreign keys plus inferred join candidates (same key column name and compatible type, "
        "or the <table>_id convention) within and across connections, from metadata only.",
        db_infer_relationships,
    )

    return mcp


# ---------------------------------------------------------------- shared utils




def _value_matches(value: Any, needle: str, numeric: int | float | None, match: str) -> bool:
    """Python-side confirmation that a returned cell really contains the
    query (the server predicate may have matched on a column we do not
    show, and LIKE wildcards are escaped so only literal text counts)."""
    text = str(value).lower()
    if match == "prefix":
        return text.startswith(needle)
    if match == "contains":
        return needle in text
    if text == needle:
        return True
    if numeric is not None:
        try:
            return float(value) == float(numeric)
        except (TypeError, ValueError):
            return False
    return False


def _redact_foreign_target(policy: EffectivePolicy, key: KeyInfo) -> dict[str, Any]:
    """A permitted table's foreign key may point at a schema the allowlist
    hides; the key is reported but the hidden target is not named."""
    data = dataclasses.asdict(key)
    ref_schema = key.ref_schema
    if ref_schema and not (policy.schema_allowed(ref_schema) or policy.system_schema_allowed(ref_schema)):
        data["ref_schema"] = "<not permitted>"
        data["ref_table"] = "<not permitted>"
        data["ref_columns"] = []
    return data



def _unquote_identifier(part: str) -> str:
    part = part.strip()
    quoted = len(part) >= 2 and (
        (part[0] == part[-1] and part[0] in ('"', '`')) or (part[0] == "[" and part[-1] == "]")
    )
    if quoted:
        return part[1:-1]
    return part


def _split_qualified_name(schema: str | None, object_name: str) -> tuple[str | None, str]:
    """Accept ``schema.table`` (optionally quoted parts) in ``object_name``.

    A three-part name is refused: the database is fixed by the connection,
    so ``db.schema.table`` cannot be honoured and must not be silently
    reinterpreted. When both the ``schema`` argument and a qualified name are
    given they have to agree."""
    parts = object_name.split(".") if "." in object_name else [object_name]
    if len(parts) == 1:
        return schema, _unquote_identifier(object_name)
    if len(parts) != 2 or not all(p.strip() for p in parts):
        raise ToolFailure(
            ErrorCategory.VALIDATION,
            f"object name '{object_name}' must be 'table' or 'schema.table' (the database is fixed by the connection)",
        )
    qualified_schema, name = _unquote_identifier(parts[0]), _unquote_identifier(parts[1])
    if schema is not None and schema.lower() != qualified_schema.lower():
        raise ToolFailure(
            ErrorCategory.VALIDATION,
            f"schema argument '{schema}' disagrees with the qualified name '{object_name}'",
        )
    return qualified_schema, name


async def _resolve_object(
    app: AppContext,
    connector: DatabaseConnector,
    policy: EffectivePolicy,
    schema: str | None,
    object_name: str,
) -> tuple[str | None, str]:
    """Authorize + resolve one object reference against policy and metadata.
    Unqualified names resolve only when default-deny finds them in a permitted
    schema; unknown names are denied, never guessed. Both branches return the
    catalog's canonical (schema, name) spelling whenever the metadata provides
    a match: connector catalog SQL and sample queries quote identifiers
    verbatim, so the caller's casing would silently miss on case-sensitive
    engines (Oracle, Db2, Postgres quoted identifiers)."""
    # "schema.table" is how agents (and the catalog tool's own output) spell
    # an object; it must mean the same as schema="schema", object_name="table"
    schema, object_name = _split_qualified_name(schema, object_name)
    if schema is None:
        if not policy.default_deny_objects:
            return schema, object_name
        tables = await app.tables_for(policy, connector)
        matches = [t for t in tables if t.name.lower() == object_name.lower()]
        if not matches:
            raise ToolFailure(
                ErrorCategory.AUTHZ,
                f"object '{object_name}' could not be resolved to a permitted "
                f"object; qualify it with an allowed schema",
            )
        schemas = {(t.schema or "").lower() for t in matches}
        if len(schemas) > 1:
            raise ToolFailure(
                ErrorCategory.VALIDATION,
                f"object '{object_name}' exists in several schemas ({', '.join(sorted(schemas))}); "
                f"qualify it with a schema",
            )
        # Never trust the metadata scope alone: the resolved object still goes
        # through the same policy check a qualified reference would.
        policy.check_object(matches[0].schema, matches[0].name)
        return matches[0].schema, matches[0].name
    policy.check_object(schema, object_name)
    # default-deny additionally requires the object to exist in metadata
    if policy.default_deny_objects:
        tables = await app.tables_for(policy, connector)
        matches = [
            t
            for t in tables
            if t.name.lower() == object_name.lower() and t.schema and t.schema.lower() == schema.lower()
        ]
        if not matches:
            raise ToolFailure(
                ErrorCategory.AUTHZ,
                f"object '{schema}.{object_name}' is not a permitted object on connection '{policy.connection_id}'",
            )
        # Return the catalog's canonical spelling, not the caller's: the
        # existence check above is case-insensitive but the connector's
        # catalog queries and quoted identifiers are not.
        return matches[0].schema, matches[0].name
    # Policy permits without a metadata check; no catalog match is available
    # to canonicalize against, so the caller's spelling is used verbatim.
    return schema, object_name


def _validate_limitations(policy: EffectivePolicy) -> list[str]:
    out = [
        "validation is dialect-aware but parser-based; read-only database accounts remain the primary control",
        "row, byte, cell, and timeout ceilings are enforced at execution, not by this validation",
    ]
    if not policy.allow_explain_analyze:
        out.append("EXPLAIN ANALYZE is disabled by policy")
    return out


def _version() -> str:
    from universal_db_mcp import __version__

    return __version__


async def _infer_relationships(
    app: AppContext,
    connector: DatabaseConnector,
    policy: EffectivePolicy,
    schema: str | None,
    table: str,
) -> list[dict[str, Any]]:
    """Name-based relationship inference: never samples values, always labeled
    inferred=true with reason and uncertainty."""
    cols = await run_meta(app, policy.connection_id, lambda c: c.list_columns(schema, table))
    mine = {c.name.lower() for c in cols}
    tables = (await app.tables_for(policy, connector))[:_INFER_MAX_TABLES]
    results: list[dict[str, Any]] = []
    for t in tables:
        if t.kind != "table":
            continue
        if (t.schema or "").lower() == (schema or "").lower() and t.name.lower() == table.lower():
            continue
        try:
            tcols = await run_meta(
                app,
                policy.connection_id,
                lambda c, _s=t.schema, _n=t.name: c.list_columns(_s, _n),  # type: ignore[misc] # noqa: B023
            )
        except ToolFailure:
            continue
        names = {c.name.lower() for c in tcols}
        if "id" not in names:
            continue
        singular = t.name[:-1] if t.name.lower().endswith("s") else t.name
        candidate = f"{singular}_id"
        if candidate in mine:
            results.append(
                {
                    "inferred": True,
                    "from_table": f"{schema}.{table}" if schema else table,
                    "from_columns": [candidate],
                    "to_table": f"{t.schema}.{t.name}" if t.schema else t.name,
                    "to_columns": ["id"],
                    "reason": f"column '{candidate}' matches table name "
                    f"'{t.name}' + 'id' primary-key naming convention",
                    "uncertainty": "name-based heuristic; no values were "
                    "sampled; confirm against declared foreign keys",
                }
            )
    return results
