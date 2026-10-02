"""MCP server wiring: the full tool surface + shared services.

Handlers stay thin. All database work runs through the bounded executor
(worker threads + deadlines); policy lives in EffectivePolicy; dialect-aware
SQL validation lives in SqlGuard; audit/redaction wrap every call.

Stdout is protocol-only (stdio transport); application logs go to stderr.
"""

from __future__ import annotations

import base64
import dataclasses
import decimal
import dis
import functools
import hashlib
import inspect
import itertools
import json
import math
import os
import re
import sqlite3
import string
import sys
import threading
import time
import unicodedata
import weakref
from collections import Counter, deque
from collections.abc import AsyncIterator, Callable, Iterable, Iterator, Mapping
from contextlib import asynccontextmanager, suppress
from typing import Annotated, Any, Literal

import anyio
from mcp.server.mcpserver import Context, MCPServer

# mcp 2.x: ToolError is the documented way to surface a deliberate failure
# message to the client; any other exception is masked as UnexpectedToolError
# with a generic message (verified against the pinned SDK source).
from mcp.server.mcpserver.exceptions import ToolError, UnexpectedToolError
from mcp.types import CallToolResult, InputRequiredResult, TextContent, ToolAnnotations
from pydantic import Field, ValidationError
from sqlglot import exp
from sqlglot.optimizer.scope import Scope, ScopeType, traverse_scope

from universal_db_mcp.config import AppConfig, ResolvedConnection
from universal_db_mcp.connectors import registry
from universal_db_mcp.connectors.base import (
    ConnectorError,
    DatabaseConnector,
    DriverUnavailableError,
    IndexInfo,
    NameBinding,
    ObjectNotFound,
    QuerySpec,
    SynonymTarget,
)
from universal_db_mcp.connectors.driver_helpers import capped_text
from universal_db_mcp.discovery.document import render_data_dictionary
from universal_db_mcp.discovery.inference import TableFacts, TableRef, infer_relationships
from universal_db_mcp.discovery.profile import (
    TOP_VALUES,
    aggregate_select_list,
    build_profiles,
    findings_for_table,
    wants_top_values,
)
from universal_db_mcp.discovery.system_schemas import dictionary_binding, is_session_sql_view, is_system_object
from universal_db_mcp.discovery.types import portable_type
from universal_db_mcp.errors import ToolFailure
from universal_db_mcp.models.capabilities import Cap, CapabilityState
from universal_db_mcp.models.responses import Envelope, ErrorCategory
from universal_db_mcp.security.cursors import CursorCodec, policy_fingerprint
from universal_db_mcp.security.policy import EffectivePolicy, check_not_session_sql
from universal_db_mcp.security.redact import (
    new_request_id,
    redact_text,
    redact_value,
    scrub_exception,
    sql_fingerprint,
)
from universal_db_mcp.security.session import SERVER_READ_ONLY_AVAILABLE
from universal_db_mcp.security.sql_guard import (
    _MAX_SQL_BYTES,
    GuardResult,
    ListedBinding,
    SqlGuard,
    StaticResolver,
    clickhouse_recursive_branches,
    sqlglot_dialect,
)
from universal_db_mcp.services.audit import AuditLog, AuditWriteFailure
from universal_db_mcp.services.executor import ExecutionService
from universal_db_mcp.services.metadata import MetadataCache, connection_target, rank_search

_PAGE_SIZE = 50
_SEARCH_CAP = 25

_DISCOVERY_MAX_SCHEMAS = 20
_PROFILE_MAX_COLUMNS = 60
_PROFILE_DEFAULT_SAMPLE = 10_000
_PROFILE_MAX_TOP_COLUMNS = 20
_SEARCH_MAX_SELECT = 8  # projection of a value-search statement: matched columns, the key, then context
_SEARCH_CHUNK_COLUMNS = 16  # predicate columns per value-search statement
_SEARCH_MAX_COLUMNS = 128  # searchable columns per table; the rest are reported as not searched
_DISCOVERY_INFER_MAX_TABLES = 500
_DISCOVERY_INFER_MAX_SCHEMAS = 50  # schemas whose catalog (3 bulk calls each) one inference call reads
_INFER_MAX_RELATIONSHIPS = 1000  # inferred candidates per call; declared keys are never dropped by it
_INFER_MAX_PER_COLUMN = 5  # inferred candidates per source column
_FEDERATED_MAX_BUDGET_SECONDS = 300.0
_FEDERATED_MAX_MERGED_ROWS = 5000
_FEDERATED_MAX_JOIN_KEYS = 16  # [left, right] pairs in db_federated_join's `on`
_REVIEW_MAX_TABLES = 100
_REVIEW_MIN_TABLE_SECONDS = 5.0
_REVIEW_MAX_RECOMMENDATIONS = 200
_DOCUMENT_MAX_TABLES = 100
_SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2, "info": 3}
_HISTORY_CAP = 200
_INFER_MAX_TABLES = 50  # bounds metadata traversal for inference
_META_TIMEOUT = 15.0
# A caller's connection list: the engines behind it are few, a repeated id
# is worked on once, and no list is longer than this (checked before any I/O).
_MAX_CONNECTIONS_ARG = 64
_IdList = Annotated[list[str], Field(max_length=_MAX_CONNECTIONS_ARG)]
_ID_TEXT_CHARS = 64  # a caller-supplied id or name is echoed (errors) and recorded (audit) up to this length
_ERROR_TEXT_CHARS = 2000  # a tool error's text, whatever a refusal written elsewhere echoes
# security.max_response_bytes bounds the data of every envelope. Pagers keep
# this much of it (an eighth of a smaller ceiling) free for the envelope around
# the items (ids, counts, notes, warnings); a response larger than the ceiling
# plus _RESPONSE_SLACK is refused outright (the backstop for a path that has no
# pager).
_ENVELOPE_ALLOWANCE = 2048
_RESPONSE_SLACK = 64 * 1024
_MAX_WARNINGS = 50
_TOOL_NAME_CHARS = 128  # a tool name the SDK refused is recorded up to this length
# PostgreSQL attribute notation (b.fn is fn(b)): masking reads the column
# names of the base tables a statement qualifies columns with, at most this
# many per statement, and reuses them for _ROW_COLUMNS_TTL seconds.
_ROW_FUNCTION_TABLES = 16
_ROW_COLUMNS_TTL = 300.0
_ROW_COLUMNS_CAP = 4096  # cached (connection, schema, table) entries before the cache starts over
# The whole schema list a connection's allowlist compares spellings with
# (AppContext.schema_names) is read again after this many seconds, the
# metadata cache's TTL.
_SCHEMA_NAMES_TTL = 300.0


def _process_identity() -> str:
    """Audit identity of this process: the OS account it runs as, never
    USER/LOGNAME/USERNAME, which any launcher (an MCP client config's env
    block included) can set to name another account - getpass.getuser()
    reads them first. On POSIX it is the passwd name of the effective UID, or
    ``uid:<n>`` when the UID has no passwd entry (a container running as an
    unmapped UID; that used to raise, and the CLI blamed the config file). On
    Windows it is the account of the process token."""
    geteuid = getattr(os, "geteuid", None)  # absent on Windows
    if geteuid is not None:
        uid = geteuid()
        try:
            import pwd

            return pwd.getpwuid(uid).pw_name or f"uid:{uid}"
        except (KeyError, ImportError):
            return f"uid:{uid}"
    try:
        return _windows_account() or "unknown"
    except Exception:  # noqa: BLE001 - no readable token account: unknown, never the environment's claim
        return "unknown"


def _windows_account() -> str:
    """DOMAIN\\name of this process's token user, read with pywin32 (installed
    on Windows as a dependency of the mcp package); its SID when the account
    has no name."""
    if sys.platform != "win32":
        return ""
    import win32api  # type: ignore[import-untyped]
    import win32security  # type: ignore[import-untyped]

    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32security.TOKEN_QUERY)
    sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
    try:
        name, domain, _kind = win32security.LookupAccountSid(None, sid)
    except win32security.error:
        return str(win32security.ConvertSidToStringSid(sid))
    return f"{domain}\\{name}" if domain else str(name)


def _caller_fields(app: AppContext) -> dict[str, Any]:
    """The caller of an audit record: the process identity and, on POSIX,
    the effective UID it was resolved from."""
    geteuid = getattr(os, "geteuid", None)
    return {"caller": app.identity, **({"caller_uid": geteuid()} if geteuid is not None else {})}


def _id_text(connection_id: str) -> str:
    """A caller-supplied connection id, object name or schema as error text:
    it is whatever the caller sent (megabytes, over HTTP, and the SDK logs the
    text too), so only its head is echoed."""
    return repr(str(connection_id)[:_ID_TEXT_CHARS])


def _names_text(names: list[Any]) -> str:
    """Caller-supplied names (columns, object kinds) as error text: the
    first few, each cut like an id."""
    shown = ", ".join(_id_text(n) for n in names[:5])
    return shown + (f" and {len(names) - 5} more" if len(names) > 5 else "")


def _bounded_error(text: str) -> str:
    return text if len(text) <= _ERROR_TEXT_CHARS else text[: _ERROR_TEXT_CHARS - 1] + "…"


def _connection_unavailable(resolved: dict[str, ResolvedConnection], connection_id: str) -> ToolFailure:
    return ToolFailure(
        ErrorCategory.AUTHZ if resolved else ErrorCategory.CONFIG,
        f"connection {_id_text(connection_id)} is not available to this caller",
    )


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
        # discarded exactly like executor-poisoned connections. An id leaves
        # the set when its connector is discarded or freed (_mark_poisoned),
        # so a recycled address never condemns a healthy connector.
        self.poisoned_connectors: set[int] = set()
        # Discarded connectors that pool sessions (they have close()), with
        # that close: each is called once no worker thread is inside it.
        self._retired: list[tuple[DatabaseConnector, Callable[[], object]]] = []
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
        # (connection, schema, table) -> (read at, its column names): what
        # masking needs to tell a PostgreSQL column from a row function
        self.row_columns: dict[tuple[str, str, str], tuple[float, frozenset[str]]] = {}
        # connection -> (read at, its whole schema list): schema_names
        self._schema_names: dict[str, tuple[float, list[str]]] = {}
        # connection -> (read at, how its sessions bind names): name_binding
        self._name_bindings: dict[str, tuple[float, NameBinding | None]] = {}
        self._targets: dict[str, str] = {}  # connection -> its metadata cache target

    def connection(self, connection_id: str) -> tuple[DatabaseConnector, EffectivePolicy]:
        if connection_id not in self.resolved:
            raise _connection_unavailable(self.resolved, connection_id)
        policy = self._policy_for(connection_id)
        if policy.require_tls and not self.resolved[connection_id].config.tls.enabled:
            raise ToolFailure(
                ErrorCategory.CONFIG,
                f"connection {_id_text(connection_id)} requires TLS "
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
            self.poisoned_connectors.discard(id(existing))
            close = getattr(existing, "close", None)
            if callable(close):
                self._retired.append((existing, close))
        self._close_retired()
        if connection_id not in self.connectors:
            try:
                self.connectors[connection_id] = registry.build_connector(self.resolved[connection_id], policy)
            except DriverUnavailableError:
                raise
            except Exception as exc:
                raise ToolFailure(ErrorCategory.CONNECTION, _construction_error_text(exc)) from exc
        return self.connectors[connection_id], policy

    def _close_retired(self) -> None:
        """Close the sessions of discarded connectors whose abandoned worker
        has returned (closing one under a running driver call is not safe),
        each on its own thread: a close can wait on a hung server."""
        if not self._retired:
            return
        busy = []
        for connector, close in self._retired:
            if self.executor.has_live_worker(connector):
                busy.append((connector, close))
            else:
                threading.Thread(target=_close_quietly, args=(close,), name="udbmcp-close", daemon=True).start()
        self._retired = busy

    def _policy_for(self, connection_id: str) -> EffectivePolicy:
        if connection_id not in self.policies:
            self.policies[connection_id] = EffectivePolicy.build(self.cfg.security, self.resolved[connection_id])
        return self.policies[connection_id]

    def guard(self, policy: EffectivePolicy, objects: set[tuple[str | None, str]] | None = None) -> SqlGuard:
        if objects is not None:
            return SqlGuard(policy.engine, policy, StaticResolver(objects))
        raise ValueError("internal: guards require a prefetched object set")

    async def tables_for(self, policy: EffectivePolicy, connector: DatabaseConnector) -> list[Any]:
        """Permitted table/view summaries, cached and policy-scoped, less the
        tables of a schema spelled otherwise than the policy admits where the
        catalog holds its name in several cases (EffectivePolicy.
        shadowed_spellings, over the whole schema list: schema_names); the
        result carries those spellings as ``shadowed`` (_Listing), and the
        cache keeps their tables.

        Cache I/O runs off the event loop (a busy/locked SQLite cache file
        must not freeze every session), and any cache failure is a miss,
        never a failed tool call."""
        fp = policy_fingerprint(policy)
        target = self._target(policy.connection_id)
        try:
            cached = await anyio.to_thread.run_sync(
                functools.partial(self.cache.get_tables, policy.connection_id, fp, target=target)
            )
        except sqlite3.Error as exc:
            print(
                f"universal-db-mcp: metadata cache read failed (treated as a miss): {exc}",
                file=sys.stderr,
            )
            cached = None
        if cached is not None:
            listed = [t for t in cached if not _never_listed(policy.engine, t)]
            return _Listing.pinned(policy, listed, await self.schema_names(policy))
        kinds = {"table", "view", "materialized_view"}
        tables = await run_meta(self, policy.connection_id, lambda c: c.list_tables(None, kinds, None))
        # SQLite's own catalog, and a view of other sessions' SQL text, is
        # never an object of the caller's, whatever the connector lists
        # (include_system does not bring it back)
        tables = [t for t in tables if not _never_listed(policy.engine, t)]
        # Connectors return the whole catalog; the policy scope is applied HERE
        # so that every consumer (object resolution, the guard's live resolver,
        # relationship inference) only ever sees permitted schemas.
        if policy.allowed_schemas:
            tables = [
                t for t in tables if policy.schema_allowed(t.schema) or policy.system_schema_allowed(t.schema)
            ]
        try:
            await anyio.to_thread.run_sync(
                functools.partial(self.cache.put_tables, policy.connection_id, fp, tables, target=target)
            )
        except sqlite3.Error as exc:
            print(
                f"universal-db-mcp: metadata cache write failed (entry skipped): {exc}",
                file=sys.stderr,
            )
        return _Listing.pinned(policy, tables, await self.schema_names(policy))

    def _target(self, connection_id: str) -> str:
        """What the connection reaches (metadata.connection_target), the
        cache entry's owner: the cache file outlives this process and may be
        shared with other configs."""
        target = self._targets.get(connection_id)
        if target is None:
            target = self._targets[connection_id] = connection_target(self.resolved[connection_id])
        return target

    async def schema_names(self, policy: EffectivePolicy) -> list[str]:
        """The whole schema list (connector.list_schemas, as db_list_schemas
        reads it) where an allowlist makes a namesake matter, else none;
        kept per connection for _SCHEMA_NAMES_TTL seconds. The listing alone
        holds a schema only through the tables it lists: where the spelling
        the policy admits held none of them (empty, or only foreign tables or
        partitioned parents), the listing held its namesake alone, admitted
        it, and db_query, db_sample_table and db_list_tables read "OCEAN"
        under allowed_schemas [ocean] while db_list_schemas hid it (review,
        2026-09-28)."""
        if not policy.allowed_schemas:
            return []
        now = time.monotonic()
        kept = self._schema_names.get(policy.connection_id)
        if kept is not None and now - kept[0] < _SCHEMA_NAMES_TTL:
            return kept[1]
        names = [str(s) for s in await run_meta(self, policy.connection_id, lambda c: c.list_schemas(None, None)) if s]
        self._schema_names[policy.connection_id] = (now, names)
        return names

    async def name_binding(self, policy: EffectivePolicy) -> NameBinding | None:
        """How the connection's sessions bind a statement's names
        (DatabaseConnector.name_binding), read once per _SCHEMA_NAMES_TTL
        and kept in process memory. A failed read fails the tool call."""
        now = time.monotonic()
        kept = self._name_bindings.get(policy.connection_id)
        if kept is not None and now - kept[0] < _SCHEMA_NAMES_TTL:
            return kept[1]
        binding: NameBinding | None = await run_meta(self, policy.connection_id, lambda c: c.name_binding())
        self._name_bindings[policy.connection_id] = (now, binding)
        return binding

    def record_history(self, record: dict[str, Any]) -> None:
        self.history.append({"identity": self.identity, **record})


class _Listing(list[Any]):
    """AppContext.tables_for's result: the permitted tables, the catalog
    spellings of an allowed schema it left out as case-variant namesakes
    (EffectivePolicy.shadowed_spellings), which no reference may name, and
    the permitted schemas' spellings in the schema list it compared them
    with."""

    shadowed: frozenset[str] = frozenset()
    schemas: tuple[str, ...] = ()

    @classmethod
    def pinned(cls, policy: EffectivePolicy, tables: list[Any], schemas: list[str]) -> _Listing:
        """``tables`` less the namesakes among them and ``schemas`` (the
        whole schema list, where the policy has an allowlist)."""
        shadowed = policy.shadowed_spellings([*schemas, *(t.schema for t in tables)])
        listing = cls(t for t in tables if t.schema not in shadowed)
        listing.shadowed = shadowed
        listing.schemas = tuple(s for s in schemas if _SchemaView(policy, shadowed).visible(s))
        return listing


def _shadowed_of(tables: list[Any]) -> frozenset[str]:
    """The namesake spellings tables_for left out (a stand-in list has none)."""
    return tables.shadowed if isinstance(tables, _Listing) else frozenset()


class _LiveResolver:
    """Resolves unqualified object names against a prefetched (policy-scoped)
    object list. Unknown => False (deny). Constructed by ``_validated``."""

    def __init__(self, tables: list[Any], shadowed: frozenset[str] = frozenset()) -> None:
        self._names = {t.name.lower() for t in tables}
        self._qualified = {((t.schema or "").lower(), t.name.lower()) for t in tables if t.schema}
        # bare name -> the schemas it lives in (lets the guard re-authorize the
        # schema an unqualified reference actually binds to)
        self._schemas_of: dict[str, set[str]] = {}
        # schema, folded -> its catalog spellings (the guard compares the one
        # a reference names with them, and spells its hints with them): the
        # listing's, and the whole schema list's where _Listing holds it (a
        # permitted schema that holds nothing listed is still spelled so)
        self._spellings: dict[str, set[str]] = {}
        for t in tables:
            self._schemas_of.setdefault(t.name.lower(), set()).add((t.schema or "").lower())
            if t.schema:
                self._spellings.setdefault(t.schema.lower(), set()).add(t.schema)
        for schema in tables.schemas if isinstance(tables, _Listing) else ():
            self._spellings.setdefault(schema.lower(), set()).add(schema)
        self._shadowed = shadowed
        # (schema, name) and bare name, folded -> the listed objects as the
        # catalog spells them (listed_spellings)
        self._listed: dict[tuple[str | None, str], set[tuple[str, str]]] = {}
        for t in tables:
            if t.schema:
                for key in ((t.schema.lower(), t.name.lower()), (None, t.name.lower())):
                    self._listed.setdefault(key, set()).add((t.schema, t.name))

    def resolve(self, schema: str | None, name: str) -> bool:
        if schema is None:
            return name.lower() in self._names
        return (schema.lower(), name.lower()) in self._qualified

    def schemas_for(self, name: str) -> set[str]:
        return set(self._schemas_of.get(name.lower(), set()))

    def listed_spellings(self, schema: str | None, name: str) -> set[tuple[str, str]]:
        """The listed objects, as the catalog spells their schema and name,
        that ``schema.name`` (a bare ``name``: in any schema) matches
        ignoring case: the guard reads the one the engine looks up
        (SqlGuard._check_listed_spelling)."""
        return set(self._listed.get((schema.lower() if schema is not None else None, name.lower()), set()))

    def schema_spellings(self, schema: str) -> tuple[set[str], bool]:
        """How the catalog spells ``schema`` in the listing and the schema
        list, and whether it also holds a namesake spelling the policy does
        not admit."""
        folded = schema.lower()
        return set(self._spellings.get(folded, set())), any(s.lower() == folded for s in self._shadowed)


_FoldTable = Mapping[int, int | str]
_Folding = tuple[_FoldTable | None, _FoldTable | None]
_ASCII_LOWER = str.maketrans(string.ascii_uppercase, string.ascii_lowercase)
_ASCII_UPPER = str.maketrans(string.ascii_lowercase, string.ascii_uppercase)


class _UnicodeCase(dict[int, str]):
    """A str.translate table that folds every character by Unicode's case
    rules, not only ASCII's, one character for one as the engines do: a
    character whose case mapping is longer (ß to SS, İ to i̇) stays itself."""

    def __init__(self, *, upper: bool) -> None:
        super().__init__()
        self._upper = upper

    def __missing__(self, key: int) -> str:
        ch = chr(key)
        mapped = ch.upper() if self._upper else ch.lower()
        folded = self[key] = mapped if len(mapped) == 1 else ch
        return folded


# How an engine folds a bare name before it compares it with a CTE's:
# (unquoted, quoted) translation tables, None keeping the name as written.
# ASCII only where the engine does so (PostgreSQL on UTF-8, SQLite); Oracle
# upper-cases an unquoted name by Unicode's rules (é names É, live). An
# engine not listed compares names as written (SQL Server's and MySQL's case
# sensitivity is a collation's or a server setting's), which can take a CTE
# reference for a table, and authorize it, but never a table for a CTE.
_CASE_INSENSITIVE: _Folding = (_ASCII_LOWER, _ASCII_LOWER)
_NAME_FOLDING: dict[str, _Folding] = {
    "sqlite": _CASE_INSENSITIVE,
    "postgres": (_ASCII_LOWER, None),
    "oracle": (_UnicodeCase(upper=True), None),
    "db2": (_ASCII_UPPER, None),
}
# How an engine may also fold an unquoted name outside ASCII, where it is
# not known to keep it: Db2 may upper-case it by Unicode's rules, and
# PostgreSQL lower-cases it on a database in a single-byte encoding. A FROM
# item is a CTE's only where both readings bind it to one (_cte_hidden_tables
# probes it as a table otherwise, and _cte_misbound leaves the statement
# untraced).
_UNICODE_FOLDING: dict[str, _Folding] = {
    "db2": (_UnicodeCase(upper=True), None),
    "postgres": (_UnicodeCase(upper=False), None),
}
# Engines whose names a collation or a server setting makes case-insensitive
# or not: a statement whose CTE binding depends on it cannot be traced
# (_cte_misbound).
_CASE_UNKNOWN_ENGINES = frozenset({"mssql", "mysql"})
# Engines where a CTE naming itself is recursive, RECURSIVE keyword or not:
# SQL Server, Oracle and Db2 have no such keyword, and SQLite reports a
# circular reference. On ClickHouse it is only in the branches of its
# recursion (clickhouse_recursive_branches).
_SELF_RECURSIVE_CTES = frozenset({"sqlite", "mssql", "oracle", "db2"})


def _folded_name(engine: str, ident: exp.Identifier, folding: _Folding | None = None) -> str:
    unquoted, quoted = folding or _NAME_FOLDING.get(engine, (None, None))
    table = quoted if ident.quoted else unquoted
    return str(ident.this).translate(table) if table is not None else str(ident.this)


def _cte_in_reach(
    engine: str,
    table: exp.Table,
    name: str,
    declared: dict[int, dict[str, int]],
    position: dict[int, int],
    recursive: dict[int, str],
    memo: dict[tuple[int, str], bool],
) -> bool:
    """Whether a CTE the FROM item can see declares its (folded) name: one of
    each WITH on a query around it; from inside a WITH's own CTE, one before
    it, itself too where naming itself is recursive, and any of them on
    SQLite and under PostgreSQL's RECURSIVE; on ClickHouse any other one (the
    guard refuses CTEs naming each other), and itself in a branch of its
    recursion. ``declared``: per WITH, each name its CTEs declare and the
    position of the first; ``position``: each CTE's in its WITH;
    ``recursive``: each ClickHouse recursive branch, by id, and its CTE's
    name; ``memo``: the answer from each node walked so far up, per name (a
    long UNION is one deep tree its branches share)."""
    walked: list[tuple[int, str]] = []
    node: exp.Expr = table
    found = False
    while node.parent is not None:
        if (id(node), name) in memo:
            found = memo[(id(node), name)]
            break
        walked.append((id(node), name))
        if recursive.get(id(node)) == name:
            found = True
            break
        parent = node.parent
        if isinstance(parent, exp.With) and isinstance(node, exp.CTE):
            first = declared[id(parent)].get(name)
            if engine == "clickhouse":
                found = first is not None and first != position[id(node)]
            elif engine == "sqlite" or (engine == "postgres" and parent.recursive):
                found = first is not None
            else:
                reach = position[id(node)] + (1 if parent.recursive or engine in _SELF_RECURSIVE_CTES else 0)
                found = first is not None and first < reach
        else:
            with_ = parent.args.get("with_")
            found = isinstance(with_, exp.With) and node is not with_ and name in declared[id(with_)]
        if found:
            break
        node = parent
    for key in walked:
        memo[key] = found
    return found


def _cte_bindings(engine: str, ast: exp.Expression, folding: _Folding | None = None) -> list[tuple[exp.Table, bool]]:
    """Each bare FROM item whose name some CTE of the statement declares, in
    whatever scope (the guard takes each for a CTE's reference, and so leaves
    it unchecked), and whether the engine binds it to a CTE in reach: where
    it does not, it names a table. ClickHouse's WITH <expression> AS name
    names a value, never a table. ``folding`` replaces the engine's
    (_NAME_FOLDING). Each WITH's names are read once, so a statement at the
    size ceiling with thousands of CTEs costs a pass, not their square."""
    skipped = {cte.alias_or_name.lower() for cte in ast.find_all(exp.CTE)}
    if not skipped:
        return []
    declared: dict[int, dict[str, int]] = {}
    position: dict[int, int] = {}
    recursive: dict[int, str] = {}
    for with_ in ast.find_all(exp.With):
        names = declared[id(with_)] = {}
        for at, cte in enumerate(with_.expressions):
            position[id(cte)] = at
            alias = cte.args.get("alias")
            if cte.args.get("scalar") or not isinstance(alias, exp.TableAlias):
                continue
            if isinstance(alias.this, exp.Identifier):
                name = _folded_name(engine, alias.this, folding)
                names.setdefault(name, at)
                if engine == "clickhouse":
                    for branch in clickhouse_recursive_branches(cte):
                        recursive[id(branch)] = name
    memo: dict[tuple[int, str], bool] = {}
    bindings = []
    for table in ast.find_all(exp.Table):
        ident = table.this
        if not isinstance(ident, exp.Identifier) or table.db or table.catalog or table.name.lower() not in skipped:
            continue
        name = _folded_name(engine, ident, folding)
        bindings.append((table, _cte_in_reach(engine, table, name, declared, position, recursive, memo)))
    return bindings


def _unicode_folding(engine: str, ast: exp.Expression) -> _Folding | None:
    """``engine``'s other reading of names outside ASCII (_UNICODE_FOLDING),
    where the statement names a table or CTE outside ASCII (only then can
    the readings differ)."""
    if engine not in _UNICODE_FOLDING:
        return None
    names = itertools.chain(
        (t.name for t in ast.find_all(exp.Table)), (c.alias_or_name for c in ast.find_all(exp.CTE))
    )
    return None if all(name.isascii() for name in names) else _UNICODE_FOLDING[engine]


def _foldings(engine: str, ast: exp.Expression) -> list[_Folding | None]:
    """Every way ``engine`` may fold the statement's names (None: _NAME_FOLDING's)."""
    out: list[_Folding | None] = [None]
    if engine in _CASE_UNKNOWN_ENGINES:
        out.append(_CASE_INSENSITIVE)
    if (unicode := _unicode_folding(engine, ast)) is not None:
        out.append(unicode)
    return out


def _cte_hidden_tables(engine: str, ast: exp.Expression) -> list[exp.Table]:
    """The FROM items the guard takes for CTE references that no CTE in
    reach declares (_cte_bindings): a CTE of the same name inside EXISTS hid
    the outer pg_stat_activity or sqlite_schema from default-deny. Where the
    engine may also fold a name outside ASCII (_UNICODE_FOLDING), one that a
    CTE covers under only one reading is hidden too: Db2 may read WITH "é"
    ... FROM é as the table É."""
    foldings: list[_Folding | None] = [None]
    if (unicode := _unicode_folding(engine, ast)) is not None:
        foldings.append(unicode)
    hidden: dict[int, exp.Table] = {}
    for folding in foldings:
        for table, bound in _cte_bindings(engine, ast, folding):
            if not bound:
                hidden.setdefault(id(table), table)
    return list(hidden.values())


def _engine_view(
    ast: exp.Expression, engine: str, table_columns: dict[int, frozenset[str]] | None
) -> tuple[exp.Expression, dict[int, frozenset[str]]]:
    """A copy of the statement for the taint walk, which binds a FROM item as
    sqlglot does - by the exact name, and a CTE's self-reference only under
    RECURSIVE - with the names CTEs declare, and the bare FROM items that
    name one of them, folded as the engine folds them (_NAME_FOLDING), and
    each WITH read as RECURSIVE where a CTE naming itself is recursive without
    the keyword (_SELF_RECURSIVE_CTES): otherwise the walk traced a clean
    CTE's literals over the table the engine read, or took a self-reference
    for a base table whose columns trace clean. ``table_columns`` is re-keyed
    to the copy's FROM items."""
    view = ast.copy()
    columns = {}
    if table_columns:
        for original, copied in zip(ast.find_all(exp.Table), view.find_all(exp.Table), strict=True):
            if id(original) in table_columns:
                columns[id(copied)] = table_columns[id(original)]
    declared: set[str] = set()
    for with_ in view.find_all(exp.With):
        if engine in _SELF_RECURSIVE_CTES:
            with_.set("recursive", True)
        for cte in with_.expressions:
            alias = cte.args.get("alias")
            if isinstance(alias, exp.TableAlias) and isinstance(alias.this, exp.Identifier):
                declared.add(alias.this.name.lower())
                alias.this.set("this", _folded_name(engine, alias.this))
    for table in view.find_all(exp.Table):
        ident = table.this
        if isinstance(ident, exp.Identifier) and not table.db and not table.catalog and ident.name.lower() in declared:
            ident.set("this", _folded_name(engine, ident))
    return view, columns


def _cte_misbound(engine: str, view: exp.Expression, scopes: list[Scope]) -> bool:
    """Whether sqlglot's scopes over the walk's view (_engine_view) bind some
    FROM item to a CTE, or another query, where the engine reads a table, or
    to a table where the engine reads a CTE (_cte_bindings): a CTE declared
    after the one naming it (SQLite, PostgreSQL's RECURSIVE, ClickHouse), a
    ClickHouse anchor naming its own CTE, or a name SQL Server's or MySQL's
    collation may compare case-insensitively. The walk would trace the
    values from the wrong source."""
    analysed = {
        id(table)
        for scope in scopes
        for table in scope.tables
        if isinstance(source := scope.sources.get(table.alias_or_name), Scope) and source.expression is not table
    }
    return any(
        analysed != {id(table) for table, bound in _cte_bindings(engine, view, folding) if bound}
        for folding in _foldings(engine, view)
    )


def _validate_in_scope(guard: SqlGuard, engine: str, validate: Callable[[SqlGuard], GuardResult]) -> GuardResult:
    """``validate``, then each bare name the guard left unchecked as a CTE's
    that no CTE in reach declares (_cte_hidden_tables), authorized as the
    table it is by the same guard, and added to the result's tables."""
    result = validate(guard)
    probed: set[tuple[str, bool]] = set()
    hidden = _cte_hidden_tables(engine, result.ast)
    # a CTE in reach whose name differs only in case covers the reference
    # where the collation or setting compares names so (_CASE_UNKNOWN_ENGINES)
    case_bound = (
        {id(t) for t, bound in _cte_bindings(engine, result.ast, _CASE_INSENSITIVE) if bound}
        if hidden and engine in _CASE_UNKNOWN_ENGINES
        else set()
    )
    for table in hidden:
        ident = table.this
        if (table.name, bool(ident.quoted)) in probed:
            continue
        probed.add((table.name, bool(ident.quoted)))
        probe = exp.select("1").from_(exp.Table(this=ident.copy()))
        try:
            # the table as the probe read it, quoting and all (ObjectRef.looked_up)
            refs = guard.validate_select(probe.sql(dialect=sqlglot_dialect(engine))).tables
        except ToolFailure as exc:
            note = "a CTE of that name elsewhere in the statement does not cover this reference"
            if id(table) in case_bound:
                declared = next(
                    cte.alias_or_name
                    for cte in result.ast.find_all(exp.CTE)
                    if cte.alias_or_name.lower() == table.name.lower()
                )
                note = (
                    f"the CTE {declared} covers it only where the server compares names ignoring case, which "
                    f"its collation or settings decide: spell the reference as the CTE is declared ({declared})"
                )
            raise ToolFailure(exc.category, f"{str(exc).removeprefix(f'{exc.category}: ')}; {note}") from exc
        for ref in refs:
            if ref not in result.tables:
                result.tables.append(ref)
    return result


async def _validated(
    app: AppContext,
    connector: DatabaseConnector,
    policy: EffectivePolicy,
    validate: Callable[[SqlGuard], GuardResult],
) -> GuardResult:
    """A caller's statement through the guard, off the event loop. On an
    engine whose listing names every object (_LISTED_ONLY_ENGINES) each table
    it reads must be a listed one, default-deny or not, exactly like an
    object the metadata tools resolve: without default-deny the guard
    resolves no name, and on SQLite a name the listing lacks is its own
    catalog (sqlite_schema.sql, a sensitive column's DEFAULT literal
    included) or an eponymous virtual table (pragma_table_info WHERE arg =
    't' reads the same DEFAULTs, pragma_database_list the file's path). A
    name the guard took for a CTE's is checked where no CTE in reach
    declares it (_validate_in_scope). Under default-deny a name read as
    the engine binds it must be the listed table the guard matched it to
    (ListedBinding, _check_bindings)."""
    tables = await app.tables_for(policy, connector)
    listed = _LiveResolver(tables, _shadowed_of(tables))
    guard = SqlGuard(policy.engine, policy, listed)
    result = await anyio.to_thread.run_sync(_validate_in_scope, guard, policy.engine, validate)
    if guard.bindings:
        await _check_bindings(app, policy, guard.bindings)
    await _check_synonyms(
        app, connector, policy, [ref.looked_up or (ref.schema, ref.name) for ref in result.tables]
    )
    if policy.engine in _LISTED_ONLY_ENGINES:
        for ref in result.tables:
            if _engine_catalog_table(policy.engine, ref.name):
                raise ToolFailure(
                    ErrorCategory.POLICY,
                    f"SQLite catalog table {_id_text(ref.name)} is not readable through a query on connection "
                    f"'{policy.connection_id}'; use db_list_tables / db_get_table for metadata",
                )
            if not listed.resolve(ref.schema, ref.name):
                raise ToolFailure(
                    ErrorCategory.POLICY,
                    f"object {_id_text(ref.name)} could not be resolved to a permitted object on connection "
                    f"'{policy.connection_id}': a statement reads only the tables and views db_list_tables lists",
                )
    return result


# Where each engine looks a bare name up first, for the refusal
_BARE_NAME_LOOKUP = {
    "postgres": "the first schema of its search_path, and pg_catalog before it unless the path names pg_catalog",
    "oracle": "its CURRENT_SCHEMA, then the PUBLIC synonyms",
    "mssql": "the login's default schema, then dbo",
    "db2": "its CURRENT SCHEMA, then the public aliases",
}


async def _check_bindings(app: AppContext, policy: EffectivePolicy, bindings: list[ListedBinding]) -> None:
    """Refuse a name default-deny matched to a listed table that the engine
    does not read for it in the sessions of this connection
    (ListedBinding): a bare one whose table is not in the first schema
    the session looks bare names up in, which binds it to that schema's
    object of the name, a synonym, a PUBLIC synonym or a dictionary view
    before the listed table (live, re-attack round 2: with an empty
    R2OWN.DATABASE_PROPERTIES listed, a bare DATABASE_PROPERTIES read
    Oracle's; with an empty r2own.syslogins, SQL Server's logins), and on
    SQL Server one spelled in another case where the database collation
    compares case. How the session binds names is asked of the database
    (AppContext.name_binding); an engine that binds a bare name only within
    the connection's database answers None, and its listing decides."""
    binding = await app.name_binding(policy)
    for named in dict.fromkeys(bindings):
        if named.folded and (binding is None or not binding.ignores_case):
            raise ToolFailure(
                ErrorCategory.POLICY,
                f"table {named.written} is not spelled as the catalog lists it on connection "
                f"'{policy.connection_id}' ({named.spelled}): SQL Server compares names as the database collation "
                f"does, which here does not ignore case, so it names another object than the listed one, or none; "
                f"write {named.spelled}",
            )
        if not named.bare or binding is None:
            continue
        first = _first_schema(policy.engine, binding, named.name)
        same = (
            first is not None
            and (first.lower() == named.schema.lower() if binding.ignores_case else first == named.schema)
        )
        if not same:
            where = f"{first} first" if first is not None else "no schema"
            raise ToolFailure(
                ErrorCategory.POLICY,
                f"the bare name {named.written} is the listed {named.schema}.{named.name} only where the session "
                f"looks bare names up in {named.schema} first; on connection '{policy.connection_id}' a bare name "
                f"is looked up in {where} ({_BARE_NAME_LOOKUP.get(policy.engine, 'its default schema')}), where "
                f"the catalog lists no {named.name}, so the engine reads another object of that name, there or "
                f"after it (a dictionary view, a synonym), or none; write {named.spelled}",
            )


def _first_schema(engine: str, binding: NameBinding, name: str) -> str | None:
    """The first schema a session binding so looks the bare ``name`` up in
    that may hold it. PostgreSQL searches pg_catalog, which holds only pg_
    names (live, 17), first unless the search_path names it, and then
    current_schemas(false) does: with pg_catalog in allowed_system_schemas a
    bare pg_tables was refused as looked up in public first (review of
    re-attack round 2)."""
    schemas = binding.bare_schemas
    if engine == "postgres":
        if not name.startswith("pg_"):
            schemas = tuple(s for s in schemas if s != "pg_catalog")
        elif "pg_catalog" not in schemas:
            schemas = ("pg_catalog", *schemas)
    return schemas[0] if schemas else None


# Engines where a name may be a synonym (Db2: an alias) of another object.
_SYNONYM_ENGINES = frozenset({"oracle", "mssql", "db2"})


async def _check_synonyms(
    app: AppContext, connector: DatabaseConnector, policy: EffectivePolicy, names: list[tuple[str | None, str]]
) -> None:
    """Refuse a name that is a synonym (Db2: an alias) of an object a
    statement could not name, directly or through others: each object the
    chain names goes through every check a written reference does
    (EffectivePolicy.check_object: the views no allowlist opens, system
    schemas, allowed_schemas, SQL Server's compatibility views), and one in
    another database, or over a database link, is refused as such a
    reference is. Without default-deny a name in a permitted schema was
    admitted as written: SQL Server's dbo.w4rv_logins FOR sys.sql_logins
    handed back the login hashes (re-attack, round 1), and with the views'
    lists checked alone TRAVEL synonyms read another schema's table, the
    same over a database link, and SYS.ALL_USERS, SQL Server ones
    master.dbo.spt_values and sys.objects, and a Db2 alias SYSCAT.DBAUTH
    (live, round 2). With default-deny a synonym is no listed object and is
    refused as such. ``names`` are as the engine looks them up (a statement's
    ObjectRef.looked_up; a tool's as it quotes them, verbatim). A qualified
    name the listing holds exactly so is a table or a view, which share the
    synonyms' namespace, and is not looked up; any other is, a bare one as a
    synonym of any schema (connector.synonym_chains, which matches names as
    the engine does). Compared ignoring case, Oracle's TRAVEL."Bookings" FOR
    R3RVOWN.PAYROLL, beside the listed TRAVEL.BOOKINGS, was never looked up
    and read the table (live, review of round 2)."""
    if policy.default_deny_objects or policy.engine not in _SYNONYM_ENGINES:
        return
    listed = {(t.schema, t.name) for t in await app.tables_for(policy, connector) if t.schema}
    wanted = [(schema, name) for schema, name in dict.fromkeys(names) if schema is None or (schema, name) not in listed]
    if not wanted:
        return
    chains = await run_meta(app, policy.connection_id, lambda c: c.synonym_chains(wanted))
    kind = "an alias" if policy.engine == "db2" else "a synonym"

    def check(target: SynonymTarget, *, views_only: bool) -> None:
        if views_only:
            check_not_session_sql(policy.engine, target.schema, target.name)
            return
        if target.elsewhere is not None:
            where = (
                f"over the database link {target.elsewhere}"
                if policy.engine == "oracle"
                else f"in the database {target.elsewhere}"
            )
            raise ToolFailure(
                ErrorCategory.POLICY,
                f"it is {where}, which no allowlist of connection '{policy.connection_id}' governs: a statement "
                "reads only this connection's database",
            )
        policy.check_object(target.schema, target.name)

    for (schema, name), chain in chains.items():
        targets = [SynonymTarget(*step) for step in chain]
        # the views no allowlist opens name the refusal first, wherever in the chain
        for views_only, target in [(True, t) for t in targets] + [(False, t) for t in targets]:
            try:
                check(target, views_only=views_only)
            except ToolFailure as exc:
                shown = f"{schema}.{name}" if schema else name
                named = ".".join(part for part in target[:2] if part)
                raise ToolFailure(
                    exc.category,
                    f"'{shown}' is {kind} that reads '{named}', refused as that is: "
                    + str(exc).removeprefix(f"{exc.category}: "),
                ) from exc


# --------------------------------------------------------------------- helpers


# Engines quote the offending VALUE in data errors - PostgreSQL: invalid input
# syntax for type integer: "MB-ALPHA"; ClickHouse: Cannot parse string 'x' as
# Int32; SQL Server: converting the varchar value '...' to data type int - so a
# failing CAST hands a masked value back in clear, and one wrapped around
# string_agg or LISTAGG hands back all of them. Known echoes, quoted or not,
# are cut first (each pattern keeps its group 1 and replaces the rest of the
# match), then bare numbers (_NUMBERS); then everything between the first and
# the last quote of a kind goes, because an echoed value may itself contain
# quotes (PostgreSQL prints a whole row as "(1,"Jane Doe",...)" without
# escaping them).
_VALUE_ECHOES = (
    re.compile(r"(?i)(cannot parse string ).*(?= as )"),
    # ClickHouse: Cannot parse uuid <value>: Cannot parse UUID from String
    # (also IPv4/IPv6, and 'date here: <value>')
    re.compile(r"(?i)(cannot parse )(?!string ).*(?=: cannot parse )"),
    re.compile(r"(?i)(converting the \w+ value ).*(?= to data type)"),
    # Oracle ORA-03302 details: the value runs to the end and may hold spaces
    re.compile(r"(?i)(invalid string value:?).*"),
    # PostgreSQL json input: CONTEXT: JSON data, line 1: <the input>
    re.compile(r"(?i)(json data, line \d+: ).*"),
    # PostgreSQL XML input (::xml, xmlparse, xpath): libxml's DETAIL repeats
    # the input line, and names taken from it, unquoted: invalid XML content
    # DETAIL:  line 1: Premature end of data in tag a line 1 <a>MB-ALPHA ^
    re.compile(r"(?i)((?:invalid xml (?:content|document)|could not parse xml document) ?).+"),
    re.compile(r"(?i)(detail: +line \d+: ).*"),  # the same libxml detail under any other message
    re.compile(r"(?i)(\bhere: )[^:]*"),  # ClickHouse: Cannot parse boolean value here: <value>, ...
)
# Drivers that render the whole diagnostic as a quoted string: pyodbc
# ('SQLSTATE', "[SQLSTATE] [vendor]...message") and PyMySQL (errno, 'message').
# Those quotes wrap the message, not an echoed value, so the message itself is
# sanitized instead of disappearing whole. Only the driver puts a wrapper at
# the very start of its text (after the exception class names) and closes it
# at the very end; a wrapper-shaped fragment anywhere else is an echoed value
# a statement built to look like one ('[AAAAA] [' || callsign).
_WRAPPED_DIAGNOSTICS = (
    re.compile(r"""(?P<head>(?:\w+: )*\((['"])[0-9A-Z]{5}\2, )(?P<q>['"])(?P<body>\[[0-9A-Z]{5}\] ?\[.*)(?P=q)\)"""),
    re.compile(r"""(?P<head>(?:\w+: )*\(\d+, )(?P<q>['"])(?P<body>.*)(?P=q)\)"""),
)
# Engines also print values as bare numbers - PostgreSQL "requested character
# too large for encoding: 77000000" and "time field value out of range:
# 77:00:00", SQL Server "value = 123456789" - and a statement can scale a
# value, or one character of it, into any message that prints a number. So
# every number goes, except the engine's own codes and positions in the text
# the caller wrote (group 1).
_KEPT_NUMBERS = (
    r"[Cc]ode:? -?\d+"  # ClickHouse: code: 376, Code: 6
    r"|SQLSTATE[= ]?\w{5}|SQLCODE[= ]?-?\d+"  # Db2
    r"|\[[0-9A-Z]{5}\]"  # ODBC: [22018]
    r"|\(\d+\)(?= \(SQL\w+\))"  # the native error pyodbc appends: (245) (SQLExecDirectW)
    r"|ODBC Driver \d+"
    r"|LINE \d+:"  # psycopg: the line of the caller's statement
    r"|argument \d+"  # an argument's place in the call the caller wrote
    r"|version [\d.]+"
)
_NUMBERS = re.compile(
    rf"({_KEPT_NUMBERS})"
    # a number not glued to a word (Int32, SQL0138N, ORA-01722): digits with the
    # separators of dates, times and decimals, an exponent, or hex
    r"|(?<![\w$#])(?<![A-Za-z]-)[-+]?(?:0[xX][0-9A-Fa-f]+|\d+(?:[.:/,-]\d+)*(?:[eE][-+]?\d+)?)(?![\w$#])"
)


def _sanitize_driver_text(text: str) -> str:
    """Driver error text with quoted fragments, numbers and known value
    echoes replaced by ``<redacted>``; the exception class name, SQLSTATE and
    engine error code survive. Deliberately not gated on the statement naming
    a sensitive column: a whole-row cast leaks without naming one."""
    for wrapper in _WRAPPED_DIAGNOSTICS:
        found = wrapper.fullmatch(text)
        if found:
            quote = found.group("q")
            return f"{found.group('head')}{quote}{_redact_echoes(found.group('body'))}{quote})"
    return _redact_echoes(text)


def _redact_echoes(text: str) -> str:
    """One diagnostic message with its value echoes, numbers and quoted
    fragments replaced (never unwrapped again: a wrapper inside a message is
    an echo)."""
    for pat in _VALUE_ECHOES:
        text = pat.sub(r"\1<redacted>", text)
    text = _NUMBERS.sub(lambda m: m.group(1) or "<redacted>", text)

    def is_quote(i: int) -> bool:
        ch = text[i]
        if ch == '"':
            return True
        # an apostrophe inside a word (doesn't, O'Brien) neither opens nor closes
        return ch == "'" and not (0 < i < len(text) - 1 and text[i - 1].isalnum() and text[i + 1].isalnum())

    out: list[str] = []
    i = 0
    while i < len(text):
        if not is_quote(i):
            out.append(text[i])
            i += 1
            continue
        last = len(text) - 1  # the last quote of the same kind; unterminated runs to the end
        while last > i and not (text[last] == text[i] and is_quote(last)):
            last -= 1
        out.append("<redacted>")
        i = len(text) if last == i else last + 1
    return "".join(out)


_RAISE_OPCODE = dis.opmap["RAISE_VARARGS"]


def _unchained(exc: BaseException) -> bool:
    return exc.__cause__ is None and (exc.__context__ is None or exc.__suppress_context__)


def _raised_here(exc: BaseException) -> bool:
    """Whether ``exc`` is a plain RuntimeError a ``raise`` statement of this
    package raised on no other exception: a connector's own diagnostic (SQL
    Server: the ODBC driver it needs is not installed, naming the installed
    ones; a tls.ca_file the OS does not trust), which translated_driver_errors
    wraps like a driver's. A driver's exception is never one: its class is
    the driver's, or it was raised inside a call (a C driver raising from the
    connector's line is a CALL there, not a RAISE)."""
    if type(exc) is not RuntimeError or not _unchained(exc):
        return False
    tb = exc.__traceback__
    while tb is not None and tb.tb_next is not None:
        tb = tb.tb_next
    if tb is None or not str(tb.tb_frame.f_globals.get("__name__", "")).startswith("universal_db_mcp."):
        return False
    code = tb.tb_frame.f_code.co_code
    return 0 <= tb.tb_lasti < len(code) and code[tb.tb_lasti] == _RAISE_OPCODE


def _own_text(exc: BaseException) -> bool:
    """Whether a failure's text was written by this server or a connector,
    not by a driver: a ToolFailure, or a ConnectorError raised on no driver
    exception (no cause, and no context it did not suppress) - a connector's
    own refusal, whose numbers are what the caller acts on (ClickHouse: more
    than 8 MiB on 1-row blocks) - or one wrapping the connector's own
    RuntimeError (_raised_here). A connector that words a driver error
    raises from it, so that text is sanitized."""
    if isinstance(exc, ToolFailure):
        return True
    if not isinstance(exc, ConnectorError):
        return False
    if exc.__cause__ is not None and exc.__context__ is exc.__cause__:
        return _raised_here(exc.__cause__)
    return _unchained(exc)


def _error_text(exc: BaseException) -> str:
    """One-line text of a failure for an error entry or a warning: the
    server's and the connectors' own messages as written, anything else
    (driver text) sanitized."""
    text = scrub_exception(exc)
    return text if _own_text(exc) else _sanitize_driver_text(text)


# An absolute file path (POSIX, a Windows drive or a UNC share, spaces
# included) in a Python error, up to a quote, a parenthesis or ': ' (x.so:
# undefined symbol)
_ABSOLUTE_PATH = re.compile(r"(?<![\w.])(?:/|[A-Za-z]:\\|\\\\)(?:[^'\"()\n:]|:(?! ))+")


def _construction_error_text(exc: BaseException) -> str:
    """The text of a failure to build a connector. An OSError or ImportError
    while its module loads names the file (Too many open files:
    '/opt/.../connectors/sqlite.py'): the install path is not the caller's
    business, and neither is anything else such text quotes."""
    text = _error_text(exc)
    return text if _own_text(exc) else _ABSOLUTE_PATH.sub("<path>", text)


def _connector_error_category(exc: ConnectorError) -> str:
    """A connector marks an error the engine raised while running a statement
    (a data or SQL error) with a category; anything else from the database
    layer is a connection failure."""
    category = getattr(exc, "category", None)
    return category if isinstance(category, str) and category else ErrorCategory.CONNECTION


def _failure_outcome(category: str) -> str:
    """Audit outcome of a failed call, by its category whoever raised it: a
    refusal (the guard's, the policy's, or a connector's own - SQL Server's
    multi-statement check raises POLICY_VIOLATION) is a deny; a failed
    connection or statement is an error, and so is a statement that ran out
    of time, whether the executor's deadline or the engine's own statement
    ceiling (57014, SQL0952N, HYT00, MySQL 3024, DPY-4024) stopped it."""
    failed = (ErrorCategory.CONNECTION, ErrorCategory.QUERY, ErrorCategory.INTERNAL, ErrorCategory.TIMEOUT)
    return "error" if category in failed else "deny"


def _audit_status(app: AppContext, warnings: list[str]) -> dict[str, Any]:
    """The audit log's state, server-wide (db_list_connections and
    db_test_connection): with audit_fail_closed false a failed audit write
    lets the call go ahead, and only this counter remembers it."""
    dropped = app.audit.dropped_records
    if not app.cfg.application.audit_path:
        warnings.append("application.audit_path is unset: tool calls are not audited")
    elif dropped:
        warnings.append(
            f"{dropped} audit record(s) could not be written since this server started "
            "(application.audit_fail_closed=false, so those calls ran unaudited); check the audit "
            "path's disk space and permissions"
        )
    return {
        "path": app.cfg.application.audit_path,
        "fail_closed": app.cfg.application.audit_fail_closed,
        "dropped_records": dropped,
    }


def _audit_connection_id(app: AppContext, connection_id: str | None) -> dict[str, Any]:
    """The connection fields of an audit or history record. A configured
    id, or any id short enough to be harmless, is recorded as sent; a longer
    value that is not configured (it can be megabytes over HTTP, and denied
    calls are cheap) is recorded as a marker with its length and digest, so
    a denied call's record stays small and pins no memory in the history
    (AuditLog.record_refusal bounds how many are written)."""
    if connection_id is None or len(connection_id) <= _ID_TEXT_CHARS or connection_id in app.resolved:
        return {"connection_id": connection_id}
    return {
        "connection_id": "<unknown>",
        "connection_id_sha256": hashlib.sha256(connection_id.encode("utf-8", "surrogatepass")).hexdigest(),
        "connection_id_len": len(connection_id),
    }


_SqlKept = Literal["text", "digest", "length"]


def _audit_sql(app: AppContext, sql: str, *, keep: _SqlKept = "text") -> tuple[dict[str, Any], dict[str, Any]]:
    """(record fields, audit-only fields) of one statement. The guard
    refuses statements over _MAX_SQL_BYTES, so only that prefix is
    fingerprinted and, with audit_sql_text, kept; a longer text is recorded
    by its length (and, with the text, its digest) - one call carrying
    megabytes of SQL cannot fill the audit log or hold the event loop. With
    audit_sql_text, ``keep`` says what else names the statement: its
    ``text``; only its length and ``digest``, for one that never reached a
    database (a caller can send it again and again for nothing); or only
    its ``length``, where the call's ':statement' record holds the text
    (the text is kept once per call; the AuditLog also caps how much is
    written per window). No unsalted digest of the unredacted statement
    sits beside its redacted text, where it would confirm a guess of a
    scrubbed literal."""
    prefix = sql[:_MAX_SQL_BYTES]
    record: dict[str, Any] = {"sql_fingerprint": sql_fingerprint(prefix) if prefix else None}
    audit_only: dict[str, Any] = {}
    if len(sql) > _MAX_SQL_BYTES:
        record["sql_len"] = len(sql)
    if not app.cfg.security.audit_sql_text:
        return record, audit_only
    if keep == "text":
        # Even when raw SQL text is explicitly enabled by policy it must
        # pass through the redaction chokepoint: credential-shaped
        # literals (password=..., api_key=..., driver URLs) are scrubbed.
        audit_only["sql_text"] = redact_text(prefix)
        if len(sql) > _MAX_SQL_BYTES:
            audit_only["sql_text_truncated"] = True
            audit_only["sql_sha256"] = hashlib.sha256(sql.encode("utf-8", "surrogatepass")).hexdigest()
        return record, audit_only
    audit_only["sql_len"] = len(sql)
    if keep == "digest":
        audit_only["sql_sha256"] = hashlib.sha256(sql.encode("utf-8", "surrogatepass")).hexdigest()
    return record, audit_only


@asynccontextmanager
async def tool_span(
    app: AppContext,
    tool: str,
    connection_id: str | None = None,
    sql: str | None = None,
) -> AsyncIterator[dict[str, Any]]:
    """Request lifecycle: timing, audit, structured error mapping, history.

    ``state['executed']`` says whether the call's statement reached a
    database: the executor's worker began the driver call (_sends). Left
    unset, a call that succeeded is taken to have sent it, and one that
    failed not (an unknown connection, invalid arguments, the guard, the
    executor's own refusals, a cancellation in line). A call that sent
    nothing is recorded without its SQL text, and one that also failed
    (deny or error) through AuditLog.record_refusal, which coalesces
    repeats."""
    start = time.monotonic()
    request_id = new_request_id()
    state: dict[str, Any] = {
        "request_id": request_id, "tool": tool, "start": start, "row_count": None, "warnings": [],
    }
    if sql is not None:
        state["statement"] = (connection_id, sql)  # the statement this span's own record describes
    outcome = "allow"
    category = None
    try:
        yield state
        size = state.get("response_bytes")
        if size is not None and size > app.cfg.security.max_response_bytes + _RESPONSE_SLACK:
            # The backstop behind every pager: a result far past the ceiling
            # (a path that pages by count only, one enormous object) is
            # refused, and audited as such, instead of being sent twice
            # (structured content and text).
            raise ToolFailure(
                ErrorCategory.LIMIT,
                f"the response would be {size} bytes, over security.max_response_bytes "
                f"({app.cfg.security.max_response_bytes}); narrow the request (a schema, one object, fewer "
                "columns or a smaller page)",
            )
    except ToolFailure as exc:
        outcome, category = _failure_outcome(exc.category), exc.category
        raise ToolError(_bounded_error(str(exc))) from exc
    except DriverUnavailableError as exc:
        outcome, category = "deny", ErrorCategory.DRIVER_MISSING
        raise ToolError(_bounded_error(f"{ErrorCategory.DRIVER_MISSING}: {exc}")) from exc
    except ConnectorError as exc:
        # a data or SQL error is not a network problem; and whatever the
        # engine quoted back (the offending value) never reaches the caller
        category = _connector_error_category(exc)
        outcome = _failure_outcome(category)
        raise ToolError(f"{category}: {_error_text(exc)}") from exc
    except ObjectNotFound as exc:
        # Only a genuine "that object is not there" is the caller's problem.
        # This used to catch bare LookupError, whose subclasses KeyError and
        # IndexError are raised by driver and catalog code: a server-side bug
        # was reported to the model as ITS invalid arguments and audited as a
        # policy deny.
        outcome, category = "deny", ErrorCategory.VALIDATION
        raise ToolError(_bounded_error(f"{ErrorCategory.VALIDATION}: {redact_text(str(exc))}")) from exc
    except NotImplementedError as exc:
        # A capability the connector declares unsupported (db_get_capabilities
        # already says so); reporting it as INTERNAL_ERROR invited bug reports
        # for a documented limitation.
        outcome, category = "deny", ErrorCategory.CAPABILITY
        raise ToolError(_bounded_error(f"{ErrorCategory.CAPABILITY}: {redact_text(str(exc))}")) from exc
    except anyio.get_cancelled_exc_class():
        # Cancellation (client disconnect, shutdown) is not an error: it is a
        # request that happened and must still leave an audit trail below.
        outcome, category = "cancelled", None
        raise
    except AuditWriteFailure:
        raise
    except Exception as exc:  # noqa: BLE001
        outcome, category = "error", ErrorCategory.INTERNAL
        # an unwrapped driver exception lands here with the engine's text
        raise ToolError(f"{ErrorCategory.INTERNAL}: {_error_text(exc)}") from exc
    finally:
        elapsed = int((time.monotonic() - start) * 1000)
        sent = bool(state.get("executed", outcome == "allow"))
        # the text is kept once: a ':statement' record of this statement has it
        keep: _SqlKept = "length" if state.get("statement_text_recorded") else "text" if sent else "digest"
        sql_fields, sql_audit = (
            _audit_sql(app, sql, keep=keep) if sql is not None else ({"sql_fingerprint": None}, {})
        )
        record = {
            "request_id": request_id,
            "action": tool,
            **_audit_connection_id(app, connection_id),
            "outcome": outcome,
            "elapsed_ms": elapsed,
            **sql_fields,
            "row_count": state.get("row_count"),
        }
        if state.get("connection_ids") is not None:
            # a cross-connection tool names the connections it actually read
            record["connection_ids"] = state["connection_ids"]
        if category:
            record["category"] = category
        if state.get("warnings"):
            # the audit log and the history keep warnings even when result
            # rows are not audited: every warning built from driver text was
            # sanitized where it was built (_error_text), and the server's own
            # text is kept as the caller saw it
            record["warnings"] = [str(w) for w in state["warnings"][:5]]
        audit_record = {
            "event": "tool_call",
            **_caller_fields(app),
            **redact_value(record),
        }
        audit_record.update(sql_audit)
        if outcome == "cancelled":
            # A query may have been in flight when the request was cancelled;
            # the worker thread cannot be interrupted, so the connector's
            # driver state is unknown and the connection must be discarded.
            conn_obj = state.get("connector")
            if conn_obj is not None:
                _mark_poisoned(app.poisoned_connectors, conn_obj)
        # The write is awaited inside a shielded scope: under an active outer
        # cancellation every unprotected await raises immediately (anyio
        # cancel-scope semantics), which used to drop the audit record of a
        # query that actually ran and defeated audit_fail_closed.
        with anyio.CancelScope(shield=True):
            try:
                # fsync + rotation are blocking; never run them on the event loop
                await anyio.to_thread.run_sync(_audit_writer(app, _coalesced(outcome, sent)), audit_record)
            except AuditWriteFailure as audit_exc:
                app.record_history({**record, "ts": _now()})
                raise ToolError(f"{ErrorCategory.CONFIG}: {audit_exc}") from audit_exc
        app.record_history({**record, "ts": _now()})


def _coalesced(outcome: str, sent: bool) -> bool:
    """Whether a record goes through AuditLog.record_refusal: a call that
    failed (deny or error) without sending anything to a database cost its
    caller nothing. A statement that reached a database keeps every record,
    whatever its outcome, and so does a call that returned something, or
    one its caller cancelled."""
    return not sent and outcome in ("deny", "error")


def _sends(*states: dict[str, Any]) -> Callable[[], None]:
    """The executor's on_start hook: marks each of ``states`` executed once
    the worker begins the driver call, so a call refused or given up before
    then (the breaker, the connection's gate, the token or server-share
    wait, a cancellation in line) is audited as one that sent nothing, and
    one cancelled after as one that sent its statement."""

    def started() -> None:
        for state in states:
            state["executed"] = True

    return started


def _audit_writer(app: AppContext, coalesce: bool, kind_action: str | None = None) -> Callable[[dict[str, Any]], None]:
    """How a record is written: one of a call that failed before anything
    was sent is coalesced with its kind's repeats (AuditLog.record_refusal)."""
    if coalesce:
        return functools.partial(app.audit.record_refusal, kind_action=kind_action)
    return app.audit.record


def _close_quietly(close: Callable[[], object]) -> None:
    """Best effort: a discarded connector's sessions go at exit or garbage
    collection anyway."""
    with suppress(Exception):
        close()


def _mark_poisoned(poisoned: set[int], connector: object) -> None:
    """Record a connector whose driver state is uncertain (its request was
    cancelled mid-query). It is held by id, so the record never keeps it
    alive, and the id leaves the set when the connector is freed - before
    CPython can hand its address to a new object. A plain id used to stay
    for the life of the process, and a healthy connector allocated at that
    address later was discarded and rebuilt."""
    key = id(connector)
    if key not in poisoned:
        try:
            weakref.finalize(connector, poisoned.discard, key)
        except TypeError:
            pass  # not weakly referenceable: the id goes when connection() discards the connector
    poisoned.add(key)


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


class _Serialized(dict[str, Any]):
    """An envelope together with the compact JSON text it was measured as
    for the response ceiling: that text is the block the client receives, so
    a response is serialized once, not once to measure and once to send."""

    __slots__ = ("text",)

    def __init__(self, data: dict[str, Any], text: str) -> None:
        super().__init__(data)
        self.text = text


def _compact_result(data: dict[str, Any]) -> CallToolResult:
    """One compact JSON text block plus the same dict as structured content."""
    if isinstance(data, _Serialized):
        text = data.text
    else:
        text = json.dumps(data, separators=(",", ":"), ensure_ascii=False, default=str)
    return CallToolResult(content=[TextContent(type="text", text=text)], structured_content=data)


def _bounded_warnings(warnings: list[str]) -> list[str]:
    """At most _MAX_WARNINGS warnings of at most 1000 characters: a search
    over hundreds of failing tables must not outgrow the payload it annotates."""
    def one(w: str) -> str:
        return w if len(w) <= 1000 else w[:999] + "…"

    if len(warnings) <= _MAX_WARNINGS:
        return [one(w) for w in warnings]
    shown = [one(w) for w in warnings[: _MAX_WARNINGS - 1]]
    return [*shown, f"{len(warnings) - len(shown)} further warning(s) omitted"]


def _envelope(
    st: dict[str, Any], connection_id: str | None, engine: str | None, data: Any, **kw: Any
) -> dict[str, Any]:
    if "warnings" in kw:
        kw["warnings"] = _bounded_warnings(kw["warnings"])
    env = Envelope(
        request_id=st["request_id"],
        connection_id=connection_id,
        engine=engine,
        data=data,
        elapsed_ms=int((time.monotonic() - st["start"]) * 1000),
        **kw,
    )
    out = env.model_dump(exclude_none=True)
    text = json.dumps(out, separators=(",", ":"), ensure_ascii=False, default=str)
    st["response_bytes"] = len(text.encode("utf-8", "replace"))  # checked against the ceiling when the span closes
    return _Serialized(out, text)


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
    *,
    on_start: Callable[[], object] | None = None,
) -> Any:
    connector, policy = app.connection(connection_id)
    return await app.executor.run_bounded(
        connector,
        lambda c: c.execute_query(spec),
        spec.timeout_seconds,
        description=description,
        on_start=on_start,
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
    render: Callable[[Any], Any] | None = None,
    st: dict[str, Any] | None = None,
) -> tuple[list[Any], str | None]:
    """Opaque, identity/policy/expiry-bound pagination. With ``render`` the
    page holds the rendered items and also ends before the first one that
    would take it past security.max_response_bytes (a warning goes to ``st``);
    the cursor resumes exactly there."""
    offset = _cursor_offset(app, cursor, kind=kind, connection_id=connection_id, policy=policy)
    end = max(offset, min(offset + page_size, len(items)))
    window = items[offset:end]
    if render is not None:
        window, cut = _page_bytes(window, 0, _item_budget(policy.max_response_bytes), render)
        if offset + cut < end and st is not None:
            st["warnings"].append(_byte_cut_warning(cut, end - offset))
        end = offset + cut
    next_cursor = None
    if end < len(items):
        next_cursor = _cursor_for(app, end, kind=kind, connection_id=connection_id, policy=policy)
    return window, next_cursor


def _page_bytes(
    items: list[Any], offset: int, budget: int, serialize: Callable[[Any], Any]
) -> tuple[list[Any], int]:
    """The serialized items from ``offset`` on, cut before the first one
    that would take their compact JSON past ``budget`` UTF-8 bytes. The first
    item is always kept, so every page makes progress. Returns (kept, the
    offset a cursor resumes at)."""
    kept: list[Any] = []
    used = 0
    for item in itertools.islice(items, offset, None):
        out = serialize(item)
        size = _json_size(out)
        if kept and used + size > budget:
            break
        used += size
        kept.append(out)
    return kept, offset + len(kept)


def _byte_cut_warning(kept: int, of: int) -> str:
    return (
        f"response byte ceiling (security.max_response_bytes) reached after {kept} of {of} item(s); "
        "continue with the cursor"
    )


def _fit_entries(
    st: dict[str, Any], entries: list[dict[str, Any]], budget: int, size: Callable[[dict[str, Any]], int], part: str
) -> list[dict[str, Any]]:
    """The leading entries (tables of a catalog or data dictionary page)
    that fit ``budget``; a caller's cursor resumes after them. A first entry
    that does not fit even alone keeps the leading ``part`` items (its
    columns) that do, rather than breaking the ceiling or never ending."""
    kept: list[dict[str, Any]] = []
    used = 0
    for entry in entries:
        n = size(entry)
        if kept and used + n > budget:
            st["warnings"].append(_byte_cut_warning(len(kept), len(entries)))
            break
        if not kept and n > budget:
            n = _trim_entry(st, entry, budget, size, part)
        used += n
        kept.append(entry)
    return kept


def _trim_entry(
    st: dict[str, Any], entry: dict[str, Any], budget: int, size: Callable[[dict[str, Any]], int], part: str
) -> int:
    """Keep the most leading ``entry[part]`` items that fit ``budget`` (a
    binary search: sizing re-renders the entry), mark ``<part>_truncated``
    and say so. Returns the entry's new size."""
    items = list(entry.get(part) or [])
    lo, hi = 0, len(items)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if size({**entry, part: items[:mid]}) <= budget:
            lo = mid
        else:
            hi = mid - 1
    entry[part] = items[:lo]
    entry[f"{part}_truncated"] = True
    name = ".".join(str(x) for x in (entry.get("schema"), entry.get("name")) if x)
    st["warnings"].append(
        f"{name}: only the first {lo} of {len(items)} {part} fit security.max_response_bytes; "
        + ("db_list_columns pages through them" if part == "columns" else "narrow the request")
    )
    return size(entry)


def _cap_text(value: Any, policy: EffectivePolicy, st: dict[str, Any] | None) -> Any:
    """Catalog text (a view or table definition, a comment) cut to
    security.max_cell_bytes like a result cell."""
    if not isinstance(value, str):
        return value
    text, cut = capped_text(value, policy.max_cell_bytes)
    if cut and st is not None:
        warning = (
            f"definition or comment text longer than security.max_cell_bytes ({policy.max_cell_bytes}) "
            "was truncated"
        )
        if warning not in st["warnings"]:
            st["warnings"].append(warning)
    return text


def _cursor_offset(
    app: AppContext, cursor: str | None, *, kind: str, connection_id: str, policy: EffectivePolicy
) -> int:
    if not cursor:
        return 0
    body = app.cursors.decode(
        cursor,
        expect_identity=app.identity,
        expect_connection=connection_id,
        expect_kind=kind,
        policy_fingerprint=policy_fingerprint(policy),
    )
    return int(body.get("offset", 0))


def _cursor_for(app: AppContext, offset: int, *, kind: str, connection_id: str, policy: EffectivePolicy) -> str:
    """A cursor that resumes at ``offset``: tools that stop a page early (time
    or byte budget) hand back exactly the position they reached, so no item
    is skipped."""
    return app.cursors.encode(
        {
            "offset": int(offset),
            "identity": app.identity,
            "connection_id": connection_id,
            "kind": kind,
            "policy": policy_fingerprint(policy),
        }
    )


def _filtered_kind(kind: str, *filters: Any) -> str:
    """A cursor kind bound to the filter arguments of the listing it pages:
    an offset taken from one list (unfiltered, another schema or search) and
    applied to another returned the wrong page, or an empty one reported as
    complete."""
    digest = hashlib.sha256(json.dumps(filters, default=str).encode("utf-8", "surrogatepass")).hexdigest()
    return f"{kind}:{digest[:16]}"


def _sensitive_name(patterns: Iterable[re.Pattern[str]], name: str) -> bool:
    """Whether a column name matches an administrator's mask pattern in any
    spelling an engine folds it to: Oracle and Db2 report an unquoted name in
    upper case, PostgreSQL in lower case, so a case-sensitive pattern must
    see either - in a statement, a driver's column list and the catalog alike.
    A name outside ASCII or with blanks around it is also matched in its NFKC
    form, stripped: SQL Server read ＭＲＮ and [MRN ] as MRN, and Db2 "SSN "
    as SSN (the guard refuses those spellings there; this is the second line)."""
    spellings = {name, name.lower(), name.upper()}
    if not name.isascii() or name != name.strip():
        folded = unicodedata.normalize("NFKC", name).strip()
        spellings |= {folded, folded.lower(), folded.upper()}
    return any(pat.search(spelling) for pat in patterns for spelling in spellings)


def _names_masked_columns(policy: EffectivePolicy, ast: exp.Expression) -> bool:
    """Whether a validated statement may name a column masking hides: a name
    the mask patterns match (a column, an alias, USING's), or a column it
    names without writing it - a star other than COUNT(*)'s, a NATURAL join."""
    for node in ast.walk():
        if isinstance(node, exp.Identifier) and _sensitive_name(policy.sensitive_patterns, node.name):
            return True
        if isinstance(node, exp.Star) and not isinstance(node.parent, exp.Count):
            return True
        if isinstance(node, exp.Join) and str(node.args.get("method") or "").upper() == "NATURAL":
            return True
    return False


def _tabular_plan(plan: Any) -> bool:
    """A MySQL plan in the tabular format (FORMAT=TRADITIONAL, MariaDB's
    plain EXPLAIN): rows of several columns, where TREE and JSON are one."""
    rows = plan.get("raw") if isinstance(plan, dict) else None
    return isinstance(rows, list) and bool(rows) and all(isinstance(r, list) and len(r) > 1 for r in rows)


def _sensitive_output_names(policy: EffectivePolicy, ast: exp.Expression) -> frozenset[str]:
    """Lowercased output names that expose a sensitive source column, even
    under an alias or through a derived table / CTE. A projection's emitted
    name is tainted when the expression behind it references a sensitive
    column or a name that is already tainted; the fixpoint follows alias
    chains across scopes (``SELECT password AS p``, ``SELECT p FROM
    (SELECT password AS p ...) sub``, CTEs). A name alone never proves a
    column clean - drivers report generic names for unaliased expressions
    ('upper', '1', '') and set operations carry the first branch's names -
    so this is only an extra check on top of the positional taint of
    :func:`_sensitive_output_positions`."""
    if not policy.sensitive_patterns:
        return frozenset()

    def sensitive(name: str) -> bool:
        return _sensitive_name(policy.sensitive_patterns, name)

    # A worklist over "name -> the outputs that read it": linear in the
    # statement. Re-scanning every projection until nothing grew was
    # quadratic in an alias chain (14 s for a 60 KiB statement).
    tainted: set[str] = set()
    readers: dict[str, list[str]] = {}
    pending: list[str] = []
    for proj in (p for sel in ast.find_all(exp.Select) for p in sel.expressions):
        out = proj.alias_or_name.lower()
        if not out:
            continue
        refs = [c.name for c in proj.find_all(exp.Column)]
        if any(sensitive(r) for r in refs):
            pending.append(out)
        for ref in refs:
            readers.setdefault(ref.lower(), []).append(out)
    while pending:
        name = pending.pop()
        if name not in tainted:
            tainted.add(name)
            pending.extend(readers.get(name, ()))
    return frozenset(tainted)


# A run of output columns whose width only the driver knows: a star over a
# base table ("base": the driver reports the table's own column names, so the
# name heuristics decide) or columns that cannot be traced to their sources
# ("unknown": every one of them is treated as sensitive).
_SPREAD_BASE = "base"
_SPREAD_UNKNOWN = "unknown"
# The positional taint walk runs after the statement did, on a worker thread:
# rounds over the whole statement, and the time they may take, are bounded.
_TAINT_MAX_ROUNDS = 16
_TAINT_BUDGET_SECONDS = 2.0
# PostgreSQL reads t.fn as fn(t) when t has no column fn (attribute notation):
# these functions take a whole row and hand back its values (to_json,
# record_out, quote_literal, the aggregates), its hash or its size. They are
# the built-ins that resolve so on PostgreSQL 17 (pg_proc: one record,
# polymorphic or "any" argument), plus hstore and PostGIS; the ones that
# return nothing of the values (count, num_nulls, pg_typeof) are left out, so
# a table's own column of that name stays readable. A site's own function
# over a row type is known only where the source's columns are (a derived
# table or CTE, or a base table whose columns _row_function_columns read from
# the catalog, directly or through a star that hands its row on): there any
# name that is not a column is a function.
_PG_ROW_FUNCTIONS = frozenset({
    "any_value", "array_agg", "concat", "hash_record", "json_agg", "json_agg_strict", "json_build_array",
    "jsonb_agg", "jsonb_agg_strict", "jsonb_build_array", "pg_column_size", "quote_literal", "quote_nullable",
    "record_out", "record_send", "row_to_json", "to_json", "to_jsonb",
    "hstore", "st_asflatgeobuf", "st_asgeobuf", "st_asgeojson", "st_asmvt",
})


@dataclasses.dataclass(frozen=True)
class _OutCol:
    """One traced output column: the name SQL gives it (lowercased; None
    when the engine invents one) and whether its value can carry a
    sensitive source value."""

    name: str | None
    tainted: bool
    # the name is an alias the statement wrote, which every engine reports as
    # the column's name (_map_positions checks the layout against it)
    explicit: bool = False


_OutItem = _OutCol | str  # a traced column or a _SPREAD_* run
# A qualifier the analysis cannot bind to one source: two FROM items whose
# names differ only in case, where the engine may bind either (_lookup).
_AMBIGUOUS = object()
# A name made only of word characters: the names SQLite gives an unaliased
# expression ("upper(x)", "+x") or a duplicate column ("x:1") never are.
_PLAIN_NAME = re.compile(r"[^\W\d]\w*")
# Bare names an engine answers itself where no source has such a column
# (Oracle's ROWNUM in a pagination wrapper, SQLite's rowid): no value of a
# source column.
_PSEUDO_COLUMNS = frozenset({
    "rownum", "level", "rowid", "ora_rowscn", "sysdate", "systimestamp", "user", "uid", "_rowid_", "oid",
    "ctid", "xmin", "xmax", "cmin", "cmax", "tableoid", "current_date", "current_time", "current_timestamp",
    "localtime", "localtimestamp", "current_user", "session_user",
})


def _engine_named(node: exp.Expr) -> str | None:
    """The name an engine gives an unaliased output: a column's (through
    parentheses and COLLATE, as PostgreSQL and SQLite name ``(x)`` and ``x
    COLLATE nocase`` x), else None - a name the engine makes up."""
    while isinstance(node, exp.Paren | exp.Collate):
        node = node.this
    if isinstance(node, exp.Column) and not isinstance(node.this, exp.Star):
        return node.name.lower() or None
    return None


def _expands(node: exp.Expr) -> bool:
    """A select item that is several output columns: PostgreSQL's composite
    expansion ``(expr).*`` and ClickHouse's ``untuple(t)``."""
    if isinstance(node, exp.Dot) and isinstance(node.expression, exp.Star):
        return True
    return isinstance(node, exp.Anonymous) and str(node.this).lower() == "untuple"


class _TableSpread(str):
    """A _SPREAD_BASE run (equal to it wherever positions are laid out) over
    base tables whose column names the catalog listed: ``columns`` holds
    every name the run can output, as the catalog spells them."""

    columns: frozenset[str]

    def __new__(cls, columns: frozenset[str]) -> _TableSpread:
        run = super().__new__(cls, _SPREAD_BASE)
        run.columns = columns
        return run


class _Untraceable(Exception):
    """The statement's output columns cannot be mapped to their sources."""


def _tainted_out_names(items: list[_OutItem]) -> set[str]:
    return {i.name for i in items if isinstance(i, _OutCol) and i.tainted and i.name}


@dataclasses.dataclass(frozen=True)
class _OutIndex:
    """One scope's traced output, indexed for lookups by name."""

    names: dict[str, bool]  # name -> whether a column of that name is tainted
    unknown: bool  # an untraceable run
    anonymous: bool  # an engine-named tainted column
    row: bool  # the row used as a value may carry a sensitive value
    spread: bool  # a run of columns whose names only the driver knows
    # every name the runs can output, when the catalog listed them all (_TableSpread)
    spread_columns: frozenset[str] | None = None
    # the catalog listed some of the runs' tables but not every run (a star
    # over a table and unnest or VALUES): a name may be a function of the row
    partly_listed: bool = False

    @classmethod
    def of(cls, items: list[_OutItem]) -> _OutIndex:
        names: dict[str, bool] = {}
        for item in items:
            if isinstance(item, _OutCol) and item.name:
                names[item.name] = names.get(item.name, False) or item.tainted
        runs = [i for i in items if isinstance(i, str)]
        listed = [i.columns for i in runs if isinstance(i, _TableSpread)]
        return cls(
            names,
            unknown=_SPREAD_UNKNOWN in items,
            anonymous=any(isinstance(i, _OutCol) and i.name is None and i.tainted for i in items),
            row=any(not isinstance(i, _OutCol) or i.tainted for i in items),
            spread=bool(runs),
            spread_columns=frozenset().union(*listed) if len(listed) == len(runs) else None,
            partly_listed=bool(listed) and len(listed) != len(runs),
        )


_NO_OUTPUT = _OutIndex({}, unknown=False, anonymous=False, row=False, spread=False)  # not evaluated yet


@dataclasses.dataclass
class _Reach:
    """What an unqualified name can read in one scope, merged over every
    candidate source so a lookup costs the same with 1 or 1000 FROM items."""

    always: bool = False  # a source the analysis cannot see into: every name is suspect
    tainted: set[str] = dataclasses.field(default_factory=set)
    known: set[str] = dataclasses.field(default_factory=set)  # every name a derived source outputs
    closed: bool = True  # every source is a derived one whose every output name is known
    scope_row: bool = False  # a derived source's row may carry a sensitive value
    anonymous: int = 0  # sources with an engine-named tainted column
    named_in_anonymous: dict[str, int] = dataclasses.field(default_factory=dict)
    rows: dict[str, bool] = dataclasses.field(default_factory=dict)  # alias -> its row is tainted
    any_row: bool = False


class _OutputTaint:
    """Positional taint of a validated statement's output columns.

    Scopes (CTEs, derived tables, set-operation branches, subqueries, table
    functions) are evaluated innermost first. A projection is tainted when a
    column in it resolves to a sensitive source column, to a tainted output
    of an inner scope (by name, or by position through an explicit column
    list such as ``WITH t(a)``, ``AS q(a)`` or ``customers AS t(a, b)``), to
    an alias the scope defines anywhere (ClickHouse resolves ``(ssn AS x)``
    from WHERE in the SELECT list), or to a whole row that may hold one
    (``CAST(t AS text)``, ``to_json(t.*)``, ``COLUMNS('re')``); a scalar
    subquery taints it when anything the subquery reads is sensitive. A set
    operation taints a position when any branch does, and stars expand
    positionally over inner scopes. Recursive CTEs are iterated to a
    fixpoint. Whatever cannot be traced is tainted: the analysis fails
    closed. ``engine`` is the connection's engine: PostgreSQL alone reads
    ``t.fn`` as a function of t's whole row. ``table_columns`` holds the
    column names of base tables, by the id of their FROM item, where the
    catalog provided them (_row_function_columns)."""

    def __init__(
        self,
        patterns: list[re.Pattern[str]],
        ast: exp.Expression,
        engine: str = "",
        table_columns: dict[int, frozenset[str]] | None = None,
    ) -> None:
        self._patterns = patterns
        self._engine = engine
        self._row_functions = _PG_ROW_FUNCTIONS if engine == "postgres" else frozenset()
        self._table_columns = (table_columns or {}) if engine == "postgres" else {}
        self._scopes = list(traverse_scope(ast))
        if not self._scopes:
            raise _Untraceable("no query scope")
        if _cte_misbound(engine, ast, self._scopes):
            raise _Untraceable("the engine may bind a FROM item to a CTE where the analysis does not, or the reverse")
        if any(w.args.get("search") for w in ast.find_all(exp.With)) or any(
            s.args.get("match") for s in ast.find_all(exp.Select)
        ):
            # PostgreSQL's SEARCH/CYCLE add columns holding the BY columns'
            # values (ord, path) and Oracle's MATCH_RECOGNIZE computes
            # MEASURES over the rows: outputs this walk does not model
            raise _Untraceable("SEARCH/CYCLE or MATCH_RECOGNIZE output")
        self._scope_of = {id(s.expression): s for s in self._scopes}
        self._out: dict[int, list[_OutItem]] = {}
        self._index: dict[int, _OutIndex] = {}
        self._rollup: dict[int, bool] = {}  # anything the (sub)query reads is sensitive
        self._tainted_names: set[str] = set()
        # the tainted names a SELECT binds anywhere in it (_alias_closure)
        self._aliases: dict[int, set[str]] = {}
        # ClickHouse `WITH <expression> AS name` and `WITH (<subquery>) AS name`
        # bind a scalar, not a relation
        self._scalars = {
            cte.alias.lower(): cte.this
            for cte in ast.find_all(exp.CTE)
            if cte.args.get("scalar") or not isinstance(cte.this, exp.Query)
        }
        self._resolving: set[str] = set()
        self._candidates_of: dict[int, list[tuple[str, Any, Any]]] = {}
        self._named_of: dict[int, dict[str, list[tuple[Any, Any, exp.Identifier]]]] = {}
        self._reach_of: dict[int, _Reach] = {}  # rebuilt every round
        self._ref_index_of: dict[int, _OutIndex] = {}  # rebuilt every round

    def root_items(self) -> list[_OutItem]:
        root = self._scopes[-1]
        deadline = time.monotonic() + _TAINT_BUDGET_SECONDS
        # Scopes are visited innermost first and a SELECT's aliases are closed
        # over each other before its projections are traced, so one round
        # settles everything but back edges (recursive CTEs). A round is
        # linear in the statement; a statement that needs more rounds than
        # this, or more time, is untraceable - and so masked whole - instead
        # of holding a worker thread for one round per link of a chain.
        for _ in range(_TAINT_MAX_ROUNDS):
            before = (dict(self._out), dict(self._rollup), dict(self._aliases), len(self._tainted_names))
            self._reach_of.clear()
            self._ref_index_of.clear()
            for scope in self._scopes:
                if time.monotonic() > deadline:
                    raise _Untraceable("taint analysis over its time budget")
                key = id(scope.expression)
                if isinstance(scope.expression, exp.Select):
                    self._aliases[key] = self._alias_closure(scope)
                raw = self._scope_items(scope)
                self._aliases[key] = self._aliases.get(key, set()) | _tainted_out_names(raw)
                items = self._rename(raw, scope.outer_columns)
                self._out[key] = items
                self._index[key] = _OutIndex.of(items)
                self._tainted_names.update(n for n, tainted in self._index[key].names.items() if tainted)
                self._rollup[key] = not scope.is_root and (
                    self._index[key].row or self._expr_tainted(scope, scope.expression)
                )
            if (self._out, self._rollup, self._aliases, len(self._tainted_names)) == before:
                return self._out[id(root.expression)]
        raise _Untraceable("taint did not settle")

    def _sensitive(self, name: str) -> bool:
        return _sensitive_name(self._patterns, name)

    def _walk(self, node: exp.Expr) -> Iterator[exp.Expr]:
        """The nodes of ``node``'s own scope: a nested scope's query is
        yielded, never entered."""
        stack = [node]
        while stack:
            sub = stack.pop()
            yield sub
            if sub is node or id(sub) not in self._scope_of:
                stack.extend(sub.iter_expressions())

    def _own_scopes(self, scope: Scope) -> list[Scope]:
        """The child scopes inside ``scope``'s own expression; a table
        function's sources also hold the lateral FROM items before it."""
        found = []
        for source in scope.sources.values():
            if isinstance(source, Scope):
                node: exp.Expr | None = source.expression
                while node is not None and node is not scope.expression:
                    node = node.parent
                if node is not None:
                    found.append(source)
        return found

    def _scope_items(self, scope: Scope) -> list[_OutItem]:
        node = scope.expression
        if isinstance(node, exp.Select):
            items = [item for proj in node.expressions for item in self._projection(scope, proj)]
            for_ = node.args.get("for_")
            if isinstance(for_, exp.ForClause) and str(for_.args.get("kind") or "").upper() in ("JSON", "XML"):
                # SQL Server FOR JSON / FOR XML fold every row into one column
                # the driver names JSON_F52E2B61-... or XML_F52E2B61-...: it
                # carries every value the projections carry, a base table's
                # sensitive columns under a star included
                suspect = any(not isinstance(i, _OutCol) or i.tainted for i in items)
                return [_SPREAD_UNKNOWN if suspect else _OutCol(None, False)]
            return items
        if isinstance(node, exp.SetOperation):
            if len(scope.union_scopes) != 2:
                raise _Untraceable("set operation without two branches")
            left, right = (self._out.get(id(s.expression), []) for s in scope.union_scopes)
            return self._merge(left, right)
        own = self._own_scopes(scope)
        if isinstance(node, exp.Subquery | exp.Lateral) and len(own) == 1:
            return self._source_items(own[0])  # a parenthesized query or a LATERAL subquery
        if isinstance(node, exp.Table) and isinstance(node.this, exp.Identifier):
            # a parenthesized table (sqlglot reads PostgreSQL's `(TABLE t)`
            # so): the table's own columns, renamed by a column list after it
            return [self._table_run(node)]
        # a table-valued expression (VALUES, UNNEST, ...): its columns carry
        # whatever it reads
        tainted = self._expr_tainted(scope, node)
        if scope.outer_columns:
            return [_OutCol(None, tainted) for _ in scope.outer_columns]
        return [_SPREAD_UNKNOWN if tainted else _SPREAD_BASE]

    def _projection(self, scope: Scope, proj: exp.Expression) -> list[_OutItem]:
        if isinstance(proj, exp.Star) or (isinstance(proj, exp.Column) and isinstance(proj.this, exp.Star)):
            return self._expand_star(scope, proj)
        body = proj.unalias()
        if _expands(body):
            # (expr).* and untuple(t) are as many columns as the row has: a
            # run, never one column a star beside it would make up for
            return [_SPREAD_UNKNOWN if self._expr_tainted(scope, body.this) else _SPREAD_BASE]
        if isinstance(body, exp.Apply) or proj.find(exp.Columns):
            # ClickHouse `* APPLY(f)` and COLUMNS('re') expand to columns the
            # statement never names
            return [_SPREAD_UNKNOWN if self._expr_tainted(scope, proj) else _SPREAD_BASE]
        tainted = self._expr_tainted(scope, proj)
        if isinstance(proj, exp.Alias) and proj.alias:
            return [_OutCol(proj.alias.lower(), tainted, explicit=True)]
        return [_OutCol(_engine_named(body), tainted)]

    def _expand_star(self, scope: Scope, proj: exp.Expression) -> list[_OutItem]:
        star = proj.this if isinstance(proj, exp.Column) else proj
        if star.args.get("replace") or star.args.get("rename"):
            return [_SPREAD_UNKNOWN]  # a value may now sit under another column's name
        select = scope.expression
        joins = select.args.get("joins") or []
        if isinstance(proj, exp.Column) and proj.table:
            node, source = self._lookup(scope, proj.args["table"])
            parts = [self._source_items(source, node)]
        else:
            from_ = select.args.get("from_")
            nodes = [from_.this, *(j.this for j in joins)] if from_ is not None else []
            parts = [self._from_item_items(scope, n) for n in nodes]
        items = [item for part in parts for item in part]
        merged = len(parts) > 1 and any(
            j.args.get("using") or str(j.args.get("method") or "").upper() == "NATURAL" for j in joins
        )
        if merged or star.args.get("except_") or star.args.get("ilike"):
            # USING/NATURAL merge columns and EXCEPT/ILIKE drop some: positions shift
            suspect = any(i == _SPREAD_UNKNOWN if isinstance(i, str) else i.tainted for i in items)
            return [_SPREAD_UNKNOWN if suspect else self._spread_of(items)]
        return items

    @staticmethod
    def _spread_of(items: list[_OutItem]) -> str:
        """One run for ``items`` whose positions shift: it keeps the names
        they can have when every one of them is known."""
        names: set[str] = set()
        for item in items:
            if isinstance(item, _TableSpread):
                names |= item.columns
            elif isinstance(item, _OutCol) and item.name:
                names.add(item.name)
            else:
                return _SPREAD_BASE
        return _TableSpread(frozenset(names))

    def _from_item_items(self, scope: Scope, node: exp.Expression) -> list[_OutItem]:
        if node.args.get("pivots"):
            return [_SPREAD_UNKNOWN]  # PIVOT/UNPIVOT reshape the columns
        # a derived table or table function is found by identity: unaliased
        # ones (PostgreSQL 16+, ClickHouse) all share the alias ""
        inner = self._scope_of.get(id(node.this if isinstance(node, exp.Subquery) else node))
        if inner is not None:
            return self._source_items(inner)
        found = self._named(scope).get(node.alias_or_name.lower()) or []
        own = [e for e in found if e[0] is node]
        if own:
            return self._source_items(own[0][1], node)
        if found:
            return self._source_items(found[0][1] if len({id(e[1]) for e in found}) == 1 else _AMBIGUOUS, node)
        if isinstance(node, exp.Table | exp.Subquery):
            return [_SPREAD_UNKNOWN]
        # an expression joined as rows (ClickHouse ARRAY JOIN arr AS x)
        return [_SPREAD_UNKNOWN if self._expr_tainted(scope, node) else _SPREAD_BASE]

    @staticmethod
    def _source_key(source: Scope) -> int | None:
        """The key of a scope's output, or None when a PIVOT/UNPIVOT on the
        derived table reshapes it."""
        node = source.expression
        while isinstance(node.parent, exp.SetOperation):
            # a recursive CTE's self-reference is scoped to its anchor
            # branch; what it returns is the whole CTE's output
            node = node.parent
        if isinstance(node.parent, exp.Subquery) and node.parent.args.get("pivots"):
            return None
        return id(node)

    @staticmethod
    def _alias_columns(node: Any) -> list[str]:
        """The column list of a FROM item's alias (``customers AS t(a, b)``,
        ``cte AS d(w, x)``), which renames its columns positionally."""
        alias = node.args.get("alias") if isinstance(node, exp.Table) else None
        return [c.name for c in alias.columns] if isinstance(alias, exp.TableAlias) else []

    @classmethod
    def _renamed(cls, table: exp.Table) -> set[str]:
        return {c.lower() for c in cls._alias_columns(table)}

    def _source_items(self, source: Any, ref: Any = None) -> list[_OutItem]:
        """The output of ``source`` as the FROM item ``ref`` names it: a CTE
        referenced as ``t AS d(w, x)`` is renamed for that reference only."""
        if isinstance(source, Scope):
            key = self._source_key(source)
            # not evaluated yet (recursion): the fixpoint revisits it
            items: list[_OutItem] = [_SPREAD_UNKNOWN] if key is None else self._out.get(key, [])
            return self._rename(items, self._alias_columns(ref))
        if isinstance(source, exp.Table) and not source.args.get("pivots") and not self._renamed(source):
            return [self._table_run(source)]
        return [_SPREAD_UNKNOWN]

    def _table_run(self, table: exp.Table) -> str:
        """A base table's columns as one run, named when the catalog listed them."""
        known = self._table_columns.get(id(table))
        return _SPREAD_BASE if known is None else _TableSpread(known)

    def _ref_index(self, ref: Any, source: Scope) -> _OutIndex:
        """The indexed output of an evaluated scope as ``ref`` names it."""
        if not self._alias_columns(ref):
            key = self._source_key(source)
            return self._index.get(key, _NO_OUTPUT) if key is not None else _OutIndex.of([_SPREAD_UNKNOWN])
        index = self._ref_index_of.get(id(ref))
        if index is None:
            index = self._ref_index_of[id(ref)] = _OutIndex.of(self._source_items(source, ref))
        return index

    def _named(self, scope: Scope) -> dict[str, list[tuple[Any, Any, exp.Identifier]]]:
        """``scope``'s sources by lowercased name, each as (the FROM item that
        names it, or None for a CTE the scope does not select from; the
        source; the name as written). Names that differ only in case are
        kept apart (_lookup); a PIVOT/UNPIVOT's alias names its FROM item."""
        named = self._named_of.get(id(scope))
        if named is None:
            named = {}
            for alias, (node, source) in scope.selected_sources.items():
                for ident in self._source_names(alias, node):
                    named.setdefault(ident.name.lower(), []).append((node, source, ident))
            for alias, source in scope.sources.items():
                if alias not in scope.selected_sources:
                    named.setdefault(alias.lower(), []).append((None, source, exp.to_identifier(alias)))
            self._named_of[id(scope)] = named
        return named

    @staticmethod
    def _source_names(alias: str, node: Any) -> list[exp.Identifier]:
        """The identifiers that name a selected source: its alias (or bare
        table name) as written, quoting and all, and a PIVOT's alias."""
        if not isinstance(node, exp.Expression):
            return [exp.Identifier(this=alias, quoted=False)]
        written: list[Any] = []
        for holder in (node, node.parent):  # (TABLE t) q: q is the parenthesis's alias
            alias_node = holder.args.get("alias") if isinstance(holder, exp.Expression) else None
            if isinstance(alias_node, exp.TableAlias):
                written.append(alias_node.this)
        if isinstance(node, exp.Table):
            written.append(node.this)
        names = [next(
            (i for i in written if isinstance(i, exp.Identifier) and i.name == alias),
            exp.Identifier(this=alias, quoted=False),
        )]
        for pivot in node.args.get("pivots") or []:
            pivot_alias = pivot.args.get("alias")
            if isinstance(pivot_alias, exp.TableAlias) and isinstance(pivot_alias.this, exp.Identifier):
                names.append(pivot_alias.this)
        return names

    def _fold(self, ident: exp.Identifier) -> str:
        """A name as the engine compares it: folded where the engine's rule
        is known (_NAME_FOLDING), else as written (SQL Server's and MySQL's
        collations decide; ClickHouse compares names exactly)."""
        return _folded_name(self._engine, ident) if self._engine in _NAME_FOLDING else ident.name

    def _lookup(self, scope: Scope | None, qualifier: Any) -> tuple[Any, Any]:
        """(FROM item, source) a qualifier names, in ``scope`` or an enclosing
        one; (None, None) when it names no source, and (None, _AMBIGUOUS)
        when names that differ only in case leave the engine's choice open:
        two FROM items "A" and a, or an inner a and an outer "A" where the
        engine's folding is unknown or the spelling matches neither."""
        ident = qualifier if isinstance(qualifier, exp.Identifier) else exp.to_identifier(str(qualifier))
        want, folded = ident.name.lower(), self._fold(ident)
        skipped: list[tuple[Any, Any]] = []  # nearer sources whose name matches only ignoring case
        while scope is not None:
            entries = self._named(scope).get(want)
            if entries:
                matching = {id(e[1]): e for e in entries if self._fold(e[2]) == folded}
                if matching:
                    if len(matching) > 1 or (skipped and self._engine not in _NAME_FOLDING):
                        return None, _AMBIGUOUS
                    node, source, _ident = next(iter(matching.values()))
                    return node, source
                distinct = {id(e[1]): e for e in entries}
                skipped.append((None, _AMBIGUOUS) if len(distinct) > 1 else entries[0][:2])
            scope = scope.parent
        if len(skipped) == 1 and self._engine not in _NAME_FOLDING:
            return skipped[0]  # the engine bound it ignoring case, or the statement failed
        return (None, _AMBIGUOUS) if skipped else (None, None)

    def _candidates(self, scope: Scope) -> list[tuple[str, Any, Any]]:
        """The sources an unqualified column may read, as (alias, FROM item,
        source): this scope's, plus the enclosing ones for a (correlated)
        subquery, a table function or a scope with no FROM."""
        cached = self._candidates_of.get(id(scope))
        if cached is not None:
            return cached
        found: list[tuple[str, Any, Any]] = []
        seen: set[int] = set()
        current: Scope | None = scope
        while current is not None:
            for alias, (node, source) in current.selected_sources.items():
                seen.add(id(source))
                found.append((alias, node, source))
            # unaliased derived tables share the alias "": only the last one is a named source
            for source in current.table_scopes:
                if id(source) not in seen:
                    seen.add(id(source))
                    found.append(("", None, source))
            if found and current.scope_type not in (ScopeType.SUBQUERY, ScopeType.UDTF):
                break
            current = current.parent
        self._candidates_of[id(scope)] = found
        return found

    def _col_tainted(self, scope: Scope, col: exp.Column) -> bool:
        if isinstance(col.this, exp.Star):  # t.* used as a value: the whole row
            return self._whole_row_tainted(self._lookup(scope, col.args["table"])[1] if col.table else None)
        name = col.name.lower()
        if self._sensitive(col.name):
            return True
        if col.table:
            node, source = self._lookup(scope, col.args["table"])
            if source is not None:
                return self._by_name(source, name, node, col.this)
            if col.db:
                # t.objcol.attr (an Oracle object column's attribute): the
                # value is objcol's
                node, source = self._lookup(scope, col.args["db"])
                if source is not None:
                    return self._by_name(source, col.table.lower(), node, col.args["table"])
            if self._engine != "clickhouse":
                # a qualifier the walk binds to no source (a PIVOT's, a
                # MATCH_RECOGNIZE's, a construct it does not model): its
                # column is not proven clean
                return True
            return self._qualifier_tainted(scope, col)
        if self._scalar_tainted(scope, name):
            return True
        # ClickHouse resolves a bare name to an alias defined anywhere in the SELECT
        if name in self._aliases.get(id(scope.expression), ()):
            return True
        if not self._candidates(scope):
            return name in self._tainted_names
        reach = self._reach(scope)
        plain = bool(_PLAIN_NAME.fullmatch(name))
        return (
            reach.always
            or name in reach.tainted
            # an engine-named column (PostgreSQL names upper(x) "upper") may be
            # the one referenced; SQLite names it "upper(x)", the first of
            # several, so an explicit alias of that text does not tell them apart
            or (bool(reach.anonymous) and (not plain or reach.named_in_anonymous.get(name, 0) < reach.anonymous))
            # a bare table alias is a whole-row reference (PostgreSQL: SELECT t FROM t)
            or reach.rows.get(name, False)
            # a name no source outputs: one the engine made (SQLite's "x:1"
            # for a second x), unless a base table or a star may hold it
            or (
                name not in reach.known and name not in _PSEUDO_COLUMNS and reach.scope_row
                and (reach.closed or not plain)
            )
        )

    def _qualifier_tainted(self, scope: Scope, col: exp.Column) -> bool:
        """A qualified column whose qualifier is not a FROM item: a struct or
        tuple column (ClickHouse n.field), or an element of a tuple bound by
        an alias (x.1 over ARRAY JOIN [(ssn, 1)] AS x, or over an alias in
        WHERE) or by a WITH scalar."""
        qualifier = col.table.lower()
        if self._sensitive(col.table) or {col.name.lower(), qualifier} & self._tainted_names:
            return True
        current: Scope | None = scope
        while current is not None:
            if qualifier in self._aliases.get(id(current.expression), ()):
                return True
            current = current.parent
        return self._scalar_tainted(scope, qualifier)

    def _scalar_tainted(self, scope: Scope, name: str) -> bool:
        """Whether ``name`` is a ClickHouse WITH scalar that reads a sensitive
        value (a scalar may read another; a cycle reads nothing new)."""
        if name not in self._scalars or name in self._resolving:
            return False
        self._resolving.add(name)
        try:
            return self._expr_tainted(scope, self._scalars[name])
        finally:
            self._resolving.discard(name)

    def _reach(self, scope: Scope) -> _Reach:
        reach = self._reach_of.get(id(scope))
        if reach is not None:
            return reach
        reach = _Reach()
        for alias, node, source in self._candidates(scope):
            row = self._whole_row_tainted(source)
            reach.any_row = reach.any_row or row
            if alias:
                reach.rows[alias.lower()] = reach.rows.get(alias.lower(), False) or row
            key = self._source_key(source) if isinstance(source, Scope) else None
            if key is not None:
                index = self._ref_index(node, source)
                reach.always = reach.always or index.unknown
                reach.tainted.update(n for n, tainted in index.names.items() if tainted)
                reach.known.update(index.names)
                reach.closed = reach.closed and not index.spread
                reach.scope_row = reach.scope_row or index.row
                if index.anonymous:
                    reach.anonymous += 1
                    for n in index.names:
                        reach.named_in_anonymous[n] = reach.named_in_anonymous.get(n, 0) + 1
            elif isinstance(source, exp.Table) and not source.args.get("pivots"):
                # a base table's own column names were checked against the patterns
                reach.tainted.update(self._renamed(source))
                reach.closed = False
            else:
                reach.always = True
        self._reach_of[id(scope)] = reach
        return reach

    def _alias_closure(self, scope: Scope) -> set[str]:
        """Tainted aliases a SELECT defines anywhere in it - its projections,
        and those in WHERE, ORDER BY or ARRAY JOIN that ClickHouse lets the
        SELECT list read - closed over the bare names they read from each
        other with a worklist, so an alias chain settles in one pass."""
        key = id(scope.expression)
        self._aliases[key] = set()  # each alias's own taint first, without its siblings'
        pending: list[str] = []
        readers: dict[str, list[str]] = {}
        for node in self._walk(scope.expression):
            if not (isinstance(node, exp.Alias) and node.alias):
                continue
            name = node.alias.lower()
            if self._expr_tainted(scope, node.this):
                pending.append(name)
            for sub in self._walk(node.this):
                if isinstance(sub, exp.Column) and not sub.table and not isinstance(sub.this, exp.Star):
                    readers.setdefault(sub.name.lower(), []).append(name)
        tainted: set[str] = set()
        while pending:
            name = pending.pop()
            if name not in tainted:
                tainted.add(name)
                pending.extend(readers.get(name, ()))
        return tainted

    def _by_name(self, source: Any, name: str, ref: Any = None, ident: Any = None) -> bool:
        """Taint of ``q.name`` where q names ``source`` through the FROM item
        ``ref``. A base table's own column names were already checked against
        the patterns; on PostgreSQL q.to_json is to_json(q), its whole row,
        and so is q.site_fn over a table the catalog says has no such column,
        or over a derived table or CTE whose star hands such a table's row on
        (``ident`` is the name as written: PostgreSQL folds it unless quoted)."""
        if not isinstance(source, Scope):
            if isinstance(source, exp.Table) and not source.args.get("pivots"):
                if name in self._renamed(source) or name in self._row_functions:
                    return True
                known = self._table_columns.get(id(source))
                return known is not None and ident is not None and _pg_identifier(ident) not in known
            return True
        if self._source_key(source) is None:
            return True
        index = self._ref_index(ref, source)
        tainted = index.names.get(name)
        plain = bool(_PLAIN_NAME.fullmatch(name))
        if tainted is not None:
            # SQLite names an unaliased expression by its text: an alias of
            # that text names the second of the two
            return tainted or index.unknown or (index.anonymous and not plain)
        # Not a column the scope outputs by name: an engine-named column
        # (PostgreSQL names upper(x) "upper", SQLite a second x "x:1"), or on
        # PostgreSQL a function of the whole row - any name where every
        # column is known (a star's too, where the catalog listed its
        # tables) or where it listed some and a run beside them leaves the
        # rest to the driver, else a known row function.
        listed = index.spread_columns
        return index.unknown or index.anonymous or (
            index.row and (
                not index.spread
                or not plain
                or name in self._row_functions
                or (bool(self._row_functions) and index.partly_listed)
                or (listed is not None and _pg_identifier(name if ident is None else ident) not in listed)
            )
        )

    def _whole_row_tainted(self, source: Any) -> bool:
        """A row used as a value carries every column of it; a base table's
        columns are not known here, so its row counts as sensitive."""
        if isinstance(source, Scope):
            key = self._source_key(source)
            return key is None or self._index.get(key, _NO_OUTPUT).row
        return True

    def _expr_tainted(self, scope: Scope, node: exp.Expr) -> bool:
        for sub in self._walk(node):
            if sub is not node and id(sub) in self._scope_of:
                if self._rollup.get(id(sub), False):  # a subquery: anything it reads
                    return True
            elif isinstance(sub, exp.Column):
                if self._col_tainted(scope, sub):
                    return True
            elif isinstance(sub, exp.Select | exp.SetOperation) and sub is not node:
                return True  # a query the scope analysis did not place
            elif isinstance(sub, exp.Columns) or (
                isinstance(sub, exp.Star) and not isinstance(sub.parent, exp.Column | exp.Count)
            ):
                # a row used as a value (not COUNT(*))
                if not self._candidates(scope) or self._reach(scope).any_row:
                    return True
        return False

    @staticmethod
    def _rename(items: list[_OutItem], names: list[str]) -> list[_OutItem]:
        """An explicit column list (``WITH t(a, b)``, ``AS q(a, b)``) renames
        positionally."""
        if not names:
            return items
        lowered = [n.lower() for n in names]
        if len(lowered) > len(items) or not all(isinstance(i, _OutCol) for i in items):
            # the renamed positions cannot be matched to their values
            return [*(_OutCol(n, True) for n in lowered), _SPREAD_UNKNOWN]
        cols = [i for i in items if isinstance(i, _OutCol)]
        return [*(_OutCol(n, c.tainted) for n, c in zip(lowered, cols, strict=False)), *cols[len(lowered):]]

    @staticmethod
    def _merge(left: list[_OutItem], right: list[_OutItem]) -> list[_OutItem]:
        """A set operation: names come from the left branch, values from both."""
        lcols = [i for i in left if isinstance(i, _OutCol)]
        rcols = [i for i in right if isinstance(i, _OutCol)]
        if len(lcols) == len(left) and len(rcols) == len(right) and len(left) == len(right):
            return [_OutCol(lc.name, lc.tainted or rc.tainted) for lc, rc in zip(lcols, rcols, strict=True)]
        if len(rcols) == len(right) and not any(rc.tainted for rc in rcols):
            return left  # the right branch adds no sensitive value (or is not evaluated yet)
        return [_SPREAD_UNKNOWN]


def _pg_identifier(ident: Any) -> str:
    """A PostgreSQL identifier as the catalog spells it: folded to lower case
    unless quoted."""
    if isinstance(ident, exp.Identifier):
        return str(ident.this) if ident.quoted else str(ident.this).translate(_ASCII_LOWER)
    return str(getattr(ident, "name", ident)).translate(_ASCII_LOWER)


def _pg_table_ident(table: exp.Table) -> Any:
    """The identifier that names ``table``'s relation: sqlglot reads
    PostgreSQL's ``(TABLE t)`` as a table named TABLE aliased t (an unquoted
    TABLE is a reserved word, never a table's name)."""
    this, alias = table.this, table.args.get("alias")
    if (
        isinstance(this, exp.Identifier) and not this.quoted and str(this.this).upper() == "TABLE"
        and isinstance(alias, exp.TableAlias) and isinstance(alias.this, exp.Identifier)
    ):
        return alias.this
    return this


async def _row_function_columns(
    app: AppContext, connector: DatabaseConnector, policy: EffectivePolicy, ast: exp.Expression, warnings: list[str]
) -> dict[int, frozenset[str]]:
    """PostgreSQL reads ``b.fn`` as ``fn(b)`` when the table b names has no
    column fn (attribute notation), so a site's own function over a base
    table's row hands the row back under a name no pattern matches. This
    reads, from the catalog, the column names of each base table a qualified
    column names, and of each one a derived table or CTE hands on whole
    (``SELECT *``, ``TABLE t``: x.fn is then fn over t's row), keyed by the
    id of its FROM item, so the taint walk can tell a column from such a
    call. A table whose columns cannot be read, or that information_schema
    lists none of (a materialized view), a bare name the catalog listing does
    not hold, or one that comes after _ROW_FUNCTION_TABLES lookups, maps to
    no columns, so every name qualified by it is masked (fail closed): decoy
    tables ahead of it cannot use the lookups up. The listing is read once
    per statement, and a table named again is not resolved again."""
    if policy.engine != "postgres" or not policy.sensitive_patterns:
        return {}
    qualifiers = {c.table.lower() for c in ast.find_all(exp.Column) if c.table}
    if not qualifiers:
        return {}
    try:
        # the scopes of the walk's own view, where a FROM item binds to a CTE
        # as PostgreSQL folds the names (_engine_view): WITH "CUSTOMERS" ...
        # FROM CUSTOMERS reads the table customers
        view, _ = _engine_view(ast, policy.engine, None)
        scopes = list(traverse_scope(view))
    except Exception:  # noqa: BLE001 - the taint walk cannot follow it either, and masks the result whole
        return {}
    # the view's FROM items, by id, to the statement's (the copy keeps their order)
    original = {id(v): id(t) for t, v in zip(ast.find_all(exp.Table), view.find_all(exp.Table), strict=True)}
    # A FROM item names a CTE only where its scope says so: a CTE of the same
    # name inside EXISTS or a scalar subquery leaves an outer table a table.
    # (A parenthesized TABLE t is a scope of its own, not a reference to one.)
    cte_refs = {
        original.get(id(node))
        for s in scopes
        for node, source in s.selected_sources.values()
        if isinstance(source, Scope) and source.expression is not node
    }
    handed_on = {
        original.get(id(source))
        for s in scopes
        if not s.is_root
        and (isinstance(s.expression, exp.Table) or (isinstance(s.expression, exp.Select) and s.expression.is_star))
        for source in s.sources.values()
        if isinstance(source, exp.Table)
    }
    now = time.monotonic()
    out: dict[int, frozenset[str]] = {}
    resolved: dict[tuple[str | None, str], frozenset[str]] = {}  # (schema as written, name) -> its columns
    listed: list[Any] | Exception | None = None  # the catalog listing, read on the first bare name
    lookups = 0
    over_budget = False
    for table in ast.find_all(exp.Table):
        if not isinstance(table.this, exp.Identifier) or id(table) in cte_refs:
            continue  # a table function, or a CTE, whose columns the walk knows
        if table.alias_or_name.lower() not in qualifiers and id(table) not in handed_on:
            continue
        name = _pg_identifier(_pg_table_ident(table))
        written = _pg_identifier(table.args["db"]) if table.db else None
        if (written, name) in resolved:  # the same table named again (a long UNION) is resolved once
            out[id(table)] = resolved[(written, name)]
            continue
        known: frozenset[str] | None = None
        columnless = False  # a relation it may name lists no columns
        try:
            if written is not None:
                schemas = [written]
            else:  # search_path picks among the tables the listing holds under this name
                if listed is None:
                    try:
                        listed = await app.tables_for(policy, connector)
                    except Exception as exc:  # noqa: BLE001 - every bare name is then reported below
                        listed = exc
                if isinstance(listed, Exception):
                    raise listed
                schemas = sorted({t.schema for t in listed if t.schema and t.name == name})
                if not schemas:
                    # Nothing restricting names, the guard let PostgreSQL bind
                    # one the listing leaves out: a partitioned parent, a
                    # foreign table, a table newer than the cached listing.
                    warnings.append(
                        f"{_id_text(name)} is not in the catalog listing, so its columns are unknown: every "
                        "column named through it was masked, since PostgreSQL may read such a name as a "
                        "site-defined function of the whole row (fail closed); qualify it with its schema"
                    )
                    known = frozenset()
            for schema in schemas:
                key = (policy.connection_id, schema, name)
                cached = app.row_columns.get(key)
                if cached is not None and now - cached[0] < _ROW_COLUMNS_TTL:
                    names = cached[1]
                elif lookups >= _ROW_FUNCTION_TABLES:
                    over_budget, known = True, frozenset()
                    break
                else:
                    lookups += 1
                    cols = await run_meta(app, policy.connection_id, _meta_call("list_columns", schema, name))
                    names = frozenset(str(c.name) for c in cols)
                    if len(app.row_columns) >= _ROW_COLUMNS_CAP:
                        app.row_columns.clear()
                    app.row_columns[key] = (now, names)
                columnless = columnless or not names
                # a bare name may bind to any of these: only a column of every one is surely a column
                known = names if known is None else known & names
            if columnless:
                warnings.append(
                    f"the catalog lists no columns for {_id_text(name)} (information_schema leaves out a "
                    "materialized view's): every column named through it with a qualifier was masked, since "
                    "PostgreSQL may read such a name as a site-defined function of the whole row (fail closed); "
                    "name its columns without the qualifier"
                )
        except Exception as exc:  # noqa: BLE001 - the statement ran; only its masking is at stake
            warnings.append(
                f"the columns of {_id_text(name)} could not be read ({_error_text(exc)}): every column named "
                "through it was masked, since PostgreSQL may read such a name as a site-defined function of the "
                "whole row (fail closed)"
            )
            known = frozenset()
        out[id(table)] = resolved[(written, name)] = frozenset() if known is None else known
    if over_budget:
        warnings.append(
            f"the statement names more than {_ROW_FUNCTION_TABLES} tables whose columns were not yet known (one "
            "catalog lookup each): the columns named through the others were masked, since PostgreSQL may read "
            "such a name as a site-defined function of the whole row (fail closed); a repeated call finds them known"
        )
    return out


def _output_items(
    policy: EffectivePolicy, ast: exp.Expression, table_columns: dict[int, frozenset[str]] | None = None
) -> list[_OutItem] | None:
    try:
        view, columns = _engine_view(ast, policy.engine, table_columns)
        return _OutputTaint(policy.sensitive_patterns, view, policy.engine, columns).root_items()
    except Exception:  # noqa: BLE001 - an AST the analysis cannot follow is masked, never trusted
        return None


def _driver_name(name: str) -> str:
    return unicodedata.normalize("NFKC", name).casefold()


def _map_positions(items: list[_OutItem], width: int, names: list[str] | None = None) -> set[int] | None:
    """Tainted indices among the driver's ``width`` columns, or None when the
    traced output cannot be laid over them. ``names``: the driver's column
    names; where a run of unknown width takes up the difference, every alias
    the statement wrote must be reported at the position the layout gives it
    - a construct the walk counts as one column and the engine as several
    would otherwise shift each traced position after it onto another column."""
    runs: list[_OutItem] = []
    for item in items:
        if isinstance(item, str) and runs and isinstance(runs[-1], str):
            runs[-1] = _SPREAD_UNKNOWN if _SPREAD_UNKNOWN in (item, runs[-1]) else _SPREAD_BASE
        else:
            runs.append(item)
    spreads = [r for r in runs if isinstance(r, str)]
    span = width - (len(runs) - len(spreads))
    if span < 0 or (not spreads and span != 0):
        return None
    if len(spreads) > 1:
        # several runs of unknown width: exact only when the name heuristics
        # alone decide every column
        if _SPREAD_UNKNOWN in spreads or any(r.tainted for r in runs if isinstance(r, _OutCol)):
            return None
        return set()
    hit: set[int] = set()
    pos = 0
    for run in runs:
        if isinstance(run, str):
            if run == _SPREAD_UNKNOWN:
                hit.update(range(pos, pos + span))
            pos += span
        else:
            if spreads and names is not None and run.explicit and run.name is not None and (
                pos >= len(names) or _driver_name(names[pos]) != _driver_name(run.name)
            ):
                return None
            if run.tainted:
                hit.add(pos)
            pos += 1
    return hit


def _sensitive_output_positions(policy: EffectivePolicy, ast: exp.Expression, width: int) -> set[int] | None:
    """Indices of a validated statement's output columns (``width`` of them,
    as the driver reported) whose values derive from a sensitive column,
    traced on the AST in the connection's dialect - never from the name the
    driver reports. None when the output cannot be mapped (fail closed)."""
    if not policy.sensitive_patterns:
        return set()
    items = _output_items(policy, ast)
    return None if items is None else _map_positions(items, width)


def _query_mask_positions(
    policy: EffectivePolicy,
    ast: exp.Expression,
    columns: list[tuple[str, str]],
    warnings: list[str] | None = None,
    table_columns: dict[int, frozenset[str]] | None = None,
) -> set[int]:
    """The positions to mask in a validated statement's result: the traced
    ones, or - when the output cannot be mapped - every column whose name the
    statement does not prove clean (fail closed). A name proves a column clean
    only when nothing the statement outputs is tainted and no star run is
    involved: otherwise the driver may report a folded or renamed column under
    any name, a clean alias's included (SQL Server names FOR JSON output
    JSON_F52E2B61-..., which a statement can also use as an alias).
    ``table_columns``: base tables' column names (_row_function_columns)."""
    if not policy.sensitive_patterns:
        return set()
    items = _output_items(policy, ast, table_columns)
    positions = None if items is None else _map_positions(items, len(columns), [name for name, _t in columns])
    if positions is not None:
        return positions
    clean: set[str] = set()
    if items is not None and all(isinstance(i, _OutCol) and not i.tainted for i in items):
        clean = {i.name for i in items if isinstance(i, _OutCol) and i.name}
    hit = {i for i, (name, _t) in enumerate(columns) if name.lower() not in clean}
    if hit and warnings is not None:
        warnings.append(
            "the result's columns could not all be traced to their source columns; every column the "
            "statement does not prove clean was masked (fail closed)"
        )
    return hit


def _mask_columns(
    policy: EffectivePolicy,
    columns: list[tuple[str, str]],
    sensitive_names: frozenset[str] | None = None,
    positions: set[int] | None = None,
) -> set[int]:
    """Indices of columns to mask/omit: the positions traced on the validated
    statement (see :func:`_query_mask_positions`), plus the output-name
    heuristics and the guard-derived names that expose a sensitive source
    column (aliasing a sensitive column does not launder it past policy)."""
    extra = sensitive_names or frozenset()
    hit: set[int] = {i for i in positions or () if 0 <= i < len(columns)}
    for i, (name, _t) in enumerate(columns):
        if name.lower() in extra or _sensitive_name(policy.sensitive_patterns, name):
            hit.add(i)
    return hit


def _apply_masking(
    policy: EffectivePolicy,
    columns: list[tuple[str, str]],
    rows: list[list[Any]],
    state: dict[str, Any],
    sensitive_names: frozenset[str] | None = None,
    positions: set[int] | None = None,
) -> tuple[list[tuple[str, str]], list[list[Any]]]:
    hit = _mask_columns(policy, columns, sensitive_names, positions)
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


def _select_connections(app: AppContext, connections: list[str] | None) -> list[str]:
    """The connections a cross-connection tool works on: every configured
    one when omitted, else the caller's list with each id once (a repeated id
    used to be searched, ranked and paired once per copy). Checked before any
    I/O: an empty or over-long list is a VALIDATION error, an unknown id the
    same AUTHORIZATION error every tool gives."""
    if connections is None:
        return sorted(app.resolved)
    if not connections:
        raise ToolFailure(ErrorCategory.VALIDATION, "connections must be omitted or non-empty")
    if len(connections) > _MAX_CONNECTIONS_ARG:
        raise ToolFailure(
            ErrorCategory.VALIDATION, f"connections lists at most {_MAX_CONNECTIONS_ARG} connection ids"
        )
    ids = list(dict.fromkeys(connections))
    for cid in ids:
        if cid not in app.resolved:
            raise _connection_unavailable(app.resolved, cid)
    return ids


def _scope_listing(view: _SchemaView, schema: str | None, items: list[Any]) -> list[Any]:
    """Policy scope for schema-less catalog listings (views/synonyms/routines).
    With an explicit schema the caller was authorized via ``check_object``
    (and _check_schema_spelling) before the listing; without one, items
    living in schemas the caller may not see - a namesake of an allowed one
    included - are dropped here, the same rule ``tables_for`` applies to
    tables, instead of leaking whatever the database login sees."""
    if schema is not None:
        return items
    return [i for i in items if view.visible(i.schema)]


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


class _AuditedServer(MCPServer[Any]):
    """The MCP server, whose tools/call path also audits the calls the SDK
    refuses before a handler - and so tool_span - runs: an unknown tool name,
    or arguments that fail the tool's input schema (a wrong type, a missing
    field, a list over its maxItems). No database is touched on those paths,
    but an agent probing the surface left no trace in the audit log."""

    def __init__(self, app: AppContext, **settings: Any) -> None:
        super().__init__(**settings)
        self._app = app
        self.tool_parameters: dict[str, frozenset[str]] = {}  # filled by build_server's register()

    async def call_tool(
        self, name: str, arguments: dict[str, Any], context: Context[Any, Any] | None = None
    ) -> CallToolResult | InputRequiredResult:
        started = time.monotonic()
        try:
            return await super().call_tool(name, arguments, context)
        except ToolError as exc:
            if isinstance(exc, UnexpectedToolError):
                raise
            known = self.tool_parameters.get(name)
            if known is None:
                await _audit_rejected_call(self._app, name, arguments, started, "unknown tool", None)
            elif isinstance(exc.__cause__, ValidationError):
                # the top-level parameter names only: a nested location can
                # hold a caller-chosen key, and no value is ever recorded
                fields = sorted({str(e["loc"][0]) for e in exc.__cause__.errors() if e["loc"]} & known)
                await _audit_rejected_call(self._app, name, arguments, started, "invalid arguments", fields)
            raise


def _arguments_digest(arguments: dict[str, Any]) -> str | None:
    """SHA-256 of the arguments' canonical JSON: a rejected call can be
    matched against a client's log without its values being recorded."""
    try:
        raw = json.dumps(arguments, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    except (TypeError, ValueError, RecursionError):
        return None
    return hashlib.sha256(raw.encode("utf-8", "surrogatepass")).hexdigest()


async def _audit_rejected_call(
    app: AppContext, name: str, arguments: dict[str, Any], started: float, reason: str, fields: list[str] | None
) -> None:
    """The deny record of a tools/call the SDK refused. The requested name is
    kept, capped; the arguments only as a digest, never their values (the
    caller's data, possibly megabytes). Written shielded and fail-closed
    exactly like tool_span's record, and coalesced like its refusals (every
    unknown name as one kind)."""
    with anyio.CancelScope(shield=True):
        digest = await anyio.to_thread.run_sync(_arguments_digest, arguments)
        record: dict[str, Any] = {
            "request_id": new_request_id(),
            "action": name[:_TOOL_NAME_CHARS],
            "connection_id": None,
            "outcome": "deny",
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "sql_fingerprint": None,
            "row_count": None,
            "category": ErrorCategory.VALIDATION,
            "reason": reason,
            "arguments_sha256": digest,
        }
        if fields is not None:
            record["invalid_arguments"] = fields
        audit_record = {"event": "tool_call", **_caller_fields(app), **redact_value(record)}
        write = _audit_writer(app, True, _UNKNOWN_TOOL if fields is None else None)
        try:
            await anyio.to_thread.run_sync(write, audit_record)
        except AuditWriteFailure as audit_exc:
            app.record_history({**record, "ts": _now()})
            raise ToolError(f"{ErrorCategory.CONFIG}: {audit_exc}") from audit_exc
    app.record_history({**record, "ts": _now()})


# The action every unknown tool's refusal is counted under (AuditLog.
# record_refusal): the name itself is the caller's choice.
_UNKNOWN_TOOL = "<unknown tool>"


def build_server(app: AppContext) -> MCPServer[Any]:
    mcp = _AuditedServer(
        app,
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
        mcp.tool_parameters[name] = frozenset(inspect.signature(handler).parameters)

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
                        # read_only is the server's promise (the guard refuses
                        # writes); this says whether the database session
                        # refuses them too, which session.enforce_read_only
                        # turns off (not on SQLite, whose connector always
                        # opens the file mode=ro with query_only on) and
                        # Oracle, Db2 and SQL Server cannot do
                        "server_read_only_session": bool(
                            rc.config.read_only
                            and (rc.config.session.enforce_read_only or rc.config.type == "sqlite")
                            and SERVER_READ_ONLY_AVAILABLE.get(rc.config.type, False)
                        ),
                        "allowed_schemas": sorted(rc.config.allowed_schemas),
                    }
                )
            st["row_count"] = len(conns)
            data = {"connections": conns, "audit": _audit_status(app, st["warnings"])}
            return _envelope(st, None, None, data, warnings=st["warnings"])

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
                on_start=_sends(st),
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
            data["audit"] = _audit_status(app, st["warnings"])
            return _envelope(st, connection_id, policy.engine, data, warnings=st["warnings"])

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
                # the same allowlist db_list_schemas applies: a database is a schema here
                listed = await run_meta(app, connection_id, lambda c: c.list_schemas(None, None))
                view = await _schema_view(app, connector, policy, listed)
                schemas = [s for s in listed if view.visible(s)]
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
            view = await _schema_view(app, connector, policy, schemas)
            visible = [s for s in schemas if view.visible(s)]
            window, next_cursor = _page(
                app,
                visible,
                cursor,
                kind=_filtered_kind("schemas", catalog, search or None),
                connection_id=connection_id,
                policy=policy,
                page_size=_PAGE_SIZE,
                render=str,
                st=st,
            )
            st["row_count"] = len(window)
            return _envelope(
                st,
                connection_id,
                policy.engine,
                {"schemas": window},
                warnings=st["warnings"],
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
                await _check_schema_spelling(app, connector, policy, schema)
            if object_kinds is not None and not object_kinds:
                # `x or default` made an explicit [] mean "every kind"; None
                # is the default, an empty list is a caller mistake.
                raise ToolFailure(ErrorCategory.VALIDATION, "object_kinds must be omitted or non-empty")
            kinds = set(object_kinds) if object_kinds is not None else {"table", "view", "materialized_view"}
            unknown = kinds - {"table", "view", "materialized_view", "foreign_table", "alias"}
            if unknown:
                raise ToolFailure(ErrorCategory.VALIDATION, f"unknown object kinds: {_names_text(sorted(unknown))}")
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
                # the filters as applied above (case-insensitive schema and search)
                kind=_filtered_kind(
                    "tables", schema.lower() if schema is not None else None, (search or "").lower(), sorted(kinds)
                ),
                connection_id=connection_id,
                policy=policy,
                page_size=_PAGE_SIZE,
                render=lambda t: {
                    "schema": t.schema,
                    "name": t.name,
                    "kind": t.kind,
                    "row_estimate": t.row_estimate,
                    "row_estimate_source": t.row_estimate_source,
                },
                st=st,
            )
            st["row_count"] = len(window)
            return _envelope(
                st,
                connection_id,
                policy.engine,
                {"tables": window},
                warnings=st["warnings"],
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
            detail = _scoped_table_detail(policy, detail, st, await _schema_view(app, connector, policy))
            return _envelope(st, connection_id, policy.engine, detail, warnings=st["warnings"])

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
                render=lambda c: {
                    **c.__dict__,
                    "default": _masked_default(policy, c.name, c.default),
                    "comment": _cap_text(c.comment, policy, st),
                },
                st=st,
            )
            st["row_count"] = len(window)
            return _envelope(
                st,
                connection_id,
                policy.engine,
                {"columns": window},
                warnings=st["warnings"],
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
                await _check_schema_spelling(app, connector, policy, schema)
            views = await run_meta(app, connection_id, lambda c: c.list_views(schema))
            views = _scope_listing(await _schema_view(app, connector, policy), schema, views)
            names = await _quoted_word_names(app, connection_id, policy, views)
            window, next_cursor = _page(
                app,
                views,
                cursor,
                kind=_filtered_kind("views", schema),
                connection_id=connection_id,
                policy=policy,
                page_size=_PAGE_SIZE,
                render=lambda v: {
                    **v.__dict__, "definition": _view_definition(policy, v.definition, st, v.name, names)
                },
                st=st,
            )
            st["row_count"] = len(window)
            return _envelope(
                st,
                connection_id,
                policy.engine,
                {"views": window},
                warnings=st["warnings"],
                next_cursor=next_cursor,
                returned_row_count=len(window),
                truncated=next_cursor is not None,
            )

    register(
        "db_list_views",
        "List views and materialized views; definitions included only where the engine reports them.",
        db_list_views,
    )

    async def db_list_synonyms(
        connection_id: str, schema: str | None = None, cursor: str | None = None
    ) -> dict[str, Any]:
        async with tool_span(app, "db_list_synonyms", connection_id) as st:
            connector, policy = _require_engine(app, connection_id)
            if _capability_unavailable(connector.capabilities().get(Cap.LIST_SYNONYMS)):
                raise ToolFailure(
                    ErrorCategory.CAPABILITY,
                    f"engine '{policy.engine}' has no synonyms/aliases concept",
                )
            if schema is not None:
                policy.check_object(schema, "*")
                await _check_schema_spelling(app, connector, policy, schema)
            syns = await run_meta(app, connection_id, lambda c: c.list_synonyms(schema))
            syns = _scope_listing(await _schema_view(app, connector, policy), schema, syns)
            window, next_cursor = _page(
                app, syns, cursor, kind=f"synonyms:{schema or '*'}", connection_id=connection_id, policy=policy,
                page_size=_PAGE_SIZE, render=lambda s: dict(s.__dict__), st=st,
            )
            st["row_count"] = len(window)
            return _envelope(
                st, connection_id, policy.engine, {"synonyms": window}, warnings=st["warnings"],
                next_cursor=next_cursor, returned_row_count=len(window), truncated=next_cursor is not None,
            )

    register(
        "db_list_synonyms",
        "List synonyms/aliases and their target objects (bounded pagination); remote links are reported, "
        "never traversed.",
        db_list_synonyms,
    )

    async def db_list_routines(
        connection_id: str, schema: str | None = None, cursor: str | None = None
    ) -> dict[str, Any]:
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
                await _check_schema_spelling(app, connector, policy, schema)
            routines = await run_meta(app, connection_id, lambda c: c.list_routines(schema))
            routines = _scope_listing(await _schema_view(app, connector, policy), schema, routines)
            window, next_cursor = _page(
                app, routines, cursor, kind=f"routines:{schema or '*'}", connection_id=connection_id,
                policy=policy, page_size=_PAGE_SIZE, render=lambda r: dict(r.__dict__), st=st,
            )
            st["row_count"] = len(window)
            return _envelope(
                st, connection_id, policy.engine, {"routines": window}, warnings=st["warnings"],
                next_cursor=next_cursor, returned_row_count=len(window), truncated=next_cursor is not None,
            )

    register(
        "db_list_routines",
        "List functions/procedures with bounded pagination (metadata only; routines are never executed "
        "for discovery).",
        db_list_routines,
    )

    # ---- search / relationships / stats ---------------------------------------

    async def db_search_metadata(
        query: str,
        connections: _IdList | None = None,
        object_types: list[str] | None = None,
        result_cap: int = _SEARCH_CAP,
    ) -> dict[str, Any]:
        async with tool_span(app, "db_search_metadata") as st:
            if not query or len(query) > 200:
                raise ToolFailure(ErrorCategory.VALIDATION, "query must be 1-200 characters")
            cap = min(max(result_cap, 1), _SEARCH_CAP)
            conn_ids = _select_connections(app, connections)
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
                except Exception as exc:  # noqa: BLE001 - one dead connection must not end the search
                    # A missing driver, an unreachable engine, a metadata
                    # timeout or a raw driver error on one connection must not
                    # abort the cross-connection search — unless the caller
                    # explicitly named exactly that one connection.
                    if connections is not None and len(conn_ids) == 1:
                        raise
                    warnings.append(f"connection '{cid}' skipped: {_error_text(exc)}")
                    continue
                items.extend((cid, t.schema or "", t.name, t.kind) for t in conn_tables if t.kind in types)
            # scoring and sorting every catalog entry is CPU work: off the event loop
            ranked = await anyio.to_thread.run_sync(rank_search, query, items, cap)
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
            view = await _schema_view(app, connector, policy)
            confirmed = []
            for fk in fks:
                # a declared key may target a schema the allowlist hides: the
                # key and its local columns are reported, the target is not named
                visible = view.visible(fk.ref_schema)
                target = f"{fk.ref_schema}.{fk.ref_table}" if fk.ref_schema else fk.ref_table
                confirmed.append(
                    {
                        "relationship": "declared_foreign_key",
                        "inferred": False,
                        "from_table": f"{schema2}.{name}",
                        "from_columns": fk.columns,
                        "to_table": target if visible else "<not permitted>",
                        "to_columns": fk.ref_columns if visible else [],
                        "constraint_name": fk.name,
                    }
                )
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
            st["executed"] = False  # validation never sends the statement
            connector, policy = _require_engine(app, connection_id)
            result = await _validated(app, connector, policy, lambda g: g.validate_any(sql, operation))
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
            read = await _guarded_read(app, st, connection_id, sql, parameters, max_rows, timeout_seconds)
            st["row_count"] = len(read.rows)
            data = {
                "columns": [{"name": n, "type": t} for n, t in read.columns],
                "rows": read.rows,
            }
            warnings = list(read.outcome.warnings) + st["warnings"]
            if read.outcome.truncated:
                # No claim about where the limits applied: some drivers buffer
                # the whole result (ClickHouse), and cells are cut only after
                # they were read.
                warnings.append(
                    f"result truncated: limits are rows<={read.row_limit}, bytes<={read.policy.max_response_bytes}"
                )
            return _envelope(
                st,
                connection_id,
                read.policy.engine,
                data,
                warnings=warnings,
                returned_row_count=len(read.rows),
                truncated=read.outcome.truncated,
            )

    register(
        "db_query",
        "Execute one validated, bounded read statement with optional bound "
        "parameters; row/byte/timeout ceilings are enforced server-side.",
        db_query,
    )

    async def db_federated_query(
        sql: str | None = None,
        connections: _IdList | None = None,
        queries: Annotated[dict[str, str], Field(max_length=_MAX_CONNECTIONS_ARG)] | None = None,
        parameters: list[Any] | dict[str, Any] | None = None,
        max_rows_per_connection: int | None = None,
        time_budget_seconds: float = 60.0,
    ) -> dict[str, Any]:
        async with tool_span(app, "db_federated_query") as st:
            if bool(sql) == bool(queries):
                raise ToolFailure(
                    ErrorCategory.VALIDATION,
                    "pass either sql (run on every listed connection) or queries (one statement per connection)",
                )
            _check_parameters(parameters)  # the caller's mistake, not one per connection
            if queries:
                if connections:
                    raise ToolFailure(ErrorCategory.VALIDATION, "connections is implied by the keys of queries")
                _select_connections(app, list(queries))
                plan = dict(queries)
            else:
                plan = {cid: str(sql) for cid in _select_connections(app, connections)}
            if not plan:
                raise ToolFailure(ErrorCategory.VALIDATION, "no connections selected")
            budget = max(1.0, min(float(time_budget_seconds), _FEDERATED_MAX_BUDGET_SECONDS))
            deadline = time.monotonic() + budget
            results: list[dict[str, Any]] = []
            byte_ceiling: int | None = None
            used_bytes = 0
            exhausted = False
            for cid, statement in plan.items():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    exhausted = True
                    st["warnings"].append(f"time budget of {budget:.0f}s exhausted before '{cid}' ran")
                    break
                t0 = time.monotonic()
                try:
                    _, pol = _require_engine(app, cid)
                    # the strictest ceiling seen so far binds the whole response;
                    # each statement gets what is left of it, so a result that
                    # ran is always reported (truncated by its own read, never
                    # dropped after the fact)
                    byte_ceiling = (
                        pol.max_response_bytes if byte_ceiling is None else min(byte_ceiling, pol.max_response_bytes)
                    )
                    remaining_bytes = byte_ceiling - used_bytes
                    if remaining_bytes <= 0:
                        st["warnings"].append(
                            "response byte ceiling (security.max_response_bytes) reached; "
                            f"'{cid}' and later connections were not run"
                        )
                        exhausted = True
                        break
                    read = await _guarded_read(
                        app, st, cid, statement, parameters, max_rows_per_connection, min(remaining, budget),
                        byte_budget=remaining_bytes,
                    )
                except AuditWriteFailure:
                    raise
                except Exception as exc:  # noqa: BLE001 - one failing connection is reported, not fatal
                    results.append({"connection": cid, "error": _error_text(exc)})
                    st["warnings"].append(f"'{cid}': {_error_text(exc)}")
                    continue
                entry = {
                    "connection": cid,
                    "engine": read.policy.engine,
                    "columns": [{"name": n, "type": t} for n, t in read.columns],
                    "rows": read.rows,
                    "truncated": read.outcome.truncated,
                    "elapsed_ms": int((time.monotonic() - t0) * 1000),
                }
                used_bytes += len(json.dumps(entry, default=str))
                results.append(entry)
                if used_bytes >= byte_ceiling:
                    st["warnings"].append(
                        "response byte ceiling (security.max_response_bytes) reached; later connections were not run"
                    )
                    exhausted = True
                    break
            ok = [r for r in results if "rows" in r]
            merged: dict[str, Any] | None = None
            if ok:
                shapes = {tuple(c["name"].lower() for c in r["columns"]) for r in ok}
                if len(shapes) == 1:
                    names = ["connection", *[c["name"] for c in ok[0]["columns"]]]
                    rows: list[list[Any]] = []
                    # the merged view repeats the rows of 'results': it is
                    # charged against the same byte ceiling, never beside it
                    ceiling = byte_ceiling if byte_ceiling is not None else app.cfg.security.max_response_bytes
                    merged_full = True
                    for r in ok:
                        for row in r["rows"]:
                            merged_row = [r["connection"], *row]
                            size = _json_size(merged_row)
                            if len(rows) >= _FEDERATED_MAX_MERGED_ROWS or used_bytes + size > ceiling:
                                merged_full = False
                                break
                            used_bytes += size
                            rows.append(merged_row)
                        if not merged_full:
                            break
                    total = sum(len(r["rows"]) for r in ok)
                    merged = {"columns": names, "rows": rows, "row_count": len(rows), "truncated": total > len(rows)}
                    if total > len(rows) and len(rows) < _FEDERATED_MAX_MERGED_ROWS:
                        st["warnings"].append(
                            f"response byte ceiling (security.max_response_bytes) reached: the merged view holds "
                            f"{len(rows)} of {total} rows; the others are in the per-connection results"
                        )
                else:
                    st["warnings"].append(
                        "column names differ between connections; no merged view (per-connection results only)"
                    )
            st["row_count"] = sum(len(r["rows"]) for r in ok)
            return _envelope(
                st, None, None,
                {
                    "results": results,
                    "merged": merged,
                    "connections_run": len(ok),
                    "connections_failed": len(results) - len(ok),
                    "budget_exhausted": exhausted,
                    "note": "each statement is validated and bounded under its own connection's policy; masked "
                    "columns are masked per connection before merging",
                },
                warnings=st["warnings"],
            )

    register(
        "db_federated_query",
        "Run one validated read statement on several connections (or one statement per connection) and "
        "return per-connection results plus a merged view with a leading 'connection' column when the "
        "column names agree. Each statement is guarded, bounded and masked under its own connection's policy; "
        "one failing connection is a warning.",
        db_federated_query,
    )

    async def db_federated_join(
        left: dict[str, Any],
        right: dict[str, Any],
        on: Annotated[list[list[str]], Field(max_length=_FEDERATED_MAX_JOIN_KEYS)],
        join: Literal["inner", "left"] = "inner",
        max_rows: int = 500,
        max_rows_per_side: int | None = None,
        case_insensitive_keys: bool = False,
    ) -> dict[str, Any]:
        async with tool_span(app, "db_federated_join") as st:
            # the key list is bounded and checked before anything else: each
            # pair is a column every row's key is built from, on the event loop
            if not isinstance(on, list) or not 0 < len(on) <= _FEDERATED_MAX_JOIN_KEYS:
                raise ToolFailure(
                    ErrorCategory.VALIDATION,
                    f"on must list 1 to {_FEDERATED_MAX_JOIN_KEYS} [left_column, right_column] pairs",
                )
            sides: dict[str, tuple[str, str]] = {}
            for name, side in (("left", left), ("right", right)):
                if not isinstance(side, dict) or not side.get("connection") or not side.get("sql"):
                    raise ToolFailure(ErrorCategory.VALIDATION, f"{name} must be {{connection, sql}}")
                if side["connection"] not in app.resolved:
                    raise _connection_unavailable(app.resolved, str(side["connection"]))
                sides[name] = (str(side["connection"]), str(side["sql"]))
            pairs = [(str(p[0]), str(p[1])) for p in on if isinstance(p, list | tuple) and len(p) == 2]
            if not pairs or len(pairs) != len(on):
                raise ToolFailure(
                    ErrorCategory.VALIDATION, "on must be a non-empty list of [left_column, right_column] pairs"
                )
            pairs = list(dict.fromkeys(pairs))  # a repeated pair adds nothing to the key
            cap = max(1, min(int(max_rows), _FEDERATED_MAX_MERGED_ROWS))
            reads: dict[str, _GuardedRead] = {}
            for name, (cid, statement) in sides.items():
                reads[name] = await _guarded_read(app, st, cid, statement, None, max_rows_per_side, None)
            lcols = [n for n, _t in reads["left"].columns]
            rcols = [n for n, _t in reads["right"].columns]
            for lc, rc in pairs:
                if lc not in lcols:
                    raise ToolFailure(ErrorCategory.VALIDATION, f"left result has no column '{lc}' (columns: {lcols})")
                if rc not in rcols:
                    raise ToolFailure(ErrorCategory.VALIDATION, f"right result has no column '{rc}' (columns: {rcols})")
            li = [lcols.index(lc) for lc, _rc in pairs]
            ri = [rcols.index(rc) for _lc, rc in pairs]

            def key(row: list[Any], idx: list[int]) -> tuple[Any, ...] | None:
                parts = []
                for i in idx:
                    v = row[i]
                    if v is None or v == "<masked>":
                        return None
                    parts.append(_join_key(v, case_insensitive_keys))
                return tuple(parts)

            index: dict[tuple[Any, ...], list[list[Any]]] = {}
            for row in reads["right"].rows:
                k = key(row, ri)
                if k is not None:
                    index.setdefault(k, []).append(row)
            out_rows: list[list[Any]] = []
            matched_left = 0
            unmatched_left = 0
            truncated = False
            byte_truncated = False
            used_bytes = 0
            # each side was bounded by its own policy; the joined output (a
            # cross product per key) is bounded by the stricter of the two
            byte_ceiling = min(reads["left"].policy.max_response_bytes, reads["right"].policy.max_response_bytes)
            empty_right = [None] * len(rcols)

            def emit(joined: list[Any]) -> bool:
                nonlocal used_bytes, truncated, byte_truncated
                if len(out_rows) >= cap:
                    truncated = True
                    return False
                size = len(json.dumps(joined, default=str))
                if out_rows and used_bytes + size > byte_ceiling:
                    truncated = byte_truncated = True
                    return False
                used_bytes += size
                out_rows.append(joined)
                return True

            for row in reads["left"].rows:
                k = key(row, li)
                matches = index.get(k, []) if k is not None else []
                if matches:
                    matched_left += 1
                    for m in matches:
                        if not emit([*row, *m]):
                            break
                else:
                    unmatched_left += 1
                    if join == "left":
                        emit([*row, *empty_right])
                if truncated:
                    break
            if byte_truncated:
                st["warnings"].append(
                    "response byte ceiling (security.max_response_bytes) reached; the join output is partial"
                )
            if any(read.outcome.truncated for read in reads.values()):
                st["warnings"].append(
                    "a side was truncated by its row or byte ceiling; the join is incomplete (raise max_rows_per_side "
                    "or narrow the statements)"
                )
            if any(v == "<masked>" for r in reads["left"].rows for v in (r[i] for i in li)) or any(
                v == "<masked>" for r in reads["right"].rows for v in (r[i] for i in ri)
            ):
                st["warnings"].append("join keys with masked values never match (sensitive columns are not join keys)")
            st["row_count"] = len(out_rows)
            return _envelope(
                st, None, None,
                {
                    "columns": [f"left.{c}" for c in lcols] + [f"right.{c}" for c in rcols],
                    "rows": out_rows,
                    "join": join,
                    "on": [list(p) for p in pairs],
                    "left": {"connection": sides["left"][0], "rows": len(reads["left"].rows),
                             "truncated": reads["left"].outcome.truncated},
                    "right": {"connection": sides["right"][0], "rows": len(reads["right"].rows),
                              "truncated": reads["right"].outcome.truncated},
                    "matched_left_rows": matched_left,
                    "unmatched_left_rows": unmatched_left,
                    "truncated": truncated,
                    "note": "hash join computed here from two guarded, bounded, masked result sets; keys compare "
                    "as normalised text (numbers by value), nothing is written anywhere",
                },
                warnings=st["warnings"],
            )

    register(
        "db_federated_join",
        "Join two bounded read results from two connections (or the same one) on key columns, computed here: "
        "inner or left join, row-capped, keys compared as normalised text. Each side is guarded, bounded and "
        "masked under its own connection's policy; masked values never match.",
        db_federated_join,
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
            _require_printable(schema2, name)
            row_limit = policy.clamp_sample_limit(limit)
            allowed_cols = {c.name for c in await run_meta(app, connection_id, lambda c: c.list_columns(schema2, name))}
            if columns:
                bad = [c for c in columns if c not in allowed_cols]
                if bad:
                    raise ToolFailure(ErrorCategory.VALIDATION, f"unknown columns: {_names_text(bad)}")
                named = [c for c in columns if _printable(c)]
                if len(named) < len(columns):
                    st["warnings"].append(
                        f"{len(columns) - len(named)} column(s) whose names hold control characters were not sampled"
                    )
                    if not named:
                        raise ToolFailure(ErrorCategory.VALIDATION, "no requested column can be sampled")
                    columns = named
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
            outcome = await _audited_query(app, st, connection_id, spec, f"sample on '{connection_id}'")
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
            if parameters:
                # a plan is captured for the statement text as written; a bound
                # value that is silently dropped would plan a different statement
                raise ToolFailure(
                    ErrorCategory.VALIDATION,
                    "db_explain does not bind parameters: inline the literal values in the statement "
                    "(the plan is captured for the text as written) or leave parameters empty",
                )
            connector, policy = _require_engine(app, connection_id)
            result = await _validated(app, connector, policy, lambda g: g.validate_explain(sql))
            if analyze and not policy.allow_explain_analyze:
                raise ToolFailure(ErrorCategory.POLICY, "EXPLAIN ANALYZE is disabled by policy")
            if analyze:
                # allow_explain_analyze only picks this refusal over the one
                # above: no connector executes a statement to plan it, and the
                # guard refuses EXPLAIN ANALYZE written in the text alike
                raise ToolFailure(
                    ErrorCategory.VALIDATION,
                    "analyze=true is not supported by db_explain: plans are captured without executing the "
                    "statement; call it without analyze",
                )
            # the engine sees the statement the guard validated, as written:
            # re-rendering the AST drops clauses sqlglot does not carry (Db2
            # WITH UR, OPTIMIZE FOR n ROWS), which would plan a different text
            statement = result.text or result.ast.sql(dialect=sqlglot_dialect(policy.engine))
            st["connector"] = connector  # discarded on cancellation
            plan = await app.executor.run_bounded(
                connector,
                lambda c: c.explain(statement, False),
                policy.clamp_timeout(None),
                description=f"explain on '{connection_id}'",
                on_start=_sends(st),
            )
            if policy.engine == "mysql" and not _tabular_plan(plan) and _names_masked_columns(policy, result.ast):
                # MySQL reads a const table (a primary or unique key equality)
                # while it plans and prints its values into TREE and JSON
                # plans, masked ones included (live, 9.7: Filter: (b.bean_origin
                # = 'R. Haddad'); review, 2026-09-28); the tabular one prints none
                raise ToolFailure(
                    ErrorCategory.POLICY,
                    "this plan is not returned: MySQL reads const tables (rows a primary or unique key equality "
                    "finds) while it plans, and prints their values into TREE and JSON plans, and this statement "
                    "names a masked column (or selects *, or joins NATURAL); use EXPLAIN FORMAT=TRADITIONAL, "
                    "which prints no values",
                )
            if isinstance(plan, dict) and plan.get("cleanup_warning"):
                st["warnings"].append(str(plan.pop("cleanup_warning")))
            st["row_count"] = 1
            return _envelope(
                st,
                connection_id,
                policy.engine,
                {
                    "plan": plan,
                    "raw_preserved": True,
                    "note": "raw plan output is preserved; no optimization findings are invented; the plan names "
                    "every object the engine touches, including base tables behind a permitted view",
                },
                warnings=st["warnings"],
            )

    register(
        "db_explain",
        "Non-executing query plan for validated SQL. EXPLAIN ANALYZE (analyze=true) is never run: plans are captured "
        "without executing the statement. On MySQL a TREE or JSON plan of a statement naming a masked column is "
        "not returned (MySQL prints values it reads while planning); FORMAT=TRADITIONAL is.",
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
                {
                    "history": data,
                    "note": "operational history of this server process (under HTTP, every client's calls); raw "
                    "SQL text is not included",
                },
            )

    register(
        "db_get_query_history",
        "Redacted operational history of this server process (fingerprints, not raw SQL); under HTTP it holds "
        "every client's calls. Not a substitute for the audit log.",
        db_get_query_history,
    )


    # ---- discovery: indexes, catalog snapshot, profiling, value search, inference

    async def _permitted_tables(
        app_: AppContext,
        connector: DatabaseConnector,
        policy: EffectivePolicy,
        schema: str | None,
        include_system: bool = True,
    ) -> list[Any]:
        tables = [t for t in await app_.tables_for(policy, connector) if _readable(policy, t)]
        if schema is not None:
            if not (policy.schema_allowed(schema) or policy.system_schema_allowed(schema)):
                raise ToolFailure(
                    ErrorCategory.AUTHZ, f"schema '{schema}' is not permitted on connection '{policy.connection_id}'"
                )
            await _check_schema_spelling(app_, connector, policy, schema)
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
        cursor: str | None = None,
    ) -> dict[str, Any]:
        async with tool_span(app, "db_list_indexes", connection_id) as st:
            connector, policy = _require_engine(app, connection_id)
            if object_name:
                schema2, name = await _resolve_object(app, connector, policy, schema, object_name)
                indexes = await run_meta(app, connection_id, lambda c: c.list_indexes(schema2, name))
                kind = f"indexes:{schema2}.{name}"
            else:
                kind = f"indexes:{schema or '*'}:{int(include_system)}"
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
            window, next_cursor = _page(
                app, indexes, cursor, kind=kind, connection_id=connection_id, policy=policy,
                page_size=len(indexes), render=lambda i: _index_entry(policy, i, st), st=st,
            )
            st["row_count"] = len(window)
            return _envelope(
                st, connection_id, policy.engine, {"indexes": window}, warnings=st["warnings"],
                next_cursor=next_cursor, returned_row_count=len(window), truncated=next_cursor is not None,
            )

    register(
        "db_list_indexes",
        "Indexes and primary keys of one permitted object, or of every permitted table in a schema "
        "(ClickHouse: sorting keys and data-skipping indices); paged by the response byte ceiling.",
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
            kind = f"catalog:{schema or '*'}:{int(include_indexes)}:{int(include_system)}"
            offset = _cursor_offset(app, cursor, kind=kind, connection_id=connection_id, policy=policy)
            page = tables[offset : offset + size]
            out_tables = await _catalog_tables(
                app, connection_id, policy, page, include_indexes, st, await _schema_view(app, connector, policy)
            )
            # page_size counts tables; the byte ceiling may end the page earlier
            # and the cursor resumes at the first table that did not fit
            out_tables = _fit_entries(st, out_tables, _item_budget(policy.max_response_bytes), _json_size, "columns")
            end = offset + len(out_tables)
            next_cursor = (
                _cursor_for(app, end, kind=kind, connection_id=connection_id, policy=policy)
                if end < len(tables) else None
            )
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
                warnings=st["warnings"],
                next_cursor=next_cursor,
            )


    async def db_review_schema(
        connection_id: str,
        schema: str | None = None,
        max_tables: int = 25,
        sample_rows: int | None = None,
        include_top_values: bool = False,
        include_system: bool = False,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        async with tool_span(app, "db_review_schema", connection_id) as st:
            connector, policy = _require_engine(app, connection_id)
            size = max(1, min(int(max_tables), _REVIEW_MAX_TABLES))
            tables = await _permitted_tables(app, connector, policy, schema, include_system)
            tables = [t for t in tables if t.kind == "table"]
            # biggest tables first: that is where an index or a type change pays
            tables.sort(key=lambda t: (t.row_estimate is None, -(t.row_estimate or 0), (t.schema or "").lower(),
                                       t.name.lower()))
            kind = f"review:{schema or '*'}:{int(include_system)}"
            offset = _cursor_offset(app, cursor, kind=kind, connection_id=connection_id, policy=policy)
            page = tables[offset : offset + size]
            next_cursor = (
                _cursor_for(app, offset + size, kind=kind, connection_id=connection_id, policy=policy)
                if offset + size < len(tables) else None
            )
            budget = float(policy.discovery_time_budget_seconds)
            deadline = time.monotonic() + budget
            share = max(_REVIEW_MIN_TABLE_SECONDS, budget / max(1, len(page)))
            reviewed: list[dict[str, Any]] = []
            recommendations: list[dict[str, Any]] = []
            by_severity: dict[str, int] = {}
            by_code: dict[str, int] = {}
            exhausted = False
            used_bytes = 0
            byte_budget = _item_budget(policy.max_response_bytes)

            def charged(entry: dict[str, Any]) -> int:
                # every finding is sent twice: in its table and in recommendations
                return _json_size(entry) + sum(
                    _json_size({"schema": entry["schema"], "table": entry["name"], **f}) for f in entry["findings"]
                )

            st["connector"] = connector
            for i, t in enumerate(page):
                now = time.monotonic()
                if now >= deadline:
                    exhausted = True
                    st["warnings"].append(
                        f"discovery time budget of {budget:.0f}s exhausted after {len(reviewed)} of {len(page)} "
                        "tables; continue with the cursor"
                    )
                    next_cursor = _cursor_for(app, offset + i, kind=kind, connection_id=connection_id, policy=policy)
                    break
                table_deadline = min(deadline, now + share)
                try:
                    data = await _profile_object(
                        app, connection_id, connector, policy, st, t.schema, t.name,
                        columns=None, sample_rows=sample_rows, include_top_values=include_top_values,
                        deadline=table_deadline,
                    )
                except AuditWriteFailure:
                    raise  # fail closed: a statement that ran without its audit record ends the call
                except Exception as exc:  # noqa: BLE001 - one unreadable table must not end the review
                    st["warnings"].append(f"{t.schema}.{t.name}: {_error_text(exc)}")
                    continue
                entry = {
                    "schema": t.schema, "name": t.name, "row_estimate": data["row_estimate"],
                    "sample_rows": data["sample"]["rows"], "findings": data["findings"],
                }
                size = charged(entry)
                if reviewed and used_bytes + size > byte_budget:
                    # the ceiling binds the whole review, not each aggregate row;
                    # resume exactly here rather than dropping tables silently
                    exhausted = True
                    st["warnings"].append(
                        f"response byte ceiling (security.max_response_bytes) reached after {len(reviewed)} of "
                        f"{len(page)} tables; continue with the cursor"
                    )
                    next_cursor = _cursor_for(app, offset + i, kind=kind, connection_id=connection_id, policy=policy)
                    break
                if not reviewed and size > byte_budget:
                    size = _trim_entry(st, entry, byte_budget, charged, "findings")
                used_bytes += size
                reviewed.append(entry)
                for f in entry["findings"]:
                    by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1
                    by_code[f["code"]] = by_code.get(f["code"], 0) + 1
                    recommendations.append({"schema": t.schema, "table": t.name, **f})
            recommendations.sort(key=lambda r: (_SEVERITY_RANK.get(r["severity"], 9), r["code"], r["table"]))
            st["row_count"] = len(reviewed)
            return _envelope(
                st, connection_id, policy.engine,
                {
                    "schema": schema,
                    "tables": reviewed,
                    "summary": {
                        "tables_in_scope": len(tables),
                        "tables_reviewed": len(reviewed),
                        "tables_with_findings": sum(1 for r in reviewed if r["findings"]),
                        "by_severity": by_severity,
                        "by_code": by_code,
                    },
                    "recommendations": recommendations[:_REVIEW_MAX_RECOMMENDATIONS],
                    "budget_exhausted": exhausted,
                    "note": "each finding carries its evidence and a suggestion; 'sampled' means the measures "
                    "come from the first rows only. Nothing here changes the database.",
                },
                next_cursor=next_cursor,
                warnings=st["warnings"],
            )

    register(
        "db_review_schema",
        "Optimization review of the permitted tables of a schema or connection: profiles each table on a "
        "bounded sample under one time budget and returns prioritized, evidence-backed findings (missing "
        "keys, unindexed foreign keys, oversized or never-null columns, enum candidates, stale statistics). "
        "Biggest tables first, paged, read-only.",
        db_review_schema,
    )

    async def db_document_schema(
        connection_id: str,
        schema: str | None = None,
        include_indexes: bool = True,
        include_system: bool = False,
        cursor: str | None = None,
        page_size: int = 25,
    ) -> dict[str, Any]:
        async with tool_span(app, "db_document_schema", connection_id) as st:
            connector, policy = _require_engine(app, connection_id)
            size = max(1, min(int(page_size), _DOCUMENT_MAX_TABLES))
            tables = await _permitted_tables(app, connector, policy, schema, include_system)
            tables = sorted(tables, key=lambda t: ((t.schema or "").lower(), t.name.lower()))
            kind = f"document:{schema or '*'}:{int(include_indexes)}:{int(include_system)}"
            offset = _cursor_offset(app, cursor, kind=kind, connection_id=connection_id, policy=policy)
            page = tables[offset : offset + size]
            next_cursor = (
                _cursor_for(app, offset + size, kind=kind, connection_id=connection_id, policy=policy)
                if offset + size < len(tables) else None
            )
            entries = await _catalog_tables(
                app, connection_id, policy, page, include_indexes, st, await _schema_view(app, connector, policy)
            )
            # the byte ceiling binds the rendered document: each table is charged
            # the UTF-8 bytes it adds to the page (its section and its declared
            # relationships); whole tables are kept and the cursor resumes at
            # the first one that did not fit
            empty = len(render_data_dictionary(connection_id, policy.engine, [], schema=schema).encode("utf-8"))

            def rendered(entry: dict[str, Any]) -> int:
                one = render_data_dictionary(connection_id, policy.engine, [entry], schema=schema)
                return len(one.encode("utf-8")) - empty

            kept = _fit_entries(st, entries, _item_budget(policy.max_response_bytes), rendered, "columns")
            if len(kept) < len(page):  # the byte ceiling or the time budget ended the page early
                next_cursor = _cursor_for(
                    app, offset + len(kept), kind=kind, connection_id=connection_id, policy=policy
                )
            entries = kept
            markdown = render_data_dictionary(connection_id, policy.engine, entries, schema=schema)
            st["row_count"] = len(entries)
            return _envelope(
                st, connection_id, policy.engine,
                {
                    "format": "markdown",
                    "markdown": markdown,
                    "tables": len(entries),
                    "table_count": len(tables),
                    "note": "generated from catalog metadata only; no table data was read. Column notes "
                    "marked 'sensitive' come from the security.mask_columns name heuristic.",
                },
                next_cursor=next_cursor,
                warnings=st["warnings"],
            )

    register(
        "db_document_schema",
        "Data dictionary (Markdown) of the permitted tables of a schema or connection: every column with "
        "its declared and portable type, nullability, defaults, keys, indexes and comments, plus the "
        "declared relationships. Paged; metadata only, no table data is read.",
        db_document_schema,
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
            deadline = time.monotonic() + float(policy.discovery_time_budget_seconds)
            data = await _profile_object(
                app, connection_id, connector, policy, st, schema2, name,
                columns=columns, sample_rows=sample_rows, include_top_values=include_top_values, deadline=deadline,
            )
            st["row_count"] = data["sample"]["rows"]
            return _envelope(st, connection_id, policy.engine, data, warnings=st["warnings"])

    register(
        "db_profile_table",
        "Bounded data profile of one permitted table (null ratio, distinct, min/max, string lengths, "
        "top values for low-cardinality columns) plus evidence-backed optimization findings. "
        "Runs over a sample under the session safety profile; sensitive columns return counts only.",
        db_profile_table,
    )

    async def db_search_values(
        query: str,
        connections: _IdList | None = None,
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
            conn_ids = _select_connections(app, connections)
            if schemas is not None and not schemas:
                raise ToolFailure(ErrorCategory.VALIDATION, "schemas must be omitted or non-empty")
            per_table = max(1, min(int(max_hits_per_table), 50))
            table_cap = max(1, min(int(max_tables), 500))
            budget = max(1.0, min(float(time_budget_seconds), 300.0))
            per_table_timeout = max(1.0, min(float(per_table_timeout_seconds), 120.0))
            byte_ceiling: int | None = None
            hit_bytes = 0
            candidates_total = 0  # permitted tables in scope, across the connections reached
            considered = 0  # tables the loop actually looked at (searched or skipped)
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
            out_of_bytes = False  # the byte ceiling, not the clock, ended the search
            connections_not_searched: list[str] = []  # never reached: the budget or the byte ceiling ended first
            connections_failed: list[str] = []  # reached, but unusable (dead or metadata unavailable)
            partially: list[dict[str, Any]] = []  # searched, but some searchable columns were not
            unsafe_names = 0  # catalog names holding control characters: never put into generated SQL
            read_from: list[str] = []  # connections a statement actually ran on (the span's audit record)
            st["connection_ids"] = read_from
            for i, cid in enumerate(conn_ids):
                if exhausted or time.monotonic() > deadline:
                    exhausted = True
                    connections_not_searched = conn_ids[i:]
                    break
                try:
                    connector, policy = _require_engine(app, cid)
                    tables = await app.tables_for(policy, connector)
                except Exception as exc:  # noqa: BLE001 - one dead connection must not end the search
                    if connections is not None and len(conn_ids) == 1:
                        raise
                    connections_failed.append(cid)
                    warnings.append(f"connection '{cid}' skipped: {_error_text(exc)}")
                    continue
                # the policy's discovery budget and byte ceiling bind the whole search
                budget = min(budget, float(policy.discovery_time_budget_seconds))
                deadline = min(deadline, time.monotonic() + budget)
                byte_ceiling = (
                    policy.max_response_bytes if byte_ceiling is None
                    else min(byte_ceiling, policy.max_response_bytes)
                )
                tables = [t for t in tables if t.kind == "table" and _readable(policy, t)]
                if wanted_schemas is not None:
                    tables = [t for t in tables if (t.schema or "").lower() in wanted_schemas]
                elif not include_system:
                    tables = [t for t in tables if not is_system_object(policy.engine, t.schema, t.name)]
                catalog: dict[str | None, tuple[_TableSplit, _TableSplit]] = {}
                folded = _folded_names(tables)
                candidates_total += len(tables)
                for t in tables:
                    if searched >= table_cap:
                        break
                    if time.monotonic() > deadline:
                        exhausted = True
                        break
                    considered += 1
                    if not (_printable(t.schema) and _printable(t.name)):
                        unsafe_names += 1
                        continue
                    if t.schema not in catalog:
                        try:
                            all_cols = await run_meta(app, cid, _meta_call("list_all_columns", t.schema))
                        except Exception as exc:  # noqa: BLE001 - that schema is reported, the others searched
                            warnings.append(f"{cid}.{t.schema}: columns unavailable: {_error_text(exc)}")
                            all_cols = []
                        try:
                            all_idx = await run_meta(app, cid, _meta_call("list_indexes", t.schema, None))
                        except Exception:  # noqa: BLE001 - keys only order the projection; searching goes on
                            all_idx = []
                        catalog[t.schema] = (
                            _split_by_table(all_cols, t.schema, _column_owner),
                            _split_by_table(all_idx, t.schema, _index_owner),
                        )
                    col_split, idx_split = catalog[t.schema]
                    unique = folded[((t.schema or "").lower(), t.name.lower())] == 1
                    cols = col_split.get(t.schema, t.name, unique_on_page=unique)
                    named = [c for c in cols if _printable(c.name)]
                    unsafe_names += len(cols) - len(named)
                    visible = [c.name for c in named if not _sensitive(policy, c.name)]
                    matchable: list[tuple[Any, Any]] = []
                    for c in named:
                        pt = portable_type(policy.engine, c.data_type)
                        if c.name in visible and (
                            pt.kind == "string" or (pt.kind == "numeric" and numeric is not None and match == "exact")
                        ):
                            matchable.append((c, pt))
                    if not matchable:
                        skipped += 1
                        continue
                    primary = next(
                        (ix for ix in idx_split.get(t.schema, t.name, unique_on_page=unique) if ix.primary), None
                    )
                    pk = [n for n in primary.columns if n in visible] if primary is not None else []
                    # a key names a row only whole and unique: rows that share
                    # the visible part of one whose other column is sensitive,
                    # or a ClickHouse sorting key, are different rows
                    keys = pk if primary is not None and primary.unique and pk == primary.columns else []
                    searched += 1
                    table_hits = done = 0  # hits from this table; its matchable columns already searched
                    found: list[tuple[int, dict[str, Any]]] = []  # (chunk start, hit) of this table's hits
                    complete = True  # every statement so far returned all the rows it matched
                    stopped: str | None = None  # why columns were left unsearched
                    table_deadline = min(deadline, time.monotonic() + per_table_timeout)
                    # Every column a predicate reads is also projected: a row
                    # that matched in a column the SELECT list left out was
                    # dropped, and it used up the LIMIT. Wide tables are
                    # searched in chunks of columns, one statement each.
                    for start in range(0, len(matchable), _SEARCH_CHUNK_COLUMNS):
                        if table_hits >= per_table:
                            break
                        if start >= _SEARCH_MAX_COLUMNS:
                            stopped = f"at most {_SEARCH_MAX_COLUMNS} columns per table"
                            break
                        now = time.monotonic()
                        if now > table_deadline:
                            exhausted = exhausted or now > deadline
                            stopped = "time budget" if now > deadline else "per_table_timeout_seconds"
                            break
                        chunk = matchable[start : min(start + _SEARCH_CHUNK_COLUMNS, _SEARCH_MAX_COLUMNS)]
                        chunk_names = [c.name for c, _pt in chunk]
                        chosen = {*chunk_names, *pk}
                        if not keys and len(matchable) > _SEARCH_CHUNK_COLUMNS:
                            # without a key a row is recognised by every column
                            # an earlier hit matched in and by the leading
                            # columns each statement reads (_earlier_hit)
                            chosen.update(n for _s, h in found for n in h["matched_columns"])
                            chosen.update(visible[:_SEARCH_MAX_SELECT])
                        context = [n for n in visible if n not in chosen]
                        chosen.update(context[: max(0, _SEARCH_MAX_SELECT - len(chosen))])
                        preds, params = _value_search_predicates(connector, chunk, needle, numeric, match)
                        # a row an earlier chunk reported can come back: it is
                        # merged, not counted, so it must not take a new row's place
                        limit = per_table
                        sql = connector.build_search_query(
                            t.schema,
                            t.name,
                            [n for n in visible if n in chosen],
                            " OR ".join(preds),
                            limit,
                        )
                        spec = QuerySpec(
                            sql=sql,
                            parameters=connector.pack_parameters(params),
                            max_rows=limit,
                            max_response_bytes=policy.max_response_bytes,
                            max_cell_bytes=policy.max_cell_bytes,
                            timeout_seconds=min(policy.clamp_timeout(None), max(1.0, table_deadline - now)),
                        )
                        if cid not in read_from:
                            read_from.append(cid)
                        try:
                            outcome = await _audited_query(app, st, cid, spec, f"value search on '{cid}'")
                        except AuditWriteFailure:
                            raise  # fail closed: a statement that ran without its audit record ends the call
                        except Exception as exc:  # noqa: BLE001 - one unreadable table must not end the search
                            warnings.append(f"{cid}.{t.schema}.{t.name}: {_error_text(exc)}")
                            break
                        done = start + len(chunk)
                        columns2, rows = _apply_masking(policy, outcome.columns, outcome.rows, st)
                        names = [n for n, _t in columns2]
                        joined: set[int] = set()  # earlier hits a row of this statement joined
                        for row in rows:
                            values = dict(zip(names, row, strict=False))
                            where = [
                                n for n in chunk_names
                                if values.get(n) is not None and _value_matches(values[n], needle, numeric, match)
                            ]
                            if not where:
                                continue  # the engine matched on a masked value; not a hit we can show
                            earlier = _earlier_hit(found, start, values, keys, joined, complete)
                            if earlier is None and table_hits >= per_table:
                                continue
                            hit = _merged_hit(earlier, where, values) if earlier is not None else {
                                "connection": cid, "schema": t.schema, "table": t.name,
                                "matched_columns": where, "row": values,
                            }
                            hit_bytes += len(json.dumps(hit, default=str)) - (
                                0 if earlier is None else len(json.dumps(earlier, default=str))
                            )
                            if byte_ceiling is not None and hit_bytes > byte_ceiling:
                                warnings.append(
                                    "response byte ceiling reached (security.max_response_bytes); results are partial"
                                )
                                exhausted = out_of_bytes = True
                                break
                            if earlier is not None:
                                earlier.update(hit)
                                joined.add(id(earlier))
                                continue
                            hits.append(hit)
                            found.append((start, hit))
                            table_hits += 1
                        # a statement cut at its LIMIT (or byte ceiling) left rows it matched unreported
                        complete = complete and not outcome.truncated and len(outcome.rows) < limit
                        if exhausted:
                            break
                    if stopped is not None and done < len(matchable) and table_hits < per_table:
                        partially.append({
                            "connection": cid, "schema": t.schema, "table": t.name,
                            "columns_searched": done, "columns_searchable": len(matchable),
                        })
                        warnings.append(
                            f"{cid}.{t.schema}.{t.name}: {done} of {len(matchable)} searchable columns were searched "
                            f"({stopped}); a value in the others is NOT reported"
                        )
                    if exhausted:
                        break
            st["row_count"] = len(hits)
            not_reached = max(0, candidates_total - considered)
            if not_reached:
                warnings.append(
                    f"{not_reached} permitted table(s) were not searched (max_tables={table_cap}"
                    + ((", byte ceiling" if out_of_bytes else ", time budget") if exhausted else "")
                    + "); a needle in one of them is NOT reported: narrow with schemas or raise max_tables"
                )
            if unsafe_names:
                warnings.append(
                    f"{unsafe_names} table(s) or column(s) whose names hold control characters were not searched"
                )
            if connections_not_searched:
                warnings.append(
                    f"{len(connections_not_searched)} connection(s) were never searched (the time budget or the "
                    f"byte ceiling ended the search first): {', '.join(connections_not_searched)}"
                )
            if exhausted and not out_of_bytes:
                warnings.append(f"time budget of {budget:.0f}s exhausted; results are partial")
            if warnings:
                st["warnings"].extend(warnings)
            return _envelope(
                st, None, None,
                {
                    "query": query, "match": match, "hits": hits,
                    "tables_searched": searched, "tables_skipped_no_candidate_columns": skipped,
                    "tables_not_searched": not_reached,
                    "tables_partially_searched": partially,
                    "connections_not_searched": connections_not_searched,
                    "connections_failed": connections_failed,
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
        connections: _IdList | None = None,
        schemas: list[str] | None = None,
        cross_connection: bool = True,
        include_system: bool = False,
    ) -> dict[str, Any]:
        async with tool_span(app, "db_infer_relationships") as st:
            conn_ids = _select_connections(app, connections)
            if schemas is not None and not schemas:
                raise ToolFailure(ErrorCategory.VALIDATION, "schemas must be omitted or non-empty")
            wanted = {s.lower() for s in schemas} if schemas else None
            facts: list[TableFacts] = []
            warnings: list[str] = []
            policies: dict[str, EffectivePolicy] = {}
            views: dict[str, _SchemaView] = {}  # each connection's, for the relationships' targets
            # One deadline and one schema count across the whole catalog
            # fan-out: three bulk calls per schema, each allowed _META_TIMEOUT,
            # over hundreds of schemas held an executor slot for minutes.
            budget = math.inf
            exhausted = False
            schemas_read = 0
            left_out = 0  # tables of schemas whose catalog was not read (budget or schema cap)
            capped_schemas = 0
            for i, cid in enumerate(conn_ids):
                if time.monotonic() >= st["start"] + budget:
                    exhausted = True
                    warnings.append(
                        f"discovery time budget of {budget:.0f}s exhausted before connection(s) "
                        f"{', '.join(conn_ids[i:])} were read; narrow with connections or schemas"
                    )
                    break
                try:
                    connector, policy = _require_engine(app, cid)
                    tables = await app.tables_for(policy, connector)
                except Exception as exc:  # noqa: BLE001 - one dead connection must not end inference
                    if connections is not None and len(conn_ids) == 1:
                        raise
                    warnings.append(f"connection '{cid}' skipped: {_error_text(exc)}")
                    continue
                policies[cid] = policy
                views[cid] = await _schema_view(app, connector, policy)
                budget = min(budget, float(policy.discovery_time_budget_seconds))
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
                per_schema: dict[str | None, tuple[_TableSplit, _TableSplit, _TableSplit]] = {}
                in_scope = sorted({t.schema for t in tables}, key=lambda x: x or "")
                room = max(0, _DISCOVERY_INFER_MAX_SCHEMAS - schemas_read)
                capped_schemas += max(0, len(in_scope) - room)
                for sch in in_scope[:room]:
                    if time.monotonic() >= st["start"] + budget:
                        exhausted = True
                        break
                    schemas_read += 1
                    try:
                        cols = await run_meta(app, cid, _meta_call("list_all_columns", sch))
                        idx = await run_meta(app, cid, _meta_call("list_indexes", sch, None))
                        fks = await run_meta(app, cid, _meta_call("get_foreign_keys", sch, None))
                    except Exception as exc:  # noqa: BLE001 - that schema is reported, the others inferred
                        warnings.append(f"{cid}.{sch}: metadata unavailable: {_error_text(exc)}")
                        cols, idx, fks = [], [], []
                    per_schema[sch] = (
                        _split_by_table(cols, sch, _column_owner),
                        _split_by_table(idx, sch, _index_owner),
                        _split_by_table(fks, sch, _fk_owner),
                    )
                left_out += sum(1 for t in tables if t.schema not in per_schema)
                tables = [t for t in tables if t.schema in per_schema]
                folded = _folded_names(tables)
                for t in tables:
                    col_split, idx_split, fk_split = per_schema[t.schema]
                    unique = folded[((t.schema or "").lower(), t.name.lower())] == 1
                    facts.append(TableFacts(
                        ref=TableRef(cid, t.schema, t.name), engine=policy.engine,
                        columns=col_split.get(t.schema, t.name, unique_on_page=unique),
                        indexes=idx_split.get(t.schema, t.name, unique_on_page=unique),
                        foreign_keys=fk_split.get(t.schema, t.name, unique_on_page=unique),
                    ))
            if exhausted and left_out:
                warnings.append(
                    f"discovery time budget of {budget:.0f}s exhausted: {left_out} table(s) whose catalog was not "
                    "read were left out; narrow with connections or schemas"
                )
            elif capped_schemas:
                warnings.append(
                    f"at most {_DISCOVERY_INFER_MAX_SCHEMAS} schemas are read per call: {left_out} table(s) in "
                    f"{capped_schemas} further schema(s) were left out; narrow with connections or schemas"
                )
            # pairing every column with every key is CPU work: off the event loop
            rels = await anyio.to_thread.run_sync(
                lambda: infer_relationships(facts, cross_connection=cross_connection)
            )
            rels = [
                r for r in rels
                if r.target.connection not in views or views[r.target.connection].visible(r.target.schema)
            ]
            ceiling = min(
                (p.max_response_bytes for p in policies.values()), default=app.cfg.security.max_response_bytes
            )
            kept, dropped = await anyio.to_thread.run_sync(_bound_relationships, rels, _item_budget(ceiling))
            if dropped:
                warnings.append(
                    f"{dropped} relationship(s) not returned: at most {_INFER_MAX_RELATIONSHIPS} inferred "
                    f"candidates, {_INFER_MAX_PER_COLUMN} per source column, within security.max_response_bytes "
                    f"({ceiling}); declared keys come first. Narrow with connections or schemas"
                )
            st["row_count"] = len(kept)
            if warnings:
                st["warnings"].extend(warnings)
            return _envelope(
                st, None, None,
                {
                    "relationships": kept,
                    "tables_considered": len(facts),
                    "truncated": dropped > 0,
                    "more_available": dropped,
                    "budget_exhausted": exhausted,
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
    if isinstance(value, dict) and isinstance(value.get("$binary_b64"), str):
        # a binary cell as the connectors hand it over (driver_helpers), its
        # head when "$truncated": ClickHouse's FixedString is one
        try:
            value = base64.b64decode(value["$binary_b64"], validate=True)
        except ValueError:
            return False
    if isinstance(value, bytes | bytearray):
        # a FixedString is NUL-padded to its width; str() of the bytes is
        # "b'...'", which never matched
        value = bytes(value).decode("utf-8", errors="replace").rstrip("\x00")
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



def _earlier_hit(
    found: list[tuple[int, dict[str, Any]]],
    chunk: int,
    values: dict[str, Any],
    keys: list[str],
    joined: set[int],
    complete: bool,
) -> dict[str, Any] | None:
    """The hit an earlier column chunk of the same table made of this row,
    or None: the row is then a hit of its own. A hit made by this statement
    (``chunk``), or one another of its rows already joined (``joined``, by
    id), is never it: one statement's rows are distinct rows. A unique key
    names the row. Without one, a row alike to an earlier hit - the same
    value in every column that hit matched in (each chunk reads them again)
    and in every other column both statements read - matched that hit's
    chunk too, so it is one of the earlier hits when every earlier statement
    returned all the rows it matched (``complete``). It joins one only when
    which is certain: the only alike hit, or alike hits that all show the
    same values. Joining one of several that differ could show another
    row's values; a repeated hit is the lesser harm."""

    def same(row: dict[str, Any], names: Iterable[str]) -> bool:
        return all(json.dumps(row.get(n), default=str) == json.dumps(values.get(n), default=str) for n in names)

    earlier = [hit for seen, hit in found if seen != chunk and id(hit) not in joined]
    if keys:
        return next((hit for hit in earlier if same(hit["row"], keys)), None)
    if not complete:
        return None
    alike = [
        hit for hit in earlier
        if all(n in values for n in hit["matched_columns"]) and same(hit["row"], (n for n in values if n in hit["row"]))
    ]
    shown = {json.dumps(hit["row"], sort_keys=True, default=str) for hit in alike}
    return alike[0] if len(shown) == 1 else None


def _merged_hit(hit: dict[str, Any], where: list[str], values: dict[str, Any]) -> dict[str, Any]:
    """``hit`` with the columns a later chunk matched it in, and their values."""
    return {
        **hit,
        "matched_columns": [*hit["matched_columns"], *(n for n in where if n not in hit["matched_columns"])],
        "row": {**hit["row"], **{n: v for n, v in values.items() if n not in hit["row"]}},
    }


class _TableSplit:
    """One schema-wide catalog list (columns, indexes or foreign keys)
    assigned to tables by the exact (schema, table) the catalog names. Quoted
    names are case-sensitive on PostgreSQL, Oracle and Db2 and every name is
    on ClickHouse, so "Case_T" and case_t are two tables: a lower-cased match
    gave each the union of both. A table falls back to a case-insensitive
    match only when its folded name is unique on the page and the list spells
    it one way; several spellings are never merged."""

    def __init__(self, exact: dict[tuple[str, str], list[Any]]) -> None:
        self._exact = exact
        self._folded: dict[tuple[str, str], list[tuple[str, str]]] = {}
        for key in exact:
            self._folded.setdefault((key[0].lower(), key[1].lower()), []).append(key)

    def get(self, schema: str | None, name: str, *, unique_on_page: bool) -> list[Any]:
        found = self._exact.get((schema or "", name))
        if found is not None:
            return found
        spellings = self._folded.get(((schema or "").lower(), name.lower()), [])
        return self._exact[spellings[0]] if unique_on_page and len(spellings) == 1 else []


def _split_by_table(
    items: Iterable[Any], schema: str | None, owner: Callable[[Any], tuple[str | None, str | None]]
) -> _TableSplit:
    """Split a list fetched for ``schema`` by ``owner(item)`` = (schema,
    table); an entry without a schema belongs to the one it was fetched for.
    One pass, instead of scanning the whole list once per table."""
    exact: dict[tuple[str, str], list[Any]] = {}
    for item in items:
        item_schema, table = owner(item)
        exact.setdefault((item_schema or schema or "", table or ""), []).append(item)
    return _TableSplit(exact)


def _folded_names(tables: Iterable[Any]) -> Counter[tuple[str, str]]:
    """How many tables of a page share each case-folded (schema, name)."""
    return Counter(((t.schema or "").lower(), t.name.lower()) for t in tables)


def _column_owner(c: Any) -> tuple[str | None, str | None]:
    return c.schema, c.table


def _index_owner(i: Any) -> tuple[str | None, str | None]:
    return i.schema, i.table


def _fk_owner(k: Any) -> tuple[str | None, str | None]:
    return k.source_schema, k.source_table


def _json_size(value: Any) -> int:
    """UTF-8 bytes of ``value`` as the compact JSON text a response carries."""
    return len(json.dumps(value, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8", "replace"))


def _rows_within(rows: list[list[Any]], budget: int) -> int:
    """How many leading result rows fit ``budget`` bytes, each measured as
    the connectors measure it while fetching."""
    used = 0
    for n, row in enumerate(rows):
        used += len(json.dumps(row, default=str).encode("utf-8", "replace"))
        if used > budget:
            return n
    return len(rows)


def _item_budget(ceiling: int) -> int:
    """The part of security.max_response_bytes a pager may fill with items;
    the rest is the envelope's (ids, counts, notes, warnings)."""
    return ceiling - min(_ENVELOPE_ALLOWANCE, ceiling // 8)


def _bound_relationships(rels: list[Any], budget: int) -> tuple[list[dict[str, Any]], int]:
    """Declared keys first, then inferred candidates by confidence; at most
    _INFER_MAX_RELATIONSHIPS inferred ones and _INFER_MAX_PER_COLUMN per
    source column, and never past ``budget`` bytes. The count caps never drop
    a declared key. Returns (the relationships as dicts, how many were not)."""
    ordered = sorted(rels, key=lambda r: (r.kind != "declared", -r.confidence))
    kept: list[dict[str, Any]] = []
    inferred = used = 0
    per_column: Counter[tuple[Any, ...]] = Counter()
    for r in ordered:
        column = (r.source.connection, r.source.schema, r.source.table, tuple(c.lower() for c in r.source_columns))
        capped = inferred >= _INFER_MAX_RELATIONSHIPS or per_column[column] >= _INFER_MAX_PER_COLUMN
        if r.kind != "declared" and capped:
            continue
        item = r.as_dict()
        size = _json_size(item)
        if kept and used + size > budget:
            break
        used += size
        kept.append(item)
        if r.kind != "declared":
            inferred += 1
            per_column[column] += 1
    return kept, len(ordered) - len(kept)


def _printable(name: str | None) -> bool:
    """False for a catalog name holding NUL or another control character:
    such a name is never put into SQL this server generates (defense in depth
    behind the connectors' identifier quoting)."""
    return name is None or not any(ord(ch) < 32 or ord(ch) == 127 for ch in name)


def _require_printable(schema: str | None, name: str) -> None:
    """Refuse one object whose schema or name holds a control character: a
    statement this server generates never names it (a loop over many objects
    skips it with a warning instead)."""
    if not (_printable(schema) and _printable(name)):
        raise ToolFailure(
            ErrorCategory.VALIDATION,
            "the object's schema or name holds a control character; no statement is generated for it",
        )


def _value_search_predicates(
    connector: DatabaseConnector, chunk: list[tuple[Any, Any]], needle: str, numeric: int | float | None, match: str
) -> tuple[list[str], list[Any]]:
    """The WHERE terms of one value-search statement, one per (column,
    portable type); the needle is always a bound parameter."""
    preds: list[str] = []
    params: list[Any] = []
    for c, pt in chunk:
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
        else:  # a numeric column, searched only for an exact numeric query
            params.append(numeric)
            preds.append(f"{q} = {connector.placeholder(len(params))}")
    return preds, params


def _meta_call(method: str, *args: Any) -> Callable[[DatabaseConnector], Any]:
    """A typed thunk for run_meta: ``connector.<method>(*args)``."""

    def call(c: DatabaseConnector) -> Any:
        return getattr(c, method)(*args)

    return call


def _sensitive(policy: EffectivePolicy, name: str) -> bool:
    return _sensitive_name(policy.sensitive_patterns, name)


def _masked_default(policy: EffectivePolicy, name: str, default: Any) -> Any:
    """A sensitive column's DEFAULT literal is a value too (legacy schemas
    carry `password ... DEFAULT 'changeme'`); it is hidden like row values."""
    if default is not None and _sensitive(policy, name):
        return "<masked>"
    return default


# DDL text is read with a tokenizer, never a quote-matching regex: an
# apostrophe inside a quoted name ("user's id", [o'k]), a comment or MySQL's
# backslash escape ('it\'s') desynced the regex, which then took the rest of
# the text for a literal and the sensitive name beside a real literal for part
# of it. Every reading the engine may use is tried - backslash escapes or
# not, nested block comments or not - and the text is withheld if any of them
# finds a literal beside a sensitive name, or cannot finish (fail closed).
_DDL_WORD = re.compile(r"[^\W\d][\w$#]*")
_DDL_WORD_NO_HASH = re.compile(r"[^\W\d][\w$]*")  # MySQL and ClickHouse: '#' starts a comment
_DDL_DOLLAR = re.compile(r"\$([^\W\d]\w*)?\$")
_CREATE_TABLE = re.compile(r"(?is)\s*create\b[^(]*\btable\b")
_DdlToken = tuple[str, str]  # (kind, text): lit, ident, dquoted, word, or the punctuation itself


def _ddl_tokens(text: str, engine: str, *, backslash: bool, nested: bool) -> list[_DdlToken] | None:
    """``text`` as tokens: ``lit`` (a string literal; a comment too, whose
    words are also yielded as ``word``), ``ident`` (a quoted name, unquoted),
    ``dquoted`` (a double-quoted token where the engine may read it as a
    string: SQLite, MySQL), ``word``, and ( ) , as themselves. ``backslash``:
    a backslash escapes the next character inside quotes; ``nested``: block
    comments nest. None when a quote or comment never ends."""
    hash_comments = engine in ("mysql", "clickhouse")
    brackets = engine in ("mssql", "sqlite")
    word = _DDL_WORD_NO_HASH if hash_comments else _DDL_WORD
    tokens: list[_DdlToken] = []

    def quoted(i: int, close: str) -> int:
        """The index after the quoted token opening at ``i``, or -1."""
        j = i + 1
        while j < len(text):
            ch = text[j]
            if backslash and ch == "\\" and close != "]":
                j += 2
                continue
            if ch == close:
                if text[j + 1 : j + 2] == close:  # doubled: the character itself
                    j += 2
                    continue
                return j + 1
            j += 1
        return -1

    def comment(body: str) -> None:
        tokens.append(("lit", body))
        tokens.extend(("word", m.group(0)) for m in word.finditer(body))

    i = 0
    while i < len(text):
        ch = text[i]
        if ch.isspace():
            i += 1
        elif text.startswith("--", i) or (hash_comments and ch == "#"):
            end = text.find("\n", i)
            end = len(text) if end == -1 else end
            comment(text[i:end])
            i = end
        elif text.startswith("/*", i):
            depth, j = 1, i + 2
            while depth and j < len(text):
                if nested and text.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif text.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            if depth:
                return None
            comment(text[i:j])
            i = j
        elif ch == "'":
            end = quoted(i, "'")
            if end < 0:
                return None
            tokens.append(("lit", text[i + 1 : end - 1]))
            i = end
        elif ch in '"`' or (brackets and ch == "["):
            end = quoted(i, "]" if ch == "[" else ch)
            if end < 0:
                return None
            name = text[i + 1 : end - 1].replace(("]" if ch == "[" else ch) * 2, "]" if ch == "[" else ch)
            tokens.append(("dquoted" if ch == '"' and engine in ("sqlite", "mysql") else "ident", name))
            i = end
        elif ch == "$" and engine == "postgres" and (dollar := _DDL_DOLLAR.match(text, i)) is not None:
            end = text.find(dollar.group(0), dollar.end())
            if end < 0:
                return None
            tokens.append(("lit", text[dollar.end() : end]))
            i = end + len(dollar.group(0))
        elif ch in "(),":
            tokens.append((ch, ch))
            i += 1
        elif (found := word.match(text, i)) is not None:
            tokens.append(("word", found.group(0)))
            i = found.end()
        else:
            i += 1
    return tokens


def _ddl_parts(tokens: list[_DdlToken], table: bool) -> list[list[_DdlToken]]:
    """A CREATE TABLE's column definitions and constraints (the tokens
    between the commas directly inside its outer parentheses); any other
    definition whole."""
    if not table:
        return [tokens]
    parts: list[list[_DdlToken]] = [[]]
    depth = 0
    for token in tokens:
        if token[0] == "(":
            depth += 1
        elif token[0] == ")":
            depth -= 1
        elif token[0] == "," and depth <= 1:
            parts.append([])
            continue
        parts[-1].append(token)
    return parts


def _literal_beside_sensitive(policy: EffectivePolicy, definition: Any, identifiers: Iterable[str] = ()) -> bool:
    """Whether DDL text carries a string literal where it names a sensitive
    column: a CHECK constraint, generated column, view or partial-index
    predicate can hold a value of that column (password <> 'Sup3rSecret') in
    clear. A table is judged per column definition or constraint (another
    column's DEFAULT literal is harmless), a view or an index as a whole.
    SQLite (and MySQL outside ANSI_QUOTES) also read a double-quoted word as
    a string: there any double-quoted word but the ``identifiers`` (the
    object's own name and columns) counts as one. Text no reading can
    tokenize to its end is withheld wherever it names a sensitive word."""
    if not isinstance(definition, str) or not policy.sensitive_patterns:
        return False
    if "'" not in definition and '"' not in definition and "$" not in definition and "--" not in definition \
            and "/*" not in definition and "#" not in definition:
        return False
    known = {n.lower() for n in identifiers}
    table = bool(_CREATE_TABLE.match(definition))
    for backslash in (False, True):
        for nested in (False, True):
            tokens = _ddl_tokens(definition, policy.engine, backslash=backslash, nested=nested)
            if tokens is None:
                if any(_sensitive(policy, m.group(0)) for m in _DDL_WORD.finditer(definition)):
                    return True
                continue
            for part in _ddl_parts(tokens, table):
                literal = any(
                    kind == "lit" or (kind == "dquoted" and value.lower() not in known) for kind, value in part
                )
                if literal and any(
                    kind in ("ident", "dquoted", "word") and _sensitive(policy, value) for kind, value in part
                ):
                    return True
    return False


def _view_definition(
    policy: EffectivePolicy, definition: Any, st: dict[str, Any], name: str = "", identifiers: Iterable[str] = ()
) -> Any:
    """A listed view's definition under the rule db_get_table applies.
    ``identifiers``: names a double-quoted word in it may be (SQLite's)."""
    if _literal_beside_sensitive(policy, definition, [name, *identifiers]):
        warning = "view definition(s) withheld: they name a sensitive column beside a string literal"
        if warning not in st["warnings"]:
            st["warnings"].append(warning)
        return None
    return _cap_text(definition, policy, st)


async def _quoted_word_names(
    app: AppContext, connection_id: str, policy: EffectivePolicy, views: list[Any]
) -> frozenset[str]:
    """On SQLite, the table and column names of the views' schemas: a
    double-quoted word in a view's text is a string only where it names no
    column, so one that names a column the database has is not taken for a
    literal (a string equal to a column's name would be no secret either).
    Unreadable names leave every double-quoted word a literal (fail closed)."""
    if policy.engine != "sqlite" or not any(isinstance(v.definition, str) and '"' in v.definition for v in views):
        return frozenset()
    names: set[str] = set()
    for schema in sorted({v.schema or "main" for v in views}):
        try:
            columns = await run_meta(app, connection_id, _meta_call("list_all_columns", schema))
        except Exception:  # noqa: BLE001 - the definitions are then judged without these names
            columns = []
        names.update(str(n) for c in columns for n in (c.name, c.table) if n)
    return frozenset(names)


def _index_entry(policy: EffectivePolicy, index: Any, st: dict[str, Any]) -> Any:
    """An index as the discovery tools list it. Its definition is DDL text
    too: a partial-index predicate beside a sensitive column (PostgreSQL:
    WHERE (password = 'changeme'::text)) is withheld like a table's CHECK,
    and any definition is cut to security.max_cell_bytes."""
    entry = dataclasses.asdict(index) if isinstance(index, IndexInfo) else index
    if not isinstance(entry, dict) or not isinstance(entry.get("definition"), str):
        return entry
    if _literal_beside_sensitive(policy, entry["definition"], [str(entry.get("name") or "")]):
        warning = "index definition(s) withheld: they name a sensitive column beside a string literal"
        if warning not in st["warnings"]:
            st["warnings"].append(warning)
        return {**entry, "definition": None}
    return {**entry, "definition": _cap_text(entry["definition"], policy, st)}


def _scoped_table_detail(policy: EffectivePolicy, detail: Any, st: dict[str, Any], view: _SchemaView) -> Any:
    """db_get_table's connector detail under the same rules as the other
    metadata tools: a sensitive column's DEFAULT literal is masked (the column
    itself is kept, as db_list_columns keeps it, whatever mask_action says),
    a DDL definition that would repeat that literal is withheld, definitions
    and comments are cut to security.max_cell_bytes, and foreign keys never
    name a target in a schema the allowlist hides."""
    if not isinstance(detail, dict):
        return detail
    detail = dict(detail)
    literal_hidden = False
    if isinstance(detail.get("columns"), list):
        columns: list[Any] = []
        for col in detail["columns"]:
            if isinstance(col, dict):
                name = str(col.get("name") or "")
                sensitive = _sensitive(policy, name)
                literal_hidden = literal_hidden or (sensitive and col.get("default") is not None)
                col = {
                    **col,
                    "default": _masked_default(policy, name, col.get("default")),
                    "comment": _cap_text(col.get("comment"), policy, st),
                    "sensitive": sensitive,
                }
            columns.append(col)
        detail["columns"] = columns
    identifiers = [str(detail.get(k) or "") for k in ("schema", "name")] + [
        str(c.get("name") or "") for c in detail.get("columns") or () if isinstance(c, dict)
    ]
    if literal_hidden and detail.get("definition") is not None:
        detail["definition"] = None
        st["warnings"].append("definition withheld: a sensitive column carries a DEFAULT literal")
    elif _literal_beside_sensitive(policy, detail.get("definition"), identifiers):
        detail["definition"] = None
        st["warnings"].append("definition withheld: it names a sensitive column beside a string literal")
    for key in ("definition", "comment"):
        if isinstance(detail.get(key), str):
            detail[key] = _cap_text(detail[key], policy, st)
    if isinstance(detail.get("indexes"), list):
        detail["indexes"] = [_index_entry(policy, i, st) for i in detail["indexes"]]
    if isinstance(detail.get("foreign_keys"), list):
        detail["foreign_keys"] = [
            view.foreign_key(fk) if isinstance(fk, dict) else fk for fk in detail["foreign_keys"]
        ]
    return detail


async def _catalog_tables(
    app: AppContext,
    connection_id: str,
    policy: EffectivePolicy,
    page: list[Any],
    include_indexes: bool,
    st: dict[str, Any],
    view: _SchemaView,
) -> list[dict[str, Any]]:
    """The catalog entries for one page of table summaries: columns with
    portable types, primary key, foreign keys (targets outside the allowlist
    redacted) and indexes. Metadata only; one bulk catalog call per schema.

    The schemas are read in page order under security.discovery_time_budget_seconds
    (from the start of the call); when it runs out, the entries end before
    the first table whose schema was not read, and the caller's cursor
    resumes there. The first schema is always read, so every page makes
    progress."""
    budget = float(policy.discovery_time_budget_seconds)
    schemas = list(dict.fromkeys(t.schema for t in page))
    by_schema: dict[str | None, tuple[_TableSplit, _TableSplit, _TableSplit]] = {}
    for sch in schemas:
        if by_schema and time.monotonic() >= st["start"] + budget:
            st["warnings"].append(
                f"discovery time budget of {budget:.0f}s exhausted after the catalog of {len(by_schema)} of "
                f"{len(schemas)} schema(s) on this page; continue with the cursor"
            )
            break
        cols = await run_meta(app, connection_id, _meta_call("list_all_columns", sch))
        idx = (
            await run_meta(app, connection_id, _meta_call("list_indexes", sch, None))
            if include_indexes else []
        )
        fks = await run_meta(app, connection_id, _meta_call("get_foreign_keys", sch, None))
        by_schema[sch] = (
            _split_by_table(cols, sch, _column_owner),
            _split_by_table(idx, sch, _index_owner),
            _split_by_table(fks, sch, _fk_owner),
        )
    folded = _folded_names(page)
    page = list(itertools.takewhile(lambda t: t.schema in by_schema, page))
    out_tables: list[dict[str, Any]] = []
    for t in page:
        sch = t.schema
        col_split, idx_split, fk_split = by_schema[sch]
        unique = folded[((sch or "").lower(), t.name.lower())] == 1
        cols = col_split.get(sch, t.name, unique_on_page=unique)
        idx = idx_split.get(sch, t.name, unique_on_page=unique)
        fks = fk_split.get(sch, t.name, unique_on_page=unique)
        pk = next((i.columns for i in idx if i.primary), None)
        fk_data = [view.foreign_key(dataclasses.asdict(k)) for k in fks]
        out_tables.append({
            "schema": sch,
            "name": t.name,
            "kind": t.kind,
            "row_estimate": t.row_estimate,
            "row_estimate_source": t.row_estimate_source,
            "comment": _cap_text(t.comment, policy, st),
            "primary_key": pk,
            "columns": [
                {
                    "name": c.name,
                    "data_type": c.data_type,
                    **portable_type(policy.engine, c.data_type).as_dict(),
                    "nullable": c.nullable,
                    "default": _masked_default(policy, c.name, c.default),
                    "comment": _cap_text(c.comment, policy, st),
                    "in_primary_key": bool(pk and c.name in pk),
                    "sensitive": _sensitive(policy, c.name),
                }
                for c in cols
            ],
            "indexes": [_index_entry(policy, i, st) for i in idx],
            "foreign_keys": fk_data,
        })
    return out_tables



async def _profile_object(
    app: AppContext,
    connection_id: str,
    connector: DatabaseConnector,
    policy: EffectivePolicy,
    st: dict[str, Any],
    schema2: str | None,
    name: str,
    *,
    columns: list[str] | None,
    sample_rows: int | None,
    include_top_values: bool,
    deadline: float,
) -> dict[str, Any]:
    """One table's bounded profile + findings (the body shared by
    db_profile_table and db_review_schema). Warnings go to ``st``; the
    caller owns the envelope. ``deadline`` is a monotonic instant every
    statement of this profile must finish by."""
    _require_printable(schema2, name)
    all_cols = await run_meta(app, connection_id, lambda c: c.list_columns(schema2, name))
    if columns is not None and not columns:
        raise ToolFailure(ErrorCategory.VALIDATION, "columns must be omitted or non-empty")
    if columns:
        known = {c.name for c in all_cols}
        bad = [c for c in columns if c not in known]
        if bad:
            raise ToolFailure(ErrorCategory.VALIDATION, f"unknown columns: {_names_text(bad)}")
        all_cols = [c for c in all_cols if c.name in set(columns)]
    named = [c for c in all_cols if _printable(c.name)]
    if len(named) < len(all_cols):
        st["warnings"].append(
            f"{len(all_cols) - len(named)} column(s) whose names hold control characters were not profiled"
        )
        all_cols = named
    if len(all_cols) > _PROFILE_MAX_COLUMNS:
        st["warnings"].append(
            f"profiled the first {_PROFILE_MAX_COLUMNS} of {len(all_cols)} columns; pass columns=[...] to profile "
            "the others in further calls"
        )
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
    # near-timeout scans (security.discovery_time_budget_seconds); the
    # caller passes the instant they must all finish by.
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
    outcome = await _audited_query(app, st, connection_id, spec, f"profile of '{connection_id}'")
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
            tv = await _audited_query(app, st, connection_id, tv_spec, f"top values on '{connection_id}'")
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
    if total == 0:
        st["warnings"].append(
            "the sample returned no rows (empty table, or the account cannot read it): "
            "column measures are absent and only metadata findings apply"
        )
    return {
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
    }



@dataclasses.dataclass
class _GuardedRead:
    """One validated, bounded, masked read: what db_query returns before it
    is wrapped, reused by the federated tools."""

    policy: EffectivePolicy
    columns: list[tuple[str, str]]
    rows: list[list[Any]]
    outcome: Any
    row_limit: int


async def _audit_statement(
    app: AppContext,
    st: dict[str, Any],
    connection_id: str,
    sql: str,
    *,
    outcome: str,
    category: Any,
    row_count: int | None,
    started: float,
    executed: bool,
) -> None:
    """The federated tools, value search, sampling and profiling run
    statements under ONE tool span. Each statement leaves its own audit record
    (same request_id, action '<tool>:statement', its connection and
    fingerprint) so the per-connection trail is as complete as db_query's.
    Written shielded and fail-closed exactly like the span's own record. A
    statement that never reached a database is left to the span's record
    where that one describes it (db_query), and otherwise recorded without
    its text, and coalesced when it failed. One that did keeps its text
    here, and the span's record of the same statement names it by length
    (and the request id they share)."""
    own = st.get("statement") == (connection_id, sql)
    if not executed and own:
        return
    sql_fields, sql_audit = _audit_sql(app, sql, keep="text" if executed else "digest")
    record: dict[str, Any] = {
        "request_id": st["request_id"],
        "action": f"{st.get('tool', 'tool')}:statement",
        **_audit_connection_id(app, connection_id),
        "outcome": outcome,
        "elapsed_ms": int((time.monotonic() - started) * 1000),
        **sql_fields,
        "row_count": row_count,
    }
    if category:
        record["category"] = category
    audit_record = {"event": "tool_call", **_caller_fields(app), **redact_value(record), **sql_audit}
    with anyio.CancelScope(shield=True):
        await anyio.to_thread.run_sync(_audit_writer(app, _coalesced(outcome, executed)), audit_record)
    if own:
        st["statement_text_recorded"] = True
    app.record_history({**record, "ts": _now()})


@asynccontextmanager
async def _statement_audit(
    app: AppContext, st: dict[str, Any], connection_id: str, sql: str
) -> AsyncIterator[dict[str, Any]]:
    """One statement's audit record around the work that runs it: a refusal
    is a deny, a failure an error (both with their category), success an allow
    with the ``row_count`` the body sets, a cancellation a cancelled one. The
    body passes ``_sends(result, st)`` to the executor, which sets
    ``executed`` on both once the statement's driver call begins. A failed
    audit write is never swallowed: the call fails closed."""
    started = time.monotonic()
    result: dict[str, Any] = {"row_count": None, "executed": False}

    async def audit(outcome: str, category: Any, row_count: int | None) -> None:
        await _audit_statement(
            app, st, connection_id, sql, outcome=outcome, category=category, row_count=row_count, started=started,
            executed=result["executed"],
        )

    try:
        yield result
    except anyio.get_cancelled_exc_class():
        with anyio.CancelScope(shield=True):
            await audit("cancelled", None, None)
        raise
    except ToolFailure as exc:
        await audit(_failure_outcome(exc.category), exc.category, None)
        raise
    except ConnectorError as exc:
        category = _connector_error_category(exc)
        await audit(_failure_outcome(category), category, None)
        raise
    except AuditWriteFailure:
        raise
    except Exception:
        await audit("error", ErrorCategory.INTERNAL, None)
        raise
    await audit("allow", None, result["row_count"])


async def _audited_query(
    app: AppContext, st: dict[str, Any], connection_id: str, spec: QuerySpec, description: str
) -> Any:
    """run_query for a statement this server generated (value search,
    sample, profile), with its own '<tool>:statement' audit record. Values
    are bound parameters, so the fingerprint and any audited text carry the
    placeholders, never the searched value."""
    async with _statement_audit(app, st, connection_id, spec.sql) as audit:
        outcome = await run_query(app, connection_id, spec, description, on_start=_sends(audit, st))
        audit["row_count"] = len(outcome.rows)
    return outcome


_PARAMETER_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _check_parameters(parameters: list[Any] | dict[str, Any] | None) -> None:
    """Bound values are JSON scalars, and names are identifiers. The tool
    schema takes any JSON value, and a list or an object reached the driver
    after the guard had run: PyMySQL expanded a list into SQL tuple syntax
    and, before 1.2, interpolated a dict key unescaped."""
    if parameters is None:
        return
    if isinstance(parameters, dict):
        if not all(isinstance(k, str) and _PARAMETER_NAME.fullmatch(k) for k in parameters):
            raise ToolFailure(ErrorCategory.VALIDATION, "parameter names must be identifiers ([A-Za-z_][A-Za-z0-9_]*)")
        named = [(_id_text(k), v) for k, v in parameters.items()]
    else:
        named = [(str(i), v) for i, v in enumerate(parameters, start=1)]
    for label, value in named:
        if value is not None and not isinstance(value, bool | int | float | str):
            raise ToolFailure(
                ErrorCategory.VALIDATION,
                f"parameter values must be JSON scalars (string, number, boolean or null); parameter {label} is "
                + ("an array" if isinstance(value, list | tuple) else "an object"),
            )


async def _guarded_read(
    app: AppContext,
    st: dict[str, Any],
    connection_id: str,
    sql: str,
    parameters: list[Any] | dict[str, Any] | None,
    max_rows: int | None,
    timeout_seconds: float | None,
    *,
    byte_budget: int | None = None,
) -> _GuardedRead:
    """One statement on one connection, exactly as db_query runs it, plus its
    own audit record. `byte_budget` lets a federated caller hand each
    statement what is left of the shared response ceiling."""
    async with _statement_audit(app, st, connection_id, sql) as audit:
        _check_parameters(parameters)
        connector, policy = _require_engine(app, connection_id)
        validated = await _validated(app, connector, policy, lambda g: g.validate_select(sql))
        row_limit = policy.clamp_row_limit(max_rows)
        timeout = policy.clamp_timeout(timeout_seconds)
        ceiling = policy.max_response_bytes
        if byte_budget is not None:
            ceiling = max(1, min(ceiling, int(byte_budget)))
        spec = QuerySpec(
            sql=sql,
            parameters=parameters,
            max_rows=row_limit,
            max_response_bytes=ceiling,
            max_cell_bytes=policy.max_cell_bytes,
            timeout_seconds=timeout,
        )
        st["connector"] = connector  # discarded if the request is cancelled mid-query
        outcome = await run_query(
            app, connection_id, spec, f"query on '{connection_id}'", on_start=_sends(audit, st)
        )
        trace_warnings: list[str] = []
        table_columns = await _row_function_columns(app, connector, policy, validated.ast, trace_warnings)
        # both walks are linear in the statement, but a 64 KiB statement must
        # not hold the event loop, exactly like its validation
        sensitive, positions = await anyio.to_thread.run_sync(
            lambda: (
                _sensitive_output_names(policy, validated.ast),
                _query_mask_positions(policy, validated.ast, outcome.columns, trace_warnings, table_columns),
            )
        )
        st["warnings"].extend(trace_warnings)
        columns, rows = _apply_masking(
            policy, outcome.columns, outcome.rows, st, sensitive_names=sensitive, positions=positions
        )
        if columns is not outcome.columns:
            # the connector fitted the rows to the ceiling before masking, and
            # '<masked>' can be longer than the value it replaced
            keep = _rows_within(rows, ceiling)
            if keep < len(rows):
                rows = rows[:keep]
                outcome = dataclasses.replace(outcome, truncated=True)
        audit["row_count"] = len(rows)
    return _GuardedRead(policy=policy, columns=columns, rows=rows, outcome=outcome, row_limit=row_limit)


def _join_key(value: Any, case_insensitive: bool) -> str:
    """Normalise a join key so 5, 5.0, Decimal('5.00') and '5' from different
    engines compare equal, while text stays text."""
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float | decimal.Decimal):
        if isinstance(value, float) and not math.isfinite(value):
            return str(value)  # nan/inf stay text and never equal a number
        d = decimal.Decimal(str(value))
        if not d.is_finite():
            return str(value)
        if d == 0:
            return "0"  # 0, 0.0, -0.0 and 0E+2 are one key
        # plain digits, no exponent, no context rounding (Decimal.normalize()
        # would round a key longer than the 28-digit default precision)
        text = format(d, "f")
        return text.rstrip("0").rstrip(".") if "." in text else text
    text = str(value).strip()
    if text.lstrip("-").replace(".", "", 1).isdigit():
        try:
            return _join_key(decimal.Decimal(text), case_insensitive)
        except decimal.InvalidOperation:
            pass
    return text.lower() if case_insensitive else text


def _readable(policy: EffectivePolicy, table: Any) -> bool:
    """Whether a listed table passes the same check_object a named one does.
    The listing keeps objects no tool may read (Db2's SYSIBM.SYSCOLUMNS,
    whose HIGH2KEY/LOW2KEY hold other columns' values, once SYSIBM is
    opened): the tools that walk it - value search, the review, the catalog
    and document tools - read only what db_sample_table would."""
    try:
        policy.check_object(table.schema, table.name)
    except ToolFailure:
        return False
    return True


def _schema_visible(policy: EffectivePolicy, schema: str | None) -> bool:
    """Whether a schema may be named to the caller: no allowlist, an allowed
    schema, or an allowed system schema."""
    return policy.schema_allowed(schema) or policy.system_schema_allowed(schema)


@dataclasses.dataclass(frozen=True)
class _SchemaView:
    """The one rule for which schema names a connection's caller may see:
    an allowed (or allowed system) schema, and of a name the catalog holds
    in several spellings only the one the policy admits - never a namesake
    (EffectivePolicy.shadowed_spellings). Every tool that names a schema
    (listings, foreign-key targets, inferred relationships, a schema
    argument) asks it, so none shows "Ocean" beside an allowed ocean."""

    policy: EffectivePolicy
    shadowed: frozenset[str] = frozenset()

    def visible(self, schema: str | None) -> bool:
        return not schema or (_schema_visible(self.policy, schema) and schema not in self.shadowed)

    def foreign_key(self, data: dict[str, Any]) -> dict[str, Any]:
        """A permitted table's foreign key may point at a schema the caller
        may not see; the key and its local columns are reported, the hidden
        target is not named."""
        if not self.visible(data.get("ref_schema")):
            return {**data, "ref_schema": "<not permitted>", "ref_table": "<not permitted>", "ref_columns": []}
        return data


async def _schema_view(
    app: AppContext, connector: DatabaseConnector, policy: EffectivePolicy, names: Iterable[str] = ()
) -> _SchemaView:
    """The connection's _SchemaView: the namesakes of the whole schema list
    (tables_for: a filtered schema listing may hold one spelling alone), and
    any ``names`` the caller is about to see show."""
    if not policy.allowed_schemas:
        return _SchemaView(policy)
    shadowed = _shadowed_of(await app.tables_for(policy, connector)) | policy.shadowed_spellings(names)
    return _SchemaView(policy, shadowed)


async def _check_schema_spelling(
    app: AppContext, connector: DatabaseConnector, policy: EffectivePolicy, schema: str
) -> None:
    """Refuse a schema argument that names a spelling of an allowed schema
    the policy does not admit (EffectivePolicy.shadowed_spellings). The
    metadata and sample tools hand the caller's spelling to the connector
    as written, and check_object folds case, so under allowed_schemas
    [ocean] schema="Ocean" listed, described and sampled PostgreSQL's other
    schema "Ocean" (review, 2026-09-28). Only where the catalog holds the
    name in several spellings: otherwise the one it holds is the allowed
    schema, and a spelling the engine does not match reads nothing. The
    namesakes are those of the whole schema list, as db_list_schemas shows
    it (AppContext.schema_names), not only of the schemas the listing holds
    tables in: one holding nothing else - a PostgreSQL partitioned parent, a
    foreign table - is refused too."""
    if schema not in (await _schema_view(app, connector, policy)).shadowed:
        return
    raise ToolFailure(
        ErrorCategory.AUTHZ,
        f"schema '{schema}' is not permitted on connection '{policy.connection_id}': schema names that differ "
        f"only in case name different schemas here, and this spelling is not the permitted one; spell it as "
        f"db_list_schemas does",
    )



def _unquote_identifier(part: str) -> str:
    part = part.strip()
    if len(part) >= 2 and part[0] == part[-1] and part[0] in ('"', '`'):
        return part[1:-1].replace(part[0] * 2, part[0])
    if len(part) >= 2 and part[0] == "[" and part[-1] == "]":
        return part[1:-1].replace("]]", "]")
    return part


def _split_dotted(name: str) -> list[str]:
    """Split on dots that are OUTSIDE quotes ("a.b" is one identifier;
    doubled quotes inside a quoted part are literal)."""
    parts: list[str] = []
    cur: list[str] = []
    quote: str | None = None
    i = 0
    while i < len(name):
        ch = name[i]
        if quote:
            closing = "]" if quote == "[" else quote
            if ch == closing:
                if name[i + 1 : i + 2] == closing:  # doubled closer = literal
                    cur.append(ch + ch)
                    i += 2
                    continue
                quote = None
            cur.append(ch)
        elif ch in ('"', "`", "["):
            quote = ch
            cur.append(ch)
        elif ch == ".":
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
        i += 1
    parts.append("".join(cur))
    return parts


def _split_qualified_name(schema: str | None, object_name: str) -> tuple[str | None, str]:
    """Accept ``schema.table`` (optionally quoted parts) in ``object_name``.

    Dots inside quotes belong to the identifier. A three-part name is
    refused: the database is fixed by the connection, so ``db.schema.table``
    cannot be honoured and must not be silently reinterpreted. When both the
    ``schema`` argument and a qualified name are given they have to agree."""
    parts = _split_dotted(object_name)
    unquoted = [_unquote_identifier(p) for p in parts]
    if len(parts) > 2 or not all(u.strip() for u in unquoted):
        # an empty quoted part ("".ALL_USERS, [].syslogins) is no schema: the
        # connector builds the bare name, which the bare-name rules must see
        raise ToolFailure(
            ErrorCategory.VALIDATION,
            f"object name {_id_text(object_name)} must be 'table' or 'schema.table', each part a non-empty name "
            "(the database is fixed by the connection)",
        )
    if len(parts) == 1:
        return schema, unquoted[0]
    qualified_schema, name = unquoted
    if schema is not None and schema.lower() != qualified_schema.lower():
        raise ToolFailure(
            ErrorCategory.VALIDATION,
            f"schema argument {_id_text(schema)} disagrees with the qualified name {_id_text(object_name)}",
        )
    return qualified_schema, name


def _unique_match(matches: list[Any], schema: str | None, object_name: str) -> Any:
    """The one catalog object a case-insensitive lookup stands for. The
    exact spelling wins; objects whose names differ only in case (quoted
    names on PostgreSQL, Oracle and Db2, every name on ClickHouse) are
    refused as ambiguous instead of picking one."""
    exact = [t for t in matches if t.name == object_name and (schema is None or t.schema == schema)]
    if not exact and schema is not None:
        exact = [t for t in matches if t.name == object_name]
    chosen = exact or matches
    schemas = {(t.schema or "").lower() for t in chosen}
    if len(schemas) > 1:
        raise ToolFailure(
            ErrorCategory.VALIDATION,
            f"object {_id_text(object_name)} exists in several schemas ({', '.join(sorted(schemas))}); "
            f"qualify it with a schema",
        )
    if len(chosen) > 1:
        spellings = ", ".join(sorted(f"{t.schema}.{t.name}" if t.schema else t.name for t in chosen))
        raise ToolFailure(
            ErrorCategory.VALIDATION,
            f"object {_id_text(object_name)} matches several objects whose names differ only in case ({spellings}); "
            f"spell it exactly as the catalog does",
        )
    return chosen[0]


# Dictionary objects an engine binds a bare name to without being asked:
# PostgreSQL searches pg_catalog before the search_path, Oracle's PUBLIC
# synonyms name the SYS views, SQL Server keeps its compatibility views
# (sysobjects, syscomments) readable unqualified. engine -> (the schema they
# live in, name prefixes, names).
_IMPLICIT_DICTIONARY: dict[str, tuple[str, tuple[str, ...], frozenset[str]]] = {
    "postgres": ("pg_catalog", ("pg_",), frozenset()),
    "oracle": (
        "sys",
        ("all_", "user_", "dba_", "cdb_", "v$", "gv$", "v_$", "gv_$", "dict", "role_", "session_", "nls_"),
        frozenset({"tab", "tabs", "cat", "cols", "ind", "obj", "seq", "syn", "clu", "global_name",
                   "product_component_version"}),
    ),
    "mssql": ("sys", ("sys",), frozenset()),
}


def _engine_catalog_table(engine: str, name: str) -> bool:
    """SQLite reserves the sqlite_ prefix for its own catalog: sqlite_schema
    (sqlite_master) holds every table's DDL, a sensitive column's DEFAULT
    literal included, and no user table can carry the prefix. Only there:
    Oracle's SYS_ or PostgreSQL's pg_ table names are a site's to use."""
    return engine == "sqlite" and name.lower().startswith("sqlite_")


def _never_listed(engine: str, table: Any) -> bool:
    """A catalog entry no listing holds: SQLite's own catalog
    (_engine_catalog_table), a view of other sessions' SQL text, of
    column statistics or of stored credentials (is_session_sql_view), which
    the policy refuses to every tool, and a table the engine never reads by
    its name, reading a dictionary view in its place (dictionary_binding:
    SQL Server's FROM dbo.sysusers is sys.sysusers whatever dbo holds); value
    search and the catalog tools walk the listing, not the policy."""
    return (
        _engine_catalog_table(engine, table.name)
        or is_session_sql_view(engine, table.schema, table.name)
        or dictionary_binding(engine, table.schema, table.name) is not None
    )


# Engines that bind a bare name missing from the caller's schema to a PUBLIC
# synonym. Oracle's are thousands, most of them naming SYS views
# (DATABASE_PROPERTIES, TABLE_PRIVILEGES) that no name list covers.
_PUBLIC_SYNONYM_ENGINES = frozenset({"oracle"})

# Engines whose listing names every object of the caller's, so a name
# resolves against it default-deny or not: SQLite lists each table and view
# of every attached database (PRAGMA table_list), and a name it does not list
# is one of its eponymous virtual tables - pragma_database_list reads the
# file's path, pragma_table_list and dbstat the catalog's own names.
_LISTED_ONLY_ENGINES = frozenset({"sqlite"})


async def _unrestricted_name(
    app: AppContext, connector: DatabaseConnector, policy: EffectivePolicy, object_name: str
) -> tuple[str | None, str]:
    """A bare name when no allowlist and no default-deny restrict it: sent as
    written, and the engine resolves it. A name the engine's dictionary
    would answer (pg_roles, ALL_USERS, sysobjects) - on Oracle any bare name,
    since a PUBLIC synonym may answer it - is the catalog's own object,
    qualified, when the catalog lists one; otherwise it needs the dictionary's
    schema in security.allowed_system_schemas, exactly like its qualified
    spelling."""
    implicit = _IMPLICIT_DICTIONARY.get(policy.engine)
    folded = object_name.lower()
    dictionary = implicit is not None and (folded.startswith(implicit[1]) or folded in implicit[2])
    synonyms = policy.engine in _PUBLIC_SYNONYM_ENGINES
    if implicit is None or not (dictionary or synonyms):
        return None, object_name
    matches = [t for t in await app.tables_for(policy, connector) if t.name.lower() == folded]
    if matches:
        match = _unique_match(matches, None, object_name)
        policy.check_object(match.schema, match.name)
        return match.schema, match.name
    if not dictionary and not policy.system_schema_allowed(implicit[0]):
        raise ToolFailure(
            ErrorCategory.AUTHZ,
            f"object {_id_text(object_name)} is not a table or view in the catalog; on this engine a bare name "
            f"that is not one resolves through a synonym, possibly a PUBLIC synonym to a {implicit[0].upper()} "
            f"view: qualify it with its schema",
        )
    policy.check_object(implicit[0], object_name)
    return None, object_name


async def _resolve_object(
    app: AppContext,
    connector: DatabaseConnector,
    policy: EffectivePolicy,
    schema: str | None,
    object_name: str,
) -> tuple[str | None, str]:
    """Authorize + resolve one object reference against policy and metadata.
    Unqualified names resolve only against the permitted objects - whenever
    default-deny is on or an allowlist exists - so the engine never picks the
    schema (MySQL's default database, Oracle's PUBLIC synonyms, PostgreSQL's
    search_path with its implicit pg_catalog); unknown names are denied, never
    guessed. Without either, a bare name goes to the engine unless its
    dictionary would answer it (_unrestricted_name); on SQLite every name
    resolves against the listing (_LISTED_ONLY_ENGINES). Both branches return
    the catalog's canonical (schema, name)
    spelling whenever the metadata provides a match: connector catalog SQL and
    sample queries quote identifiers verbatim, so the caller's casing would
    silently miss on case-sensitive engines (Oracle, Db2, Postgres quoted
    identifiers)."""
    if schema is not None and not schema.strip():
        # schema="" is no schema: it used to skip the bare-name rules below
        # while the connector built the same unqualified reference
        schema = None
    # "schema.table" is how agents (and the catalog tool's own output) spell
    # an object; it must mean the same as schema="schema", object_name="table"
    schema, object_name = _split_qualified_name(schema, object_name)
    if _engine_catalog_table(policy.engine, object_name):
        # _validated refuses it in a statement; the metadata and sample
        # tools reach the connector without it, in every branch below
        raise ToolFailure(
            ErrorCategory.AUTHZ,
            f"object {_id_text(object_name)} is SQLite's own catalog, which is not readable on connection "
            f"'{policy.connection_id}'; use db_list_tables / db_get_table on the tables it describes",
        )
    listed_only = policy.default_deny_objects or policy.engine in _LISTED_ONLY_ENGINES
    if schema is None:
        if not listed_only and not policy.allowed_schemas:
            # nothing restricts user schemas: the engine resolves the bare name,
            # unless its dictionary would answer it
            resolved = await _unrestricted_name(app, connector, policy, object_name)
            await _check_synonyms(app, connector, policy, [resolved])
            return resolved
        tables = await app.tables_for(policy, connector)  # policy-scoped
        matches = [t for t in tables if t.name.lower() == object_name.lower()]
        if not matches:
            raise ToolFailure(
                ErrorCategory.AUTHZ,
                f"object {_id_text(object_name)} could not be resolved to a permitted "
                f"object; qualify it with an allowed schema",
            )
        match = _unique_match(matches, None, object_name)
        # Never trust the metadata scope alone: the resolved object still goes
        # through the same policy check a qualified reference would.
        policy.check_object(match.schema, match.name)
        return match.schema, match.name
    policy.check_object(schema, object_name)
    await _check_schema_spelling(app, connector, policy, schema)
    # default-deny additionally requires the object to exist in metadata
    if listed_only:
        tables = await app.tables_for(policy, connector)
        matches = [
            t
            for t in tables
            if t.name.lower() == object_name.lower() and t.schema and t.schema.lower() == schema.lower()
        ]
        if not matches:
            raise ToolFailure(
                ErrorCategory.AUTHZ,
                f"object {_id_text(f'{schema}.{object_name}')} is not a permitted object on connection "
                f"'{policy.connection_id}'",
            )
        # Return the catalog's canonical spelling, not the caller's: the
        # existence check above is case-insensitive but the connector's
        # catalog queries and quoted identifiers are not.
        match = _unique_match(matches, schema, object_name)
        return match.schema, match.name
    # Policy permits without a metadata check; no catalog match is available
    # to canonicalize against, so the caller's spelling is used verbatim, and
    # it is the name the engine looks up (the connector quotes it as given):
    # the listed table only where the listing spells it so, else possibly a
    # synonym (TRAVEL."Bookings" beside TRAVEL.BOOKINGS)
    await _check_synonyms(app, connector, policy, [(schema, object_name)])
    return schema, object_name


def _validate_limitations(policy: EffectivePolicy) -> list[str]:
    out = [
        "validation is dialect-aware but parser-based; read-only database accounts remain the primary control",
        "row, byte, cell, and timeout ceilings are enforced at execution, not by this validation",
        "db_explain captures plans without executing the statement: EXPLAIN ANALYZE is not supported",
    ]
    if not policy.allow_explain_analyze:
        out.append("EXPLAIN ANALYZE is disabled by policy")
    if policy.engine == "mysql":
        out.append(
            "db_explain returns a TREE or JSON plan only for a statement naming no masked column (MySQL prints the "
            "values it reads from const tables into those formats); FORMAT=TRADITIONAL plans are returned for any"
        )
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
