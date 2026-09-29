"""Effective security policy: server ceilings + per-connection allowances.

The policy is the single authority the tool layer consults. Model-supplied
arguments can only narrow (fewer rows, shorter timeout), never widen.
"""

from __future__ import annotations

import math
import re
import string
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from universal_db_mcp.discovery.system_schemas import (
    DISCOVERY_ONLY_SCHEMAS,
    dictionary_binding,
    is_column_statistics_view,
    is_credential_view,
    is_data_free_table,
    is_listed_system_schema,
    is_session_sql_view,
    value_columns,
)
from universal_db_mcp.errors import ToolFailure
from universal_db_mcp.models.responses import ErrorCategory

if TYPE_CHECKING:
    from universal_db_mcp.config import ResolvedConnection, SecurityConfig

# How an engine folds an unquoted name, ASCII only as the engines do. The
# others keep it as written (MySQL's and SQL Server's case rules are a server
# setting or a collation; ClickHouse's names are case-sensitive).
_ASCII_LOWER = str.maketrans(string.ascii_uppercase, string.ascii_lowercase)
_ASCII_UPPER = str.maketrans(string.ascii_lowercase, string.ascii_uppercase)
_UNQUOTED_FOLDING = {"postgres": _ASCII_LOWER, "oracle": _ASCII_UPPER, "db2": _ASCII_UPPER}


def unquoted_name(engine: str, name: str) -> str:
    """The name an engine looks up for ``name`` written without quotes."""
    folding = _UNQUOTED_FOLDING.get(engine)
    return name.translate(folding) if folding is not None else name


def check_not_session_sql(engine: str, schema: str | None, name: str, *, columns_checked: bool = False) -> None:
    """Refuse a view that shows other sessions' statements or the values
    they handle (SESSION_SQL_VIEWS), a column's values (column
    statistics), or stored credentials (CREDENTIAL_VIEWS), on every
    connection and whatever the allowlists open: it would hand back the
    values masking hides, or a password. A catalog view that carries
    each column's low and high values (COLUMN_VALUE_COLUMNS) is refused too,
    unless the caller - the guard, which refuses a statement naming those
    columns or reading every column - says ``columns_checked``."""
    shown = f"{schema}.{name}" if schema else name
    if is_credential_view(engine, schema, name):
        raise ToolFailure(
            ErrorCategory.POLICY,
            f"'{shown}' holds stored credentials (password hashes, or the passwords and connection details the "
            f"database keeps for other servers), which are not catalog metadata: it is not readable on any "
            f"connection, whatever security.allowed_system_schemas allows",
        )
    if is_column_statistics_view(engine, schema, name):
        raise ToolFailure(
            ErrorCategory.POLICY,
            f"'{shown}' holds column statistics (histogram buckets, most common values, low and high values) "
            f"taken from the columns' data, which would hand back values column masking hides: it is not readable "
            f"on any connection, whatever security.allowed_system_schemas allows",
        )
    carried = frozenset() if columns_checked else value_columns(engine, schema, name)
    if carried:
        raise ToolFailure(
            ErrorCategory.POLICY,
            f"'{shown}' carries each column's low and high values beside its description, which would hand back "
            f"values column masking hides: read it with db_query naming the columns you need (not "
            f"{', '.join(sorted(c.upper() for c in carried))})",
        )
    if is_session_sql_view(engine, schema, name):
        raise ToolFailure(
            ErrorCategory.POLICY,
            f"'{shown}' shows other sessions' SQL or the values it carries (statement text, literals, bind values, "
            f"error text, locked keys), which would hand back values column masking hides: it is not readable on "
            f"any connection, whatever security.allowed_system_schemas allows",
        )


@dataclass(slots=True)
class EffectivePolicy:
    connection_id: str
    engine: str
    hard_max_rows: int
    max_response_bytes: int
    max_cell_bytes: int
    hard_query_timeout_seconds: float
    default_max_rows: int
    default_query_timeout_seconds: float
    allowed_schemas: frozenset[str]
    default_deny_objects: bool
    allowed_system_schemas: frozenset[str]
    sample_limit: int
    profile_max_sample_rows: int
    discovery_time_budget_seconds: float
    require_tls: bool
    audit_sql_text: bool
    audit_parameter_values: bool
    audit_result_rows: bool
    allow_explain_analyze: bool
    sensitive_patterns: list[re.Pattern[str]] = field(default_factory=list)
    mask_action: str = "mask"
    # allowed_schemas and allowed_system_schemas as the administrator wrote
    # them: the case of an entry picks one of several catalog schemas whose
    # names differ only in case (shadowed_spellings)
    schema_entries: frozenset[str] = frozenset()

    @classmethod
    def build(
        cls,
        security: SecurityConfig,
        connection: ResolvedConnection,
    ) -> EffectivePolicy:
        cfg = connection.config
        require_tls = cfg.type != "sqlite" and (security.require_remote_tls or cfg.tls.enabled)
        return cls(
            connection_id=connection.name,
            engine=cfg.type,
            hard_max_rows=security.hard_max_rows,
            max_response_bytes=security.max_response_bytes,
            max_cell_bytes=security.max_cell_bytes,
            hard_query_timeout_seconds=security.hard_query_timeout_seconds,
            default_max_rows=security.default_max_rows,
            default_query_timeout_seconds=security.default_query_timeout_seconds,
            allowed_schemas=frozenset(s.lower() for s in cfg.allowed_schemas),
            default_deny_objects=security.default_deny_objects,
            allowed_system_schemas=frozenset(s.lower() for s in security.allowed_system_schemas),
            sample_limit=security.sample_limit,
            profile_max_sample_rows=security.profile_max_sample_rows,
            discovery_time_budget_seconds=security.discovery_time_budget_seconds,
            require_tls=require_tls,
            audit_sql_text=security.audit_sql_text,
            audit_parameter_values=security.audit_parameter_values,
            audit_result_rows=security.audit_result_rows,
            allow_explain_analyze=security.allow_explain_analyze,
            sensitive_patterns=[re.compile(p) for p in security.mask_columns],
            mask_action=security.mask_action,
            schema_entries=frozenset(cfg.allowed_schemas) | frozenset(security.allowed_system_schemas),
        )

    # ---- ceilings enforced server-side regardless of tool arguments ----

    @staticmethod
    def _finite(value: float, what: str) -> None:
        # NaN compares False against every bound and min(nan, x) returns nan,
        # so an unchecked NaN would silently disable the ceiling (policy bypass).
        if isinstance(value, bool):
            raise ToolFailure(ErrorCategory.VALIDATION, f"{what} must be a finite number")
        if isinstance(value, int) and abs(value) > 2**53:
            # JSON carries arbitrary-precision integers; math.isfinite() raises
            # OverflowError converting one to float, which surfaced as
            # INTERNAL_ERROR. The NaN sibling was already handled.
            raise ToolFailure(
                ErrorCategory.VALIDATION, f"{what} is too large to be a meaningful limit"
            )
        if not math.isfinite(value):
            raise ToolFailure(ErrorCategory.VALIDATION, f"{what} must be a finite number")

    def clamp_row_limit(self, requested: int | None) -> int:
        limit = self.default_max_rows if requested is None else requested
        self._finite(limit, "row limit")
        if limit < 1:
            raise ToolFailure(ErrorCategory.VALIDATION, "row limit must be >= 1")
        return int(min(limit, self.hard_max_rows))

    def clamp_timeout(self, requested: float | None) -> float:
        timeout = self.default_query_timeout_seconds if requested is None else requested
        self._finite(timeout, "timeout")
        if timeout <= 0:
            raise ToolFailure(ErrorCategory.VALIDATION, "timeout must be positive")
        return float(min(timeout, self.hard_query_timeout_seconds))

    def clamp_sample_limit(self, requested: int | None) -> int:
        limit = self.sample_limit if requested is None else requested
        self._finite(limit, "sample limit")
        if limit < 1:
            raise ToolFailure(ErrorCategory.VALIDATION, "sample limit must be >= 1")
        return int(min(limit, self.sample_limit))

    # ---- object authorization ----

    def schema_allowed(self, schema: str | None) -> bool:
        """Check a *declared* schema against the connection allowlist."""
        if not self.allowed_schemas:
            return True  # administrator did not restrict schemas
        if schema is None:
            return True  # resolution of unqualified names is done elsewhere
        return schema.lower() in self.allowed_schemas

    def shadowed_spellings(self, schemas: Iterable[str | None]) -> frozenset[str]:
        """Of the catalog's schema names, the spellings of an allowed schema
        this policy does not admit. Entries match names ignoring case, but
        where the catalog holds one name in several spellings - different
        schemas to PostgreSQL, Oracle and Db2 (quoted), ClickHouse, MySQL
        with lower_case_table_names=0 and SQL Server under a case-sensitive
        collation - an entry written in one case is read as an unquoted name:
        it admits the spelling the engine folds it to (unquoted_name), so a
        conventional lower-case 'travel' keeps Oracle's TRAVEL, or else the
        spelling written exactly. A mixed-case entry ('Ocean') admits its
        exact spelling first, and so does an entry where another is written
        as its folded spelling (listing TRAVEL and travel admits both). The
        others are namesakes the administrator never named. A name held in
        one spelling is admitted in any case."""
        if not self.allowed_schemas:
            return frozenset()  # user schemas are not restricted
        restricted = self.allowed_schemas | self.allowed_system_schemas
        spellings: dict[str, set[str]] = {}
        for schema in schemas:
            if schema and schema.lower() in restricted:
                spellings.setdefault(schema.lower(), set()).add(schema)
        shadowed: set[str] = set()
        for key, names in spellings.items():
            if len(names) < 2:
                continue
            entries = {entry for entry in self.schema_entries if entry.lower() == key}
            admitted = set()
            for entry in entries:
                folded = unquoted_name(self.engine, entry)
                mixed = entry.translate(_ASCII_LOWER) != entry and entry.translate(_ASCII_UPPER) != entry
                exact_first = mixed or (folded != entry and folded in entries)
                for spelling in (entry, folded) if exact_first else (folded, entry):
                    if spelling in names:
                        admitted.add(spelling)
                        break
            shadowed |= names - admitted
        return frozenset(shadowed)

    def system_schema_allowed(self, schema: str | None) -> bool:
        if schema is None:
            return False
        return schema.lower() in self.allowed_system_schemas

    def is_system_schema(self, schema: str | None) -> bool:
        """The engine's own dictionary/catalog schemas (SYS, SYSCAT, pg_catalog, ...)."""
        if schema is None:
            return False
        folded = schema.strip().lower()
        if folded in DISCOVERY_ONLY_SCHEMAS.get(self.engine, frozenset()):
            return False
        return is_listed_system_schema(self.engine, folded)

    def check_object(self, schema: str | None, name: str, *, columns_checked: bool = False) -> None:
        """Authorization for a concrete object reference (schema given), or
        for the dictionary object the engine reads for it whatever the
        catalog holds (dictionary_binding: SQL Server's dbo.syslogins is
        sys.syslogins). ``columns_checked``: see check_not_session_sql."""
        bound = dictionary_binding(self.engine, schema, name)
        if bound is not None:
            try:
                self.check_object(*bound, columns_checked=columns_checked)
            except ToolFailure as exc:
                shown = f"{schema}.{name}" if schema else name
                raise ToolFailure(
                    exc.category,
                    f"'{shown}' is SQL Server's compatibility view {bound[0]}.{bound[1]}, which it reads under dbo "
                    "and bare ahead of any other object of the name: " + str(exc).removeprefix(f"{exc.category}: "),
                ) from exc
            return
        check_not_session_sql(self.engine, schema, name, columns_checked=columns_checked)
        if schema is None or is_data_free_table(self.engine, schema, name):
            return  # DUAL / SYSIBM.SYSDUMMYn hold no data (DATA_FREE_TABLES)
        # An empty allowlist leaves user schemas unrestricted; it never opens
        # the engine's dictionaries. A system schema needs
        # allowed_system_schemas, or the connection's allowlist naming it.
        if (
            self.is_system_schema(schema)
            and not self.system_schema_allowed(schema)
            and schema.lower() not in self.allowed_schemas
        ):
            raise ToolFailure(
                ErrorCategory.AUTHZ,
                f"schema '{schema}' is a system schema and is not permitted on connection "
                f"'{self.connection_id}'; an administrator can allow it in security.allowed_system_schemas",
            )
        if self.schema_allowed(schema):
            return
        if self.system_schema_allowed(schema):
            return
        raise ToolFailure(
            ErrorCategory.AUTHZ,
            f"schema '{schema}' is not permitted on connection '{self.connection_id}'",
        )
