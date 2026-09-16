"""Effective security policy: server ceilings + per-connection allowances.

The policy is the single authority the tool layer consults. Model-supplied
arguments can only narrow (fewer rows, shorter timeout), never widen.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from universal_db_mcp.errors import ToolFailure
from universal_db_mcp.models.responses import ErrorCategory

if TYPE_CHECKING:
    from universal_db_mcp.config import ResolvedConnection, SecurityConfig


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

    def system_schema_allowed(self, schema: str | None) -> bool:
        if schema is None:
            return False
        return schema.lower() in self.allowed_system_schemas

    def check_object(self, schema: str | None, name: str) -> None:
        """Authorization for a concrete object reference (schema given)."""
        if schema is None:
            return
        if self.schema_allowed(schema):
            return
        if self.system_schema_allowed(schema):
            return
        raise ToolFailure(
            ErrorCategory.AUTHZ,
            f"schema '{schema}' is not permitted on connection '{self.connection_id}'",
        )
