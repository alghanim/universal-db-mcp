"""Validated YAML configuration.

- Strict schema: unknown or misplaced fields are rejected (``extra='forbid'``).
- Secrets are resolved from the environment or secret *files* at load time and
  wrapped in :class:`SecretMark` so they can never be serialized, logged, or
  echoed. Raw values never live in the config model exposed to tools.
- Secret files with group/world read bits are rejected where the OS supports
  the check (POSIX), per the spec's unsafe-permission rule.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from universal_db_mcp.errors import ConfigError
from universal_db_mcp.security.redact import SecretMark

ENGINE_TYPES = ("sqlite", "db2", "oracle", "mssql", "postgres", "clickhouse", "mysql")

# Built-in sensitive-column heuristics (name-based masking hints). These are
# useful heuristics, NOT the security boundary; read-only accounts and grants
# remain mandatory. Administrators extend/override via security.mask_columns.
DEFAULT_SENSITIVE_PATTERNS = [
    r"(?i)(password|passwd|pwd|secret|token|api_key|apikey|access_key|private_key)",
    r"(?i)(ssn|social_security|tax_id|national_id|credit_card|card_number|cvv|pan)",
]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ApplicationConfig(StrictModel):
    airgapped: bool = True
    transport: Literal["stdio", "http"] = "stdio"
    metadata_cache_path: str | None = None
    audit_path: str | None = None
    audit_max_bytes: int = Field(default=50 * 1024 * 1024, gt=0)
    audit_max_backups: int = Field(default=5, gt=0)  # rotation cannot be disabled (bounded audit growth)
    audit_fail_closed: bool = True
    telemetry_enabled: bool = False
    # HTTP transport only:
    http_host: str = "127.0.0.1"  # restrictive default bind
    http_port: int = Field(default=8765, ge=1, le=65535)
    http_bearer_token_file: str | None = None

    @field_validator("telemetry_enabled")
    @classmethod
    def _no_telemetry(cls, v: bool) -> bool:
        if v:
            raise ValueError(
                "application.telemetry_enabled=true is not supported: this build "
                "contains no telemetry and the setting must remain false"
            )
        return v

    @field_validator("airgapped")
    @classmethod
    def _airgap_required(cls, v: bool) -> bool:
        if not v:
            raise ValueError(
                "application.airgapped=false is not supported by this build; the "
                "server never performs network acquisition in any mode"
            )
        return v


class TlsConfig(StrictModel):
    enabled: bool = False
    verify_server: bool = True
    ca_file: str | None = None
    client_cert_file: str | None = None
    client_key_file: str | None = None

    @model_validator(mode="after")
    def _verify_needs_ca(self) -> TlsConfig:
        if self.enabled and self.verify_server and not self.ca_file:
            raise ValueError(
                "tls.verify_server=true requires tls.ca_file pointing at the "
                "internal CA certificate; disabling verification is not permitted"
            )
        return self


# Per-engine option allowlist: unknown keys are rejected, values are typed.
# Anything else an engine needs must be added here deliberately (spec: strict
# schema everywhere).
_ENGINE_OPTIONS: dict[str, dict[str, type]] = {
    "sqlite": {},
    "postgres": {"application_name": str},
    "mysql": {"ssl_mode": str},
    "clickhouse": {"compress": bool},
    "oracle": {"tns_admin": str, "wallet_location": str, "thick_mode": bool},
    "mssql": {"odbc_driver": str},
    "db2": {},
}


class ConnectionConfig(StrictModel):
    type: Literal["sqlite", "db2", "oracle", "mssql", "postgres", "clickhouse", "mysql"]
    family: str | None = None  # db2: luw | zos | i
    host: str | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    database: str | None = None
    username_env: str | None = None
    password_env: str | None = None
    password_file: str | None = None
    tls: TlsConfig = Field(default_factory=TlsConfig)
    allowed_schemas: list[str] = Field(default_factory=list)
    read_only: bool = True
    connect_timeout_seconds: float = Field(default=10.0, gt=0, le=120)
    # Engine-specific, tightly validated options (see engine modules).
    options: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _hosts(self) -> ConnectionConfig:
        if self.type != "sqlite":
            if not self.host:
                raise ValueError(f"connections: host is required for type '{self.type}'")
            if not self.database:
                raise ValueError(f"connections: database is required for type '{self.type}'")
        if self.type == "db2" and self.family not in (None, "luw"):
            raise ValueError(
                "db2 'family' must be 'luw' in this build; z/OS and Db2 for i "
                "require separate validation and are not implemented"
            )
        allowed = _ENGINE_OPTIONS.get(self.type, {})
        unknown = set(self.options) - set(allowed)
        if unknown:
            raise ValueError(f"connections: unknown options for type '{self.type}': {sorted(unknown)}")
        for key, value in self.options.items():
            if not isinstance(value, allowed[key]):
                raise ValueError(f"connections: option '{key}' for type '{self.type}' must be {allowed[key].__name__}")
        return self


class SecurityConfig(StrictModel):
    read_only: bool = True
    allow_write_operations: bool = False
    default_max_rows: int = Field(default=1000, gt=0)
    hard_max_rows: int = Field(default=10000, gt=0)
    max_response_bytes: int = Field(default=1024 * 1024, gt=0)
    max_cell_bytes: int = Field(default=8192, gt=0)
    default_query_timeout_seconds: float = Field(default=30.0, gt=0)
    hard_query_timeout_seconds: float = Field(default=60.0, gt=0)
    max_concurrent_queries: int = Field(default=4, gt=0)
    require_remote_tls: bool = True
    default_deny_objects: bool = True
    allowed_system_schemas: list[str] = Field(default_factory=lambda: ["information_schema"])
    sample_limit: int = Field(default=20, gt=0)
    audit_sql_text: bool = False
    audit_parameter_values: bool = False
    audit_result_rows: bool = False
    allow_explain_analyze: bool = False
    mask_columns: list[str] = Field(default_factory=DEFAULT_SENSITIVE_PATTERNS.copy)
    mask_action: Literal["mask", "omit"] = "mask"

    @field_validator("mask_columns")
    @classmethod
    def _valid_mask_regexes(cls, v: list[str]) -> list[str]:
        import re as _re

        for pattern in v:
            try:
                _re.compile(pattern)
            except _re.error as exc:
                raise ValueError(f"invalid mask_columns regex {pattern!r}: {exc}") from exc
        return v

    @field_validator("allow_write_operations")
    @classmethod
    def _no_writes(cls, v: bool) -> bool:
        if v:
            raise ValueError(
                "allow_write_operations=true is not supported in v1; the write "
                "capability requires a separately reviewed design"
            )
        return v

    @field_validator("read_only")
    @classmethod
    def _read_only_required(cls, v: bool) -> bool:
        if not v:
            raise ValueError("security.read_only=false is not supported in v1")
        return v

    @model_validator(mode="after")
    def _ceilings(self) -> SecurityConfig:
        if self.default_max_rows > self.hard_max_rows:
            raise ValueError("default_max_rows must be <= hard_max_rows")
        if self.default_query_timeout_seconds > self.hard_query_timeout_seconds:
            raise ValueError("default_query_timeout_seconds must be <= hard_query_timeout_seconds")
        return self


class AppConfig(StrictModel):
    application: ApplicationConfig = Field(default_factory=ApplicationConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    connections: dict[str, ConnectionConfig] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _state_isolated_from_data_sources(self) -> AppConfig:
        """Writable audit/cache state must be separate files from queried
        SQLite data sources (spec §5)."""
        state_paths = [
            os.path.abspath(p) for p in (self.application.audit_path, self.application.metadata_cache_path) if p
        ]
        for name, conn in self.connections.items():
            if conn.type == "sqlite" and conn.database:
                dbp = os.path.abspath(conn.database)
                for sp in state_paths:
                    if sp == dbp:
                        raise ValueError(
                            f"application state path '{sp}' must be a separate "
                            f"file from the queried SQLite data source of "
                            f"connection '{name}'"
                        )
        return self

    @field_validator("connections")
    @classmethod
    def _reserved_names(cls, v: dict[str, ConnectionConfig]) -> dict[str, ConnectionConfig]:
        for name in v:
            if not name or len(name) > 64 or not name.replace("-", "").replace("_", "").isalnum():
                raise ValueError(f"connection id '{name}' must be 1-64 chars of [A-Za-z0-9_-]")
        return v


def _check_secret_file_permissions(path: Path) -> None:
    """Reject secret files readable by group/other (POSIX systems)."""
    if sys.platform == "win32":  # pragma: no cover - documented limitation
        return
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError as exc:
        raise ConfigError(f"secret file '{path}' is not readable: {exc}") from exc
    if mode & 0o077:
        raise ConfigError(
            f"secret file '{path}' has unsafe permissions ({stat.filemode(mode)}): remove group/other access bits"
        )


def resolve_env_name(name: str, *, kind: str) -> str:
    if not name or not name.replace("_", "").isalnum() or name[0].isdigit():
        raise ConfigError(f"invalid environment variable name for {kind}")
    return name


class ResolvedConnection:
    """A connection config with secrets resolved to SecretMark values."""

    __slots__ = ("config", "name", "username", "password")

    def __init__(self, name: str, config: ConnectionConfig) -> None:
        self.name = name
        self.config = config
        self.username: SecretMark | None = None
        self.password: SecretMark | None = None
        if config.username_env:
            env = resolve_env_name(config.username_env, kind="username_env")
            val = os.environ.get(env)
            if not val:
                raise ConfigError(f"connection '{name}': environment variable {env} (username_env) is not set")
            self.username = SecretMark(val)
        if config.password_env:
            env = resolve_env_name(config.password_env, kind="password_env")
            val = os.environ.get(env)
            if not val:
                raise ConfigError(f"connection '{name}': environment variable {env} (password_env) is not set")
            self.password = SecretMark(val)
        elif config.password_file:
            p = Path(config.password_file)
            _check_secret_file_permissions(p)
            val = p.read_text(encoding="utf-8").strip("\r\n")
            if not val:
                raise ConfigError(f"connection '{name}': secret file '{p}' is empty")
            self.password = SecretMark(val)


def _format_validation_errors(exc: ValidationError) -> str:
    """Render pydantic errors without echoing the rejected input value.

    pydantic v2's default str(exc) includes ``input_value=...`` for every
    error, which would leak an inline secret (e.g. ``password: hunter2``)
    into stderr, logs and doctor output via the CONFIG_ERROR message.
    Report only location, message and error type.
    """
    parts = []
    for err in exc.errors(include_url=False, include_input=False):
        loc = ".".join(str(part) for part in err.get("loc", ()))
        msg = err.get("msg", "")
        etype = err.get("type", "")
        parts.append(f"{loc}: {msg} [{etype}]" if loc else f"{msg} [{etype}]")
    return "; ".join(parts)


def load_config(path: str | Path) -> AppConfig:
    p = Path(path)
    try:
        raw_text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read config file '{p}': {exc}") from exc
    try:
        raw = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in '{p}': {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"config '{p}' must be a mapping at the top level")
    try:
        return AppConfig.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(f"invalid configuration in '{p}': {_format_validation_errors(exc)}") from exc
    except Exception as exc:
        raise ConfigError(f"invalid configuration in '{p}': {exc}") from exc


def load_resolved(path: str | Path) -> tuple[AppConfig, dict[str, ResolvedConnection]]:
    """Load config and resolve all secrets. Raises ConfigError on any missing
    or unsafe secret reference (fail fast, name the artifact)."""
    cfg = load_config(path)
    resolved: dict[str, ResolvedConnection] = {}
    for name, conn in cfg.connections.items():
        resolved[name] = ResolvedConnection(name, conn)
    return cfg, resolved
