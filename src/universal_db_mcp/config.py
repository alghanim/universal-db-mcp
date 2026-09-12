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
# remain mandatory. Administrators extend via security.mask_columns (the
# built-in patterns always apply and cannot be removed by configuration).
# Each token is boundary-anchored to identifier characters ([a-z0-9], with '_'
# treated as a boundary) so short tokens like 'pan' or 'ssn' do not substring-
# match ordinary identifiers such as company_name, span_ms or issn.
DEFAULT_SENSITIVE_PATTERNS = [
    r"(?i)(?<![a-z0-9])(password|passwd|pwd|secret|token|api_?key|access_key|private_key)(?![a-z0-9])",
    r"(?i)(?<![a-z0-9])(ssn|social_security|tax_id|national_id|credit_card|card_number|cvv|pan)(?![a-z0-9])",
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

    @model_validator(mode="after")
    def _http_requires_bearer_token(self) -> ApplicationConfig:
        if self.transport == "http" and not self.http_bearer_token_file:
            raise ValueError(
                "application.transport=http requires application.http_bearer_token_file "
                "(the bearer token is the only authentication on the HTTP listener)"
            )
        return self


class TlsConfig(StrictModel):
    enabled: bool = False
    verify_server: bool = True
    ca_file: str | None = None
    client_cert_file: str | None = None
    client_key_file: str | None = None

    @model_validator(mode="after")
    def _verify_needs_ca(self) -> TlsConfig:
        if self.enabled and not self.verify_server:
            raise ValueError(
                "tls.verify_server=false is not permitted: certificate verification "
                "cannot be disabled (supply tls.ca_file pointing at the internal "
                "CA certificate instead)"
            )
        if self.enabled and not self.ca_file:
            raise ValueError(
                "tls.verify_server=true requires tls.ca_file pointing at the "
                "internal CA certificate; disabling verification is not permitted"
            )
        return self


# Per-engine option allowlist: unknown keys are rejected, values are typed.
# Anything else an engine needs must be added here deliberately (spec: strict
# schema everywhere). Only options actually consumed by a connector are
# allowlisted — an accepted-but-ignored option (e.g. a TLS control that is a
# no-op) would mislead operators into believing a setting is enforced.
_ENGINE_OPTIONS: dict[str, dict[str, type]] = {
    "sqlite": {},
    "postgres": {},
    "mysql": {},
    "clickhouse": {},
    "oracle": {"tns_admin": str, "wallet_location": str, "thick_mode": bool},
    # MssqlConnector reads options.odbc_driver to select the installed ODBC
    # driver (and doctor matches the exact name); a wrong name fails closed
    # at connect time naming the installed drivers.
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
        if self.type == "sqlite" and not self.database:
            raise ValueError("connections: database (file path) is required for type 'sqlite'")
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
        if self.type == "oracle":
            if self.options.get("thick_mode"):
                raise ValueError(
                    "oracle thick_mode is not supported in this build; use Thin "
                    "mode or run a separately reviewed deployment for the Instant Client"
                )
            if self.tls.enabled and not self.options.get("wallet_location"):
                raise ValueError(
                    "oracle tls.enabled=true requires options.wallet_location "
                    "(administrator-supplied, outside distributable artifacts); "
                    "refusing a plaintext connection"
                )
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
    mask_columns: list[str] = Field(default_factory=list)
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

    @model_validator(mode="after")
    def _merge_mask_columns(self) -> SecurityConfig:
        """security.mask_columns EXTENDS the built-in sensitive patterns (the
        documented 'additional patterns' semantics). Without this merge, any
        configured value would silently drop the default password/ssn/
        credit-card heuristics, unmasking those columns with no warning."""
        import re as _re

        merged: list[str] = []
        for pattern in (*DEFAULT_SENSITIVE_PATTERNS, *self.mask_columns):
            if pattern not in merged:
                merged.append(pattern)
        for pattern in merged:
            try:
                _re.compile(pattern)
            except _re.error as exc:
                raise ValueError(f"invalid mask_columns regex {pattern!r}: {exc}") from exc
        if merged != list(self.mask_columns):
            # frozen model: bypass __setattr__ to store the merged list
            object.__setattr__(self, "mask_columns", merged)
        return self

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
        """Writable audit/cache state (and secret files) must be separate files
        from each other and from queried SQLite data sources (spec §5).

        Paths are resolved with os.path.realpath so a symlink that points at a
        data source (or at another state file) cannot bypass the check the way
        a plain os.path.abspath comparison could."""
        state: list[tuple[str, str]] = []
        if self.application.audit_path:
            state.append(("application.audit_path", os.path.realpath(self.application.audit_path)))
        if self.application.metadata_cache_path:
            state.append(
                ("application.metadata_cache_path", os.path.realpath(self.application.metadata_cache_path))
            )
        if self.application.http_bearer_token_file:
            state.append(
                ("application.http_bearer_token_file", os.path.realpath(self.application.http_bearer_token_file))
            )
        for name, conn in self.connections.items():
            if conn.password_file:
                state.append((f"connections.{name}.password_file", os.path.realpath(conn.password_file)))

        seen: dict[str, str] = {}
        for label, rp in state:
            other = seen.get(rp)
            if other is not None:
                raise ValueError(
                    f"application state path '{rp}' is shared by '{other}' and "
                    f"'{label}': audit, metadata-cache and secret files must "
                    f"each be a separate file"
                )
            seen[rp] = label

        for name, conn in self.connections.items():
            if conn.type == "sqlite" and conn.database:
                dbp = os.path.realpath(conn.database)
                for label, sp in state:
                    if sp == dbp:
                        raise ValueError(
                            f"application state path '{sp}' ('{label}') must be a "
                            f"separate file from the queried SQLite data source "
                            f"of connection '{name}'"
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


def _apply_http_token_env_override(raw: dict[str, object]) -> dict[str, object]:
    """Allow the HTTP bearer-token PATH to come from the service environment.

    A service-manager deployment (systemd unit, launchd plist, container
    compose) forces ``--transport http`` on the command line while sharing the
    SAME config file with per-harness stdio spawns, so the config template
    keeps ``transport: stdio`` and cannot hard-code the token path. The unit
    sets ``UDBMCP_HTTP_BEARER_TOKEN_FILE`` and the provisioner creates that
    file; an explicit ``application.http_bearer_token_file`` in the config
    always wins. This is a PATH override only — the token itself is never
    carried in an environment variable.
    """
    env_path = os.environ.get("UDBMCP_HTTP_BEARER_TOKEN_FILE")
    if not env_path:
        return raw
    app = raw.get("application")
    if app is None:
        app = {}
        raw["application"] = app
    if isinstance(app, dict) and not app.get("http_bearer_token_file"):
        app["http_bearer_token_file"] = env_path
    return raw


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
    raw = _apply_http_token_env_override(raw)
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
