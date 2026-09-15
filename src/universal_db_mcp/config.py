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
    # gssencmode/krbsrvname reach Kerberos deployments (the bundled libpq is
    # built --with-gssapi); service/passfile reach libpq's own config files;
    # sslmode is only for the TLS-disabled case (an enabled tls: block already
    # pins verify-full and must not be weakened from options).
    "postgres": {
        "os_authentication": bool,
        "gssencmode": str,
        "krbsrvname": str,
        "service": str,
        "passfile": str,
        "sslmode": str,
    },
    "mysql": {"os_authentication": bool, "unix_socket": str},
    "clickhouse": {"os_authentication": bool},
    # thick_mode + lib_dir: Thick mode via an ADMINISTRATOR-SUPPLIED Oracle
    # Instant Client (licensed by Oracle, never shipped here). It is the only
    # client-side way to authenticate an account that carries just the legacy
    # 10G password verifier, which Thin mode refuses with DPY-3015.
    # sid / tns_alias: pre-12c databases reached by SID, and tnsnames.ora
    # aliases (with tns_admin), neither expressible as an easy-connect service.
    "oracle": {
        "tns_admin": str,
        "wallet_location": str,
        "thick_mode": bool,
        "lib_dir": str,
        "sid": str,
        "tns_alias": str,
        "wallet_password": str,
    },
    # MssqlConnector reads options.odbc_driver to select the installed ODBC
    # driver (and doctor matches the exact name); a wrong name fails closed
    # at connect time naming the installed drivers.
    "mssql": {"odbc_driver": str, "trusted_connection": bool},
    # authentication: the CLI keyword the bundled clidriver already supports;
    # without it a server demanding a specific mechanism answers SQL30082N
    # reason 17, indistinguishable from the credential bug fixed in 854b50d.
    "db2": {"authentication": str},
}


# Characters that are GRAMMAR, not data, in an Oracle connect string. Verified
# against oracledb 4.0.2's own parser (2026-09-15): a `database` of
# "ORCL?ssl_server_dn_match=false" disables certificate matching - defeating
# this module's own refusal to set tls.verify_server=false - and a `host`
# carrying ")(ADDRESS=(PROTOCOL=TCP)(HOST=..." appends a PLAINTEXT fallback
# address. In Thick mode the driver does not parse the string at all
# (thick_mode_dsn_passthrough defaults to True), so the value reaches Oracle
# Net unchecked. Values are therefore validated here, at config time.
_ORACLE_GRAMMAR = set("()?&,;:/@= \t\r\n\"'\\")
_IPV6_ALLOWED = set("0123456789abcdefABCDEF:.")


def _reject_oracle_grammar(field: str, value: str | None) -> None:
    if not value:
        return
    if value.startswith("[") and value.endswith("]"):
        # bracketed IPv6 literal: colons are the address, not the port separator
        if set(value[1:-1]) <= _IPV6_ALLOWED:
            return
    bad = sorted(set(value) & _ORACLE_GRAMMAR)
    if bad:
        raise ValueError(
            f"oracle {field} contains connect string grammar {bad!r}; those characters are "
            "parsed as Oracle Net syntax (they can disable certificate matching, add a "
            "plaintext address or set a proxy), so they are not allowed in a value"
        )


class ConnectionConfig(StrictModel):
    type: Literal["sqlite", "db2", "oracle", "mssql", "postgres", "clickhouse", "mysql"]
    family: str | None = None  # db2: luw | zos | i
    host: str | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    database: str | None = None
    username_env: str | None = None
    password_env: str | None = None
    password_file: str | None = None
    # File-based username (mirrors password_file; added for the add-connection
    # wizard so credential FILES can carry both halves without env juggling).
    # Never inline credentials in this config.
    username_file: str | None = None
    tls: TlsConfig = Field(default_factory=TlsConfig)
    allowed_schemas: list[str] = Field(default_factory=list)
    read_only: bool = True
    connect_timeout_seconds: float = Field(default=10.0, gt=0, le=120)
    # Engine-specific, tightly validated options (see engine modules).
    options: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _hosts(self) -> ConnectionConfig:
        if self.type != "sqlite":
            if not self.host and not self.options.get("unix_socket"):
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
        if self.type in ("postgres", "mysql", "clickhouse") and not (
            self.username_env or self.username_file or self.options.get("os_authentication")
        ):
            # Omitting the username is NOT "send no credential": psycopg and
            # PyMySQL substitute the OS account of the server process and
            # clickhouse-connect substitutes 'default' (verified in the
            # installed drivers, 2026-09-15). Make that identity explicit.
            raise ValueError(
                f"connections: {self.type} needs username_env or username_file; omitting it "
                "makes the driver authenticate as an implicit identity (the service account's "
                "OS user, or 'default' on clickhouse). Set options.os_authentication: true to "
                "choose that deliberately"
            )
        if self.type == "clickhouse" and self.port in (9000, 9440):
            raise ValueError(
                f"clickhouse port {self.port} is the NATIVE TCP protocol; clickhouse-connect "
                "speaks HTTP only and would report an opaque protocol error. Use the HTTP "
                "interface (8123, or 8443 with tls.enabled)"
            )
        if self.type == "mssql" and self.options.get("trusted_connection") and (
            self.username_env or self.username_file
        ):
            raise ValueError(
                "mssql options.trusted_connection uses the process's Windows/Kerberos identity; "
                "remove username_env/username_file (a SQL login cannot be combined with it)"
            )
        if self.type == "db2" and (auth := self.options.get("authentication")):
            allowed_auth = {
                "CERTIFICATE", "SERVER", "SERVER_ENCRYPT", "SERVER_ENCRYPT_AES",
                "KERBEROS", "GSSPLUGIN", "TOKEN",
            }
            if str(auth).upper() not in allowed_auth:
                raise ValueError(
                    f"db2 options.authentication '{auth}' is not a CLI value; use one of "
                    f"{sorted(allowed_auth)}"
                )
        if self.type == "postgres" and self.options.get("sslmode") and self.tls.enabled:
            raise ValueError(
                "postgres options.sslmode cannot be combined with tls.enabled: the tls block "
                "already pins verify-full, and an sslmode from options could only weaken it"
            )
        if self.type == "postgres" and self.host and "," in self.host:
            raise ValueError(
                "postgres host contains a comma, which libpq reads as a multi-host failover "
                "list: the credentials would be offered to every host in turn"
            )
        if self.type == "oracle":
            _reject_oracle_grammar("host", self.host)
            _reject_oracle_grammar("database", self.database)
            _reject_oracle_grammar("options.sid", self.options.get("sid"))
            _reject_oracle_grammar("options.tns_alias", self.options.get("tns_alias"))
            if self.options.get("sid") and self.options.get("tns_alias"):
                raise ValueError(
                    "oracle options 'sid' and 'tns_alias' are mutually exclusive: "
                    "a TNS alias already names its own connect descriptor"
                )
            if self.options.get("tns_alias") and not self.options.get("tns_admin"):
                raise ValueError(
                    "oracle options.tns_alias requires options.tns_admin (the directory "
                    "holding tnsnames.ora); without it the alias cannot be resolved"
                )
            if self.options.get("lib_dir") and not self.options.get("thick_mode"):
                raise ValueError(
                    "oracle options.lib_dir only applies to Thick mode; set "
                    "options.thick_mode: true or drop lib_dir"
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
    def _oracle_thick_mode_is_all_or_nothing(self) -> AppConfig:
        """python-oracledb's init_oracle_client() switches the WHOLE process to
        Thick mode, so a config that mixes thick and thin oracle connections
        would silently make every oracle connection thick. Refuse instead."""
        modes = {
            bool(conn.options.get("thick_mode"))
            for conn in self.connections.values()
            if conn.type == "oracle"
        }
        if len(modes) > 1:
            raise ValueError(
                "oracle thick_mode is process-global (init_oracle_client switches the "
                "whole interpreter): either every oracle connection sets "
                "options.thick_mode: true, or none does"
            )
        return self

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
        if config.username_env and config.username_file:
            raise ConfigError(
                f"connection '{name}': username_env and username_file are mutually "
                "exclusive (pick one credential source)"
            )
        if config.username_env:
            env = resolve_env_name(config.username_env, kind="username_env")
            val = os.environ.get(env)
            if not val:
                raise ConfigError(f"connection '{name}': environment variable {env} (username_env) is not set")
            self.username = SecretMark(val)
        elif config.username_file:
            p = Path(config.username_file)
            _check_secret_file_permissions(p)
            val = p.read_text(encoding="utf-8").strip("\r\n")
            if not val:
                raise ConfigError(f"connection '{name}': username file '{p}' is empty")
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
