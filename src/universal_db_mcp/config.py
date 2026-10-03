"""Validated YAML configuration.

- Strict schema: unknown or misplaced fields are rejected (``extra='forbid'``).
- Secrets are resolved from the environment or secret *files* at load time and
  wrapped in :class:`SecretMark` so they can never be serialized, logged, or
  echoed. Raw values never live in the config model exposed to tools.
- Secret files other local users can read are rejected, per the spec's
  unsafe-permission rule: group/world mode bits on POSIX; on Windows an ACE
  giving a broad group read or write access (or the right to change the DACL
  or owner), an ACE whose trustee cannot be checked, or a foreign owner.
- A repeated mapping key is an error (PyYAML would keep the last value), and
  relative secret, TLS and state paths are relative to the config file.
"""

from __future__ import annotations

import errno
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    ValidationError,
    ValidationInfo,
    field_validator,
    model_validator,
)

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
    # Set by load_config when the file leaves audit_path unset: which default
    # location it chose, for doctor to report. Not a config key.
    _audit_path_default: str | None = PrivateAttr(default=None)

    @property
    def audit_path_default(self) -> str | None:
        """The default location load_config chose for an unset ``audit_path``,
        or None when the config file set it."""
        return self._audit_path_default

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
        # a password-protected wallet: the password is a secret, referenced
        # like password_file/password_env and never inlined in the config
        "wallet_password_file": str,
        "wallet_password_env": str,
    },
    # MssqlConnector reads options.odbc_driver to select the installed ODBC
    # driver (and doctor matches the exact name); a wrong name fails closed
    # at connect time naming the installed drivers.
    "mssql": {"odbc_driver": str, "trusted_connection": bool, "application_intent": str},
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


# Isolation levels each engine can be asked for. Db2 and SQL Server take
# share locks on ordinary reads, so a reporting session against production
# must run at an isolation that does not (UR / READ UNCOMMITTED); the MVCC
# engines never block writers with a read, so their server default stands.
ENGINE_ISOLATION_LEVELS: dict[str, tuple[str, ...]] = {
    "db2": ("ur", "cs", "rs", "rr"),
    "mssql": ("read_uncommitted", "read_committed", "repeatable_read", "serializable", "snapshot"),
    "postgres": ("read_committed", "repeatable_read", "serializable"),
    "mysql": ("read_uncommitted", "read_committed", "repeatable_read", "serializable"),
    "oracle": ("read_committed", "serializable"),
    "clickhouse": (),
    "sqlite": (),
}
# used with fullmatch: '$' would also accept a trailing newline
_APP_NAME_RE = re.compile(r"[A-Za-z0-9_.:@-]{1,64}")
# no leading '-': every command line that takes the id would read it as an option
_CONNECTION_ID_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_-]{0,63}")
_ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


class SessionConfig(StrictModel):
    """What the connector does to the SERVER session right after connecting,
    so an agent's reads cannot hurt production. Resolved per engine by
    ``universal_db_mcp.security.session``.

    * ``isolation``: engine-specific level; None = the engine's safe default
      (Db2 ``ur`` and SQL Server ``read_uncommitted`` for read-only
      connections, otherwise the server default). Setting it is enforced:
      a server that refuses it fails the connection rather than running at
      the default level silently.
    * ``lock_timeout_seconds``: how long a statement may wait for a lock
      (None = server default). Default 5 s so the agent never queues behind
      a writer indefinitely.
    * ``application_name``: what DBAs see in the session list; default
      ``udbmcp:<connection id>``. DSN-safe characters only.
    * ``enforce_read_only``: ask the server to refuse writes for this
      session where the engine supports it (PostgreSQL, MySQL, ClickHouse,
      SQLite). The SQL guard remains the enforcement on Oracle/Db2/SQL Server.
    * ``statement_timeout_from_policy``: apply the policy's hard query
      timeout server-side too, not only as a client-side cancel.
    """

    isolation: str | None = None
    lock_timeout_seconds: float | None = Field(default=5.0, ge=0, le=300)
    application_name: str | None = None
    enforce_read_only: bool = True
    statement_timeout_from_policy: bool = True

    @field_validator("isolation")
    @classmethod
    def _lower(cls, v: str | None) -> str | None:
        return v.strip().lower() if isinstance(v, str) else v

    @field_validator("application_name")
    @classmethod
    def _dsn_safe(cls, v: str | None) -> str | None:
        if v is not None and not _APP_NAME_RE.fullmatch(v):
            raise ValueError(
                "session.application_name may contain only letters, digits, '_', '.', ':', '@' "
                "and '-' (1-64 chars): it is written into driver connection strings"
            )
        return v


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
    session: SessionConfig = Field(default_factory=SessionConfig)

    def secret_env_variables(self) -> list[str]:
        """The environment variables this connection reads its credentials
        from (names only; values are never read here): username_env,
        password_env and the Oracle options.wallet_password_env. A server a
        GUI harness spawns does not inherit them from any shell."""
        wallet = self.options.get("wallet_password_env")
        return [
            v for v in (self.username_env, self.password_env, wallet if isinstance(wallet, str) else None) if v
        ]

    @field_validator("read_only")
    @classmethod
    def _read_only_required(cls, v: bool) -> bool:
        # The server-side read-only session and the Db2/SQL Server UR default
        # both key off this flag, while db_list_connections reports every
        # connection read-only.
        if not v:
            raise ValueError("read_only=false is not supported in v1; every connection is read-only")
        return v

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
        if self.type == "oracle" and "wallet_password" in self.options:
            raise ValueError(
                "oracle options.wallet_password would inline a secret in the config file; reference it "
                "with options.wallet_password_file (a file only the service account can read) or "
                "options.wallet_password_env instead"
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
        if self.session.isolation is not None:
            allowed_levels = ENGINE_ISOLATION_LEVELS.get(self.type, ())
            if self.session.isolation not in allowed_levels:
                raise ValueError(
                    f"session.isolation '{self.session.isolation}' is not valid for {self.type}"
                    + (f"; use one of {list(allowed_levels)}" if allowed_levels else
                       "; this engine has no session isolation setting")
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
            if self.options.get("wallet_password_file") and self.options.get("wallet_password_env"):
                raise ValueError(
                    "oracle options.wallet_password_file and options.wallet_password_env are mutually "
                    "exclusive (pick one source for the wallet password)"
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
    # Discovery ceilings (db_profile_table / db_search_values): rows a profile
    # may scan, and the wall-clock budget one discovery call may spend across
    # all the statements it issues. Every statement is also bounded by the
    # query timeout above.
    profile_max_sample_rows: int = Field(default=50_000, ge=100, le=1_000_000)
    discovery_time_budget_seconds: float = Field(default=60.0, ge=5, le=900)
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
    def _state_isolated_from_data_sources(self, info: ValidationInfo) -> AppConfig:
        """Writable state must each be a separate file, and none of it may be
        a file the server reads: a secret, a TLS file, the HTTP bearer token
        or a queried SQLite data source (spec §5). State is every file the
        server writes: the audit log, its .lock sidecar, its rotated
        backups <audit_path>.1..N and <audit_path>.rotating, and the metadata cache with the -wal,
        -shm and -journal files SQLite keeps beside it. Read-only inputs of
        one kind may be shared, e.g. two connections using one password file
        or one CA bundle; the bearer token, which every HTTP client holds,
        may not double as any other file.

        Paths are resolved with os.path.realpath so a symlink that points at
        a data source (or at another state file) cannot bypass the check the
        way a plain os.path.abspath comparison could. Two existing paths are
        also one file when they name one inode (a hard link, or a case
        variant on a case-insensitive filesystem), and on macOS and Windows,
        whose default filesystems ignore case, paths are compared case-folded.
        No state file may be a network configuration or wallet file the
        Oracle client reads from options.wallet_location or tns_admin (other
        files in those directories are fine), nor lie in the Instant Client
        directory options.lib_dir itself or in its network/admin subdirectory.

        A message about an audit_path that load_config filled in (validation
        context ``audit_path_default``) says so: the file never set it."""
        app = self.application
        audit_default = info.context.get("audit_path_default") if isinstance(info.context, dict) else None

        def named(label: str) -> str:
            if audit_default and label.startswith("application.audit_path"):
                return f"'{label}' (application.audit_path is unset; this is its default in the {audit_default})"
            return f"'{label}'"

        files: list[tuple[str, str, str | None]] = [
            ("state", "application.audit_path", app.audit_path),
            # the cross-process rotation lock AuditLog keeps next to the log
            ("state", "application.audit_path lock file", f"{app.audit_path}.lock" if app.audit_path else None),
            # where rotation moves the log before it shifts the backups
            (
                "state",
                "application.audit_path rotation file",
                f"{app.audit_path}.rotating" if app.audit_path else None,
            ),
            ("state", "application.metadata_cache_path", app.metadata_cache_path),
            ("token", "application.http_bearer_token_file", app.http_bearer_token_file),
        ]
        if app.metadata_cache_path:
            files += [
                ("state", f"application.metadata_cache_path {suffix} file", f"{app.metadata_cache_path}{suffix}")
                for suffix in ("-wal", "-shm", "-journal")
            ]
        for name, conn in self.connections.items():
            files += [
                ("secret", f"connections.{name}.username_file", conn.username_file),
                ("secret", f"connections.{name}.password_file", conn.password_file),
                (
                    "secret",
                    f"connections.{name}.options.wallet_password_file",
                    conn.options.get("wallet_password_file"),
                ),
                (
                    "secret",
                    f"connections.{name}.options.passfile",
                    conn.options.get("passfile") if conn.type == "postgres" else None,
                ),
                ("tls", f"connections.{name}.tls.ca_file", conn.tls.ca_file),
                ("tls", f"connections.{name}.tls.client_cert_file", conn.tls.client_cert_file),
                ("tls", f"connections.{name}.tls.client_key_file", conn.tls.client_key_file),
                # the connector opens Path(database).expanduser().resolve()
                (
                    "data",
                    f"connections.{name}.database",
                    os.path.expanduser(conn.database) if conn.type == "sqlite" and conn.database else None,
                ),
            ]

        def state_clash(rp: str, first: str, second: str) -> ValueError:
            return ValueError(
                f"application state path '{rp}' is shared by {named(first)} and {named(second)}: the audit log "
                f"(with its lock file and rotated backups) and the metadata cache (with its SQLite "
                f"sidecars) must each be a separate file from each other and from every file the "
                f"server reads"
            )

        seen: dict[object, tuple[str, str]] = {}
        resolved: list[tuple[str, str, str]] = []  # (kind, label, realpath)
        for kind, label, path in files:
            if not path:
                continue
            rp = os.path.realpath(path)
            resolved.append((kind, label, rp))
            keys = _same_file_keys(path, rp)
            clash = next((seen[k] for k in keys if k in seen), None)
            for k in keys:
                seen.setdefault(k, (kind, label))
            if clash is None:
                continue
            other_kind, other = clash
            if kind == other_kind and kind in ("secret", "tls", "data"):
                continue
            if "state" in (kind, other_kind):
                raise state_clash(rp, other, label)
            if "token" in (kind, other_kind):
                raise ValueError(
                    f"'{other}' and '{label}' name the same file '{rp}': every HTTP client holds the "
                    f"bearer token, so the token file must be a separate file"
                )
            raise ValueError(
                f"'{other}' and '{label}' name the same file '{rp}': a secret, a TLS file and a "
                f"queried SQLite data source must each be a separate file"
            )
        if app.audit_path:
            # Rotation renames the log to <audit_path>.1 .. .<audit_max_backups>
            # in the log's own directory, replacing whatever file is there.
            head, tail = os.path.split(os.path.abspath(app.audit_path))
            prefix = _fold_case(os.path.join(os.path.realpath(head), tail) + ".")
            for _kind, label, rp in resolved:
                folded = _fold_case(rp)
                n = folded[len(prefix) :] if folded.startswith(prefix) else ""
                if n.isascii() and n.isdigit() and not n.startswith("0") and int(n) <= app.audit_max_backups:
                    raise state_clash(rp, f"application.audit_path backup .{n}", label)
        # The log would append into ewallet.pem or tnsnames.ora, and rotation
        # would rename it away. Only those files are off limits: TNS_ADMIN is
        # often $HOME or the per-user state directory itself.
        state = [(label, rp) for kind, label, rp in resolved if kind == "state"]
        state_files = [(label, set(_same_file_keys(rp, rp))) for label, rp in state]
        for name, conn in self.connections.items():
            lib_dir = conn.options.get("lib_dir")
            client_dirs = [(option, conn.options.get(option)) for option in _ORACLE_CLIENT_DIR_OPTIONS]
            if isinstance(lib_dir, str) and lib_dir:
                # A full Oracle Client's lib_dir is ORACLE_HOME/lib (ORACLE_HOME\bin
                # on Windows): its network configuration is ORACLE_HOME/network/admin.
                client_dirs.append(("lib_dir", os.path.join(lib_dir, os.pardir, "network", "admin")))
            for option, directory in client_dirs:
                if not isinstance(directory, str) or not directory:
                    continue
                for client_file in (os.path.join(directory, f) for f in _ORACLE_CLIENT_FILES):
                    client_keys = _same_file_keys(client_file, os.path.realpath(client_file))
                    for label, state_keys in state_files:
                        if state_keys.intersection(client_keys):
                            raise ValueError(
                                f"{named(label)} is '{client_file}', a file the Oracle client reads through "
                                f"connections.{name}.options.{option}: the audit log and the metadata cache "
                                "must be separate from the wallet and network configuration files"
                            )
            # The client loads the files in lib_dir and in lib_dir/network/admin
            # only: deeper down (lib_dir=$HOME with the per-user default) is fine.
            if not isinstance(lib_dir, str) or not lib_dir:
                continue
            lib_dirs = {
                _fold_case(os.path.realpath(directory)): directory
                for directory in (lib_dir, os.path.join(lib_dir, "network", "admin"))
            }
            for label, rp in state:
                directory = lib_dirs.get(_fold_case(os.path.dirname(rp)))
                if directory is not None:
                    raise ValueError(
                        f"{named(label)} ('{rp}') is in '{directory}' (connections.{name}.options.lib_dir): the "
                        "Oracle client loads its libraries from lib_dir and its network configuration from "
                        "lib_dir/network/admin, so the audit log and the metadata cache must be elsewhere"
                    )
        return self

    @field_validator("connections")
    @classmethod
    def _reserved_names(cls, v: dict[str, ConnectionConfig]) -> dict[str, ConnectionConfig]:
        folded: dict[str, str] = {}
        for name in v:
            # ASCII only (str.isalnum() is Unicode-wide): canonically equivalent
            # ids such as U+1F71 and U+03AC differ under casefold() but name
            # the same secret files on a normalization-insensitive filesystem
            if not _CONNECTION_ID_RE.fullmatch(name):
                raise ValueError(f"connection id '{name}' must be 1-64 chars of [A-Za-z0-9_-], not starting with '-'")
            other = folded.setdefault(name.casefold(), name)
            if other != name:
                # the wizard names secret files after the id, and a
                # case-insensitive filesystem would give both ids one pair
                raise ValueError(
                    f"connection ids '{other}' and '{name}' differ only in case; rename one "
                    "(case-insensitive filesystems would give them the same secret files)"
                )
        return v


# Connection options naming a directory the Oracle client reads files from,
# and the files it reads there: network configuration, Thick mode's
# oraaccess.xml and the wallet (Thin mode also looks for the wallet in the
# TNS_ADMIN directory, and a cloud wallet directory is usually TNS_ADMIN too).
# The Instant Client directory (options.lib_dir) holds the client's libraries
# and, in network/admin, its default TNS_ADMIN: no state goes in either one.
# A full client's default TNS_ADMIN is lib_dir/../network/admin, whose
# files above count as the client's too.
_ORACLE_CLIENT_DIR_OPTIONS = ("wallet_location", "tns_admin")
_ORACLE_CLIENT_FILES = (
    "tnsnames.ora",
    "sqlnet.ora",
    "ldap.ora",
    "oraaccess.xml",
    "ewallet.pem",
    "cwallet.sso",
    "ewallet.p12",
)


def _fold_case(path: str) -> str:
    """*path* as compared for identity: case-folded on macOS and Windows,
    whose default filesystems ignore case."""
    return path.casefold() if sys.platform in ("darwin", "win32") else path


def _same_file_keys(path: str, realpath: str) -> list[object]:
    """Keys under which two configured paths are the same file: the
    (case-folded) real path, and for an existing file its inode, which also
    catches a hard link and a case variant on any case-insensitive
    filesystem."""
    keys: list[object] = [_fold_case(realpath)]
    try:
        st = os.stat(path)
    except OSError:
        return keys
    if st.st_ino:  # 0 where the filesystem has no file ids
        keys.append((st.st_dev, st.st_ino))
    return keys


# Windows: trustees that stand for "other local users" (or for anyone). A
# secret file must not grant any of them read or write access, nor the right
# to rewrite its DACL or take ownership (either leads to read access), and must
# be owned by SYSTEM, Administrators or the account the server runs as. A
# grant to one named account, such as the read access the MSI gives the
# service account, is an administrator's explicit choice and is allowed.
_WIN32_BROAD_SIDS = {
    "S-1-1-0": "Everyone",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-32-545": "Users",
    "S-1-5-4": "Interactive",
    "S-1-5-32-546": "Guests",
    "S-1-5-7": "Anonymous Logon",
    "S-1-5-2": "Network",
    "S-1-5-1": "Dialup",
    "S-1-5-3": "Batch",
    "S-1-5-6": "Service",
    "S-1-5-13": "Terminal Server User",
    "S-1-5-14": "Remote Interactive Logon",
    "S-1-5-15": "This Organization",
    "S-1-5-113": "Local account",
    "S-1-5-32-547": "Power Users",
    "S-1-5-32-555": "Remote Desktop Users",
    "S-1-2-0": "Local",
    "S-1-2-1": "Console Logon",
    "S-1-15-2-1": "All Application Packages",
    "S-1-15-2-2": "All Restricted Application Packages",
}
# Groups every account or computer of a domain is in: the RID that ends a
# S-1-5-21-<domain>-<rid> SID.
_WIN32_BROAD_DOMAIN_RIDS = {"513": "Domain Users", "514": "Domain Guests", "515": "Domain Computers"}
_WIN32_TRUSTED_OWNERS = {"S-1-5-18": "SYSTEM", "S-1-5-32-544": "Administrators"}
_ACCESS_ALLOWED_ACE_TYPE = 0x0
# Object, callback (conditional) and callback-object allow ACEs. Their
# trustee is not read here, so one that grants access is refused unchecked.
_WIN32_OPAQUE_ALLOW_ACE_TYPES = (0x5, 0x9, 0xB)
_INHERIT_ONLY_ACE = 0x08
# FILE_READ_DATA, GENERIC_ALL, GENERIC_READ
_WIN32_READ_RIGHTS = 0x0001 | 0x10000000 | 0x80000000
# FILE_WRITE_DATA, FILE_APPEND_DATA, GENERIC_WRITE: the trustee can replace
# the secret (a bearer token it knows), as group/other write bits on POSIX
_WIN32_WRITE_RIGHTS = 0x0002 | 0x0004 | 0x40000000
# WRITE_DAC, WRITE_OWNER: the trustee can grant itself read access
_WIN32_TAKEOVER_RIGHTS = 0x00040000 | 0x00080000
_WIN32_REFUSED_RIGHTS = _WIN32_READ_RIGHTS | _WIN32_WRITE_RIGHTS | _WIN32_TAKEOVER_RIGHTS


def _win32_file_security(path: Path) -> tuple[str, str, list[tuple[int, int, int, str]] | None]:
    """(owner SID, SID of this process's user, DACL entries) of *path*. Each
    entry is (ACE type, ACE flags, access mask, trustee SID); a NULL DACL,
    which grants everyone full access, is None. Read with pywin32, which is
    installed on Windows as a dependency of the mcp package."""
    if sys.platform != "win32":
        raise OSError(f"cannot read a Windows DACL on {sys.platform}")
    import win32api  # type: ignore[import-untyped]
    import win32security  # type: ignore[import-untyped]

    info = win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION
    sd = win32security.GetFileSecurity(str(path), info)
    owner = win32security.ConvertSidToStringSid(sd.GetSecurityDescriptorOwner())
    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32security.TOKEN_QUERY)
    user = win32security.ConvertSidToStringSid(win32security.GetTokenInformation(token, win32security.TokenUser)[0])
    dacl = sd.GetSecurityDescriptorDacl()
    if dacl is None:
        return owner, user, None
    aces: list[tuple[int, int, int, str]] = []
    for i in range(dacl.GetAceCount()):
        (ace_type, ace_flags), mask, *rest = dacl.GetAce(i)
        # object ACEs carry GUIDs before the SID; only the standard
        # allow/deny layout ends in the trustee SID
        sid = win32security.ConvertSidToStringSid(rest[-1]) if ace_type in (0, 1) else ""
        aces.append((ace_type, ace_flags, mask, sid))
    return owner, user, aces


def win32_secret_file_problems(path: Path) -> list[str]:
    """Why other local users could read or rewrite the secret file *path*
    on Windows (empty when they cannot). A DACL that cannot be read is a
    problem too: a secret whose access cannot be verified is refused."""
    try:
        owner, user, aces = _win32_file_security(path)
    except Exception as exc:  # noqa: BLE001 - fail closed on anything
        return [f"its Windows access control list could not be read ({exc})"]
    problems: list[str] = []
    if owner not in _WIN32_TRUSTED_OWNERS and owner != user:
        problems.append(f"owned by {owner}, not by SYSTEM, Administrators or the account running this process")
    if aces is None:
        problems.append("its DACL is NULL, which grants everyone full access")
        return problems
    for ace_type, ace_flags, mask, sid in aces:
        if ace_flags & _INHERIT_ONLY_ACE or not mask & _WIN32_REFUSED_RIGHTS:
            continue
        if ace_type in _WIN32_OPAQUE_ALLOW_ACE_TYPES:
            problems.append(
                f"an object or conditional allow entry (ACE type {ace_type}) grants access to a trustee "
                "that cannot be checked"
            )
        elif ace_type == _ACCESS_ALLOWED_ACE_TYPE and (broad := _win32_broad_trustee(sid)):
            if mask & _WIN32_READ_RIGHTS:
                problems.append(f"readable by {broad} ({sid})")
            elif mask & _WIN32_WRITE_RIGHTS:
                problems.append(f"writable by {broad} ({sid}), which could replace the secret")
            else:
                problems.append(f"{broad} ({sid}) may change its DACL or owner, and so grant itself read access")
    return problems


def _win32_broad_trustee(sid: str) -> str | None:
    """The name of *sid* when it stands for a broad set of accounts."""
    if sid in _WIN32_BROAD_SIDS:
        return _WIN32_BROAD_SIDS[sid]
    parts = sid.split("-")
    if sid.startswith("S-1-5-21-") and len(parts) == 8:
        return _WIN32_BROAD_DOMAIN_RIDS.get(parts[-1])
    return None


def _check_secret_file_permissions(path: Path) -> None:
    """Reject secret files other local users can read: group/other mode bits
    on POSIX, the DACL and owner problems win32_secret_file_problems names on
    Windows."""
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError as exc:
        raise ConfigError(f"secret file '{path}' is not readable: {exc}") from exc
    if sys.platform == "win32":
        problems = win32_secret_file_problems(path)
        if problems:
            raise ConfigError(
                f"secret file '{path}' has unsafe permissions: {'; '.join(problems)}. Remove inherited "
                "access (icacls <file> /inheritance:r) and grant only SYSTEM, Administrators and the "
                "service account"
            )
        return
    if mode & 0o077:
        raise ConfigError(
            f"secret file '{path}' has unsafe permissions ({stat.filemode(mode)}): remove group/other access bits"
        )
    try:
        problems = darwin_secret_file_acl_problems(path)
    except OSError as exc:
        raise ConfigError(f"secret file '{path}': its access control list cannot be read ({exc.strerror})") from exc
    if problems:
        raise ConfigError(
            f"secret file '{path}' has unsafe permissions: {'; '.join(problems)}. Remove the access control "
            "list (chmod -N <file>)"
        )


# macOS <sys/acl.h>: ACL_TYPE_EXTENDED (the only ACL type macOS has), the
# ACL_EXTENDED_ALLOW tag, acl_get_entry's ACL_FIRST_ENTRY/ACL_NEXT_ENTRY and
# the rights that expose or replace a secret; <membership.h> ID_TYPE_UID.
_DARWIN_ACL_TYPE_EXTENDED = 0x00000100
_DARWIN_ACL_EXTENDED_ALLOW = 1
_DARWIN_ACL_FIRST_ENTRY = 0
_DARWIN_ACL_NEXT_ENTRY = -1
_DARWIN_ID_TYPE_UID = 0
_DARWIN_ACL_RIGHTS = (
    (1 << 1, "read"),
    (1 << 2, "write"),
    (1 << 5, "append"),
    (1 << 12, "writesecurity"),
    (1 << 13, "chown"),
)


def darwin_secret_file_acl_problems(path: Path) -> list[str]:
    """What the macOS extended ACL of *path* grants beyond its mode bits: each
    allow entry giving anyone but the file's owner read or write access, or
    the right to rewrite the ACL or take ownership (either leads to read
    access). A 0600 file with 'everyone allow read' lists as -rw-------+ and
    every local user can read it. Deny entries only take access away. Empty
    on other platforms and on a filesystem without ACLs; OSError when the
    ACL cannot be read."""
    if sys.platform != "darwin":
        return []
    import ctypes

    libc = _darwin_acl_libc()
    libc.acl_get_file.restype = ctypes.c_void_p
    libc.acl_get_file.argtypes = [ctypes.c_char_p, ctypes.c_int]
    ctypes.set_errno(0)
    acl = libc.acl_get_file(os.fsencode(path), _DARWIN_ACL_TYPE_EXTENDED)
    return _darwin_acl_grants(libc, acl, lambda: os.stat(path).st_uid, _DARWIN_ACL_RIGHTS, str(path))


# Every right an entry can carry on a directory (<sys/kauth.h> KAUTH_VNODE_*,
# named as chmod(1) names them for a directory).
_DARWIN_DIRECTORY_ACL_RIGHTS = (
    (1 << 1, "list"),
    (1 << 2, "add_file"),
    (1 << 3, "search"),
    (1 << 4, "delete"),
    (1 << 5, "add_subdirectory"),
    (1 << 6, "delete_child"),
    (1 << 7, "readattr"),
    (1 << 8, "writeattr"),
    (1 << 9, "readextattr"),
    (1 << 10, "writeextattr"),
    (1 << 11, "readsecurity"),
    (1 << 12, "writesecurity"),
    (1 << 13, "chown"),
)


def darwin_directory_acl_problems(fd: int) -> list[str]:
    """What the macOS extended ACL of the directory *fd* grants anyone but its
    owner: each allow entry with any right at all, inheritable ones included
    (every file created in the directory takes those). Deny entries only take
    access away ('group:everyone deny delete', which macOS puts on every home
    directory, among them), and the owner's own entry adds nothing. Empty on
    other platforms and on a filesystem without ACLs; OSError when the ACL
    cannot be read."""
    if sys.platform != "darwin":
        return []
    import ctypes

    libc = _darwin_acl_libc()
    libc.acl_get_fd_np.restype = ctypes.c_void_p
    libc.acl_get_fd_np.argtypes = [ctypes.c_int, ctypes.c_int]
    ctypes.set_errno(0)
    acl = libc.acl_get_fd_np(fd, _DARWIN_ACL_TYPE_EXTENDED)
    return _darwin_acl_grants(libc, acl, lambda: os.fstat(fd).st_uid, _DARWIN_DIRECTORY_ACL_RIGHTS, "a directory")


def _darwin_acl_libc() -> Any:
    import ctypes

    libc = ctypes.CDLL(None, use_errno=True)
    libc.acl_get_entry.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)]
    libc.acl_get_tag_type.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
    libc.acl_get_permset.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    libc.acl_get_perm_np.argtypes = [ctypes.c_void_p, ctypes.c_int]
    libc.acl_get_qualifier.restype = ctypes.c_void_p
    libc.acl_get_qualifier.argtypes = [ctypes.c_void_p]
    libc.mbr_uuid_to_id.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_int)]
    libc.acl_free.argtypes = [ctypes.c_void_p]
    return libc


def _darwin_acl_grants(
    libc: Any, acl: Any, owner_of: Any, rights_table: tuple[tuple[int, str], ...], what: str
) -> list[str]:
    """The allow entries of *acl* (from acl_get_file or acl_get_fd_np, just
    called; freed here) that give anyone but the owner (*owner_of*()) one of
    the rights in *rights_table*; [] for no ACL (ENOENT) or none possible."""
    import ctypes

    if not acl:
        err = ctypes.get_errno()
        if err in (errno.ENOENT, errno.ENOTSUP, errno.EOPNOTSUPP):  # no ACL, or none possible here
            return []
        raise OSError(err, os.strerror(err), what)
    problems: list[str] = []
    try:
        owner = owner_of()
        entry = ctypes.c_void_p()
        which = _DARWIN_ACL_FIRST_ENTRY
        while libc.acl_get_entry(acl, which, ctypes.byref(entry)) == 0:
            which = _DARWIN_ACL_NEXT_ENTRY
            tag, permset = ctypes.c_int(), ctypes.c_void_p()
            if libc.acl_get_tag_type(entry, ctypes.byref(tag)) or libc.acl_get_permset(entry, ctypes.byref(permset)):
                problems.append("an access control list entry cannot be read")
                continue
            if tag.value != _DARWIN_ACL_EXTENDED_ALLOW:
                continue
            rights = ",".join(name for bit, name in rights_table if libc.acl_get_perm_np(permset, bit) == 1)
            if not rights:
                continue
            ident, id_type = ctypes.c_uint32(), ctypes.c_int()
            qualifier = libc.acl_get_qualifier(entry)
            unresolved = 1
            if qualifier:
                try:
                    unresolved = libc.mbr_uuid_to_id(qualifier, ctypes.byref(ident), ctypes.byref(id_type))
                finally:
                    libc.acl_free(qualifier)
            if unresolved:
                problems.append(f"an access control list entry grants {rights} to a trustee that cannot be checked")
            elif id_type.value != _DARWIN_ID_TYPE_UID or ident.value != owner:  # the owner's own entry adds nothing
                who = _darwin_trustee_name(ident.value, user=id_type.value == _DARWIN_ID_TYPE_UID)
                problems.append(f"an access control list entry grants {rights} to {who}")
    finally:
        libc.acl_free(acl)
    return problems


def _darwin_trustee_name(ident: int, *, user: bool) -> str:
    import grp
    import pwd

    try:
        return f"user {pwd.getpwuid(ident).pw_name}" if user else f"group {grp.getgrgid(ident).gr_name}"
    except KeyError:
        return f"uid {ident}" if user else f"gid {ident}"


def resolve_env_name(name: str, *, kind: str) -> str:
    # ASCII only, as for connection ids: str.isalnum() is Unicode-wide
    if not _ENV_NAME_RE.fullmatch(name):
        raise ConfigError(f"invalid environment variable name for {kind}")
    return name


def _identity_mark(value: str) -> SecretMark:
    """Wrap a username so it is never serialized, WITHOUT registering it for
    free-text scrubbing. A username is an identifier the agent can read back
    with SELECT current_user; registered as a secret, a common one ('default',
    'sa') rewrote that word in every unrelated error message. The driver
    auth-failure shapes that embed a username stay scrubbed by redact_text's
    own patterns."""
    mark = SecretMark.__new__(SecretMark)
    mark.value = value
    return mark


def _read_secret_file(p: Path, what: str) -> str:
    _check_secret_file_permissions(p)
    try:
        val = p.read_text(encoding="utf-8").strip("\r\n")
    except UnicodeDecodeError:
        # the codec's message quotes a byte of the secret and its offset
        raise ConfigError(f"{what} '{p}' is not valid UTF-8 text") from None
    if not val:
        raise ConfigError(f"{what} '{p}' is empty")
    return val


class ResolvedConnection:
    """A connection config with secrets resolved to SecretMark values.

    An Oracle wallet password (options.wallet_password_file/_env) is resolved
    too: it is registered for redaction as ``wallet_password`` and handed to
    the connector as ``config.options['wallet_password']``, the key the
    Oracle connector reads."""

    __slots__ = ("config", "name", "username", "password", "wallet_password")

    def __init__(self, name: str, config: ConnectionConfig) -> None:
        self.name = name
        self.config = config
        self.username: SecretMark | None = None
        self.password: SecretMark | None = None
        self.wallet_password: SecretMark | None = None
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
            self.username = _identity_mark(val)
        elif config.username_file:
            self.username = _identity_mark(
                _read_secret_file(Path(config.username_file), f"connection '{name}': username file")
            )
        if config.password_env:
            env = resolve_env_name(config.password_env, kind="password_env")
            val = os.environ.get(env)
            if not val:
                raise ConfigError(f"connection '{name}': environment variable {env} (password_env) is not set")
            self.password = SecretMark(val)
        elif config.password_file:
            self.password = SecretMark(
                _read_secret_file(Path(config.password_file), f"connection '{name}': secret file")
            )
        wallet_env = config.options.get("wallet_password_env")
        wallet_file = config.options.get("wallet_password_file")
        if wallet_env:
            env = resolve_env_name(wallet_env, kind="options.wallet_password_env")
            val = os.environ.get(env)
            if not val:
                raise ConfigError(
                    f"connection '{name}': environment variable {env} (options.wallet_password_env) is not set"
                )
            self.wallet_password = SecretMark(val)
        elif wallet_file:
            self.wallet_password = SecretMark(
                _read_secret_file(Path(wallet_file), f"connection '{name}': wallet password file")
            )
        if self.wallet_password is not None:
            self.config = config.model_copy(
                update={"options": {**config.options, "wallet_password": self.wallet_password.value}}
            )


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


class _DuplicateKeyError(yaml.YAMLError):
    pass


class _UniqueKeySafeLoader(yaml.SafeLoader):
    """SafeLoader that refuses a mapping key given twice. PyYAML keeps the
    last value silently, so a repeated allowed_schemas, security block,
    connection id or read_only would weaken the policy the file shows before
    pydantic's extra='forbid' could see anything.

    Every mapping of the document is checked before anything is constructed,
    the sources of '<<' merges included: construction flattens merged pairs
    into the merging mapping, where an explicit key overriding a merged one
    is the merge's purpose, not a repeat. A second '<<' in one mapping is a
    repeat (the later merge would silently win); several sources go in one
    merge, '<<: [*a, *b]'."""

    def construct_document(self, node: yaml.Node) -> Any:
        self._refuse_duplicate_keys(node)
        return super().construct_document(node)

    def _refuse_duplicate_keys(self, root: yaml.Node) -> None:
        stack = [root]
        visited: set[int] = set()
        while stack:
            node = stack.pop()
            if id(node) in visited:
                continue  # an alias: its anchored node is checked once
            visited.add(id(node))
            if isinstance(node, yaml.SequenceNode):
                stack.extend(node.value)
                continue
            if not isinstance(node, yaml.MappingNode):
                continue
            first_line: dict[Any, int] = {}
            merge_line: int | None = None
            for key_node, value_node in node.value:
                stack.extend((key_node, value_node))
                line = key_node.start_mark.line + 1
                if key_node.tag == "tag:yaml.org,2002:merge":
                    if merge_line is not None:
                        raise _DuplicateKeyError(
                            f"duplicate merge key '<<' at line {line} (first given at line {merge_line}); the "
                            "later merge would silently override the earlier one. Merge several mappings "
                            "with one key: '<<: [*a, *b]'"
                        )
                    merge_line = line
                    continue
                if not isinstance(key_node, yaml.ScalarNode):
                    continue  # a collection key the base constructor refuses as unhashable
                key = self.construct_object(key_node, deep=True)
                earlier = first_line.get(key)
                if earlier is not None:
                    raise _DuplicateKeyError(
                        f"duplicate key '{key}' at line {line} (first given at line {earlier}); YAML would "
                        "silently keep only the last value"
                    )
                first_line[key] = line


def load_yaml_strict(text: str, source: str = "<string>") -> Any:
    """``yaml.safe_load`` that raises ConfigError on invalid YAML and on a
    mapping key given twice (naming the key and both lines)."""
    try:
        return yaml.load(text, Loader=_UniqueKeySafeLoader)  # noqa: S506 - a SafeLoader subclass
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in '{source}': {describe_yaml_error(exc)}") from None


# A quoted fragment in a PyYAML message: the file's own text (an alias, anchor,
# tag or escape character) unless it is a token name ('<block end>') or one
# of the grammar characters the parser expected. Linear: no nested quantifier.
_YAML_QUOTED = re.compile(r"'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"")
_YAML_TOKEN_NAME = re.compile(r"'<[a-z ]{1,40}>'")
_YAML_GRAMMAR = frozenset({"','", "'}'", "']'", "':'", "'-'", "'\\t'"})
_YAML_MESSAGE_CAP = 200


def _content_free(message: str) -> str:
    """*message* (a PyYAML context or problem) without the file's text: each
    quoted fragment that is not a token name or a grammar character becomes
    '…', and the rest from an unbalanced quote on is cut."""
    message = message[:_YAML_MESSAGE_CAP]
    out: list[str] = []
    end = 0
    for match in [*_YAML_QUOTED.finditer(message), None]:
        between = message[end : match.start() if match else len(message)]
        quote = min((i for i in (between.find("'"), between.find('"')) if i >= 0), default=-1)
        if quote >= 0:
            out.append(between[:quote].rstrip() + " …")
            break
        out.append(between)
        if match is None:
            break
        fragment = match.group(0)
        out.append(fragment if fragment in _YAML_GRAMMAR or _YAML_TOKEN_NAME.fullmatch(fragment) else "…")
        end = match.end()
    return "".join(out)


def describe_yaml_error(exc: BaseException) -> str:
    """Why a YAML document did not parse, by line and column, without its text.

    PyYAML's own message quotes the offending line (about 32 characters on
    each side of the error) and names aliases, anchors and tags from the
    document. Harness configs hold other MCP servers' tokens, and a config may
    inline a secret by mistake, so neither is ever printed: the parser's
    reason, with every quoted fragment of the file replaced, and where it is.
    A repeated mapping key keeps its own message (the key and both lines).
    """
    if isinstance(exc, _DuplicateKeyError):
        return str(exc)
    if isinstance(exc, yaml.MarkedYAMLError):
        reason = "; ".join(_content_free(part) for part in (exc.context, exc.problem) if part) or "malformed"
        mark = exc.problem_mark or exc.context_mark
        return f"{reason} (line {mark.line + 1}, column {mark.column + 1})" if mark is not None else reason
    if isinstance(exc, yaml.reader.ReaderError):
        return f"a character YAML does not accept at character offset {exc.position}"
    if isinstance(exc, yaml.YAMLError):
        return "malformed YAML"
    return f"the YAML parser failed ({type(exc).__name__})"


def describe_decode_error(exc: UnicodeDecodeError) -> str:
    """Where a file is not UTF-8, by line: the codec's own message quotes the
    byte and its offset, and the file may hold a secret."""
    data = exc.object if isinstance(exc.object, bytes | bytearray) else b""
    line = data.count(b"\n", 0, exc.start) + 1
    return f"not valid UTF-8 text (line {line})"


# Where auditing goes when the config file leaves application.audit_path unset:
# omitting the key never switches auditing off. A config in the system
# deployment directory belongs to the service account and audits into the
# directory the packages create for it (the path the shipped template names;
# on Windows the logs subfolder of the machine-wide ProgramData folder, which
# the MSI makes writable for the service account: the folder itself, holding
# the config and secrets, is read-only to it). Any other config is a per-user
# run and audits under ~/.universal-db-mcp, as the seeded per-user config does.
SYSTEM_AUDIT_DIR = Path("/var/log/universal-db-mcp")
WIN32_SYSTEM_AUDIT_SUBDIR = "logs"
AUDIT_FILE_NAME = "audit.jsonl"


def is_system_config(config_path: str | Path) -> bool:
    """True when *config_path* lies in the system deployment directory, i.e.
    it is the service account's config rather than a per-user one. Either
    place counts: the directory the name is given in (the service is started
    with the system path, which may be a symlink to a file kept elsewhere)
    and the directory the file really is in (a link to the system config
    runs the service's config). Directories are compared resolved (/etc is
    /private/etc on macOS) and case-folded on macOS and Windows, where
    realpath keeps whatever case the name is given in."""
    from universal_db_mcp.agents import core as agents_core

    system_dir = _fold_case(os.path.realpath(agents_core.system_config_dir()))
    given = os.path.abspath(config_path)
    return any(
        Path(_fold_case(directory)).is_relative_to(system_dir)
        for directory in (os.path.realpath(os.path.dirname(given)), os.path.dirname(os.path.realpath(given)))
    )


def default_audit_path(config_path: str | Path) -> tuple[Path, str]:
    """(path, description) of the audit log for a config file that sets no
    ``application.audit_path``."""
    from universal_db_mcp.agents import core as agents_core

    if is_system_config(config_path):
        if sys.platform == "win32":
            service_dir = agents_core.system_config_dir() / WIN32_SYSTEM_AUDIT_SUBDIR
        else:
            service_dir = SYSTEM_AUDIT_DIR
        return service_dir / AUDIT_FILE_NAME, f"service state directory {service_dir}"

    def underivable(why: object) -> ConfigError:
        return ConfigError(
            f"application.audit_path is not set and the per-user default cannot be derived ({why}); "
            "set application.audit_path"
        )

    try:
        home = Path.home()
    except RuntimeError as exc:
        raise underivable(exc) from exc
    # HOME='' reads as '/', and a relative HOME would follow the working
    # directory of whichever client spawned the server
    if not home.is_absolute() or home == Path(home.anchor):
        what = "the filesystem root" if home.is_absolute() else "relative"
        raise underivable(f"the home directory '{home}' is {what}")
    user_dir = home / agents_core.PER_USER_CONFIG_DIR
    return user_dir / AUDIT_FILE_NAME, f"per-user state directory {user_dir}"


def _apply_audit_path_default(raw: dict[str, object], config_path: Path) -> str | None:
    """Fill in an unset (or empty) application.audit_path; returns which
    default was chosen, or None when the file sets one."""
    if "application" not in raw:
        raw["application"] = {}
    app = raw["application"]
    if not isinstance(app, dict) or app.get("audit_path"):
        return None
    path, where = default_audit_path(config_path)
    app["audit_path"] = str(path)
    return where


# Path-valued keys that are relative to the config file's directory when not
# absolute: secrets, TLS material and server state. (A SQLite data source and
# the engine options that name directories are passed on as written.)
_APPLICATION_PATH_KEYS = ("audit_path", "metadata_cache_path", "http_bearer_token_file")
_CONNECTION_PATH_KEYS = ("username_file", "password_file")
_TLS_PATH_KEYS = ("ca_file", "client_cert_file", "client_key_file")
_OPTION_PATH_KEYS = ("wallet_password_file", "passfile")


def _resolve_relative_paths(raw: dict[str, object], base: Path) -> None:
    def resolve(section: object, keys: tuple[str, ...]) -> None:
        if isinstance(section, dict):
            for key in keys:
                value = section.get(key)
                if isinstance(value, str) and value and not os.path.isabs(value):
                    section[key] = str(base / value)

    resolve(raw.get("application"), _APPLICATION_PATH_KEYS)
    connections = raw.get("connections")
    if isinstance(connections, dict):
        for conn in connections.values():
            resolve(conn, _CONNECTION_PATH_KEYS)
            if isinstance(conn, dict):
                resolve(conn.get("tls"), _TLS_PATH_KEYS)
                resolve(conn.get("options"), _OPTION_PATH_KEYS)


def load_config(path: str | Path) -> AppConfig:
    p = Path(path)
    try:
        raw_text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read config file '{p}': {exc}") from exc
    except UnicodeDecodeError:
        # the codec's message would quote a byte of the file
        raise ConfigError(f"config file '{p}' is not valid UTF-8 text") from None
    raw = load_yaml_strict(raw_text, str(p))
    if not isinstance(raw, dict):
        raise ConfigError(f"config '{p}' must be a mapping at the top level")
    # relative paths follow the file, not the directory the server started in
    _resolve_relative_paths(raw, Path(os.path.abspath(p)).parent)
    raw = _apply_http_token_env_override(raw)
    audit_default = _apply_audit_path_default(raw, p)
    try:
        cfg = AppConfig.model_validate(raw, context={"audit_path_default": audit_default})
    except ValidationError as exc:
        raise ConfigError(f"invalid configuration in '{p}': {_format_validation_errors(exc)}") from exc
    except Exception as exc:
        raise ConfigError(f"invalid configuration in '{p}': {exc}") from exc
    cfg.application._audit_path_default = audit_default
    return cfg


def load_resolved(path: str | Path) -> tuple[AppConfig, dict[str, ResolvedConnection]]:
    """Load config and resolve all secrets. Raises ConfigError on any missing
    or unsafe secret reference (fail fast, name the artifact)."""
    cfg = load_config(path)
    resolved: dict[str, ResolvedConnection] = {}
    for name, conn in cfg.connections.items():
        resolved[name] = ResolvedConnection(name, conn)
    return cfg, resolved
