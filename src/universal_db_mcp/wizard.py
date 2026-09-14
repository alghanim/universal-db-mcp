"""Interactive ``add-connection`` wizard: add a database connection to a
config file, step by step, without hand-editing YAML.

Invariants (never broken):

* Secrets are REFERENCED, never inlined: the username and password are
  written as 0600 files under ``<config dir>/secrets/`` (dir 0700) and the
  config carries only ``username_file`` / ``password_file`` pointers.
* The edited config is never clobbered wholesale: a timestamped ``.bak``
  precedes every write, the leading comment header is preserved, and a
  malformed (unparseable) config is refused - never rewritten.
* The merged result is schema-validated (``load_config``) before the wizard
  reports success; unknown fields or bad values fail closed.
* The optional live test uses the SAME connector + policy machinery as the
  server (``build_connector`` + ``EffectivePolicy.build``), then closes the
  connector.
"""

from __future__ import annotations

import getpass
import os
import shutil
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from universal_db_mcp.config import AppConfig, ConnectionConfig, ResolvedConnection, load_config
from universal_db_mcp.connectors.registry import build_connector
from universal_db_mcp.errors import ConfigError
from universal_db_mcp.security.policy import EffectivePolicy

ENGINES = ["sqlite", "postgres", "mysql", "clickhouse", "oracle", "mssql", "db2"]
DEFAULT_PORTS: dict[str, int] = {
    "postgres": 5432,
    "mysql": 3306,
    "clickhouse": 8123,
    "oracle": 1521,
    "mssql": 1433,
    "db2": 50000,
}

MINIMAL_CONFIG = """\
# universal-db-mcp configuration (created by the add-connection wizard).
# Add connections with: udbmcp add-connection
application:
  transport: stdio
"""


class WizardError(Exception):
    """Fail-closed wizard error: the config is left untouched."""


def _stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%S%f") + "Z"


def validate_connection_name(name: str) -> str:
    if (
        not name
        or len(name) > 64
        or name[0].isdigit()
        or os.sep in name
        or (os.altsep and os.altsep in name)
        or not name.replace("-", "").replace("_", "").isalnum()
    ):
        raise WizardError(
            f"invalid connection name {name!r}: use 1-64 letters, digits, '-' or '_' "
            "(not starting with a digit, no path separators)"
        )
    return name


def secrets_dir_for(config_path: Path) -> Path:
    return config_path.parent / "secrets"


def _write_secret(path: Path, content: str) -> None:
    """Create-or-truncate a 0600 secret file WITHOUT a wider-permission window:
    the file is born with its final mode (no write-then-chmod race) and
    O_NOFOLLOW refuses a pre-planted symlink at that path."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, (content + "\n").encode("utf-8"))
    finally:
        os.close(fd)


def store_credentials(
    config_path: Path, name: str, username: str, password: str | None
) -> tuple[Path, Path | None]:
    """Write this connection's username (and password, when provided) as 0600
    files under ``<config dir>/secrets/`` (enforced 0700). Re-running the
    wizard for the same connection replaces ITS pair; no other file in the
    secrets dir is read or touched. The name is validated HERE (before any
    filesystem effect - it derives two paths), an empty username is refused,
    and an omitted/empty password simply produces no password file."""
    validate_connection_name(name)
    if not username.strip():
        raise WizardError("username must not be empty")
    sdir = secrets_dir_for(config_path)
    sdir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(sdir, 0o700)  # a pre-existing weak dir is tightened, never trusted
    username_file = sdir / f"{name}.username"
    _write_secret(username_file, username)
    password_file = None
    if password:
        password_file = sdir / f"{name}.password"
        _write_secret(password_file, password)
    return username_file, password_file


def build_connection(  # noqa: PLR0913 - explicit wizard answer fields
    *,
    name: str,
    engine: str,
    database: str,
    host: str | None = None,
    port: int | None = None,
    username_file: str | None = None,
    password_file: str | None = None,
    read_only: bool = True,
) -> ConnectionConfig:
    """Construct (and schema-validate) a ConnectionConfig from wizard answers."""
    validate_connection_name(name)
    kwargs: dict[str, Any] = {
        "type": engine,
        "database": database,
        "read_only": read_only,
    }
    if engine != "sqlite":
        kwargs["host"] = host
        if port is not None:
            kwargs["port"] = port
    if username_file:
        kwargs["username_file"] = username_file
    if password_file:
        kwargs["password_file"] = password_file
    return ConnectionConfig(**kwargs)


def _split_header(raw: str) -> tuple[list[str], list[str], bool]:
    """Split leading comment/blank lines from the YAML body. Returns
    (header_lines, body_lines, body_has_comments): comments AFTER the first
    non-comment line cannot survive the safe_dump rewrite - the caller must
    disclose that honestly."""
    lines = raw.splitlines(keepends=True)
    header: list[str] = []
    body_start = 0
    for i, line in enumerate(lines):
        if line.strip().startswith("#") or not line.strip():
            header.append(line)
            body_start = i + 1
        else:
            break
    body = lines[body_start:]
    body_has_comments = any(line.strip().startswith("#") for line in body)
    return header, body, body_has_comments


def merge_connection(config_path: Path, name: str, connection: ConnectionConfig) -> Path:
    """Add or replace one connection in the config file.

    Preserves the leading comment header, keeps every other key untouched,
    writes a timestamped ``.bak`` first, PRESERVES the file's existing mode
    (a 0640 service-owned config must not silently lose its group-read bit),
    and refuses (leaving the file untouched) when the config is missing,
    unreadable, or malformed. Returns the backup path.
    """
    if not config_path.is_file():
        raise WizardError(f"config file not found: {config_path}")
    original_mode = stat.S_IMODE(config_path.stat().st_mode)
    header, body, _has_comments = _split_header(config_path.read_text(encoding="utf-8"))
    try:
        data = yaml.safe_load("".join(body))
    except yaml.YAMLError as exc:
        raise WizardError(f"config is not valid YAML; refusing to edit ({exc})") from exc
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise WizardError("config top level must be a mapping; refusing to edit")
    connections = data.get("connections")
    if connections is None:
        connections = {}
        data["connections"] = connections
    if not isinstance(connections, dict):
        raise WizardError("'connections' is not a mapping; refusing to edit")

    connections[name] = connection.model_dump(mode="json", exclude_none=True)

    backup = config_path.with_name(config_path.name + ".bak." + _stamp())
    shutil.copy2(config_path, backup)
    config_path.write_text("".join(header) + yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    os.chmod(config_path, original_mode)

    # Schema-validate the MERGED result before claiming success: a wizard bug
    # must not leave a config the server would refuse.
    try:
        load_config(config_path)
    except ConfigError as exc:
        shutil.copy2(backup, config_path)
        raise WizardError(f"merged config failed schema validation (restored backup): {exc}") from exc
    return backup


def ensure_config_exists(config_path: Path) -> bool:
    """Create a minimal valid config when absent. Returns True when created."""
    if config_path.is_file():
        return False
    config_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    config_path.write_text(MINIMAL_CONFIG, encoding="utf-8")
    os.chmod(config_path, 0o600)
    return True


def test_connection(cfg: AppConfig, name: str) -> dict[str, Any]:
    """Live health check using the same machinery as the server's
    db_test_connection tool (connector + effective policy)."""
    resolved = ResolvedConnection(name, cfg.connections[name])
    policy = EffectivePolicy.build(cfg.security, resolved)
    connector = build_connector(resolved, policy)
    try:
        health = connector.health_check()
    finally:
        close = getattr(connector, "close", None)
        if callable(close):
            close()
    out: dict[str, Any] = {
        "healthy": health.healthy,
        "server_version": health.server_version,
        "latency_ms": health.latency_ms,
    }
    if health.detail:
        out["detail"] = health.detail
    return out


def _ask(prompt: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default is not None else ""
    answer = input(f"{prompt}{suffix}: ").strip()
    return answer or (default or "")


def _ask_bool(prompt: str, default: bool = True) -> bool:
    suffix = "Y/n" if default else "y/N"
    answer = input(f"{prompt} [{suffix}]: ").strip().lower()
    if not answer:
        return default
    return answer in ("y", "yes")


def collect_answers_interactive(cfg_path: Path) -> tuple[str, ConnectionConfig, bool]:
    """Prompt for every wizard answer on the terminal. The password is read
    via getpass (never echoed, never written to the transcript)."""
    print(f"Adding a database connection to: {cfg_path}")
    print("Engines:", ", ".join(f"{i + 1}) {e}" for i, e in enumerate(ENGINES)))
    while True:
        choice = _ask("Engine", "1")
        if choice.isdigit() and 1 <= int(choice) <= len(ENGINES):
            engine = ENGINES[int(choice) - 1]
            break
        if choice in ENGINES:
            engine = choice
            break
        print("  pick a number from the list (or type an engine name)")

    name = ""
    while True:
        name = _ask("Connection name")
        try:
            validate_connection_name(name)
            break
        except WizardError as exc:
            print(f"  {exc}")

    host: str | None = None
    port: int | None = None
    if engine == "sqlite":
        database = _ask("Database file (absolute path)")
    else:
        host = _ask("Host", "127.0.0.1")
        default_port = str(DEFAULT_PORTS[engine])
        while True:
            port_raw = _ask("Port", default_port)
            if port_raw.isdigit() and 1 <= int(port_raw) <= 65535:
                port = int(port_raw)
                break
            if port_raw == default_port:
                port = DEFAULT_PORTS[engine]
                break
            print("  port must be a number between 1 and 65535")
        database = _ask("Database")

    username_file = password_file = None
    if engine != "sqlite":
        while True:
            username = _ask("Username")
            if username.strip():
                break
            print("  username must not be empty")
        password = getpass.getpass("Password (input hidden): ")
        # An empty password simply produces no password file (some databases
        # allow passwordless accounts); a HALF-filled pair is never written.
        username_file, password_file = store_credentials(cfg_path, name, username, password or None)

    read_only = _ask_bool("Read-only connection?", True)

    connection = build_connection(
        name=name,
        engine=engine,
        database=database,
        host=host,
        port=port,
        username_file=str(username_file) if username_file else None,
        password_file=str(password_file) if password_file else None,
        read_only=read_only,
    )
    run_test = _ask_bool("Test the connection now?", True)
    return name, connection, run_test


def apply_connection(
    cfg_path: Path, name: str, connection: ConnectionConfig, *, run_test: bool
) -> dict[str, Any]:
    """Merge + validate + optionally live-test. Returns a result dict used by
    both the human and --json outputs."""
    existing = Path(cfg_path)
    replaced = False
    comments_dropped = False
    if existing.is_file():
        try:
            data = yaml.safe_load(existing.read_text(encoding="utf-8"))
            if isinstance(data, dict) and isinstance(data.get("connections"), dict):
                replaced = name in data["connections"]
            _, _, comments_dropped = _split_header(existing.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            pass  # merge_connection will refuse with its own diagnostic

    backup = merge_connection(existing, name, connection)
    cfg = load_config(existing)  # schema-valid (merge already verified)

    result: dict[str, Any] = {
        "config": str(existing),
        "connection": name,
        "engine": connection.type,
        "replaced": replaced,
        "kept": True,
        "comments_dropped": comments_dropped,
        "backup": str(backup),
        "tested": False,
    }
    if run_test:
        try:
            result["test"] = test_connection(cfg, name)
            result["tested"] = True
        except Exception as exc:
            # A failed live test does NOT roll back the add: the database may
            # simply be down. Report honestly; doctor validates the rest.
            result["test"] = {"healthy": False, "error": f"{type(exc).__name__}: {exc}"}
            result["tested"] = True
    return result
