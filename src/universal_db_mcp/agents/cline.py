"""Cline (VS Code extension ``saoudrizwan.claude-dev``) MCP-registration adapter.

Used by ``universal_db_mcp configure-agents`` to detect a local Cline
installation and, only after explicit confirmation at the CLI layer, register
the universal-db MCP server into Cline's MCP settings file:

    ~/Library/Application Support/Code/User/globalStorage/\\
        saoudrizwan.claude-dev/settings/cline_mcp_settings.json   (macOS)

(plus the platform-appropriate VS Code ``globalStorage`` location on
Linux/Windows: under ``$XDG_CONFIG_HOME`` or ``~/.config``, and under
``%APPDATA%``). Detection is defined as that settings path existing.

Written registration shape (no secrets — launch command, ``UDBMCP_CONFIG``
path and nothing else)::

    {
      "mcpServers": {
        "universal-db": {
          "command": "<venv python>",
          "args": ["-I", "-m", "universal_db_mcp", "serve", "--transport", "stdio"],
          "env": {"UDBMCP_CONFIG": "<config path>"},
          "disabled": false,
          "autoApprove": []
        }
      }
    }

``disabled: false`` and ``autoApprove: []`` are Cline's fields, written in
their safe defaults: the server is enabled and auto-approves nothing.

Fail-closed rules implemented here:

* A settings file that is unreadable, malformed, not a JSON object, or whose
  ``mcpServers`` is not an object yields
  ``AgentStatus.UNKNOWN_STATE_FAIL_CLOSED`` — the intended config block is
  printed and nothing is ever written.
* An existing ``universal-db`` entry whose contents differ from what this
  adapter would write is operator-managed state; it is reported fail-closed,
  never silently rewritten. The one exception is this tool's own pre-``-I``
  registration (identical except for the launch args), which is upgraded
  like a fresh write.
* A settings file the write would replace but may not (read-only, another
  user's, hard-linked, with an access control list the replace would change,
  in a read-only directory, or as root behind a user's symlink:
  ``core.ensure_replaceable``) fails closed at detection.
* ``apply`` writes only when ``confirmed=True`` (the CLI layer owns the
  interactive y/n prompt, ``--yes`` and ``--dry-run``). Every first write is
  preceded by a timestamped, private ``.bak`` copy of the settings file and
  replaces the file atomically (a failed write leaves it as it was); re-runs
  are idempotent and never duplicate an existing equivalent registration.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .core import (
    SERVER_ARGS,
    AgentStatus,
    Plan,
    absolute_interpreter,
    app_data_base,
    atomic_write_text,
    backup_path,
    ensure_replaceable,
    fail_closed_block,
    holds_legacy_entry,
    is_legacy_entry,
    load_json_or_fail_closed,
    load_problem_note,
    other_unisolated_note,
    require_isolated_import,
    resolve_harness_config_path,
    unisolated_entry_note,
    unreplaceable_reason,
    write_private_backup,
)

AGENT_NAME = "cline"
SERVER_KEY = "universal-db"
MCP_SERVERS_KEY = "mcpServers"

EXTENSION_ID = "saoudrizwan.claude-dev"
SETTINGS_FILENAME = "cline_mcp_settings.json"

# Cline stores its MCP settings inside the per-user VS Code globalStorage
# directory of the extension, under the platform's application-config root
# (core.app_data_base). An unknown platform is fail-closed (we refuse to
# guess where the settings live).
_SUPPORTED_PLATFORMS = frozenset({"darwin", "linux", "win32"})
_STORAGE_SUBDIR = ("Code", "User", "globalStorage")

VENV_PYTHON_ENV = "UDBMCP_VENV_PYTHON"
UDBMCP_CONFIG_ENV = "UDBMCP_CONFIG"

# Canonical air-gapped deployment location (see docs/offline-deployment.md).
SYSTEM_CONFIG_PATH = Path("/etc/universal-db-mcp/config.yaml")

# Hard allowlists: the persisted registration may contain nothing else.
_ALLOWED_ENTRY_KEYS = frozenset({"command", "args", "env", "disabled", "autoApprove"})
_ALLOWED_ENTRY_ENV_KEYS = frozenset({UDBMCP_CONFIG_ENV})


def settings_path(home: Path, env: Mapping[str, str] | None = None) -> Path:
    """Absolute path of Cline's ``cline_mcp_settings.json`` for ``home``.

    ``env`` supplies ``APPDATA`` / ``XDG_CONFIG_HOME``; without it the
    HOME-relative defaults are used.
    """
    if sys.platform not in _SUPPORTED_PLATFORMS:
        raise RuntimeError(
            f"cline adapter: unsupported platform {sys.platform!r}; refusing to guess the settings location"
        )
    root = app_data_base(env or {}, home, sys.platform)
    return root.joinpath(*_STORAGE_SUBDIR, EXTENSION_ID, "settings", SETTINGS_FILENAME)


def _venv_python(env: Mapping[str, str]) -> str:
    """Interpreter written into the launch command.

    Prefers an explicit ``UDBMCP_VENV_PYTHON`` override (made absolute: a
    path is anchored at the working directory, a bare name looked up on PATH;
    one naming no file is refused); otherwise uses the interpreter running
    this CLI, which is the venv python whenever the package was installed into
    a virtual environment (refused when it cannot import the package under
    ``-I``, as with a user-site install).
    """
    override = env.get(VENV_PYTHON_ENV, "").strip()
    if override:
        return absolute_interpreter(override, VENV_PYTHON_ENV, env)
    require_isolated_import(sys.executable)
    return sys.executable


def _udbmcp_config_path(env: Mapping[str, str], home: Path) -> str:
    """Config path advertised to the launched server via ``UDBMCP_CONFIG``.

    Delegates to the shared resolver (agents.core): harness spawns run as the
    logged-in USER, so the advertised path must be readable by them - the
    system deployment is service-account owned (0640 root:_udbmcp) and is
    not. Unreadable-system spawns died right after connecting (seen live
    2026-09-14); the resolver falls back to the per-user config, which
    ``configure-agents`` seeds on apply.
    """
    return resolve_harness_config_path(env, home, strict=True, for_harness=True)


def registration_entry(env: Mapping[str, str], home: Path) -> dict[str, Any]:
    """The exact dict written under ``mcpServers`` (contains no secrets)."""
    entry: dict[str, Any] = {
        "command": _venv_python(env),
        "args": list(SERVER_ARGS),
        "env": {UDBMCP_CONFIG_ENV: _udbmcp_config_path(env, home)},
        "disabled": False,
        "autoApprove": [],
    }
    _assert_no_secrets(entry)
    return entry


def _assert_no_secrets(entry: Mapping[str, Any]) -> None:
    """Hard guarantee: the registration carries no secret material."""
    unexpected = set(entry) - _ALLOWED_ENTRY_KEYS
    if unexpected:
        raise RuntimeError(f"cline adapter: refusing to write unexpected registration keys: {sorted(unexpected)}")
    env_keys = set(entry.get("env", {}))
    if env_keys - _ALLOWED_ENTRY_ENV_KEYS:
        raise RuntimeError(f"cline adapter: refusing to write non-allowlisted env keys: {sorted(env_keys)}")


def _entries_equal(existing: Any, desired: Mapping[str, Any]) -> bool:
    return isinstance(existing, dict) and existing == dict(desired)


def detect(env: Mapping[str, str], home: Path) -> AgentStatus:
    """Classify the Cline harness state without writing anything.

    - ``not_installed``: the ``cline_mcp_settings.json`` path does not exist
      (detection for this adapter is defined as that path existing).
    - ``configured``: the file parses and already holds an equivalent
      ``universal-db`` entry.
    - ``installed_unconfigured``: the file parses and lacks our entry (it may
      hold other servers; those are preserved on apply), or holds the
      pre-``-I`` registration (upgraded on apply).
    - ``unknown_state_fail_closed``: the file is unreadable/malformed/not a
      JSON object, ``mcpServers`` is not an object, or our key holds a
      differing entry, or it would be written but may not be replaced
      (read-only, another user's, hard-linked).
    """
    status = _config_status(env, home)
    if status is AgentStatus.INSTALLED_UNCONFIGURED and unreplaceable_reason(settings_path(home, env)) is not None:
        return AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    return status


def _config_status(env: Mapping[str, str], home: Path) -> AgentStatus:
    """:func:`detect` from the settings file's content alone (no replace check)."""
    target = settings_path(home, env)
    if not target.is_file():
        return AgentStatus.NOT_INSTALLED

    # Resolved up front: an override that cannot be registered (a relative
    # path naming no file) is refused at detection, before any write is offered.
    entry = registration_entry(env, home)
    data, _error = load_json_or_fail_closed(target)
    if data is None:
        return AgentStatus.UNKNOWN_STATE_FAIL_CLOSED

    servers = data.get(MCP_SERVERS_KEY)
    if servers is None:
        return AgentStatus.INSTALLED_UNCONFIGURED
    if not isinstance(servers, dict):
        return AgentStatus.UNKNOWN_STATE_FAIL_CLOSED

    if SERVER_KEY in servers and is_legacy_entry(servers[SERVER_KEY], entry):
        return AgentStatus.INSTALLED_UNCONFIGURED
    if SERVER_KEY in servers and not _entries_equal(servers[SERVER_KEY], entry):
        # A differently-shaped registration under our server key: operator
        # state we must not silently rewrite.
        return AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    if SERVER_KEY in servers:
        return AgentStatus.CONFIGURED
    return AgentStatus.INSTALLED_UNCONFIGURED


def _fail_closed_block(target: Path, entry: Mapping[str, Any]) -> str:
    """What a fail-closed plan prints: the registration and this tool's own
    entry in ``target``, never its other servers (``core.fail_closed_block``)."""
    return fail_closed_block(target, MCP_SERVERS_KEY, SERVER_KEY, entry)


def _write_failed(step: str, target: Path, entry: dict[str, Any], exc: OSError, backup: Path | None) -> Plan:
    """Fail-closed result for a backup or write (``step``) that raised
    (target unchanged)."""
    note = f"; backup: {backup}" if backup is not None else ""
    return Plan(
        agent=AGENT_NAME,
        config_path=target,
        status=AgentStatus.UNKNOWN_STATE_FAIL_CLOSED,
        backup_paths=(backup,) if backup is not None else (),
        summary=f"{AGENT_NAME}: {step} failed ({exc}); {target} was left as it was{note}",
        config_block=_fail_closed_block(target, entry),
        entry=entry,
    )


def plan(env: Mapping[str, str], home: Path) -> Plan:
    """Describe exactly what would be added to Cline's settings; never writes."""
    target = settings_path(home, env)
    status = detect(env, home)
    if status is AgentStatus.NOT_INSTALLED:
        # Nothing would be registered, so nothing is resolved: an override
        # that cannot be registered must not turn "not installed" into an error.
        return Plan(
            agent=AGENT_NAME,
            config_path=target,
            status=status,
            summary=f"{AGENT_NAME}: not installed ({target} does not exist); nothing would be written",
        )
    entry = registration_entry(env, home)
    block = json.dumps({MCP_SERVERS_KEY: {SERVER_KEY: entry}}, indent=2)

    if status is AgentStatus.CONFIGURED:
        summary = (
            f"{AGENT_NAME}: already configured in {target} under "
            f'"{MCP_SERVERS_KEY}"["{SERVER_KEY}"]; no changes needed'
        )
        block = ""
    elif status is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED:
        refused = unreplaceable_reason(target)
        if refused is not None and _config_status(env, home) is AgentStatus.INSTALLED_UNCONFIGURED:
            summary = f"{AGENT_NAME}: refusing to write: {refused}"
        else:
            summary = (
                f"{AGENT_NAME}: {target} is unreadable, malformed, or holds a differing "
                f'"{SERVER_KEY}" entry{load_problem_note(target)}; refusing to write (fix or inspect the file, '
                "then re-run)"
            ) + unisolated_entry_note(target, MCP_SERVERS_KEY, SERVER_KEY)
        block = _fail_closed_block(target, entry)
    elif holds_legacy_entry(target, MCP_SERVERS_KEY, SERVER_KEY, entry):
        summary = (
            f"{AGENT_NAME}: would back up {target} to a timestamped .bak, then replace this tool's "
            f'earlier "{SERVER_KEY}" registration with one that starts the server in isolated mode (-I) '
            "(other entries preserved)"
        )
    else:
        summary = (
            f'{AGENT_NAME}: would back up {target} to a timestamped .bak, then add '
            f'"{SERVER_KEY}" under "{MCP_SERVERS_KEY}" (other entries preserved)'
        )

    return Plan(
        agent=AGENT_NAME,
        config_path=target,
        status=status,
        summary=summary + other_unisolated_note(target, MCP_SERVERS_KEY, SERVER_KEY),
        config_block=block,
        entry=entry,
    )


def apply(env: Mapping[str, str], home: Path, confirmed: bool) -> Plan:
    """Write the registration after explicit confirmation.

    Refuses to write when ``confirmed`` is False (the CLI layer owns the
    interactive y/n prompt and the ``--yes`` flag). Creates a timestamped
    ``.bak`` of the settings file before the first write, never duplicates an
    existing equivalent registration, and never touches a malformed config
    (fail closed).
    """
    target = settings_path(home, env)
    status = detect(env, home)

    if status is not AgentStatus.INSTALLED_UNCONFIGURED:
        # not_installed / configured / fail-closed: nothing safe to write.
        return plan(env, home)

    if not confirmed:
        planned = plan(env, home)
        return Plan(
            agent=planned.agent,
            config_path=planned.config_path,
            status=planned.status,
            summary=planned.summary + " (not applied: confirmation refused)",
            config_block=planned.config_block,
            entry=planned.entry,
        )

    data, error = load_json_or_fail_closed(target)
    servers = data.get(MCP_SERVERS_KEY) if data is not None else None
    # Re-check at write time, with the same classification detect() uses: a
    # missing (or JSON-null) mcpServers is "absent" and will be created below,
    # while a non-object value fails closed rather than being overwritten.
    if data is None or (servers is not None and not isinstance(servers, dict)):
        return plan(env, home)

    entry = registration_entry(env, home)
    if not isinstance(servers, dict):
        servers = {}
        data[MCP_SERVERS_KEY] = servers
    if SERVER_KEY in servers and not is_legacy_entry(servers[SERVER_KEY], entry):
        # Concurrent modification between detect() and this re-read: an equal
        # entry is an idempotent no-op; a differing entry is operator state
        # this adapter must never silently overwrite (plan() re-detects and
        # reports it fail-closed).
        return plan(env, home)

    try:
        ensure_replaceable(target)  # refused before the backup, so none is left behind
    except OSError as exc:
        return _write_failed(f"writing {target}", target, entry, exc, None)
    backup = backup_path(target)
    try:
        write_private_backup(target, backup)
    except OSError as exc:
        return _write_failed(f"backing up {target} to {backup}", target, entry, exc, None)
    servers[SERVER_KEY] = entry
    payload = json.dumps(data, indent=2) + "\n"
    try:
        atomic_write_text(target, payload)
    except OSError as exc:
        return _write_failed(f"writing {target}", target, entry, exc, backup)

    return Plan(
        agent=AGENT_NAME,
        config_path=target,
        status=AgentStatus.CONFIGURED,
        backup_paths=(backup,),
        summary=f'{AGENT_NAME}: added "{SERVER_KEY}" to {target} (backup: {backup})'
        + other_unisolated_note(target, MCP_SERVERS_KEY, SERVER_KEY),
        config_block=json.dumps({MCP_SERVERS_KEY: {SERVER_KEY: entry}}, indent=2),
        entry=entry,
    )
