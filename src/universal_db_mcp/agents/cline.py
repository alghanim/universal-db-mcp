"""Cline (VS Code extension ``saoudrizwan.claude-dev``) MCP-registration adapter.

Used by ``universal_db_mcp configure-agents`` to detect a local Cline
installation and, only after explicit confirmation at the CLI layer, register
the universal-db MCP server into Cline's MCP settings file:

    ~/Library/Application Support/Code/User/globalStorage/\\
        saoudrizwan.claude-dev/settings/cline_mcp_settings.json   (macOS)

(plus the platform-appropriate VS Code ``globalStorage`` location on
Linux/Windows). Detection is defined as that settings path existing.

Written registration shape (no secrets — launch command, ``UDBMCP_CONFIG``
path and nothing else)::

    {
      "mcpServers": {
        "universal-db": {
          "command": "<venv python>",
          "args": ["-m", "universal_db_mcp", "serve", "--transport", "stdio"],
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
  never silently rewritten.
* ``apply`` writes only when ``confirmed=True`` (the CLI layer owns the
  interactive y/n prompt, ``--yes`` and ``--dry-run``). Every first write is
  preceded by a timestamped ``.bak`` copy of the settings file; re-runs are
  idempotent and never duplicate an existing equivalent registration.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .core import (
    AgentStatus,
    Plan,
    backup_path,
    load_json_or_fail_closed,
    resolve_harness_config_path,
)

AGENT_NAME = "cline"
SERVER_KEY = "universal-db"
MCP_SERVERS_KEY = "mcpServers"

EXTENSION_ID = "saoudrizwan.claude-dev"
SETTINGS_FILENAME = "cline_mcp_settings.json"

# Cline stores its MCP settings inside the per-user VS Code globalStorage
# directory of the extension. Keyed by sys.platform; an unknown platform is
# fail-closed (we refuse to guess where the settings live).
_STORAGE_ROOT = {
    "darwin": ("Library", "Application Support", "Code", "User", "globalStorage"),
    "linux": (".config", "Code", "User", "globalStorage"),
    "win32": ("AppData", "Roaming", "Code", "User", "globalStorage"),
}

VENV_PYTHON_ENV = "UDBMCP_VENV_PYTHON"
UDBMCP_CONFIG_ENV = "UDBMCP_CONFIG"

# Canonical air-gapped deployment location (see docs/offline-deployment.md).
SYSTEM_CONFIG_PATH = Path("/etc/universal-db-mcp/config.yaml")

# Hard allowlists: the persisted registration may contain nothing else.
_ALLOWED_ENTRY_KEYS = frozenset({"command", "args", "env", "disabled", "autoApprove"})
_ALLOWED_ENTRY_ENV_KEYS = frozenset({UDBMCP_CONFIG_ENV})


def settings_path(home: Path) -> Path:
    """Absolute path of Cline's ``cline_mcp_settings.json`` for ``home``."""
    root = _STORAGE_ROOT.get(sys.platform)
    if root is None:
        raise RuntimeError(
            f"cline adapter: unsupported platform {sys.platform!r}; refusing to guess the settings location"
        )
    return home.joinpath(*root, EXTENSION_ID, "settings", SETTINGS_FILENAME)


def _venv_python(env: Mapping[str, str]) -> str:
    """Interpreter written into the launch command.

    Prefers an explicit ``UDBMCP_VENV_PYTHON`` override; otherwise uses the
    interpreter running this CLI, which is the venv python whenever the
    package was installed into a virtual environment.
    """
    override = env.get(VENV_PYTHON_ENV, "").strip()
    if override:
        return override
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
    return resolve_harness_config_path(env, home)


def registration_entry(env: Mapping[str, str], home: Path) -> dict[str, Any]:
    """The exact dict written under ``mcpServers`` (contains no secrets)."""
    entry: dict[str, Any] = {
        "command": _venv_python(env),
        "args": ["-m", "universal_db_mcp", "serve", "--transport", "stdio"],
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
      hold other servers; those are preserved on apply).
    - ``unknown_state_fail_closed``: the file is unreadable/malformed/not a
      JSON object, ``mcpServers`` is not an object, or our key holds a
      differing entry.
    """
    target = settings_path(home)
    if not target.is_file():
        return AgentStatus.NOT_INSTALLED

    data, _error = load_json_or_fail_closed(target)
    if data is None:
        return AgentStatus.UNKNOWN_STATE_FAIL_CLOSED

    servers = data.get(MCP_SERVERS_KEY)
    if servers is None:
        return AgentStatus.INSTALLED_UNCONFIGURED
    if not isinstance(servers, dict):
        return AgentStatus.UNKNOWN_STATE_FAIL_CLOSED

    if SERVER_KEY in servers and not _entries_equal(servers[SERVER_KEY], registration_entry(env, home)):
        # A differently-shaped registration under our server key: operator
        # state we must not silently rewrite.
        return AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    if SERVER_KEY in servers:
        return AgentStatus.CONFIGURED
    return AgentStatus.INSTALLED_UNCONFIGURED


def _fail_closed_block(target: Path, intended_block: str) -> str:
    """Render the intended registration plus the offending file's bytes."""
    header = f"# intended registration for {target}:\n{intended_block}\n"
    try:
        raw = target.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return f"{header}\n# {target} could not be read: {exc}"
    return f"{header}\n# current contents of {target}:\n{raw}"


def plan(env: Mapping[str, str], home: Path) -> Plan:
    """Describe exactly what would be added to Cline's settings; never writes."""
    target = settings_path(home)
    status = detect(env, home)
    entry = registration_entry(env, home)
    block = json.dumps({MCP_SERVERS_KEY: {SERVER_KEY: entry}}, indent=2)

    if status is AgentStatus.NOT_INSTALLED:
        summary = f"{AGENT_NAME}: not installed ({target} does not exist); nothing would be written"
        block = ""
    elif status is AgentStatus.CONFIGURED:
        summary = (
            f"{AGENT_NAME}: already configured in {target} under "
            f'"{MCP_SERVERS_KEY}"["{SERVER_KEY}"]; no changes needed'
        )
        block = ""
    elif status is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED:
        summary = (
            f"{AGENT_NAME}: {target} is unreadable, malformed, or holds a differing "
            f'"{SERVER_KEY}" entry; refusing to write (fix or inspect the file, then re-run)'
        )
        block = _fail_closed_block(target, block)
    else:
        summary = (
            f'{AGENT_NAME}: would back up {target} to a timestamped .bak, then add '
            f'"{SERVER_KEY}" under "{MCP_SERVERS_KEY}" (other entries preserved)'
        )

    return Plan(
        agent=AGENT_NAME,
        config_path=target,
        status=status,
        summary=summary,
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
    target = settings_path(home)
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
    if SERVER_KEY in servers:
        # Concurrent modification between detect() and this re-read: an equal
        # entry is an idempotent no-op; a differing entry is operator state
        # this adapter must never silently overwrite (plan() re-detects and
        # reports it fail-closed).
        return plan(env, home)

    backup = backup_path(target)
    backup.write_bytes(target.read_bytes())
    servers[SERVER_KEY] = entry
    payload = json.dumps(data, indent=2) + "\n"
    target.write_text(payload, encoding="utf-8")

    return Plan(
        agent=AGENT_NAME,
        config_path=target,
        status=AgentStatus.CONFIGURED,
        summary=f'{AGENT_NAME}: added "{SERVER_KEY}" to {target} (backup: {backup})',
        config_block=json.dumps({MCP_SERVERS_KEY: {SERVER_KEY: entry}}, indent=2),
        entry=entry,
    )
