"""Cursor adapter: register the universal-db MCP server into Cursor.

Cursor stores global MCP registrations in ``~/.cursor/mcp.json`` under the
top-level ``mcpServers`` key. Detection considers Cursor installed when the
``~/.cursor`` directory exists.

Written registration shape (no secrets -- launch command, UDBMCP_CONFIG path,
and non-secret env only)::

    {
      "mcpServers": {
        "universal-db": {
          "command": "<venv>/bin/python",
          "args": ["-m", "universal_db_mcp", "serve", "--transport", "stdio"],
          "env": {"UDBMCP_CONFIG": "<config path>"}
        }
      }
    }

Fail-closed rules implemented here:

- An existing ``mcp.json`` that is missing, unreadable, or does not parse as
  a JSON object yields ``AgentStatus.UNKNOWN_STATE_FAIL_CLOSED`` and the
  adapter refuses to write. A valid file that already holds a
  differently-shaped "universal-db" registration is user-managed state and
  also fails closed (reported as a conflicting entry, never overwritten).
- ``apply`` only writes when ``confirmed=True`` (the CLI layer owns the
  interactive y/n prompt and the ``--yes`` / ``--dry-run`` flags).
- Every first write is preceded by a timestamped ``.bak`` copy of the target.
- Re-runs are idempotent: an existing equivalent registration is never
  duplicated or rewritten.
"""

from __future__ import annotations

import json
import shutil
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

AGENT_NAME = "cursor"
SERVER_KEY = "universal-db"
MCP_SERVERS_KEY = "mcpServers"
CONFIG_DIR_NAME = ".cursor"
CONFIG_FILE_NAME = "mcp.json"

VENV_PYTHON_ENV = "UDBMCP_VENV_PYTHON"
UDBMCP_CONFIG_ENV = "UDBMCP_CONFIG"

# Canonical air-gapped deployment locations (see docs/offline-deployment.md).
SYSTEM_CONFIG_PATH = Path("/etc/universal-db-mcp/config.yaml")


def config_path(home: Path) -> Path:
    """Absolute path of the Cursor MCP config file for the given HOME."""
    return home / CONFIG_DIR_NAME / CONFIG_FILE_NAME


def _venv_python(env: Mapping[str, str]) -> str:
    """Interpreter that will be written into the launch command.

    Prefers an explicit ``UDBMCP_VENV_PYTHON`` override; otherwise uses the
    interpreter running this CLI, which is the venv python whenever the
    package was installed into a virtual environment.
    """
    override = env.get(VENV_PYTHON_ENV, "").strip()
    if override:
        return override
    return sys.executable


def _udbmcp_config_path(env: Mapping[str, str], home: Path) -> str:
    """Config path to advertise to the launched server via UDBMCP_CONFIG.

    Delegates to the shared resolver (agents.core): harness spawns run as the
    logged-in USER, so the advertised path must be readable by them - the
    system deployment is service-account owned (0640 root:_udbmcp) and is
    not. Unreadable-system spawns died right after connecting (seen live
    2026-09-14); the resolver falls back to the per-user config, which
    ``configure-agents`` seeds on apply.
    """
    return resolve_harness_config_path(env, home)


def registration_entry(env: Mapping[str, str], home: Path) -> dict[str, Any]:
    """The exact dict that would be written under ``mcpServers``.

    Contains no secrets: only the server launch command and the
    ``UDBMCP_CONFIG`` path.
    """
    return {
        "command": _venv_python(env),
        "args": ["-m", "universal_db_mcp", "serve", "--transport", "stdio"],
        "env": {UDBMCP_CONFIG_ENV: _udbmcp_config_path(env, home)},
    }


def _entries_equal(existing: Any, desired: Mapping[str, Any]) -> bool:
    """True when an existing registration already matches the desired one."""
    if not isinstance(existing, dict):
        return False
    return existing == dict(desired)


def detect(env: Mapping[str, str], home: Path) -> AgentStatus:
    """Classify the Cursor harness state without writing anything.

    - ``not_installed``: no ``~/.cursor`` directory.
    - ``configured``: ``mcp.json`` parses, has ``mcpServers``, and contains an
      entry for this server.
    - ``installed_unconfigured``: ``mcp.json`` absent, or parses and lacks our
      entry (it may hold other servers; those are preserved on apply).
    - ``unknown_state_fail_closed``: ``mcp.json`` exists but is unreadable or
      is not a JSON object / ``mcpServers`` is not an object.
    """
    cursor_dir = home / CONFIG_DIR_NAME
    if not cursor_dir.is_dir():
        return AgentStatus.NOT_INSTALLED

    target = config_path(home)
    if not target.exists():
        return AgentStatus.INSTALLED_UNCONFIGURED

    data, error = load_json_or_fail_closed(target)
    if data is None:
        return AgentStatus.UNKNOWN_STATE_FAIL_CLOSED

    servers = data.get(MCP_SERVERS_KEY)
    if servers is None:
        return AgentStatus.INSTALLED_UNCONFIGURED
    if not isinstance(servers, dict):
        return AgentStatus.UNKNOWN_STATE_FAIL_CLOSED

    if SERVER_KEY in servers and not _entries_equal(servers[SERVER_KEY], registration_entry(env, home)):
        # A differently-shaped registration for our server key: treat the
        # file as user-managed state we must not silently rewrite.
        return AgentStatus.UNKNOWN_STATE_FAIL_CLOSED

    if SERVER_KEY in servers:
        return AgentStatus.CONFIGURED
    return AgentStatus.INSTALLED_UNCONFIGURED


def _has_conflicting_registration(
    target: Path, env: Mapping[str, str], home: Path
) -> bool:
    """True when ``target`` is a healthy file holding a differently-shaped
    "universal-db" registration under a dict "mcpServers" key.

    ``detect`` returns ``UNKNOWN_STATE_FAIL_CLOSED`` both for genuinely
    missing/unreadable/malformed configs and for this user-managed state;
    this helper lets ``plan``/``apply`` report an accurate reason (the file
    is readable and valid, we simply refuse to overwrite a conflicting
    registration) instead of a false "malformed" diagnostic.
    """
    data, _error = load_json_or_fail_closed(target)
    if data is None:
        return False
    servers = data.get(MCP_SERVERS_KEY)
    if not isinstance(servers, dict):
        return False
    return SERVER_KEY in servers and not _entries_equal(
        servers[SERVER_KEY], registration_entry(env, home)
    )


def plan(env: Mapping[str, str], home: Path) -> Plan:
    """Describe exactly what would be added to ``~/.cursor/mcp.json``."""
    target = config_path(home)
    status = detect(env, home)
    entry = registration_entry(env, home)

    if status is AgentStatus.NOT_INSTALLED:
        summary = (
            f"{AGENT_NAME}: not installed ({home / CONFIG_DIR_NAME} does not "
            "exist); nothing would be written"
        )
        block = ""
    elif status is AgentStatus.CONFIGURED:
        summary = (
            f"{AGENT_NAME}: already configured in {target} under "
            f'"{MCP_SERVERS_KEY}"["{SERVER_KEY}"]; no changes needed'
        )
        block = ""
    elif status is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED:
        if _has_conflicting_registration(target, env, home):
            summary = (
                f'{AGENT_NAME}: {target} already contains a "{SERVER_KEY}" '
                f'registration under "{MCP_SERVERS_KEY}" that differs from '
                "what this tool would write; refusing to overwrite "
                "user-managed state (edit or remove that entry manually, "
                "then re-run)"
            )
        else:
            summary = (
                f"{AGENT_NAME}: {target} is missing, unreadable, or malformed; "
                "refusing to write (fix or remove the file, then re-run)"
            )
        block = _fail_closed_block(target)
    else:
        if target.exists():
            summary = (
                f'{AGENT_NAME}: would back up {target} to a timestamped .bak, '
                f'then add "{SERVER_KEY}" under "{MCP_SERVERS_KEY}" (other '
                "entries preserved)"
            )
        else:
            summary = (
                f'{AGENT_NAME}: would create {target} with "{SERVER_KEY}" '
                f'under "{MCP_SERVERS_KEY}" (no existing file to back up)'
            )
        block = json.dumps({MCP_SERVERS_KEY: {SERVER_KEY: entry}}, indent=2, sort_keys=True)

    return Plan(
        agent=AGENT_NAME,
        config_path=target,
        status=status,
        summary=summary,
        config_block=block,
        entry=entry,
    )


def _fail_closed_block(target: Path) -> str:
    """Render the offending file's current bytes for operator inspection."""
    try:
        raw = target.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return f"# {target} could not be read: {exc}"
    return f"# current contents of {target}:\n{raw}"


def apply(env: Mapping[str, str], home: Path, confirmed: bool) -> Plan:
    """Write the registration after explicit confirmation.

    Refuses to write when ``confirmed`` is False (the CLI layer owns the
    interactive y/n prompt and the ``--yes`` flag). Creates a timestamped
    ``.bak`` of an existing config before the first write, never duplicates
    an existing equivalent registration, and never touches a malformed
    config (fail closed).
    """
    target = config_path(home)
    status = detect(env, home)

    if status is AgentStatus.NOT_INSTALLED:
        return plan(env, home)
    if status is AgentStatus.CONFIGURED:
        return plan(env, home)
    if status is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED:
        # Malformed/unreadable existing config: report, never write.
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

    entry = registration_entry(env, home)

    if target.exists():
        data, error = load_json_or_fail_closed(target)
        if data is None:
            # Re-check at write time: fail closed rather than overwrite.
            return plan(env, home)
        servers = data.get(MCP_SERVERS_KEY)
        if servers is None:
            # Valid mcp.json without an "mcpServers" key (e.g. "{}"): create
            # the key rather than silently no-oping a confirmed write.
            servers = {}
        if not isinstance(servers, dict):
            return plan(env, home)
        if SERVER_KEY in servers and _entries_equal(servers[SERVER_KEY], entry):
            return plan(env, home)  # idempotent no-op
        backup = backup_path(target)
        shutil.copy2(target, backup)
        servers[SERVER_KEY] = entry
        data[MCP_SERVERS_KEY] = servers
        payload = json.dumps(data, indent=2, sort_keys=True) + "\n"
        target.write_text(payload, encoding="utf-8")
        summary = (
            f"{AGENT_NAME}: added \"{SERVER_KEY}\" to {target} "
            f"(backup: {backup})"
        )
    else:
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps({MCP_SERVERS_KEY: {SERVER_KEY: entry}}, indent=2, sort_keys=True) + "\n"
        target.write_text(payload, encoding="utf-8")
        summary = f"{AGENT_NAME}: created {target} with \"{SERVER_KEY}\""

    return Plan(
        agent=AGENT_NAME,
        config_path=target,
        status=AgentStatus.CONFIGURED,
        summary=summary,
        config_block=json.dumps({MCP_SERVERS_KEY: {SERVER_KEY: entry}}, indent=2, sort_keys=True),
        entry=entry,
    )
