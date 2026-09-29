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
          "args": ["-I", "-m", "universal_db_mcp", "serve", "--transport", "stdio"],
          "env": {"UDBMCP_CONFIG": "<config path>"}
        }
      }
    }

Fail-closed rules implemented here:

- An existing ``mcp.json`` that is missing, unreadable, or does not parse as
  a JSON object yields ``AgentStatus.UNKNOWN_STATE_FAIL_CLOSED`` and the
  adapter refuses to write. A valid file that already holds a
  differently-shaped "universal-db" registration is user-managed state and
  also fails closed (reported as a conflicting entry, never overwritten). The
  one exception is this tool's own pre-``-I`` registration (identical except
  for the launch args), which is upgraded like a fresh write.
- A config the write would replace or create but may not (read-only,
  another user's, hard-linked, with an access control list the replace would
  change, in a read-only directory, or as root behind a user's symlink:
  ``core.ensure_replaceable``) fails closed at detection too.
- ``apply`` only writes when ``confirmed=True`` (the CLI layer owns the
  interactive y/n prompt and the ``--yes`` / ``--dry-run`` flags).
- Every first write is preceded by a timestamped, private ``.bak`` copy of
  the target, and the write replaces the file atomically (a failed write
  leaves it as it was).
- Re-runs are idempotent: an existing equivalent registration is never
  duplicated or rewritten.
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
    atomic_write_text,
    backup_path,
    ensure_directory,
    ensure_replaceable,
    holds_legacy_entry,
    is_legacy_entry,
    load_json_or_fail_closed,
    other_unisolated_note,
    require_isolated_import,
    resolve_harness_config_path,
    unisolated_entry_note,
    unreplaceable_reason,
    write_private_backup,
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
    """Config path to advertise to the launched server via UDBMCP_CONFIG.

    Delegates to the shared resolver (agents.core): harness spawns run as the
    logged-in USER, so the advertised path must be readable by them - the
    system deployment is service-account owned (0640 root:_udbmcp) and is
    not. Unreadable-system spawns died right after connecting (seen live
    2026-09-14); the resolver falls back to the per-user config, which
    ``configure-agents`` seeds on apply.
    """
    return resolve_harness_config_path(env, home, strict=True, for_harness=True)


def registration_entry(env: Mapping[str, str], home: Path) -> dict[str, Any]:
    """The exact dict that would be written under ``mcpServers``.

    Contains no secrets: only the server launch command and the
    ``UDBMCP_CONFIG`` path.
    """
    return {
        "command": _venv_python(env),
        "args": list(SERVER_ARGS),
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
      entry (it may hold other servers; those are preserved on apply), or
      holds the pre-``-I`` registration (upgraded on apply).
    - ``unknown_state_fail_closed``: ``mcp.json`` exists but is unreadable or
      is not a JSON object / ``mcpServers`` is not an object, or it would be
      written but may not be replaced (read-only, another user's,
      hard-linked: ``core.ensure_replaceable``).
    """
    status = _config_status(env, home)
    if status is AgentStatus.INSTALLED_UNCONFIGURED and unreplaceable_reason(config_path(home)) is not None:
        return AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    return status


def _config_status(env: Mapping[str, str], home: Path) -> AgentStatus:
    """:func:`detect` from the config's content alone (no replace check)."""
    cursor_dir = home / CONFIG_DIR_NAME
    if not cursor_dir.is_dir():
        return AgentStatus.NOT_INSTALLED

    # Resolved up front: an override that cannot be registered (a relative
    # path naming no file) is refused at detection, before any write is offered.
    entry = registration_entry(env, home)
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

    if SERVER_KEY in servers and is_legacy_entry(servers[SERVER_KEY], entry):
        return AgentStatus.INSTALLED_UNCONFIGURED
    if SERVER_KEY in servers and not _entries_equal(servers[SERVER_KEY], entry):
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
    entry = registration_entry(env, home)
    existing = servers.get(SERVER_KEY)
    return SERVER_KEY in servers and not (_entries_equal(existing, entry) or is_legacy_entry(existing, entry))


def plan(env: Mapping[str, str], home: Path) -> Plan:
    """Describe exactly what would be added to ``~/.cursor/mcp.json``."""
    target = config_path(home)
    status = detect(env, home)
    if status is AgentStatus.NOT_INSTALLED:
        # Nothing would be registered, so nothing is resolved: an override
        # that cannot be registered must not turn "not installed" into an error.
        return Plan(
            agent=AGENT_NAME,
            config_path=target,
            status=status,
            summary=f"{AGENT_NAME}: not installed ({home / CONFIG_DIR_NAME} does not exist); nothing would be written",
        )
    entry = registration_entry(env, home)

    if status is AgentStatus.CONFIGURED:
        summary = (
            f"{AGENT_NAME}: already configured in {target} under "
            f'"{MCP_SERVERS_KEY}"["{SERVER_KEY}"]; no changes needed'
        )
        block = ""
    elif status is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED:
        refused = unreplaceable_reason(target)
        if _has_conflicting_registration(target, env, home):
            summary = (
                f'{AGENT_NAME}: {target} already contains a "{SERVER_KEY}" '
                f'registration under "{MCP_SERVERS_KEY}" that differs from '
                "what this tool would write; refusing to overwrite "
                "user-managed state (edit or remove that entry manually, "
                "then re-run)"
            ) + unisolated_entry_note(target, MCP_SERVERS_KEY, SERVER_KEY)
        elif refused is not None and _config_status(env, home) is AgentStatus.INSTALLED_UNCONFIGURED:
            summary = f"{AGENT_NAME}: refusing to write: {refused}"
        else:
            summary = (
                f"{AGENT_NAME}: {target} is missing, unreadable, or malformed; "
                "refusing to write (fix or remove the file, then re-run)"
            )
        block = _fail_closed_block(target)
    else:
        if holds_legacy_entry(target, MCP_SERVERS_KEY, SERVER_KEY, entry):
            summary = (
                f"{AGENT_NAME}: would back up {target} to a timestamped .bak, "
                f'then replace this tool\'s earlier "{SERVER_KEY}" registration '
                "with one that starts the server in isolated mode (-I) (other "
                "entries preserved)"
            )
        elif target.exists():
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
        summary=summary + other_unisolated_note(target, MCP_SERVERS_KEY, SERVER_KEY),
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
        config_block=_fail_closed_block(target),
        entry=entry,
    )


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

    backup: Path | None = None
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
        if SERVER_KEY in servers and not is_legacy_entry(servers[SERVER_KEY], entry):
            return plan(env, home)  # a differing entry appeared since detect(): never overwrite
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
        data[MCP_SERVERS_KEY] = servers
        payload = json.dumps(data, indent=2, sort_keys=True) + "\n"
        summary = (
            f"{AGENT_NAME}: added \"{SERVER_KEY}\" to {target} "
            f"(backup: {backup})"
        )
    else:
        payload = json.dumps({MCP_SERVERS_KEY: {SERVER_KEY: entry}}, indent=2, sort_keys=True) + "\n"
        summary = f"{AGENT_NAME}: created {target} with \"{SERVER_KEY}\""

    try:
        ensure_directory(target.parent)
        # Found absent: only ever created, so one that appeared meanwhile fails closed.
        atomic_write_text(target, payload, create=backup is None)
    except OSError as exc:
        return _write_failed(f"writing {target}", target, entry, exc, backup)

    return Plan(
        agent=AGENT_NAME,
        config_path=target,
        status=AgentStatus.CONFIGURED,
        backup_paths=(backup,) if backup is not None else (),
        summary=summary + other_unisolated_note(target, MCP_SERVERS_KEY, SERVER_KEY),
        config_block=json.dumps({MCP_SERVERS_KEY: {SERVER_KEY: entry}}, indent=2, sort_keys=True),
        entry=entry,
    )
