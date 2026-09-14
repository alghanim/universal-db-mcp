"""Claude Code adapter: register the universal-db MCP server into Claude Code.

Two configuration scopes are handled:

* user scope:    ``<home>/.claude.json``      (top-level ``mcpServers`` key)
* project scope: ``<project_dir>/.mcp.json``  (top-level ``mcpServers`` key)

Detection considers Claude Code installed when the user config exists, the
``~/.claude`` directory exists, a ``claude`` binary is on PATH, or a
project-scope ``.mcp.json`` exists.

Written registration shape (no secrets -- launch command, UDBMCP_CONFIG path,
and non-secret env only)::

    {
      "mcpServers": {
        "universal-db": {
          "type": "stdio",
          "command": "<venv>/bin/python",
          "args": ["-m", "universal_db_mcp", "serve", "--transport", "stdio"],
          "env": {"UDBMCP_CONFIG": "<config path>"}
        }
      }
    }

Scope policy: the user config is always written (created when absent); a
project ``.mcp.json`` is only updated when it already exists — this adapter
never drops a new file into a working tree unprompted.

Fail-closed rules implemented here:

- An existing config that is unreadable, malformed, not a JSON object, or
  whose ``mcpServers`` is not an object yields
  ``AgentStatus.UNKNOWN_STATE_FAIL_CLOSED`` and the adapter refuses to write,
  printing the offending file's current contents.
- A differing registration already sitting under the ``universal-db`` key is
  operator-managed state and is never silently rewritten (fail closed).
- ``apply`` only writes when ``confirmed=True`` (the CLI layer owns the
  interactive y/n prompt and the ``--yes`` / ``--dry-run`` flags).
- Every first write to an existing file is preceded by a timestamped ``.bak``
  copy; all targets are validated before the first byte is written.
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

AGENT_NAME = "claude-code"
SERVER_KEY = "universal-db"
MCP_SERVERS_KEY = "mcpServers"
USER_CONFIG_NAME = ".claude.json"
USER_DIR_NAME = ".claude"
PROJECT_CONFIG_NAME = ".mcp.json"

VENV_PYTHON_ENV = "UDBMCP_VENV_PYTHON"
UDBMCP_CONFIG_ENV = "UDBMCP_CONFIG"

# Canonical air-gapped deployment location (see docs/offline-deployment.md).
SYSTEM_CONFIG_PATH = Path("/etc/universal-db-mcp/config.yaml")


def user_config_path(home: Path) -> Path:
    """Absolute path of the user-scope Claude Code config for ``home``."""
    return home / USER_CONFIG_NAME


def project_config_path(project_dir: Path) -> Path:
    """Absolute path of the project-scope ``.mcp.json`` for ``project_dir``."""
    return project_dir / PROJECT_CONFIG_NAME


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
        "type": "stdio",
        "command": _venv_python(env),
        "args": ["-m", "universal_db_mcp", "serve", "--transport", "stdio"],
        "env": {UDBMCP_CONFIG_ENV: _udbmcp_config_path(env, home)},
    }


def _targets(home: Path, project_dir: Path) -> list[tuple[str, Path, bool]]:
    """Write targets as ``(scope, path, create_if_missing)``."""
    return [
        ("user", user_config_path(home), True),
        ("project", project_config_path(project_dir), False),
    ]


def _is_installed(home: Path, project_dir: Path) -> bool:
    if user_config_path(home).exists():
        return True
    if (home / USER_DIR_NAME).is_dir():
        return True
    if project_config_path(project_dir).exists():
        return True
    return shutil.which("claude") is not None


def _entries_equal(existing: Any, desired: Mapping[str, Any]) -> bool:
    return isinstance(existing, dict) and existing == dict(desired)


def _scope_problems(
    env: Mapping[str, str], home: Path, project_dir: Path
) -> tuple[AgentStatus | None, Path | None]:
    """First fail-closed condition across both scopes, if any.

    Returns ``(status, offending_path)`` or ``(None, None)`` when every
    existing config parses cleanly and holds no conflicting registration.
    """
    entry = registration_entry(env, home)
    for _scope, path, _create in _targets(home, project_dir):
        if not path.exists():
            continue
        data, _error = load_json_or_fail_closed(path)
        if data is None:
            return AgentStatus.UNKNOWN_STATE_FAIL_CLOSED, path
        if MCP_SERVERS_KEY not in data:
            continue  # key absent: benign, nothing registered yet
        servers = data[MCP_SERVERS_KEY]
        if not isinstance(servers, dict):
            # Present but not an object (null, array, string, ...): the
            # operator's file is in a state we do not understand.
            return AgentStatus.UNKNOWN_STATE_FAIL_CLOSED, path
        if SERVER_KEY in servers and not _entries_equal(servers[SERVER_KEY], entry):
            # A differently-shaped registration under our server key:
            # operator state we must not silently rewrite.
            return AgentStatus.UNKNOWN_STATE_FAIL_CLOSED, path
    return None, None


def detect(
    env: Mapping[str, str], home: Path, *, project_dir: Path | None = None
) -> AgentStatus:
    """Classify the Claude Code harness state without writing anything.

    - ``not_installed``: no user config, no ``~/.claude/``, no ``claude``
      binary on PATH, and no project ``.mcp.json``.
    - ``configured``: an equivalent ``universal-db`` registration already
      exists in the user or project scope.
    - ``installed_unconfigured``: installed, and no config holds our entry.
    - ``unknown_state_fail_closed``: an existing config is unreadable,
      malformed, not a JSON object, has a non-object ``mcpServers``, or holds
      a differing ``universal-db`` entry.
    """
    proj = project_dir if project_dir is not None else Path.cwd()
    if not _is_installed(home, proj):
        return AgentStatus.NOT_INSTALLED

    problem, _path = _scope_problems(env, home, proj)
    if problem is not None:
        return problem

    entry = registration_entry(env, home)
    for _scope, path, _create in _targets(home, proj):
        if not path.exists():
            continue
        data, _error = load_json_or_fail_closed(path)
        if data is None:
            continue
        servers = data.get(MCP_SERVERS_KEY)
        if isinstance(servers, dict) and _entries_equal(servers.get(SERVER_KEY), entry):
            return AgentStatus.CONFIGURED
    return AgentStatus.INSTALLED_UNCONFIGURED


def _fail_closed_block(target: Path) -> str:
    """Render the offending file's current bytes for operator inspection."""
    try:
        raw = target.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return f"# {target} could not be read: {exc}"
    return f"# current contents of {target}:\n{raw}"


def plan(
    env: Mapping[str, str], home: Path, *, project_dir: Path | None = None
) -> Plan:
    """Describe exactly what would be added across both scopes; never writes."""
    proj = project_dir if project_dir is not None else Path.cwd()
    target = user_config_path(home)
    status = detect(env, home, project_dir=proj)
    entry = registration_entry(env, home)
    block = json.dumps({MCP_SERVERS_KEY: {SERVER_KEY: entry}}, indent=2, sort_keys=True)

    if status is AgentStatus.NOT_INSTALLED:
        summary = (
            f"{AGENT_NAME}: not installed (no {target}, no {home / USER_DIR_NAME}/, "
            "no 'claude' binary on PATH, no project .mcp.json); nothing would be written"
        )
        block = ""
    elif status is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED:
        problem, bad_path = _scope_problems(env, home, proj)
        if bad_path is None:  # pragma: no cover — detect just reported it
            bad_path = target
        assert problem is not None  # invariant from detect()
        summary = (
            f"{AGENT_NAME}: {bad_path} is unreadable, malformed, or holds a differing "
            f'"{SERVER_KEY}" entry; refusing to write (fix or inspect the file, then re-run)'
        )
        block = _fail_closed_block(bad_path)
    elif status is AgentStatus.CONFIGURED:
        summary = (
            f"{AGENT_NAME}: already configured under "
            f'"{MCP_SERVERS_KEY}"["{SERVER_KEY}"]; no changes needed'
        )
        block = ""
    else:
        parts: list[str] = []
        for scope, path, create in _targets(home, proj):
            if path.exists():
                parts.append(
                    f"{scope} scope {path}: would back up to a timestamped .bak, then add "
                    f'"{SERVER_KEY}" under "{MCP_SERVERS_KEY}" (other entries preserved)'
                )
            elif create:
                parts.append(
                    f'{scope} scope {path}: would be created with "{SERVER_KEY}" under "{MCP_SERVERS_KEY}"'
                )
            else:
                parts.append(f"{scope} scope {path}: absent; left absent (no project file is created unprompted)")
        summary = f"{AGENT_NAME}: " + "; ".join(parts)

    return Plan(
        agent=AGENT_NAME,
        config_path=target,
        status=status,
        summary=summary,
        config_block=block,
        entry=entry,
    )


def apply(
    env: Mapping[str, str], home: Path, confirmed: bool, *, project_dir: Path | None = None
) -> Plan:
    """Write the registration after explicit confirmation.

    Refuses to write when ``confirmed`` is False (the CLI layer owns the
    interactive y/n prompt and the ``--yes`` flag). Every existing target is
    validated and backed up (timestamped ``.bak``) before the first write,
    equivalent registrations are never duplicated, and malformed configs are
    never touched (fail closed).
    """
    proj = project_dir if project_dir is not None else Path.cwd()
    status = detect(env, home, project_dir=proj)

    if status is not AgentStatus.INSTALLED_UNCONFIGURED:
        # not_installed / configured / fail-closed: nothing safe to write.
        return plan(env, home, project_dir=proj)

    if not confirmed:
        planned = plan(env, home, project_dir=proj)
        return Plan(
            agent=planned.agent,
            config_path=planned.config_path,
            status=planned.status,
            summary=planned.summary + " (not applied: confirmation refused)",
            config_block=planned.config_block,
            entry=planned.entry,
        )

    # Pre-validate every existing target BEFORE any write (fail closed,
    # so a malformed project file blocks the user-scope write too).
    entry = registration_entry(env, home)
    staged: list[tuple[Path, dict[str, Any], Path | None]] = []
    for _scope, path, create in _targets(home, proj):
        if path.exists():
            data, _error = load_json_or_fail_closed(path)
            if data is None or (
                MCP_SERVERS_KEY in data and not isinstance(data[MCP_SERVERS_KEY], dict)
            ):
                # Re-check at write time: fail closed rather than overwrite.
                # plan() re-runs detect(), which reports the fail-closed
                # state (with the offending file's contents) for these cases.
                return plan(env, home, project_dir=proj)
            # Absent key and present-but-null both normalize to an empty
            # registry (mirrors the write loop below).
            servers = data.get(MCP_SERVERS_KEY)
            if not isinstance(servers, dict):
                servers = {}
                data[MCP_SERVERS_KEY] = servers
            if SERVER_KEY in servers and _entries_equal(servers[SERVER_KEY], entry):
                continue  # idempotent: never duplicate
            staged.append((path, data, backup_path(path)))
        elif create:
            staged.append((path, {MCP_SERVERS_KEY: {}}, None))
        # else: absent project file is never created unprompted

    if not staged:  # pragma: no cover — detect() would have said CONFIGURED
        return plan(env, home, project_dir=proj)

    def _write_interrupted(failed_path: Path, exc: OSError, done: list[str]) -> Plan:
        completed = "; ".join(done) if done else "nothing"
        return Plan(
            agent=AGENT_NAME,
            config_path=user_config_path(home),
            status=AgentStatus.UNKNOWN_STATE_FAIL_CLOSED,
            summary=(
                f"{AGENT_NAME}: writing {failed_path} failed ({exc}); "
                f"completed before the failure: {completed}"
            ),
            config_block=_fail_closed_block(failed_path),
            entry=entry,
        )

    # Phase 1: create every timestamped .bak before any config byte changes,
    # so a failure partway through never leaves a modified file unbacked up.
    backed_up: list[str] = []
    for path, _data, backup in staged:
        if backup is None:
            continue
        try:
            backup.write_bytes(path.read_bytes())
        except OSError as exc:
            return _write_interrupted(path, exc, backed_up)
        backed_up.append(f"{path} (backup: {backup})")

    # Phase 2: write the registrations.
    written: list[str] = list(backed_up)
    for path, data, backup in staged:
        try:
            if backup is None:
                path.parent.mkdir(parents=True, exist_ok=True)
            servers = data.get(MCP_SERVERS_KEY)
            if not isinstance(servers, dict):
                servers = {}
                data[MCP_SERVERS_KEY] = servers
            servers[SERVER_KEY] = dict(entry)
            payload = json.dumps(data, indent=2) + "\n"
            path.write_text(payload, encoding="utf-8")
        except OSError as exc:
            return _write_interrupted(path, exc, written)
        written.append(str(path))

    return Plan(
        agent=AGENT_NAME,
        config_path=user_config_path(home),
        status=AgentStatus.CONFIGURED,
        summary=f'{AGENT_NAME}: added "{SERVER_KEY}" to ' + "; ".join(written),
        config_block=json.dumps({MCP_SERVERS_KEY: {SERVER_KEY: entry}}, indent=2, sort_keys=True),
        entry=entry,
    )
