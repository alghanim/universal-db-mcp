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
          "args": ["-I", "-m", "universal_db_mcp", "serve", "--transport", "stdio"],
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
  operator-managed state and is never silently rewritten (fail closed). The
  one exception is this tool's own pre-``-I`` registration (identical except
  for the launch args), which is upgraded like a fresh write.
- A config the write would replace or create but may not (read-only,
  another user's, hard-linked, with an access control list the replace would
  change, in a read-only directory, or as root behind a user's symlink:
  ``core.ensure_replaceable``) fails closed at detection too.
- ``apply`` only writes when ``confirmed=True`` (the CLI layer owns the
  interactive y/n prompt and the ``--yes`` / ``--dry-run`` flags).
- Every first write to an existing file is preceded by a timestamped, private
  ``.bak`` copy; all targets are validated before the first byte is written,
  and each write replaces its file atomically (a failed write leaves it as
  it was).
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
    require_isolated_import,
    resolve_harness_config_path,
    unisolated_entry_note,
    unisolated_launches,
    unisolated_launches_note,
    unreplaceable_reason,
    write_private_backup,
)

AGENT_NAME = "claude-code"
SERVER_KEY = "universal-db"
MCP_SERVERS_KEY = "mcpServers"
USER_CONFIG_NAME = ".claude.json"
USER_DIR_NAME = ".claude"
PROJECT_CONFIG_NAME = ".mcp.json"
# ~/.claude.json's per-project settings: {"projects": {"<dir>": {"mcpServers": {...}}}}.
PROJECTS_KEY = "projects"

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
        "type": "stdio",
        "command": _venv_python(env),
        "args": list(SERVER_ARGS),
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


def _holds_entry(path: Path, desired: Mapping[str, Any]) -> bool:
    """True when the config at ``path`` already holds ``desired`` (apply() skips it)."""
    data, _error = load_json_or_fail_closed(path)
    servers = data.get(MCP_SERVERS_KEY) if data is not None else None
    return isinstance(servers, dict) and _entries_equal(servers.get(SERVER_KEY), desired)


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
        existing = servers.get(SERVER_KEY)
        if SERVER_KEY in servers and not (_entries_equal(existing, entry) or is_legacy_entry(existing, entry)):
            # A differently-shaped registration under our server key:
            # operator state we must not silently rewrite.
            return AgentStatus.UNKNOWN_STATE_FAIL_CLOSED, path
    return None, None


def _unreplaceable_scope(
    entry: Mapping[str, Any], home: Path, project_dir: Path
) -> tuple[Path, str] | None:
    """The first config ``apply`` would write but may not, and why: an existing
    one it would rewrite (read-only, another user's, hard-linked, with an ACL
    the replace would change, in a read-only directory), or the user-scope
    one it would create (``core.ensure_replaceable``)."""
    for _scope, path, create in _targets(home, project_dir):
        written = not _holds_entry(path, entry) if path.exists() else create
        if written:
            reason = unreplaceable_reason(path)
            if reason is not None:
                return path, reason
    return None


def _unisolated_note(path: Path) -> str:
    """``core.unisolated_launches_note`` for ``path``: its other servers and,
    in ``~/.claude.json``, every per-project server (Claude Code launches
    those too) that start this package without ``-I``."""
    data, _error = load_json_or_fail_closed(path)
    if data is None:
        return ""
    names = [f'"{MCP_SERVERS_KEY}"["{name}"]' for name in unisolated_launches(data.get(MCP_SERVERS_KEY), SERVER_KEY)]
    projects = data.get(PROJECTS_KEY)
    for directory, project in projects.items() if isinstance(projects, dict) else ():
        servers = project.get(MCP_SERVERS_KEY) if isinstance(project, dict) else None
        names += [
            f'"{PROJECTS_KEY}"["{directory}"]["{MCP_SERVERS_KEY}"]["{name}"]' for name in unisolated_launches(servers)
        ]
    return unisolated_launches_note(path, names)


def _unisolated_notes(home: Path, project_dir: Path) -> str:
    """:func:`_unisolated_note` for both scopes."""
    return "".join(_unisolated_note(path) for _scope, path, _create in _targets(home, project_dir))


def detect(
    env: Mapping[str, str], home: Path, *, project_dir: Path | None = None
) -> AgentStatus:
    """Classify the Claude Code harness state without writing anything.

    - ``not_installed``: no user config, no ``~/.claude/``, no ``claude``
      binary on PATH, and no project ``.mcp.json``.
    - ``configured``: an equivalent ``universal-db`` registration already
      exists in the user or project scope, and neither holds the pre-``-I``
      registration.
    - ``installed_unconfigured``: installed, and no config holds our entry, or
      one holds the pre-``-I`` registration (upgraded on apply).
    - ``unknown_state_fail_closed``: an existing config is unreadable,
      malformed, not a JSON object, has a non-object ``mcpServers``, or holds
      a differing ``universal-db`` entry, or one ``apply`` would rewrite may
      not be replaced (read-only, another user's, hard-linked).
    """
    proj = project_dir if project_dir is not None else Path.cwd()
    if not _is_installed(home, proj):
        return AgentStatus.NOT_INSTALLED

    problem, _path = _scope_problems(env, home, proj)
    if problem is not None:
        return problem

    entry = registration_entry(env, home)
    configured = upgradeable = False
    for _scope, path, _create in _targets(home, proj):
        if not path.exists():
            continue
        data, _error = load_json_or_fail_closed(path)
        if data is None:
            continue
        servers = data.get(MCP_SERVERS_KEY)
        if not isinstance(servers, dict):
            continue
        if is_legacy_entry(servers.get(SERVER_KEY), entry):
            upgradeable = True
        elif _entries_equal(servers.get(SERVER_KEY), entry):
            configured = True
    if configured and not upgradeable:
        return AgentStatus.CONFIGURED
    if _unreplaceable_scope(entry, home, proj) is not None:
        return AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
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
    if status is AgentStatus.NOT_INSTALLED:
        # Nothing would be registered, so nothing is resolved: an override
        # that cannot be registered must not turn "not installed" into an error.
        return Plan(
            agent=AGENT_NAME,
            config_path=target,
            status=status,
            summary=(
                f"{AGENT_NAME}: not installed (no {target}, no {home / USER_DIR_NAME}/, "
                "no 'claude' binary on PATH, no project .mcp.json); nothing would be written"
            ),
        )
    entry = registration_entry(env, home)
    block = json.dumps({MCP_SERVERS_KEY: {SERVER_KEY: entry}}, indent=2, sort_keys=True)

    if status is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED:
        problem, bad_path = _scope_problems(env, home, proj)
        refused = _unreplaceable_scope(entry, home, proj) if problem is None else None
        if refused is not None:
            bad_path, reason = refused
            summary = f"{AGENT_NAME}: refusing to write: {reason}"
        else:
            if bad_path is None:  # pragma: no cover — detect just reported it
                bad_path = target
            summary = (
                f"{AGENT_NAME}: {bad_path} is unreadable, malformed, or holds a differing "
                f'"{SERVER_KEY}" entry; refusing to write (fix or inspect the file, then re-run)'
            ) + unisolated_entry_note(bad_path, MCP_SERVERS_KEY, SERVER_KEY)
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
            if _holds_entry(path, entry):
                parts.append(f"{scope} scope {path}: already registered (left untouched)")
            elif holds_legacy_entry(path, MCP_SERVERS_KEY, SERVER_KEY, entry):
                parts.append(
                    f"{scope} scope {path}: would back up to a timestamped .bak, then replace this "
                    f'tool\'s earlier "{SERVER_KEY}" registration with one that starts the server '
                    "in isolated mode (-I) (other entries preserved)"
                )
            elif path.exists():
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
        summary=summary + _unisolated_notes(home, proj),
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
            if SERVER_KEY in servers and not is_legacy_entry(servers[SERVER_KEY], entry):
                # A differing entry appeared since detect(): never overwrite.
                return plan(env, home, project_dir=proj)
            staged.append((path, data, backup_path(path)))
        elif create:
            staged.append((path, {MCP_SERVERS_KEY: {}}, None))
        # else: absent project file is never created unprompted

    if not staged:  # pragma: no cover — detect() would have said CONFIGURED
        return plan(env, home, project_dir=proj)

    backups: list[Path] = []
    backed_up: list[str] = []
    written: list[str] = []

    def _write_interrupted(step: str, failed_path: Path, exc: OSError) -> Plan:
        return Plan(
            agent=AGENT_NAME,
            config_path=user_config_path(home),
            status=AgentStatus.UNKNOWN_STATE_FAIL_CLOSED,
            backup_paths=tuple(backups),
            summary=(
                f"{AGENT_NAME}: {step} failed ({exc}); {failed_path} was left as it was; "
                f"backed up: {', '.join(backed_up) or 'nothing'}; written: {', '.join(written) or 'nothing'}"
            ),
            config_block=_fail_closed_block(failed_path),
            entry=entry,
        )

    # Phase 0: refuse a config the replace may not touch (read-only, another
    # user's, hard-linked) before any backup exists, so none is left behind.
    for path, _data, backup in staged:
        if backup is None:
            continue
        try:
            ensure_replaceable(path)
        except OSError as exc:
            return _write_interrupted(f"writing {path}", path, exc)

    # Phase 1: create every timestamped .bak before any config byte changes,
    # so a failure partway through never leaves a modified file unbacked up.
    for path, _data, backup in staged:
        if backup is None:
            continue
        try:
            write_private_backup(path, backup)
        except OSError as exc:
            return _write_interrupted(f"backing up {path} to {backup}", path, exc)
        backups.append(backup)
        backed_up.append(f"{path} to {backup}")

    # Phase 2: write the registrations.
    for path, data, backup in staged:
        try:
            if backup is None:
                ensure_directory(path.parent)
            servers = data.get(MCP_SERVERS_KEY)
            if not isinstance(servers, dict):
                servers = {}
                data[MCP_SERVERS_KEY] = servers
            servers[SERVER_KEY] = dict(entry)
            payload = json.dumps(data, indent=2) + "\n"
            # Found absent: only ever created, so one that appeared meanwhile fails closed.
            atomic_write_text(path, payload, create=backup is None)
        except OSError as exc:
            return _write_interrupted(f"writing {path}", path, exc)
        written.append(str(path))

    backup_note = f" (backup: {', '.join(str(b) for b in backups)})" if backups else ""
    return Plan(
        agent=AGENT_NAME,
        config_path=user_config_path(home),
        status=AgentStatus.CONFIGURED,
        backup_paths=tuple(backups),
        summary=f'{AGENT_NAME}: added "{SERVER_KEY}" to '
        + "; ".join(written)
        + backup_note
        + _unisolated_notes(home, proj),
        config_block=json.dumps({MCP_SERVERS_KEY: {SERVER_KEY: entry}}, indent=2, sort_keys=True),
        entry=entry,
    )
