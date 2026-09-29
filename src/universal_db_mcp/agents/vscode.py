"""VS Code (Copilot MCP) adapter: register the universal-db MCP server.

VS Code discovers Copilot MCP servers from ``mcp.json`` files in two scopes:

* user profile — ``~/Library/Application Support/Code/User/mcp.json`` (macOS),
  ``%APPDATA%\\Code\\User\\mcp.json`` (Windows) or
  ``$XDG_CONFIG_HOME/Code/User/mcp.json``, default ``~/.config/...`` (Linux/other);
* workspace scope — ``<workspace>/.vscode/mcp.json``.

Like the other adapters this module is HOME-keyed and manages the
user-profile file; when the CLI layer additionally passes an explicit
``workspace`` whose ``.vscode`` directory already exists, the workspace file
is managed in the same confirmed operation (a ``.vscode`` directory is never
created in a project that does not already have one). VS Code's native
top-level key is ``"servers"`` (not ``mcpServers``).

Detection considers VS Code installed when its platform configuration
directory (``.../Code``) exists.

Written registration shape (no secrets — launch command, UDBMCP_CONFIG path,
and non-secret env only)::

    {
      "servers": {
        "universal-db": {
          "type": "stdio",
          "command": "<venv>/bin/python",
          "args": ["-I", "-m", "universal_db_mcp", "serve", "--transport", "stdio"],
          "env": {"UDBMCP_CONFIG": "<config path>"}
        }
      }
    }

Fail-closed rules implemented here:

- An existing ``mcp.json`` that is unreadable, or does not parse as a JSON
  object with a ``servers`` object, yields
  ``AgentStatus.UNKNOWN_STATE_FAIL_CLOSED`` and the adapter refuses to write.
- A differently-shaped existing registration under our server key is treated
  as user-managed state and also fails closed rather than being overwritten.
  The one exception is this tool's own pre-``-I`` registration (identical
  except for the launch args), which is upgraded like a fresh write.
- A file the write would replace or create but may not (read-only, another
  user's, hard-linked, with an access control list the replace would change,
  in a read-only directory, or as root behind a user's symlink:
  ``core.ensure_replaceable``) fails closed at detection too.
- ``apply`` only writes when ``confirmed=True`` (the CLI layer owns the
  interactive y/n prompt and the ``--yes`` / ``--dry-run`` flags); when any
  managed target is malformed, nothing is written anywhere.
- Every first write to an existing file is preceded by a timestamped,
  private ``.bak`` copy of that file, and each write replaces its file
  atomically (a failed write leaves it as it was).
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
    app_data_base,
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

AGENT_NAME = "vscode"
SERVER_KEY = "universal-db"
SERVERS_KEY = "servers"
CONFIG_FILE_NAME = "mcp.json"
WORKSPACE_DIR_NAME = ".vscode"

VENV_PYTHON_ENV = "UDBMCP_VENV_PYTHON"
UDBMCP_CONFIG_ENV = "UDBMCP_CONFIG"

# Canonical air-gapped deployment location (see docs/offline-deployment.md).
SYSTEM_CONFIG_PATH = Path("/etc/universal-db-mcp/config.yaml")


def user_config_dir(home: Path, platform: str | None = None, *, env: Mapping[str, str] | None = None) -> Path:
    """User-profile ``Code/User`` directory for the given HOME and platform.

    ``platform`` defaults to the running ``sys.platform``; tests pass an
    explicit value to exercise each layout without touching the real HOME.
    ``env`` supplies ``APPDATA`` / ``XDG_CONFIG_HOME`` (see
    :func:`~universal_db_mcp.agents.core.app_data_base`); without it the
    HOME-relative defaults are used.
    """
    return app_data_base(env or {}, home, platform) / "Code" / "User"


def install_marker(home: Path, platform: str | None = None, *, env: Mapping[str, str] | None = None) -> Path:
    """Directory whose existence means VS Code is installed on this machine."""
    return user_config_dir(home, platform, env=env).parent


def config_path(home: Path, platform: str | None = None, *, env: Mapping[str, str] | None = None) -> Path:
    """Absolute path of the user-profile MCP config file for the given HOME."""
    return user_config_dir(home, platform, env=env) / CONFIG_FILE_NAME


def workspace_config_path(workspace: Path) -> Path:
    """Absolute path of the workspace-scoped MCP config file."""
    return workspace / WORKSPACE_DIR_NAME / CONFIG_FILE_NAME


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
    """The exact dict that would be written under ``servers``.

    Contains no secrets: only the server launch command and the
    ``UDBMCP_CONFIG`` path.
    """
    return {
        "type": "stdio",
        "command": _venv_python(env),
        "args": list(SERVER_ARGS),
        "env": {UDBMCP_CONFIG_ENV: _udbmcp_config_path(env, home)},
    }


def _entries_equal(existing: Any, desired: Mapping[str, Any]) -> bool:
    """True when an existing registration already matches the desired one."""
    if not isinstance(existing, dict):
        return False
    return existing == dict(desired)


def _classify_data(data: Mapping[str, Any], entry: Mapping[str, Any]) -> AgentStatus:
    """Classify an already-parsed ``mcp.json`` document.

    Shared by :func:`_registration_status` and the write-time re-check in
    :func:`_apply_target` so both classify identically.

    - ``installed_unconfigured``: no ``servers`` key, or it holds an object
      with no entry for this server (other servers may be present; those are
      preserved on apply), or with the pre-``-I`` registration (upgraded on
      apply).
    - ``configured``: an equivalent entry already exists under our server key.
    - ``unknown_state_fail_closed``: ``servers`` is present but not an object
      (including JSON ``null``), or our server key holds a differently-shaped
      registration (user-managed state we must not silently rewrite).
    """
    if SERVERS_KEY not in data:
        return AgentStatus.INSTALLED_UNCONFIGURED

    servers = data[SERVERS_KEY]
    if not isinstance(servers, dict):
        return AgentStatus.UNKNOWN_STATE_FAIL_CLOSED

    if SERVER_KEY in servers and is_legacy_entry(servers[SERVER_KEY], entry):
        return AgentStatus.INSTALLED_UNCONFIGURED
    if SERVER_KEY in servers and not _entries_equal(servers[SERVER_KEY], entry):
        return AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    if SERVER_KEY in servers:
        return AgentStatus.CONFIGURED
    return AgentStatus.INSTALLED_UNCONFIGURED


def _registration_status(target: Path, entry: Mapping[str, Any]) -> AgentStatus:
    """Classify one ``mcp.json`` target without writing anything.

    - ``installed_unconfigured``: the file is absent, or parses and holds no
      entry for this server (other servers may be present; those are
      preserved on apply).
    - ``configured``: the file parses and already holds an equivalent entry.
    - ``unknown_state_fail_closed``: the file exists but is unreadable or is
      not a JSON object, or ``servers`` is present but not an object
      (including JSON ``null``), or our server key holds a differently-shaped
      registration (user-managed state we must not silently rewrite), or it
      would be written but may not be (read-only, another user's,
      hard-linked, in a read-only directory: ``core.ensure_replaceable``).
    """
    if not target.exists():
        if unreplaceable_reason(target) is not None:
            return AgentStatus.UNKNOWN_STATE_FAIL_CLOSED  # the create may not happen
        return AgentStatus.INSTALLED_UNCONFIGURED

    data, _error = load_json_or_fail_closed(target)
    if data is None:
        return AgentStatus.UNKNOWN_STATE_FAIL_CLOSED

    status = _classify_data(data, entry)
    if status is AgentStatus.INSTALLED_UNCONFIGURED and unreplaceable_reason(target) is not None:
        return AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    return status


def detect(env: Mapping[str, str], home: Path, platform: str | None = None) -> AgentStatus:
    """Classify the VS Code harness state without writing anything.

    - ``not_installed``: the platform ``Code`` configuration directory does
      not exist under HOME.
    - ``configured`` / ``installed_unconfigured`` /
      ``unknown_state_fail_closed``: see :func:`_registration_status` for the
      user-profile ``mcp.json``.
    """
    if not install_marker(home, platform, env=env).is_dir():
        return AgentStatus.NOT_INSTALLED

    # Resolved up front: an override that cannot be registered (a relative
    # path naming no file) is refused at detection, before any write is offered.
    entry = registration_entry(env, home)
    return _registration_status(config_path(home, platform, env=env), entry)


def _fail_closed_block(target: Path) -> str:
    """Render the offending file's current bytes for operator inspection."""
    try:
        raw = target.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return f"# {target} could not be read: {exc}"
    return f"# current contents of {target}:\n{raw}"


def _desired_block(entry: Mapping[str, Any]) -> str:
    """Exact JSON that would be added to a config file (pretty-printed)."""
    return json.dumps({SERVERS_KEY: {SERVER_KEY: dict(entry)}}, indent=2, sort_keys=True)


def _describe(status: AgentStatus, target: Path, scope: str, entry: Mapping[str, Any]) -> str:
    """Human sentence describing what would be done for one target."""
    prefix = f"{AGENT_NAME} [{scope}]"
    if status is AgentStatus.CONFIGURED:
        return (
            f'{prefix}: already configured in {target} under "{SERVERS_KEY}"'
            f'["{SERVER_KEY}"]; no changes needed'
        )
    if status is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED:
        data, _error = load_json_or_fail_closed(target)
        if not target.exists():
            content = AgentStatus.INSTALLED_UNCONFIGURED  # only the create is refused
        else:
            content = _classify_data(data, entry) if data is not None else status
        refused = unreplaceable_reason(target)
        if refused is not None and content is AgentStatus.INSTALLED_UNCONFIGURED:
            return f"{prefix}: refusing to write: {refused}"
        servers = data.get(SERVERS_KEY) if data is not None else None
        if isinstance(servers, dict) and content is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED:
            # It parses, and "servers" is an object: our key holds a differing entry.
            return (
                f'{prefix}: {target} already contains a "{SERVER_KEY}" registration under '
                f'"{SERVERS_KEY}" that differs from what this tool would write; refusing to '
                "overwrite user-managed state (edit or remove that entry manually, then re-run)"
            ) + unisolated_entry_note(target, SERVERS_KEY, SERVER_KEY)
        return (
            f"{prefix}: {target} is unreadable or malformed; refusing to "
            "write (fix or remove the file, then re-run)"
        )
    if holds_legacy_entry(target, SERVERS_KEY, SERVER_KEY, entry):
        return (
            f"{prefix}: would back up {target} to a timestamped .bak, then replace this "
            f'tool\'s earlier "{SERVER_KEY}" registration with one that starts the server '
            "in isolated mode (-I) (other entries preserved)"
        )
    if target.exists():
        return (
            f'{prefix}: would back up {target} to a timestamped .bak, then '
            f'add "{SERVER_KEY}" under "{SERVERS_KEY}" (other entries preserved)'
        )
    return f'{prefix}: would create {target} with "{SERVER_KEY}" under "{SERVERS_KEY}"'


def _unisolated_notes(paths: list[Path]) -> str:
    """``core.other_unisolated_note`` for every managed ``mcp.json``."""
    return "".join(other_unisolated_note(path, SERVERS_KEY, SERVER_KEY) for path in paths)


def _plan_block(status: AgentStatus, target: Path, entry: Mapping[str, Any]) -> str:
    """The config block a plan prints for one target."""
    if status is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED:
        return _fail_closed_block(target)
    if status is AgentStatus.CONFIGURED:
        return ""
    return _desired_block(entry)


def _combine(statuses: list[AgentStatus]) -> AgentStatus:
    """Fold per-target statuses into one overall status (fail closed wins)."""
    if any(s is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED for s in statuses):
        return AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    if all(s is AgentStatus.NOT_INSTALLED for s in statuses):
        return AgentStatus.NOT_INSTALLED
    if any(s is AgentStatus.INSTALLED_UNCONFIGURED for s in statuses):
        return AgentStatus.INSTALLED_UNCONFIGURED
    return AgentStatus.CONFIGURED


def plan(
    env: Mapping[str, str],
    home: Path,
    platform: str | None = None,
    workspace: Path | None = None,
) -> Plan:
    """Describe exactly what would be added, without writing anything."""
    target = config_path(home, platform, env=env)
    installed = install_marker(home, platform, env=env).is_dir()
    in_workspace = workspace is not None and (workspace / WORKSPACE_DIR_NAME).is_dir()
    # Resolved only when something would be registered: an override that
    # cannot be registered must not turn "not installed" into an error.
    entry = registration_entry(env, home) if installed or in_workspace else {}

    statuses: list[AgentStatus] = []
    sentences: list[str] = []
    blocks: list[str] = []
    paths: list[Path] = [target]

    if installed:
        status = _registration_status(target, entry)
        statuses.append(status)
        sentences.append(_describe(status, target, "user profile", entry))
        blocks.append(_plan_block(status, target, entry))
    else:
        statuses.append(AgentStatus.NOT_INSTALLED)
        sentences.append(
            f"{AGENT_NAME} [user profile]: not installed "
            f"({install_marker(home, platform, env=env)} does not exist); nothing "
            "would be written to the user profile"
        )

    if workspace is not None:
        ws_path = workspace_config_path(workspace)
        if (workspace / WORKSPACE_DIR_NAME).is_dir():
            paths.append(ws_path)
            ws_status = _registration_status(ws_path, entry)
            statuses.append(ws_status)
            sentences.append(_describe(ws_status, ws_path, "workspace", entry))
            blocks.append(_plan_block(ws_status, ws_path, entry))
        else:
            sentences.append(
                f"{AGENT_NAME}: workspace {workspace} has no "
                f"{WORKSPACE_DIR_NAME} directory; workspace configuration skipped"
            )

    return Plan(
        agent=AGENT_NAME,
        status=_combine(statuses),
        config_path=target,
        config_paths=tuple(paths),
        summary="; ".join(sentences) + _unisolated_notes(paths),
        config_block="\n\n".join(b for b in blocks if b),
        entry=dict(entry),
    )


def _write_failed(
    label: str, step: str, target: Path, exc: OSError, backup: Path | None
) -> tuple[AgentStatus, str, str, Path | None]:
    """Fail-closed :func:`_apply_target` result for a backup or write
    (``step``) that raised (``target`` unchanged; ``backup`` is reported when
    one was made)."""
    note = f"; backup: {backup}" if backup is not None else ""
    return (
        AgentStatus.UNKNOWN_STATE_FAIL_CLOSED,
        f"{AGENT_NAME} [{label}]: {step} failed ({exc}); {target} was left as it was{note}",
        _fail_closed_block(target),
        backup,
    )


def _apply_target(
    label: str, target: Path, entry: Mapping[str, Any], confirmed: bool
) -> tuple[AgentStatus, str, str, Path | None]:
    """Write one ``mcp.json`` target after confirmation.

    Returns ``(status, summary sentence, printed config block, backup path)``
    where the backup path is set only when an existing file was backed up
    before being rewritten (even if that rewrite then failed). Refuses to
    write when ``confirmed`` is False; creates a timestamped ``.bak`` before
    the first write to an existing file; never duplicates an existing
    equivalent registration.
    """
    status = _registration_status(target, entry)
    if status is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED:
        return (
            status,
            _describe(status, target, label, entry),
            _fail_closed_block(target),
            None,
        )
    if status is AgentStatus.CONFIGURED:
        return (status, _describe(status, target, label, entry), "", None)

    if not confirmed:
        return (
            status,
            f"{_describe(status, target, label, entry)} (not applied: confirmation refused)",
            _desired_block(entry),
            None,
        )

    if target.exists():
        # Re-check at write time: classify the exact bytes about to be
        # merged, so a registration that appeared under our server key
        # between the status check above and this write is never silently
        # overwritten — fail closed unless the file still reads as
        # unconfigured for this server.
        data, _error = load_json_or_fail_closed(target)
        if data is None or _classify_data(data, entry) is not AgentStatus.INSTALLED_UNCONFIGURED:
            return (
                AgentStatus.UNKNOWN_STATE_FAIL_CLOSED,
                f"{AGENT_NAME} [{label}]: {target} changed state; refusing to write",
                _fail_closed_block(target),
                None,
            )
        # An mcp.json without a "servers" key is INSTALLED_UNCONFIGURED, not an
        # error: {} , a file carrying only "inputs", or one copied from another
        # client all reach here and used to raise KeyError, which the CLI
        # reported as a fail-closed write blaming the user's file.
        servers = data.get(SERVERS_KEY) or {}
        try:
            ensure_replaceable(target)  # refused before the backup, so none is left behind
        except OSError as exc:
            return _write_failed(label, f"writing {target}", target, exc, None)
        backup = backup_path(target)
        try:
            write_private_backup(target, backup)
        except OSError as exc:
            return _write_failed(label, f"backing up {target} to {backup}", target, exc, None)
        merged_servers = dict(servers)
        merged_servers[SERVER_KEY] = dict(entry)
        data[SERVERS_KEY] = merged_servers
        try:
            atomic_write_text(target, json.dumps(data, indent=2, sort_keys=True) + "\n")
        except OSError as exc:
            return _write_failed(label, f"writing {target}", target, exc, backup)
        return (
            AgentStatus.CONFIGURED,
            f'{AGENT_NAME} [{label}]: added "{SERVER_KEY}" to {target} (backup: {backup})',
            _desired_block(entry),
            backup,
        )

    try:
        ensure_directory(target.parent)
        # Found absent: only ever created, so one that appeared meanwhile fails closed.
        atomic_write_text(target, _desired_block(entry) + "\n", create=True)
    except OSError as exc:
        return _write_failed(label, f"writing {target}", target, exc, None)
    return (
        AgentStatus.CONFIGURED,
        f'{AGENT_NAME} [{label}]: created {target} with "{SERVER_KEY}"',
        _desired_block(entry),
        None,
    )


def apply(
    env: Mapping[str, str],
    home: Path,
    confirmed: bool,
    platform: str | None = None,
    workspace: Path | None = None,
) -> Plan:
    """Write the registration after explicit confirmation.

    Refuses to write when ``confirmed`` is False (the CLI layer owns the
    interactive y/n prompt and the ``--yes`` flag). The user profile is only
    touched when VS Code is detected; a ``workspace`` is only touched when
    its ``.vscode`` directory already exists. If any managed target is
    malformed, nothing is written anywhere (fail closed). Every first write
    to an existing file is preceded by a timestamped ``.bak`` copy, and
    re-runs are idempotent.
    """
    target = config_path(home, platform, env=env)
    installed = install_marker(home, platform, env=env).is_dir()

    # Resolve every active target up front so a malformed file anywhere
    # fails the whole operation closed before anything is written.
    active: list[tuple[str, Path]] = []
    if installed:
        active.append(("user profile", target))
    if workspace is not None and (workspace / WORKSPACE_DIR_NAME).is_dir():
        active.append(("workspace", workspace_config_path(workspace)))
    if not active:
        return plan(env, home, platform=platform, workspace=workspace)  # not installed: nothing to resolve
    entry = registration_entry(env, home)
    if any(
        _registration_status(path, entry) is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
        for _label, path in active
    ):
        # Malformed/unreadable existing config: report, never write.
        return plan(env, home, platform=platform, workspace=workspace)

    statuses: list[AgentStatus] = []
    sentences: list[str] = []
    blocks: list[str] = []
    paths: list[Path] = [target]
    backups: list[Path] = []

    if installed:
        status, sentence, block, backup = _apply_target("user profile", target, entry, confirmed)
        if backup is not None:
            backups.append(backup)
    else:
        status = AgentStatus.NOT_INSTALLED
        sentence = (
            f"{AGENT_NAME} [user profile]: not installed "
            f"({install_marker(home, platform, env=env)} does not exist); nothing would be written"
        )
        block = ""
    statuses.append(status)
    sentences.append(sentence)
    blocks.append(block)

    if workspace is not None:
        ws_path = workspace_config_path(workspace)
        if (workspace / WORKSPACE_DIR_NAME).is_dir():
            paths.append(ws_path)
            ws_status, ws_sentence, ws_block, ws_backup = _apply_target("workspace", ws_path, entry, confirmed)
            if ws_backup is not None:
                backups.append(ws_backup)
            statuses.append(ws_status)
            sentences.append(ws_sentence)
            blocks.append(ws_block)
        else:
            sentences.append(
                f"{AGENT_NAME}: workspace {workspace} has no "
                f"{WORKSPACE_DIR_NAME} directory; workspace configuration skipped"
            )

    return Plan(
        agent=AGENT_NAME,
        status=_combine(statuses),
        config_path=target,
        config_paths=tuple(paths),
        backup_paths=tuple(backups),
        summary="; ".join(sentences) + _unisolated_notes(paths),
        config_block="\n\n".join(b for b in blocks if b),
        entry=dict(entry),
    )
