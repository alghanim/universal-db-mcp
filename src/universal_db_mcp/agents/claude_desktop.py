"""Claude Desktop adapter: register the universal-db MCP server.

Claude Desktop (the Anthropic desktop app) stores MCP registrations in
``claude_desktop_config.json`` under the top-level ``mcpServers`` key. The
config directory is platform-specific:

* macOS:   ``~/Library/Application Support/Claude/``
* Windows: ``%APPDATA%\\Claude\\``
* Linux:   ``~/.config/Claude/`` (unofficial builds)

Detection counts Claude Desktop as installed when any of these hold: one of
the platform config directories exists, the app bundle is present (macOS:
``/Applications/Claude.app`` or ``~/Applications/Claude.app``; Windows:
``%LOCALAPPDATA%\\AnthropicClaude``). When several platform locations exist,
the one already holding a config file wins; otherwise the platform-canonical
location is used.

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

Fail-closed rules implemented here (shared by every adapter):

- ``apply`` only writes when ``confirmed=True`` (the CLI layer owns the
  interactive y/n prompt and the ``--yes`` / ``--dry-run`` flags); with
  ``confirmed=False`` nothing is ever written.
- Every first write to an existing config is preceded by a timestamped
  ``.bak`` copy (a brand-new file needs no backup).
- Re-runs are idempotent: an existing equivalent registration is never
  duplicated or rewritten.
- An existing config that is unreadable, malformed, not a JSON object, has a
  non-object ``mcpServers``, or holds a *differing* entry under our server
  key yields ``AgentStatus.UNKNOWN_STATE_FAIL_CLOSED``: the offending file's
  raw bytes are printed and nothing is written.
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

AGENT_NAME = "claude-desktop"
SERVER_KEY = "universal-db"
MCP_SERVERS_KEY = "mcpServers"
CONFIG_DIR_NAME = "Claude"
CONFIG_FILE_NAME = "claude_desktop_config.json"

VENV_PYTHON_ENV = "UDBMCP_VENV_PYTHON"
UDBMCP_CONFIG_ENV = "UDBMCP_CONFIG"

# Canonical air-gapped deployment location (see docs/offline-deployment.md).
SYSTEM_CONFIG_PATH = Path("/etc/universal-db-mcp/config.yaml")

# App-bundle markers outside HOME (monkeypatched to () in tests for hermeticity).
SYSTEM_APP_PATHS: tuple[Path, ...] = (Path("/Applications/Claude.app"),) if sys.platform == "darwin" else ()

# Hard allowlist for the written registration (no secrets may sneak in).
_ALLOWED_ENTRY_KEYS = frozenset({"command", "args", "env"})
_ALLOWED_ENTRY_ENV_KEYS = frozenset({UDBMCP_CONFIG_ENV})


# ---------------------------------------------------------------------------
# Platform paths
# ---------------------------------------------------------------------------


def _windows_config_dir(env: Mapping[str, str], home: Path) -> Path:
    appdata = env.get("APPDATA", "").strip()
    base = Path(appdata) if appdata else home / "AppData" / "Roaming"
    return base / CONFIG_DIR_NAME


def _macos_config_dir(home: Path) -> Path:
    return home / "Library" / "Application Support" / CONFIG_DIR_NAME


def _linux_config_dir(home: Path) -> Path:
    return home / ".config" / CONFIG_DIR_NAME


def _candidate_dirs(env: Mapping[str, str], home: Path) -> list[Path]:
    """Platform-canonical config dir first, then the other platforms' locations."""
    if sys.platform == "win32":
        ordered = [_windows_config_dir(env, home), _macos_config_dir(home), _linux_config_dir(home)]
    elif sys.platform == "darwin":
        ordered = [_macos_config_dir(home), _windows_config_dir(env, home), _linux_config_dir(home)]
    else:
        ordered = [_linux_config_dir(home), _macos_config_dir(home), _windows_config_dir(env, home)]
    unique: list[Path] = []
    for d in ordered:
        if d not in unique:
            unique.append(d)
    return unique


def config_path(env: Mapping[str, str], home: Path) -> Path:
    """Active ``claude_desktop_config.json`` path for the given HOME/env.

    The first platform location that already holds the config file wins;
    otherwise the platform-canonical location is used (the file may not exist
    yet and would be created there).
    """
    candidates = _candidate_dirs(env, home)
    for d in candidates:
        if (d / CONFIG_FILE_NAME).is_file():
            return d / CONFIG_FILE_NAME
    return candidates[0] / CONFIG_FILE_NAME


def _app_installed(env: Mapping[str, str], home: Path) -> bool:
    """True when Claude Desktop (or at least its config state) is present."""
    if any(d.is_dir() for d in _candidate_dirs(env, home)):
        return True
    if any(p.exists() for p in SYSTEM_APP_PATHS):
        return True
    if sys.platform == "darwin" and (home / "Applications" / "Claude.app").exists():
        return True
    if sys.platform == "win32":
        local = env.get("LOCALAPPDATA", "").strip()
        base = Path(local) if local else home / "AppData" / "Local"
        if (base / "AnthropicClaude").exists():
            return True
    return False


# ---------------------------------------------------------------------------
# Registration entry (the only bytes we ever write)
# ---------------------------------------------------------------------------


def _venv_python(env: Mapping[str, str]) -> str:
    """Interpreter for the launch command: ``UDBMCP_VENV_PYTHON`` override,
    else the interpreter running this CLI (the venv python in an install)."""
    override = env.get(VENV_PYTHON_ENV, "").strip()
    if override:
        return override
    return sys.executable


def _udbmcp_config_path(env: Mapping[str, str], home: Path) -> str:
    """Config path advertised via ``UDBMCP_CONFIG``. Never a secret.

    Delegates to the shared resolver (agents.core): harness spawns run as the
    logged-in USER, so the advertised path must be readable by them - the
    system deployment is service-account owned (0640 root:_udbmcp) and is
    not. Unreadable-system spawns died right after connecting (seen live
    2026-09-14); the resolver falls back to the per-user config, which
    ``configure-agents`` seeds on apply."""
    return resolve_harness_config_path(env, home)


def registration_entry(env: Mapping[str, str], home: Path) -> dict[str, Any]:
    """The exact dict written under ``mcpServers`` (contains no secrets)."""
    entry: dict[str, Any] = {
        "command": _venv_python(env),
        "args": ["-m", "universal_db_mcp", "serve", "--transport", "stdio"],
        "env": {UDBMCP_CONFIG_ENV: _udbmcp_config_path(env, home)},
    }
    _assert_no_secrets(entry)
    return entry


def _assert_no_secrets(entry: Mapping[str, Any]) -> None:
    """Hard guarantee: the registration carries no secret material."""
    unexpected = set(entry) - _ALLOWED_ENTRY_KEYS
    if unexpected:
        raise RuntimeError(
            f"claude-desktop adapter: refusing to write unexpected registration keys: {sorted(unexpected)}"
        )
    env_keys = set(entry.get("env", {}))
    if env_keys - _ALLOWED_ENTRY_ENV_KEYS:
        raise RuntimeError(f"claude-desktop adapter: refusing to write non-allowlisted env keys: {sorted(env_keys)}")


def _entries_equal(existing: Any, desired: Mapping[str, Any]) -> bool:
    return isinstance(existing, dict) and existing == dict(desired)


def _intended_block(entry: Mapping[str, Any]) -> str:
    """The exact JSON that would be added, pretty-printed."""
    return json.dumps({MCP_SERVERS_KEY: {SERVER_KEY: dict(entry)}}, indent=2, sort_keys=True)


def _fail_closed_block(target: Path) -> str:
    """Render the offending file's current bytes for operator inspection."""
    try:
        raw = target.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return f"# {target} could not be read: {exc}"
    return f"# current contents of {target}:\n{raw}"


# ---------------------------------------------------------------------------
# Public adapter API
# ---------------------------------------------------------------------------


def detect(env: Mapping[str, str], home: Path) -> AgentStatus:
    """Classify the Claude Desktop harness state without writing anything.

    - ``not_installed``: no config directory and no app bundle found.
    - ``configured``: the config parses and already holds an equivalent
      ``universal-db`` registration.
    - ``installed_unconfigured``: the config is absent, or parses and lacks
      our entry (other keys and servers are preserved on apply).
    - ``unknown_state_fail_closed``: the config is unreadable/malformed/not a
      JSON object, ``mcpServers`` is present but not an object (including an
      explicit JSON null), or our key holds a differing entry (operator state
      we must not silently rewrite).
    """
    if not _app_installed(env, home):
        return AgentStatus.NOT_INSTALLED

    target = config_path(env, home)
    if not target.exists():
        return AgentStatus.INSTALLED_UNCONFIGURED

    data, _error = load_json_or_fail_closed(target)
    if data is None:
        return AgentStatus.UNKNOWN_STATE_FAIL_CLOSED

    if MCP_SERVERS_KEY in data:
        # A present-but-non-object ``mcpServers`` (including an explicit JSON
        # null) is unrecognized operator state: fail closed rather than
        # conflate it with an absent key.
        servers = data[MCP_SERVERS_KEY]
        if not isinstance(servers, dict):
            return AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    else:
        servers = {}

    if SERVER_KEY in servers and not _entries_equal(servers[SERVER_KEY], registration_entry(env, home)):
        return AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    if SERVER_KEY in servers:
        return AgentStatus.CONFIGURED
    return AgentStatus.INSTALLED_UNCONFIGURED


def plan(env: Mapping[str, str], home: Path) -> Plan:
    """Describe exactly what would be added to ``claude_desktop_config.json``."""
    target = config_path(env, home)
    status = detect(env, home)
    entry = registration_entry(env, home)

    if status is AgentStatus.NOT_INSTALLED:
        summary = (
            f"{AGENT_NAME}: not installed (no Claude config directory and no "
            "Claude app bundle found); nothing would be written"
        )
        block = ""
    elif status is AgentStatus.CONFIGURED:
        summary = (
            f"{AGENT_NAME}: already configured in {target} under "
            f'"{MCP_SERVERS_KEY}"["{SERVER_KEY}"]; no changes needed'
        )
        block = ""
    elif status is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED:
        summary = (
            f"{AGENT_NAME}: {target} is unreadable, malformed, or holds "
            "unrecognized state; refusing to write (fix or remove the file, "
            "then re-run)"
        )
        block = _fail_closed_block(target)
    else:
        if target.exists():
            summary = (
                f"{AGENT_NAME}: would back up {target} to a timestamped .bak "
                f"({target.name}.bak.<YYYYmmddTHHMMSSffffffZ>), then add "
                f'"{SERVER_KEY}" under "{MCP_SERVERS_KEY}" (all other existing '
                "keys preserved)"
            )
        else:
            summary = (
                f"{AGENT_NAME}: would create {target} with \"{SERVER_KEY}\" "
                f'under "{MCP_SERVERS_KEY}" (no existing file to back up)'
            )
        block = _intended_block(entry)

    return Plan(
        agent=AGENT_NAME,
        config_path=target,
        status=status,
        summary=summary,
        config_block=block,
        entry=dict(entry),
    )


def apply(env: Mapping[str, str], home: Path, confirmed: bool) -> Plan:
    """Write the registration after explicit confirmation.

    Refuses to write when ``confirmed`` is False (the CLI layer owns the
    interactive y/n prompt and the ``--yes`` flag). Creates a timestamped
    ``.bak`` of an existing config before the first write, never duplicates
    an existing equivalent registration, and never touches a malformed or
    unrecognized config (fail closed).
    """
    status = detect(env, home)

    if status is AgentStatus.NOT_INSTALLED:
        return plan(env, home)
    if status is AgentStatus.CONFIGURED:
        return plan(env, home)
    if status is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED:
        # Malformed/unreadable/unrecognized existing config: report, never write.
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
    target = config_path(env, home)

    if target.exists():
        data, _error = load_json_or_fail_closed(target)
        if data is None:
            # Re-check at write time: fail closed rather than overwrite.
            return plan(env, home)
        servers = data.get(MCP_SERVERS_KEY)
        # A present-but-non-object ``mcpServers`` (including JSON null) fails
        # closed; only a genuinely absent key is filled in below.
        if MCP_SERVERS_KEY in data and not isinstance(servers, dict):
            return plan(env, home)
        if isinstance(servers, dict) and SERVER_KEY in servers and _entries_equal(servers[SERVER_KEY], entry):
            return plan(env, home)  # idempotent no-op
        backup = backup_path(target)
        shutil.copy2(target, backup)
        if not isinstance(servers, dict):
            servers = {}
        servers[SERVER_KEY] = dict(entry)
        data[MCP_SERVERS_KEY] = servers
        payload = json.dumps(data, indent=2, sort_keys=True) + "\n"
        summary = f"{AGENT_NAME}: added \"{SERVER_KEY}\" to {target} (backup: {backup})"
    else:
        backup = None
        payload = json.dumps({MCP_SERVERS_KEY: {SERVER_KEY: dict(entry)}}, indent=2, sort_keys=True) + "\n"
        summary = f"{AGENT_NAME}: created {target} with \"{SERVER_KEY}\""

    # Verification gate: never write bytes we cannot parse back.
    json.loads(payload)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(payload, encoding="utf-8")

    return Plan(
        agent=AGENT_NAME,
        config_path=target,
        status=AgentStatus.CONFIGURED,
        summary=summary,
        config_block=_intended_block(entry),
        entry=dict(entry),
    )
