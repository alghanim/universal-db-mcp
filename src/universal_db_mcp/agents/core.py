"""Agent-harness registration adapters (``universal_db_mcp configure-agents``).

Each adapter module detects one installed AI-agent harness on the local
machine and, after explicit confirmation at the CLI layer, registers the
universal-db MCP server into that harness's config file. Shared primitives
live here so every adapter behaves identically:

* :class:`AgentStatus` — the four fail-closed-aware states.
* :class:`Plan` — a printable description of exactly what would be added.
* :func:`backup_path` — timestamped ``.bak`` sibling path.
* :func:`load_json_or_fail_closed` — parse-or-report helper that never
  raises and never silently overwrites malformed user state.
* :func:`load_yaml_or_fail_closed` — the same fail-closed contract for
  YAML-config harnesses.
* :class:`AgentConfigError` — typed fail-closed error for infrastructure
  problems (e.g. an adapter module that cannot be imported).

``Plan`` is a superset of the fields used by the individual adapters
(single- vs multi-file harnesses, JSON vs generated-config harnesses);
adapters populate only the fields that apply to them.
"""

from __future__ import annotations

import enum
import json
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class AgentConfigError(Exception):
    """Fail-closed error in the agent-registration infrastructure itself.

    Raised by the adapter registry (for example when an adapter module cannot
    be imported). This is distinct from a harness's ``unknown_state_fail_closed``
    status: an :class:`AgentConfigError` means the CLI cannot even evaluate the
    harness, so it reports the problem and never writes to that harness.
    """


class AgentStatus(enum.Enum):
    """State of one agent harness on this machine."""

    NOT_INSTALLED = "not_installed"
    INSTALLED_UNCONFIGURED = "installed_unconfigured"
    CONFIGURED = "configured"
    UNKNOWN_STATE_FAIL_CLOSED = "unknown_state_fail_closed"


@dataclass(frozen=True)
class Plan:
    """What an adapter would do / did, for printing at the CLI layer.

    Common fields (every adapter sets ``agent`` and ``status``):

    * ``agent`` — adapter name (``"cline"``, ``"cursor"``, ...).
    * ``status`` — the detected / resulting :class:`AgentStatus`.
    * ``config_path`` — the primary config file (single-file harnesses).
    * ``summary`` / ``description`` — human-readable explanation.
    * ``config_block`` / ``block`` — the exact bytes that would be added,
      pretty-printed; empty when no write would happen. In a fail-closed
      state this carries the operator-inspection block instead.
    * ``entry`` / ``server_block`` — the dict written under the harness's
      ``mcpServers`` key; never contains secrets.

    Multi-file harnesses (e.g. Claude Code's user + project scopes) use the
    plural ``config_paths`` / ``backup_paths``; ``action`` describes the
    write mode for generated-config harnesses (``"none"``,
    ``"append-registration"``, ...).
    """

    agent: str
    status: AgentStatus
    config_path: Path | None = None
    config_paths: tuple[Path, ...] = ()
    backup_paths: tuple[Path, ...] = ()
    action: str = ""
    summary: str = ""
    description: str = ""
    config_block: str = ""
    block: str = ""
    entry: dict[str, Any] = field(default_factory=dict)
    server_block: dict[str, Any] = field(default_factory=dict)


def backup_path(target: Path) -> Path:
    """Timestamped sibling backup path for ``target`` (never overwrites)."""
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    return target.parent / f"{target.name}.bak.{stamp}"


def load_json_or_fail_closed(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    """Read ``path`` as a JSON object, reporting problems instead of raising.

    Returns ``(data, None)`` on success or ``(None, reason)`` when the file
    is missing, unreadable, malformed, or not a JSON object. Callers treat
    the failure case as fail-closed: report, never overwrite.
    """
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None, f"{path} does not exist"
    except (OSError, UnicodeDecodeError) as exc:
        return None, f"{path} could not be read: {exc}"
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        return None, f"{path} is not valid JSON: {exc}"
    if not isinstance(data, dict):
        return None, f"{path} does not contain a JSON object at the top level"
    return data, None


def load_yaml_or_fail_closed(path: Path) -> tuple[Any | None, str | None]:
    """Read ``path`` as YAML, reporting problems instead of raising.

    Same fail-closed contract as :func:`load_json_or_fail_closed`: returns
    ``(data, None)`` on success or ``(None, reason)`` when the file is
    missing, unreadable, or malformed. Unlike the JSON helper, the top-level
    document is returned as-is (YAML harness configs may legitimately be
    sequences, e.g. the dsh patch layer).
    """
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None, f"{path} does not exist"
    except (OSError, UnicodeDecodeError) as exc:
        return None, f"{path} could not be read: {exc}"
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover — PyYAML is a hard dependency
        return None, f"PyYAML is not available: {exc}"
    try:
        data = yaml.safe_load(raw)
    except Exception as exc:
        return None, f"{path} is not valid YAML: {exc}"
    return data, None


# ---------------------------------------------------------------------------
# per-user harness config resolution + seeding
# ---------------------------------------------------------------------------

# The root-owned system deployment. It belongs to the launchd/systemd service
# account (mode 0640, group = service account) and is NOT readable by a normal
# user - harness (stdio) spawns run as the logged-in user and died right after
# connecting with "Permission denied" when pointed at it (seen live
# 2026-09-14). Resolution therefore checks READABILITY, not mere existence.
SYSTEM_CONFIG_PATH = Path("/etc/universal-db-mcp/config.yaml")
PER_USER_CONFIG_DIR = ".universal-db-mcp"

_SEED_CONFIG_TEMPLATE = """\
# Per-user configuration for universal-db-mcp harness (stdio) spawns, seeded
# by `configure-agents`: the root-owned system deployment
# (/etc/universal-db-mcp/config.yaml) belongs to the launchd/systemd service
# account and is NOT readable by your user, so personal spawns get their own
# config and state. Add connections below (secrets are referenced via
# *_env / password_file, never inlined) and validate with:
#   universal_db_mcp doctor --config {config_path}
application:
  transport: stdio
  metadata_cache_path: {metadata_path}
  audit_path: {audit_path}
"""


def resolve_harness_config_path(env: Mapping[str, str], home: Path) -> str:
    """Config path advertised to a per-user harness (stdio) spawn.

    Harness spawns run AS THE LOGGED-IN USER, so the advertised path must be
    readable by that user. Resolution order: explicit ``UDBMCP_CONFIG`` from
    the current environment (the operator's override - their responsibility),
    then the system deployment when it exists AND is readable, then the
    per-user default (which :func:`ensure_per_user_harness_config` seeds on
    apply).
    """
    from_env = env.get("UDBMCP_CONFIG", "").strip()
    if from_env:
        return from_env
    if SYSTEM_CONFIG_PATH.is_file() and os.access(SYSTEM_CONFIG_PATH, os.R_OK):
        return str(SYSTEM_CONFIG_PATH)
    return str(home / PER_USER_CONFIG_DIR / "config.yaml")


def ensure_per_user_harness_config(
    env: Mapping[str, str], home: Path
) -> tuple[Path | None, str]:
    """Seed the per-user harness config when the advertised path needs it.

    Only-if-absent: an existing per-user config is never clobbered. Returns
    ``(created_path, note)``; ``created_path`` is None when the advertised
    config needs no seeding (explicit env override, readable system
    deployment, or the per-user file already exists).
    """
    advertised = resolve_harness_config_path(env, home)
    per_user = home / PER_USER_CONFIG_DIR / "config.yaml"
    if advertised != str(per_user):
        return None, f"advertised config needs no seeding ({advertised})"
    if per_user.is_file():
        return None, "per-user config already present (left untouched)"
    parent = per_user.parent
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    per_user.write_text(
        _SEED_CONFIG_TEMPLATE.format(
            config_path=per_user,
            metadata_path=parent / "metadata.sqlite",
            audit_path=parent / "audit.jsonl",
        ),
        encoding="utf-8",
    )
    os.chmod(per_user, 0o600)
    return per_user, "seeded per-user config (0600; state and audit are per-user)"
