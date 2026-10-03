"""Registry of agent-harness adapters for ``universal_db_mcp configure-agents``.

Adapter modules are loaded lazily (``importlib``) so a missing or broken
adapter file degrades to a per-harness ``AgentConfigError`` report instead of
breaking the whole command. The registry normalizes the two adapter calling
conventions into one interface for the CLI layer:

* JSON-config harnesses (``claude-code``, ``claude-desktop``, ``cursor``,
  ``vscode``, ``cline``) expose ``detect(env, home) -> AgentStatus``,
  ``plan(env, home) -> Plan`` and ``apply(env, home, confirmed) -> Plan``.
* The dsh harness is generated-config/YAML and keys on ``~/.dsh`` instead of
  ``(env, home)``; its ``apply`` returns an ``ApplyResult`` which is
  normalized into a :class:`~universal_db_mcp.agents.core.Plan` here.

The registry never writes anything itself and holds no state; every write
goes through an adapter's ``apply(confirmed=True)`` after the CLI layer has
obtained explicit user confirmation.
"""

from __future__ import annotations

import importlib
from pathlib import Path
from typing import Any, cast

from universal_db_mcp.agents.core import AgentConfigError, AgentStatus, Plan

#: Canonical harness names, in the order the CLI presents them.
HARNESS_NAMES: tuple[str, ...] = (
    "claude-code",
    "claude-desktop",
    "dsh",
    "cursor",
    "vscode",
    "cline",
)

#: Harness name -> adapter module (imported lazily by :func:`load_adapter`).
ADAPTER_MODULES: dict[str, str] = {
    "claude-code": "universal_db_mcp.agents.claude_code",
    "claude-desktop": "universal_db_mcp.agents.claude_desktop",
    "dsh": "universal_db_mcp.agents.dsh",
    "cursor": "universal_db_mcp.agents.cursor",
    "vscode": "universal_db_mcp.agents.vscode",
    "cline": "universal_db_mcp.agents.cline",
}

_DSH_HOME_DIRNAME = ".dsh"


def load_adapter(name: str) -> Any:
    """Import and return the adapter module for ``name``.

    Raises :class:`AgentConfigError` when the name is unknown or the module
    cannot be imported, so callers fail closed with a clear message instead
    of a traceback.
    """
    module_name = ADAPTER_MODULES.get(name)
    if module_name is None:
        raise AgentConfigError(
            f"no adapter registered for agent {name!r}; known agents: {', '.join(HARNESS_NAMES)}"
        )
    try:
        return importlib.import_module(module_name)
    except ImportError as exc:
        raise AgentConfigError(
            f"adapter module {module_name!r} for agent {name!r} is not available: {exc}"
        ) from exc


def _dsh_home(home: Path) -> Path:
    return home / _DSH_HOME_DIRNAME


def detect_status(name: str, env: Any, home: Path) -> AgentStatus:
    """Normalized ``detect`` for one harness (never writes)."""
    mod = load_adapter(name)
    if name == "dsh":
        return cast(AgentStatus, mod.detect(_dsh_home(home)))
    return cast(AgentStatus, mod.detect(env, home))


def build_plan(name: str, env: Any, home: Path) -> Plan:
    """Normalized ``plan`` for one harness (never writes)."""
    mod = load_adapter(name)
    if name == "dsh":
        return cast(Plan, mod.plan(_dsh_home(home)))
    return cast(Plan, mod.plan(env, home))


def registered_config_path(name: str, env: Any, home: Path) -> str | None:
    """The config path the CONFIGURED registration of ``name`` names (never
    writes). A JSON harness is configured only when its entry equals the one
    this environment would write, so that is the path this environment
    advertises; dsh counts its row as configured whatever config it names,
    so its row is read."""
    from universal_db_mcp.agents.core import resolve_harness_config_path

    if name == "dsh":
        return cast("str | None", load_adapter(name).registered_config_path(_dsh_home(home)))
    return resolve_harness_config_path(env, home, for_harness=True)


def apply_confirmed(name: str, env: Any, home: Path, confirmed: bool) -> Plan:
    """Normalized ``apply`` for one harness.

    ``confirmed`` must come from the CLI layer's explicit confirmation
    (``--yes`` or an interactive ``y`` answer); adapters refuse unconfirmed
    calls. The dsh adapter's ``ApplyResult`` is converted to a :class:`Plan`
    so the CLI prints one uniform result shape.
    """
    mod = load_adapter(name)
    if name != "dsh":
        return cast(Plan, mod.apply(env, home, confirmed))

    target = _dsh_home(home) / mod.PATCH_FILENAME
    result = mod.apply(_dsh_home(home), confirmed)
    backups: tuple[Path, ...] = ()
    backup = getattr(result, "backup_path", None)
    if backup is not None:
        backups = (backup,)
    return Plan(
        agent=getattr(result, "agent", name),
        config_path=target,
        status=cast(AgentStatus, result.status_after),
        summary=result.message,
        backup_paths=backups,
    )
