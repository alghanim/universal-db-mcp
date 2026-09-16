"""Adapter: register the Universal Database MCP server into the dsh harness.

dsh (DeepSeek harness) stores user-level MCP patches in ``~/.dsh/cordis.patch.yml``
and harness state in ``~/.dsh/settings.yaml`` (plus ``profiles/``, ``sessions/``,
``storages/``). The patch file is a YAML *sequence* of patch rows. The only
reliable way to ADD a server is the ``- insert:`` form; a plain ``- id:`` row is
an OVERRIDE of an existing entry and fails with entry-not-found. This module
therefore always writes the ``- insert:`` shape (verified against a live
``cordis.patch.yml`` on a working machine).

Shared-core contract (``universal_db_mcp.agents.core``):

- ``AgentStatus`` -- Enum with exactly the members ``NOT_INSTALLED``,
  ``INSTALLED_UNCONFIGURED``, ``CONFIGURED``, ``UNKNOWN_STATE_FAIL_CLOSED``.
- ``Plan`` -- frozen dataclass: ``agent: str``, ``config_path: Path``,
  ``status: AgentStatus``, ``summary: str``, ``config_block: str`` (the exact
  bytes that would be added; empty when no write would happen) and
  ``entry: dict`` (the logical registration entry; never contains secrets).
- ``backup_path(target: Path) -> Path`` -- timestamped sibling
  ``<target>.bak.<UTC stamp>`` for the pre-write backup (never overwrites).
- ``load_json_or_fail_closed()`` -- for JSON-config harnesses. dsh configs are
  YAML, so this adapter uses its own fail-closed YAML loader
  (:func:`_load_patch`) instead: it never raises on malformed input and the
  caller reports ``unknown_state_fail_closed``.

Security posture (hard rules):
- No secrets are ever written: the registration row contains only the venv
  python launch command, the ``UDBMCP_CONFIG`` path and ``failOnStartupError``.
- A timestamped ``.bak`` of the patch file is written before the first
  modification of an existing file (nothing to back up when creating it).
- ``apply(confirmed=False)`` never writes; the CLI layer owns the interactive
  y/n prompt and passes explicit confirmation through.
- Malformed or unrecognized harness state fails closed: the existing config
  block is reported (via :func:`plan` / :class:`ApplyResult`) and nothing is
  written.
- Re-runs are idempotent: an existing registration (matched by id, regardless
  of its env keys) is reported as already-configured, never duplicated.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from universal_db_mcp.agents.core import (
    AgentStatus,
    Plan,
    backup_path,
    resolve_harness_config_path,
)

AGENT_NAME = "dsh"
PATCH_FILENAME = "cordis.patch.yml"
SETTINGS_FILENAME = "settings.yaml"
REGISTRATION_ID = "mcp-universal-db"
SERVER_NAME = "udb"
CLIENT_NAME = "@deepseek-ai/dsh-mcp-client"

# Files/directories whose presence identifies a real dsh home. An existing but
# completely unrecognized (non-empty) ~/.dsh is treated as unknown state and
# fails closed rather than being written into.
DSH_HOME_MARKERS = (
    SETTINGS_FILENAME,
    PATCH_FILENAME,
    "database-connections.json",
    "profiles",
    "sessions",
    "storages",
    "attachments",
)

_NEW_FILE_HEADER = (
    "# dsh patch layer (partially managed by 'universal_db_mcp configure-agents').\n"
    "# Existing rows are preserved; this file is a YAML sequence of patch rows.\n"
)

# Plain YAML scalars that need no quoting: alphanumerics, common path
# characters, spaces. Anything else is emitted double-quoted (JSON-compatible).
_PLAIN_SCALAR_SAFE = re.compile(r"[A-Za-z0-9_@/.\- ]+")

_REGISTRATION_BLOCK_TEMPLATE = (
    "# Universal Database MCP server (air-gapped local build), registered by\n"
    "# 'universal_db_mcp configure-agents'. Its 25 tools appear to the model as\n"
    "# mcp__udb__<tool_name>.\n"
    "- insert:\n"
    "    - id: mcp-universal-db\n"
    "      name: '@deepseek-ai/dsh-mcp-client'\n"
    "      config:\n"
    "        serverName: udb\n"
    "        transport: stdio\n"
    "        command: {command}\n"
    "        args: ['-m', 'universal_db_mcp', 'serve', '--transport', 'stdio']\n"
    "        env:\n"
    "          UDBMCP_CONFIG: {config_path}\n"
    "        failOnStartupError: true\n"
)


@dataclass(frozen=True)
class ApplyResult:
    """Outcome of :func:`apply`; ``wrote`` is True only when bytes hit disk."""

    agent: str
    status_before: AgentStatus
    status_after: AgentStatus
    wrote: bool
    backup_path: Path | None
    message: str


# ---------------------------------------------------------------------------
# Environment resolution helpers (monkeypatched in tests).
# ---------------------------------------------------------------------------


def _resolve_python() -> str:
    """Absolute path to the python that runs this package (venv preferred)."""
    if sys.prefix != getattr(sys, "base_prefix", sys.prefix):
        exe = Path(sys.prefix) / ("python.exe" if sys.platform == "win32" else "bin/python")
        if exe.is_file():
            return str(exe)
    return sys.executable


def _resolve_config_path() -> str:
    """Non-secret path handed to the server via ``UDBMCP_CONFIG``.

    Order: explicit ``$UDBMCP_CONFIG``; otherwise a config file at the root of
    this checkout (editable install), preferring a real ``config.yaml`` over
    the bundled examples.
    """
    from_env = os.environ.get("UDBMCP_CONFIG")
    if from_env:
        return from_env
    # Editable-install dev case: a real config at the checkout root wins.
    root = Path(__file__).resolve().parents[3]
    for candidate in ("config.yaml", "config.mockdbs.yaml"):
        if (root / candidate).is_file():
            return str(root / candidate)
    # Installed case: the system deployment only when the USER can READ it
    # (harness spawns run as the user; the service-owned 0640 config killed
    # them right after connecting - seen live 2026-09-14), else the per-user
    # config that `configure-agents` seeds on apply. config.example.yaml is
    # no longer advertised: it is a documentation artifact, not runnable.
    return resolve_harness_config_path({}, Path.home())


def _yaml_scalar(value: str) -> str:
    """Render a string as a YAML scalar matching the live patch-file style.

    Plain (unquoted) scalars are used for ordinary paths (matching the working
    reference on a live machine); anything YAML-ambiguous falls back to a
    double-quoted, JSON-compatible scalar.
    """
    if _PLAIN_SCALAR_SAFE.fullmatch(value):
        return value
    return json.dumps(value)


def _registration_entry() -> dict[str, Any]:
    """The logical registration entry (never contains secrets)."""
    return {
        "id": REGISTRATION_ID,
        "name": CLIENT_NAME,
        "config": {
            "serverName": SERVER_NAME,
            "transport": "stdio",
            "command": _resolve_python(),
            "args": ["-m", "universal_db_mcp", "serve", "--transport", "stdio"],
            "env": {"UDBMCP_CONFIG": _resolve_config_path()},
            "failOnStartupError": True,
        },
    }


def _registration_block() -> str:
    """The exact bytes that would be added for the registration row.

    Derived from the same values as :func:`_registration_entry` so the printed
    block and the logical entry can never drift apart.
    """
    entry = _registration_entry()
    config = entry["config"]
    return _REGISTRATION_BLOCK_TEMPLATE.format(
        command=_yaml_scalar(config["command"]),
        config_path=_yaml_scalar(config["env"]["UDBMCP_CONFIG"]),
    )


# ---------------------------------------------------------------------------
# Fail-closed YAML loading (dsh configs are YAML, not JSON).
# ---------------------------------------------------------------------------


def _load_patch(patch: Path) -> tuple[Any, str | None]:
    """Parse ``cordis.patch.yml``; return ``(data, None)`` or ``(None, reason)``.

    Never raises: any read/parse/shape problem becomes a reason string so the
    caller can fail closed.
    """
    try:
        text = patch.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        return None, f"unreadable (not valid UTF-8): {exc}"
    except OSError as exc:
        return None, f"unreadable: {exc}"
    try:
        import yaml

        data = yaml.safe_load(text)
    except Exception as exc:  # yaml.YAMLError and any unexpected parser issue
        return None, f"malformed YAML: {exc}"
    if data is None:  # empty file: an empty patch sequence
        return [], None
    return data, None


def _scan_rows(data: Any) -> tuple[bool, bool, str | None]:
    """Scan patch rows. Returns ``(registered, broken_override, reason)``."""
    if not isinstance(data, list):
        return False, False, f"expected a YAML sequence at top level, found {type(data).__name__}"
    registered = False
    broken = False
    reason: str | None = None
    for index, row in enumerate(data):
        if not isinstance(row, dict):
            reason = f"row {index} is not a mapping"
            continue
        if "insert" in row:
            entries = row["insert"]
            if not isinstance(entries, list) or not all(isinstance(e, dict) for e in entries):
                reason = f"row {index} has a malformed 'insert' block"
                continue
            if any(e.get("id") == REGISTRATION_ID for e in entries):
                registered = True
        elif row.get("id") == REGISTRATION_ID:
            # Plain "- id:" is an override row; it fails with entry-not-found
            # for an id that was never inserted, and adding an insert row would
            # duplicate the id. Fail closed and ask for manual cleanup.
            broken = True
            reason = (
                f"an override-form row '- id: {REGISTRATION_ID}' exists; "
                "overrides fail with entry-not-found and block a clean insert"
            )
    return registered, broken, reason


def _looks_like_dsh(env_home: Path) -> bool:
    try:
        return any((env_home / marker).exists() for marker in DSH_HOME_MARKERS)
    except OSError:
        return False


def _dsh_cli_on_path() -> bool:
    return shutil.which("dsh") is not None


def _unknown_reason(patch: Path) -> str:
    """Best-effort human reason for an unknown-state fail-closed verdict."""
    data, reason = _load_patch(patch)
    if reason is not None:
        return reason
    _, _, row_reason = _scan_rows(data)
    return row_reason or "unrecognized dsh state"


# ---------------------------------------------------------------------------
# Public adapter API.
# ---------------------------------------------------------------------------


def detect(env_home: Path) -> Any:
    """Classify the dsh installation under ``env_home`` (typically ``~/.dsh``)."""
    patch = env_home / PATCH_FILENAME
    if patch.exists():
        data, reason = _load_patch(patch)
        if reason is not None:
            return AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
        if not isinstance(data, list):
            return AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
        registered, broken, _ = _scan_rows(data)
        if broken:
            return AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
        if registered:
            return AgentStatus.CONFIGURED
        return AgentStatus.INSTALLED_UNCONFIGURED
    if not env_home.is_dir():
        return AgentStatus.NOT_INSTALLED
    if _looks_like_dsh(env_home):
        return AgentStatus.INSTALLED_UNCONFIGURED
    try:
        empty = not any(env_home.iterdir())
    except OSError:
        empty = False
    if empty:
        if _dsh_cli_on_path():
            # A `dsh` binary exists and created a fresh, empty home: usable.
            return AgentStatus.INSTALLED_UNCONFIGURED
        # A bare, empty directory proves nothing about dsh; do not write into it.
        return AgentStatus.NOT_INSTALLED
    return AgentStatus.UNKNOWN_STATE_FAIL_CLOSED


def plan(env_home: Path) -> Plan:
    """Describe exactly what :func:`apply` would change, without changing it."""
    patch = env_home / PATCH_FILENAME
    status = detect(env_home)
    if status == AgentStatus.CONFIGURED:
        return Plan(
            agent=AGENT_NAME,
            config_path=patch,
            status=status,
            summary=(
                f"action=none: already configured; {patch} contains an insert row with "
                f"id {REGISTRATION_ID!r}; nothing to do"
            ),
            config_block="",
        )
    if status == AgentStatus.UNKNOWN_STATE_FAIL_CLOSED:
        if patch.exists():
            reason = _unknown_reason(patch)
            try:
                existing = patch.read_text(encoding="utf-8", errors="replace")
            except OSError:
                # The fail-closed report itself must never raise (e.g. the
                # patch path is a directory); report the reason without the
                # config-block dump instead.
                existing = "<existing config could not be read for display>"
            summary = (
                f"action=none (FAIL CLOSED): not modifying {patch} ({reason}). "
                "Manual review required; existing config block:\n" + existing
            )
        else:
            summary = (
                f"action=none (FAIL CLOSED): {env_home} exists but is not a recognizable dsh "
                f"home (no dsh markers among {', '.join(DSH_HOME_MARKERS)}); not writing."
            )
        return Plan(
            agent=AGENT_NAME,
            config_path=patch,
            status=status,
            summary=summary,
            config_block="",
        )
    if status == AgentStatus.NOT_INSTALLED:
        return Plan(
            agent=AGENT_NAME,
            config_path=patch,
            status=status,
            summary=(
                "action=none: dsh not detected under "
                f"{env_home} (no dsh home markers among {', '.join(DSH_HOME_MARKERS)}, "
                "no 'dsh' on PATH); nothing to do"
            ),
            config_block="",
        )
    # installed_unconfigured
    exists = patch.exists()
    block = _registration_block()
    size = len(block.encode("utf-8"))
    if exists:
        action = "append-registration"
        summary = (
            f"action={action}: would append {size} bytes to {patch} (after a timestamped "
            f"{patch.name}.bak.<UTC stamp> backup); existing rows preserved untouched."
        )
    else:
        action = "create-registration"
        summary = f"action={action}: would create {patch} ({size} bytes) with the registration row below."
    return Plan(
        agent=AGENT_NAME,
        config_path=patch,
        status=status,
        summary=summary + "\n" + block,
        config_block=block,
        entry=_registration_entry(),
    )


def apply(env_home: Path, confirmed: bool) -> ApplyResult:
    """Write the registration row, but only when ``confirmed`` is True.

    Refuses unconfirmed calls (the CLI layer owns the interactive y/n). Creates
    a timestamped ``.bak`` before modifying an existing patch file, preserves
    all pre-existing rows, verifies the merged document still parses BEFORE
    writing (fail closed without touching the file on any inconsistency), and
    is idempotent.
    """
    import yaml

    patch = env_home / PATCH_FILENAME
    status_before = detect(env_home)
    if not confirmed:
        return ApplyResult(
            AGENT_NAME, status_before, status_before, False, None,
            "refused: confirmed=False (adapter never writes without explicit confirmation)",
        )
    if status_before == AgentStatus.NOT_INSTALLED:
        return ApplyResult(
            AGENT_NAME, status_before, status_before, False, None,
            f"dsh not detected under {env_home}; nothing written",
        )
    if status_before == AgentStatus.CONFIGURED:
        return ApplyResult(
            AGENT_NAME, status_before, status_before, False, None,
            f"already configured: {patch} contains id {REGISTRATION_ID!r}; nothing written",
        )
    if status_before == AgentStatus.UNKNOWN_STATE_FAIL_CLOSED:
        detail = _unknown_reason(patch) if patch.exists() else "unrecognized dsh home"
        return ApplyResult(
            AGENT_NAME, status_before, status_before, False, None,
            f"FAIL CLOSED: {detail}; {patch} left untouched",
        )

    block = _registration_block()
    backup: Path | None = None
    if patch.exists():
        try:
            original = patch.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            # TOCTOU guard: the file changed/unreadable between detect() and
            # here. Fail closed; nothing has been written or backed up yet.
            return ApplyResult(
                AGENT_NAME, status_before, AgentStatus.UNKNOWN_STATE_FAIL_CLOSED,
                False, None,
                f"FAIL CLOSED: could not read {patch} ({exc}); nothing written",
            )
        backup = backup_path(patch)
        backup.write_text(original, encoding="utf-8")
        payload = original if (not original or original.endswith("\n")) else original + "\n"
        payload += block
    else:
        payload = _NEW_FILE_HEADER + block

    # Verification gate: the merged document must parse as a sequence that now
    # contains our registration. Otherwise roll back and fail closed.
    try:
        merged = yaml.safe_load(payload)
        registered, _, _ = _scan_rows(merged)
        if not isinstance(merged, list) or not registered:
            raise ValueError("merged patch file does not contain the registration row")
    except Exception as exc:
        # Verification runs BEFORE the write, so patch still holds the
        # original bytes; nothing to roll back, just fail closed.
        return ApplyResult(
            AGENT_NAME, status_before, AgentStatus.UNKNOWN_STATE_FAIL_CLOSED, False, backup,
            f"FAIL CLOSED: merged patch failed verification ({exc}); original content restored",
        )

    patch.write_text(payload, encoding="utf-8")
    status_after = detect(env_home)
    if status_after != AgentStatus.CONFIGURED:  # defensive: should not happen
        return ApplyResult(
            AGENT_NAME, status_before, status_after, True, backup,
            f"wrote {patch} but post-write verification is inconclusive; re-run detect",
        )
    verb = "appended registration row to" if backup is not None else "created"
    bak_note = f" (backup: {backup})" if backup is not None else ""
    return ApplyResult(
        AGENT_NAME, status_before, status_after, True, backup,
        f"{verb} {patch}{bak_note}",
    )
