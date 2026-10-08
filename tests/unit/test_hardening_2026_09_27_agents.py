"""Agent-registration (``configure-agents``) regressions from the 2026-09-27
security/production review.

Each section names the finding it pins:

* F45 - backups of a private harness config were created under the umask
  (0644 from a 0600 ``~/.claude.json``) and followed a symlink planted at the
  backup path.
* F46 - the registered ``python -m universal_db_mcp`` put the harness's
  working directory first on ``sys.path``, so a project's ``yaml.py`` or
  ``universal_db_mcp/`` ran inside the server process.
* F48 - config writes truncated the target in place, so a failed write left
  ``~/.claude.json`` (or ``~/.cursor/mcp.json``) empty.
* F58 - relative ``UDBMCP_CONFIG`` / ``UDBMCP_VENV_PYTHON`` values were copied
  into global registrations, so the open repository chose the config.
* F79 - VS Code and Cline ignored ``%APPDATA%`` and ``$XDG_CONFIG_HOME``;
  Claude Desktop ignored ``$XDG_CONFIG_HOME``.

Every test runs against fake HOME trees under ``tmp_path``.
"""

from __future__ import annotations

import errno
import json
import os
import shutil
import stat
import struct
import subprocess
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any, cast

import pytest
import yaml

import universal_db_mcp.agents as agents_pkg
from universal_db_mcp.__main__ import main
from universal_db_mcp.agents import claude_code, claude_desktop, cline, cursor, dsh, vscode
from universal_db_mcp.agents import core as agents_core
from universal_db_mcp.agents.core import AgentStatus, Plan
from universal_db_mcp.errors import ConfigError

_POSIX_ONLY = pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode and symlink semantics")

ISOLATED_ARGS = ["-I", "-m", "universal_db_mcp", "serve", "--transport", "stdio"]
LEGACY_ARGS = ["-m", "universal_db_mcp", "serve", "--transport", "stdio"]

FAKE_PYTHON = "/opt/universal-db-mcp/venv/bin/python"
FAKE_CONFIG = "/etc/universal-db-mcp/config.yaml"
ENV: dict[str, str] = {"UDBMCP_VENV_PYTHON": FAKE_PYTHON, "UDBMCP_CONFIG": FAKE_CONFIG}

ADAPTERS = ("claude-code", "claude-desktop", "cursor", "vscode", "cline", "dsh")
JSON_ADAPTERS = ("claude-code", "claude-desktop", "cursor", "vscode", "cline")
CREATING_ADAPTERS = ("claude-code", "claude-desktop", "cursor", "vscode", "dsh")
ENTRY_MODULES: tuple[ModuleType, ...] = (claude_code, claude_desktop, cursor, vscode, cline)

_SECRET_SERVER = {"command": "/usr/bin/other", "env": {"API_TOKEN": "fake-secret-token"}}
_DSH_EXISTING = "# user patch layer\n- id: database\n  disabled: true\n"


class _Harness:
    """One adapter wired to a fake HOME: its target file plus detect/apply."""

    def __init__(
        self,
        module: ModuleType,
        target: Path,
        servers_key: str,
        detect: Callable[[], AgentStatus],
        apply: Callable[[bool], Any],
        plan: Callable[[], Plan],
    ) -> None:
        self.module = module
        self.target = target
        self.servers_key = servers_key
        self.detect = detect
        self.apply = apply
        self.plan = plan


def _harness(name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> _Harness:
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    if name == "claude-code":
        (home / ".claude").mkdir(exist_ok=True)
        proj = tmp_path / "proj"
        proj.mkdir(exist_ok=True)
        return _Harness(
            claude_code,
            claude_code.user_config_path(home),
            "mcpServers",
            lambda: claude_code.detect(ENV, home, project_dir=proj),
            lambda ok: claude_code.apply(ENV, home, ok, project_dir=proj),
            lambda: claude_code.plan(ENV, home, project_dir=proj),
        )
    if name == "claude-desktop":
        monkeypatch.setattr(claude_desktop, "SYSTEM_APP_PATHS", ())
        target = claude_desktop.config_path(ENV, home)
        target.parent.mkdir(parents=True, exist_ok=True)
        return _Harness(
            claude_desktop,
            target,
            "mcpServers",
            lambda: claude_desktop.detect(ENV, home),
            lambda ok: claude_desktop.apply(ENV, home, ok),
            lambda: claude_desktop.plan(ENV, home),
        )
    if name == "cursor":
        target = cursor.config_path(home)
        target.parent.mkdir(parents=True, exist_ok=True)
        return _Harness(
            cursor,
            target,
            "mcpServers",
            lambda: cursor.detect(ENV, home),
            lambda ok: cursor.apply(ENV, home, ok),
            lambda: cursor.plan(ENV, home),
        )
    if name == "vscode":
        target = vscode.config_path(home, "darwin")
        target.parent.mkdir(parents=True, exist_ok=True)
        return _Harness(
            vscode,
            target,
            "servers",
            lambda: vscode.detect(ENV, home, platform="darwin"),
            lambda ok: vscode.apply(ENV, home, ok, platform="darwin"),
            lambda: vscode.plan(ENV, home, platform="darwin"),
        )
    if name == "cline":
        target = cline.settings_path(home)
        target.parent.mkdir(parents=True, exist_ok=True)
        return _Harness(
            cline,
            target,
            "mcpServers",
            lambda: cline.detect(ENV, home),
            lambda ok: cline.apply(ENV, home, ok),
            lambda: cline.plan(ENV, home),
        )
    assert name == "dsh"
    monkeypatch.setattr(dsh, "_resolve_python", lambda: FAKE_PYTHON)
    monkeypatch.setattr(dsh, "_resolve_config_path", lambda: FAKE_CONFIG)
    monkeypatch.setattr(dsh, "_dsh_cli_on_path", lambda: False)
    dsh_home = tmp_path / ".dsh"
    dsh_home.mkdir(exist_ok=True)
    (dsh_home / "settings.yaml").write_text("ui-onboarding:\n  welcomeNoticeVersion: 1\n", encoding="utf-8")
    return _Harness(
        dsh,
        dsh_home / dsh.PATCH_FILENAME,
        "",
        lambda: dsh.detect(dsh_home),
        lambda ok: dsh.apply(dsh_home, ok),
        lambda: dsh.plan(dsh_home),
    )


def _existing_body(h: _Harness) -> str:
    if h.module is dsh:
        return _DSH_EXISTING
    return json.dumps({h.servers_key: {"other": _SECRET_SERVER}}, indent=2) + "\n"


def _with_existing(name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> _Harness:
    h = _harness(name, tmp_path, monkeypatch)
    h.target.write_text(_existing_body(h), encoding="utf-8")
    return h


def _status(result: Any) -> AgentStatus:
    if isinstance(result, dsh.ApplyResult):
        return result.status_after
    status = result.status
    assert isinstance(status, AgentStatus)
    return status


def _reported_backups(result: Any) -> list[Path]:
    if isinstance(result, dsh.ApplyResult):
        return [] if result.backup_path is None else [result.backup_path]
    return list(result.backup_paths)


def _backups(target: Path) -> list[Path]:
    return sorted(target.parent.glob(target.name + ".bak.*"))


def _registered(h: _Harness) -> Any:
    """The universal-db registration now stored in the harness's target."""
    if h.module is dsh:
        rows = yaml.safe_load(h.target.read_text(encoding="utf-8"))
        for row in rows:
            for item in row.get("insert", []) if isinstance(row, dict) else []:
                if item.get("id") == dsh.REGISTRATION_ID:
                    return item
        return None
    return json.loads(h.target.read_text(encoding="utf-8"))[h.servers_key].get("universal-db")


@pytest.fixture
def umask_022() -> Iterator[None]:
    old = os.umask(0o022)
    try:
        yield
    finally:
        os.umask(old)


# ---------------------------------------------------------------------------
# F45: backups are private, byte-identical, and never follow a planted link
# ---------------------------------------------------------------------------


@_POSIX_ONLY
@pytest.mark.parametrize("name", ADAPTERS)
def test_f45_backup_of_private_config_is_private_and_exact(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, umask_022: None
) -> None:
    h = _with_existing(name, tmp_path, monkeypatch)
    h.target.chmod(0o600)
    original = h.target.read_bytes()

    result = h.apply(True)

    assert _status(result) is AgentStatus.CONFIGURED
    backups = _backups(h.target)
    assert len(backups) == 1
    for backup in backups:
        assert stat.S_IMODE(backup.lstat().st_mode) & 0o077 == 0, (
            f"{name}: backup {backup.name} is {oct(stat.S_IMODE(backup.lstat().st_mode))}; "
            "it holds the harness config (other servers' tokens) and must not be group/other readable"
        )
        assert backup.read_bytes() == original


@_POSIX_ONLY
@pytest.mark.parametrize("name", CREATING_ADAPTERS)
def test_f45_created_config_is_private(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, umask_022: None
) -> None:
    h = _harness(name, tmp_path, monkeypatch)
    assert not h.target.exists()

    result = h.apply(True)

    assert _status(result) is AgentStatus.CONFIGURED
    assert stat.S_IMODE(h.target.stat().st_mode) == 0o600


@_POSIX_ONLY
@pytest.mark.parametrize(
    ("original_mode", "backup_mode"), [(0o644, 0o600), (0o640, 0o600), (0o600, 0o600), (0o400, 0o400)]
)
def test_f45_backup_mode_is_the_original_capped_at_0600(
    original_mode: int, backup_mode: int, tmp_path: Path, umask_022: None
) -> None:
    source = tmp_path / "mcp.json"
    source.write_bytes(b'{"mcpServers": {}}\n')
    source.chmod(original_mode)
    backup = tmp_path / "mcp.json.bak.stamp"

    agents_core.write_private_backup(source, backup)

    assert stat.S_IMODE(backup.stat().st_mode) == backup_mode
    assert backup.read_bytes() == b'{"mcpServers": {}}\n'


@_POSIX_ONLY
@pytest.mark.parametrize("name", ADAPTERS)
def test_f45_symlink_planted_at_backup_path_fails_closed(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    h = _with_existing(name, tmp_path, monkeypatch)
    original = h.target.read_bytes()
    frozen = h.target.parent / f"{h.target.name}.bak.20260927T000000000000Z"
    monkeypatch.setattr(h.module, "backup_path", lambda _target: frozen)
    victim = tmp_path / "victim.txt"
    victim.write_text("victim\n", encoding="utf-8")
    frozen.symlink_to(victim)

    result = h.apply(True)

    assert _status(result) is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    assert victim.read_text(encoding="utf-8") == "victim\n", "the backup was written through the planted link"
    assert frozen.is_symlink()
    assert h.target.read_bytes() == original


# ---------------------------------------------------------------------------
# F46: registrations run the server in isolated mode (-I)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("module", ENTRY_MODULES, ids=lambda m: m.__name__.rsplit(".", 1)[-1])
def test_f46_json_adapters_register_isolated_mode(module: ModuleType, tmp_path: Path) -> None:
    entry = module.registration_entry(ENV, tmp_path)
    assert entry["args"][:3] == ["-I", "-m", "universal_db_mcp"]
    assert entry["args"] == ISOLATED_ARGS


def test_f46_dsh_block_and_entry_register_isolated_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dsh, "_resolve_python", lambda: FAKE_PYTHON)
    monkeypatch.setattr(dsh, "_resolve_config_path", lambda: FAKE_CONFIG)
    entry = dsh._registration_entry()
    block = dsh._registration_block()

    assert entry["config"]["args"] == ISOLATED_ARGS
    assert "'-I'" in block
    # The printed/written block and the logical entry stay in sync.
    parsed = yaml.safe_load(block)
    assert parsed[0]["insert"][0] == entry


def _minimal_config(tmp_path: Path) -> Path:
    import sqlite3

    state = tmp_path / "state"
    state.mkdir()
    db = state / "demo.db"
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE t (id INTEGER)")
    cfg = state / "config.yaml"
    cfg.write_text(
        "application:\n"
        "  transport: stdio\n"
        f"  metadata_cache_path: {json.dumps(str(state / 'metadata.sqlite'))}\n"
        f"  audit_path: {json.dumps(str(state / 'audit.jsonl'))}\n"
        "connections:\n"
        "  demo:\n"
        "    type: sqlite\n"
        f"    database: {json.dumps(str(db))}\n"
        "    read_only: true\n",
        encoding="utf-8",
    )
    return cfg


def _spawn_initialize(argv: list[str], cwd: Path, env: dict[str, str]) -> dict[str, Any]:
    messages = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "hardening-test", "version": "0"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
    ]
    stdin = "".join(json.dumps(m) + "\n" for m in messages)
    proc = subprocess.run(  # noqa: S603 - the registered argv, run in a tmp project
        argv, cwd=cwd, env=env, input=stdin, capture_output=True, text=True, timeout=90
    )
    for line in proc.stdout.splitlines():
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(message, dict) and message.get("id") == 1:
            return message
    raise AssertionError(f"no initialize response (rc={proc.returncode}); stderr tail:\n{proc.stderr[-2000:]}")


_PLANTED_MARKER = (
    "import os\n"
    "open(os.path.join(os.path.dirname(os.path.abspath(__file__)), {name!r}), 'w').write('ran')\n"
)

_PROJECTS: dict[str, dict[str, str]] = {
    # A project whose files would run inside the server with the old argv.
    "shadowing": {
        "yaml.py": _PLANTED_MARKER.format(name="PLANTED_yaml"),
        "universal_db_mcp/__init__.py": "",
        "universal_db_mcp/__main__.py": _PLANTED_MARKER.format(name="PLANTED_pkg"),
    },
    # A harmless project with a top-level mcp/ package used to stop the
    # server from starting (ModuleNotFoundError: mcp.server).
    "benign-mcp-package": {"mcp/__init__.py": "# a project package that happens to be named mcp\n"},
}


@pytest.mark.parametrize("project", sorted(_PROJECTS))
def test_f46_registered_command_ignores_the_harness_working_directory(project: str, tmp_path: Path) -> None:
    probe = subprocess.run(
        [sys.executable, "-I", "-c", "import universal_db_mcp"], cwd=tmp_path, capture_output=True, timeout=60
    )
    if probe.returncode != 0:
        pytest.skip("universal_db_mcp is not installed into this interpreter (source-tree run)")
    cfg = _minimal_config(tmp_path)
    home = tmp_path / "home"
    home.mkdir()
    proj = tmp_path / "proj"
    for rel, body in _PROJECTS[project].items():
        path = proj / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")

    entry = claude_code.registration_entry({"UDBMCP_CONFIG": str(cfg)}, home)
    env = {"PATH": os.environ.get("PATH", ""), "HOME": str(home), **entry["env"]}
    if sys.platform == "win32":
        env["SYSTEMROOT"] = os.environ.get("SYSTEMROOT", "")
    response = _spawn_initialize([entry["command"], *entry["args"]], proj, env)

    assert response["result"]["serverInfo"]["name"] == "universal-db-mcp"
    assert sorted(p.name for p in proj.glob("PLANTED_*")) == []


def _legacy_entry(h: _Harness) -> dict[str, Any]:
    entry = dict(h.module.registration_entry(ENV, h.target.parent))
    entry["args"] = list(LEGACY_ARGS)
    return entry


@pytest.mark.parametrize("name", JSON_ADAPTERS)
def test_f46_exact_legacy_entry_is_upgraded_with_backup(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    h = _harness(name, tmp_path, monkeypatch)
    legacy = _legacy_entry(h)
    h.target.write_text(
        json.dumps({h.servers_key: {"universal-db": legacy, "other": _SECRET_SERVER}}, indent=2) + "\n",
        encoding="utf-8",
    )
    original = h.target.read_bytes()

    assert h.detect() is AgentStatus.INSTALLED_UNCONFIGURED
    refused = h.apply(False)
    assert _status(refused) is AgentStatus.INSTALLED_UNCONFIGURED
    assert h.target.read_bytes() == original and _backups(h.target) == []

    result = h.apply(True)

    assert _status(result) is AgentStatus.CONFIGURED
    assert _registered(h)["args"] == ISOLATED_ARGS
    assert _registered(h) == {**legacy, "args": ISOLATED_ARGS}
    assert json.loads(h.target.read_text(encoding="utf-8"))[h.servers_key]["other"] == _SECRET_SERVER
    backups = _backups(h.target)
    assert len(backups) == 1 and backups[0].read_bytes() == original
    assert h.detect() is AgentStatus.CONFIGURED


@pytest.mark.parametrize("name", JSON_ADAPTERS)
@pytest.mark.parametrize("change", ["command", "env", "args"])
def test_f46_other_differing_entries_still_fail_closed(
    name: str, change: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    h = _harness(name, tmp_path, monkeypatch)
    near_legacy = _legacy_entry(h)
    if change == "command":
        near_legacy["command"] = "/somewhere/else/python"
    elif change == "env":
        near_legacy["env"] = {"UDBMCP_CONFIG": "/somewhere/else/config.yaml"}
    else:
        near_legacy["args"] = [*LEGACY_ARGS, "--extra"]
    h.target.write_text(json.dumps({h.servers_key: {"universal-db": near_legacy}}, indent=2), encoding="utf-8")
    original = h.target.read_bytes()

    assert h.detect() is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    result = h.apply(True)

    assert _status(result) is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    assert h.target.read_bytes() == original
    assert _backups(h.target) == []


# The exact block the pre-fix template wrote, for the dsh legacy upgrade.
_DSH_LEGACY_BLOCK = (
    "# Universal Database MCP server (air-gapped local build), registered by\n"
    "# 'universal_db_mcp configure-agents'. Its 29 tools appear to the model as\n"
    "# mcp__udb__<tool_name>.\n"
    "- insert:\n"
    "    - id: mcp-universal-db\n"
    "      name: '@deepseek-ai/dsh-mcp-client'\n"
    "      config:\n"
    "        serverName: udb\n"
    "        transport: stdio\n"
    f"        command: {FAKE_PYTHON}\n"
    "        args: ['-m', 'universal_db_mcp', 'serve', '--transport', 'stdio']\n"
    "        env:\n"
    f"          UDBMCP_CONFIG: {FAKE_CONFIG}\n"
    "        failOnStartupError: true\n"
)


# Earlier releases wrote a different tool count in the comment header; only
# the row itself has to match.
@pytest.mark.parametrize("tools", ["29", "20"])
def test_f46_dsh_legacy_row_is_upgraded_in_place(tools: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    h = _harness("dsh", tmp_path, monkeypatch)
    legacy_block = _DSH_LEGACY_BLOCK.replace("Its 29 tools", f"Its {tools} tools")
    h.target.write_text(_DSH_EXISTING + legacy_block, encoding="utf-8")
    original = h.target.read_bytes()

    assert h.detect() is AgentStatus.INSTALLED_UNCONFIGURED
    assert "action=upgrade-registration" in dsh.plan(h.target.parent).summary
    refused = h.apply(False)
    assert refused.wrote is False and h.target.read_bytes() == original

    result = h.apply(True)

    assert result.wrote is True and _status(result) is AgentStatus.CONFIGURED
    text = h.target.read_text(encoding="utf-8")
    assert text == original.decode("utf-8").replace(
        "args: ['-m', 'universal_db_mcp',", "args: ['-I', '-m', 'universal_db_mcp',"
    )
    assert _registered(h) == dsh._registration_entry()
    backups = _backups(h.target)
    assert len(backups) == 1 and backups[0].read_bytes() == original
    assert h.detect() is AgentStatus.CONFIGURED


_DSH_UNISOLATED_ROWS = {
    # Written for another interpreter, or while a different UDBMCP_CONFIG was exported.
    "other-command": _DSH_LEGACY_BLOCK.replace(FAKE_PYTHON, "/old/venv/bin/python"),
    "other-config": _DSH_LEGACY_BLOCK.replace(FAKE_CONFIG, "/home/me/.universal-db-mcp/config.yaml"),
    "no-final-newline": _DSH_LEGACY_BLOCK.rstrip("\n"),
    "hand-written": _DSH_LEGACY_BLOCK.replace(", '--transport', 'stdio']", "]"),
    "two-identical-rows": _DSH_LEGACY_BLOCK + _DSH_LEGACY_BLOCK.split("# mcp__udb__<tool_name>.\n")[1],
    "ours-and-another": _DSH_LEGACY_BLOCK + _DSH_LEGACY_BLOCK.replace(FAKE_PYTHON, "/old/venv/bin/python"),
}


@pytest.mark.parametrize("variant", sorted(_DSH_UNISOLATED_ROWS))
def test_f46_dsh_row_that_starts_without_isolation_fails_closed(
    variant: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Only this install's exact pre-``-I`` row is upgraded. Any other
    # registration that still launches ``-m universal_db_mcp`` without ``-I``
    # used to be reported "already configured" and kept the vulnerable launch.
    h = _harness("dsh", tmp_path, monkeypatch)
    h.target.write_text(_DSH_EXISTING + _DSH_UNISOLATED_ROWS[variant], encoding="utf-8")
    original = h.target.read_bytes()

    assert h.detect() is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    summary = h.plan().summary
    assert "FAIL CLOSED" in summary and "without -I" in summary
    result = h.apply(True)

    assert result.wrote is False and _status(result) is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    assert "without -I" in result.message
    assert h.target.read_bytes() == original
    assert _backups(h.target) == []


def test_f46_dsh_row_written_under_another_config_resolution_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The reviewer's repro: the legacy row an earlier run wrote while
    # UDBMCP_CONFIG was exported, detected by a run without that export.
    h = _harness("dsh", tmp_path, monkeypatch)
    monkeypatch.setattr(dsh, "_resolve_config_path", lambda: "/etc/elsewhere/config.yaml")
    legacy_then, _current = dsh._registration_rows()
    h.target.write_text(legacy_then, encoding="utf-8")
    assert h.detect() is AgentStatus.INSTALLED_UNCONFIGURED  # same resolution: upgradeable

    monkeypatch.setattr(dsh, "_resolve_config_path", lambda: FAKE_CONFIG)

    assert h.detect() is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    assert h.apply(True).wrote is False
    assert h.target.read_text(encoding="utf-8") == legacy_then


@pytest.mark.parametrize(
    "row",
    [
        _DSH_LEGACY_BLOCK.replace(FAKE_PYTHON, "/old/venv/bin/python").replace(
            "args: ['-m',", "args: ['-I', '-m',"
        ),
        _DSH_LEGACY_BLOCK.replace(f"command: {FAKE_PYTHON}", "command: /usr/local/bin/udbmcp").replace(
            "args: ['-m', 'universal_db_mcp', ", "args: ["
        ),
    ],
    ids=["isolated-other-install", "not-a-python-launch"],
)
def test_f46_dsh_other_isolated_registration_is_still_configured(
    row: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    h = _harness("dsh", tmp_path, monkeypatch)
    h.target.write_text(_DSH_EXISTING + row, encoding="utf-8")
    original = h.target.read_bytes()

    assert h.detect() is AgentStatus.CONFIGURED  # matched by id, as before
    assert h.apply(True).wrote is False
    assert h.target.read_bytes() == original and _backups(h.target) == []


def test_f46_dsh_count_rows_counts_adjacent_rows() -> None:
    row = "- insert:\n    - id: x\n"
    assert dsh._count_rows(row + row, row) == 2
    assert dsh._count_rows("# c\n" + row + "- id: y\n" + row, row) == 2
    assert dsh._count_rows("  " + row, row) == 0, "only rows that start a line"


def test_f46_dsh_apply_never_writes_a_patch_that_still_starts_without_isolation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Defence in depth: an unisolated row that appears between detect() and
    # the write fails the pre-write verification instead of being kept.
    h = _harness("dsh", tmp_path, monkeypatch)
    h.target.write_text(_DSH_EXISTING, encoding="utf-8")
    raced = _DSH_EXISTING + _DSH_UNISOLATED_ROWS["other-command"]
    real_detect = dsh.detect

    def detect_then_race(env_home: Path) -> Any:
        status = real_detect(env_home)
        h.target.write_text(raced, encoding="utf-8")
        return status

    monkeypatch.setattr(dsh, "detect", detect_then_race)
    result = h.apply(True)

    assert result.wrote is False and _status(result) is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    assert h.target.read_text(encoding="utf-8") == raced


# ---------------------------------------------------------------------------
# F48: writes are atomic (temp file + fsync + os.replace)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ADAPTERS)
def test_f48_failed_replace_leaves_target_byte_identical(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    h = _with_existing(name, tmp_path, monkeypatch)
    original = h.target.read_bytes()

    monkeypatch.setattr(os, "replace", _enospc)
    result = h.apply(True)

    assert _status(result) is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    assert h.target.read_bytes() == original
    assert [p.name for p in h.target.parent.iterdir() if p.name.endswith(".tmp")] == []
    backups = _backups(h.target)
    assert len(backups) == 1 and backups[0].read_bytes() == original
    assert _reported_backups(result) == backups, "the CLI must be able to print the .bak path"


@_POSIX_ONLY
@pytest.mark.parametrize("name", ADAPTERS)
def test_f48_existing_mode_is_preserved(name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    h = _with_existing(name, tmp_path, monkeypatch)
    h.target.chmod(0o640)

    result = h.apply(True)

    assert _status(result) is AgentStatus.CONFIGURED
    assert stat.S_IMODE(h.target.stat().st_mode) == 0o640


@_POSIX_ONLY
@pytest.mark.parametrize("name", ADAPTERS)
def test_f48_symlinked_target_stays_a_symlink(name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    h = _harness(name, tmp_path, monkeypatch)
    real = tmp_path / "dotfiles" / h.target.name
    real.parent.mkdir()
    real.write_text(_existing_body(h), encoding="utf-8")
    h.target.symlink_to(real)

    result = h.apply(True)

    assert _status(result) is AgentStatus.CONFIGURED
    assert h.target.is_symlink() and h.target.resolve() == real.resolve()
    assert _registered(h) is not None
    assert [p.name for p in real.parent.iterdir()] == [real.name], "no temp file may be left beside the real file"


def _enospc(*_args: object, **_kwargs: object) -> None:
    raise OSError(errno.ENOSPC, "No space left on device")


@pytest.mark.parametrize("existing", [True, False], ids=["replace", "create"])
def test_f48_failed_temp_write_leaves_no_trace(existing: bool, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # ENOSPC usually surfaces while the new bytes are written/fsynced, before
    # os.replace is reached: the target keeps its bytes and no temp is left.
    target = tmp_path / "mcp.json"
    if existing:
        target.write_text("original\n", encoding="utf-8")
    monkeypatch.setattr(os, "fsync", _enospc)

    with pytest.raises(OSError, match="No space left"):
        agents_core.atomic_write_text(target, "new\n")

    assert sorted(p.name for p in tmp_path.iterdir()) == (["mcp.json"] if existing else [])
    if existing:
        assert target.read_text(encoding="utf-8") == "original\n"


def test_f48_cli_prints_the_backup_when_a_write_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    home = tmp_path / "home"
    target = cursor.config_path(home)
    target.parent.mkdir(parents=True)
    target.write_text(json.dumps({"mcpServers": {"other": _SECRET_SERVER}}), encoding="utf-8")
    original = target.read_bytes()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)  # a Linux host's own would win over HOME
    monkeypatch.setenv("PATH", "")
    for variable, value in ENV.items():
        monkeypatch.setenv(variable, value)
    monkeypatch.setattr(os, "replace", _enospc)

    main(["configure-agents", "--agent", "cursor", "--yes"])
    out = capsys.readouterr().out

    (backup,) = _backups(target)
    assert f"backup: {backup}" in out
    assert "unknown_state_fail_closed" in out and "was left as it was" in out
    assert target.read_bytes() == original


def test_f48_no_adapter_writes_a_config_in_place() -> None:
    agents_dir = Path(agents_pkg.__file__).parent
    offenders = [
        f"{py.name}: {pattern}"
        for py in sorted(agents_dir.glob("*.py"))
        for pattern in (".write_text(", ".write_bytes(", "shutil.copy", "copyfile(")
        if pattern in py.read_text(encoding="utf-8")
    ]
    assert offenders == [], "agent config writes must go through agents.core.atomic_write_text"


# ---------------------------------------------------------------------------
# F58: relative overrides become absolute (or are refused) before registering
# ---------------------------------------------------------------------------


@pytest.fixture
def relative_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    monkeypatch.chdir(tmp_path)
    cfg = tmp_path / "rel" / "config.yaml"
    cfg.parent.mkdir()
    cfg.write_text("application:\n  transport: stdio\n", encoding="utf-8")
    venv_python = tmp_path / ".venv" / "bin" / "python"
    venv_python.parent.mkdir(parents=True)
    if sys.platform == "win32":
        venv_python.write_bytes(b"")
    else:
        # A venv's bin/python is a symlink to the base interpreter; resolving
        # it would silently drop the venv, so it must stay unresolved.
        venv_python.symlink_to(sys.executable)
    return {"UDBMCP_CONFIG": "rel/config.yaml", "UDBMCP_VENV_PYTHON": ".venv/bin/python"}


@pytest.mark.parametrize("module", ENTRY_MODULES, ids=lambda m: m.__name__.rsplit(".", 1)[-1])
def test_f58_relative_overrides_are_registered_as_absolute_paths(
    module: ModuleType, tmp_path: Path, relative_env: dict[str, str]
) -> None:
    entry = module.registration_entry(relative_env, tmp_path / "home")

    command = Path(entry["command"])
    config = Path(entry["env"]["UDBMCP_CONFIG"])
    assert command.is_absolute() and config.is_absolute()
    assert os.path.samefile(command, tmp_path / ".venv" / "bin" / "python")
    assert command.parts[-3:] == (".venv", "bin", "python"), "the venv python must not be symlink-resolved"
    assert os.path.samefile(config, tmp_path / "rel" / "config.yaml")


@pytest.mark.parametrize("module", ENTRY_MODULES, ids=lambda m: m.__name__.rsplit(".", 1)[-1])
@pytest.mark.parametrize("variable", ["UDBMCP_CONFIG", "UDBMCP_VENV_PYTHON"])
def test_f58_missing_relative_override_is_refused(
    module: ModuleType, variable: str, tmp_path: Path, relative_env: dict[str, str]
) -> None:
    env = {**relative_env, variable: "missing/nothing-here"}
    with pytest.raises(ConfigError, match="CONFIG_ERROR"):
        module.registration_entry(env, tmp_path / "home")


def _installed_without_config(name: str, home: Path) -> Callable[[dict[str, str]], AgentStatus]:
    """Make ``name`` look installed under ``home`` with no config file yet."""
    if name == "claude-code":
        (home / ".claude").mkdir(parents=True)
        return lambda env: claude_code.detect(env, home, project_dir=home)
    if name == "claude-desktop":
        claude_desktop.config_path({}, home).parent.mkdir(parents=True)
        return lambda env: claude_desktop.detect(env, home)
    if name == "cursor":
        (home / ".cursor").mkdir(parents=True)
        return lambda env: cursor.detect(env, home)
    if name == "vscode":
        vscode.user_config_dir(home, "darwin").mkdir(parents=True)
        return lambda env: vscode.detect(env, home, platform="darwin")
    assert name == "cline"  # installed == the settings file exists
    target = cline.settings_path(home)
    target.parent.mkdir(parents=True)
    target.write_text("{}", encoding="utf-8")
    return lambda env: cline.detect(env, home)


@pytest.mark.parametrize("name", JSON_ADAPTERS)
@pytest.mark.parametrize("variable", ["UDBMCP_CONFIG", "UDBMCP_VENV_PYTHON"])
def test_f58_detect_refuses_an_unregistrable_override(
    name: str, variable: str, tmp_path: Path, relative_env: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # Refused at detection, so the CLI never offers (or --json --yes applies) a write.
    monkeypatch.setattr(claude_desktop, "SYSTEM_APP_PATHS", ())
    detect = _installed_without_config(name, tmp_path / "home")
    assert detect(relative_env) is AgentStatus.INSTALLED_UNCONFIGURED

    with pytest.raises(ConfigError, match="CONFIG_ERROR"):
        detect({**relative_env, variable: "missing/nothing-here"})


def test_f58_dsh_relative_config_is_absolute_or_refused(
    tmp_path: Path, relative_env: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("UDBMCP_CONFIG", relative_env["UDBMCP_CONFIG"])
    resolved = Path(dsh._resolve_config_path())
    assert resolved.is_absolute() and os.path.samefile(resolved, tmp_path / "rel" / "config.yaml")

    monkeypatch.setenv("UDBMCP_CONFIG", "missing/config.yaml")
    with pytest.raises(ConfigError, match="CONFIG_ERROR"):
        dsh._resolve_config_path()


def test_f58_resolver_absolutizes_without_refusing_by_default(
    tmp_path: Path, relative_env: dict[str, str]
) -> None:
    home = tmp_path / "home"
    # add-connection creates a missing config, so the default stays lenient.
    missing = agents_core.resolve_harness_config_path({"UDBMCP_CONFIG": "new/config.yaml"}, home)
    assert Path(missing).is_absolute() and Path(missing).parts[-2:] == ("new", "config.yaml")
    with pytest.raises(ConfigError, match="CONFIG_ERROR"):
        agents_core.resolve_harness_config_path({"UDBMCP_CONFIG": "new/config.yaml"}, home, strict=True)


def test_f58_configure_agents_json_refuses_and_keeps_stdout_pure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    home = tmp_path / "home"
    (home / ".cursor").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)  # a Linux host's own would win over HOME
    monkeypatch.setenv("PATH", "")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("UDBMCP_CONFIG", "examples/sqlite-demo/config.yaml")
    monkeypatch.delenv("UDBMCP_VENV_PYTHON", raising=False)

    main(["configure-agents", "--json", "--agent", "cursor", "--yes"])
    payload = json.loads(capsys.readouterr().out)

    (harness,) = payload["harnesses"]
    assert harness["writable"] is False
    assert "CONFIG_ERROR" in harness["detail"]
    assert payload["applied"] == []
    assert not (home / ".cursor" / "mcp.json").exists()


# ---------------------------------------------------------------------------
# F79: %APPDATA% and $XDG_CONFIG_HOME are honoured
# ---------------------------------------------------------------------------


def test_f79_app_data_base(tmp_path: Path) -> None:
    home = tmp_path / "home"
    roam = tmp_path / "roam"
    xdg = tmp_path / "x"
    assert agents_core.app_data_base({"APPDATA": str(roam)}, home, "win32") == roam
    assert agents_core.app_data_base({}, home, "win32") == home / "AppData" / "Roaming"
    assert agents_core.app_data_base({"XDG_CONFIG_HOME": str(xdg)}, home, "linux") == xdg
    # XDG base-dir spec: a relative value is invalid and ignored.
    assert agents_core.app_data_base({"XDG_CONFIG_HOME": "rel/x"}, home, "linux") == home / ".config"
    assert agents_core.app_data_base({}, home, "linux") == home / ".config"
    assert agents_core.app_data_base({"XDG_CONFIG_HOME": str(xdg)}, home, "darwin") == (
        home / "Library" / "Application Support"
    )


@pytest.mark.parametrize(
    ("platform", "variable"), [("win32", "APPDATA"), ("linux", "XDG_CONFIG_HOME")]
)
def test_f79_vscode_follows_the_environment(platform: str, variable: str, tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    base = tmp_path / "redirected"
    (base / "Code" / "User").mkdir(parents=True)
    env = {**ENV, variable: str(base)}

    assert vscode.detect(env, home, platform=platform) is AgentStatus.INSTALLED_UNCONFIGURED
    assert vscode.plan(env, home, platform=platform).config_path == base / "Code" / "User" / "mcp.json"


@pytest.mark.parametrize(
    ("platform", "variable"), [("win32", "APPDATA"), ("linux", "XDG_CONFIG_HOME")]
)
def test_f79_cline_follows_the_environment(
    platform: str, variable: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sys, "platform", platform)
    if platform == "win32":
        monkeypatch.setitem(sys.modules, "_winapi", _fake_winapi())
    home = tmp_path / "home"
    home.mkdir()
    base = tmp_path / "redirected"
    env = {**ENV, variable: str(base)}
    expected = base.joinpath(
        "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"
    )
    expected.parent.mkdir(parents=True)
    expected.write_text("{}", encoding="utf-8")

    assert cline.detect(env, home) is AgentStatus.INSTALLED_UNCONFIGURED
    assert cline.plan(env, home).config_path == expected


def test_f79_claude_desktop_follows_xdg_on_linux(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(claude_desktop, "SYSTEM_APP_PATHS", ())
    home = tmp_path / "home"
    home.mkdir()
    xdg = tmp_path / "x"
    (xdg / "Claude").mkdir(parents=True)
    env = {**ENV, "XDG_CONFIG_HOME": str(xdg)}

    assert claude_desktop.detect(env, home) is AgentStatus.INSTALLED_UNCONFIGURED
    assert claude_desktop.plan(env, home).config_path == xdg / "Claude" / "claude_desktop_config.json"


# ---------------------------------------------------------------------------
# Review of the fixes above (round 1)
# ---------------------------------------------------------------------------

_THEIRS = {"command": "/theirs/bin/python", "args": ["serve"]}

# The check apply() relies on before its own re-read of the file, and how many
# calls of it happen first (vscode checks every target, then each one again).
_LAST_CHECK: dict[str, tuple[str, int]] = {
    "claude-code": ("detect", 1),
    "claude-desktop": ("detect", 1),
    "cursor": ("detect", 1),
    "vscode": ("_registration_status", 2),
    "cline": ("detect", 1),
}


@pytest.mark.parametrize("name", JSON_ADAPTERS)
def test_f46_differing_entry_that_appears_after_detect_is_never_overwritten(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The legacy upgrade lets apply() replace an existing "universal-db"
    # entry; the re-read before the write must still refuse anything else.
    h = _harness(name, tmp_path, monkeypatch)
    h.target.write_text(json.dumps({h.servers_key: {}}), encoding="utf-8")
    raced = json.dumps({h.servers_key: {"universal-db": _THEIRS}}, indent=2) + "\n"
    hook, after = _LAST_CHECK[name]
    real_check = getattr(h.module, hook)
    calls = 0

    def check_then_race(*args: Any, **kwargs: Any) -> AgentStatus:
        nonlocal calls
        status = real_check(*args, **kwargs)
        calls += 1
        if calls == after:
            h.target.write_text(raced, encoding="utf-8")  # another writer, right after the check
        return cast(AgentStatus, status)

    monkeypatch.setattr(h.module, hook, check_then_race)

    result = h.apply(True)

    assert calls >= after, "the race was never injected"
    assert _status(result) is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    assert h.target.read_text(encoding="utf-8") == raced
    assert _backups(h.target) == []


@_POSIX_ONLY
@pytest.mark.parametrize("euid", [0, 4001], ids=["root", "user"])
def test_f48_written_files_keep_the_owner_as_root_and_the_group_otherwise(
    euid: int, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # As "user" the process is the (fake) owner of the file it replaces: a
    # file another user owns is refused (test_f48_config_owned_by_another_user...).
    source = tmp_path / "mcp.json"
    source.write_text("{}\n", encoding="utf-8")
    # Distinct fake owners, so the file's and the directory's ids cannot be confused.
    owners = {os.path.realpath(source): (4001, 4002), os.path.realpath(tmp_path): (5001, 5002)}
    real_stat = Path.stat

    def owned_stat(self: Path, *, follow_symlinks: bool = True) -> os.stat_result:
        st = real_stat(self, follow_symlinks=follow_symlinks)
        ids = owners.get(os.path.realpath(self))
        if ids is None:
            return st
        fields: list[float] = list(st[:10])
        fields[4:6] = ids
        return os.stat_result(fields)

    calls: list[tuple[int, int]] = []
    monkeypatch.setattr(Path, "stat", owned_stat)
    monkeypatch.setattr(os, "geteuid", lambda: euid)
    # The user is in both groups (a group it is not in is refused under a mode
    # that gives the group access of its own, as umask 002 does).
    monkeypatch.setattr(os, "getgroups", lambda: [4002, 5002])
    monkeypatch.setattr(os, "fchown", lambda _fd, uid, gid: calls.append((uid, gid)))

    agents_core.write_private_backup(source, tmp_path / "mcp.json.bak.stamp")
    agents_core.atomic_write_text(source, "{}\n")  # replace
    agents_core.atomic_write_text(tmp_path / "new.json", "{}\n")  # create

    if euid == 0:
        # A sudo run must not leave the user's config (or its backup) root-owned.
        assert calls == [(4001, 4002), (4001, 4002), (5001, 5002)]
    else:
        assert calls == [(-1, 4002), (-1, 4002), (-1, 5002)]


@_POSIX_ONLY
def test_f48_group_restore_is_best_effort_unless_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "mcp.json"
    target.write_text("old\n", encoding="utf-8")

    def refuse(*_args: object) -> None:
        raise PermissionError(errno.EPERM, "Operation not permitted")

    monkeypatch.setattr(os, "fchown", refuse)
    owner = target.stat().st_uid
    if owner == 0:
        pytest.skip("the non-root half needs a file this non-root process owns")
    monkeypatch.setattr(os, "geteuid", lambda: owner)  # the file's owner, not root
    agents_core.atomic_write_text(target, "new\n")
    assert target.read_text(encoding="utf-8") == "new\n"

    monkeypatch.setattr(os, "geteuid", lambda: 0)
    with pytest.raises(PermissionError):
        agents_core.atomic_write_text(target, "newer\n")
    assert target.read_text(encoding="utf-8") == "new\n"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["mcp.json"]


def _executable(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\necho planted\n", encoding="utf-8")
    path.chmod(0o755)
    return path


@_POSIX_ONLY
@pytest.mark.parametrize("module", ENTRY_MODULES, ids=lambda m: m.__name__.rsplit(".", 1)[-1])
def test_f58_bare_interpreter_name_is_looked_up_on_path_not_in_the_cwd(
    module: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A bare name used to reach the harness as-is (resolved through PATH); it
    # must not be pinned to a same-named file in the directory this runs from.
    monkeypatch.chdir(tmp_path)
    _executable(tmp_path / "python3")
    on_path = _executable(tmp_path / "bin" / "python3")
    env = {**ENV, "UDBMCP_VENV_PYTHON": "python3", "PATH": str(on_path.parent)}
    home = tmp_path / "home"

    assert module.registration_entry(env, home)["command"] == str(on_path)

    # Not on PATH: refused, although ./python3 exists.
    with pytest.raises(ConfigError, match="CONFIG_ERROR"):
        module.registration_entry({**env, "PATH": str(tmp_path / "empty")}, home)
    # Found only through a PATH entry that means "the working directory".
    for cwd_path in (".", "", f"{tmp_path / 'empty'}{os.pathsep}"):
        with pytest.raises(ConfigError, match="CONFIG_ERROR"):
            module.registration_entry({**env, "PATH": cwd_path}, home)


def _python_without_the_package() -> str:
    """This venv's base interpreter, which cannot import universal_db_mcp under ``-I``."""
    base = str(getattr(sys, "_base_executable", ""))
    if not base or sys.prefix == sys.base_prefix:
        pytest.skip("not running from a virtual environment")
    probe = subprocess.run(  # noqa: S603 - this interpreter's own base python
        [base, "-I", "-c", "import universal_db_mcp"], capture_output=True, timeout=60
    )
    if probe.returncode == 0:
        pytest.skip("the base interpreter can import universal_db_mcp")
    return base


@pytest.mark.parametrize("module", ENTRY_MODULES, ids=lambda m: m.__name__.rsplit(".", 1)[-1])
def test_f46_interpreter_that_cannot_import_under_isolated_mode_is_refused(
    module: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # -I leaves the user site-packages and PYTHONPATH off sys.path: a package
    # this CLI imports from there is missing in the registered launch, and the
    # harness's server died at startup.
    monkeypatch.setattr(sys, "executable", _python_without_the_package())
    env = {"UDBMCP_CONFIG": FAKE_CONFIG}

    with pytest.raises(ConfigError, match="-I cannot import universal_db_mcp"):
        module.registration_entry(env, tmp_path)
    # An explicit interpreter is the operator's choice and is not second-guessed.
    assert module.registration_entry({**env, "UDBMCP_VENV_PYTHON": FAKE_PYTHON}, tmp_path)["command"] == FAKE_PYTHON


def test_f46_dsh_interpreter_that_cannot_import_under_isolated_mode_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base = _python_without_the_package()
    monkeypatch.setattr(sys, "executable", base)
    monkeypatch.setattr(sys, "prefix", sys.base_prefix)  # not a venv: dsh registers sys.executable

    with pytest.raises(ConfigError, match="-I cannot import universal_db_mcp"):
        dsh._resolve_python()


def _run_python(python: str, code: str, env: dict[str, str], cwd: Path | None = None) -> str:
    return subprocess.run(  # noqa: S603 - this interpreter's own base python (or a venv made from it)
        [python, "-c", code], cwd=cwd, env=env, capture_output=True, text=True, timeout=120, check=True
    ).stdout.strip()


def _venv_seeing_only_the_package(base: str, tmp_path: Path, env: dict[str, str]) -> str:
    """A venv (with the user site enabled) whose own site-packages hold only
    universal_db_mcp, so ``-I`` imports the package but none of its
    dependencies; returns its python."""
    import universal_db_mcp

    venv = tmp_path / "venv"
    subprocess.run(  # noqa: S603 - this interpreter's own base python
        [base, "-m", "venv", "--without-pip", "--system-site-packages", str(venv)],
        env=env,
        capture_output=True,
        timeout=120,
        check=True,
    )
    python = str(venv / "bin" / "python")
    only_the_package = tmp_path / "pkg"
    only_the_package.mkdir()
    (only_the_package / "universal_db_mcp").symlink_to(Path(universal_db_mcp.__file__).parent)
    site_packages = Path(_run_python(python, "import sysconfig; print(sysconfig.get_paths()['purelib'])", env))
    (site_packages / "udbmcp.pth").write_text(f"{only_the_package}\n", encoding="utf-8")
    probe = subprocess.run(  # noqa: S603 - the venv made above
        [python, "-I", "-c", "import universal_db_mcp; import yaml"], env=env, capture_output=True, timeout=60
    )
    if b"No module named 'yaml'" not in probe.stderr:
        pytest.skip("the base interpreter's own site-packages provide the dependencies")
    return python


@_POSIX_ONLY
@pytest.mark.parametrize("layout", ["package-in-user-site", "dependencies-in-user-site"])
def test_f46_user_site_install_is_refused_end_to_end(layout: str, tmp_path: Path) -> None:
    # `pip install --user` into a non-venv python, simulated under a scratch
    # PYTHONUSERBASE: the package imports normally, but not under -I. In the
    # second layout only the dependencies (mcp, yaml, pydantic, sqlglot) come
    # from the user site: `import universal_db_mcp` alone passed under -I,
    # and the registered server died at every harness start.
    import sysconfig

    import universal_db_mcp

    base = _python_without_the_package()
    env = {"PATH": os.environ.get("PATH", ""), "HOME": str(tmp_path), "PYTHONUSERBASE": str(tmp_path / "ub")}
    python = base if layout == "package-in-user-site" else _venv_seeing_only_the_package(base, tmp_path, env)
    user_site = Path(_run_python(python, "import site; print(site.getusersitepackages())", env))
    user_site.mkdir(parents=True)
    if layout == "package-in-user-site":
        (user_site / "universal_db_mcp").symlink_to(Path(universal_db_mcp.__file__).parent)
    (user_site / "deps.pth").write_text(sysconfig.get_paths()["purelib"] + "\n", encoding="utf-8")
    script = (
        "from pathlib import Path\n"
        "from universal_db_mcp.agents import cursor\n"
        "from universal_db_mcp.errors import ConfigError\n"
        "try:\n"
        "    print('registered', cursor.registration_entry({'UDBMCP_CONFIG': '/etc/x.yaml'}, Path('/h'))['command'])\n"
        "except ConfigError as exc:\n"
        "    print('refused', exc)\n"
    )

    out = _run_python(python, script, env, cwd=tmp_path)

    assert out.startswith("refused "), out
    assert "-I cannot import universal_db_mcp" in out


def test_f46_venv_install_is_registered_with_the_running_interpreter() -> None:
    assert cursor.registration_entry({"UDBMCP_CONFIG": FAKE_CONFIG}, Path("/nonexistent"))["command"] == sys.executable


@pytest.mark.parametrize("name", JSON_ADAPTERS)
def test_f46_legacy_upgrade_plan_says_replace_not_add(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    h = _harness(name, tmp_path, monkeypatch)
    h.target.write_text(
        json.dumps({h.servers_key: {"universal-db": _legacy_entry(h), "other": _SECRET_SERVER}}, indent=2),
        encoding="utf-8",
    )

    summary = h.plan().summary

    assert 'replace this tool\'s earlier "universal-db" registration' in summary
    assert "isolated mode (-I)" in summary
    assert "then add" not in summary

    # A plain add still says add.
    h.target.write_text(json.dumps({h.servers_key: {"other": _SECRET_SERVER}}), encoding="utf-8")
    assert "then add" in h.plan().summary


@pytest.mark.parametrize("name", JSON_ADAPTERS)
def test_f48_failed_backup_is_reported_as_a_backup_failure(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    h = _with_existing(name, tmp_path, monkeypatch)
    original = h.target.read_bytes()
    monkeypatch.setattr(h.module, "write_private_backup", _enospc)

    result = h.apply(True)

    assert _status(result) is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    assert f"backing up {h.target} to {h.target}.bak." in result.summary
    assert f"writing {h.target}" not in result.summary
    assert h.target.read_bytes() == original


def test_f48_claude_code_failure_separates_backups_from_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    h = _with_existing("claude-code", tmp_path, monkeypatch)
    project = claude_code.project_config_path(tmp_path / "proj")
    # The project file is written only to upgrade this tool's own entry (G5).
    project.write_text(json.dumps({"mcpServers": {"universal-db": _legacy_entry(h)}}), encoding="utf-8")
    project_before = project.read_bytes()
    real_replace = os.replace
    replaced: list[str] = []

    def second_replace_fails(src: Any, dst: Any) -> None:
        if replaced:
            _enospc()
        replaced.append(os.fspath(dst))
        real_replace(src, dst)

    monkeypatch.setattr(os, "replace", second_replace_fails)

    result = h.apply(True)

    (user_backup,) = _backups(h.target)
    (project_backup,) = _backups(project)
    assert _status(result) is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    assert f"writing {project} failed" in result.summary
    assert f"backed up: {h.target} to {user_backup}, {project} to {project_backup}" in result.summary
    assert f"written: {h.target}" in result.summary
    assert "completed before the failure" not in result.summary
    assert project.read_bytes() == project_before


@pytest.mark.parametrize("name", ADAPTERS)
def test_f48_single_file_bind_mount_fails_closed_and_names_the_backup(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # rename(2) over a mount point (a bind-mounted ~/.claude.json) is EBUSY:
    # a documented limit of the atomic replace, which must stay fail-closed.
    h = _with_existing(name, tmp_path, monkeypatch)
    original = h.target.read_bytes()

    def busy(*_args: object) -> None:
        raise OSError(errno.EBUSY, "Device or resource busy")

    monkeypatch.setattr(os, "replace", busy)
    result = h.apply(True)

    (backup,) = _backups(h.target)
    assert _status(result) is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    assert h.target.read_bytes() == original and backup.read_bytes() == original
    assert _reported_backups(result) == [backup]
    assert "Device or resource busy" in (result.message if isinstance(result, dsh.ApplyResult) else result.summary)


# ---------------------------------------------------------------------------
# Fix-up round 2: review findings on the changes above
# ---------------------------------------------------------------------------


def test_f46_claude_code_plan_leaves_an_already_registered_scope_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The user scope holds the current entry and the project scope the legacy
    # one: apply() rewrites only the project file, and the plan must say so.
    h = _harness("claude-code", tmp_path, monkeypatch)
    project = claude_code.project_config_path(tmp_path / "proj")
    current = claude_code.registration_entry(ENV, h.target.parent)
    h.target.write_text(json.dumps({"mcpServers": {"universal-db": current}}), encoding="utf-8")
    project.write_text(json.dumps({"mcpServers": {"universal-db": _legacy_entry(h)}}), encoding="utf-8")
    user_before = h.target.read_bytes()

    summary = h.plan().summary

    assert f"user scope {h.target}: already registered (left untouched)" in summary
    assert f"user scope {h.target}: would back up" not in summary
    assert f"project scope {project}: would back up to a timestamped .bak, then replace" in summary

    result = h.apply(True)

    assert _status(result) is AgentStatus.CONFIGURED
    assert h.target.read_bytes() == user_before and _backups(h.target) == []
    assert len(_backups(project)) == 1


@pytest.mark.parametrize("name", ADAPTERS)
def test_f48_successful_apply_reports_its_backup(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # configure-agents --json prints Plan.backup_paths as "backups".
    h = _with_existing(name, tmp_path, monkeypatch)

    result = h.apply(True)

    assert _status(result) is AgentStatus.CONFIGURED
    backups = _backups(h.target)
    assert len(backups) == 1
    assert _reported_backups(result) == backups


def test_f48_configure_agents_json_lists_the_backup_of_a_successful_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    home = tmp_path / "home"
    target = cursor.config_path(home)
    target.parent.mkdir(parents=True)
    target.write_text(json.dumps({"mcpServers": {"other": _SECRET_SERVER}}), encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)  # a Linux host's own would win over HOME
    monkeypatch.setenv("PATH", "")
    for variable, value in ENV.items():
        monkeypatch.setenv(variable, value)

    main(["configure-agents", "--json", "--agent", "cursor", "--yes"])
    payload = json.loads(capsys.readouterr().out)

    (backup,) = _backups(target)
    (applied,) = payload["applied"]
    assert applied["status"] == "configured"
    assert applied["backups"] == [str(backup)]


@_POSIX_ONLY
@pytest.mark.parametrize("name", ADAPTERS)
def test_f48_hard_linked_config_fails_closed(name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # os.replace gives the target a new inode: the other name would silently
    # keep the old bytes. Refuse instead of splitting the link.
    h = _with_existing(name, tmp_path, monkeypatch)
    twin = tmp_path / "twin"
    os.link(h.target, twin)
    original = h.target.read_bytes()

    result = h.apply(True)

    assert _status(result) is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    message = result.message if isinstance(result, dsh.ApplyResult) else result.summary
    assert "hard link" in message
    assert h.target.read_bytes() == original and twin.read_bytes() == original
    assert os.path.samefile(h.target, twin)
    assert [p.name for p in h.target.parent.iterdir() if p.name.endswith(".tmp")] == []
    assert _backups(h.target) == [], "refused before the backup"


@_POSIX_ONLY
def test_f48_atomic_write_refuses_a_hard_linked_target(tmp_path: Path) -> None:
    target = tmp_path / "mcp.json"
    target.write_text("old\n", encoding="utf-8")
    os.link(target, tmp_path / "twin")

    with pytest.raises(OSError, match="hard link"):
        agents_core.atomic_write_text(target, "new\n")

    assert target.read_text(encoding="utf-8") == "old\n"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["mcp.json", "twin"]


def test_f58_relative_home_still_registers_an_absolute_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # HOME=. (or any relative HOME): the per-user fallback was returned
    # relative, so the open project supplied .universal-db-mcp/config.yaml.
    monkeypatch.setattr(agents_core, "SYSTEM_CONFIG_PATH", tmp_path / "etc" / "config.yaml")
    monkeypatch.chdir(tmp_path)
    expected = tmp_path / ".universal-db-mcp" / "config.yaml"

    resolved = agents_core.resolve_harness_config_path({}, Path("."))
    assert Path(resolved).is_absolute() and os.path.samefile(Path(resolved).parent.parent, tmp_path)
    assert resolved == os.path.abspath(expected)

    seeded, _note = agents_core.ensure_per_user_harness_config({}, Path("."))
    assert seeded is not None and seeded.is_absolute() and os.path.samefile(seeded, expected)

    entry = cursor.registration_entry({"UDBMCP_VENV_PYTHON": FAKE_PYTHON}, Path("."))
    assert entry["env"]["UDBMCP_CONFIG"] == resolved


def test_f79_relative_appdata_is_ignored(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    fallback = home / "AppData" / "Roaming"
    assert agents_core.app_data_base({"APPDATA": "rel\\roam"}, home, "win32") == fallback
    assert agents_core.app_data_base({"APPDATA": "rel/roam"}, home, "win32") == fallback
    assert agents_core.app_data_base({"APPDATA": str(tmp_path / "roam")}, home, "win32") == tmp_path / "roam"
    # A drive path is absolute on a Windows host (and only there: see
    # test_f79_windows_appdata_is_not_absolute_on_a_posix_host).
    monkeypatch.setattr(sys, "platform", "win32")
    windows = "C:\\Users\\me\\AppData\\Roaming"
    assert agents_core.app_data_base({"APPDATA": windows}, home, "win32") == Path(windows)


@_POSIX_ONLY
@pytest.mark.parametrize("euid", [0, 501], ids=["root", "user"])
def test_f45_directories_created_as_root_take_the_owner_of_their_parent(
    euid: int, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A sudo run used to mkdir the harness's config directory as root, and the
    # new config inside it then took that root owner (0600: unreadable by the
    # user whose harness reads it).
    existing = tmp_path / "Application Support"
    existing.mkdir()
    real_stat = Path.stat

    def owned_stat(self: Path, *, follow_symlinks: bool = True) -> os.stat_result:
        st = real_stat(self, follow_symlinks=follow_symlinks)
        if os.path.realpath(self) != os.path.realpath(existing):
            return st
        fields: list[float] = list(st[:10])
        fields[4:6] = (4001, 4002)
        return os.stat_result(fields)

    chowned: list[tuple[str, int, int]] = []
    monkeypatch.setattr(Path, "stat", owned_stat)
    monkeypatch.setattr(os, "geteuid", lambda: euid)
    monkeypatch.setattr(os, "chown", lambda p, uid, gid, **_kw: chowned.append((os.fspath(p), uid, gid)))

    agents_core.ensure_directory(existing / "Claude" / "sub", mode=0o700)

    assert (existing / "Claude" / "sub").is_dir()
    if euid == 0:
        assert chowned == [
            (str(existing / "Claude"), 4001, 4002),
            (str(existing / "Claude" / "sub"), 4001, 4002),
        ]
    else:
        assert chowned == []
    assert stat.S_IMODE((existing / "Claude" / "sub").stat().st_mode) == 0o700
    agents_core.ensure_directory(existing / "Claude")  # already there: no error, no chown
    assert len(chowned) == (2 if euid == 0 else 0)


@_POSIX_ONLY
def test_f45_root_run_creates_the_desktop_config_directory_for_the_user(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    target = claude_desktop.config_path(ENV, home)
    target.parent.parent.mkdir(parents=True)  # Application Support exists; Claude/ does not
    monkeypatch.setattr(claude_desktop, "SYSTEM_APP_PATHS", ())
    monkeypatch.setattr(claude_desktop, "detect", lambda _env, _home: AgentStatus.INSTALLED_UNCONFIGURED)
    chowned: list[tuple[str, int, int]] = []
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(os, "chown", lambda p, uid, gid, **_kw: chowned.append((os.fspath(p), uid, gid)))
    monkeypatch.setattr(os, "fchown", lambda _fd, _uid, _gid: None)

    result = claude_desktop.apply(ENV, home, True)

    assert result.status is AgentStatus.CONFIGURED and target.is_file()
    owner = target.parent.parent.stat()
    assert chowned == [(str(target.parent), owner.st_uid, owner.st_gid)]


def test_f45_adapters_create_directories_through_the_shared_helper() -> None:
    agents_dir = Path(agents_pkg.__file__).parent
    offenders = [
        py.name
        for py in sorted(agents_dir.glob("*.py"))
        if py.name != "core.py" and ".mkdir(" in py.read_text(encoding="utf-8")
    ]
    assert offenders == [], "use agents.core.ensure_directory (a sudo run must not leave root-owned dirs)"


@_POSIX_ONLY
@pytest.mark.parametrize("name", ADAPTERS)
def test_f45_earlier_readable_backups_are_tightened_on_the_next_backup(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, umask_022: None
) -> None:
    # Releases before the F45 fix left <config>.bak.<stamp> at 0644, holding
    # other servers' tokens. The next backup of that config tightens them.
    h = _with_existing(name, tmp_path, monkeypatch)
    old = h.target.parent / f"{h.target.name}.bak.20260901T101010123456Z"
    old.write_text("old backup\n", encoding="utf-8")
    old.chmod(0o644)
    victim = tmp_path / "victim"
    victim.write_text("not ours\n", encoding="utf-8")
    victim.chmod(0o644)
    planted = h.target.parent / f"{h.target.name}.bak.20260902T101010123456Z"
    planted.symlink_to(victim)
    unrelated = h.target.parent / f"{h.target.name}.bak.notes"
    unrelated.write_text("mine\n", encoding="utf-8")
    unrelated.chmod(0o644)

    result = h.apply(True)

    assert _status(result) is AgentStatus.CONFIGURED
    assert stat.S_IMODE(old.stat().st_mode) == 0o600
    assert old.read_text(encoding="utf-8") == "old backup\n"
    assert stat.S_IMODE(victim.stat().st_mode) == 0o644, "a symlink at a backup name is never followed"
    assert stat.S_IMODE(unrelated.stat().st_mode) == 0o644, "only this tool's backup names are touched"


# ---------------------------------------------------------------------------
# Round 3: review findings on the changes above
# ---------------------------------------------------------------------------

_AS_ROOT = sys.platform != "win32" and os.geteuid() == 0


@_POSIX_ONLY
@pytest.mark.skipif(_AS_ROOT, reason="root may write any file, as it always could")
@pytest.mark.parametrize("name", ADAPTERS)
def test_f48_read_only_config_is_never_replaced(name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The atomic replace needs only a writable directory: a config the
    # operator made 0444 was rewritten and reported configured, where the
    # in-place write it replaced failed with PermissionError.
    h = _with_existing(name, tmp_path, monkeypatch)
    h.target.chmod(0o444)
    original = h.target.read_bytes()

    result = h.apply(True)

    assert _status(result) is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    assert "not writable" in (result.message if isinstance(result, dsh.ApplyResult) else result.summary)
    assert h.target.read_bytes() == original
    assert stat.S_IMODE(h.target.stat().st_mode) == 0o444
    assert [p.name for p in h.target.parent.iterdir() if p.name.endswith(".tmp")] == []
    # Refused before the backup: every re-run used to leave another .bak.
    assert _backups(h.target) == [] and _reported_backups(result) == []


@_POSIX_ONLY
def test_f48_config_owned_by_another_user_is_never_replaced(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A root-owned (managed) config in a user-writable directory: the replace
    # would silently hand it to this user (fchown to its owner is EPERM).
    target = tmp_path / "mcp.json"
    target.write_text("old\n", encoding="utf-8")
    user = target.stat().st_uid or 501
    real_stat = Path.stat

    def foreign_stat(self: Path, *, follow_symlinks: bool = True) -> os.stat_result:
        st = real_stat(self, follow_symlinks=follow_symlinks)
        if os.path.realpath(self) != os.path.realpath(target):
            return st
        fields: list[float] = list(st[:10])
        fields[4] = user + 1
        return os.stat_result(fields)

    monkeypatch.setattr(Path, "stat", foreign_stat)
    monkeypatch.setattr(os, "geteuid", lambda: user)
    with pytest.raises(PermissionError, match="owned by another user"):
        agents_core.atomic_write_text(target, "new\n")
    assert target.read_text(encoding="utf-8") == "old\n"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["mcp.json"]

    # As root (sudo configure-agents) the file keeps its owner, as before.
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(os, "fchown", lambda _fd, _uid, _gid: None)
    agents_core.atomic_write_text(target, "new\n")
    assert target.read_text(encoding="utf-8") == "new\n"


def _deny_path(path: Path, real: Callable[..., Any]) -> Callable[..., Any]:
    """``real`` (os.stat / open), refusing ``path`` like a folder this user may not list."""

    def denied(file: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(file, (str, os.PathLike)) and os.fspath(file) == str(path):
            raise PermissionError(errno.EACCES, "Access is denied", str(path))
        return real(file, *args, **kwargs)

    return denied


def test_msi_system_config_that_cannot_be_probed_falls_back_to_per_user(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The MSI's %ProgramData%\UniversalDB MCP is SYSTEM/Administrators-only:
    # stat() of the config inside it raises instead of returning "absent", and
    # configure-agents, doctor, site-check and add-connection crashed.
    system = tmp_path / "ProgramData" / "UniversalDB MCP" / "config.yaml"
    system.parent.mkdir(parents=True)
    system.write_text("application:\n  transport: stdio\n", encoding="utf-8")
    monkeypatch.setattr(agents_core, "SYSTEM_CONFIG_PATH", system)
    home = tmp_path / "home"
    per_user = os.path.abspath(home / ".universal-db-mcp" / "config.yaml")
    assert agents_core.resolve_harness_config_path({}, home) == os.path.abspath(system)

    monkeypatch.setattr(os, "stat", _deny_path(system, os.stat))

    assert agents_core.resolve_harness_config_path({}, home) == per_user
    assert agents_core.resolve_harness_config_path({}, home, strict=True) == per_user


def test_msi_windows_readability_is_tested_by_opening_the_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # os.access ignores Windows ACLs: a file the ACL denies to this user was
    # "readable" and got advertised to harness spawns that then could not open it.
    import builtins

    system = tmp_path / "ProgramData" / "UniversalDB MCP" / "config.yaml"
    system.parent.mkdir(parents=True)
    system.write_text("application:\n  transport: stdio\n", encoding="utf-8")
    monkeypatch.setattr(agents_core, "SYSTEM_CONFIG_PATH", system)
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(os, "access", lambda *_args, **_kwargs: True)
    home = tmp_path / "home"
    assert agents_core.resolve_harness_config_path({}, home) == os.path.abspath(system)

    monkeypatch.setattr(builtins, "open", _deny_path(system, builtins.open))

    assert agents_core.resolve_harness_config_path({}, home) == os.path.abspath(
        home / ".universal-db-mcp" / "config.yaml"
    )


@_POSIX_ONLY
@pytest.mark.skipif(_AS_ROOT, reason="root may list any directory")
def test_msi_system_config_in_an_unlistable_directory_falls_back_to_per_user(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The POSIX analog of the ProgramData ACL: the probe itself is denied.
    system = tmp_path / "locked" / "config.yaml"
    system.parent.mkdir()
    system.write_text("application:\n  transport: stdio\n", encoding="utf-8")
    monkeypatch.setattr(agents_core, "SYSTEM_CONFIG_PATH", system)
    home = tmp_path / "home"
    system.parent.chmod(0o000)
    try:
        resolved = agents_core.resolve_harness_config_path({}, home)
    finally:
        system.parent.chmod(0o755)
    assert resolved == os.path.abspath(home / ".universal-db-mcp" / "config.yaml")


def test_f45_config_that_appears_just_before_the_create_is_never_clobbered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The target was absent at atomic_write_text's own check and appears
    # between that check and the create: the exclusive create must fail
    # instead of truncating it. (The adapters' own "absent" decision is
    # pinned by test_f45_config_that_appears_after_the_absent_decision_...)
    target = tmp_path / "mcp.json"
    theirs = "written by another process\n"
    real_stat = Path.stat

    def absent_then_appears(self: Path, *, follow_symlinks: bool = True) -> os.stat_result:
        try:
            return real_stat(self, follow_symlinks=follow_symlinks)
        except FileNotFoundError:
            if os.path.realpath(self) == os.path.realpath(target):
                with open(target, "x", encoding="utf-8") as fh:  # the other writer
                    fh.write(theirs)
            raise

    monkeypatch.setattr(Path, "stat", absent_then_appears)

    with pytest.raises(FileExistsError):
        agents_core.atomic_write_text(target, "ours\n")

    assert target.read_text(encoding="utf-8") == theirs
    assert sorted(p.name for p in tmp_path.iterdir()) == ["mcp.json"]


@_POSIX_ONLY
def test_f45_earlier_backup_owned_by_someone_else_is_left_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, umask_022: None
) -> None:
    # Under sudo the tightening runs as root: only backups owned by the
    # config's owner are this tool's to change.
    source = tmp_path / "mcp.json"
    source.write_text("{}\n", encoding="utf-8")
    mine = tmp_path / "mcp.json.bak.20260901T101010123456Z"
    mine.write_text("mine\n", encoding="utf-8")
    theirs = tmp_path / "mcp.json.bak.20260902T101010123456Z"
    theirs.write_text("theirs\n", encoding="utf-8")
    for path in (mine, theirs):
        path.chmod(0o644)
    theirs_inode = theirs.stat().st_ino
    real_fstat = os.fstat
    real_fchmod = os.fchmod
    chmodded: list[int] = []

    def foreign_fstat(fd: int) -> os.stat_result:
        st = real_fstat(fd)
        if st.st_ino != theirs_inode:
            return st
        fields: list[float] = list(st[:10])
        fields[4] = st.st_uid + 1
        return os.stat_result(fields)

    def recording_fchmod(fd: int, mode: int) -> None:
        chmodded.append(real_fstat(fd).st_ino)
        real_fchmod(fd, mode)

    monkeypatch.setattr(os, "fstat", foreign_fstat)
    monkeypatch.setattr(os, "fchmod", recording_fchmod)

    agents_core.write_private_backup(source, tmp_path / "mcp.json.bak.20260927T101010123456Z")

    assert theirs_inode not in chmodded
    assert stat.S_IMODE(theirs.stat().st_mode) == 0o644
    assert stat.S_IMODE(mine.stat().st_mode) == 0o600
    assert mine.stat().st_ino in chmodded


def test_f46_isolated_import_probe_imports_the_server_module(monkeypatch: pytest.MonkeyPatch) -> None:
    # `import universal_db_mcp` alone never touches mcp, yaml, pydantic or
    # sqlglot: an interpreter whose dependencies sit in the user site passed.
    calls: list[list[str]] = []

    def fake_run(argv: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(list(argv))
        return subprocess.CompletedProcess(argv, 1, "", "ModuleNotFoundError: No module named 'yaml'\n")

    agents_core._isolated_import_problem.cache_clear()
    monkeypatch.setattr(subprocess, "run", fake_run)
    try:
        with pytest.raises(ConfigError, match="No module named 'yaml'"):
            agents_core.require_isolated_import("/some/python")
    finally:
        agents_core._isolated_import_problem.cache_clear()

    assert calls == [["/some/python", "-I", "-c", "import universal_db_mcp.server"]]


_DSH_CURRENT_ROW = _DSH_LEGACY_BLOCK.replace("args: ['-m',", "args: ['-I', '-m',").split(
    "# mcp__udb__<tool_name>.\n"
)[1]


def test_f46_dsh_legacy_row_beside_the_current_one_is_not_upgraded_into_a_duplicate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The legacy row byte-matched, so apply() upgraded it and left two
    # "mcp-universal-db" rows, reported "configured".
    h = _harness("dsh", tmp_path, monkeypatch)
    h.target.write_text(_DSH_EXISTING + _DSH_LEGACY_BLOCK + _DSH_CURRENT_ROW, encoding="utf-8")
    original = h.target.read_bytes()

    assert h.detect() is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    summary = h.plan().summary
    assert "FAIL CLOSED" in summary and "without -I" in summary and "duplicate" in summary
    result = h.apply(True)

    assert result.wrote is False and _status(result) is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    assert "duplicate" in result.message
    assert h.target.read_bytes() == original and _backups(h.target) == []


def test_f46_dsh_duplicate_isolated_rows_fail_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    h = _harness("dsh", tmp_path, monkeypatch)
    h.target.write_text(_DSH_EXISTING + _DSH_CURRENT_ROW + _DSH_CURRENT_ROW, encoding="utf-8")
    original = h.target.read_bytes()

    assert h.detect() is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    summary = h.plan().summary
    assert "2 rows insert id 'mcp-universal-db'" in summary and "without -I" not in summary
    assert h.apply(True).wrote is False
    assert h.target.read_bytes() == original


def test_f46_dsh_apply_never_writes_a_duplicate_row(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A current row that appears between detect() and the write fails the
    # pre-write verification instead of being joined by a second one.
    h = _harness("dsh", tmp_path, monkeypatch)
    h.target.write_text(_DSH_EXISTING, encoding="utf-8")
    raced = _DSH_EXISTING + _DSH_CURRENT_ROW
    real_detect = dsh.detect

    def detect_then_race(env_home: Path) -> Any:
        status = real_detect(env_home)
        h.target.write_text(raced, encoding="utf-8")
        return status

    monkeypatch.setattr(dsh, "detect", detect_then_race)
    result = h.apply(True)

    assert result.wrote is False and _status(result) is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    assert "more than one row" in result.message
    assert h.target.read_text(encoding="utf-8") == raced


@pytest.mark.parametrize(
    ("args", "unisolated"),
    [
        (LEGACY_ARGS, True),
        (ISOLATED_ARGS, False),
        (["-u", "-m", "universal_db_mcp", "serve"], True),
        (["-I", "-u", "-m", "universal_db_mcp"], False),
        # Any launch of the package puts the working directory on sys.path.
        (["-m", "universal_db_mcp.__main__"], True),
        (["-m", "universal_db_mcp.server", "serve"], True),
        (["-muniversal_db_mcp", "serve"], True),
        (["-umuniversal_db_mcp.__main__"], True),
        (["-X", "importtime", "-m", "universal_db_mcp"], True),
        (["-Ximporttime", "-m", "universal_db_mcp"], True),
        (["-X", "-I", "-m", "universal_db_mcp"], True),  # "-I" is -X's value here
        (["--check-hash-based-pycs", "never", "-m", "universal_db_mcp"], True),
        (["-E", "-s", "-m", "universal_db_mcp"], True),
        # -I combined with other short flags still isolates.
        (["-Im", "universal_db_mcp"], False),
        (["-Imuniversal_db_mcp"], False),
        (["-IB", "-m", "universal_db_mcp"], False),
        (["-BI", "-m", "universal_db_mcp.__main__"], False),
        (["-I", "-X", "importtime", "-m", "universal_db_mcp"], False),
        # Through a wrapper: the interpreter is an argument (command /usr/bin/env, uv, ...).
        (["python3", "-m", "universal_db_mcp", "serve"], True),
        (["/opt/v/bin/python3.12", "-u", "-m", "universal_db_mcp"], True),
        (["-u", "HOME", "PYTHONUTF8=1", "python3", "-m", "universal_db_mcp"], True),
        (["-i", "--", "python3", "-m", "universal_db_mcp"], True),
        (["run", "python", "-m", "universal_db_mcp", "serve"], True),
        (["run", "--with", "x", "python3", "-m", "universal_db_mcp"], True),
        (["run", "-m", "universal_db_mcp"], True),
        (["C:\\Python312\\python.exe", "-muniversal_db_mcp"], True),
        (["py", "-3.12", "-m", "universal_db_mcp"], True),
        (["python3", "-I", "-m", "universal_db_mcp", "serve"], False),
        (["run", "python", "-IB", "-m", "universal_db_mcp"], False),
        (["python3", "-X", "python", "-I", "-m", "universal_db_mcp"], False),
        (["-I", "-X", "python", "-m", "universal_db_mcp"], False),  # "python" is -X's value
        (["python3", "script.py", "-m", "universal_db_mcp"], False),
        (["python3", "-m", "other", "python", "-m", "universal_db_mcp"], False),
        (["run", "serve", "-m", "universal_db_mcp"], False),
        # Not a launch of this package.
        (["-m", "universal_db_mcpx"], False),
        (["-m", "other", "universal_db_mcp"], False),
        (["-c", "import universal_db_mcp", "-m", "universal_db_mcp"], False),
        (["script.py", "-m", "universal_db_mcp"], False),
        (["serve", "--transport", "stdio"], False),
        ("-m universal_db_mcp", False),
        (None, False),
    ],
)
def test_f46_starts_without_isolation(args: Any, unisolated: bool) -> None:
    assert agents_core.starts_without_isolation(args) is unisolated


@pytest.mark.parametrize("name", JSON_ADAPTERS)
def test_f46_fail_closed_entry_without_isolation_says_so(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # dsh already named the missing -I; the JSON adapters only said the entry
    # "differs", and operators kept the exploitable registration.
    h = _harness(name, tmp_path, monkeypatch)
    theirs = {**_legacy_entry(h), "command": "/old/venv/bin/python"}
    h.target.write_text(json.dumps({h.servers_key: {"universal-db": theirs}}, indent=2), encoding="utf-8")
    original = h.target.read_bytes()

    assert h.detect() is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    for summary in (h.plan().summary, h.apply(True).summary):
        assert "starts the server without -I" in summary
        assert 'add "-I" as the first "args" item' in summary
    assert h.target.read_bytes() == original

    # A differing entry that already runs isolated is not blamed on -I.
    theirs["args"] = ISOLATED_ARGS
    h.target.write_text(json.dumps({h.servers_key: {"universal-db": theirs}}, indent=2), encoding="utf-8")
    assert h.detect() is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    assert "without -I" not in h.plan().summary


@pytest.mark.skipif(sys.platform == "win32", reason="a drive path is absolute on a Windows host")
def test_f79_windows_appdata_is_not_absolute_on_a_posix_host(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Claude Desktop probes the Windows location on every OS: on macOS/Linux
    # C:\Users\me\AppData\Roaming is a relative name, and the CLI read (and
    # wrote) a Claude/ directory under its working directory.
    windows = "C:\\Users\\me\\AppData\\Roaming"
    home = tmp_path / "home"
    home.mkdir()
    assert agents_core.app_data_base({"APPDATA": windows}, home, "win32") == home / "AppData" / "Roaming"

    monkeypatch.setattr(claude_desktop, "SYSTEM_APP_PATHS", ())
    monkeypatch.chdir(tmp_path)
    planted = Path(windows) / "Claude" / "claude_desktop_config.json"
    planted.parent.mkdir(parents=True)
    planted.write_text("{}", encoding="utf-8")
    env = {**ENV, "APPDATA": windows}

    assert claude_desktop.config_path(env, home).is_absolute()
    assert claude_desktop.detect(env, home) is AgentStatus.NOT_INSTALLED


def _unregistrable_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """No harness installed under ``tmp_path/home``, and a UDBMCP_CONFIG that cannot be registered."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PATH", "")  # no `claude` binary
    monkeypatch.setenv("UDBMCP_CONFIG", "missing/nothing-here")  # dsh reads the process env
    for variable in ("APPDATA", "XDG_CONFIG_HOME", "UDBMCP_VENV_PYTHON"):
        monkeypatch.delenv(variable, raising=False)
    monkeypatch.setattr(claude_desktop, "SYSTEM_APP_PATHS", ())
    (tmp_path / "home").mkdir()
    return {"UDBMCP_CONFIG": "missing/nothing-here", "UDBMCP_VENV_PYTHON": FAKE_PYTHON}


@pytest.mark.parametrize("name", ADAPTERS)
def test_f58_not_installed_harness_plan_ignores_an_unregistrable_override(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The table said not_installed, then plan() resolved the registration
    # anyway and printed "FAIL CLOSED: adapter error (ConfigError ...)".
    from universal_db_mcp.agents import registry

    env = _unregistrable_env(tmp_path, monkeypatch)
    home = tmp_path / "home"

    assert registry.detect_status(name, env, home) is AgentStatus.NOT_INSTALLED
    assert registry.build_plan(name, env, home).status is AgentStatus.NOT_INSTALLED
    assert registry.apply_confirmed(name, env, home, True).status is AgentStatus.NOT_INSTALLED


def test_f58_configure_agents_reports_no_adapter_error_when_nothing_is_installed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _unregistrable_env(tmp_path, monkeypatch)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)  # a Linux host's own would win over HOME

    assert main(["configure-agents"]) == 0
    out = capsys.readouterr().out

    assert "adapter error" not in out and "CONFIG_ERROR" not in out
    assert out.count("not_installed") == len(ADAPTERS)


_APP_SCRIPT = Path(__file__).resolve().parents[2] / "packaging" / "macos-app" / "configure_agents_app.sh"
_APP_VENV_PY = 'VENV_PY="/usr/local/universal-db-mcp/venv/bin/python"\n'


def _run_app(tmp_path: Path, harnesses: list[dict[str, Any]], choose: str = "CANCELLED") -> tuple[int, list[str]]:
    """Run the Configure-Agents app script against a stub interpreter and a
    stub osascript; returns the exit status and every osascript invocation
    (its arguments, or the AppleScript it read from stdin)."""
    script = _APP_SCRIPT.read_text(encoding="utf-8")
    assert script.count(_APP_VENV_PY) == 1
    stubs = tmp_path / "stubs"
    stubs.mkdir()
    detection = tmp_path / "detect.json"
    detection.write_text(json.dumps({"home": str(tmp_path), "harnesses": harnesses}), encoding="utf-8")
    applied = json.dumps({"applied": [{"status": "configured", "summary": "registered"}]})
    venv_py = stubs / "venv-python"
    venv_py.write_text(
        "#!/bin/sh\n"
        'case "$*" in\n'
        f'  *"configure-agents --json") cat "{detection}" ;;\n'
        f"  *\"--json --yes\") echo '{applied}' ;;\n"
        f'  *) exec "{sys.executable}" "$@" ;;\n'
        "esac\n",
        encoding="utf-8",
    )
    log = tmp_path / "osascript.log"
    osascript = stubs / "osascript"
    osascript.write_text(
        "#!/bin/sh\n"
        f'{{ echo "== call"; if [ $# -eq 0 ]; then cat; echo "$CHOICE"; else printf "%s\\n" "$@"; fi; }} >> "{log}"\n'
        'if [ $# -eq 0 ]; then echo "$CHOICE"; fi\n',
        encoding="utf-8",
    )
    for stub in (venv_py, osascript):
        stub.chmod(0o755)
    app = tmp_path / "app.sh"
    app.write_text(script.replace(_APP_VENV_PY, f'VENV_PY="{venv_py}"\n'), encoding="utf-8")

    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is not installed")
    proc = subprocess.run(  # noqa: S603 - the packaged script, against stubs only
        [bash, str(app)],
        env={"PATH": f"{stubs}{os.pathsep}{os.environ.get('PATH', '')}", "HOME": str(tmp_path), "CHOICE": choose},
        capture_output=True,
        text=True,
        timeout=60,
    )
    calls = log.read_text(encoding="utf-8").split("== call\n")[1:] if log.exists() else []
    assert calls, f"osascript was never called; stderr:\n{proc.stderr}"
    return proc.returncode, calls


_BROKEN = [
    {"agent": "claude-code", "status": "adapter_error", "detail": "x", "writable": False},
    {"agent": "cursor", "status": "fail_closed", "detail": "y", "writable": False},
    {"agent": "vscode", "status": "unknown_state_fail_closed", "writable": False},
    {"agent": "cline", "status": "not_installed", "writable": False},
]


@pytest.mark.skipif(sys.platform == "win32", reason="the macOS app script runs under bash")
def test_app_reports_harnesses_that_failed_closed_instead_of_nothing_to_configure(tmp_path: Path) -> None:
    rc, calls = _run_app(tmp_path, _BROKEN)

    assert rc == 1
    (dialog,) = calls
    assert "with icon stop" in dialog and "No configurable agent harnesses found" not in dialog
    assert "claude-code, cursor, vscode" in dialog and "cline" not in dialog
    assert "universal_db_mcp configure-agents" in dialog


@pytest.mark.skipif(sys.platform == "win32", reason="the macOS app script runs under bash")
def test_app_still_says_nothing_to_configure_when_nothing_failed(tmp_path: Path) -> None:
    harnesses = [
        {"agent": "claude-code", "status": "configured", "writable": False},
        {"agent": "cline", "status": "not_installed", "writable": False},
    ]
    rc, calls = _run_app(tmp_path, harnesses)

    assert rc == 0
    (dialog,) = calls
    assert "No configurable agent harnesses found" in dialog and "with icon note" in dialog


@pytest.mark.skipif(sys.platform == "win32", reason="the macOS app script runs under bash")
def test_app_names_the_failed_harnesses_beside_the_configurable_ones(tmp_path: Path) -> None:
    harnesses = [{"agent": "claude-desktop", "status": "installed_unconfigured", "writable": True}, *_BROKEN]
    rc, calls = _run_app(tmp_path, harnesses, choose="claude-desktop")

    assert rc == 1
    choose, _confirm, report = calls
    assert 'harnessList to {"claude-desktop"}' in choose
    assert "claude-code, cursor, vscode" in choose
    assert "claude-desktop - configured: registered" in report
    assert "claude-code - FAILED" in report and "vscode - FAILED" in report and "cline" not in report


# ---------------------------------------------------------------------------
# Integration round 1: review findings on round 3
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", CREATING_ADAPTERS)
def test_f45_config_that_appears_after_the_absent_decision_is_never_clobbered(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The adapter decided "absent, so create" in detect(), and another writer
    # (the harness writing its first config) created the file before the
    # write: atomic_write_text found it and replaced it, with no backup, and
    # the result said "configured".
    h = _harness(name, tmp_path, monkeypatch)
    assert not h.target.exists()
    theirs = _existing_body(h)

    def other_writer_creates_it() -> None:
        with open(h.target, "x", encoding="utf-8") as fh:
            fh.write(theirs)

    if h.module is dsh:  # the dsh home already exists: no directory to create
        real_write = dsh.atomic_write_text

        def appears_just_before_the_write(target: Path, payload: str, **kwargs: Any) -> None:
            other_writer_creates_it()
            real_write(target, payload, **kwargs)

        monkeypatch.setattr(dsh, "atomic_write_text", appears_just_before_the_write)
    else:
        real_ensure = h.module.ensure_directory

        def appears_after_the_mkdir(directory: Path, **kwargs: Any) -> None:
            real_ensure(directory, **kwargs)
            other_writer_creates_it()

        monkeypatch.setattr(h.module, "ensure_directory", appears_after_the_mkdir)

    result = h.apply(True)

    assert _status(result) is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    assert "appeared" in (result.message if isinstance(result, dsh.ApplyResult) else result.summary)
    assert h.target.read_text(encoding="utf-8") == theirs
    assert _backups(h.target) == [] and _reported_backups(result) == []


def test_f45_seeded_config_that_appears_meanwhile_is_left_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # "Only-if-absent, never clobbered": an add-connection in another shell
    # wrote the per-user config after the seed found it absent.
    monkeypatch.setattr(agents_core, "SYSTEM_CONFIG_PATH", tmp_path / "no-system" / "config.yaml")
    home = tmp_path / "home"
    per_user = home / ".universal-db-mcp" / "config.yaml"
    mine = "connections:\n  mine: {type: sqlite, database: /x.db}\n"
    real_ensure = agents_core.ensure_directory

    def ensure_then_the_user_writes(directory: Path, **kwargs: Any) -> None:
        real_ensure(directory, **kwargs)
        with open(per_user, "x", encoding="utf-8") as fh:
            fh.write(mine)

    monkeypatch.setattr(agents_core, "ensure_directory", ensure_then_the_user_writes)

    seeded, note = agents_core.ensure_per_user_harness_config({}, home)

    assert seeded is None and "already present" in note
    assert per_user.read_text(encoding="utf-8") == mine


@_POSIX_ONLY
def test_f45_create_refuses_a_file_or_link_already_at_the_path(tmp_path: Path) -> None:
    target = tmp_path / "mcp.json"
    target.write_text("theirs\n", encoding="utf-8")
    link = tmp_path / "link.json"
    link.symlink_to(target)

    for path in (target, link):
        with pytest.raises(FileExistsError, match="appeared"):
            agents_core.atomic_write_text(path, "ours\n", create=True)

    assert target.read_text(encoding="utf-8") == "theirs\n" and link.is_symlink()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["link.json", "mcp.json"]


@_POSIX_ONLY
@pytest.mark.parametrize("name", ADAPTERS)
def test_f48_config_owned_by_another_user_is_refused_before_the_backup(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The refusal came only after the backup: every re-run against a managed
    # (root-owned) config left another user-owned copy of it.
    h = _with_existing(name, tmp_path, monkeypatch)
    original = h.target.read_bytes()
    user = h.target.stat().st_uid or 501
    real_target = os.path.realpath(h.target)
    real_stat = Path.stat

    def foreign_stat(self: Path, *, follow_symlinks: bool = True) -> os.stat_result:
        st = real_stat(self, follow_symlinks=follow_symlinks)
        if os.path.realpath(self) != real_target:
            return st
        fields: list[float] = list(st[:10])
        fields[4] = user + 1
        return os.stat_result(fields)

    monkeypatch.setattr(Path, "stat", foreign_stat)
    monkeypatch.setattr(os, "geteuid", lambda: user)

    result = h.apply(True)

    assert _status(result) is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    assert "owned by another user" in (result.message if isinstance(result, dsh.ApplyResult) else result.summary)
    assert h.target.read_bytes() == original
    assert _backups(h.target) == [] and _reported_backups(result) == []


@_POSIX_ONLY
@pytest.mark.skipif(_AS_ROOT, reason="root may write any file, as it always could")
def test_f48_claude_code_refuses_every_scope_before_any_backup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A read-only project file must not leave a backup of the user scope either.
    h = _with_existing("claude-code", tmp_path, monkeypatch)
    project = claude_code.project_config_path(tmp_path / "proj")
    # The project file is written only to upgrade this tool's own entry (G5).
    project.write_text(json.dumps({"mcpServers": {"universal-db": _legacy_entry(h)}}), encoding="utf-8")
    project.chmod(0o444)
    user_before = h.target.read_bytes()
    # Detection saw both scopes writable (the project file turned read-only
    # after it): apply()'s own check must still come before any backup.
    monkeypatch.setattr(claude_code, "unreplaceable_reason", lambda _target: None)

    result = h.apply(True)

    assert _status(result) is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    assert f"{project} is not writable" in result.summary
    assert "backed up: nothing; written: nothing" in result.summary
    assert h.target.read_bytes() == user_before
    assert _backups(h.target) == [] and _backups(project) == []


@pytest.mark.parametrize(
    "args", [["-m", "universal_db_mcp.__main__", "serve"], ["-muniversal_db_mcp", "serve"]], ids=["main", "attached"]
)
@pytest.mark.parametrize("name", JSON_ADAPTERS)
def test_f46_fail_closed_note_covers_every_unisolated_module_launch(
    name: str, args: list[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Both forms put the harness's working directory first on sys.path, as
    # the plain "-m universal_db_mcp" does, but got no -I note.
    h = _harness(name, tmp_path, monkeypatch)
    theirs = {**_legacy_entry(h), "args": args}
    h.target.write_text(json.dumps({h.servers_key: {"universal-db": theirs}}, indent=2), encoding="utf-8")
    original = h.target.read_bytes()

    assert h.detect() is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    for summary in (h.plan().summary, h.apply(True).summary):
        assert "starts the server without -I" in summary
    assert h.target.read_bytes() == original and _backups(h.target) == []


@pytest.mark.parametrize(
    "row",
    [
        _DSH_LEGACY_BLOCK.replace("'universal_db_mcp'", "'universal_db_mcp.__main__'"),
        _DSH_LEGACY_BLOCK.replace("'-m', 'universal_db_mcp'", "'-muniversal_db_mcp'"),
    ],
    ids=["main", "attached"],
)
def test_f46_dsh_every_unisolated_module_launch_fails_closed(
    row: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # These rows were reported "configured", keeping a launch that runs the
    # open project's yaml.py inside the server.
    h = _harness("dsh", tmp_path, monkeypatch)
    h.target.write_text(_DSH_EXISTING + row, encoding="utf-8")
    original = h.target.read_bytes()

    assert h.detect() is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    assert "without -I" in h.plan().summary
    result = h.apply(True)

    assert result.wrote is False and "without -I" in result.message
    assert h.target.read_bytes() == original and _backups(h.target) == []


_DSH_MAPPING_INSERT = "- insert:\n    id: mcp-universal-db\n    name: '@deepseek-ai/dsh-mcp-client'\n"


@pytest.mark.parametrize(
    "rows",
    [
        _DSH_MAPPING_INSERT,
        _DSH_LEGACY_BLOCK + _DSH_MAPPING_INSERT,
        _DSH_CURRENT_ROW + _DSH_MAPPING_INSERT,
        "- insert:\n    - id: mcp-universal-db\n      name: x\n    - just a string\n",
    ],
    ids=["mapping-alone", "legacy-then-mapping", "current-then-mapping", "list-with-a-string"],
)
def test_dsh_malformed_insert_block_with_our_id_fails_closed(
    rows: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # An "insert" that is not a list of mappings was skipped, so a legacy row
    # beside it was upgraded (or a new row appended): a second registration
    # whenever dsh reads that block too.
    h = _harness("dsh", tmp_path, monkeypatch)
    h.target.write_text(_DSH_EXISTING + rows, encoding="utf-8")
    original = h.target.read_bytes()

    assert h.detect() is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    summary = h.plan().summary
    assert "FAIL CLOSED" in summary and "not a list of mappings" in summary
    result = h.apply(True)

    assert result.wrote is False and "not a list of mappings" in result.message
    assert h.target.read_bytes() == original and _backups(h.target) == []


def test_dsh_malformed_insert_block_for_another_id_is_left_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Only a block that names our id could be a registration of ours.
    h = _harness("dsh", tmp_path, monkeypatch)
    h.target.write_text(_DSH_EXISTING + "- insert:\n    id: other-server\n", encoding="utf-8")

    assert h.detect() is AgentStatus.INSTALLED_UNCONFIGURED
    result = h.apply(True)

    assert result.wrote is True and _status(result) is AgentStatus.CONFIGURED


def test_dsh_apply_never_writes_beside_a_malformed_insert_with_our_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # One that appears between detect() and the write fails the pre-write gate.
    h = _harness("dsh", tmp_path, monkeypatch)
    h.target.write_text(_DSH_EXISTING, encoding="utf-8")
    raced = _DSH_EXISTING + _DSH_MAPPING_INSERT
    real_detect = dsh.detect

    def detect_then_race(env_home: Path) -> Any:
        status = real_detect(env_home)
        h.target.write_text(raced, encoding="utf-8")
        return status

    monkeypatch.setattr(dsh, "detect", detect_then_race)
    result = h.apply(True)

    assert result.wrote is False and _status(result) is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    assert "not a list of mappings" in result.message
    assert h.target.read_text(encoding="utf-8") == raced


# ---------------------------------------------------------------------------
# Integration round 2: review findings on round 1
# ---------------------------------------------------------------------------


_ERROR_ACCESS_DENIED = 5
_ERROR_SHARING_VIOLATION = 32


def _win32_error(code: int, path: Any) -> PermissionError:
    """The error a Win32 call (``_winapi``) raises for ``code``: EACCES for
    both codes above, told apart by ``winerror``. A POSIX Python ignores the
    constructor's winerror argument, so it is set by hand."""
    exc = PermissionError(errno.EACCES, f"WinError {code}", str(path))
    exc.winerror = code  # type: ignore[attr-defined]
    return exc


def _fake_winapi(shared: tuple[Path, ...] = ()) -> SimpleNamespace:
    """``_winapi`` on a simulated Windows host. ``CreateFile`` opens for
    writing what ``os.open`` may (the ACL) and fails with a sharing violation
    for ``shared``, files another program holds open without FILE_SHARE_WRITE."""
    held = {os.path.realpath(path) for path in shared}

    def create_file(
        name: str, access: int, share: int, security: int, disposition: int, flags: int, template: int
    ) -> int:
        assert (access, disposition, security, template) == (0x40000000, 3, 0, 0)  # GENERIC_WRITE, OPEN_EXISTING
        if os.path.realpath(name) in held:
            raise _win32_error(_ERROR_SHARING_VIOLATION, name)
        try:
            return os.open(name, os.O_WRONLY)
        except PermissionError:
            raise _win32_error(_ERROR_ACCESS_DENIED, name) from None

    return SimpleNamespace(
        GENERIC_WRITE=0x40000000, OPEN_EXISTING=3, NULL=0, CreateFile=create_file, CloseHandle=os.close
    )


def _as_windows_host(monkeypatch: pytest.MonkeyPatch, winapi: SimpleNamespace | None = None) -> None:
    """Run the platform branches as on Windows, where ``os.geteuid`` does not
    exist and ``_winapi`` does (``winapi``, or :func:`_fake_winapi`)."""
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.delattr(os, "geteuid", raising=False)
    monkeypatch.setitem(sys.modules, "_winapi", winapi or _fake_winapi())


def _deny_write_open(monkeypatch: pytest.MonkeyPatch, target: Path) -> None:
    """``os.open`` refuses to open ``target`` for writing, as a Windows ACL
    that grants this user read access only does (``os.access`` does not see it)."""
    real_open = os.open
    denied = os.path.realpath(target)

    def open_(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        if os.path.realpath(path) == denied and flags & (os.O_WRONLY | os.O_RDWR):
            raise PermissionError(errno.EACCES, "Access is denied", str(path))
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", open_)


def _message(result: Any) -> str:
    return str(result.message if isinstance(result, dsh.ApplyResult) else result.summary)


def test_i51_windows_write_check_opens_the_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # On Windows os.access sees only the read-only attribute: a config an ACL
    # keeps from this user (an Administrators- or Intune-deployed one) passed,
    # and the replace, which needs only the folder, rewrote it.
    target = tmp_path / "mcp.json"
    target.write_text("old\n", encoding="utf-8")
    _as_windows_host(monkeypatch)
    monkeypatch.setattr(os, "access", lambda *_args, **_kwargs: True)
    _deny_write_open(monkeypatch, target)

    with pytest.raises(PermissionError, match="not writable by this user"):
        agents_core.ensure_replaceable(target)
    with pytest.raises(PermissionError, match="not writable by this user"):
        agents_core.atomic_write_text(target, "ours\n")

    assert target.read_text(encoding="utf-8") == "old\n"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["mcp.json"]


def test_i51_windows_config_open_in_another_program_is_not_called_unwritable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A sharing violation is another program's open handle, not this user's
    # permission: the replace decides (and retries), as before. os.open goes
    # through the C runtime, which maps it to EACCES and drops the Windows
    # code (no winerror), so the probe cannot be os.open: it must be a
    # Win32 CreateFile, whose error keeps winerror 32.
    target = tmp_path / "mcp.json"
    target.write_text("old\n", encoding="utf-8")
    _as_windows_host(monkeypatch, _fake_winapi(shared=(target,)))
    _deny_write_open(monkeypatch, target)  # what the C runtime reports for it

    assert agents_core.unreplaceable_reason(target) is None
    agents_core.atomic_write_text(target, "ours\n")  # the replace is the verdict
    assert target.read_text(encoding="utf-8") == "ours\n"


@pytest.mark.parametrize("name", ADAPTERS)
def test_i51_windows_config_the_acl_keeps_from_this_user_is_never_replaced(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _as_windows_host(monkeypatch)
    monkeypatch.setattr(os, "access", lambda *_args, **_kwargs: True)
    h = _with_existing(name, tmp_path, monkeypatch)
    original = h.target.read_bytes()
    _deny_write_open(monkeypatch, h.target)

    assert h.detect() is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    result = h.apply(True)

    assert _status(result) is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    assert "not writable" in _message(result)
    assert h.target.read_bytes() == original
    assert _backups(h.target) == [] and _reported_backups(result) == []
    assert [p.name for p in h.target.parent.iterdir() if p.name.endswith(".tmp")] == []


@pytest.mark.parametrize("name", ADAPTERS)
def test_i51_windows_config_the_user_may_write_is_still_configured(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The control, and the pin on the owner check's Windows guard: there is no
    # os.geteuid to call.
    _as_windows_host(monkeypatch)
    h = _with_existing(name, tmp_path, monkeypatch)

    result = h.apply(True)

    assert _status(result) is AgentStatus.CONFIGURED
    assert len(_backups(h.target)) == 1


@_POSIX_ONLY
@pytest.mark.skipif(_AS_ROOT, reason="root may write any file, as it always could")
@pytest.mark.parametrize("name", ADAPTERS)
def test_i51_read_only_config_is_reported_fail_closed_before_a_write_is_offered(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # detect() said installed_unconfigured and the plan promised "would back up
    # ... then add", so --dry-run, --json (writable: true) and the macOS app
    # offered a write that apply() then refused.
    h = _with_existing(name, tmp_path, monkeypatch)
    h.target.chmod(0o444)
    original = h.target.read_bytes()

    assert h.detect() is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    planned = h.plan()

    assert planned.status is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    assert "not writable" in planned.summary
    assert "would back up" not in planned.summary and "would append" not in planned.summary
    assert h.target.read_bytes() == original and _backups(h.target) == []


@_POSIX_ONLY
@pytest.mark.skipif(_AS_ROOT, reason="root may write any file, as it always could")
@pytest.mark.parametrize("name", ADAPTERS)
def test_i51_read_only_legacy_registration_is_reported_fail_closed(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The upgradeable pre--I registration offered its upgrade the same way.
    h = _harness(name, tmp_path, monkeypatch)
    if h.module is dsh:
        h.target.write_text(_DSH_EXISTING + _DSH_LEGACY_BLOCK, encoding="utf-8")
    else:
        h.target.write_text(json.dumps({h.servers_key: {"universal-db": _legacy_entry(h)}}), encoding="utf-8")
    h.target.chmod(0o444)

    assert h.detect() is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    summary = h.plan().summary
    assert "not writable" in summary and "not upgraded automatically" not in summary


@_POSIX_ONLY
@pytest.mark.skipif(_AS_ROOT, reason="root may write any file, as it always could")
def test_i51_read_only_config_is_not_writable_in_json_or_dry_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    home = tmp_path / "home"
    target = home / ".cursor" / "mcp.json"
    target.parent.mkdir(parents=True)
    target.write_text(json.dumps({"mcpServers": {}}), encoding="utf-8")
    target.chmod(0o444)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)  # a Linux host's own would win over HOME
    for variable, value in ENV.items():
        monkeypatch.setenv(variable, value)

    main(["configure-agents", "--json", "--agent", "cursor"])
    (harness,) = json.loads(capsys.readouterr().out)["harnesses"]
    assert harness == {"agent": "cursor", "status": "unknown_state_fail_closed", "writable": False}

    main(["configure-agents", "--agent", "cursor", "--dry-run"])
    out = capsys.readouterr().out
    assert "not writable" in out and "would back up" not in out
    assert _backups(target) == []


@_POSIX_ONLY
@pytest.mark.skipif(_AS_ROOT, reason="root may write any file, as it always could")
@pytest.mark.parametrize("name", ADAPTERS)
def test_i51_config_made_read_only_after_detection_is_refused_before_the_backup(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Detection saw it writable; apply()'s own check still runs before the backup.
    h = _with_existing(name, tmp_path, monkeypatch)
    h.target.chmod(0o444)
    original = h.target.read_bytes()
    monkeypatch.setattr(h.module, "unreplaceable_reason", lambda _target: None)

    result = h.apply(True)

    assert _status(result) is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    assert "not writable" in _message(result)
    assert h.target.read_bytes() == original
    assert _backups(h.target) == [] and _reported_backups(result) == []


@_POSIX_ONLY
@pytest.mark.skipif(_AS_ROOT, reason="root may write any file, as it always could")
@pytest.mark.parametrize("name", ADAPTERS)
def test_i51_read_only_config_that_needs_no_write_is_still_configured(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    h = _harness(name, tmp_path, monkeypatch)
    if h.module is dsh:
        h.target.write_text(_DSH_EXISTING + _DSH_CURRENT_ROW, encoding="utf-8")
    else:
        current = {**_legacy_entry(h), "args": ISOLATED_ARGS}
        h.target.write_text(json.dumps({h.servers_key: {"universal-db": current}}), encoding="utf-8")
    h.target.chmod(0o444)

    assert h.detect() is AgentStatus.CONFIGURED


@_POSIX_ONLY
@pytest.mark.skipif(_AS_ROOT, reason="root may write any file, as it always could")
def test_i51_claude_code_read_only_project_file_is_reported_at_detection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    h = _with_existing("claude-code", tmp_path, monkeypatch)
    project = claude_code.project_config_path(tmp_path / "proj")
    # Written only to upgrade this tool's own entry in it (G5); one without
    # it is never written, so its mode does not matter.
    project.write_text(json.dumps({"mcpServers": {}}), encoding="utf-8")
    project.chmod(0o444)
    assert h.detect() is AgentStatus.INSTALLED_UNCONFIGURED
    project.chmod(0o644)
    project.write_text(json.dumps({"mcpServers": {"universal-db": _legacy_entry(h)}}), encoding="utf-8")
    project.chmod(0o444)

    assert h.detect() is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    planned = h.plan()
    assert f"{project} is not writable" in planned.summary and str(project) in planned.config_block

    # A read-only project file that already holds the registration is not written.
    project.chmod(0o644)
    current = {**_legacy_entry(h), "args": ISOLATED_ARGS}
    project.write_text(json.dumps({"mcpServers": {"universal-db": current}}), encoding="utf-8")
    project.chmod(0o444)
    assert h.detect() is AgentStatus.CONFIGURED


def test_i56_vscode_differing_entry_is_not_called_malformed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # "is unreadable or malformed", then "add -I to it", for a file that parses.
    h = _harness("vscode", tmp_path, monkeypatch)
    theirs = {**_legacy_entry(h), "command": "/old/python"}
    h.target.write_text(json.dumps({"servers": {"universal-db": theirs}}), encoding="utf-8")

    summary = h.plan().summary
    assert "malformed" not in summary and "unreadable" not in summary
    assert "differs" in summary and "starts the server without -I" in summary

    h.target.write_text("{ not json", encoding="utf-8")
    assert "malformed" in h.plan().summary


_OTHER_UNISOLATED = "udb"
_OTHER_ISOLATED = "isolated-udb"


def _write_other_servers(h: _Harness) -> None:
    """Two hand-written entries under other keys: one without -I, one with it."""
    if h.module is dsh:
        rows = "".join(
            f"- insert:\n    - id: {name}\n      config:\n"
            f"        command: /old/python\n        args: {json.dumps(args)}\n"
            for name, args in ((_OTHER_UNISOLATED, LEGACY_ARGS), (_OTHER_ISOLATED, ISOLATED_ARGS))
        )
        h.target.write_text(_DSH_EXISTING + rows, encoding="utf-8")
        return
    servers = {
        _OTHER_UNISOLATED: {"command": "/old/python", "args": LEGACY_ARGS},
        _OTHER_ISOLATED: {"command": "/old/python", "args": ISOLATED_ARGS},
    }
    h.target.write_text(json.dumps({h.servers_key: servers}), encoding="utf-8")


def _other_entries(h: _Harness) -> Any:
    if h.module is dsh:
        rows = yaml.safe_load(h.target.read_text(encoding="utf-8"))
        inserted = [e for row in rows if isinstance(row, dict) for e in row.get("insert", [])]
        return [e for e in inserted if e["id"] != dsh.REGISTRATION_ID]
    servers = json.loads(h.target.read_text(encoding="utf-8"))[h.servers_key]
    return {k: v for k, v in servers.items() if k != "universal-db"}


@pytest.mark.parametrize("name", ADAPTERS)
def test_i56_other_entry_that_starts_the_server_without_isolation_is_named(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # configure-agents added "universal-db" beside the operator's own "udb"
    # launch without -I, said "configured", and left that launch exploitable
    # without a word.
    h = _harness(name, tmp_path, monkeypatch)
    _write_other_servers(h)
    others = _other_entries(h)

    planned = h.plan()
    result = h.apply(True)
    configured = h.plan()

    assert _status(result) is AgentStatus.CONFIGURED and configured.status is AgentStatus.CONFIGURED
    for text in (planned.summary, _message(result), configured.summary):
        assert f"{_OTHER_UNISOLATED}\"" in text or f"'{_OTHER_UNISOLATED}'" in text, text
        assert "without -I" in text and str(h.target) in text
        assert _OTHER_ISOLATED not in text
    assert _other_entries(h) == others, "the operator's entries are never changed"


@pytest.mark.parametrize("name", JSON_ADAPTERS)
def test_i56_this_tools_own_legacy_entry_is_not_named_as_another(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # It is upgraded, and the plan says so; no second warning about it.
    h = _harness(name, tmp_path, monkeypatch)
    h.target.write_text(json.dumps({h.servers_key: {"universal-db": _legacy_entry(h)}}), encoding="utf-8")

    summary = h.plan().summary
    assert "isolated mode (-I)" in summary and "WARNING" not in summary


def test_i56_claude_code_project_entry_without_isolation_is_named(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Claude Code also launches ~/.claude.json's per-project servers.
    h = _harness("claude-code", tmp_path, monkeypatch)
    projects = {
        "/work/app": {"mcpServers": {"universal-db": {"command": "/old/python", "args": LEGACY_ARGS}}},
        "/work/other": {"mcpServers": {"db": {"command": "/old/python", "args": ISOLATED_ARGS}}},
    }
    h.target.write_text(json.dumps({"projects": projects}), encoding="utf-8")

    for text in (h.plan().summary, h.apply(True).summary):
        assert '"projects"["/work/app"]["mcpServers"]["universal-db"]' in text and "without -I" in text
        assert "/work/other" not in text
    assert json.loads(h.target.read_text(encoding="utf-8"))["projects"] == projects


def test_i57_root_relative_appdata_is_not_trusted_on_windows(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # \Users\x has no drive: Windows resolves it against the drive the CLI
    # was started from (ntpath.isabs accepts it on Python 3.12).
    monkeypatch.setattr(sys, "platform", "win32")
    home = tmp_path / "home"

    assert agents_core.app_data_base({"APPDATA": "\\Users\\x"}, home, "win32") == home / "AppData" / "Roaming"


def _system_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: int = 0o600) -> Path:
    system = tmp_path / "etc" / "universal-db-mcp" / "config.yaml"
    system.parent.mkdir(parents=True)
    system.write_text("application:\n  transport: stdio\n", encoding="utf-8")
    system.chmod(mode)
    monkeypatch.setattr(agents_core, "SYSTEM_CONFIG_PATH", system)
    return system


def _owned_by_another_user(monkeypatch: pytest.MonkeyPatch, path: Path) -> None:
    real_stat = Path.stat
    other = os.stat(path).st_uid + 1

    def stat_(self: Path, *, follow_symlinks: bool = True) -> os.stat_result:
        st = real_stat(self, follow_symlinks=follow_symlinks)
        if os.path.abspath(self) != os.path.abspath(path):
            return st
        fields: list[float] = list(st[:10])
        fields[4] = other
        return os.stat_result(fields)

    monkeypatch.setattr(Path, "stat", stat_)


@_POSIX_ONLY
def test_i52_sudo_registration_advertises_only_a_config_the_harness_user_can_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # As root every file is readable: `sudo configure-agents` registered the
    # root-only system config, and every spawn of the user's harness died.
    system = _system_config(tmp_path, monkeypatch)  # 0600, this user's
    home = tmp_path / "home"
    home.mkdir()
    per_user = os.path.abspath(home / ".universal-db-mcp" / "config.yaml")
    monkeypatch.setattr(os, "geteuid", lambda: 0)

    # The harness runs as home's owner, who here owns the config too.
    assert agents_core.resolve_harness_config_path({}, home, for_harness=True) == str(system)

    _owned_by_another_user(monkeypatch, home)
    assert agents_core.resolve_harness_config_path({}, home, for_harness=True) == per_user
    assert cursor.registration_entry({"UDBMCP_VENV_PYTHON": FAKE_PYTHON}, home)["env"]["UDBMCP_CONFIG"] == per_user
    # The operator's own view (sudo doctor, add-connection) is unchanged.
    assert agents_core.resolve_harness_config_path({}, home) == str(system)


@_POSIX_ONLY
def test_i52_harness_user_read_check_follows_the_permission_classes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import pwd

    config = tmp_path / "config.yaml"
    config.write_text("application: {}\n", encoding="utf-8")
    me = os.getuid()
    try:
        user = pwd.getpwuid(me)
    except KeyError:
        pytest.skip("this uid has no user-database entry")
    if config.stat().st_gid not in os.getgrouplist(user.pw_name, user.pw_gid):
        pytest.skip("the new file's group is not one of this user's groups")

    def readable(mode: int) -> bool:
        config.chmod(mode)
        return agents_core._mode_bits_allow_read(config, me, -1)

    # As the owner: only the owner bits count.
    assert readable(0o400) and not readable(0o044)
    # As a member of the file's group: only the group bits count.
    _owned_by_another_user(monkeypatch, config)
    assert readable(0o640) and not readable(0o604) and not readable(0o600)


@_POSIX_ONLY
def test_i52_sudo_run_seeds_the_per_user_config_it_registers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _system_config(tmp_path, monkeypatch)
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(os, "chown", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(os, "fchown", lambda *_args, **_kwargs: None)
    _owned_by_another_user(monkeypatch, home)

    seeded, _note = agents_core.ensure_per_user_harness_config({}, home)

    assert seeded == home / ".universal-db-mcp" / "config.yaml" and seeded.is_file()


def test_i52_elevated_windows_prompt_does_not_register_the_system_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # An elevated token opens the administrators-only deployment; the user's
    # own harness, started from a filtered token, cannot.
    system = _system_config(tmp_path, monkeypatch, 0o644)
    home = tmp_path / "home"
    per_user = os.path.abspath(home / ".universal-db-mcp" / "config.yaml")
    if sys.platform != "win32":
        assert agents_core._windows_token_is_elevated() is False  # no windll to ask
    _as_windows_host(monkeypatch)
    monkeypatch.setattr(agents_core, "_windows_token_is_elevated", lambda: True)

    assert agents_core.resolve_harness_config_path({}, home, for_harness=True) == per_user
    assert agents_core.resolve_harness_config_path({}, home) == os.path.abspath(system)

    monkeypatch.setattr(agents_core, "_windows_token_is_elevated", lambda: False)
    assert agents_core.resolve_harness_config_path({}, home, for_harness=True) == os.path.abspath(system)


# ---------------------------------------------------------------------------
# Integration round 3: review findings on round 2
# ---------------------------------------------------------------------------

# Hand-written launches through a wrapper: the interpreter is itself an
# argument, and its options (no -I) follow it.
_WRAPPED_LAUNCHES: dict[str, tuple[str, list[str]]] = {
    "env": ("/usr/bin/env", ["python3", *LEGACY_ARGS]),
    "uv-run-python": ("/usr/local/bin/uv", ["run", "python", *LEGACY_ARGS]),
    "uv-run-module": ("uv", ["run", *LEGACY_ARGS]),
    "uv-run-python-option": ("uv", ["run", "--python", "python3.12", *LEGACY_ARGS]),
}
# "-I" as the first item would be env's (or uv's) option, not python's.
_WRAPPED_ADVICE = {
    "env": 'add "-I" right before "-m" in "args"',
    "uv-run-python": 'add "-I" right before "-m" in "args"',
    "uv-run-module": 'insert "python", "-I" right before "-m" in "args"',
    # The -m is uv's --module: "-I" right before it would be uv's option.
    "uv-run-python-option": 'insert "python", "-I" right before "-m" in "args"',
}


@pytest.mark.parametrize("wrapper", sorted(_WRAPPED_LAUNCHES))
@pytest.mark.parametrize("name", JSON_ADAPTERS)
def test_i56_entry_that_starts_the_server_through_a_wrapper_says_so(
    name: str, wrapper: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # "/usr/bin/env python3 -m universal_db_mcp" puts the harness's working
    # directory first on sys.path as a bare "-m" does, but the fail-closed
    # summary never mentioned -I.
    h = _harness(name, tmp_path, monkeypatch)
    command, args = _WRAPPED_LAUNCHES[wrapper]
    theirs = {**_legacy_entry(h), "command": command, "args": args}
    h.target.write_text(json.dumps({h.servers_key: {"universal-db": theirs}}, indent=2), encoding="utf-8")
    original = h.target.read_bytes()

    assert h.detect() is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    for summary in (h.plan().summary, _message(h.apply(True))):
        assert "starts the server without -I" in summary
        assert _WRAPPED_ADVICE[wrapper] in summary and "as the first" not in summary
    assert h.target.read_bytes() == original and _backups(h.target) == []


@pytest.mark.parametrize("name", ADAPTERS)
def test_i56_other_entry_that_starts_the_server_through_a_wrapper_is_named(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    h = _harness(name, tmp_path, monkeypatch)
    command, args = _WRAPPED_LAUNCHES["env"]
    if h.module is dsh:
        row = f"- insert:\n    - id: {_OTHER_UNISOLATED}\n      config:\n        command: {command}\n"
        h.target.write_text(_DSH_EXISTING + row + f"        args: {json.dumps(args)}\n", encoding="utf-8")
    else:
        servers = {_OTHER_UNISOLATED: {"command": command, "args": args}}
        h.target.write_text(json.dumps({h.servers_key: servers}), encoding="utf-8")
    others = _other_entries(h)

    planned = h.plan()
    result = h.apply(True)

    assert _status(result) is AgentStatus.CONFIGURED
    for text in (planned.summary, _message(result)):
        assert f"{_OTHER_UNISOLATED}\"" in text or f"'{_OTHER_UNISOLATED}'" in text, text
        assert "without -I" in text and 'run python with "-I" before its "-m"' in text
        assert "as the first" not in text
    assert _other_entries(h) == others


_DSH_WRAPPED_ROWS = {
    wrapper: _DSH_CURRENT_ROW.replace(f"command: {FAKE_PYTHON}", f"command: {command}").replace(
        "args: ['-I', '-m', 'universal_db_mcp', 'serve', '--transport', 'stdio']", f"args: {json.dumps(args)}"
    )
    for wrapper, (command, args) in _WRAPPED_LAUNCHES.items()
}


@pytest.mark.parametrize("wrapper", sorted(_DSH_WRAPPED_ROWS))
def test_i56_dsh_row_that_starts_the_server_through_a_wrapper_fails_closed(
    wrapper: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Any row with our id counted as registered: this exploitable launch was
    # reported "configured", where the same launch without the wrapper failed closed.
    h = _harness("dsh", tmp_path, monkeypatch)
    h.target.write_text(_DSH_EXISTING + _DSH_WRAPPED_ROWS[wrapper], encoding="utf-8")
    original = h.target.read_bytes()

    assert h.detect() is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    summary = h.plan().summary
    assert "FAIL CLOSED" in summary and "without -I" in summary and _WRAPPED_ADVICE[wrapper] in summary
    result = h.apply(True)

    assert result.wrote is False and "without -I" in result.message
    assert h.target.read_bytes() == original and _backups(h.target) == []


def test_i56_dsh_isolated_row_through_a_wrapper_is_still_configured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    h = _harness("dsh", tmp_path, monkeypatch)
    row = _DSH_WRAPPED_ROWS["env"].replace("[\"python3\", \"-m\",", "[\"python3\", \"-I\", \"-m\",")
    assert '"-I"' in row
    h.target.write_text(_DSH_EXISTING + row, encoding="utf-8")

    assert h.detect() is AgentStatus.CONFIGURED


def _crlf(text: str) -> str:
    return text.replace("\n", "\r\n")


def test_i55_dsh_upgrade_keeps_crlf_line_endings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The plan promises "all other bytes preserved untouched", but the patch
    # was read with universal newlines and every CRLF was written back as LF.
    h = _harness("dsh", tmp_path, monkeypatch)
    h.target.write_bytes(_crlf(_DSH_EXISTING + _DSH_LEGACY_BLOCK).encode("utf-8"))
    original = h.target.read_bytes()
    assert h.detect() is AgentStatus.INSTALLED_UNCONFIGURED
    assert "all other bytes preserved untouched" in h.plan().summary

    result = h.apply(True)

    assert result.wrote is True and _status(result) is AgentStatus.CONFIGURED
    assert h.target.read_bytes() == original.replace(b"args: ['-m',", b"args: ['-I', '-m',")
    assert result.backup_path is not None and result.backup_path.read_bytes() == original
    assert h.detect() is AgentStatus.CONFIGURED


@pytest.mark.parametrize("final_newline", [True, False], ids=["final-newline", "no-final-newline"])
def test_i55_dsh_append_keeps_crlf_line_endings(
    final_newline: bool, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # "existing rows preserved untouched", and the appended row follows the file's line endings.
    h = _harness("dsh", tmp_path, monkeypatch)
    existing = _crlf(_DSH_EXISTING)
    if not final_newline:
        existing = existing.removesuffix("\r\n")
    h.target.write_bytes(existing.encode("utf-8"))

    result = h.apply(True)

    assert result.wrote is True and _status(result) is AgentStatus.CONFIGURED
    written = h.target.read_bytes()
    separator = "" if final_newline else "\r\n"
    assert written == (existing + separator + _crlf(dsh._registration_block())).encode("utf-8")
    assert b"\n" not in written.replace(b"\r\n", b"")
    assert h.detect() is AgentStatus.CONFIGURED


# ---------------------------------------------------------------------------
# Integration round 4: review findings on round 3
# ---------------------------------------------------------------------------


def _with_acl(monkeypatch: pytest.MonkeyPatch, target: Path) -> None:
    """``target`` carries an access control list, as ``setfacl`` (Linux) or
    ``chmod +a`` (macOS) leave one."""
    marked = os.path.realpath(target)
    monkeypatch.setattr(
        agents_core,
        "_access_control_lists",
        lambda real: ([("user:0", "allow", "read")] if os.path.realpath(real) == marked else [], []),
    )


@pytest.mark.parametrize("name", ADAPTERS)
def test_i51_config_with_an_access_control_list_is_never_replaced(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The atomic replace gives the config a new inode, and the ACL stayed on
    # the old one: a Linux "g::---" beside a 0640 mode came back as group
    # read, and a macOS "deny read" disappeared, opening other servers'
    # tokens. The in-place write of earlier releases kept it.
    h = _with_existing(name, tmp_path, monkeypatch)
    original = h.target.read_bytes()
    _with_acl(monkeypatch, h.target)

    assert h.detect() is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    planned = h.plan()
    assert "access control list" in planned.summary and "would back up" not in planned.summary
    result = h.apply(True)

    assert _status(result) is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    assert "access control list" in _message(result)
    assert h.target.read_bytes() == original
    assert _backups(h.target) == [] and _reported_backups(result) == []


@pytest.mark.parametrize("name", ADAPTERS)
def test_i51_acl_found_only_at_apply_is_refused_before_the_backup(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    h = _with_existing(name, tmp_path, monkeypatch)
    original = h.target.read_bytes()
    monkeypatch.setattr(h.module, "unreplaceable_reason", lambda _target: None)
    _with_acl(monkeypatch, h.target)

    result = h.apply(True)

    assert _status(result) is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    assert "access control list" in _message(result)
    assert h.target.read_bytes() == original
    assert _backups(h.target) == [] and _reported_backups(result) == []


def test_i51_atomic_write_refuses_a_target_with_an_access_control_list(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "mcp.json"
    target.write_text("old\n", encoding="utf-8")
    _with_acl(monkeypatch, target)

    with pytest.raises(OSError, match="access control list"):
        agents_core.atomic_write_text(target, "ours\n")

    assert target.read_text(encoding="utf-8") == "old\n"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["mcp.json"]


def test_i51_linux_acl_probe_reads_the_posix_acl_attributes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "mcp.json"
    target.write_text("{}\n", encoding="utf-8")
    asked: list[tuple[str, str]] = []
    held: dict[tuple[str, str], bytes] = {}

    def getxattr(path: Any, attribute: str, *, follow_symlinks: bool = True) -> bytes:
        asked.append((os.fspath(path), attribute))
        try:
            return held[(os.fspath(path), attribute)]
        except KeyError:
            raise OSError(errno.ENODATA, "No data available") from None

    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(os, "getxattr", getxattr, raising=False)

    # The file's access ACL and the default ACL its directory gives new files.
    assert agents_core._access_control_lists(target) == ([], [])
    assert sorted(asked) == [(str(tmp_path), "system.posix_acl_default"), (str(target), "system.posix_acl_access")]
    held[(str(target), "system.posix_acl_access")] = _INHERITED_ACL
    held[(str(tmp_path), "system.posix_acl_default")] = _DEFAULT_ACL
    own, given = agents_core._access_control_lists(target)
    assert own == given == [(_ACL_USER, 4, 1001), (_ACL_GROUP_OBJ, 5, _ACL_UNDEFINED_ID)]


def _acl_tool(*argv: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    """Run a system ACL tool (chmod/ls on macOS, setfacl/getfacl on Linux) on a tmp file."""
    return subprocess.run(  # noqa: S603 - a system tool, on a file under tmp_path
        [shutil.which(argv[0]) or argv[0], *argv[1:]], capture_output=True, text=True, check=check
    )


@pytest.mark.skipif(sys.platform != "darwin", reason="chmod +a sets a macOS access control list")
def test_i51_macos_config_with_an_access_control_list_is_never_replaced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    h = _with_existing("cursor", tmp_path, monkeypatch)
    _acl_tool("/bin/chmod", "+a", "user:daemon deny read", str(h.target))
    original = h.target.read_bytes()

    assert h.detect() is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    result = h.apply(True)

    assert _status(result) is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED and "access control list" in result.summary
    assert h.target.read_bytes() == original and _backups(h.target) == []
    assert "user:daemon deny read" in _acl_tool("/bin/ls", "-le", str(h.target)).stdout

    # Without the ACL, the same config is written.
    _acl_tool("/bin/chmod", "-N", str(h.target))
    assert h.detect() is AgentStatus.INSTALLED_UNCONFIGURED
    assert _status(h.apply(True)) is AgentStatus.CONFIGURED


@pytest.mark.skipif(
    not sys.platform.startswith("linux") or shutil.which("setfacl") is None,
    reason="setfacl sets a POSIX access control list on Linux",
)
def test_i51_linux_config_with_a_posix_acl_is_never_replaced(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    h = _with_existing("cursor", tmp_path, monkeypatch)
    h.target.chmod(0o600)
    proc = _acl_tool("setfacl", "-m", "u:0:r,g::---", str(h.target), check=False)
    if proc.returncode != 0:
        pytest.skip(f"this filesystem takes no POSIX ACL: {proc.stderr.strip()}")
    original = h.target.read_bytes()

    assert h.detect() is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    result = h.apply(True)

    assert _status(result) is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED and "access control list" in result.summary
    assert h.target.read_bytes() == original and _backups(h.target) == []
    acl = _acl_tool("getfacl", "-cp", str(h.target)).stdout
    assert "user:0:r--" in acl or "user:root:r--" in acl

    # Without the ACL, the same config is written.
    _acl_tool("setfacl", "-b", str(h.target))
    assert h.detect() is AgentStatus.INSTALLED_UNCONFIGURED
    assert _status(h.apply(True)) is AgentStatus.CONFIGURED


@_POSIX_ONLY
@pytest.mark.skipif(_AS_ROOT, reason="root may write any directory, as it always could")
@pytest.mark.parametrize("name", ADAPTERS)
def test_i51_config_in_a_read_only_directory_is_reported_fail_closed(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The replace creates its temp file beside the config: detection offered
    # the write (writable: true, "would back up") and apply() then refused it.
    h = _with_existing(name, tmp_path, monkeypatch)
    original = h.target.read_bytes()
    directory = h.target.parent
    directory.chmod(0o555)
    try:
        detected = h.detect()
        planned = h.plan()
        result = h.apply(True)
    finally:
        directory.chmod(0o755)

    assert detected is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    assert f"{os.path.realpath(directory)} is not writable" in planned.summary
    assert "would back up" not in planned.summary and "would append" not in planned.summary
    assert _status(result) is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    assert h.target.read_bytes() == original
    assert _backups(h.target) == [] and _reported_backups(result) == []


@_POSIX_ONLY
@pytest.mark.skipif(_AS_ROOT, reason="root may write any directory, as it always could")
@pytest.mark.parametrize("name", CREATING_ADAPTERS)
def test_i51_absent_config_in_a_read_only_directory_is_reported_fail_closed(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    h = _harness(name, tmp_path, monkeypatch)
    assert not h.target.exists()
    directory = h.target.parent
    directory.chmod(0o555)
    try:
        detected = h.detect()
        planned = h.plan()
        result = h.apply(True)
    finally:
        directory.chmod(0o755)

    assert detected is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    assert f"{os.path.realpath(directory)} is not writable" in planned.summary
    assert "would create" not in planned.summary and "would be created" not in planned.summary
    assert _status(result) is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    assert not h.target.exists()


@_POSIX_ONLY
@pytest.mark.skipif(_AS_ROOT, reason="root may write any directory, as it always could")
def test_i51_missing_config_is_judged_by_its_nearest_existing_directory(tmp_path: Path) -> None:
    locked = tmp_path / "locked"
    locked.mkdir()
    target = locked / "Claude" / "sub" / "claude_desktop_config.json"
    assert agents_core.unreplaceable_reason(target) is None
    locked.chmod(0o555)
    try:
        reason = agents_core.unreplaceable_reason(target)
    finally:
        locked.chmod(0o755)
    assert reason is not None and f"{os.path.realpath(locked)} is not writable" in reason


@pytest.mark.parametrize(
    ("first", "row"), [("\n", "\r\n"), ("\r\n", "\n")], ids=["lf-then-crlf-row", "crlf-then-lf-row"]
)
def test_i55_dsh_mixed_line_endings_fail_closed_at_detection(
    first: str, row: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Detection read the patch with universal newlines and offered the
    # upgrade; apply() looked for the row with the first line's ending, found
    # none, appended a second row behind a backup and failed its own gate.
    h = _harness("dsh", tmp_path, monkeypatch)
    h.target.write_bytes(("# user patch layer" + first + _DSH_LEGACY_BLOCK.replace("\n", row)).encode("utf-8"))
    original = h.target.read_bytes()

    assert h.detect() is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    summary = h.plan().summary
    assert "upgrade-registration" not in summary and "without -I" in summary
    result = h.apply(True)

    assert result.wrote is False and "without -I" in result.message and "verification" not in result.message
    assert h.target.read_bytes() == original
    assert _backups(h.target) == [] and result.backup_path is None


_RUN_ADVICE = 'insert "python", "-I" right before "-m" in "args"'


@pytest.mark.parametrize(
    ("args", "advice"),
    [
        (LEGACY_ARGS, 'add "-I" as the first "args" item'),
        (["python3", *LEGACY_ARGS], 'add "-I" right before "-m" in "args"'),
        (["run", *LEGACY_ARGS], _RUN_ADVICE),
        # The value of uv's --python names the interpreter; the -m after it is uv's --module.
        (["run", "--python", "python3.12", *LEGACY_ARGS], _RUN_ADVICE),
        (["run", "-p", "python3.12", *LEGACY_ARGS], _RUN_ADVICE),
        (["run", "--with", "x", "--python", "python3.12", *LEGACY_ARGS], _RUN_ADVICE),
        (["run", "--python", "python3.12", "python", *LEGACY_ARGS], 'add "-I" right before "-m" in "args"'),
    ],
)
def test_i56_isolation_advice_puts_i_where_the_interpreter_reads_it(args: list[str], advice: str) -> None:
    assert agents_core.starts_without_isolation(args)
    assert agents_core.isolation_advice(args) == advice


def _as_root(monkeypatch: pytest.MonkeyPatch) -> None:
    """Run as under ``sudo``: euid 0, and the ownership changes root makes succeed."""
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(os, "chown", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(os, "fchown", lambda *_args, **_kwargs: None)


@_POSIX_ONLY
@pytest.mark.parametrize("name", ADAPTERS)
def test_i51_sudo_run_never_writes_through_a_link_to_a_file_the_user_does_not_own(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # As root the owner check passes every file, and the replace followed a
    # link the user planted (~/.cursor/mcp.json -> a root-owned file).
    h = _harness(name, tmp_path, monkeypatch)
    victim = tmp_path / "etc" / "victim.conf"
    victim.parent.mkdir()
    victim.write_text(_existing_body(h), encoding="utf-8")
    h.target.symlink_to(victim)
    original = victim.read_bytes()
    _owned_by_another_user(monkeypatch, victim)
    _as_root(monkeypatch)

    assert h.detect() is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    assert f"{h.target} is a symlink" in h.plan().summary
    result = h.apply(True)

    assert _status(result) is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    assert victim.read_bytes() == original and h.target.is_symlink()
    assert _backups(h.target) == [] and _backups(victim) == [] and _reported_backups(result) == []


@_POSIX_ONLY
@pytest.mark.parametrize("name", CREATING_ADAPTERS)
def test_i51_sudo_run_never_creates_a_file_through_a_dangling_link(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A dangling link into a root-owned directory (/etc/sudoers.d/x) had root
    # create a file there.
    h = _harness(name, tmp_path, monkeypatch)
    etc = tmp_path / "etc"
    etc.mkdir()
    h.target.symlink_to(etc / "planted")
    _owned_by_another_user(monkeypatch, etc)
    _as_root(monkeypatch)

    assert h.detect() is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    assert f"{h.target} is a symlink" in h.plan().summary
    result = h.apply(True)

    assert _status(result) is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    assert list(etc.iterdir()) == [] and h.target.is_symlink()


@_POSIX_ONLY
@pytest.mark.parametrize("existing", [True, False], ids=["replace", "create"])
def test_i51_atomic_write_as_root_refuses_a_link_its_owner_may_not_follow(
    existing: bool, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Every write checks, not only detection: the per-user config seed, or a
    # link planted after detection.
    etc = tmp_path / "etc"
    etc.mkdir()
    victim = etc / "victim.conf"
    if existing:
        victim.write_text("root's\n", encoding="utf-8")
    link = tmp_path / "home" / "mcp.json"
    link.parent.mkdir()
    link.symlink_to(victim)
    _owned_by_another_user(monkeypatch, victim if existing else etc)
    _as_root(monkeypatch)

    with pytest.raises(PermissionError, match=f"{link} is a symlink"):
        agents_core.atomic_write_text(link, "ours\n", create=not existing)

    assert sorted(p.name for p in etc.iterdir()) == (["victim.conf"] if existing else [])
    assert not existing or victim.read_text(encoding="utf-8") == "root's\n"


@_POSIX_ONLY
def test_i51_sudo_run_still_writes_through_a_link_to_the_users_own_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A dotfiles link the user owns, to a file the user owns, is written through.
    h = _harness("cursor", tmp_path, monkeypatch)
    dotfiles = tmp_path / "dotfiles" / "mcp.json"
    dotfiles.parent.mkdir()
    dotfiles.write_text(_existing_body(h), encoding="utf-8")
    h.target.symlink_to(dotfiles)
    _as_root(monkeypatch)

    assert h.detect() is AgentStatus.INSTALLED_UNCONFIGURED
    assert _status(h.apply(True)) is AgentStatus.CONFIGURED
    assert h.target.is_symlink() and _registered(h) is not None


@_POSIX_ONLY
def test_i51_sudo_run_never_creates_directories_through_a_link_to_another_users_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    etc = tmp_path / "etc"
    etc.mkdir()
    (home / ".config").symlink_to(etc)
    _owned_by_another_user(monkeypatch, etc)
    _as_root(monkeypatch)

    with pytest.raises(PermissionError, match="is a symlink"):
        agents_core.ensure_directory(home / ".config" / "Code" / "User")
    assert list(etc.iterdir()) == []


def test_i57_relative_localappdata_is_ignored(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # %LOCALAPPDATA% relative to the CLI's working directory: an
    # AnthropicClaude folder in the open repository made Claude Desktop
    # "installed", and apply created %APPDATA%\Claude\claude_desktop_config.json.
    home = tmp_path / "home"
    home.mkdir()
    project = tmp_path / "project"
    (project / "rel" / "AnthropicClaude").mkdir(parents=True)
    local = tmp_path / "local"
    (local / "AnthropicClaude").mkdir(parents=True)
    monkeypatch.chdir(project)
    monkeypatch.setattr(claude_desktop, "SYSTEM_APP_PATHS", ())
    monkeypatch.setattr(sys, "platform", "win32")

    assert claude_desktop._app_installed({"LOCALAPPDATA": "rel"}, home) is False
    assert claude_desktop._app_installed({"LOCALAPPDATA": str(local)}, home) is True


# ---------------------------------------------------------------------------
# Final round: review findings on the integrated tree
# ---------------------------------------------------------------------------

# <linux/posix_acl_xattr.h>: a version header, then (tag, perm, id) entries.
_ACL_USER_OBJ, _ACL_USER, _ACL_GROUP_OBJ, _ACL_GROUP, _ACL_MASK, _ACL_OTHER = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20
_ACL_UNDEFINED_ID = 0xFFFFFFFF


def _posix_acl(*entries: tuple[int, int, int]) -> bytes:
    return struct.pack("<I", 2) + b"".join(struct.pack("<HHI", *entry) for entry in entries)


def _posix_acl_base(user: int, group: int, mask: int, other: int, *named: tuple[int, int, int]) -> bytes:
    """A POSIX ACL with the owner, owning group, mask and other entries, plus ``named`` ones."""
    return _posix_acl(
        (_ACL_USER_OBJ, user, _ACL_UNDEFINED_ID),
        *(entry for entry in named if entry[0] == _ACL_USER),
        (_ACL_GROUP_OBJ, group, _ACL_UNDEFINED_ID),
        *(entry for entry in named if entry[0] != _ACL_USER),
        (_ACL_MASK, mask, _ACL_UNDEFINED_ID),
        (_ACL_OTHER, other, _ACL_UNDEFINED_ID),
    )


# `setfacl -d -m u:1001:r` on a 0755 directory, and what a 0666 create in it inherits.
_DEFAULT_ACL = _posix_acl_base(7, 5, 5, 5, (_ACL_USER, 4, 1001))
_INHERITED_ACL = _posix_acl_base(6, 5, 4, 4, (_ACL_USER, 4, 1001))


def _linux_xattrs(monkeypatch: pytest.MonkeyPatch, attributes: dict[tuple[Path, str], bytes]) -> None:
    """Run the ACL probes as on Linux, over ``attributes`` ((path, name) -> value)."""
    held = {(os.path.realpath(path), name): value for (path, name), value in attributes.items()}

    def getxattr(path: Any, attribute: str, *, follow_symlinks: bool = True) -> bytes:
        try:
            return held[(os.path.realpath(path), attribute)]
        except KeyError:
            raise OSError(errno.ENODATA, "No data available", str(path)) from None

    def listxattr(path: Any, *, follow_symlinks: bool = True) -> list[str]:
        return [name for real, name in held if real == os.path.realpath(path)]

    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(os, "getxattr", getxattr, raising=False)
    monkeypatch.setattr(os, "listxattr", listxattr, raising=False)


def test_final_linux_acl_the_directory_gives_every_new_file_is_not_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # In a directory with a default ACL every file has an access ACL, so every
    # config there was refused with "replacing it would drop it". The temp
    # file the replace creates beside it inherits the same entries (and its
    # mask follows the mode bits it is given), so nothing is dropped.
    target = tmp_path / "mcp.json"
    target.write_text("{}\n", encoding="utf-8")
    _linux_xattrs(
        monkeypatch,
        {(target, "system.posix_acl_access"): _INHERITED_ACL, (tmp_path, "system.posix_acl_default"): _DEFAULT_ACL},
    )

    assert agents_core.unreplaceable_reason(target) is None
    agents_core.atomic_write_text(target, "ours\n")
    assert target.read_text(encoding="utf-8") == "ours\n"


@pytest.mark.parametrize(
    ("access", "default"),
    [
        # An entry of its own beside the inherited one.
        (_posix_acl_base(6, 5, 4, 4, (_ACL_USER, 4, 1001), (_ACL_USER, 6, 1002)), _DEFAULT_ACL),
        # The inherited entry, changed since.
        (_posix_acl_base(6, 5, 6, 4, (_ACL_USER, 6, 1001)), _DEFAULT_ACL),
        # A "g::---" beside group-readable mode bits (the mask).
        (_posix_acl_base(6, 0, 4, 4, (_ACL_USER, 4, 1001)), _DEFAULT_ACL),
        # The directory gives new files another list, or none.
        (_INHERITED_ACL, _posix_acl_base(7, 5, 5, 5, (_ACL_GROUP, 4, 1001))),
        (_INHERITED_ACL, None),
    ],
    ids=["own-entry", "changed-entry", "owning-group", "other-default", "no-default"],
)
def test_final_linux_acl_of_its_own_is_still_refused(
    access: bytes, default: bytes | None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "mcp.json"
    target.write_text("old\n", encoding="utf-8")
    attributes = {(target, "system.posix_acl_access"): access}
    if default is not None:
        attributes[(tmp_path, "system.posix_acl_default")] = default
    _linux_xattrs(monkeypatch, attributes)

    reason = agents_core.unreplaceable_reason(target)
    assert reason is not None and "access control list" in reason
    with pytest.raises(OSError, match="access control list"):
        agents_core.atomic_write_text(target, "ours\n")
    assert target.read_text(encoding="utf-8") == "old\n"


@pytest.mark.skipif(
    not sys.platform.startswith("linux") or shutil.which("setfacl") is None,
    reason="setfacl sets a POSIX default ACL on Linux",
)
def test_final_linux_config_that_inherits_the_directory_default_acl_is_configured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    h = _harness("cursor", tmp_path, monkeypatch)
    proc = _acl_tool("setfacl", "-d", "-m", "u:0:r", str(h.target.parent), check=False)
    if proc.returncode != 0:
        pytest.skip(f"this filesystem takes no POSIX ACL: {proc.stderr.strip()}")
    h.target.write_text(_existing_body(h), encoding="utf-8")
    assert "system.posix_acl_access" in os.listxattr(h.target)

    assert h.detect() is AgentStatus.INSTALLED_UNCONFIGURED
    assert _status(h.apply(True)) is AgentStatus.CONFIGURED
    acl = _acl_tool("getfacl", "-cp", str(h.target)).stdout
    assert "user:0:r--" in acl or "user:root:r--" in acl

    # An entry of its own on top is still refused.
    _acl_tool("setfacl", "-m", "u:1:r", str(h.target))
    reason = agents_core.unreplaceable_reason(h.target)
    assert reason is not None and "access control list" in reason


@pytest.mark.skipif(sys.platform != "darwin", reason="chmod +a sets a macOS access control list")
def test_final_macos_config_that_inherits_the_directory_acl_is_configured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A file_inherit entry on ~/.cursor gives every file created there an
    # "inherited" entry, the replace's temp file too.
    h = _harness("cursor", tmp_path, monkeypatch)
    _acl_tool("/bin/chmod", "+a", "user:daemon allow read,file_inherit,directory_inherit", str(h.target.parent))
    _acl_tool("/bin/chmod", "+a", "user:nobody deny write,file_inherit,limit_inherit", str(h.target.parent))
    _acl_tool("/bin/chmod", "+a", "user:_www allow read,directory_inherit", str(h.target.parent))
    h.target.write_text(_existing_body(h), encoding="utf-8")
    inherited = _acl_tool("/bin/ls", "-le", str(h.target)).stdout
    assert "user:daemon inherited allow read" in inherited and "_www" not in inherited

    assert h.detect() is AgentStatus.INSTALLED_UNCONFIGURED
    assert _status(h.apply(True)) is AgentStatus.CONFIGURED
    assert _acl_tool("/bin/ls", "-le", str(h.target)).stdout.splitlines()[1:] == inherited.splitlines()[1:]

    # An entry of its own on top is still refused.
    _acl_tool("/bin/chmod", "+a", "user:daemon deny read", str(h.target))
    reason = agents_core.unreplaceable_reason(h.target)
    assert reason is not None and "access control list" in reason


@pytest.mark.skipif(sys.platform != "darwin", reason="chmod +a sets a macOS access control list")
def test_final_macos_inherited_acl_the_directory_no_longer_gives_is_refused(tmp_path: Path) -> None:
    directory = tmp_path / "cursor"
    directory.mkdir()
    _acl_tool("/bin/chmod", "+a", "user:daemon allow read,file_inherit", str(directory))
    target = directory / "mcp.json"
    target.write_text("old\n", encoding="utf-8")
    _acl_tool("/bin/chmod", "-N", str(directory))

    reason = agents_core.unreplaceable_reason(target)
    assert reason is not None and "access control list" in reason


# Hand-written launches that hold the python command line in one string: a
# shell's -c (cmd's /c, PowerShell's -Command), or a "command" that a harness
# runs through a shell; and (fix-up 2) uv run launches whose own options come
# before the module.
_COMMAND_LINE_LAUNCHES: dict[str, tuple[str, list[str]]] = {
    "sh-c": ("/bin/sh", ["-c", "exec python3 -m universal_db_mcp serve"]),
    "bash-lc": ("bash", ["-lc", "cd /srv && exec /opt/v/bin/python3 -u -m universal_db_mcp serve"]),
    "sh-c-chained": ("/bin/sh", ["-c", "cd /srv&&(python3 -m universal_db_mcp serve)"]),
    "cmd-c": ("cmd", ["/c", "C:\\venv\\Scripts\\python.exe -m universal_db_mcp serve"]),
    "powershell": ("powershell", ["-Command", "& 'C:\\v\\python.exe' -m universal_db_mcp serve"]),
    "sh-uv-run": ("/bin/sh", ["-c", "uv run -m universal_db_mcp serve"]),
    "command": ("python3 -m universal_db_mcp serve", []),
    "command-uv-run": ("uv run", LEGACY_ARGS),
    "command-with-spaces": ("C:\\Program Files\\Python312\\python.exe", LEGACY_ARGS),
    # A later command of the line, after one whose python launch settles.
    "sh-c-after-python-c": (
        "bash",
        ["-c", "python3 -c 'import universal_db_mcp' && exec python3 -m universal_db_mcp serve"],
    ),
    "sh-c-after-isolated-check": (
        "bash",
        ["-c", "python3 -I -m universal_db_mcp --version; exec python3 -m universal_db_mcp serve"],
    ),
    "sh-c-next-line": ("bash", ["-c", "python3 -c 'import a; import b'\nexec python3 -m universal_db_mcp serve"]),
    # A command line quoted inside another one.
    "sh-c-nested": ("bash", ["-c", "sh -c 'python3 -m universal_db_mcp serve'"]),
    "command-sh-c": ("sh -c 'python3 -m universal_db_mcp serve'", []),
    "command-piped": ("python3 -m universal_db_mcp serve 2>&1 | tee -a /tmp/udb.log", []),
    "cmd-c-quoted": ("cmd", ["/c", '"python -m universal_db_mcp serve"']),
    # PowerShell runs the args after -Command as one command line.
    "powershell-args": ("pwsh", ["-NoProfile", "-Command", "python", "-m", "universal_db_mcp", "serve"]),
    "powershell-c-args": ("C:\\Windows\\powershell.exe", ["-c", "&", "C:\\v\\python.exe", "-m", "universal_db_mcp"]),
    # Fix-up 2: uv run's own options before its --module, with a value that
    # names no interpreter (only "--python python3.12" was recognized).
    "uv-run-python-version": ("uv", ["run", "--python", "3.12", *LEGACY_ARGS]),
    "uv-run-p-version": ("uv", ["run", "-p", "3.12", *LEGACY_ARGS]),
    "uv-run-p-attached": ("uv", ["run", "-p3.12", *LEGACY_ARGS]),
    "uv-run-python-equals": ("uv", ["run", "--python=3.12", *LEGACY_ARGS]),
    "uv-run-project": ("uv", ["run", "--project", "/opt/udb", *LEGACY_ARGS]),
    "uv-run-with": ("uv", ["run", "--with", "pandas", *LEGACY_ARGS]),
    "uv-run-env-file": ("uv", ["run", "--env-file", ".env", *LEGACY_ARGS]),
    "uv-run-long-module": ("uv", ["run", "--module", "universal_db_mcp", "serve"]),
    # uv's -m is a flag: its options may come between it and the module.
    "uv-run-module-then-options": ("uv", ["run", "-m", "--python", "3.12", "universal_db_mcp", "serve"]),
    "uv-run-quiet-module": ("uv", ["run", "-qm", "universal_db_mcp", "serve"]),
    "command-uv-run-python-version": ("uv run --python 3.12", LEGACY_ARGS),
    "sh-uv-run-python-version": ("/bin/sh", ["-c", "exec uv run --python 3.12 -m universal_db_mcp serve"]),
    "sh-uv-run-long-module": ("/bin/sh", ["-c", "uv run --module universal_db_mcp serve"]),
    # A launch the shell (or env) runs before, or instead of, an isolated one.
    "sh-c-substitution-after-isolated": (
        "/bin/sh",
        ["-c", "exec python3 -I -m universal_db_mcp serve --x $(python3 -m universal_db_mcp --version)"],
    ),
    "sh-c-backticks-after-isolated": (
        "/bin/sh",
        ["-c", "exec python3 -I -m universal_db_mcp serve --x `python3 -m universal_db_mcp --version`"],
    ),
    "sh-c-quoted-substitution-after-isolated": (
        "bash",
        ["-c", 'exec python3 -I -m universal_db_mcp serve --x "$(python3 -m universal_db_mcp --version)"'],
    ),
    "command-substitution-after-isolated": (
        "python3 -I -m universal_db_mcp serve --x $(python3 -m universal_db_mcp --version)",
        [],
    ),
    "env-S-before-isolated": ("env", ["-S", "python3 -m universal_db_mcp serve", "python3", *ISOLATED_ARGS]),
    # A shell prefix in "command" whose command line is in "args".
    "command-sh-c-line-in-args": ("sh -c", ["exec python3 -m universal_db_mcp serve"]),
    "command-powershell-line-in-args": ("powershell -NoProfile -Command", ["python -m universal_db_mcp serve"]),
}
_UV_DROP_MODULE = "drop uv's --module (-m) option and insert"
_COMMAND_LINE_ADVICE = {
    "sh-c": 'add "-I" right before "-m" in the command line in "args"',
    "bash-lc": 'add "-I" right before "-m" in the command line in "args"',
    "sh-c-chained": 'add "-I" right before "-m" in the command line in "args"',
    "cmd-c": 'add "-I" right before "-m" in the command line in "args"',
    "powershell": 'add "-I" right before "-m" in the command line in "args"',
    "sh-uv-run": 'insert "python -I" right before "-m" in the command line in "args"',
    "command": 'add "-I" right before "-m" in "command"',
    # -I as the first args item would be uv's option.
    "command-uv-run": 'insert "python", "-I" right before "-m" in "args"',
    "command-with-spaces": 'add "-I" as the first "args" item',
    "sh-c-after-python-c": 'add "-I" right before "-m" in the command line in "args"',
    "sh-c-after-isolated-check": 'add "-I" right before "-m" in the command line in "args"',
    "sh-c-next-line": 'add "-I" right before "-m" in the command line in "args"',
    "sh-c-nested": 'add "-I" right before "-m" in the command line in "args"',
    "command-sh-c": 'add "-I" right before "-m" in "command"',
    "command-piped": 'add "-I" right before "-m" in "command"',
    "cmd-c-quoted": 'add "-I" right before "-m" in the command line in "args"',
    "powershell-args": 'add "-I" right before "-m" in the command line in "args"',
    "powershell-c-args": 'add "-I" right before "-m" in the command line in "args"',
    "uv-run-python-version": 'insert "python", "-I" right before "-m" in "args"',
    "uv-run-p-version": 'insert "python", "-I" right before "-m" in "args"',
    "uv-run-p-attached": 'insert "python", "-I" right before "-m" in "args"',
    "uv-run-python-equals": 'insert "python", "-I" right before "-m" in "args"',
    "uv-run-project": 'insert "python", "-I" right before "-m" in "args"',
    "uv-run-with": 'insert "python", "-I" right before "-m" in "args"',
    "uv-run-env-file": 'insert "python", "-I" right before "-m" in "args"',
    # python takes no --module, and "-I" before a detached -m would still be uv's.
    "uv-run-long-module": f'{_UV_DROP_MODULE} "python", "-I", "-m" right before "universal_db_mcp" in "args"',
    "uv-run-module-then-options": f'{_UV_DROP_MODULE} "python", "-I", "-m" right before "universal_db_mcp" in "args"',
    "uv-run-quiet-module": f'{_UV_DROP_MODULE} "python", "-I", "-m" right before "universal_db_mcp" in "args"',
    "command-uv-run-python-version": 'insert "python", "-I" right before "-m" in "args"',
    "sh-uv-run-python-version": 'insert "python -I" right before "-m" in the command line in "args"',
    "sh-uv-run-long-module": (
        f'{_UV_DROP_MODULE} "python -I -m" right before "universal_db_mcp" in the command line in "args"'
    ),
    "sh-c-substitution-after-isolated": 'add "-I" right before "-m" in the command line in "args"',
    "sh-c-backticks-after-isolated": 'add "-I" right before "-m" in the command line in "args"',
    "sh-c-quoted-substitution-after-isolated": 'add "-I" right before "-m" in the command line in "args"',
    "command-substitution-after-isolated": 'add "-I" right before "-m" in "command"',
    "env-S-before-isolated": 'add "-I" right before "-m" in the command line in "args"',
    # The -m is in "args", not in "command".
    "command-sh-c-line-in-args": 'add "-I" right before "-m" in the command line in "args"',
    "command-powershell-line-in-args": 'add "-I" right before "-m" in the command line in "args"',
}


@pytest.mark.parametrize("launch", sorted(_COMMAND_LINE_LAUNCHES))
def test_final_launch_in_a_command_line_starts_without_isolation(launch: str) -> None:
    command, args = _COMMAND_LINE_LAUNCHES[launch]
    assert agents_core.starts_without_isolation(args, command)
    assert agents_core.isolation_advice(args, command) == _COMMAND_LINE_ADVICE[launch]


@pytest.mark.parametrize(
    ("command", "args"),
    [
        ("/bin/sh", ["-c", "exec python3 -I -m universal_db_mcp serve"]),
        ("cmd", ["/c", "C:\\venv\\Scripts\\python.exe -I -m universal_db_mcp serve"]),
        ("/bin/sh", ["-c", "exec python3 -m other_package serve"]),
        ("/bin/sh", ["-c", "echo universal_db_mcp -m python"]),
        ("python3", ["-c", "import universal_db_mcp"]),
        ("python3 -I -m universal_db_mcp serve", []),
        ("uv run", ["python", "-I", "-m", "universal_db_mcp"]),
        ("C:\\Program Files\\Python312\\python.exe", ISOLATED_ARGS),
        ("/opt/my tools/python3", ["-X", "utf8", "-I", "-m", "universal_db_mcp"]),
        # A command line whose launch settles decides: its args are not the options of a path.
        ("/opt/my tools/python3 -I", ["-m", "universal_db_mcp", "serve"]),
        # The fix-up round's forms, isolated.
        ("bash", ["-c", "python3 -c 'import universal_db_mcp' && exec python3 -I -m universal_db_mcp serve"]),
        ("bash", ["-c", "sh -c 'python3 -I -m universal_db_mcp serve'"]),
        ("sh -c 'python3 -I -m universal_db_mcp serve'", []),
        ("cmd", ["/c", '"python -I -m universal_db_mcp serve"']),
        ("pwsh", ["-Command", "python", "-I", "-m", "universal_db_mcp", "serve"]),
        # What follows an isolated launch is the server's own args, not a command line.
        ("python3", [*ISOLATED_ARGS, "--note", "python3 -m universal_db_mcp serve"]),
        ("bash", ["-c", "exec python3 -I -m universal_db_mcp serve --note 'x; python3 -m universal_db_mcp'"]),
        # bash -c runs one string; the words after it are $0, $1, ...
        ("bash", ["-c", 'exec "$@"', "python3", "-m", "universal_db_mcp"]),
        # Fix-up 2: uv run's options take their values; the command after them decides.
        ("uv", ["run", "--python", "3.12", "python", "-I", "-m", "universal_db_mcp"]),
        ("uv", ["run", "-p", "3.12", "--", "python", "-I", "-m", "universal_db_mcp"]),
        ("uv run --python 3.12 python -I -m universal_db_mcp", []),
        ("uv", ["run", "--with", "universal_db_mcp", "python", "-I", "-m", "universal_db_mcp"]),
        ("uv", ["run", "--module", "other_module", "universal_db_mcp"]),
        ("uv", ["run", "--python", "3.12", "serve", "-m", "universal_db_mcp"]),
        # Single quotes keep a substitution from running; so does a direct launch (no shell).
        ("/bin/sh", ["-c", "exec python3 -I -m universal_db_mcp serve --note '$(python3 -m universal_db_mcp)'"]),
        ("python3", [*ISOLATED_ARGS, "--note", "$(python3 -m universal_db_mcp)"]),
        ("env", ["-S", "python3 -I -m universal_db_mcp serve"]),
        ("env", ["-S", "python3 -I -m universal_db_mcp serve", "python3", *ISOLATED_ARGS]),
    ],
)
def test_final_isolated_or_foreign_command_lines_are_not_flagged(command: str, args: list[str]) -> None:
    assert not agents_core.starts_without_isolation(args, command)


def test_final_shell_strings_count_without_the_command() -> None:
    # The reviewer's repro: the args alone already show the launch.
    assert agents_core.starts_without_isolation(["-c", "exec python3 -m universal_db_mcp serve"])
    assert agents_core.starts_without_isolation(["/c", "python -m universal_db_mcp serve"])
    assert agents_core.unisolated_launches({"x": {"command": "python3 -m universal_db_mcp serve", "args": []}}) == ["x"]


@pytest.mark.parametrize("launch", sorted(_COMMAND_LINE_LAUNCHES))
@pytest.mark.parametrize("name", JSON_ADAPTERS)
def test_final_entry_that_starts_the_server_from_a_command_line_says_so(
    name: str, launch: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The entry failed closed as "differs" without a word about -I, so the
    # operator was not told that the launch stays exploitable.
    h = _harness(name, tmp_path, monkeypatch)
    command, args = _COMMAND_LINE_LAUNCHES[launch]
    theirs = {**_legacy_entry(h), "command": command, "args": args}
    h.target.write_text(json.dumps({h.servers_key: {"universal-db": theirs}}, indent=2), encoding="utf-8")
    original = h.target.read_bytes()

    assert h.detect() is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    for summary in (h.plan().summary, _message(h.apply(True))):
        assert "starts the server without -I" in summary and _COMMAND_LINE_ADVICE[launch] in summary
    assert h.target.read_bytes() == original and _backups(h.target) == []


@pytest.mark.parametrize("launch", sorted(_COMMAND_LINE_LAUNCHES))
@pytest.mark.parametrize("name", ADAPTERS)
def test_final_other_entry_that_starts_the_server_from_a_command_line_is_named(
    name: str, launch: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    h = _harness(name, tmp_path, monkeypatch)
    command, args = _COMMAND_LINE_LAUNCHES[launch]
    if h.module is dsh:
        row = f"- insert:\n    - id: {_OTHER_UNISOLATED}\n      config:\n        command: {json.dumps(command)}\n"
        h.target.write_text(_DSH_EXISTING + row + f"        args: {json.dumps(args)}\n", encoding="utf-8")
    else:
        servers = {_OTHER_UNISOLATED: {"command": command, "args": args}}
        h.target.write_text(json.dumps({h.servers_key: servers}), encoding="utf-8")
    others = _other_entries(h)

    planned = h.plan()
    result = h.apply(True)

    assert _status(result) is AgentStatus.CONFIGURED
    for text in (planned.summary, _message(result)):
        assert f"{_OTHER_UNISOLATED}\"" in text or f"'{_OTHER_UNISOLATED}'" in text, text
        assert "without -I" in text
    assert _other_entries(h) == others


def _dsh_row(command: str, args: list[str]) -> str:
    return _DSH_CURRENT_ROW.replace(f"command: {FAKE_PYTHON}", f"command: {json.dumps(command)}").replace(
        "args: ['-I', '-m', 'universal_db_mcp', 'serve', '--transport', 'stdio']", f"args: {json.dumps(args)}"
    )


@pytest.mark.parametrize("launch", sorted(_COMMAND_LINE_LAUNCHES))
def test_final_dsh_row_that_starts_the_server_from_a_command_line_fails_closed(
    launch: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A row with our id that is not a python launch counted as registered:
    # "sh -c 'exec python3 -m universal_db_mcp serve'" was reported "configured".
    h = _harness("dsh", tmp_path, monkeypatch)
    command, args = _COMMAND_LINE_LAUNCHES[launch]
    h.target.write_text(_DSH_EXISTING + _dsh_row(command, args), encoding="utf-8")
    original = h.target.read_bytes()

    assert h.detect() is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    summary = h.plan().summary
    assert "FAIL CLOSED" in summary and "without -I" in summary and _COMMAND_LINE_ADVICE[launch] in summary
    result = h.apply(True)

    assert result.wrote is False and "without -I" in result.message
    assert h.target.read_bytes() == original and _backups(h.target) == []


def test_final_dsh_isolated_row_in_a_shell_string_is_still_configured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    h = _harness("dsh", tmp_path, monkeypatch)
    h.target.write_text(
        _DSH_EXISTING + _dsh_row("/bin/sh", ["-c", "exec python3 -I -m universal_db_mcp serve"]), encoding="utf-8"
    )

    assert h.detect() is AgentStatus.CONFIGURED


def test_final_seeded_config_names_this_platforms_system_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Its header said the system deployment "(/etc/universal-db-mcp/config.yaml)
    # belongs to the launchd/systemd service account and is NOT readable by
    # your user" on every host, also where there is none (or it is under
    # %ProgramData% on Windows).
    system = tmp_path / "ProgramData" / "UniversalDB MCP" / "config.yaml"
    monkeypatch.setattr(agents_core, "SYSTEM_CONFIG_PATH", system)
    home = tmp_path / "home"
    home.mkdir()

    created, _note = agents_core.ensure_per_user_harness_config({}, home)

    assert created is not None
    text = created.read_text(encoding="utf-8")
    assert f"({system})" in text and "/etc/universal-db-mcp" not in text
    assert "absent or your user cannot read it" in text and "service account" not in text
    assert yaml.safe_load(text)["application"]["audit_path"] == str(created.parent / "audit.jsonl")


# ---------------------------------------------------------------------------
# Final round, fix-up 1: review findings on the final round
# ---------------------------------------------------------------------------


def test_final_dsh_isolated_row_whose_server_args_look_like_a_launch_is_configured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The string after an isolated launch is the server's own argument, and
    # it was read as a command line: the row failed closed.
    h = _harness("dsh", tmp_path, monkeypatch)
    args = [*ISOLATED_ARGS, "--note", "python3 -m universal_db_mcp serve"]
    h.target.write_text(_DSH_EXISTING + _dsh_row(FAKE_PYTHON, args), encoding="utf-8")

    assert h.detect() is AgentStatus.CONFIGURED


def test_final_linux_config_without_an_acl_where_the_directory_gives_one_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The replace's temp file takes the directory's default ACL, so a config
    # without one (written before the default was set, or moved in) came back
    # readable by the default's named user.
    h = _harness("cursor", tmp_path, monkeypatch)
    h.target.write_text(_existing_body(h), encoding="utf-8")
    original = h.target.read_bytes()
    _linux_xattrs(monkeypatch, {(h.target.parent, "system.posix_acl_default"): _DEFAULT_ACL})

    reason = agents_core.unreplaceable_reason(h.target)
    assert reason is not None and "access control list" in reason and "its directory gives" in reason
    assert h.detect() is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    result = h.apply(True)

    assert _status(result) is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED and "access control list" in _message(result)
    with pytest.raises(OSError, match="access control list"):
        agents_core.atomic_write_text(h.target, "ours\n")
    assert h.target.read_bytes() == original and _backups(h.target) == []
    assert sorted(p.name for p in h.target.parent.iterdir()) == [h.target.name]


@pytest.mark.parametrize(
    "attributes",
    [
        {},
        # A default ACL of the base entries only: the mode bits carry all of it.
        {"system.posix_acl_default": _posix_acl((_ACL_USER_OBJ, 7, 0), (_ACL_GROUP_OBJ, 5, 0), (_ACL_OTHER, 0, 0))},
    ],
    ids=["none", "base-entries-only"],
)
def test_final_linux_config_where_the_directory_gives_no_extra_entries_is_written(
    attributes: dict[str, bytes], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "mcp.json"
    target.write_text("old\n", encoding="utf-8")
    _linux_xattrs(monkeypatch, {(tmp_path, name): value for name, value in attributes.items()})

    assert agents_core.unreplaceable_reason(target) is None
    agents_core.atomic_write_text(target, "ours\n")
    assert target.read_text(encoding="utf-8") == "ours\n"


def test_final_linux_acl_probe_failure_refuses_the_replace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "mcp.json"
    target.write_text("old\n", encoding="utf-8")
    failures: dict[str, OSError] = {}

    def getxattr(path: Any, attribute: str, *, follow_symlinks: bool = True) -> bytes:
        raise failures.get(attribute, OSError(errno.ENODATA, "No data available"))

    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(os, "getxattr", getxattr, raising=False)

    # A filesystem without extended attributes holds no POSIX ACL.
    failures["system.posix_acl_access"] = OSError(errno.EOPNOTSUPP, "Operation not supported")
    failures["system.posix_acl_default"] = OSError(errno.ENOTSUP, "Operation not supported")
    assert agents_core.unreplaceable_reason(target) is None
    # Any other failure to look, at the file or at its directory, is not "none".
    for attribute in ("system.posix_acl_access", "system.posix_acl_default"):
        failures.clear()
        failures[attribute] = OSError(errno.EIO, "Input/output error")
        reason = agents_core.unreplaceable_reason(target)
        assert reason is not None and "could not be checked for an access control list" in reason
        with pytest.raises(OSError, match="could not be checked"):
            agents_core.atomic_write_text(target, "ours\n")
    assert target.read_text(encoding="utf-8") == "old\n"


@pytest.mark.skipif(
    not sys.platform.startswith("linux") or shutil.which("setfacl") is None,
    reason="setfacl sets a POSIX default ACL on Linux",
)
def test_final_linux_config_older_than_the_directory_default_acl_is_never_replaced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    h = _with_existing("cursor", tmp_path, monkeypatch)
    h.target.chmod(0o640)
    proc = _acl_tool("setfacl", "-d", "-m", "u:0:r", str(h.target.parent), check=False)
    if proc.returncode != 0:
        pytest.skip(f"this filesystem takes no POSIX ACL: {proc.stderr.strip()}")
    original = h.target.read_bytes()
    assert "system.posix_acl_access" not in os.listxattr(h.target)

    assert h.detect() is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    result = h.apply(True)

    assert _status(result) is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED and "access control list" in _message(result)
    assert h.target.read_bytes() == original and _backups(h.target) == []
    assert "system.posix_acl_access" not in os.listxattr(h.target)


@pytest.mark.skipif(sys.platform != "darwin", reason="chmod +a sets a macOS access control list")
@pytest.mark.parametrize(
    "entry",
    ["user:daemon allow read,file_inherit", "everyone deny read,file_inherit,only_inherit"],
    ids=["allow", "deny"],
)
def test_final_macos_config_older_than_the_directory_acl_is_never_replaced(
    entry: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # An inherited allow entry opened a 0600 config to another user (macOS
    # does not limit it by the mode bits); an inherited "deny read" locked
    # the owner out of their own config.
    h = _with_existing("cursor", tmp_path, monkeypatch)
    h.target.chmod(0o600)
    _acl_tool("/bin/chmod", "+a", entry, str(h.target.parent))
    original = h.target.read_bytes()
    try:
        assert _acl_tool("/bin/ls", "-le", str(h.target)).stdout.count("\n") == 1  # no ACL of its own

        assert h.detect() is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
        result = h.apply(True)

        assert _status(result) is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED and "access control list" in _message(result)
        assert h.target.read_bytes() == original and _backups(h.target) == []
        assert _acl_tool("/bin/ls", "-le", str(h.target)).stdout.count("\n") == 1
    finally:
        _acl_tool("/bin/chmod", "-N", str(h.target.parent))


# ---------------------------------------------------------------------------
# Final round, fix-up 2: review findings on fix-up 1
# ---------------------------------------------------------------------------


def _in_group(target: Path, gid: int, monkeypatch: pytest.MonkeyPatch, *, directory_gid: int | None = None) -> None:
    """Make ``target`` (and, with ``directory_gid``, its set-group-ID
    directory) belong to group ``gid`` as ``Path.stat`` sees them."""
    groups = {os.path.realpath(target): (gid, 0)}
    if directory_gid is not None:
        groups[os.path.realpath(target.parent)] = (directory_gid, stat.S_ISGID)
    real_stat = Path.stat

    def grouped_stat(self: Path, *, follow_symlinks: bool = True) -> os.stat_result:
        st = real_stat(self, follow_symlinks=follow_symlinks)
        found = groups.get(os.path.realpath(self))
        if found is None:
            return st
        fields: list[float] = list(st[:10])
        fields[0] = st.st_mode | found[1]
        fields[5] = found[0]
        return os.stat_result(fields)

    monkeypatch.setattr(Path, "stat", grouped_stat)


def _foreign_gid(directory: Path) -> int:
    """A group this process is not in, and not ``directory``'s."""
    return max(os.getegid(), directory.stat().st_gid, *os.getgroups()) + 1


@_POSIX_ONLY
@pytest.mark.skipif(_AS_ROOT, reason="root keeps the group, as it always did")
@pytest.mark.parametrize("name", ADAPTERS)
def test_final_config_in_a_group_this_user_is_not_in_is_never_replaced(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The temp file's group could not be set to the config's (this user is
    # not in it), so a runner:secret 0640 config came back runner:runner (on
    # macOS: the directory's group, usually staff) - silently.
    h = _with_existing(name, tmp_path, monkeypatch)
    h.target.chmod(0o640)
    original = h.target.read_bytes()
    foreign = _foreign_gid(h.target.parent)
    _in_group(h.target, foreign, monkeypatch)

    reason = agents_core.unreplaceable_reason(h.target)
    assert reason is not None and f"belongs to group {foreign}, which this user is not in" in reason
    assert h.detect() is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    result = h.apply(True)

    assert _status(result) is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    assert f"belongs to group {foreign}" in _message(result)
    with pytest.raises(PermissionError, match="changing who may read it"):
        agents_core.atomic_write_text(h.target, "ours\n")
    assert h.target.read_bytes() == original
    assert _backups(h.target) == [] and _reported_backups(result) == []
    assert list(h.target.parent.glob(f".{h.target.name}.*.tmp")) == []  # no temp file left either


@_POSIX_ONLY
@pytest.mark.skipif(_AS_ROOT, reason="root keeps the group, as it always did")
@pytest.mark.parametrize("mode", [0o600, 0o644, 0o660], ids=["0600", "0644", "member-0660"])
def test_final_group_change_that_changes_no_access_is_written(
    mode: int, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # 0600 and 0644 give the group what they give everyone else, so its
    # group decides nothing; a group this user is in is kept by the replace.
    target = tmp_path / "mcp.json"
    target.write_text("old\n", encoding="utf-8")
    target.chmod(mode)
    foreign = _foreign_gid(tmp_path)
    _in_group(target, foreign, monkeypatch)
    calls: list[int] = []
    if mode == 0o660:
        monkeypatch.setattr(os, "getgroups", lambda: [foreign])
        monkeypatch.setattr(os, "fchown", lambda _fd, _uid, gid: calls.append(gid))

    assert agents_core.unreplaceable_reason(target) is None
    agents_core.atomic_write_text(target, "ours\n")
    assert target.read_text(encoding="utf-8") == "ours\n"
    assert calls == ([foreign] if mode == 0o660 else [])


@_POSIX_ONLY
@pytest.mark.skipif(_AS_ROOT, reason="root keeps the group, as it always did")
@pytest.mark.parametrize(
    ("platform", "setgid", "refused"),
    [("darwin", False, False), ("linux", True, False), ("linux", False, True)],
    ids=["bsd-directory-group", "linux-setgid-directory", "linux-own-group"],
)
def test_final_group_a_new_file_gets_anyway_is_no_reason_to_refuse(
    platform: str, setgid: bool, refused: bool, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A file created in the directory takes its group on macOS (and in a
    # set-group-ID directory on Linux): the replace keeps it without a chown.
    target = tmp_path / "mcp.json"
    target.write_text("old\n", encoding="utf-8")
    target.chmod(0o640)
    foreign = _foreign_gid(tmp_path)
    if setgid or platform == "darwin":
        _in_group(target, foreign, monkeypatch, directory_gid=foreign)
    else:
        _in_group(target, foreign, monkeypatch)
    monkeypatch.setattr(sys, "platform", platform)
    monkeypatch.setattr(os, "getxattr", lambda *_args, **_kwargs: b"", raising=False)

    reason = agents_core.unreplaceable_reason(target)
    assert (reason is not None and f"belongs to group {foreign}" in reason) is refused, reason


@_POSIX_ONLY
@pytest.mark.skipif(_AS_ROOT, reason="root keeps the group, as it always did")
def test_final_group_the_replace_could_not_keep_fails_the_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The membership check said yes but the chown still failed: the new file
    # must not take another group in silence.
    target = tmp_path / "mcp.json"
    target.write_text("old\n", encoding="utf-8")
    target.chmod(0o640)
    foreign = _foreign_gid(tmp_path)
    _in_group(target, foreign, monkeypatch)
    monkeypatch.setattr(os, "getgroups", lambda: [foreign])

    def refuse(*_args: object) -> None:
        raise PermissionError(errno.EPERM, "Operation not permitted")

    monkeypatch.setattr(os, "fchown", refuse)

    assert agents_core.unreplaceable_reason(target) is None
    with pytest.raises(PermissionError, match=f"group {foreign}"):
        agents_core.atomic_write_text(target, "ours\n")
    assert target.read_text(encoding="utf-8") == "old\n"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["mcp.json"]
