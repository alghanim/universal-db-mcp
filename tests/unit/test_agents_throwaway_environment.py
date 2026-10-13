"""configure-agents refuses to register an interpreter that lives in a package
manager's cache: `uvx udbmcp configure-agents` would otherwise register
~/.cache/uv/archive-v0/<id>/bin/python, which works until uv prunes its cache
and then fails at every harness start."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from universal_db_mcp.agents import claude_code, claude_desktop, cline, cursor, vscode
from universal_db_mcp.agents import core as agents_core
from universal_db_mcp.errors import ConfigError

UVX_PYTHON = "/home/me/.cache/uv/archive-v0/bpvF6qlYOhiiSuLC/bin/python"
FAKE_CONFIG = "/etc/universal-db-mcp/config.yaml"


@pytest.mark.parametrize(
    ("python", "tool"),
    [
        (UVX_PYTHON, "uv"),
        ("/Users/runner/.cache/uv/archive-v0/x1/bin/python3.12", "uv"),
        (r"C:\Users\me\AppData\Local\uv\cache\archive-v0\x1\Scripts\python.exe", "uv"),
        ("/home/me/.local/pipx/.cache/4f1c2a/bin/python", "pipx"),
        # installs that stay: uv tool, pipx install, a project venv, the bundle
        ("/home/me/.local/share/uv/tools/udbmcp/bin/python", None),
        ("/home/me/.local/pipx/venvs/udbmcp/bin/python", None),
        ("/home/me/src/uv/archive/.venv/bin/python", None),
        ("/opt/universal-db-mcp/venv/bin/python", None),
        (r"C:\Program Files\universal-db-mcp\venv\Scripts\python.exe", None),
    ],
)
def test_a_cache_interpreter_is_recognised_and_an_install_is_not(python: str, tool: str | None) -> None:
    assert agents_core._throwaway_environment(python) == tool


def test_the_refusal_comes_before_the_import_probe_and_names_the_way_out(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def fake_run(argv: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, "", "")

    agents_core._isolated_import_problem.cache_clear()
    monkeypatch.setattr(subprocess, "run", fake_run)
    try:
        with pytest.raises(ConfigError, match="uv's cache") as raised:
            agents_core.require_isolated_import(UVX_PYTHON)
    finally:
        agents_core._isolated_import_problem.cache_clear()
    assert "uv tool install udbmcp" in str(raised.value)
    assert calls == []  # the interpreter imports fine today; that is the trap


@pytest.mark.parametrize("module", [claude_code, claude_desktop, cline, cursor, vscode])
def test_every_adapter_refuses_to_register_from_uvx(
    module: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sys, "executable", UVX_PYTHON)
    env = {"UDBMCP_CONFIG": FAKE_CONFIG}

    with pytest.raises(ConfigError, match="uv's cache"):
        module.registration_entry(env, tmp_path)
    # An explicit interpreter is the operator's choice and is not second-guessed.
    stable = "/opt/universal-db-mcp/venv/bin/python"
    assert module.registration_entry({**env, "UDBMCP_VENV_PYTHON": stable}, tmp_path)["command"] == stable
