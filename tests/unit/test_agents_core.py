"""Unit tests for the ``configure-agents`` shared core, registry, and CLI flow.

All CLI tests run against a fake HOME and a stub adapter monkeypatched into
``universal_db_mcp.agents.registry``; nothing touches the real user profile
and nothing is written unless the test explicitly exercises ``--yes`` or an
affirmative TTY prompt.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

from universal_db_mcp.__main__ import main
from universal_db_mcp.agents import core, registry
from universal_db_mcp.agents.core import (
    AgentConfigError,
    AgentStatus,
    backup_path,
    load_json_or_fail_closed,
    load_yaml_or_fail_closed,
)

FAKE_PYTHON = "/opt/universal-db-mcp/venv/bin/python"
FAKE_CONFIG = "/etc/universal-db-mcp/config.yaml"


# ---------------------------------------------------------------------------
# Core helpers
# ---------------------------------------------------------------------------


def test_backup_path_is_timestamped_sibling(tmp_path: Path) -> None:
    target = tmp_path / "config.json"
    first = backup_path(target)
    second = backup_path(target)
    assert first.parent == tmp_path
    assert first.name.startswith("config.json.bak.")
    assert first != second  # timestamped, never collides/overwrites


def test_load_json_or_fail_closed(tmp_path: Path) -> None:
    good = tmp_path / "good.json"
    good.write_text('{"mcpServers": {}}', encoding="utf-8")
    data, reason = load_json_or_fail_closed(good)
    assert data == {"mcpServers": {}}
    assert reason is None

    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    data, reason = load_json_or_fail_closed(bad)
    assert data is None
    assert reason is not None and "not valid JSON" in reason

    scalar = tmp_path / "scalar.json"
    scalar.write_text("[1, 2]", encoding="utf-8")
    data, reason = load_json_or_fail_closed(scalar)
    assert data is None
    assert reason is not None and "JSON object" in reason

    missing = tmp_path / "missing.json"
    data, reason = load_json_or_fail_closed(missing)
    assert data is None and reason is not None


def test_load_yaml_or_fail_closed(tmp_path: Path) -> None:
    seq = tmp_path / "patch.yml"
    seq.write_text("- insert:\n    - id: mcp-universal-db\n", encoding="utf-8")
    data, reason = load_yaml_or_fail_closed(seq)
    assert reason is None
    assert data == [{"insert": [{"id": "mcp-universal-db"}]}]

    bad = tmp_path / "bad.yml"
    bad.write_text("key: [unclosed\n  :: nope", encoding="utf-8")
    data, reason = load_yaml_or_fail_closed(bad)
    assert data is None
    assert reason is not None and "not valid YAML" in reason

    missing = tmp_path / "missing.yml"
    data, reason = load_yaml_or_fail_closed(missing)
    assert data is None and reason is not None


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


def test_harness_names_are_the_documented_six() -> None:
    assert registry.HARNESS_NAMES == ("claude-code", "claude-desktop", "dsh", "cursor", "vscode", "cline")
    assert set(registry.ADAPTER_MODULES) == set(registry.HARNESS_NAMES)


def test_load_adapter_missing_module_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(registry.ADAPTER_MODULES, "cursor", "universal_db_mcp.agents.nonexistent_adapter_zz")
    with pytest.raises(AgentConfigError, match="not available"):
        registry.load_adapter("cursor")


def test_load_adapter_unknown_name_fails_closed() -> None:
    with pytest.raises(AgentConfigError, match="no adapter registered"):
        registry.load_adapter("does-not-exist")


def test_load_adapter_returns_module_for_every_harness() -> None:
    for name in registry.HARNESS_NAMES:
        mod = registry.load_adapter(name)
        assert callable(mod.detect)
        assert callable(mod.plan)
        assert callable(mod.apply)


# ---------------------------------------------------------------------------
# Stub adapter + CLI flow
# ---------------------------------------------------------------------------

STUB_TARGET_NAME = "cline"
STUB_SETTINGS = "cline_mcp_settings.json"


def _plan(
    agent: str,
    target: Path,
    status: AgentStatus,
    summary: str,
    block: str = "",
) -> core.Plan:
    return core.Plan(agent=agent, config_path=target, status=status, summary=summary, config_block=block)


class StubAdapter:
    """Adapter with the JSON-harness signature, recording apply() calls."""

    def __init__(self, status: AgentStatus = AgentStatus.INSTALLED_UNCONFIGURED) -> None:
        self.status = status
        self.apply_calls: list[bool] = []
        self.configured = False

    def _target(self, home: Path) -> Path:
        return home / ".cline" / STUB_SETTINGS

    def _block(self) -> str:
        return json.dumps(
            {"mcpServers": {"universal-db": {"command": FAKE_PYTHON, "env": {"UDBMCP_CONFIG": FAKE_CONFIG}}}},
            indent=2,
        )

    def detect(self, env: dict[str, str], home: Path) -> AgentStatus:
        if self.configured:
            return AgentStatus.CONFIGURED
        return self.status

    def plan(self, env: dict[str, str], home: Path) -> core.Plan:
        target = self._target(home)
        if self.configured:
            return _plan(STUB_TARGET_NAME, target, AgentStatus.CONFIGURED, "stub: already configured")
        if self.status is AgentStatus.INSTALLED_UNCONFIGURED:
            return _plan(
                STUB_TARGET_NAME,
                target,
                self.status,
                "stub: would add the universal-db entry",
                block=self._block(),
            )
        if self.status is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED:
            return _plan(
                STUB_TARGET_NAME,
                target,
                self.status,
                "stub: malformed config; refusing to write",
                block=f"# current contents of {target}:\n{{garbage",
            )
        return _plan(STUB_TARGET_NAME, target, self.status, f"stub: {self.status.value}")

    def apply(self, env: dict[str, str], home: Path, confirmed: bool) -> core.Plan:
        self.apply_calls.append(confirmed)
        if confirmed and not self.configured and self.status is AgentStatus.INSTALLED_UNCONFIGURED:
            target = self._target(home)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(self._block(), encoding="utf-8")
            self.configured = True
            return _plan(STUB_TARGET_NAME, target, AgentStatus.CONFIGURED, "stub: wrote the registration")
        return self.plan(env, home)


@pytest.fixture()
def fake_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Fake HOME + deterministic registration env; also move cwd off the repo."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)  # a Linux host's own would win over HOME
    monkeypatch.setenv("UDBMCP_CONFIG", FAKE_CONFIG)
    monkeypatch.setenv("UDBMCP_VENV_PYTHON", FAKE_PYTHON)
    monkeypatch.chdir(tmp_path)
    return home


def _install_stub(monkeypatch: pytest.MonkeyPatch, stub: StubAdapter) -> None:
    real_load = registry.load_adapter

    def fake_load(name: str) -> Any:
        if name == STUB_TARGET_NAME:
            return stub
        return real_load(name)

    monkeypatch.setattr(registry, "load_adapter", fake_load)
    monkeypatch.setattr(registry, "HARNESS_NAMES", (STUB_TARGET_NAME,))


class FakeTTY:
    def isatty(self) -> bool:
        return True


def test_cli_dry_run_writes_nothing(
    monkeypatch: pytest.MonkeyPatch, fake_home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    stub = StubAdapter()
    _install_stub(monkeypatch, stub)

    rc = main(["configure-agents", "--dry-run"])

    assert rc == 0
    out = capsys.readouterr().out
    assert stub.apply_calls == []
    assert not (fake_home / ".cline" / STUB_SETTINGS).exists()
    assert "would add" in out
    assert "universal-db" in out
    assert "dry-run: nothing written" in out


def test_cli_yes_writes(
    monkeypatch: pytest.MonkeyPatch, fake_home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    stub = StubAdapter()
    _install_stub(monkeypatch, stub)

    rc = main(["configure-agents", "--yes"])

    assert rc == 0
    capsys.readouterr()
    assert stub.apply_calls == [True]
    assert (fake_home / ".cline" / STUB_SETTINGS).exists()


def test_cli_yes_is_idempotent(
    monkeypatch: pytest.MonkeyPatch, fake_home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    stub = StubAdapter()
    _install_stub(monkeypatch, stub)

    assert main(["configure-agents", "--yes"]) == 0
    capsys.readouterr()
    assert main(["configure-agents", "--yes"]) == 0
    capsys.readouterr()

    assert stub.apply_calls == [True]  # second run detected CONFIGURED; no apply
    target = fake_home / ".cline" / STUB_SETTINGS
    assert json.loads(target.read_text(encoding="utf-8"))["mcpServers"]["universal-db"]["command"] == FAKE_PYTHON


def test_cli_non_tty_without_yes_writes_nothing(
    monkeypatch: pytest.MonkeyPatch, fake_home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    stub = StubAdapter()
    _install_stub(monkeypatch, stub)

    rc = main(["configure-agents"])

    assert rc == 1
    out = capsys.readouterr().out
    assert stub.apply_calls == []
    assert not (fake_home / ".cline" / STUB_SETTINGS).exists()
    assert "would add" in out
    assert "NOT CONFIRMED" in out
    assert "--yes" in out


def test_cli_unknown_agent_fails_closed_with_valid_names(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["configure-agents", "--agent", "nope"])

    assert rc == 2
    err = capsys.readouterr().err
    for name in ("claude-code", "claude-desktop", "dsh", "cursor", "vscode", "cline"):
        assert name in err


def test_cli_tty_prompt_accepted(
    monkeypatch: pytest.MonkeyPatch, fake_home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    stub = StubAdapter()
    _install_stub(monkeypatch, stub)
    prompts: list[str] = []

    def fake_input(prompt: str = "") -> str:
        prompts.append(prompt)
        return "y"

    monkeypatch.setattr(sys, "stdin", FakeTTY())
    monkeypatch.setattr("builtins.input", fake_input)

    rc = main(["configure-agents"])

    assert rc == 0
    capsys.readouterr()
    assert len(prompts) == 1 and "[y/N]" in prompts[0]
    assert stub.apply_calls == [True]
    assert (fake_home / ".cline" / STUB_SETTINGS).exists()


def test_cli_tty_prompt_declined(
    monkeypatch: pytest.MonkeyPatch, fake_home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    stub = StubAdapter()
    _install_stub(monkeypatch, stub)

    monkeypatch.setattr(sys, "stdin", FakeTTY())
    monkeypatch.setattr("builtins.input", lambda prompt="": "n")

    rc = main(["configure-agents"])

    assert rc == 0
    capsys.readouterr()
    assert stub.apply_calls == []
    assert not (fake_home / ".cline" / STUB_SETTINGS).exists()


def test_cli_fail_closed_state_prints_block_and_never_applies(
    monkeypatch: pytest.MonkeyPatch, fake_home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    stub = StubAdapter(status=AgentStatus.UNKNOWN_STATE_FAIL_CLOSED)
    _install_stub(monkeypatch, stub)

    # Asked to apply (--yes), a harness that failed closed fails the run
    # (exit 2), as one whose adapter raised does.
    rc = main(["configure-agents", "--yes"])

    assert rc == 2
    captured = capsys.readouterr()
    out = captured.out
    assert "CONFIG_ERROR" in captured.err and STUB_TARGET_NAME in captured.err
    assert stub.apply_calls == []  # never even offered, even with --yes
    assert not (fake_home / ".cline" / STUB_SETTINGS).exists()
    assert "FAIL CLOSED" in out
    assert "{garbage" in out  # the offending file's contents for inspection


def test_cli_missing_adapter_degrades_without_writing(
    monkeypatch: pytest.MonkeyPatch, fake_home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setitem(registry.ADAPTER_MODULES, STUB_TARGET_NAME, "universal_db_mcp.agents.nonexistent_adapter_zz")
    monkeypatch.setattr(registry, "HARNESS_NAMES", (STUB_TARGET_NAME,))

    # Plain detection reports it and succeeds; asked to apply (--yes), the
    # run fails (exit 2), because a harness that could not be evaluated must
    # not read as success. Either way nothing is written.
    assert main(["configure-agents"]) == 0
    assert "adapter-unavailable" in capsys.readouterr().out

    rc = main(["configure-agents", "--yes"])

    assert rc == 2
    captured = capsys.readouterr()
    assert "adapter-unavailable" in captured.out
    assert "CONFIG_ERROR" in captured.err and STUB_TARGET_NAME in captured.err
    assert not (fake_home / ".cline" / STUB_SETTINGS).exists()


def test_cli_detection_table_lists_all_six_harnesses(fake_home: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # No stub: the real adapters run against the fake HOME (all not installed).
    rc = main(["configure-agents", "--dry-run"])

    assert rc in (0, 1)  # 1 only if a real harness on this machine needs --yes
    out = capsys.readouterr().out
    for name in registry.HARNESS_NAMES:
        assert name in out
