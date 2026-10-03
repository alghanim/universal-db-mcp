"""Regression tests for the /code-review fixes in the CLI, agent adapters, the
wizard and the macOS Configure app (findings G1-G6, C1, X5, R3, X2, M2).

Every test runs against a fake HOME under tmp_path; nothing touches the real
home directory, and no AppleScript dialog is ever shown (osascript is a stub;
the snippets it is handed are only compiled with osacompile).
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

import pytest

# The harness fixtures the agent hardening tests already wire to a fake HOME.
import test_hardening_2026_09_27_agents as hard

from universal_db_mcp import wizard
from universal_db_mcp.__main__ import main
from universal_db_mcp.agents import claude_code, dsh
from universal_db_mcp.agents import core as agents_core
from universal_db_mcp.agents.core import AgentStatus
from universal_db_mcp.errors import ConfigError

_POSIX_ONLY = pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode and symlink semantics")
_AS_ROOT = sys.platform != "win32" and os.geteuid() == 0

_TOKEN = "fake-secret-token"
_DSH_SECRET_ROWS = (
    "- insert:\n"
    "    - id: other-server\n"
    "      config:\n"
    "        command: /usr/bin/other\n"
    "        env:\n"
    f"          API_TOKEN: {_TOKEN}\n"
)


def _shown(result: Any) -> str:
    """Everything a plan or apply result prints."""
    if isinstance(result, dsh.ApplyResult):
        return result.message
    return f"{result.summary}\n{result.config_block}\n{result.block}"


def _secret_body(h: hard._Harness) -> str:
    if h.module is dsh:
        return _DSH_SECRET_ROWS
    return json.dumps({h.servers_key: {"other": hard._SECRET_SERVER}}, indent=2) + "\n"


# --- G1: a refused config never has its other entries printed --------------------------


@_POSIX_ONLY
@pytest.mark.parametrize("name", hard.ADAPTERS)
def test_g1_a_config_refused_for_its_permissions_shows_only_this_tools_registration(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A hard link makes the replace refuse the file whoever runs it; the plan
    # printed the whole file (other servers' tokens) under "would add:".
    h = hard._harness(name, tmp_path, monkeypatch)
    h.target.write_text(_secret_body(h), encoding="utf-8")
    os.link(h.target, h.target.with_name("alias-of-config"))

    assert h.detect() is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    planned = h.plan()
    assert "hard links" in planned.summary
    assert _TOKEN not in _shown(planned)
    if h.module is not dsh:
        assert hard.FAKE_PYTHON in planned.config_block  # what would be added
    assert _TOKEN not in _shown(h.apply(True))


@pytest.mark.parametrize("name", hard.JSON_ADAPTERS)
def test_g1_a_malformed_or_conflicting_config_is_described_not_dumped(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    h = hard._harness(name, tmp_path, monkeypatch)
    secret = json.dumps({h.servers_key: {"other": hard._SECRET_SERVER}})
    h.target.write_text(secret[:-2], encoding="utf-8")  # truncated: not JSON

    planned = h.plan()
    assert planned.status is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    assert _TOKEN not in _shown(planned) and "not valid JSON" in planned.config_block
    assert _TOKEN not in _shown(h.apply(True))

    # A differing entry under our key is ours to show; the other servers are not.
    theirs = {"command": "/old/python", "args": ["serve"]}
    h.target.write_text(
        json.dumps({h.servers_key: {"other": hard._SECRET_SERVER, "universal-db": theirs}}), encoding="utf-8"
    )
    planned = h.plan()
    assert planned.status is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    assert _TOKEN not in _shown(planned) and "/old/python" in planned.config_block


def test_g1_dsh_fail_closed_report_shows_only_its_own_rows(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    h = hard._harness("dsh", tmp_path, monkeypatch)
    h.target.write_text(_DSH_SECRET_ROWS + "- id: mcp-universal-db\n  disabled: true\n", encoding="utf-8")

    planned = h.plan()
    assert planned.status is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    assert "override-form row" in planned.summary and "mcp-universal-db" in planned.summary
    assert _TOKEN not in _shown(planned)


@_POSIX_ONLY
def test_g1_configure_agents_dry_run_never_prints_another_servers_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    h = hard._harness("cursor", tmp_path, monkeypatch)
    h.target.write_text(_secret_body(h), encoding="utf-8")
    os.link(h.target, h.target.with_name("alias-of-config"))
    for key, value in hard.ENV.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))

    assert main(["configure-agents", "--dry-run", "--agent", "cursor"]) == 2
    out = capsys.readouterr().out
    assert "FAIL CLOSED" in out and _TOKEN not in out


# --- G2: as root, a user's link to a file they do not own is never read ----------------


@_POSIX_ONLY
@pytest.mark.parametrize("name", hard.ADAPTERS)
@pytest.mark.parametrize("victim_text", ['{"mcpServers": {"universal-db": {"d": "TOP-SECRET"}}}', "TOP-SECRET key"])
def test_g2_sudo_dry_run_never_reads_through_a_planted_link(
    name: str, victim_text: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    h = hard._harness(name, tmp_path, monkeypatch)
    victim = tmp_path / "etc" / "private_key.json"
    victim.parent.mkdir()
    victim.write_text(victim_text.replace("mcpServers", h.servers_key or "mcpServers"), encoding="utf-8")
    h.target.symlink_to(victim)
    hard._owned_by_another_user(monkeypatch, victim)
    hard._as_root(monkeypatch)
    real_read_bytes = Path.read_bytes

    def read_bytes(self: Path) -> bytes:
        assert os.path.realpath(self) != str(victim.resolve()), f"read {self} as root"
        return real_read_bytes(self)

    monkeypatch.setattr(Path, "read_bytes", read_bytes)
    monkeypatch.setattr(Path, "read_text", lambda self, *a, **k: read_bytes(self).decode())

    assert h.detect() is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    planned = h.plan()
    assert "TOP-SECRET" not in _shown(planned)
    assert f"{h.target} is a symlink" in _shown(planned)


@_POSIX_ONLY
def test_g2_as_root_a_hard_link_to_a_file_the_home_owner_does_not_own_is_not_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    h = hard._harness("cursor", tmp_path, monkeypatch)
    victim = tmp_path / "victim.json"
    victim.write_text('{"mcpServers": {"universal-db": {"d": "TOP-SECRET"}}}', encoding="utf-8")
    os.link(victim, h.target)
    hard._owned_by_another_user(monkeypatch, h.target)
    hard._as_root(monkeypatch)

    assert agents_core.load_json_or_fail_closed(h.target)[0] is None
    assert "TOP-SECRET" not in _shown(h.plan())


# --- G3: dsh resolves its registration at detection, as every adapter does -------------


def test_g3_dsh_with_an_unregistrable_override_fails_closed_at_detection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    home = tmp_path / "home"
    (home / ".dsh").mkdir(parents=True)
    (home / ".dsh" / "settings.yaml").write_text("x: 1\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("UDBMCP_CONFIG", "missing/rel.yaml")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(dsh, "_resolve_python", lambda: hard.FAKE_PYTHON)

    with pytest.raises(ConfigError):
        dsh.detect(home / ".dsh")
    assert main(["configure-agents", "--json", "--agent", "dsh"]) == 2
    (row,) = json.loads(capsys.readouterr().out)["harnesses"]
    assert row["status"] == "fail_closed" and row["writable"] is False
    assert main(["configure-agents", "--json", "--agent", "dsh", "--yes"]) == 2
    assert not (home / ".dsh" / dsh.PATCH_FILENAME).exists()


def test_g3_dsh_not_installed_resolves_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("UDBMCP_CONFIG", "missing/rel.yaml")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(dsh, "_dsh_cli_on_path", lambda: False)
    assert dsh.detect(tmp_path / "no-dsh") is AgentStatus.NOT_INSTALLED


# --- G4: a seeding failure is reported, never a traceback that skips the rest ----------


def test_g4_a_seeding_failure_after_a_write_does_not_abort_the_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    first = hard._harness("cursor", tmp_path, monkeypatch)
    second = hard._harness("cline", tmp_path, monkeypatch)
    second.target.write_text("{}", encoding="utf-8")
    for key, value in hard.ENV.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))

    def refuse(*_args: Any, **_kwargs: Any) -> Any:
        raise PermissionError("~/.universal-db-mcp is a symlink to /etc, which its owner does not own")

    monkeypatch.setattr(agents_core, "ensure_per_user_harness_config", refuse)

    assert main(["configure-agents", "--yes"]) == 1
    captured = capsys.readouterr()
    assert "Traceback" not in captured.out + captured.err
    assert "is a symlink to /etc" in captured.out
    assert first.detect() is AgentStatus.CONFIGURED and second.detect() is AgentStatus.CONFIGURED

    first.target.unlink()
    assert main(["configure-agents", "--json", "--yes", "--agent", "cursor"]) == 1
    (applied,) = json.loads(capsys.readouterr().out)["applied"]
    assert applied["status"] == "configured" and "is a symlink to /etc" in applied["seed_error"]


# --- G5: a project-scoped file never gets this machine's paths -------------------------


def _claude_code_with_project(tmp_path: Path, project_servers: dict[str, Any]) -> tuple[Path, Path, Path]:
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    proj = tmp_path / "proj"
    proj.mkdir()
    project_file = claude_code.project_config_path(proj)
    project_file.write_text(json.dumps({"mcpServers": project_servers}, indent=2), encoding="utf-8")
    return home, proj, project_file


def _legacy() -> dict[str, Any]:
    return {
        "type": "stdio",
        "command": hard.FAKE_PYTHON,
        "args": hard.LEGACY_ARGS,
        "env": {"UDBMCP_CONFIG": hard.FAKE_CONFIG},
    }


def test_g5_upgrading_the_user_scope_never_adds_an_entry_to_the_projects_mcp_json(tmp_path: Path) -> None:
    home, proj, project_file = _claude_code_with_project(tmp_path, {"team": {"command": "/usr/bin/team"}})
    claude_code.user_config_path(home).write_text(json.dumps({"mcpServers": {"universal-db": _legacy()}}))
    committed = project_file.read_bytes()

    planned = claude_code.plan(hard.ENV, home, project_dir=proj)
    assert planned.status is AgentStatus.INSTALLED_UNCONFIGURED
    assert f"project scope {project_file}: left as it is" in planned.summary
    result = claude_code.apply(hard.ENV, home, True, project_dir=proj)

    assert result.status is AgentStatus.CONFIGURED
    assert project_file.read_bytes() == committed
    assert not list(proj.glob(".mcp.json.bak.*"))
    user = json.loads(claude_code.user_config_path(home).read_text())
    assert user["mcpServers"]["universal-db"]["args"] == hard.ISOLATED_ARGS
    assert claude_code.detect(hard.ENV, home, project_dir=proj) is AgentStatus.CONFIGURED


@_POSIX_ONLY
@pytest.mark.skipif(_AS_ROOT, reason="root may write any file")
def test_g5_a_read_only_project_file_this_tool_does_not_write_blocks_nothing(tmp_path: Path) -> None:
    home, proj, project_file = _claude_code_with_project(tmp_path, {})
    project_file.chmod(0o444)

    assert claude_code.detect(hard.ENV, home, project_dir=proj) is AgentStatus.INSTALLED_UNCONFIGURED
    assert claude_code.apply(hard.ENV, home, True, project_dir=proj).status is AgentStatus.CONFIGURED


def test_g5_this_tools_own_legacy_entry_in_the_project_file_is_still_upgraded(tmp_path: Path) -> None:
    # Its paths are already in the file; only the args change (-I).
    home, proj, project_file = _claude_code_with_project(tmp_path, {"universal-db": _legacy()})

    result = claude_code.apply(hard.ENV, home, True, project_dir=proj)

    assert result.status is AgentStatus.CONFIGURED
    project = json.loads(project_file.read_text())
    assert project["mcpServers"]["universal-db"] == {**_legacy(), "args": hard.ISOLATED_ARGS}


# --- G6: a '~user' typo is a clean CONFIG_ERROR ----------------------------------------


def test_g6_unknown_tilde_user_in_udbmcp_config_is_a_config_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(ConfigError, match="UDBMCP_CONFIG"):
        agents_core.resolve_harness_config_path({"UDBMCP_CONFIG": "~nosuchuser_zz/config.yaml"}, tmp_path)

    monkeypatch.setenv("UDBMCP_CONFIG", "~nosuchuser_zz/config.yaml")
    monkeypatch.setenv("HOME", str(tmp_path))
    rc = main(["add-connection", "--json", "--name", "x", "--engine", "sqlite", "--database", str(tmp_path / "x.db")])
    err = capsys.readouterr().err
    assert rc == 1 and "CONFIG_ERROR" in err and "~nosuchuser_zz" in err


# --- C1: the wizard's secrets directory carries no ACL that opens it -------------------

_DARWIN_ONLY = pytest.mark.skipif(sys.platform != "darwin", reason="macOS extended ACLs")


def _chmod_acl(path: Path, entry: str) -> None:
    subprocess.run(["/bin/chmod", "+a", entry, str(path)], check=True)  # noqa: S603 - a tmp_path dir


def _acl_listing(path: Path) -> str:
    return subprocess.run(["/bin/ls", "-led", str(path)], capture_output=True, text=True, check=True).stdout  # noqa: S603


@_DARWIN_ONLY
def test_c1_a_new_secrets_dir_does_not_inherit_the_config_dirs_acl(tmp_path: Path) -> None:
    config_dir = tmp_path / "cfg"
    config_dir.mkdir()
    _chmod_acl(config_dir, "everyone allow read,list,search,file_inherit,directory_inherit")

    fd = wizard._prepare_secrets_dir(config_dir / "secrets", None)
    assert fd is not None
    try:
        assert not wizard._has_extended_acl(fd)
    finally:
        os.close(fd)
    assert "everyone" not in _acl_listing(config_dir / "secrets")


@_DARWIN_ONLY
def test_c1_an_existing_secrets_dir_with_an_acl_is_refused(tmp_path: Path) -> None:
    sdir = tmp_path / "secrets"
    sdir.mkdir(mode=0o700)
    _chmod_acl(sdir, "everyone allow read,list,search,file_inherit")

    with pytest.raises(wizard.WizardError, match="access control list"):
        wizard._prepare_secrets_dir(sdir, None)


# --- X5: a relative ca_file default is the file the loader uses ------------------------


def test_x5_re_adding_offers_the_ca_file_the_server_resolves(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg_dir = tmp_path / "cfg"
    (cfg_dir / "certs").mkdir(parents=True)
    ca = cfg_dir / "certs" / "ca.pem"
    ca.write_text("-----BEGIN CERTIFICATE-----\n", encoding="utf-8")
    cfg = cfg_dir / "config.yaml"
    cfg.write_text(
        "connections:\n  pg:\n    type: postgres\n    host: db\n    port: 5432\n    database: fin\n"
        "    tls:\n      enabled: true\n      ca_file: certs/ca.pem\n",
        encoding="utf-8",
    )
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    # engine, name, host, port, database, username, TLS, CA file, test
    answers = iter(["2", "pg", "", "", "", "svc", "", "", "n"])
    prompts: list[str] = []

    def fake_input(prompt: str = "") -> str:
        prompts.append(prompt)
        return next(answers)

    monkeypatch.setattr("builtins.input", fake_input)
    monkeypatch.setattr(wizard.getpass, "getpass", lambda prompt="": "pw")

    _name, connection, _test, _creds = wizard.collect_answers_interactive(cfg)

    assert connection.tls.enabled and connection.tls.ca_file == str(ca)
    assert any(str(ca) in prompt for prompt in prompts)


# --- R3: a config whose group the wizard cannot keep is not regrouped ------------------


@_POSIX_ONLY
@pytest.mark.skipif(_AS_ROOT, reason="root keeps the group")
def test_r3_commit_merge_refuses_to_regroup_a_group_readable_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = tmp_path / "config.yaml"
    cfg.write_text(wizard.MINIMAL_CONFIG, encoding="utf-8")
    cfg.chmod(0o640)
    connection = wizard.build_connection(name="lite", engine="sqlite", database=str(tmp_path / "x.db"))
    plan = wizard.plan_merge(cfg, "lite", connection)
    original = cfg.read_bytes()
    foreign = max(os.getegid(), tmp_path.stat().st_gid, *os.getgroups()) + 1
    real_stat = Path.stat

    def grouped(self: Path, *, follow_symlinks: bool = True) -> os.stat_result:
        st = real_stat(self, follow_symlinks=follow_symlinks)
        if os.path.abspath(self) != str(cfg):
            return st
        fields: list[float] = list(st[:10])
        fields[5] = foreign
        return os.stat_result(fields)

    monkeypatch.setattr(Path, "stat", grouped)

    with pytest.raises(wizard.WizardError, match=f"group {foreign}"):
        wizard.commit_merge(plan)
    assert cfg.read_bytes() == original
    assert not [p for p in tmp_path.iterdir() if p.name.endswith(".tmp")]


# --- X2: the SIGTERM grace outlasts the cancel hook and the audit write ----------------


def test_x2_sigterm_grace_is_longer_than_the_cancel_hook_budget() -> None:
    import universal_db_mcp.__main__ as cli
    from universal_db_mcp.services import executor

    assert cli._sigterm_grace_seconds() > executor._CANCEL_HOOK_BUDGET
    assert cli._SIGTERM_HARD_EXIT_SECONDS > cli._sigterm_grace_seconds()


@pytest.mark.skipif(sys.platform == "win32", reason="no SIGTERM handling on Windows")
def test_x2_the_watchdog_takes_the_budget_from_the_executor(monkeypatch: pytest.MonkeyPatch) -> None:
    import anyio

    import universal_db_mcp.__main__ as cli
    from universal_db_mcp.services import executor

    monkeypatch.setattr(executor, "_CANCEL_HOOK_BUDGET", 3.5)
    timers: list[float] = []

    class FakeTimer:
        def __init__(self, interval: float, _function: Any) -> None:
            timers.append(interval)
            self.daemon = False

        def start(self) -> None:
            pass

    monkeypatch.setattr(threading, "Timer", FakeTimer)
    monkeypatch.setattr(signal, "alarm", lambda _seconds: 0)
    previous = signal.getsignal(signal.SIGALRM)

    async def run() -> None:
        async with anyio.create_task_group() as tg:
            tg.start_soon(cli._cancel_on_sigterm, tg.cancel_scope)
            await anyio.sleep(0.05)
            os.kill(os.getpid(), signal.SIGTERM)
            await anyio.sleep(5)

    try:
        anyio.run(run)
    finally:
        signal.signal(signal.SIGALRM, previous)
    assert timers == [3.5 + cli._SIGTERM_AUDIT_FLUSH_SECONDS]


# --- M2: every AppleScript the Configure app runs compiles -----------------------------

_APP_SCRIPT = Path(__file__).resolve().parents[2] / "packaging" / "macos-app" / "configure_agents_app.sh"
_APP_VENV_PY = 'VENV_PY="/usr/local/universal-db-mcp/venv/bin/python"\n'


def _app_snippets(tmp_path: Path, harnesses: list[dict[str, Any]], choose: str, *, installed: bool = True) -> list[str]:
    """Run the app script against a stub interpreter and a stub osascript (it
    never shows anything) and return every AppleScript it was handed."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    stubs = tmp_path / "stubs"
    stubs.mkdir()
    detection = tmp_path / "detect.json"
    detection.write_text(json.dumps({"home": str(tmp_path), "harnesses": harnesses}), encoding="utf-8")
    applied = json.dumps({"applied": [{"status": "configured", "summary": 'added "universal-db" to C:\\x'}]})
    venv_py = stubs / "venv-python"
    venv_py.write_text(
        "#!/bin/sh\n"
        'case "$*" in\n'
        f'  *"configure-agents --json") cat "{detection}" ;;\n'
        '  *"--agent cursor --json --yes") exit 1 ;;\n'
        f"  *\"--json --yes\") echo '{applied}' ;;\n"
        f'  *) exec "{sys.executable}" "$@" ;;\n'
        "esac\n",
        encoding="utf-8",
    )
    calls = tmp_path / "calls"
    calls.mkdir()
    osascript = stubs / "osascript"
    osascript.write_text(
        "#!/bin/bash\n"
        f'out="$(mktemp "{calls}/call.XXXXXX")"\n'
        'if [ $# -eq 0 ]; then cat > "$out"; echo "$CHOICE"; else\n'
        '  while [ $# -gt 0 ]; do [ "$1" = "-e" ] && { shift; printf "%s\\n" "$1" >> "$out"; }; shift; done\n'
        "fi\n",
        encoding="utf-8",
    )
    for stub in (venv_py, osascript):
        stub.chmod(0o755)
    script = _APP_SCRIPT.read_text(encoding="utf-8")
    assert script.count(_APP_VENV_PY) == 1
    python = venv_py if installed else tmp_path / "absent-python"
    app = tmp_path / "app.sh"
    app.write_text(script.replace(_APP_VENV_PY, f'VENV_PY="{python}"\n'), encoding="utf-8")
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is not installed")
    subprocess.run(  # noqa: S603 - the packaged script, against stubs only
        [bash, str(app)],
        env={"PATH": f"{stubs}{os.pathsep}/usr/bin:/bin", "HOME": str(tmp_path), "CHOICE": choose},
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    return [path.read_text(encoding="utf-8") for path in sorted(calls.iterdir())]


@pytest.mark.skipif(sys.platform == "win32", reason="the macOS app script runs under bash")
def test_m2_every_applescript_the_configure_app_runs_compiles(tmp_path: Path) -> None:
    osacompile = shutil.which("osacompile")
    if osacompile is None:
        pytest.skip("osacompile exists only on macOS; the AppleScript cannot be compiled here")
    writable = [
        {"agent": "claude-code", "status": "installed_unconfigured", "writable": True},
        {"agent": "cursor", "status": "installed_unconfigured", "writable": True},
        {"agent": "vscode", "status": "unknown_state_fail_closed", "writable": False},
    ]
    snippets = [
        # chooser, consent, the result dialog (one apply failed, one harness not offered)
        *_app_snippets(tmp_path / "apply", writable, "claude-code|cursor"),
        # nothing configurable, one harness failed closed: the stop dialog
        *_app_snippets(tmp_path / "failed", writable[2:], "CANCELLED"),
        # nothing configurable at all: the note dialog
        *_app_snippets(tmp_path / "none", [], "CANCELLED"),
        # not installed
        *_app_snippets(tmp_path / "absent", [], "CANCELLED", installed=False),
    ]
    assert len(snippets) == 6, snippets
    for index, snippet in enumerate(snippets):
        source = tmp_path / f"snippet{index}.applescript"
        source.write_text(snippet, encoding="utf-8")
        proc = subprocess.run(  # noqa: S603 - compiles only; nothing is shown or run
            [osacompile, "-o", "/dev/null", str(source)], capture_output=True, text=True, check=False
        )
        assert proc.returncode == 0, f"{proc.stderr}\n{snippet}"


def test_c1_a_secret_file_whose_acl_opens_it_is_refused_before_anything_is_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # config.darwin_secret_file_acl_problems is checked on every secret the
    # wizard creates, before the secret goes into it.
    checked: list[Path] = []

    def problems(path: Path) -> list[str]:
        checked.append(path)
        return ["everyone may read it"]

    monkeypatch.setattr(wizard, "darwin_secret_file_acl_problems", problems)
    secret = tmp_path / "prod.password"

    with pytest.raises(wizard.WizardError, match="everyone may read it"):
        wizard._write_secret(secret, "s3cret")
    assert checked == [secret] and not secret.exists()


# --- C7: the env-secret warning names the Oracle wallet password variable too ---------


def test_c7_env_secret_warning_names_the_wallet_password_variable(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from universal_db_mcp.__main__ import _warn_env_secret_connections

    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "connections:\n  ora:\n    type: oracle\n    host: db\n    port: 1521\n    database: FREEPDB1\n"
        "    username_env: ORA_USER\n"
        f"    options:\n      wallet_location: {tmp_path / 'wallet'}\n      wallet_password_env: ORA_WALLET_PW\n",
        encoding="utf-8",
    )

    _warn_env_secret_connections({"UDBMCP_CONFIG": str(cfg)}, tmp_path)

    err = capsys.readouterr().err
    assert "connection 'ora'" in err and "ORA_WALLET_PW" in err
    assert "Prefer username_file/password_file/options.wallet_password_file" in err
