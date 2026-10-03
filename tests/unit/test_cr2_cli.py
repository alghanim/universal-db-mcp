"""Regression tests for the second /code-review pass over the CLI, the agent
adapters, the wizard, doctor and the config loader (VERDICTS V2-a..V2-j).

Every test runs against a fake HOME under tmp_path; nothing touches the real
home directory and no GUI dialog is ever shown.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

# The harness fixtures the agent hardening tests already wire to a fake HOME.
import test_hardening_2026_09_27_agents as hard

from universal_db_mcp import wizard
from universal_db_mcp.__main__ import main
from universal_db_mcp.agents import core as agents_core
from universal_db_mcp.agents import dsh
from universal_db_mcp.agents.core import AgentStatus
from universal_db_mcp.config import load_config
from universal_db_mcp.diagnostics.doctor import run_doctor
from universal_db_mcp.errors import ConfigError

_POSIX_ONLY = pytest.mark.skipif(sys.platform == "win32", reason="POSIX ownership and modes")
_DARWIN_ONLY = pytest.mark.skipif(sys.platform != "darwin", reason="macOS extended ACLs")

# Every fragment of the planted secret that must never be printed.
_SECRET = "ghp_SECRETa1b2c3d4e5f6"
_FRAGMENTS = (_SECRET, "SECRETa1", "a1b2c3", "d4e5f6", "ghp_")


def _leaks(text: str) -> list[str]:
    return [f for f in _FRAGMENTS if f in text]


def _shown(result: Any) -> str:
    if isinstance(result, dsh.ApplyResult):
        return result.message
    return f"{result.summary}\n{result.config_block}\n{result.block}"


# Malformed YAML whose offending token holds another server's secret.
_BROKEN_YAML = {
    "unclosed-quote": f'- insert:\n    - id: gh\n      config: {{env: {{GITHUB_TOKEN: "{_SECRET}}}\n',
    "unclosed-flow": f"- insert:\n    - id: gh\n      config: {{env: {{GITHUB_TOKEN: {_SECRET}\n",
    "tab": f"- insert:\n    - id: gh\n\t{_SECRET}: x\n",
    "undefined-alias": f"- insert:\n    - id: gh\n      token: *{_SECRET}\n",
    "bad-escape": f'- insert:\n    - id: gh\n      token: "\\q{_SECRET}"\n',
    "unknown-tag": f"- insert:\n    - id: gh\n      token: !{_SECRET} x\n",
    "duplicate-anchor": f"- &{_SECRET} a\n- &{_SECRET} b\n",
    "control-char": f"- insert:\n    - id: gh\n      token: {_SECRET}\x01\n",
    "quote-in-alias": f"- a: *x'{_SECRET}\"y\n",
}


# --- V2-e: a malformed YAML file is described by line and column, never quoted ---------


@pytest.mark.parametrize("shape", sorted(_BROKEN_YAML))
def test_v2e_yaml_error_description_never_quotes_the_file(shape: str) -> None:
    import yaml

    from universal_db_mcp.config import describe_yaml_error

    with pytest.raises(yaml.YAMLError) as info:
        yaml.safe_load(_BROKEN_YAML[shape])
    described = describe_yaml_error(info.value)
    assert not _leaks(described), described
    if shape != "control-char":
        assert "line " in described and "column " in described, described


@pytest.mark.parametrize("shape", sorted(_BROKEN_YAML))
def test_v2e_dsh_never_prints_a_malformed_patch(shape: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    h = hard._harness("dsh", tmp_path, monkeypatch)
    h.target.write_text(_BROKEN_YAML[shape], encoding="utf-8")

    assert h.detect() is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    planned = h.plan()
    assert not _leaks(_shown(planned)), _shown(planned)
    assert not _leaks(_shown(h.apply(True)))
    assert h.target.read_text(encoding="utf-8") == _BROKEN_YAML[shape]  # untouched


def test_v2e_dsh_names_the_line_and_column(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    h = hard._harness("dsh", tmp_path, monkeypatch)
    h.target.write_text(_BROKEN_YAML["unclosed-quote"], encoding="utf-8")
    shown = _shown(h.plan())
    assert "malformed YAML" in shown and "line 4" in shown and "column " in shown, shown


def test_v2e_configure_agents_dry_run_never_prints_a_malformed_dsh_patch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    h = hard._harness("dsh", tmp_path, monkeypatch)
    h.target.write_text(_BROKEN_YAML["unclosed-quote"], encoding="utf-8")
    monkeypatch.setattr(dsh, "default_dsh_home", lambda: h.target.parent, raising=False)
    monkeypatch.setenv("DSH_HOME", str(h.target.parent))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    for key, value in hard.ENV.items():
        monkeypatch.setenv(key, value)

    main(["configure-agents", "--dry-run", "--agent", "dsh"])
    captured = capsys.readouterr()
    assert not _leaks(captured.out + captured.err), captured.out


def test_v2e_the_generic_yaml_loader_never_quotes_the_file(tmp_path: Path) -> None:
    target = tmp_path / "harness.yaml"
    target.write_text(_BROKEN_YAML["unclosed-quote"], encoding="utf-8")
    data, error = agents_core.load_yaml_or_fail_closed(target)
    assert data is None and error is not None and not _leaks(error) and "line 4" in error


@pytest.mark.parametrize("shape", sorted(_BROKEN_YAML))
def test_v2e_a_malformed_config_file_is_never_quoted(shape: str, tmp_path: Path) -> None:
    # A config may (wrongly) inline a secret: pydantic's input echo is already
    # suppressed, and the YAML error is the same class.
    cfg = tmp_path / "config.yaml"
    cfg.write_text("connections:\n" + _BROKEN_YAML[shape].replace("- ", "  x", 1), encoding="utf-8")
    try:
        load_config(cfg)
    except ConfigError as exc:
        assert not _leaks(str(exc)), str(exc)
    report = run_doctor(str(cfg))
    assert not _leaks(json.dumps(report))


def test_v2e_a_duplicate_key_is_still_named(tmp_path: Path) -> None:
    cfg = tmp_path / "config.yaml"
    cfg.write_text("connections: {}\nconnections: {}\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="duplicate key 'connections' at line 2"):
        load_config(cfg)


def test_v2e_the_wizard_never_quotes_a_malformed_config(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    cfg = tmp_path / "config.yaml"
    cfg.write_text(f'connections:\n  pg: {{password: "{_SECRET}}}\n', encoding="utf-8")
    rc = main(["add-connection", "--json", "--no-test", "--config", str(cfg), "--name", "x", "--engine", "sqlite",
               "--database", str(tmp_path / "x.db")])  # fmt: skip
    captured = capsys.readouterr()
    assert rc != 0 and not _leaks(captured.out + captured.err), captured.err


# --- V2-f: a harness config that is not UTF-8 is described without its bytes -----------


@pytest.mark.parametrize("name", hard.ADAPTERS)
def test_v2f_a_non_utf8_harness_config_never_shows_a_byte_or_offset(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    h = hard._harness(name, tmp_path, monkeypatch)
    if h.module is dsh:
        body = b"- insert:\n    - id: gh\n      env: {TOKEN: s3cr\xe9t}\n"
    else:
        body = b'{"' + h.servers_key.encode() + b'": {"gh": {"env": {"TOKEN": "s3cr\xe9t"}}}}'
    h.target.write_bytes(body)

    assert h.detect() is AgentStatus.UNKNOWN_STATE_FAIL_CLOSED
    for shown in (_shown(h.plan()), _shown(h.apply(True))):
        assert "0xe9" not in shown and "position" not in shown and "s3cr" not in shown, shown
        assert "UTF-8" in shown, shown
    assert h.target.read_bytes() == body


# --- V2-a: doctor reports a '~user' that names no account, never a traceback -------------


def test_v2a_doctor_reports_an_unknown_tilde_user_sqlite_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    cfg = tmp_path / "c.yaml"
    cfg.write_text(
        f"application: {{audit_path: {tmp_path}/audit.jsonl}}\n"
        "connections:\n  lite: {type: sqlite, database: ~nosuchuser_zz/app.db}\n",
        encoding="utf-8",
    )
    report = run_doctor(str(cfg))
    checks = {c["check"]: c for c in report["checks"]}
    assert checks["config"]["status"] == "ok", checks["config"]
    file_check = checks["connection-lite-file"]
    assert file_check["status"] == "fatal" and "~nosuchuser_zz" in file_check["detail"], file_check
    assert report["healthy"] is False


def test_v2a_doctor_turns_any_unexpected_error_into_a_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from universal_db_mcp.diagnostics import doctor

    def boom(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("Could not determine home directory.")

    monkeypatch.setattr(doctor, "_run_checks", boom)
    report = run_doctor(str(tmp_path / "c.yaml"))
    assert report["healthy"] is False
    assert any(c["check"] == "doctor" and "RuntimeError" in c["detail"] for c in report["checks"])


def test_v2a_the_cli_doctor_prints_json_for_an_unknown_tilde_user(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    cfg = tmp_path / "c.yaml"
    cfg.write_text(
        f"application: {{audit_path: {tmp_path}/audit.jsonl}}\n"
        "connections:\n  lite: {type: sqlite, database: ~nosuchuser_zz/app.db}\n",
        encoding="utf-8",
    )
    rc = main(["doctor", "--config", str(cfg)])
    out = capsys.readouterr().out
    assert rc == 1
    assert json.loads(out)["healthy"] is False


# --- V2-b: only an ACL that grants access refuses the secrets directory -----------------


def _chmod_acl(path: Path, entry: str) -> None:
    subprocess.run(["/bin/chmod", "+a", entry, str(path)], check=True)  # noqa: S603 - a tmp_path dir


@_DARWIN_ONLY
@pytest.mark.parametrize(
    "entry",
    ["group:everyone deny delete", "user:nobody deny read,list,file_inherit,directory_inherit"],
)
def test_v2b_a_deny_only_acl_on_an_existing_secrets_dir_is_accepted(entry: str, tmp_path: Path) -> None:
    sdir = tmp_path / "secrets"
    sdir.mkdir(mode=0o700)
    _chmod_acl(sdir, entry)
    fd = wizard._prepare_secrets_dir(sdir, None)
    assert fd is not None
    os.close(fd)


@_DARWIN_ONLY
def test_v2b_the_owners_own_allow_entry_is_accepted(tmp_path: Path) -> None:
    import pwd

    sdir = tmp_path / "secrets"
    sdir.mkdir(mode=0o700)
    _chmod_acl(sdir, f"user:{pwd.getpwuid(os.getuid()).pw_name} allow list,add_file,file_inherit")
    fd = wizard._prepare_secrets_dir(sdir, None)
    assert fd is not None
    os.close(fd)


@_DARWIN_ONLY
@pytest.mark.parametrize(
    "entry",
    [
        "everyone allow read,list,search,file_inherit",
        "everyone allow add_file,delete_child",
        "group:staff allow read,only_inherit,file_inherit",
        "everyone allow writesecurity",
    ],
)
def test_v2b_an_allow_entry_for_others_is_still_refused(entry: str, tmp_path: Path) -> None:
    sdir = tmp_path / "secrets"
    sdir.mkdir(mode=0o700)
    _chmod_acl(sdir, entry)
    with pytest.raises(wizard.WizardError, match="access control list"):
        wizard._prepare_secrets_dir(sdir, None)


@_DARWIN_ONLY
def test_v2b_add_connection_writes_secrets_into_a_deny_only_secrets_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    cfg_dir = tmp_path / "cfg"
    (cfg_dir / "secrets").mkdir(parents=True, mode=0o700)
    _chmod_acl(cfg_dir / "secrets", "group:everyone deny delete")
    pw = tmp_path / "pw"
    pw.write_text("hunter2\n", encoding="utf-8")
    pw.chmod(0o600)
    rc = main(["add-connection", "--json", "--no-test", "--config", str(cfg_dir / "config.yaml"), "--name", "pg1",
               "--engine", "postgres", "--host", "127.0.0.1", "--port", "5433", "--database", "postgres",
               "--username", "svc", "--password-file", str(pw)])  # fmt: skip
    captured = capsys.readouterr()
    assert rc == 0, captured.err
    assert json.loads(captured.out)["action"] == "added"
    assert (cfg_dir / "secrets" / "pg1.password").read_text(encoding="utf-8").strip() == "hunter2"


@_DARWIN_ONLY
def test_v2b_a_deny_only_acl_on_the_way_does_not_stop_the_root_walk(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    denied = tmp_path / "denied"
    denied.mkdir(mode=0o755)
    _chmod_acl(denied, "group:everyone deny delete")
    monkeypatch.setattr(wizard, "_only_root_can_change", lambda st: True)  # the mode bits pass
    os.close(wizard._open_root_only_directory(denied))


@_DARWIN_ONLY
def test_v2b_a_new_secrets_dir_still_drops_an_inherited_allow_entry(tmp_path: Path) -> None:
    config_dir = tmp_path / "cfg"
    config_dir.mkdir()
    _chmod_acl(config_dir, "everyone allow read,list,search,file_inherit,directory_inherit")
    fd = wizard._prepare_secrets_dir(config_dir / "secrets", None)
    assert fd is not None
    try:
        assert not wizard._has_extended_acl(fd)
    finally:
        os.close(fd)


# --- V2-c: a re-run seeds the per-user config a failed seeding left missing -------------


def _per_user_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    (home / ".cursor").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("PATH", "")
    monkeypatch.delenv("UDBMCP_CONFIG", raising=False)
    monkeypatch.setenv("UDBMCP_VENV_PYTHON", hard.FAKE_PYTHON)
    monkeypatch.setattr(agents_core, "SYSTEM_CONFIG_PATH", tmp_path / "no-such-etc" / "config.yaml")
    return home


@_POSIX_ONLY
@pytest.mark.parametrize("as_json", [False, True])
def test_v2c_a_re_run_seeds_the_config_a_failed_seeding_left_missing(
    as_json: bool, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    home = _per_user_home(tmp_path, monkeypatch)
    state = home / ".universal-db-mcp"
    state.write_text("not a directory", encoding="utf-8")
    json_flag = ["--json"] if as_json else []

    assert main(["configure-agents", *json_flag, "--agent", "cursor", "--yes"]) == 1
    first = capsys.readouterr()
    assert "Traceback" not in first.out + first.err
    assert "re-run" in first.out

    state.unlink()
    # A dry run says what is missing and writes nothing.
    main(["configure-agents", *json_flag, "--agent", "cursor", "--dry-run"])
    dry = capsys.readouterr()
    assert str(state / "config.yaml") in dry.out + dry.err
    assert not state.exists()

    assert main(["configure-agents", *json_flag, "--agent", "cursor", "--yes"]) == 0
    second = capsys.readouterr()
    assert (state / "config.yaml").is_file(), second.out
    load_config(state / "config.yaml")
    if as_json:
        assert json.loads(second.out)["config_seeded"] == str(state / "config.yaml")
    else:
        assert f"seeded per-user harness config: {state / 'config.yaml'}" in second.out


@_POSIX_ONLY
def test_v2c_a_re_run_that_still_cannot_seed_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    home = _per_user_home(tmp_path, monkeypatch)
    (home / ".universal-db-mcp").write_text("not a directory", encoding="utf-8")
    assert main(["configure-agents", "--agent", "cursor", "--yes"]) == 1
    capsys.readouterr()
    assert main(["configure-agents", "--agent", "cursor", "--yes"]) == 1
    assert "could not be seeded" in capsys.readouterr().out


@_POSIX_ONLY
def test_v2c_a_configured_harness_with_its_config_present_changes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    home = _per_user_home(tmp_path, monkeypatch)
    assert main(["configure-agents", "--agent", "cursor", "--yes"]) == 0
    seeded = home / ".universal-db-mcp" / "config.yaml"
    before = seeded.read_bytes()
    capsys.readouterr()
    assert main(["configure-agents", "--agent", "cursor", "--yes"]) == 0
    assert "seeded" not in capsys.readouterr().out
    assert seeded.read_bytes() == before


# --- V2-h: as root, a file the home's owner may not read is never read -----------------


def _report_owner(monkeypatch: pytest.MonkeyPatch, path: Path, uid: int) -> None:
    """os.fstat/os.stat report *uid* as the owner of *path*'s inode."""
    ino = os.stat(path).st_ino
    real_fstat, real_stat = os.fstat, os.stat

    def patched(st: os.stat_result) -> os.stat_result:
        if st.st_ino != ino:
            return st
        fields: list[Any] = list(st[:10])
        fields[4] = uid
        return os.stat_result(fields)

    monkeypatch.setattr(os, "fstat", lambda fd: patched(real_fstat(fd)))
    monkeypatch.setattr(os, "stat", lambda p, *a, **k: patched(real_stat(p, *a, **k)))


@_POSIX_ONLY
def test_v2h_as_root_a_renamed_hard_link_to_a_root_only_file_is_not_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The user hard-linked a root-only file in as their config; the original
    # name was then replaced by rename, leaving the inode with one link.
    h = hard._harness("cursor", tmp_path, monkeypatch)
    victim = tmp_path / "master.passwd"
    victim.write_text('{"mcpServers": {"universal-db": {"d": "TOP-SECRET"}}}', encoding="utf-8")
    victim.chmod(0o600)
    os.link(victim, h.target)
    os.replace(tmp_path / "home" / ".cursor" / "mcp.json", tmp_path / "home" / ".cursor" / "mcp.json")
    victim.unlink()  # as a rename over the original name would
    assert os.stat(h.target).st_nlink == 1
    _report_owner(monkeypatch, h.target, os.getuid() + 1)
    hard._as_root(monkeypatch)

    data, error = agents_core.load_json_or_fail_closed(h.target)
    assert data is None and error is not None and "TOP-SECRET" not in error
    assert "TOP-SECRET" not in _shown(h.plan())


@_POSIX_ONLY
def test_v2h_as_root_the_users_own_config_is_still_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    h = hard._harness("cursor", tmp_path, monkeypatch)
    h.target.write_text('{"mcpServers": {}}', encoding="utf-8")
    h.target.chmod(0o600)
    hard._as_root(monkeypatch)
    assert agents_core.load_json_or_fail_closed(h.target) == ({"mcpServers": {}}, None)
    assert h.detect() is AgentStatus.INSTALLED_UNCONFIGURED


@_POSIX_ONLY
def test_v2h_as_root_a_root_owned_config_the_user_may_read_is_still_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    h = hard._harness("cursor", tmp_path, monkeypatch)
    h.target.write_text('{"mcpServers": {}}', encoding="utf-8")
    h.target.chmod(0o644)
    _report_owner(monkeypatch, h.target, os.getuid() + 1)
    hard._as_root(monkeypatch)
    assert agents_core.load_json_or_fail_closed(h.target) == ({"mcpServers": {}}, None)


@_POSIX_ONLY
def test_v2h_as_root_a_file_swapped_after_the_check_is_not_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    h = hard._harness("cursor", tmp_path, monkeypatch)
    h.target.write_text('{"mcpServers": {}}', encoding="utf-8")
    swapped = tmp_path / "swapped.json"
    swapped.write_text('{"mcpServers": {"universal-db": {"d": "RACED-SECRET"}}}', encoding="utf-8")
    hard._as_root(monkeypatch)
    real_open = os.open

    def racing_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        if os.fspath(path) == os.path.realpath(h.target):
            os.replace(swapped, h.target)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", racing_open)
    data, error = agents_core.load_json_or_fail_closed(h.target)
    assert data is None and error is not None and "RACED-SECRET" not in error


@_POSIX_ONLY
def test_v2h_without_root_nothing_changes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    if os.geteuid() == 0:
        pytest.skip("runs as root")
    h = hard._harness("cursor", tmp_path, monkeypatch)
    h.target.write_text('{"mcpServers": {}}', encoding="utf-8")
    assert agents_core.load_json_or_fail_closed(h.target) == ({"mcpServers": {}}, None)


# --- V2-j: a '~' ca_file is offered and checked as the server resolves it ----------------


def test_v2j_a_tilde_ca_file_is_offered_and_checked_as_the_server_resolves_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    (home / "certs").mkdir(parents=True)
    ca = home / "certs" / "ca.pem"
    ca.write_text("-----BEGIN CERTIFICATE-----\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    cfg_dir = tmp_path / "cfg"
    cfg_dir.mkdir()
    cfg = cfg_dir / "config.yaml"
    cfg.write_text(
        "connections:\n  pg:\n    type: postgres\n    host: db\n    port: 5432\n    database: fin\n"
        "    username_env: PGUSER\n    tls:\n      enabled: true\n      ca_file: ~/certs/ca.pem\n",
        encoding="utf-8",
    )
    # The loader does not expand '~': the server looks under the config directory.
    served = str(cfg_dir / "~" / "certs" / "ca.pem")
    assert load_config(cfg).connections["pg"].tls.ca_file == served
    assert wizard._config_relative(cfg, "~/certs/ca.pem") == served

    # The prefilled default (what the server uses) is missing; a typed '~'
    # answer is checked as it is written: expanded, absolute.
    answers = iter(["2", "pg", "", "", "", "svc", "", "", "y", "~/certs/ca.pem", "n"])
    prompts: list[str] = []

    def fake_input(prompt: str = "") -> str:
        prompts.append(prompt)
        return next(answers)

    monkeypatch.setattr("builtins.input", fake_input)
    monkeypatch.setattr(wizard.getpass, "getpass", lambda prompt="": "pw")
    _name, connection, _test, _creds = wizard.collect_answers_interactive(cfg)
    assert connection.tls.enabled and connection.tls.ca_file == str(ca)
    assert any(served in prompt for prompt in prompts)


# --- V2-d: doctor sees an ACL that opens the audit log or the metadata cache -----------


def _state_config(tmp_path: Path, state: Path) -> Path:
    cfg = tmp_path / "c.yaml"
    cfg.write_text(
        f"application: {{audit_path: {state}/audit.jsonl, metadata_cache_path: {state}/meta.sqlite}}\n"
        "connections: {}\n",
        encoding="utf-8",
    )
    return cfg


@_DARWIN_ONLY
def test_v2d_doctor_reports_an_inherited_acl_on_the_audit_log_and_cache(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    _chmod_acl(state, "everyone allow read,file_inherit")
    for name in ("audit.jsonl", "audit.jsonl.1", "audit.jsonl.lock", "meta.sqlite"):
        fd = os.open(state / name, os.O_WRONLY | os.O_CREAT, 0o600)
        os.close(fd)
    checks = {c["check"]: c for c in run_doctor(str(_state_config(tmp_path, state)))["checks"]}
    audit = checks["audit-path-acl"]
    assert audit["status"] == "fatal", audit
    for name in ("audit.jsonl'", "audit.jsonl.1'", "audit.jsonl.lock'", "state':"):
        assert name in audit["detail"], audit
    assert checks["metadata-cache-acl"]["status"] == "fatal"


@_DARWIN_ONLY
def test_v2d_doctor_accepts_a_deny_only_acl_on_the_state_directory(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    _chmod_acl(state, "group:everyone deny delete")
    fd = os.open(state / "audit.jsonl", os.O_WRONLY | os.O_CREAT, 0o600)
    os.close(fd)
    names = {c["check"] for c in run_doctor(str(_state_config(tmp_path, state)))["checks"]}
    assert "audit-path-acl" not in names and "metadata-cache-acl" not in names
