"""Third code review, state files and CLI: the macOS audit/cache ACL rules
(the state directory's inheritable entries, the delete/writeattr rights, a
read-only directory ACL), a symlinked or briefly unopenable cache directory,
YAML loader errors that quote a value, read_config_bytes' path walk, the dsh
registration's own config, and the ClickHouse memory options."""

from __future__ import annotations

import errno
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import test_hardening_2026_09_27_agents as hard  # noqa: E402

from universal_db_mcp import wizard  # noqa: E402
from universal_db_mcp.__main__ import main  # noqa: E402
from universal_db_mcp.agents import core as agents_core
from universal_db_mcp.agents import dsh
from universal_db_mcp.agents.core import load_yaml_or_fail_closed
from universal_db_mcp.config import (
    ConfigError,
    ConnectionConfig,
    darwin_state_file_acl_problems,
    load_config,
    load_yaml_strict,
)
from universal_db_mcp.diagnostics import doctor
from universal_db_mcp.services import audit as audit_module
from universal_db_mcp.services import metadata as metadata_module
from universal_db_mcp.services.metadata import MetadataCache, cache_file_problems

# --- ClickHouse memory options (connectors owner decision) ------------------


def _clickhouse(**options: object) -> ConnectionConfig:
    return ConnectionConfig.model_validate(
        {
            "type": "clickhouse",
            "host": "127.0.0.1",
            "port": 8123,
            "database": "default",
            "username_env": "CH_USER",
            "options": options,
        }
    )


def test_clickhouse_max_memory_usage_accepts_a_byte_count() -> None:
    assert _clickhouse(max_memory_usage=4 * 1024**3).options["max_memory_usage"] == 4 * 1024**3
    assert _clickhouse(max_memory_usage=1024 * 1024).options["max_memory_usage"] == 1024 * 1024


@pytest.mark.parametrize("value", [0, -1, 1024 * 1024 - 1, True, False, "2G", 2.5])
def test_clickhouse_max_memory_usage_refuses_non_byte_counts(value: object) -> None:
    with pytest.raises(ValueError, match="max_memory_usage"):
        _clickhouse(max_memory_usage=value)


def test_clickhouse_memory_limit_from_profile_is_a_bool() -> None:
    assert _clickhouse(memory_limit_from_profile=True).options["memory_limit_from_profile"] is True
    assert _clickhouse(memory_limit_from_profile=False).options["memory_limit_from_profile"] is False
    with pytest.raises(ValueError, match="memory_limit_from_profile"):
        _clickhouse(memory_limit_from_profile="yes")


# --- macOS state-file ACLs (FINAL #10, notes: delete/writeattr) -------------

darwin_only = pytest.mark.skipif(sys.platform != "darwin", reason="macOS extended ACLs (chmod +a)")
_ACLED: list[Path] = []


def _acl(path: Path, entry: str) -> None:
    subprocess.run(["/bin/chmod", "+a", entry, str(path)], check=True, capture_output=True)  # noqa: S603
    _ACLED.append(path)


@pytest.fixture(autouse=True)
def _strip_acls():  # type: ignore[no-untyped-def]
    yield
    while _ACLED:
        target = _ACLED.pop()
        if target.is_dir():
            for child in target.iterdir():
                subprocess.run(["/bin/chmod", "-N", str(child)], check=False, capture_output=True)  # noqa: S603
        subprocess.run(["/bin/chmod", "-N", str(target)], check=False, capture_output=True)  # noqa: S603


def _state(tmp_path: Path) -> Path:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    return state


def _open(path: Path) -> int:
    return audit_module._open_state_file(path, os.O_RDWR | os.O_APPEND)


def _remedy(exc: OSError) -> list[str]:
    match = re.search(r"chmod -N (.*)$", exc.strerror or "")
    assert match, exc.strerror
    return shlex.split(match.group(1))


@darwin_only
def test_an_inheritable_state_directory_entry_is_refused_naming_the_directory(tmp_path: Path) -> None:
    state = _state(tmp_path)
    _acl(state, "everyone allow read,file_inherit")
    with pytest.raises(OSError) as info:
        _open(state / "audit.jsonl")
    assert "inheritable" in str(info.value)
    names = _remedy(info.value)
    assert names[0] == str(state), names  # the directory first
    assert str(state / "audit.jsonl") in names  # the file that already inherited it


@darwin_only
def test_one_named_chmod_clears_every_audit_file_and_rotation_stays_clean(tmp_path: Path) -> None:
    state = _state(tmp_path)
    _acl(state, "everyone allow read,file_inherit")
    for name in ("audit.jsonl", "audit.jsonl.lock", "audit.jsonl.1"):
        (state / name).write_text("")  # each inherits the entry
    log = audit_module.AuditLog(str(state / "audit.jsonl"), max_bytes=300, max_backups=2, fail_closed=True)
    with pytest.raises(audit_module.AuditWriteFailure) as info:
        log.record({"tool": "db_query", "sql": "SELECT 1"})
    cause = info.value.__cause__
    assert isinstance(cause, OSError)
    names = _remedy(cause)
    assert set(names) == {str(state), *(str(state / n) for n in ("audit.jsonl", "audit.jsonl.lock", "audit.jsonl.1"))}
    subprocess.run(["/bin/chmod", "-N", *names], check=True, capture_output=True)  # noqa: S603
    for i in range(30):  # several rotations: every new log is created clean
        log.record({"tool": "db_query", "sql": f"SELECT {i}"})
    assert (state / "audit.jsonl.2").exists()
    for member in state.iterdir():
        assert darwin_state_file_acl_problems(member) == [], member


@darwin_only
@pytest.mark.parametrize("rights", ["delete", "writeattr", "writeextattr", "writesecurity"])
def test_an_audit_log_others_may_delete_or_alter_is_refused(tmp_path: Path, rights: str) -> None:
    log = _state(tmp_path) / "audit.jsonl"
    log.write_text("")
    log.chmod(0o600)
    _acl(log, f"everyone allow {rights}")
    with pytest.raises(OSError, match=rights) as info:
        _open(log)
    assert _remedy(info.value) == [str(log)]
    assert cache_file_problems(log, owner_uid=None)  # the same rule for a cache file


@darwin_only
@pytest.mark.parametrize("rights", ["add_file", "delete_child", "add_subdirectory", "writesecurity", "chown"])
def test_a_state_directory_others_may_change_is_refused(tmp_path: Path, rights: str) -> None:
    state = _state(tmp_path)
    _acl(state, f"everyone allow {rights}")
    with pytest.raises(OSError, match=rights):
        _open(state / "audit.jsonl")
    assert any(rights in p for p in cache_file_problems(state / "cache.sqlite", owner_uid=None))


@darwin_only
def test_a_read_only_state_directory_entry_is_accepted(tmp_path: Path) -> None:
    """'list,search' is what mode 0750 grants the group: names, not contents."""
    state = _state(tmp_path)
    _acl(state, "everyone allow list,search,readattr,readextattr,readsecurity")
    os.close(_open(state / "audit.jsonl"))
    assert cache_file_problems(state / "cache.sqlite", owner_uid=None) == []
    cache = MetadataCache(str(state / "cache.sqlite"))
    assert cache._path is not None
    cache.put_tables("c", "fp", [])
    assert cache.get_tables("c", "fp") == []
    assert doctor._state_acl_problems(state / "audit.jsonl") == []


@darwin_only
def test_a_state_directory_this_account_may_not_list_is_still_checked(tmp_path: Path) -> None:
    state = _state(tmp_path)
    state.chmod(0o300)  # search and write, no read: its ACL is read by name
    try:
        os.close(_open(state / "audit.jsonl"))
        _acl(state, "everyone allow read,file_inherit")
        with pytest.raises(OSError, match="inheritable") as info:
            _open(state / "audit.log")
        assert _remedy(info.value)[0] == str(state)
    finally:
        state.chmod(0o700)


@darwin_only
def test_doctor_names_the_directory_and_each_file_in_one_command(tmp_path: Path) -> None:
    state = _state(tmp_path)
    _acl(state, "everyone allow read,file_inherit")
    (state / "audit.jsonl").write_text("")
    findings = doctor._state_acl_findings(state / "audit.jsonl")
    assert [name for name, _p in findings] == [state, state / "audit.jsonl"]


# --- metadata cache directory (FINAL #12) -----------------------------------


def test_a_cache_reached_through_a_symlinked_directory_is_trusted(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    (tmp_path / "link").symlink_to(real)
    path = tmp_path / "link" / "cache.sqlite"
    assert cache_file_problems(path, owner_uid=os.geteuid()) == []
    cache = MetadataCache(str(path))
    assert cache._path is not None
    cache.put_tables("c", "fp", [])
    assert cache.get_tables("c", "fp") == []


@darwin_only
def test_a_transient_error_inspecting_the_cache_directory_is_a_miss_not_a_shutdown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _state(tmp_path)
    cache = MetadataCache(str(state / "cache.sqlite"))
    cache.put_tables("c", "fp", [])
    real_open = os.open
    fail = {"left": 1}

    def flaky_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        if Path(path) == state and fail["left"]:
            fail["left"] -= 1
            raise OSError(errno.EMFILE, "Too many open files")
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(metadata_module.os, "open", flaky_open)
    assert cache.get_tables("c", "fp") is None  # no answer now: a miss
    assert cache._path is not None  # ...but the cache stays on
    assert cache.get_tables("c", "fp") == []
    monkeypatch.setattr(metadata_module.os, "open", real_open)
    fail["left"] = 1
    monkeypatch.setattr(metadata_module.os, "open", flaky_open)
    with pytest.raises(metadata_module.TransientCacheCheckError):
        cache_file_problems(state / "cache.sqlite", owner_uid=None)


# --- YAML loader errors that quote a value (notes: config.py:1263) ----------

_TAGGED = {
    "int": "connections:\n  pg:\n    password: !!int Hunter2Secret\n",
    "float": "x: !!float Hunter2Secret\n",
    "bool": "x: !!bool Hunter2Secret\n",
    "timestamp": "x: !!timestamp Hunter2Secret\n",
    "int key": "? !!int Hunter2Secret\n: 1\n",
}


@pytest.mark.parametrize("doc", list(_TAGGED.values()), ids=list(_TAGGED))
def test_a_tagged_value_that_fails_to_convert_is_described_without_it(doc: str, tmp_path: Path) -> None:
    with pytest.raises(ConfigError) as info:
        load_yaml_strict(doc, "f.yaml")
    message = str(info.value)
    assert "hunter2" not in message.lower(), message
    assert "line " in message and "tag" in message, message
    cfg = tmp_path / "config.yaml"
    cfg.write_text("application: {}\n" + doc)
    cfg.chmod(0o600)
    with pytest.raises(ConfigError) as info:
        load_config(cfg)
    assert "hunter2" not in str(info.value).lower()


def test_harness_yaml_readers_describe_a_tagged_value_without_it(tmp_path: Path) -> None:
    harness = tmp_path / "patch.yml"
    harness.write_text("- id: other\n  token: !!int Hunter2Secret\n")
    data, reason = load_yaml_or_fail_closed(harness)
    assert data is None and reason and "hunter2" not in reason.lower(), reason
    data, reason = dsh._load_patch(harness)
    assert data is None and reason and "hunter2" not in reason.lower(), reason
    cfg = tmp_path / "config.yaml"
    cfg.write_text("connections:\n  pg:\n    type: postgres\n    port: !!int Hunter2Secret\n")
    assert wizard._existing_block(cfg, "pg", "postgres") == {}


# --- read_config_bytes as root: an intermediate directory swapped (core.py:905)

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX root semantics")


def _root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 0)


def _root_owned_dir() -> Path:
    for candidate in (Path("/private/etc"), Path("/etc")):
        if candidate.is_dir() and not candidate.is_symlink() and candidate.stat().st_uid == 0:
            return candidate
    pytest.skip("no root-owned /etc")


@posix_only
def test_as_root_an_intermediate_directory_swapped_for_a_link_after_the_checks_is_not_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    (home / "sub").mkdir(parents=True)
    target = home / "sub" / "hosts"
    target.write_text("the user's own file\n")
    etc = _root_owned_dir()
    if not (etc / "hosts").is_file():
        pytest.skip("no /etc/hosts")
    _root(monkeypatch)
    checked = agents_core.refuse_foreign_read

    def racing_checks(path: Path) -> None:
        checked(path)  # every check passes: sub is the user's own directory
        os.rename(home / "sub", home / "sub.real")
        os.symlink(etc, home / "sub")  # ...then the user swaps it for a link to a root-owned one

    monkeypatch.setattr(agents_core, "refuse_foreign_read", racing_checks)
    with pytest.raises(PermissionError, match="symlink owned by uid"):
        agents_core.read_config_bytes(target)


@posix_only
def test_as_root_ordinary_paths_still_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    real = tmp_path / "dotfiles" / "cursor"
    real.mkdir(parents=True)
    (real / "mcp.json").write_text("{}")
    (tmp_path / "linked").symlink_to(real)  # the user's own link to their own directory
    (tmp_path / "rel").symlink_to("dotfiles/cursor/mcp.json")
    _root(monkeypatch)
    assert agents_core.read_config_bytes(real / "mcp.json") == b"{}"
    assert agents_core.read_config_bytes(tmp_path / "linked" / "mcp.json") == b"{}"
    assert agents_core.read_config_bytes(tmp_path / "rel") == b"{}"
    assert agents_core.read_config_bytes(tmp_path / "linked" / ".." / "dotfiles" / "cursor" / "mcp.json") == b"{}"
    if Path("/var").is_symlink():  # macOS: a root-owned link (/var -> private/var) is followed as before
        via_var = Path("/var") / real.relative_to("/private/var") if str(real).startswith("/private/var/") else None
        if via_var is not None:
            assert agents_core.read_config_bytes(via_var / "mcp.json") == b"{}"


@posix_only
def test_as_root_a_link_loop_and_a_missing_file_fail_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "a").symlink_to("b")
    (tmp_path / "b").symlink_to("a")
    _root(monkeypatch)
    with pytest.raises(OSError):
        agents_core.read_config_bytes(tmp_path / "a")
    with pytest.raises(FileNotFoundError):
        agents_core.read_config_bytes(tmp_path / "missing.json")


# --- dsh: only the config the registration names is seeded or asked about ---


def _dsh_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    (home / ".dsh").mkdir(parents=True)
    (home / ".dsh" / "settings.yaml").write_text("")  # a dsh home
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)  # a Linux host's own would win over HOME
    monkeypatch.setenv("PATH", "")
    monkeypatch.delenv("UDBMCP_CONFIG", raising=False)
    monkeypatch.setenv("UDBMCP_VENV_PYTHON", hard.FAKE_PYTHON)
    monkeypatch.setattr(agents_core, "SYSTEM_CONFIG_PATH", tmp_path / "no-such-etc" / "config.yaml")
    return home


@posix_only
@pytest.mark.parametrize("flags", [[], ["--json"], ["--yes"], ["--json", "--yes"]])
def test_a_dsh_registration_naming_another_config_is_not_reported_missing(
    flags: list[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    home = _dsh_home(tmp_path, monkeypatch)
    team = tmp_path / "team" / "config.yaml"
    team.parent.mkdir()
    team.write_text("application:\n  transport: stdio\n")
    team.chmod(0o600)
    monkeypatch.setenv("UDBMCP_CONFIG", str(team))
    assert main(["configure-agents", "--agent", "dsh", "--yes"]) == 0
    assert str(team) in (home / ".dsh" / dsh.PATCH_FILENAME).read_text()
    capsys.readouterr()

    monkeypatch.delenv("UDBMCP_CONFIG")  # a later run, from a shell without the override
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    assert main(["configure-agents", "--agent", "dsh", *flags]) == 0
    out = capsys.readouterr()
    assert "NOT CONFIRMED" not in out.out + out.err
    assert "config_missing" not in out.out
    assert not (home / ".universal-db-mcp").exists()  # nothing seeded the registration does not use


@posix_only
def test_a_dsh_registration_naming_the_per_user_config_still_gets_it_seeded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    home = _dsh_home(tmp_path, monkeypatch)
    # the installed case (not this checkout's own config): the per-user config
    monkeypatch.setattr(dsh, "_resolve_config_path", lambda: str(home / ".universal-db-mcp" / "config.yaml"))
    assert main(["configure-agents", "--agent", "dsh", "--yes"]) == 0
    per_user = home / ".universal-db-mcp" / "config.yaml"
    assert per_user.is_file()
    per_user.unlink()  # as a seeding that failed after the write leaves it
    other = tmp_path / "other.yaml"
    other.write_text("application:\n  transport: stdio\n")
    monkeypatch.setenv("UDBMCP_CONFIG", str(other))  # this run would advertise another config
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    capsys.readouterr()
    assert main(["configure-agents", "--agent", "dsh"]) == 1
    assert "NOT CONFIRMED" in capsys.readouterr().out
    assert main(["configure-agents", "--agent", "dsh", "--yes"]) == 0
    assert per_user.is_file()  # the config the registration names
