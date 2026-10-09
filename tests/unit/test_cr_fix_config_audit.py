"""Config, audit-log and doctor regressions from the /code-review max pass
(findings A1, A2, X3, C1-C3, C5-C8 of that review).

Each section names the finding it pins.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import textwrap
import time
from pathlib import Path
from typing import Any

import pytest

from universal_db_mcp.config import ResolvedConnection, load_config, load_resolved
from universal_db_mcp.diagnostics.doctor import run_doctor
from universal_db_mcp.errors import ConfigError
from universal_db_mcp.services import audit as audit_module
from universal_db_mcp.services.audit import AuditLog, AuditWriteFailure

_POSIX_ONLY = pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode bits")
_MACOS_ONLY = pytest.mark.skipif(sys.platform != "darwin", reason="macOS extended ACLs (chmod +a)")

_THRESHOLD = 600


@pytest.fixture(autouse=True)
def _private_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)  # a Linux host's own would win over HOME
    monkeypatch.setenv("USERPROFILE", str(home))
    return home


def _yaml(tmp_path: Path, body: str, name: str = "c.yaml") -> Path:
    p = tmp_path / name
    p.write_text(textwrap.dedent(body), encoding="utf-8")
    return p


def _doctor_check(report: dict[str, Any], name: str) -> dict[str, Any]:
    checks = [c for c in report["checks"] if c["check"] == name]
    assert checks, f"doctor produced no '{name}' check: {[c['check'] for c in report['checks']]}"
    return checks[0]  # type: ignore[no-any-return]


# --- A1: a rotation that fails part-way never loses a generation ----------------


def _fill(path: Path, marker: str) -> None:
    lines = [json.dumps({"marker": marker})]
    while sum(len(x) + 1 for x in lines) < _THRESHOLD:
        lines.append(json.dumps({"pad": "x" * 80}))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _generations(path: Path) -> dict[str, str]:
    """{file name: first marker} of the live file, its backups and anything else
    rotation left beside it (the lock file aside)."""
    out: dict[str, str] = {}
    for f in sorted(path.parent.glob(f"{path.name}*")):
        if f.name.endswith(".lock"):
            continue
        first = json.loads(f.read_text(encoding="utf-8").splitlines()[0])
        out[f.name] = first.get("marker", first.get("event"))
    return out


def _full_chain(tmp_path: Path) -> Path:
    path = tmp_path / "audit.jsonl"
    _fill(path, "CUR")
    for n in range(1, 6):
        _fill(Path(f"{path}.{n}"), f"G{n}")
    return path


def _failing_replace(monkeypatch: pytest.MonkeyPatch, source: Path, failures: int) -> list[int]:
    """os.replace (and so Path.replace) refuses to move *source* the first
    *failures* times, as Windows does while a log reader holds the file open
    without FILE_SHARE_DELETE."""
    real = os.replace
    seen = [0]

    def replace(src: Any, dst: Any, *args: Any, **kwargs: Any) -> None:
        if os.fspath(src) == os.fspath(source) and seen[0] < failures:
            seen[0] += 1
            raise PermissionError(13, "being used by another process", os.fspath(src))
        real(src, dst, *args, **kwargs)

    monkeypatch.setattr(os, "replace", replace)
    return seen


def test_a1_a_live_file_that_cannot_be_moved_costs_no_generation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _full_chain(tmp_path)
    before = _generations(path)
    seen = _failing_replace(monkeypatch, path, failures=4)
    log = AuditLog(str(path), max_bytes=_THRESHOLD, max_backups=5, fail_closed=True)
    for _ in range(4):
        with pytest.raises(AuditWriteFailure):
            log.record({"event": "refused"})
        assert _generations(path) == before  # nothing moved, nothing lost
    assert seen[0] == 4
    log.record({"event": "x"})
    assert _generations(path) == {
        "audit.jsonl": "x", "audit.jsonl.1": "CUR", "audit.jsonl.2": "G1", "audit.jsonl.3": "G2",
        "audit.jsonl.4": "G3", "audit.jsonl.5": "G4",
    }


def test_a1_a_backup_that_cannot_be_moved_costs_only_the_oldest_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failure in the middle of the shift: every retry resumes where the
    last one stopped instead of shifting the whole chain again."""
    path = _full_chain(tmp_path)
    _failing_replace(monkeypatch, Path(f"{path}.3"), failures=3)
    log = AuditLog(str(path), max_bytes=_THRESHOLD, max_backups=5, fail_closed=True)
    for _ in range(3):
        with pytest.raises(AuditWriteFailure):
            log.record({"event": "refused"})
        kept = set(_generations(path).values())
        assert {"CUR", "G1", "G2", "G3", "G4"} <= kept, kept
    log.record({"event": "x"})
    assert _generations(path) == {
        "audit.jsonl": "x", "audit.jsonl.1": "CUR", "audit.jsonl.2": "G1", "audit.jsonl.3": "G2",
        "audit.jsonl.4": "G3", "audit.jsonl.5": "G4",
    }


def test_a1_a_hole_in_the_chain_takes_the_shift(tmp_path: Path) -> None:
    """A generation removed by an administrator is a free slot: the backups
    below it move down into it and the older ones stay where they are."""
    path = tmp_path / "audit.jsonl"
    _fill(path, "CUR")
    for n in (1, 2, 4, 5):
        _fill(Path(f"{path}.{n}"), f"G{n}")
    AuditLog(str(path), max_bytes=_THRESHOLD, max_backups=5, fail_closed=True).record({"event": "x"})
    assert _generations(path) == {
        "audit.jsonl": "x", "audit.jsonl.1": "CUR", "audit.jsonl.2": "G1", "audit.jsonl.3": "G2",
        "audit.jsonl.4": "G4", "audit.jsonl.5": "G5",
    }


def test_a1_the_rotation_staging_name_is_state_too(tmp_path: Path) -> None:
    """Rotation moves the log to <audit_path>.rotating first: no file the
    server reads may have that name."""
    audit = tmp_path / "aud.jsonl"
    pw = tmp_path / "aud.jsonl.rotating"
    pw.write_text("pw\n")
    pw.chmod(0o600)
    cfg = _yaml(
        tmp_path,
        f"application: {{audit_path: {audit}}}\n"
        "connections:\n"
        f"  pg: {{type: postgres, host: db.example, database: d, username_env: PGU, password_file: {pw}}}\n",
    )
    with pytest.raises(ConfigError, match="separate file"):
        load_config(cfg)


# --- A2: summaries written before an fsync failure are not written again ---------


def test_a2_an_fsync_failure_after_the_write_does_not_double_count(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(audit_module, "_COALESCE_WINDOW_SECONDS", 0.2)
    log = AuditLog(str(path), fail_closed=True)
    monkeypatch.setattr(log, "_flush_later", lambda: None)  # the summaries go with the next record
    event = {"event": "tool_call", "caller": "u", "action": "db_query", "outcome": "deny",
             "category": "VALIDATION", "connection_id": "c", "sql_fingerprint": "f"}
    for _ in range(13):  # 10 written in full, 3 counted
        log.record_refusal(dict(event))
    time.sleep(0.3)
    real_fsync = os.fsync

    def bad_fsync(fd: int) -> None:
        raise OSError(5, "Input/output error")

    monkeypatch.setattr(os, "fsync", bad_fsync)
    with pytest.raises(AuditWriteFailure):
        log.record({"event": "tool_call", "n": 1})
    monkeypatch.setattr(os, "fsync", real_fsync)
    log.record({"event": "tool_call", "n": 2})
    records = [json.loads(line) for line in path.read_text().splitlines()]
    counts = [r["count"] for r in records if r.get("event") == "tool_call_summary"]
    assert counts == [3], counts


def test_a2_a_failed_write_still_keeps_the_summaries(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The other side: when nothing reached the file the counts wait for the
    next record, as before."""
    path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(audit_module, "_COALESCE_WINDOW_SECONDS", 0.2)
    log = AuditLog(str(path), fail_closed=True)
    monkeypatch.setattr(log, "_flush_later", lambda: None)
    event = {"event": "tool_call", "caller": "u", "action": "db_query", "outcome": "deny",
             "category": "VALIDATION", "connection_id": "c", "sql_fingerprint": "f"}
    for _ in range(13):
        log.record_refusal(dict(event))
    time.sleep(0.3)
    real_write = os.write

    def bad_write(fd: int, data: Any) -> int:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(os, "write", bad_write)
    with pytest.raises(AuditWriteFailure):
        log.record({"event": "tool_call", "n": 1})
    monkeypatch.setattr(os, "write", real_write)
    log.record({"event": "tool_call", "n": 2})
    records = [json.loads(line) for line in path.read_text().splitlines()]
    assert [r["count"] for r in records if r.get("event") == "tool_call_summary"] == [3]


# --- X3: a loosened mode on the open log is tightened again ------------------------


@_POSIX_ONLY
def test_x3_a_chmod_644_on_the_live_log_is_undone_by_the_next_record(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(str(path), fail_closed=True)
    log.record({"event": "a"})
    path.chmod(0o644)
    log.record({"event": "b"})
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


# --- C1: a macOS extended ACL on a 0600 secret file -------------------------------


def _secret(tmp_path: Path, name: str = "pw", value: bytes = b"hunter2\n") -> Path:
    p = tmp_path / name
    p.write_bytes(value)
    p.chmod(0o600)
    return p


def _pg(tmp_path: Path, pw: Path) -> Path:
    return _yaml(
        tmp_path,
        f"application: {{audit_path: {tmp_path}/audit.jsonl}}\n"
        "connections:\n"
        f"  pg: {{type: postgres, host: db.example, database: d, username_env: PGU, password_file: {pw}}}\n",
    )


@pytest.fixture
def _chmod_acl() -> Any:
    """chmod +a, undone (chmod -N) after the test: a deny-delete entry would
    stop pytest from removing tmp_path."""
    touched: list[Path] = []

    def add(path: Path, entry: str) -> None:
        touched.append(path)
        subprocess.run(["/bin/chmod", "+a", entry, str(path)], check=True)  # noqa: S603 - fixed argv, tmp file

    yield add
    for path in touched:
        subprocess.run(["/bin/chmod", "-N", str(path)], check=False)  # noqa: S603 - fixed argv, tmp file


@_MACOS_ONLY
@pytest.mark.parametrize("entry", ["everyone allow read", "group:staff allow read", "everyone allow write"])
def test_c1_an_acl_granting_others_access_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, entry: str, _chmod_acl: Any
) -> None:
    monkeypatch.setenv("PGU", "reader")
    pw = _secret(tmp_path)
    _chmod_acl(pw, entry)
    assert stat.S_IMODE(pw.stat().st_mode) == 0o600
    with pytest.raises(ConfigError, match="access control list"):
        load_resolved(_pg(tmp_path, pw))
    check = _doctor_check(run_doctor(str(_pg(tmp_path, pw))), "connection-pg-secret-perms")
    assert check["status"] == "fatal" and "access control list" in check["detail"], check


@_MACOS_ONLY
def test_c1_deny_entries_and_the_owners_own_entry_are_accepted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, _chmod_acl: Any
) -> None:
    import getpass

    monkeypatch.setenv("PGU", "reader")
    pw = _secret(tmp_path)
    _chmod_acl(pw, "everyone deny delete")
    _chmod_acl(pw, f"user:{getpass.getuser()} allow read")
    _cfg, resolved = load_resolved(_pg(tmp_path, pw))
    assert resolved["pg"].password is not None and resolved["pg"].password.value == "hunter2"


# --- C2: a non-UTF-8 secret file never has a byte of it quoted ---------------------


def test_c2_a_non_utf8_secret_is_reported_without_its_bytes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PGU", "reader")
    pw = _secret(tmp_path, value=b"hunt\xe9r2\n")
    cfg = _pg(tmp_path, pw)
    with pytest.raises(ConfigError) as info:
        load_resolved(cfg)
    message = str(info.value)
    assert "UTF-8" in message and "0xe9" not in message and "position" not in message, message
    check = _doctor_check(run_doctor(str(cfg)), "connection-pg-secrets")
    assert check["status"] == "fatal", check
    assert "UTF-8" in check["detail"] and "0xe9" not in check["detail"] and "position" not in check["detail"]


def test_c2_a_non_utf8_wallet_password_file_is_reported_without_its_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("U", "reader")
    monkeypatch.setenv("P", "pw")
    wpw = _secret(tmp_path, "wallet.pw", b"\xffsecret\n")
    conn = load_config(
        _yaml(
            tmp_path,
            f"application: {{audit_path: {tmp_path}/audit.jsonl}}\n"
            "connections:\n"
            f"  ora: {{type: oracle, host: db.example, database: ORCL, username_env: U, password_env: P,\n"
            f"         options: {{wallet_password_file: {wpw}}}}}\n",
        )
    ).connections["ora"]
    with pytest.raises(ConfigError) as info:
        ResolvedConnection("ora", conn)
    assert "UTF-8" in str(info.value) and "0xff" not in str(info.value)


# --- C3: doctor --connectivity with a host IDNA cannot encode -----------------------


@pytest.mark.parametrize("host", ["db..example.com", "a" * 64 + ".example.com"])
def test_c3_connectivity_reports_an_unencodable_host(tmp_path: Path, host: str) -> None:
    cfg = _yaml(
        tmp_path,
        f"application: {{audit_path: {tmp_path}/audit.jsonl}}\n"
        "connections:\n"
        f"  pg: {{type: postgres, host: '{host}', database: d, username_env: PGU, password_env: PGP,"
        " connect_timeout_seconds: 1}\n",
    )
    check = _doctor_check(run_doctor(str(cfg), connectivity=True), "connection-pg-reachable")
    assert check["status"] == "fatal" and host in check["detail"], check


# --- C5: an existing state file in a directory the server cannot write ------------


@_POSIX_ONLY
@pytest.mark.parametrize("label", ["audit-path", "metadata-cache-path"])
def test_c5_doctor_checks_the_directory_of_an_existing_state_file(tmp_path: Path, label: str) -> None:
    import sqlite3

    state = tmp_path / "state"
    state.mkdir()
    audit = state / "audit.jsonl"
    cache = state / "cache.sqlite"
    audit.write_text("")
    audit.chmod(0o600)
    Path(f"{audit}.lock").write_text("")
    Path(f"{audit}.lock").chmod(0o600)
    sqlite3.connect(cache).close()
    cache.chmod(0o600)
    if label == "audit-path":
        cfg = _yaml(tmp_path, f"application: {{audit_path: {audit}}}\n")
    else:
        other = tmp_path / "audit.jsonl"
        cfg = _yaml(tmp_path, f"application: {{audit_path: {other}, metadata_cache_path: {cache}}}\n")
    state.chmod(0o500)
    try:
        if os.access(state, os.W_OK):
            pytest.skip("running with privileges that ignore directory modes")
        check = _doctor_check(run_doctor(str(cfg)), label)
    finally:
        state.chmod(0o700)
    assert check["status"] == "fatal", check
    assert str(state) in check["detail"] and "directory" in check["detail"], check


# --- C6: a '~' SQLite path is the same file as an absolute one ---------------------


def test_c6_a_tilde_sqlite_path_cannot_share_the_cache_file(tmp_path: Path, _private_home: Path) -> None:
    data = _private_home / "data"
    data.mkdir()
    cfg = _yaml(
        tmp_path,
        f"application: {{audit_path: {tmp_path}/audit.jsonl, metadata_cache_path: {data}/app.db}}\n"
        "connections:\n"
        "  lite: {type: sqlite, database: ~/data/app.db}\n",
    )
    with pytest.raises(ConfigError, match="separate file"):
        load_config(cfg)


def test_c6_doctor_finds_a_tilde_sqlite_file(tmp_path: Path, _private_home: Path) -> None:
    import sqlite3

    sqlite3.connect(_private_home / "app.db").close()
    cfg = _yaml(
        tmp_path,
        f"application: {{audit_path: {tmp_path}/audit.jsonl}}\n"
        "connections:\n"
        "  lite: {type: sqlite, database: ~/app.db}\n",
    )
    check = _doctor_check(run_doctor(str(cfg)), "connection-lite-file")
    assert check["status"] == "ok", check


# --- C7: every environment-sourced secret is named -------------------------------


def test_c7_the_wallet_password_env_is_an_environment_secret(tmp_path: Path) -> None:
    conn = load_config(
        _yaml(
            tmp_path,
            f"application: {{audit_path: {tmp_path}/audit.jsonl}}\n"
            "connections:\n"
            "  ora: {type: oracle, host: db.example, database: ORCL, username_env: U, password_env: P,\n"
            "        options: {wallet_password_env: ORA_WALLET_PW}}\n",
        )
    ).connections["ora"]
    assert conn.secret_env_variables() == ["U", "P", "ORA_WALLET_PW"]


# --- C8: the shipped template says which paths follow the file -------------------


def test_c8_the_example_config_does_not_promise_every_relative_path_follows_it() -> None:
    text = (Path(__file__).resolve().parents[2] / "config.example.yaml").read_text(encoding="utf-8")
    header = text.split("application:", 1)[0]
    assert "Relative paths resolve against this file's directory" not in " ".join(header.split())
    assert "sqlite" in header.lower() and "working directory" in " ".join(header.split())
