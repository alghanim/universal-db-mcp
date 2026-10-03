"""Config, audit-log and metadata-cache regressions from the 2026-09-27
security/production review.

Each section names the finding it pins. The multi-process audit tests use the
spawn start method: every worker builds its own AuditLog on one shared path,
exactly like separate stdio server processes spawned by different MCP clients
from one per-user config. Sizes are small so a run stays well under 20 s.
"""

from __future__ import annotations

import errno
import hashlib
import json
import multiprocessing as mp
import os
import sqlite3
import stat
import sys
import textwrap
import time
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

from universal_db_mcp.config import load_config
from universal_db_mcp.connectors.base import TableSummary
from universal_db_mcp.diagnostics.doctor import run_doctor
from universal_db_mcp.errors import ConfigError
from universal_db_mcp.services import metadata
from universal_db_mcp.services.audit import AuditLog, AuditWriteFailure
from universal_db_mcp.services.metadata import MetadataCache

_POSIX_ONLY = pytest.mark.skipif(sys.platform == "win32", reason="POSIX owner/mode and rlimit semantics")


def _audit_lines(path: Path) -> list[str]:
    """Every line of the live audit file and its numbered backups."""
    files = [path] + [Path(f"{path}.{n}") for n in _backup_numbers(path)]
    lines: list[str] = []
    for f in files:
        if f.exists():
            lines.extend(f.read_text(encoding="utf-8").splitlines())
    return lines


def _backup_numbers(path: Path) -> list[int]:
    suffixes = (p.name[len(path.name) + 1 :] for p in path.parent.glob(f"{path.name}.*"))
    return sorted(int(s) for s in suffixes if s.isdigit())


def _doctor_check(report: dict[str, Any], name: str) -> dict[str, Any]:
    checks = [c for c in report["checks"] if c["check"] == name]
    assert checks, f"doctor produced no '{name}' check: {[c['check'] for c in report['checks']]}"
    return checks[0]  # type: ignore[no-any-return]


@pytest.fixture(autouse=True)
def _private_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A config without audit_path now audits under ~/.universal-db-mcp; no
    test in this file may reach the real home directory."""
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    return home


# --- F24: audit rotation is serialized across processes ---------------------


def _concurrent_writer(path: str, worker: int, count: int, start: Any, out: Any) -> None:
    log = AuditLog(path, max_bytes=2000, max_backups=500, fail_closed=True)
    failures: list[str] = []
    start.wait()
    for i in range(count):
        try:
            log.record({"event": "tool_call", "worker": worker, "i": i})
        except AuditWriteFailure as exc:
            failures.append(str(exc)[-160:])
    out.put((worker, failures))


def test_f24_processes_sharing_one_audit_path_lose_and_refuse_nothing(tmp_path: Path) -> None:
    """Four processes, each with its own AuditLog on one path, write 200
    tagged records through many rotations: no write is refused, every record
    appears exactly once, and the backups are numbered .1..k without holes."""
    path = tmp_path / "audit.jsonl"
    workers, per_worker = 4, 200
    ctx = mp.get_context("spawn")
    start = ctx.Barrier(workers)
    out = ctx.Queue()
    procs = [
        ctx.Process(target=_concurrent_writer, args=(str(path), w, per_worker, start, out))
        for w in range(workers)
    ]
    for p in procs:
        p.start()
    results = dict(out.get(timeout=120) for _ in procs)
    for p in procs:
        p.join(timeout=30)

    assert {w: f for w, f in results.items() if f} == {}, "audit writes refused under fail-closed"
    seen = Counter((r["worker"], r["i"]) for r in map(json.loads, _audit_lines(path)))
    expected = {(w, i): 1 for w in range(workers) for i in range(per_worker)}
    assert {k: n for k, n in seen.items() if n != 1} == {}, "records duplicated"
    assert set(expected) - set(seen) == set(), "acknowledged records missing"
    backups = _backup_numbers(path)
    assert backups and backups == list(range(1, len(backups) + 1)), backups


_THRESHOLD_BYTES = 2000


def _fill_generation(path: Path, marker: str) -> None:
    lines = [json.dumps({"marker": marker})]
    while sum(len(x) + 1 for x in lines) < _THRESHOLD_BYTES:
        lines.append(json.dumps({"pad": "x" * 80}))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _threshold_worker(path: str, tag: str, gate: Any, out: Any, trials: int) -> None:
    log = AuditLog(path, max_bytes=_THRESHOLD_BYTES, fail_closed=True)  # default max_backups=5
    for trial in range(trials):
        gate.wait()
        try:
            log.record({"event": "tool_call", "request_id": f"{tag}-{trial}"})
            out.put((tag, trial, "ok"))
        except AuditWriteFailure as exc:
            out.put((tag, trial, f"refused: {exc}"))


def test_f24_two_processes_at_the_rotation_threshold_keep_every_generation(tmp_path: Path) -> None:
    """The live file sits at max_bytes with generations G1..G5 behind it; two
    processes record once each at the same moment. Exactly one rotation must
    happen (.1=CUR, .2..5=G1..G4), both records land, nothing is refused."""
    path = tmp_path / "audit.jsonl"
    trials = 30
    ctx = mp.get_context("spawn")
    gate = ctx.Barrier(3)
    out = ctx.Queue()
    procs = [ctx.Process(target=_threshold_worker, args=(str(path), tag, gate, out, trials)) for tag in "ab"]
    for p in procs:
        p.start()
    defects: list[str] = []
    try:
        for trial in range(trials):
            for f in [path] + [Path(f"{path}.{n}") for n in _backup_numbers(path)]:
                f.unlink(missing_ok=True)
            _fill_generation(path, "CUR")
            for i in range(1, 6):
                _fill_generation(Path(f"{path}.{i}"), f"G{i}")
            gate.wait(timeout=60)
            outcomes = [out.get(timeout=60) for _ in procs]
            refused = [o for o in outcomes if o[2] != "ok"]
            markers = {
                n: json.loads(Path(f"{path}.{n}").read_text(encoding="utf-8").splitlines()[0]).get("marker")
                for n in _backup_numbers(path)
            }
            live = {json.loads(x).get("request_id") for x in path.read_text(encoding="utf-8").splitlines()}
            if (
                refused
                or markers != {1: "CUR", 2: "G1", 3: "G2", 4: "G3", 5: "G4"}
                or {f"a-{trial}", f"b-{trial}"} - live
            ):
                defects.append(f"trial {trial}: refused={refused} generations={markers} live={sorted(map(str, live))}")
    finally:
        for p in procs:
            p.join(timeout=30)
            if p.is_alive():
                p.kill()
    assert defects == [], defects[:3]


def test_f24_a_hole_in_the_backup_chain_is_not_an_audit_failure(tmp_path: Path) -> None:
    """A backup removed by an administrator (ENOENT mid-chain) is a free
    slot: the backups below it shift into it, the older ones stay where they
    are (no generation is dropped), and the record is written."""
    path = tmp_path / "audit.jsonl"
    _fill_generation(path, "CUR")
    _fill_generation(Path(f"{path}.1"), "G1")
    _fill_generation(Path(f"{path}.3"), "G3")
    AuditLog(str(path), max_bytes=_THRESHOLD_BYTES, max_backups=5, fail_closed=True).record({"event": "x"})
    firsts = {n: json.loads(Path(f"{path}.{n}").read_text().splitlines()[0])["marker"] for n in _backup_numbers(path)}
    assert firsts == {1: "CUR", 2: "G1", 3: "G3"}
    assert json.loads(path.read_text())["event"] == "x"


def test_f24_a_directory_at_the_audit_path_fails_closed_and_is_not_rotated(tmp_path: Path) -> None:
    """EISDIR must still fail closed: rotation only ever moves a regular file,
    so a directory at the path is never renamed away for a fresh log."""
    target = tmp_path / "audit.jsonl"
    target.mkdir()
    with pytest.raises(AuditWriteFailure):
        AuditLog(str(target), max_bytes=1, fail_closed=True).record({"event": "x"})
    assert target.is_dir()
    assert _backup_numbers(target) == []


@_POSIX_ONLY
def test_f24_lock_sidecar_is_private_and_never_follows_a_symlink(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    old_umask = os.umask(0o022)
    try:
        AuditLog(str(path), fail_closed=True).record({"event": "x"})
    finally:
        os.umask(old_umask)
    lock = Path(f"{path}.lock")
    assert stat.S_IMODE(lock.stat().st_mode) == 0o600
    assert lock.read_bytes() == b""  # the lock file never carries data

    planted = tmp_path / "planted.jsonl"
    victim = tmp_path / "victim"
    victim.write_text("keep")
    Path(f"{planted}.lock").symlink_to(victim)
    with pytest.raises(AuditWriteFailure):
        AuditLog(str(planted), fail_closed=True).record({"event": "x"})
    assert victim.read_text() == "keep"


def test_f24_lock_sidecar_is_a_state_path_for_the_overlap_validator(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    cfg = tmp_path / "c.yaml"
    cfg.write_text(f"application:\n  audit_path: {audit}\n  metadata_cache_path: {audit}.lock\n")
    with pytest.raises(ConfigError, match="separate file"):
        load_config(cfg)


@_POSIX_ONLY
def test_f24_doctor_probes_the_lock_sidecar(tmp_path: Path) -> None:
    """An existing writable audit file in a directory where the lock sidecar
    cannot be created would refuse every audited call; doctor says so."""
    state = tmp_path / "state"
    state.mkdir()
    audit = state / "audit.jsonl"
    audit.write_text("")
    audit.chmod(0o600)
    cfg = tmp_path / "c.yaml"
    cfg.write_text(f"application:\n  audit_path: {audit}\n")
    state.chmod(0o500)
    try:
        if os.access(state, os.W_OK):
            pytest.skip("running with privileges that ignore directory modes")
        check = _doctor_check(run_doctor(str(cfg)), "audit-path")
    finally:
        state.chmod(0o700)
    assert check["status"] == "fatal", check
    assert ".lock" in check["detail"]


# --- F71: a partial write never corrupts the next record; lines are capped ----


def _fsize_child(path: str, out: Any) -> None:
    import resource
    import signal

    signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
    log = AuditLog(path, fail_closed=True)
    log.record({"event": "first", "n": 1})
    soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
    resource.setrlimit(resource.RLIMIT_FSIZE, (os.path.getsize(path) + 20, hard))
    try:
        log.record({"event": "second-record-that-does-not-fit", "pad": "x" * 200})
        outcome = "accepted"
    except AuditWriteFailure:
        outcome = "refused"
    finally:
        resource.setrlimit(resource.RLIMIT_FSIZE, (soft, hard))
    log.record({"event": "third", "n": 3})
    out.put(outcome)


@_POSIX_ONLY
def test_f71_short_write_is_refused_and_leaves_no_fragment(tmp_path: Path) -> None:
    """RLIMIT_FSIZE cuts a record short (the disk-full shape): the record is
    refused, and after recovery every line in the file is valid JSON."""
    path = tmp_path / "audit.jsonl"
    ctx = mp.get_context("spawn")
    out = ctx.Queue()
    proc = ctx.Process(target=_fsize_child, args=(str(path), out))
    proc.start()
    outcome = out.get(timeout=60)
    proc.join(timeout=30)
    assert outcome == "refused"
    events = [json.loads(line)["event"] for line in path.read_text(encoding="utf-8").splitlines()]
    assert events == ["first", "third"]


def test_f71_fragment_left_by_a_dead_writer_does_not_swallow_the_next_record(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_text('{"ts":"2026-09-27T10:00:00+0000","event":"fir', encoding="utf-8")
    AuditLog(str(path), fail_closed=True).record({"event": "next"})
    last = path.read_text(encoding="utf-8").splitlines()[-1]
    assert json.loads(last)["event"] == "next"


def test_f71_oversized_record_is_capped_with_a_digest_marker(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    big = "SELECT " + "x" * 1_000_000
    AuditLog(str(path), fail_closed=True).record(
        {"event": "tool_call", "request_id": "r-1", "outcome": "ok", "sql_text": big}
    )
    raw = path.read_bytes()
    assert len(raw) <= 128 * 1024
    rec = json.loads(raw)
    assert rec["request_id"] == "r-1" and rec["outcome"] == "ok"
    # the text keeps its ends (review round 2 of wave 4); the whole is named by its digest
    head, tail = rec["sql_text"], rec["sql_text_tail"]
    assert head.startswith("SELECT x") and big.startswith(head) and big.endswith(tail)
    assert rec["sql_text_omitted"] == {
        "reason": "longer than one record holds (128 KiB)", "chars": len(big) - len(head) - len(tail),
        "sha256": hashlib.sha256(big.encode("utf-8")).hexdigest(), "len": len(big),
    }


def test_f71_record_with_many_small_values_is_still_capped(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    AuditLog(str(path), fail_closed=True).record(
        {"event": "tool_call", "request_id": "r-2", "warnings": [f"w{i}" for i in range(100_000)]}
    )
    raw = path.read_bytes()
    assert len(raw) <= 128 * 1024
    rec = json.loads(raw)
    assert rec["request_id"] == "r-2" and rec["event"] == "tool_call"
    assert set(rec["oversized_record"]) == {"sha256", "len"}


@_POSIX_ONLY
def test_f71_descriptors_are_reused_across_records_and_released(tmp_path: Path) -> None:
    """Descriptors do not pile up across records (rotations included) and are
    released with the AuditLog. That they are reused rather than reopened is
    pinned by test_f71_log_and_lock_are_opened_once_across_records."""

    def open_fds() -> int:
        return len(os.listdir("/dev/fd"))

    before = open_fds()
    log = AuditLog(str(tmp_path / "audit.jsonl"), max_bytes=500, fail_closed=True)
    for i in range(50):
        log.record({"event": "tool_call", "i": i})
    assert _backup_numbers(tmp_path / "audit.jsonl")  # rotated at least once
    assert open_fds() - before <= 2
    del log
    assert open_fds() == before


def test_f71_normal_records_are_unchanged(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(str(path), fail_closed=True)
    for i in range(3):
        log.record({"event": "tool_call", "i": i, "sql_text": "SELECT 1"})
    recs = [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines()]
    assert [(r["i"], r["sql_text"]) for r in recs] == [(0, "SELECT 1"), (1, "SELECT 1"), (2, "SELECT 1")]
    assert all(list(r)[0] == "ts" for r in recs)


# --- F27: the metadata cache is private, and future-dated entries expire -------


_T = [TableSummary(schema="main", name="customers", kind="table")]


def test_f27_future_dated_entry_is_a_miss_and_is_removed(tmp_path: Path) -> None:
    path = tmp_path / "cache.sqlite"
    cache = MetadataCache(str(path))
    cache.put_tables("c1", "fp", _T)
    ten_years = time.time() + 10 * 365 * 86400
    with sqlite3.connect(path) as conn:
        conn.execute("UPDATE cache_entries SET retrieved_at = ?", (ten_years,))
    assert cache.get_tables("c1", "fp") is None
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM cache_entries").fetchone() == (0,)


def test_f27_put_sweeps_future_dated_entries_of_other_keys(tmp_path: Path) -> None:
    path = tmp_path / "cache.sqlite"
    cache = MetadataCache(str(path))
    cache.put_tables("forged", "fp", _T)
    with sqlite3.connect(path) as conn:
        conn.execute("UPDATE cache_entries SET retrieved_at = ?", (time.time() + 86400,))
    cache.put_tables("c1", "fp", _T)
    with sqlite3.connect(path) as conn:
        keys = [k for (k,) in conn.execute("SELECT cache_key FROM cache_entries")]
    assert keys == ["tables:c1:fp"]


def test_f27_a_private_cache_still_round_trips(tmp_path: Path) -> None:
    path = tmp_path / "cache.sqlite"
    cache = MetadataCache(str(path))
    cache.put_tables("c1", "fp", _T)
    assert cache.get_tables("c1", "fp") == _T
    if sys.platform != "win32":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert metadata.cache_file_problems(path, owner_uid=os.geteuid()) == []


@_POSIX_ONLY
def test_f27_world_writable_cache_file_disables_the_cache(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "cache.sqlite"
    MetadataCache(str(path)).put_tables("c1", "fp", _T)
    path.chmod(0o666)
    cache = MetadataCache(str(path))
    assert cache.get_tables("c1", "fp") is None
    cache.put_tables("c2", "fp", _T)  # no-op: the file is not trusted or written
    with sqlite3.connect(path) as conn:
        keys = [k for (k,) in conn.execute("SELECT cache_key FROM cache_entries")]
    assert keys == ["tables:c1:fp"]
    assert "metadata cache disabled" in capsys.readouterr().err


@_POSIX_ONLY
def test_f27_chmod_failure_disables_the_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "cache.sqlite"

    def _denied(*_a: Any, **_k: Any) -> None:
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(os, "chmod", _denied)
    cache = MetadataCache(str(path))
    cache.put_tables("c1", "fp", _T)
    assert cache.get_tables("c1", "fp") is None


@_POSIX_ONLY
def test_f27_symlinked_cache_path_is_refused(tmp_path: Path) -> None:
    target = tmp_path / "elsewhere.sqlite"
    MetadataCache(str(target)).put_tables("c1", "fp", _T)
    link = tmp_path / "cache.sqlite"
    link.symlink_to(target)
    cache = MetadataCache(str(link))
    assert cache.get_tables("c1", "fp") is None
    cache.put_tables("c2", "fp", _T)
    with sqlite3.connect(target) as conn:
        assert [k for (k,) in conn.execute("SELECT cache_key FROM cache_entries")] == ["tables:c1:fp"]


@_POSIX_ONLY
def test_f27_group_writable_directory_disables_the_cache(tmp_path: Path) -> None:
    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(0o777)
    cache = MetadataCache(str(shared / "cache.sqlite"))
    cache.put_tables("c1", "fp", _T)
    assert cache.get_tables("c1", "fp") is None


@_POSIX_ONLY
def test_f27_foreign_owner_is_reported(tmp_path: Path) -> None:
    path = tmp_path / "cache.sqlite"
    MetadataCache(str(path)).put_tables("c1", "fp", _T)
    problems = metadata.cache_file_problems(path, owner_uid=os.geteuid() + 1)
    assert any("owned by uid" in p for p in problems), problems


@_POSIX_ONLY
def test_f27_doctor_reports_an_unsafe_cache_file(tmp_path: Path) -> None:
    path = tmp_path / "cache.sqlite"
    MetadataCache(str(path)).put_tables("c1", "fp", _T)
    cfg = tmp_path / "c.yaml"
    cfg.write_text(f"application:\n  metadata_cache_path: {path}\n")
    assert _doctor_check(run_doctor(str(cfg)), "metadata-cache-perms")["status"] == "ok"
    path.chmod(0o666)
    report = run_doctor(str(cfg))
    check = _doctor_check(report, "metadata-cache-perms")
    assert check["status"] == "fatal", check
    assert "-rw-rw-rw-" in check["detail"]
    assert report["healthy"] is False


# --- F28: a table list is cached whole or not at all ---------------------------


def _objects(n: int) -> list[TableSummary]:
    return [TableSummary(schema="main", name=f"t{i:02d}", kind="table") for i in range(n)]


def test_f28_an_over_cap_list_is_never_served_truncated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    five = len(json.dumps([t.__dict__ for t in _objects(5)]))
    monkeypatch.setattr(metadata, "_MAX_CACHE_PAYLOAD_BYTES", five)
    cache = MetadataCache(str(tmp_path / "cache.sqlite"))
    cache.put_tables("c1", "fp", _objects(3))
    assert cache.get_tables("c1", "fp") == _objects(3)
    cache.put_tables("c1", "fp", _objects(7))
    got = cache.get_tables("c1", "fp")
    assert got is None or got == _objects(7), got
    assert got is None  # the stale 3-object entry was deleted, not kept
    assert "not cached" in capsys.readouterr().err
    cache.put_tables("c1", "fp", _objects(5))  # at the cap: cached whole
    assert cache.get_tables("c1", "fp") == _objects(5)


def test_f28_entries_from_the_old_schema_version_are_discarded(tmp_path: Path) -> None:
    path = tmp_path / "cache.sqlite"
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE meta (k TEXT PRIMARY KEY, v TEXT)")
        conn.execute("INSERT INTO meta VALUES ('schema_version', '1')")
        conn.execute(
            "CREATE TABLE cache_entries (cache_key TEXT PRIMARY KEY, schema_version INTEGER NOT NULL,"
            " policy_fingerprint TEXT NOT NULL, retrieved_at REAL NOT NULL, payload TEXT NOT NULL)"
        )
        conn.execute(
            "INSERT INTO cache_entries VALUES ('tables:c1:fp', 1, 'fp', ?, ?)",
            (time.time(), json.dumps([t.__dict__ for t in _objects(5)])),
        )
    conn.close()
    path.chmod(0o600)
    assert metadata._SCHEMA_VERSION > 1
    cache = MetadataCache(str(path))
    assert cache.get_tables("c1", "fp") is None
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM cache_entries").fetchone() == (0,)
        assert conn.execute("SELECT v FROM meta WHERE k = 'schema_version'").fetchone() == (
            str(metadata._SCHEMA_VERSION),
        )
    cache.put_tables("c1", "fp", _objects(7))  # the refreshed cache is usable
    assert cache.get_tables("c1", "fp") == _objects(7)


# =============================================================================
# Part 2: config loading and secrets (F29, F51, F73, F74, F68, F70)
# =============================================================================


def _yaml(tmp_path: Path, body: str, name: str = "c.yaml") -> Path:
    p = tmp_path / name
    p.write_text(textwrap.dedent(body), encoding="utf-8")
    return p


def _secret(tmp_path: Path, name: str, value: str, mode: int = 0o600) -> Path:
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(value + "\n", encoding="utf-8")
    p.chmod(mode)
    return p


# --- F29: a repeated key is an error, not a silent last-wins -------------------


@pytest.mark.parametrize(
    ("body", "key", "lines"),
    [
        (
            """\
            connections:
              pg:
                type: postgres
                host: db.internal
                database: app
                username_env: PGU
                allowed_schemas: [reporting]
                allowed_schemas: []
            """,
            "allowed_schemas",
            (7, 8),
        ),
        (
            """\
            security:
              hard_max_rows: 50
              mask_columns: ['(?i)salary']
            application:
              transport: stdio
            security:
              default_deny_objects: true
            """,
            "security",
            (1, 6),
        ),
        (
            """\
            connections:
              db:
                type: sqlite
                database: /data/a.db
              db:
                type: sqlite
                database: /data/b.db
            """,
            "db",
            (2, 5),
        ),
        (
            """\
            security:
              default_deny_objects: true
              default_deny_objects: false
            """,
            "default_deny_objects",
            (2, 3),
        ),
        (
            """\
            security:
              <<: {default_deny_objects: true, mask_columns: ['(?i)salary']}
              <<: {default_deny_objects: false}
            """,
            "<<",
            (2, 3),
        ),
        (
            """\
            connections:
              pg:
                <<: {type: sqlite, database: /x, allowed_schemas: [reporting]}
                <<: {allowed_schemas: []}
            """,
            "<<",
            (3, 4),
        ),
    ],
    ids=[
        "allowed_schemas", "security_block", "connection_id", "default_deny_objects",
        "two_merge_keys_security", "two_merge_keys_connection",
    ],
)
def test_f29_repeated_key_is_refused_naming_both_lines(
    tmp_path: Path, body: str, key: str, lines: tuple[int, int]
) -> None:
    from universal_db_mcp.config import load_yaml_strict

    cfg = _yaml(tmp_path, body)
    with pytest.raises(ConfigError) as info:
        load_config(cfg)
    message = str(info.value)
    assert f"'{key}'" in message, message
    assert f"line {lines[0]}" in message and f"line {lines[1]}" in message, message
    with pytest.raises(ConfigError, match=f"'{key}'"):
        load_yaml_strict(cfg.read_text(encoding="utf-8"))


def test_f29_merge_keys_still_load_and_override(tmp_path: Path) -> None:
    cfg = _yaml(
        tmp_path,
        """\
        connections:
          base: &b {type: sqlite, database: /x}
          c: {<<: *b, database: /y}
        """,
    )
    loaded = load_config(cfg)
    assert loaded.connections["base"].database == "/x"
    assert loaded.connections["c"].database == "/y"
    assert loaded.connections["c"].type == "sqlite"


def test_f29_connection_ids_that_differ_only_in_case_are_refused(tmp_path: Path) -> None:
    cfg = _yaml(
        tmp_path,
        """\
        connections:
          prod: {type: sqlite, database: /data/a.db}
          PROD: {type: sqlite, database: /data/b.db}
        """,
    )
    with pytest.raises(ConfigError, match="'prod' and 'PROD'"):
        load_config(cfg)


def test_f29_doctor_reports_a_duplicate_key_config_as_fatal(tmp_path: Path) -> None:
    cfg = _yaml(tmp_path, "security:\n  default_deny_objects: true\n  default_deny_objects: false\n")
    report = run_doctor(str(cfg))
    check = _doctor_check(report, "config")
    assert check["status"] == "fatal", check
    assert "default_deny_objects" in check["detail"]
    assert report["healthy"] is False


# --- F70: every connection is read-only ---------------------------------------


def test_f70_connection_read_only_false_is_refused(tmp_path: Path) -> None:
    from pydantic import ValidationError

    from universal_db_mcp.config import ConnectionConfig

    body: dict[str, Any] = {"type": "postgres", "host": "db.internal", "database": "app", "username_env": "PGU"}
    with pytest.raises(ValidationError, match="not supported in v1"):
        ConnectionConfig.model_validate({**body, "read_only": False})
    assert ConnectionConfig.model_validate(body).read_only is True
    assert ConnectionConfig.model_validate({**body, "read_only": True}).read_only is True

    cfg = _yaml(tmp_path, "connections:\n  s: {type: sqlite, database: /data/x.db, read_only: false}\n")
    with pytest.raises(ConfigError, match=r"connections\.s\.read_only.*not supported in v1"):
        load_config(cfg)


_REPO = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize(
    "shipped",
    [
        "config.example.yaml",
        "config.mockdbs.yaml",
        "config.scale.yaml",
        "examples/sqlite-demo/config.yaml",
        "examples/sqlite-demo/config.template.yaml",
    ],
)
def test_f70_every_shipped_config_still_loads(shipped: str) -> None:
    path = _REPO / shipped
    if not path.is_file():
        pytest.skip(f"{shipped} is not in this checkout")
    for conn in load_config(path).connections.values():
        assert conn.read_only is True


def test_f70_generated_configs_still_load(tmp_path: Path) -> None:
    from universal_db_mcp.agents import core as agents_core
    from universal_db_mcp.wizard import MINIMAL_CONFIG

    wizard_cfg = _yaml(tmp_path, MINIMAL_CONFIG, "wizard.yaml")
    load_config(wizard_cfg)
    home = tmp_path / "seed-home"
    created, _note = agents_core.ensure_per_user_harness_config({}, home)
    if created is not None:
        assert load_config(created).application.audit_path == str(created.parent / "audit.jsonl")


# --- F73: the Oracle wallet password is a referenced secret -------------------


def _oracle_wallet_cfg(tmp_path: Path, options: str) -> Path:
    wallet = tmp_path / "wallet"
    wallet.mkdir(exist_ok=True)
    return _yaml(
        tmp_path,
        f"""\
        connections:
          ora:
            type: oracle
            host: db.internal
            database: ORCLPDB1
            tls: {{enabled: true, ca_file: {tmp_path / 'ca.pem'}}}
            options: {{wallet_location: {wallet}, {options}}}
        """,
    )


def test_f73_inline_wallet_password_is_refused(tmp_path: Path) -> None:
    cfg = _oracle_wallet_cfg(tmp_path, "wallet_password: hunter2wallet")
    with pytest.raises(ConfigError) as info:
        load_config(cfg)
    message = str(info.value)
    assert "wallet_password_file" in message and "wallet_password_env" in message, message
    assert "hunter2wallet" not in message


@_POSIX_ONLY
def test_f73_wallet_password_file_resolves_is_redacted_and_reaches_the_connector(tmp_path: Path) -> None:
    from universal_db_mcp.config import load_resolved
    from universal_db_mcp.security.redact import redact_text

    value = "wallet-pw-73c1f0"
    pw = _secret(tmp_path, "wallet.pw", value)
    _cfg, resolved = load_resolved(_oracle_wallet_cfg(tmp_path, f"wallet_password_file: {pw}"))
    conn = resolved["ora"]
    assert conn.wallet_password is not None and conn.wallet_password.value == value
    assert str(conn.wallet_password) == "<redacted>"
    # the Oracle connector reads options['wallet_password'] (oracle.py)
    assert conn.config.options["wallet_password"] == value
    assert redact_text(f"ORA-28759: failure to open file with {value} as the key") == (
        "ORA-28759: failure to open file with <redacted> as the key"
    )


def test_f73_wallet_password_env_resolves(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from universal_db_mcp.config import load_resolved

    monkeypatch.setenv("ORA_WALLET_PW", "wallet-env-73")
    _cfg, resolved = load_resolved(_oracle_wallet_cfg(tmp_path, "wallet_password_env: ORA_WALLET_PW"))
    assert resolved["ora"].config.options["wallet_password"] == "wallet-env-73"
    monkeypatch.delenv("ORA_WALLET_PW")
    with pytest.raises(ConfigError, match="ORA_WALLET_PW"):
        load_resolved(_oracle_wallet_cfg(tmp_path, "wallet_password_env: ORA_WALLET_PW"))


@_POSIX_ONLY
def test_f73_loose_wallet_password_file_is_refused(tmp_path: Path) -> None:
    from universal_db_mcp.config import load_resolved

    pw = _secret(tmp_path, "wallet.pw", "wallet-pw", mode=0o644)
    with pytest.raises(ConfigError, match="unsafe permissions"):
        load_resolved(_oracle_wallet_cfg(tmp_path, f"wallet_password_file: {pw}"))


def test_f73_wallet_password_file_and_env_are_exclusive(tmp_path: Path) -> None:
    pw = _secret(tmp_path, "wallet.pw", "wallet-pw")
    cfg = _oracle_wallet_cfg(tmp_path, f"wallet_password_file: {pw}, wallet_password_env: ORA_WALLET_PW")
    with pytest.raises(ConfigError, match="mutually exclusive"):
        load_config(cfg)


# --- F74: state paths vs input paths; relative paths follow the config file ---


def test_f74_audit_path_equal_to_a_username_file_is_refused(tmp_path: Path) -> None:
    user = _secret(tmp_path, "u1", "reader")
    pw = _secret(tmp_path, "p1", "pw")
    cfg = _yaml(
        tmp_path,
        f"""\
        application:
          audit_path: {user}
        connections:
          pg: {{type: postgres, host: db.example, database: d, username_file: {user}, password_file: {pw}}}
        """,
    )
    with pytest.raises(ConfigError, match=r"separate file") as info:
        load_config(cfg)
    assert "connections.pg.username_file" in str(info.value)


@pytest.mark.parametrize("field", ["tls.ca_file", "http_bearer_token_file"])
def test_f74_state_path_equal_to_any_other_input_is_refused(tmp_path: Path, field: str) -> None:
    shared = tmp_path / "shared-file"
    tls = f"tls: {{enabled: true, ca_file: {shared}}}" if field == "tls.ca_file" else "tls: {enabled: false}"
    token = f"  http_bearer_token_file: {shared}\n" if field == "http_bearer_token_file" else ""
    cfg = tmp_path / "c.yaml"
    cfg.write_text(
        f"application:\n  metadata_cache_path: {shared}\n{token}"
        f"connections:\n  pg: {{type: postgres, host: db.example, database: d, username_env: PGU, {tls}}}\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="separate file"):
        load_config(cfg)


@_POSIX_ONLY
def test_f74_connections_may_share_read_only_secret_and_ca_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from universal_db_mcp.config import load_resolved

    user = _secret(tmp_path, "u1", "reader")
    pw = _secret(tmp_path, "p1", "pw")
    ca = _secret(tmp_path, "ca.pem", "-----BEGIN CERTIFICATE-----")
    tls = f"tls: {{enabled: true, ca_file: {ca}}}"
    cfg = _yaml(
        tmp_path,
        f"""\
        connections:
          a: {{type: postgres, host: db.example, database: sales, username_file: {user}, password_file: {pw}, {tls}}}
          b: {{type: postgres, host: db.example, database: hr, username_file: {user}, password_file: {pw}, {tls}}}
        """,
    )
    _cfg, resolved = load_resolved(cfg)
    assert {n: c.password.value for n, c in resolved.items() if c.password} == {"a": "pw", "b": "pw"}


def test_f74_the_bearer_token_cannot_double_as_a_connection_secret(tmp_path: Path) -> None:
    pw = _secret(tmp_path, "p1", "pw")
    cfg = _yaml(
        tmp_path,
        f"""\
        application:
          http_bearer_token_file: {pw}
        connections:
          pg: {{type: postgres, host: db.example, database: d, username_env: PGU, password_file: {pw}}}
        """,
    )
    with pytest.raises(ConfigError, match="separate file"):
        load_config(cfg)


@_POSIX_ONLY
def test_f74_relative_paths_resolve_against_the_config_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from universal_db_mcp.config import load_resolved

    conf_dir = tmp_path / "D"
    _secret(conf_dir, "secrets/p", "relpw")
    _secret(conf_dir, "secrets/ca.pem", "-----BEGIN CERTIFICATE-----")
    cfg = _yaml(
        conf_dir,
        """\
        application:
          audit_path: state/audit.jsonl
          metadata_cache_path: state/meta.sqlite
        connections:
          pg:
            type: postgres
            host: db.example
            database: d
            username_env: PGU
            password_file: secrets/p
            tls: {enabled: true, ca_file: secrets/ca.pem}
        """,
    )
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    monkeypatch.setenv("PGU", "reader")
    loaded, resolved = load_resolved(cfg)
    assert loaded.connections["pg"].password_file == str(conf_dir / "secrets" / "p")
    assert loaded.connections["pg"].tls.ca_file == str(conf_dir / "secrets" / "ca.pem")
    assert loaded.application.audit_path == str(conf_dir / "state" / "audit.jsonl")
    assert loaded.application.metadata_cache_path == str(conf_dir / "state" / "meta.sqlite")
    pw = resolved["pg"].password
    assert pw is not None and pw.value == "relpw"


# --- F68: an unset audit_path audits to the platform default -------------------


def test_f68_unset_audit_path_defaults_to_the_per_user_state_directory(
    tmp_path: Path, _private_home: Path
) -> None:
    cfg = load_config(_yaml(tmp_path, "application:\n  transport: stdio\n"))
    assert cfg.application.audit_path == str(_private_home / ".universal-db-mcp" / "audit.jsonl")
    assert cfg.application.audit_path_default is not None
    assert "per-user" in cfg.application.audit_path_default
    # an empty value is the same as no value: it cannot switch auditing off
    cfg = load_config(_yaml(tmp_path, "application:\n  audit_path: ''\n"))
    assert cfg.application.audit_path == str(_private_home / ".universal-db-mcp" / "audit.jsonl")


def test_f68_explicit_audit_path_wins(tmp_path: Path) -> None:
    cfg = load_config(_yaml(tmp_path, f"application:\n  audit_path: {tmp_path / 'mine.jsonl'}\n"))
    assert cfg.application.audit_path == str(tmp_path / "mine.jsonl")
    assert cfg.application.audit_path_default is None


def test_f68_system_config_defaults_to_the_service_audit_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from universal_db_mcp import config as config_module
    from universal_db_mcp.agents import core as agents_core

    etc = tmp_path / "etc" / "universal-db-mcp"
    etc.mkdir(parents=True)
    service_dir = tmp_path / "var" / "log" / "universal-db-mcp"
    monkeypatch.setattr(agents_core, "system_config_dir", lambda: etc)
    monkeypatch.setattr(config_module, "SYSTEM_AUDIT_DIR", service_dir)
    cfg = load_config(_yaml(etc, "application:\n  transport: stdio\n", "config.yaml"))
    if sys.platform == "win32":
        assert cfg.application.audit_path == str(etc / "logs" / "audit.jsonl")
    else:
        assert cfg.application.audit_path == str(service_dir / "audit.jsonl")
    assert cfg.application.audit_path_default is not None
    assert "service" in cfg.application.audit_path_default


@_POSIX_ONLY
def test_f68_the_default_audit_directory_is_created_private(tmp_path: Path, _private_home: Path) -> None:
    from universal_db_mcp.config import load_resolved
    from universal_db_mcp.server import AppContext, build_server

    db = tmp_path / "demo.db"
    sqlite3.connect(db).close()
    cfg_path = _yaml(tmp_path, f"connections:\n  demo: {{type: sqlite, database: {db}}}\n")
    cfg, resolved = load_resolved(cfg_path)
    server = build_server(AppContext(cfg, resolved))
    import asyncio

    asyncio.run(server.call_tool("db_list_connections", {}))
    audit = _private_home / ".universal-db-mcp" / "audit.jsonl"
    assert audit.is_file(), "a config without audit_path must still produce an audit trail"
    assert stat.S_IMODE(audit.parent.stat().st_mode) == 0o700
    assert any(json.loads(line).get("action") == "db_list_connections" for line in audit.read_text().splitlines())


def test_f68_doctor_names_the_default_audit_path(tmp_path: Path, _private_home: Path) -> None:
    cfg = _yaml(tmp_path, "application:\n  transport: stdio\n")
    check = _doctor_check(run_doctor(str(cfg)), "audit-path")
    assert check["status"] == "ok", check
    assert str(_private_home / ".universal-db-mcp" / "audit.jsonl") in check["detail"]
    assert "default" in check["detail"] and "per-user" in check["detail"]


@_POSIX_ONLY
@pytest.mark.parametrize(("fail_closed", "status"), [(True, "fatal"), (False, "warning")])
def test_f68_doctor_flags_an_unwritable_default(
    tmp_path: Path, _private_home: Path, fail_closed: bool, status: str
) -> None:
    cfg = _yaml(tmp_path, f"application:\n  audit_fail_closed: {str(fail_closed).lower()}\n")
    _private_home.chmod(0o500)
    try:
        if os.access(_private_home, os.W_OK):
            pytest.skip("running with privileges that ignore directory modes")
        check = _doctor_check(run_doctor(str(cfg)), "audit-path")
    finally:
        _private_home.chmod(0o700)
    assert check["status"] == status, check
    assert "default" in check["detail"] and ".universal-db-mcp" in check["detail"]


def test_f68_doctor_flags_auditing_that_is_off(monkeypatch: pytest.MonkeyPatch) -> None:
    """Only a programmatic config can still carry no audit path; doctor must
    not call that healthy."""
    from universal_db_mcp.config import AppConfig
    from universal_db_mcp.diagnostics import doctor as doctor_module

    monkeypatch.setattr(doctor_module, "load_config", lambda _p: AppConfig())
    report = run_doctor(__file__)
    check = _doctor_check(report, "audit-path")
    assert check["status"] == "fatal", check


@_POSIX_ONLY
def test_f68_fail_open_write_failure_warns_once_per_window_and_counts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from universal_db_mcp.services import audit as audit_module

    clock = [1000.0]
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    target = tmp_path / "dir-at-audit-path"
    target.mkdir()
    log = AuditLog(str(target), fail_closed=False)
    for _ in range(3):
        log.record({"event": "tool_call", "action": "db_query"})
    err = capsys.readouterr().err
    assert err.count("\n") == 1, err
    assert str(target) in err and "EISDIR" in err and "dropped" in err
    assert log.dropped_records == 3

    clock[0] += audit_module._WARN_INTERVAL_SECONDS + 1
    log.record({"event": "tool_call", "action": "db_query"})
    err = capsys.readouterr().err
    assert err.count("\n") == 1 and "4 audit record(s) dropped" in err, err
    assert log.dropped_records == 4


def test_f68_fail_closed_still_refuses_and_does_not_count(tmp_path: Path) -> None:
    target = tmp_path / "dir-at-audit-path"
    target.mkdir()
    log = AuditLog(str(target), fail_closed=True)
    with pytest.raises(AuditWriteFailure):
        log.record({"event": "tool_call"})
    assert log.dropped_records == 0


# --- F51: secret files are checked on Windows too ------------------------------

_ME = "S-1-5-21-1000-2000-3000-1001"
_READ = 0x120089  # FILE_GENERIC_READ
_FULL = 0x1F01FF  # FILE_ALL_ACCESS


def _fake_acl(monkeypatch: pytest.MonkeyPatch, owner: str, aces: list[tuple[int, int, int, str]] | None) -> None:
    from universal_db_mcp import config as config_module

    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(config_module, "_win32_file_security", lambda _p: (owner, _ME, aces))


_PROTECTED = [(0, 0, _FULL, "S-1-5-18"), (0, 0, _FULL, "S-1-5-32-544"), (0, 0, _READ, _ME)]


@pytest.mark.parametrize(
    ("owner", "aces", "reason"),
    [
        (_ME, [*_PROTECTED, (0, 0x10, _READ, "S-1-5-32-545")], "Users"),
        (_ME, [*_PROTECTED, (0, 0, 0x80000000, "S-1-1-0")], "Everyone"),
        (_ME, [*_PROTECTED, (0, 0, _FULL, "S-1-5-11")], "Authenticated Users"),
        (_ME, [*_PROTECTED, (0, 0, _READ, "S-1-5-4")], "Interactive"),
        ("S-1-5-21-9-9-9-5000", _PROTECTED, "owned by S-1-5-21-9-9-9-5000"),
        (_ME, None, "NULL"),
    ],
    ids=["users", "everyone", "authenticated", "interactive", "foreign_owner", "null_dacl"],
)
def test_f51_win32_secret_readable_by_other_users_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, owner: str, aces: list[Any] | None, reason: str
) -> None:
    from universal_db_mcp.config import _check_secret_file_permissions

    token = _secret(tmp_path, "http-token", "x" * 40)
    _fake_acl(monkeypatch, owner, aces)
    with pytest.raises(ConfigError, match="unsafe permissions") as info:
        _check_secret_file_permissions(token)
    assert reason in str(info.value)


@pytest.mark.parametrize("owner", [_ME, "S-1-5-18", "S-1-5-32-544"])
def test_f51_win32_protected_secret_passes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, owner: str) -> None:
    from universal_db_mcp.config import _check_secret_file_permissions

    token = _secret(tmp_path, "http-token", "x" * 40)
    # a deny ACE, an inherit-only ACE and a SYNCHRONIZE-only grant give no
    # read or write access (a write grant is refused: see the round-2 tests)
    extra = [(1, 0, _READ, "S-1-5-32-545"), (0, 0x08, _READ, "S-1-1-0"), (0, 0, 0x00100000, "S-1-5-11")]
    _fake_acl(monkeypatch, owner, [*_PROTECTED, *extra])
    _check_secret_file_permissions(token)


def test_f51_win32_unreadable_acl_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from universal_db_mcp import config as config_module
    from universal_db_mcp.config import _check_secret_file_permissions

    token = _secret(tmp_path, "http-token", "x" * 40)

    def broken(_p: Path) -> Any:
        raise OSError(5, "Access is denied")

    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(config_module, "_win32_file_security", broken)
    with pytest.raises(ConfigError, match="could not be read"):
        _check_secret_file_permissions(token)


def test_f51_win32_doctor_is_fatal_for_the_token_and_connection_secrets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from universal_db_mcp.diagnostics import doctor as doctor_module

    token = _secret(tmp_path, "http-token", "x" * 40)
    pw = _secret(tmp_path, "p1", "pw")
    cfg = _yaml(
        tmp_path,
        f"""\
        application:
          audit_path: {tmp_path / 'audit.jsonl'}
          transport: http
          http_bearer_token_file: {token}
        security:
          require_remote_tls: false
        connections:
          pg: {{type: postgres, host: db.example, database: d, username_env: PGU, password_file: {pw}}}
        """,
    )
    monkeypatch.setenv("PGU", "reader")
    monkeypatch.setattr(doctor_module, "SERVICE_TOKEN_PATH", tmp_path / "no-service-token")
    _fake_acl(monkeypatch, _ME, [*_PROTECTED, (0, 0, _READ, "S-1-5-32-545")])
    report = run_doctor(str(cfg))
    assert _doctor_check(report, "http-bearer-token")["status"] == "fatal"
    assert "Users" in _doctor_check(report, "http-bearer-token")["detail"]
    assert _doctor_check(report, "connection-pg-secrets")["status"] == "fatal"
    assert _doctor_check(report, "connection-pg-secret-perms")["status"] == "fatal"

    _fake_acl(monkeypatch, _ME, _PROTECTED)
    report = run_doctor(str(cfg))
    assert _doctor_check(report, "http-bearer-token")["status"] == "ok"
    assert "NOT verified" not in _doctor_check(report, "http-bearer-token")["detail"]
    assert _doctor_check(report, "connection-pg-secrets")["status"] == "ok"


@pytest.mark.skipif(sys.platform != "win32", reason="real NTFS DACLs")
def test_f51_real_dacl_set_with_icacls(tmp_path: Path) -> None:  # pragma: no cover - Windows only
    import subprocess

    from universal_db_mcp.config import _check_secret_file_permissions

    token = tmp_path / "http-token"
    token.write_text("x" * 40, encoding="utf-8")
    me = subprocess.run(  # noqa: S603 - fixed args, Windows system tool
        ["whoami", "/user", "/fo", "csv", "/nh"], capture_output=True, text=True, check=True  # noqa: S607
    )
    my_sid = me.stdout.strip().split(",")[-1].strip('"')
    grant = ["/grant:r", "*S-1-5-18:F", "*S-1-5-32-544:F", f"*{my_sid}:F"]
    icacls = ["icacls", str(token)]
    subprocess.run([*icacls, "/inheritance:r", *grant], check=True, capture_output=True)  # noqa: S603 - fixed args
    _check_secret_file_permissions(token)
    subprocess.run([*icacls, "/grant", "*S-1-5-32-545:R"], check=True, capture_output=True)  # noqa: S603 - fixed args
    with pytest.raises(ConfigError, match="Users"):
        _check_secret_file_permissions(token)


# --- usernames are identifiers, not free-text secrets ------------------------


def test_usernames_are_not_scrubbed_from_unrelated_text(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A username such as 'default' or 'sa' registered for free-text scrubbing
    mangled unrelated messages ('the session runs at UR by <redacted>').
    Passwords stay registered; the driver auth-failure shapes that embed a
    username are still scrubbed by redact_text's own patterns."""
    from universal_db_mcp.config import load_resolved
    from universal_db_mcp.security.redact import redact_text

    user, password = "udbmcp_user_5e1a", "pw-5e1a-secret"
    monkeypatch.setenv("F_USER", user)
    monkeypatch.setenv("F_PASS", password)
    cfg = _yaml(
        tmp_path,
        "connections:\n  pg: {type: postgres, host: db.example, database: d,"
        " username_env: F_USER, password_env: F_PASS}\n",
    )
    _cfg, resolved = load_resolved(cfg)
    conn = resolved["pg"]
    assert conn.username is not None and conn.username.value == user
    assert str(conn.username) == "<redacted>"
    assert redact_text(f"the session runs at UR by {user}") == f"the session runs at UR by {user}"
    assert user not in redact_text(f'password authentication failed for user "{user}"')
    assert redact_text(f"handshake failed near {password}") == "handshake failed near <redacted>"


# --- Oracle Thick-mode wallet advice (connectors-sql note) --------------------


def test_thick_mode_tls_wallet_needs_an_auto_login_wallet(tmp_path: Path) -> None:
    wallet = tmp_path / "wallet"
    wallet.mkdir()
    (wallet / "ewallet.p12").write_bytes(b"p12")
    cfg = _yaml(
        tmp_path,
        f"""\
        application:
          audit_path: {tmp_path / 'audit.jsonl'}
        connections:
          ora:
            type: oracle
            host: db.internal
            database: ORCLPDB1
            username_env: ORA_U
            tls: {{enabled: true, ca_file: {tmp_path / 'ca.pem'}}}
            options: {{thick_mode: true, wallet_location: {wallet}}}
        """,
    )
    check = _doctor_check(run_doctor(str(cfg)), "connection-ora-oracle-wallet")
    assert check["status"] == "fatal", check
    assert "cwallet.sso" in check["detail"]
    (wallet / "cwallet.sso").write_bytes(b"sso")
    check = _doctor_check(run_doctor(str(cfg)), "connection-ora-oracle-wallet")
    assert check["status"] == "ok", check
    assert "db.internal" in check["detail"] and "SSL_SERVER_DN_MATCH" in check["detail"]


# =============================================================================
# Review round 1: gaps left by the first pass
# =============================================================================


# --- F29: a key repeated inside a '<<' merge source ------------------------------


@pytest.mark.parametrize(
    ("body", "key"),
    [
        ("connections:\n  pg: {<<: {allowed_schemas: [reporting], allowed_schemas: []}, type: postgres}\n",
         "allowed_schemas"),
        ("connections:\n  pg:\n    <<: &b {allowed_schemas: [reporting], allowed_schemas: []}\n    type: postgres\n",
         "allowed_schemas"),
        ("security:\n  <<:\n    default_deny_objects: true\n    default_deny_objects: false\n",
         "default_deny_objects"),
        ("security:\n  <<: [{default_deny_objects: true, default_deny_objects: false}]\n",
         "default_deny_objects"),
    ],
    ids=["inline_source", "anchored_source", "block_source", "sequence_source"],
)
def test_f29_repeated_key_inside_a_merge_source_is_refused(body: str, key: str) -> None:
    from universal_db_mcp.config import load_yaml_strict

    with pytest.raises(ConfigError, match=f"duplicate key '{key}'"):
        load_yaml_strict(body)


def test_f29_chained_merges_that_override_a_key_still_load(tmp_path: Path) -> None:
    """A merge source that itself merges and overrides a key holds that key
    once in the file; the check must not mistake PyYAML's flattened copy of
    it for a repeat."""
    cfg = _yaml(
        tmp_path,
        """\
        connections:
          base: &base {type: sqlite, database: /x}
          mid: &mid {<<: *base, database: /y}
          leaf: {<<: *mid}
          other: {<<: [*mid, *base]}
        """,
    )
    loaded = load_config(cfg)
    assert [loaded.connections[n].database for n in ("base", "mid", "leaf", "other")] == ["/x", "/y", "/y", "/y"]


# --- F74: rotation backups, SQLite sidecars and the postgres passfile -----------


@pytest.mark.parametrize(
    ("application", "connection", "labels"),
    [
        ("{audit_path: D/aud.jsonl}", "username_file: D/aud.jsonl.1, password_env: PGP",
         ("audit_path backup", "username_file")),
        ("{audit_path: D/aud.jsonl}", "username_env: PGU, password_file: D/aud.jsonl.5",
         ("audit_path backup", "password_file")),
        ("{audit_path: D/aud.jsonl, metadata_cache_path: D/cache.sqlite}",
         "username_env: PGU, password_file: D/cache.sqlite-wal", ("metadata_cache_path", "password_file")),
        ("{audit_path: D/aud.jsonl, metadata_cache_path: D/aud.jsonl.1}", "username_env: PGU",
         ("audit_path backup", "metadata_cache_path")),
        ("{audit_path: D/pgpass}", "username_env: PGU, options: {passfile: D/pgpass}",
         ("audit_path", "options.passfile")),
    ],
    ids=["backup_is_username_file", "last_backup_is_password_file", "cache_wal_is_password_file",
         "cache_is_audit_backup", "audit_is_passfile"],
)
def test_f74_files_the_state_paths_write_are_isolated_too(
    tmp_path: Path, application: str, connection: str, labels: tuple[str, str]
) -> None:
    cfg = _yaml(
        tmp_path,
        f"application: {application.replace('D/', f'{tmp_path}/')}\n"
        "connections:\n"
        f"  pg: {{type: postgres, host: db.example, database: d, {connection.replace('D/', f'{tmp_path}/')}}}\n",
    )
    with pytest.raises(ConfigError, match="separate file") as info:
        load_config(cfg)
    for label in labels:
        assert label in str(info.value), str(info.value)


def test_f74_a_numbered_file_past_the_retained_backups_is_not_a_conflict(tmp_path: Path) -> None:
    cfg = _yaml(
        tmp_path,
        f"application: {{audit_path: {tmp_path}/aud.jsonl, audit_max_backups: 2}}\n"
        "connections:\n"
        f"  pg: {{type: postgres, host: db.example, database: d, username_env: PGU,"
        f" password_file: {tmp_path}/aud.jsonl.3}}\n",
    )
    assert load_config(cfg).connections["pg"].password_file == f"{tmp_path}/aud.jsonl.3"


def test_f74_relative_postgres_passfile_resolves_against_the_config_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    conf_dir = tmp_path / "D"
    conf_dir.mkdir()
    cfg = _yaml(
        conf_dir,
        "connections:\n"
        "  pg: {type: postgres, host: h, database: d, username_env: PGU, options: {passfile: rel/pgpass}}\n",
    )
    monkeypatch.chdir(tmp_path)
    assert load_config(cfg).connections["pg"].options["passfile"] == str(conf_dir / "rel" / "pgpass")


def test_f74_rotation_can_no_longer_overwrite_a_username_file(tmp_path: Path) -> None:
    """The reviewer's end-to-end shape: username_file = <audit_path>.1 with a
    tiny audit_max_bytes. The config is refused before any rotation runs."""
    user = _secret(tmp_path, "aud.jsonl.1", "reader")
    pw = _secret(tmp_path, "pw", "pw")
    cfg = _yaml(
        tmp_path,
        f"application: {{audit_path: {tmp_path}/aud.jsonl, audit_max_bytes: 200}}\n"
        f"connections:\n  pg: {{type: postgres, host: h, database: d, username_file: {user}, password_file: {pw}}}\n",
    )
    with pytest.raises(ConfigError, match="separate file"):
        load_config(cfg)
    assert user.read_text() == "reader\n"


# --- metadata cache: server processes starting together on one fresh file ------


def _cache_opener(base: str, trials: int, gate: Any, out: Any) -> None:
    for trial in range(trials):
        gate.wait()
        try:
            cache = MetadataCache(os.path.join(base, f"t{trial}", "meta.sqlite"))
        except Exception as exc:  # noqa: BLE001 - reported to the parent
            out.put((trial, f"constructor raised {type(exc).__name__}: {exc}"))
            continue
        try:
            outcome = "ok"
            for _ in range(200):  # a busy first attempt is a miss; a later one caches
                cache.put_tables("c1", "fp", _T)
                if cache.get_tables("c1", "fp") == _T:
                    break
                time.sleep(0.01)
            else:
                outcome = "never cached"
        except Exception as exc:  # noqa: BLE001 - reported to the parent
            outcome = f"lookup raised {type(exc).__name__}: {exc}"
        out.put((trial, outcome))


def test_cache_opened_by_several_processes_at_once_never_fails_startup(tmp_path: Path) -> None:
    """Three processes open one fresh cache file at the same moment (stdio
    servers spawned together). 'database is locked' from the WAL switch used
    to escape MetadataCache() and fail serve with CONFIG_ERROR."""
    trials, workers = 12, 3
    for t in range(trials):
        (tmp_path / f"t{t}").mkdir(mode=0o700)
    ctx = mp.get_context("spawn")
    gate = ctx.Barrier(workers)
    out = ctx.Queue()
    procs = [ctx.Process(target=_cache_opener, args=(str(tmp_path), trials, gate, out)) for _ in range(workers)]
    for p in procs:
        p.start()
    try:
        outcomes = [out.get(timeout=120) for _ in range(trials * workers)]
    finally:
        for p in procs:
            p.join(timeout=30)
            if p.is_alive():
                p.kill()
    assert [o for o in outcomes if o[1] != "ok"] == []


class _BusyWalConnection:
    """sqlite3 connection whose WAL switch reports SQLITE_BUSY while the
    shared flag is set, the way a second process sees it mid-conversion."""

    def __init__(self, conn: sqlite3.Connection, busy: list[bool]) -> None:
        self._conn = conn
        self._busy = busy

    def execute(self, sql: str, *args: Any) -> Any:
        if self._busy[0] and sql.startswith("PRAGMA journal_mode"):
            exc = sqlite3.OperationalError("database is locked")
            exc.sqlite_errorcode = sqlite3.SQLITE_BUSY
            raise exc
        return self._conn.execute(sql, *args)

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> _BusyWalConnection:
        self._conn.__enter__()
        return self

    def __exit__(self, *exc: Any) -> Any:
        return self._conn.__exit__(*exc)


def test_cache_busy_at_startup_is_a_miss_and_initializes_on_first_use(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    busy = [True]
    real_connect = sqlite3.connect
    monkeypatch.setattr(sqlite3, "connect", lambda *a, **k: _BusyWalConnection(real_connect(*a, **k), busy))
    cache = MetadataCache(str(tmp_path / "cache.sqlite"))  # must not raise
    cache.put_tables("c1", "fp", _T)
    assert cache.get_tables("c1", "fp") is None  # still busy: a miss, never an error
    busy[0] = False
    cache.put_tables("c1", "fp", _T)
    assert cache.get_tables("c1", "fp") == _T


def test_cache_errors_after_startup_are_misses(tmp_path: Path) -> None:
    """A cache file replaced by garbage (or removed) while the server runs
    costs a live catalog read, never a failed tool call."""
    path = tmp_path / "cache.sqlite"
    cache = MetadataCache(str(path))
    cache.put_tables("c1", "fp", _T)
    for suffix in ("", "-wal", "-shm"):
        Path(f"{path}{suffix}").unlink(missing_ok=True)
    path.write_bytes(b"not a sqlite database" * 64)
    path.chmod(0o600)
    assert cache.get_tables("c1", "fp") is None
    cache.put_tables("c1", "fp", _T)
    cache.invalidate_connection("c1")
    path.unlink()
    cache.put_tables("c1", "fp", _T)  # a removed file is recreated with its schema
    assert cache.get_tables("c1", "fp") == _T


def test_corrupt_cache_file_still_fails_startup(tmp_path: Path) -> None:
    """Only a busy file is deferred: a file that is not SQLite stays fatal at
    startup, which doctor's metadata-cache-path check reports first."""
    path = tmp_path / "cache.sqlite"
    path.write_bytes(b"definitely not a sqlite database" * 4)
    path.chmod(0o600)
    with pytest.raises(sqlite3.DatabaseError):
        MetadataCache(str(path))


# --- F51: every grant that lets someone else read, or take, the secret ----------


@pytest.mark.parametrize(
    ("ace", "reason"),
    [
        ((0, 0, 0x40000, "S-1-5-32-545"), "Users"),  # WRITE_DAC: rewrite the DACL, then read
        ((0, 0, 0x80000, "S-1-1-0"), "Everyone"),  # WRITE_OWNER: take ownership, then read
        ((0, 0, _READ, "S-1-5-32-546"), "Guests"),
        ((0, 0, _READ, "S-1-5-7"), "Anonymous"),
        ((0, 0, _READ, "S-1-5-2"), "Network"),
        ((0, 0, _READ, "S-1-5-21-1-2-3-513"), "Domain Users"),
        ((9, 0, _READ, ""), "cannot be checked"),  # callback (conditional) allow ACE
        ((5, 0, _READ, ""), "cannot be checked"),  # object allow ACE
    ],
    ids=["users_write_dac", "everyone_write_owner", "guests", "anonymous", "network", "domain_users",
         "callback_ace", "object_ace"],
)
def test_f51_win32_more_grants_are_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ace: tuple[int, int, int, str], reason: str
) -> None:
    from universal_db_mcp.config import _check_secret_file_permissions

    token = _secret(tmp_path, "http-token", "x" * 40)
    _fake_acl(monkeypatch, _ME, [*_PROTECTED, ace])
    with pytest.raises(ConfigError, match="unsafe permissions") as info:
        _check_secret_file_permissions(token)
    assert reason in str(info.value)


def test_f51_win32_grant_to_the_service_account_passes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The MSI grants SYSTEM and Administrators full control and the service
    account read (service.ps1). Doctor runs as SYSTEM during an upgrade, so
    a read grant to one named account is not refused."""
    from universal_db_mcp.config import _check_secret_file_permissions

    token = _secret(tmp_path, "http-token", "x" * 40)
    grants = [(0, 0, _FULL, "S-1-5-18"), (0, 0, _FULL, "S-1-5-32-544"), (0, 0, _READ, "S-1-5-20")]
    _fake_acl(monkeypatch, "S-1-5-32-544", grants)
    _check_secret_file_permissions(token)


# --- F24: a root run cannot leave a lock (or log) the service is denied ---------


@_POSIX_ONLY
def test_f24_files_created_as_root_are_handed_to_the_audit_directory_owner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    service_uid, service_gid = 4242, 4343
    real_stat = os.stat

    def stat_as_service_owned(p: Any, *a: Any, **k: Any) -> os.stat_result:
        st = real_stat(p, *a, **k)
        if isinstance(p, (str, os.PathLike)) and Path(p) == state:
            fields = list(st[:10])
            fields[4], fields[5] = service_uid, service_gid
            return os.stat_result(fields)
        return st

    chowned: list[tuple[int, int, int]] = []
    monkeypatch.setattr(os, "stat", stat_as_service_owned)
    monkeypatch.setattr(os, "fchown", lambda fd, uid, gid: chowned.append((fd, uid, gid)))
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    log = AuditLog(str(state / "audit.jsonl"), fail_closed=True)
    log.record({"event": "x"})
    # the lock sidecar and the log, each handed over once
    assert sorted(chowned) == sorted([(log._lock_fd, service_uid, service_gid), (log._fd, service_uid, service_gid)])


@_POSIX_ONLY
def test_f24_a_non_root_run_never_changes_ownership(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    if os.geteuid() == 0:
        pytest.skip("runs as root")
    calls: list[Any] = []
    monkeypatch.setattr(os, "fchown", lambda *a: calls.append(a))
    AuditLog(str(tmp_path / "audit.jsonl"), fail_closed=True).record({"event": "x"})
    assert calls == []


# --- F71: one log and one lock descriptor serve every record --------------------


def test_f71_log_and_lock_are_opened_once_across_records(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "audit.jsonl"
    opened: list[str] = []
    real_open = os.open

    def counting_open(p: Any, *a: Any, **k: Any) -> int:
        opened.append(os.fspath(p))
        return real_open(p, *a, **k)

    monkeypatch.setattr(os, "open", counting_open)
    log = AuditLog(str(path), fail_closed=True)
    for i in range(20):
        log.record({"event": "tool_call", "i": i})
    expected = Counter({str(path): 1, f"{path}.lock": 1})
    if sys.platform == "win32":  # the log is closed after each record there (rotation needs it)
        expected[str(path)] = 20
    if sys.platform == "darwin":  # each state-file open reads its directory's ACL (third review)
        expected[str(tmp_path)] = 2
    assert Counter(opened) == expected
    if sys.platform != "win32":
        assert log._fd is not None and os.path.samestat(os.fstat(log._fd), os.stat(path))


# --- F70: doctor flags a connection that turns the server-side read-only off ----


def test_f70_doctor_warns_when_enforce_read_only_is_off_where_the_engine_has_it(tmp_path: Path) -> None:
    cfg = _yaml(
        tmp_path,
        f"""\
        application:
          audit_path: {tmp_path / 'audit.jsonl'}
        connections:
          pg: {{type: postgres, host: h, database: d, username_env: U, session: {{enforce_read_only: false}}}}
          db: {{type: db2, host: h, database: d, session: {{enforce_read_only: false}}}}
          ok: {{type: postgres, host: h, database: d, username_env: U}}
        """,
    )
    report = run_doctor(str(cfg))
    pg = _doctor_check(report, "session-pg")
    assert pg["status"] == "warning", pg
    assert "enforce_read_only" in pg["detail"] and "read-only=SQL guard only" in pg["detail"]
    assert _doctor_check(report, "session-db")["status"] == "ok"  # db2 has no session switch to lose
    assert _doctor_check(report, "session-ok")["status"] == "ok"


# --- F27: SQLite sidecar names are predictable, so a shared directory is refused -


@_POSIX_ONLY
def test_f27_sticky_world_writable_directory_is_refused_too(tmp_path: Path) -> None:
    shared = tmp_path / "sticky"
    shared.mkdir()
    shared.chmod(0o1777)
    path = shared / "cache.sqlite"
    problems = metadata.cache_file_problems(path, owner_uid=os.geteuid())
    assert any("writable by other users" in p for p in problems), problems
    cache = MetadataCache(str(path))
    cache.put_tables("c1", "fp", _T)
    assert cache.get_tables("c1", "fp") is None


# --- connectors-sql note: doctor flags a wallet_location the descriptor refuses --


@pytest.mark.parametrize("bad", ['/w")(ADDRESS=(PROTOCOL=TCP)', "/w)(x", "/w\nx"])
def test_doctor_flags_a_wallet_location_the_descriptor_cannot_carry(tmp_path: Path, bad: str) -> None:
    import yaml

    body = {
        "application": {"audit_path": str(tmp_path / "audit.jsonl")},
        "connections": {
            "ora": {
                "type": "oracle", "host": "db.internal", "database": "ORCLPDB1", "username_env": "ORA_U",
                "tls": {"enabled": True, "ca_file": str(tmp_path / "ca.pem")},
                "options": {"wallet_location": bad},
            }
        },
    }
    cfg = tmp_path / "c.yaml"
    cfg.write_text(yaml.safe_dump(body), encoding="utf-8")
    check = _doctor_check(run_doctor(str(cfg)), "connection-ora-oracle-wallet")
    assert check["status"] == "fatal", check
    assert "')('" in check["detail"] and "control character" in check["detail"]


# --- F68: the fail-open warning names the real condition -------------------------


def test_f68_audit_path_under_a_regular_file_is_reported_as_enotdir(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("")
    log = AuditLog(str(blocker / "audit.jsonl"), fail_closed=False)
    log.record({"event": "tool_call"})
    err = capsys.readouterr().err
    assert "ENOTDIR" in err and "EEXIST" not in err, err
    assert log.dropped_records == 1


# =============================================================================
# Round 2 (adversarial review): root runs, hard links, case variants, merges
# =============================================================================


def _as_root_in_service_dir(monkeypatch: pytest.MonkeyPatch, state: Path) -> tuple[list[int], list[int]]:
    """Run as euid 0 with *state* owned by a service account (the systemd
    LogsDirectory, the pkg LOG_DIR). Returns the inodes fchown'ed and the
    inodes fchmod'ed from then on."""
    real_stat, real_fstat, real_fchmod = os.stat, os.fstat, os.fchmod

    def stat_as_service_owned(p: Any, *a: Any, **k: Any) -> os.stat_result:
        st = real_stat(p, *a, **k)
        if isinstance(p, (str, os.PathLike)) and Path(p) == state:
            fields = list(st[:10])
            fields[4], fields[5] = 4242, 4343
            return os.stat_result(fields)
        return st

    chowned: list[int] = []
    chmodded: list[int] = []

    def fchmod(fd: int, mode: int) -> None:
        chmodded.append(real_fstat(fd).st_ino)
        real_fchmod(fd, mode)

    monkeypatch.setattr(os, "stat", stat_as_service_owned)
    monkeypatch.setattr(os, "fchown", lambda fd, _uid, _gid: chowned.append(real_fstat(fd).st_ino))
    monkeypatch.setattr(os, "fchmod", fchmod)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    return chowned, chmodded


@_POSIX_ONLY
@pytest.mark.parametrize("link", ["symlink", "hardlink"])
@pytest.mark.parametrize("name", ["audit.jsonl", "audit.jsonl.lock"])
def test_f24_a_root_run_never_hands_over_a_planted_log_or_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, link: str
) -> None:
    """The service account owns the audit directory, so it can plant the log
    or its lock as a link to a root file. A root run (sudo site-check) must
    refuse the record, not fchmod, fchown or append to the link's target."""
    state = tmp_path / "state"
    state.mkdir()
    victim = tmp_path / "victim"
    victim.write_text("root:x:0:0::/root:/bin/sh\n")
    victim.chmod(0o644)
    if link == "symlink":
        (state / name).symlink_to(victim)
    else:
        os.link(victim, state / name)
    victim_ino = victim.stat().st_ino
    chowned, chmodded = _as_root_in_service_dir(monkeypatch, state)
    with pytest.raises(AuditWriteFailure):
        AuditLog(str(state / "audit.jsonl"), fail_closed=True).record({"event": "site_check"})
    assert victim_ino not in chowned
    assert victim_ino not in chmodded
    assert victim.read_text() == "root:x:0:0::/root:/bin/sh\n"
    assert stat.S_IMODE(victim.stat().st_mode) == 0o644


@_POSIX_ONLY
def test_f24_a_root_run_hands_over_only_the_files_it_created(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state = tmp_path / "state"
    state.mkdir()
    AuditLog(str(state / "audit.jsonl"), fail_closed=True).record({"event": "by_the_service"})
    chowned, _chmodded = _as_root_in_service_dir(monkeypatch, state)
    AuditLog(str(state / "audit.jsonl"), fail_closed=True).record({"event": "site_check"})
    assert chowned == []
    assert [json.loads(x)["event"] for x in _audit_lines(state / "audit.jsonl")] == ["by_the_service", "site_check"]


@_POSIX_ONLY
@pytest.mark.parametrize("name", ["audit.jsonl", "audit.jsonl.lock"])
def test_f24_a_hard_linked_log_or_lock_is_refused(tmp_path: Path, name: str) -> None:
    """A second name for the log or lock is another file's content: appending
    to it (or locking it) is refused whoever runs the server."""
    other = _secret(tmp_path, "username", "udbmcp_ro")
    os.link(other, tmp_path / name)
    with pytest.raises(AuditWriteFailure, match="hard link"):
        AuditLog(str(tmp_path / "audit.jsonl"), fail_closed=True).record({"event": "tool_call"})
    assert other.read_text() == "udbmcp_ro\n"


@_POSIX_ONLY
def test_f24_a_symlinked_audit_log_is_refused(tmp_path: Path) -> None:
    target = tmp_path / "elsewhere"
    target.write_text("keep\n")
    (tmp_path / "audit.jsonl").symlink_to(target)
    with pytest.raises(AuditWriteFailure):
        AuditLog(str(tmp_path / "audit.jsonl"), fail_closed=True).record({"event": "x"})
    assert target.read_text() == "keep\n"


@_POSIX_ONLY
def test_f27_a_hard_linked_cache_file_is_refused(tmp_path: Path) -> None:
    victim = tmp_path / "victim.sqlite"
    with sqlite3.connect(victim) as conn:
        conn.execute("CREATE TABLE t (x)")
    conn.close()
    victim.chmod(0o600)
    path = tmp_path / "cache.sqlite"
    os.link(victim, path)
    problems = metadata.cache_file_problems(path, owner_uid=os.geteuid())
    assert any("hard links" in p for p in problems), problems
    cache = MetadataCache(str(path))
    cache.put_tables("c1", "fp", _T)
    assert cache.get_tables("c1", "fp") is None
    with sqlite3.connect(victim) as conn:
        assert [n for (n,) in conn.execute("SELECT name FROM sqlite_master")] == ["t"]
    conn.close()


def _stat_dir_as_owned_by(monkeypatch: pytest.MonkeyPatch, directory: Path, uid: int, mode: int) -> None:
    real_stat = os.stat

    def fake(p: Any, *a: Any, **k: Any) -> os.stat_result:
        st = real_stat(p, *a, **k)
        if isinstance(p, (str, os.PathLike)) and Path(p) == directory:
            fields = list(st[:10])
            fields[0], fields[4] = stat.S_IFDIR | mode, uid
            return os.stat_result(fields)
        return st

    monkeypatch.setattr(os, "stat", fake)


@_POSIX_ONLY
def test_f27_a_directory_owned_by_another_user_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A 0755 directory is still writable by its owner, who could plant a
    -wal file between the check and SQLite opening it."""
    other = os.geteuid() + 1
    _stat_dir_as_owned_by(monkeypatch, tmp_path, other, 0o755)
    problems = metadata.cache_file_problems(tmp_path / "cache.sqlite", owner_uid=os.geteuid())
    assert any(f"owned by uid {other}" in p for p in problems), problems
    # doctor as root knows no service uid, so it compares no owner
    assert metadata.cache_file_problems(tmp_path / "cache.sqlite", owner_uid=None) == []


@_POSIX_ONLY
def test_f27_a_foreign_owned_cache_file_disables_the_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "cache.sqlite"
    MetadataCache(str(path)).put_tables("c1", "fp", _T)
    me = os.geteuid()
    monkeypatch.setattr(os, "geteuid", lambda: me + 1)
    _stat_dir_as_owned_by(monkeypatch, tmp_path, me + 1, 0o700)  # only the file is foreign
    cache = MetadataCache(str(path))
    assert cache.get_tables("c1", "fp") is None
    cache.put_tables("c2", "fp", _T)
    assert f"owned by uid {me}, not uid {me + 1}" in capsys.readouterr().err
    monkeypatch.undo()
    with sqlite3.connect(path) as conn:
        assert [k for (k,) in conn.execute("SELECT cache_key FROM cache_entries")] == ["tables:c1:fp"]
    conn.close()


@_POSIX_ONLY
def test_f27_a_root_run_leaves_no_file_in_a_directory_another_account_owns(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A root-owned cache file would disable the service's cache for good."""
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    cache = MetadataCache(str(state / "cache.sqlite"))
    cache.put_tables("c1", "fp", _T)
    assert cache.get_tables("c1", "fp") is None
    assert list(state.iterdir()) == []


def test_f29_two_merge_keys_name_the_multi_source_form(tmp_path: Path) -> None:
    cfg = _yaml(tmp_path, "security:\n  <<: {default_deny_objects: true}\n  <<: {default_deny_objects: false}\n")
    with pytest.raises(ConfigError, match=r"<<: \[\*a, \*b\]"):
        load_config(cfg)


def test_f29_one_merge_key_with_several_sources_still_loads(tmp_path: Path) -> None:
    cfg = _yaml(
        tmp_path,
        """\
        connections:
          a: &a {type: sqlite, database: /x}
          b: &b {type: sqlite, database: /y, allowed_schemas: [main]}
          c: {<<: [*a, *b]}
        """,
    )
    loaded = load_config(cfg)
    assert loaded.connections["c"].database == "/x"  # the earlier source wins
    assert loaded.connections["c"].allowed_schemas == ["main"]


def _case_insensitive(d: Path) -> bool:
    probe = d / "CaseProbe"
    probe.write_text("")
    try:
        return (d / "caseprobe").exists()
    finally:
        probe.unlink()


@pytest.mark.parametrize(
    ("audit", "user"),
    [("SECRETS/USER", "secrets/user"), ("Audit.jsonl", "audit.jsonl.1"), ("secrets/USER.lock", "secrets/user.lock")],
    ids=["log", "rotated_backup", "lock"],
)
def test_f74_a_case_variant_of_a_secret_path_is_refused(tmp_path: Path, audit: str, user: str) -> None:
    """On a case-insensitive filesystem (the macOS and Windows default) a
    differently cased audit_path is the username file itself."""
    if not _case_insensitive(tmp_path):
        pytest.skip("case-sensitive filesystem")
    secret = _secret(tmp_path, user, "udbmcp_ro")
    audit_path = tmp_path / audit.removesuffix(".lock")
    cfg = _yaml(
        tmp_path,
        f"""\
        application:
          audit_path: {audit_path}
        connections:
          pg: {{type: postgres, host: db.example, database: d, username_file: {secret}, password_env: P}}
        """,
    )
    with pytest.raises(ConfigError, match="separate file") as info:
        load_config(cfg)
    assert "connections.pg.username_file" in str(info.value)


@pytest.mark.skipif(sys.platform not in ("darwin", "win32"), reason="case-folded comparison is macOS/Windows only")
def test_f74_state_paths_that_differ_only_in_case_are_one_file(tmp_path: Path) -> None:
    if not _case_insensitive(tmp_path):
        pytest.skip("case-sensitive filesystem")
    cfg = _yaml(
        tmp_path,
        f"application:\n  audit_path: {tmp_path / 'state' / 'a.db'}\n"
        f"  metadata_cache_path: {tmp_path / 'STATE' / 'A.DB'}\n",
    )
    with pytest.raises(ConfigError, match="separate file"):
        load_config(cfg)


@_POSIX_ONLY
@pytest.mark.parametrize("name", ["audit.jsonl", "audit.jsonl.lock"])
def test_f74_a_state_path_hard_linked_to_a_secret_is_refused(tmp_path: Path, name: str) -> None:
    user = _secret(tmp_path, "user", "udbmcp_ro")
    os.link(user, tmp_path / name)
    cfg = _yaml(
        tmp_path,
        f"""\
        application:
          audit_path: {tmp_path / 'audit.jsonl'}
        connections:
          pg: {{type: postgres, host: db.example, database: d, username_file: {user}, password_env: P}}
        """,
    )
    with pytest.raises(ConfigError, match="separate file") as info:
        load_config(cfg)
    assert "connections.pg.username_file" in str(info.value)


@pytest.mark.parametrize(
    ("option", "state_key", "name"),
    [
        ("wallet_location", "audit_path", "ewallet.pem"),
        ("wallet_location", "metadata_cache_path", "cwallet.sso"),
        ("tns_admin", "metadata_cache_path", "tnsnames.ora"),
        ("tns_admin", "audit_path", "sqlnet.ora"),
        ("tns_admin", "audit_path", "oraaccess.xml"),
    ],
)
def test_f74_state_that_is_an_oracle_client_file_is_refused(
    tmp_path: Path, option: str, state_key: str, name: str
) -> None:
    """Rotation would rename ewallet.pem away and the log would append into
    it: no state file may be one the Oracle client reads from a wallet or
    TNS_ADMIN directory (an Instant Client directory: see
    test_i32_state_inside_the_instant_client_directory_is_refused)."""
    import yaml

    client_dir = tmp_path / "oracle"
    (client_dir / name).parent.mkdir(parents=True)
    (client_dir / name).write_text("client file")
    options: dict[str, Any] = {option: str(client_dir)}
    if option == "tns_admin":
        options["tns_alias"] = "SALES"
    conn = {"type": "oracle", "host": "db.internal", "database": "ORCLPDB1", "username_env": "U", "options": options}

    def config(state_path: Path) -> Path:
        app = {"audit_path": str(tmp_path / "audit.jsonl"), state_key: str(state_path)}
        body = {"application": app, "connections": {"ora": conn}}
        cfg = tmp_path / "c.yaml"
        cfg.write_text(yaml.safe_dump(body), encoding="utf-8")
        return cfg

    with pytest.raises(ConfigError, match="Oracle client reads") as info:
        load_config(config(client_dir / name))
    assert f"connections.ora.options.{option}" in str(info.value)
    if sys.platform != "win32":  # a symlink needs a privilege on Windows
        # through a symlink it is still the client's file
        (tmp_path / "link").symlink_to(client_dir / name)
        with pytest.raises(ConfigError, match="Oracle client reads"):
            load_config(config(tmp_path / "link"))
        # and through a hard link, whose real path is its own: the inode says
        os.link(client_dir / name, tmp_path / "hardlink")
        with pytest.raises(ConfigError, match="Oracle client reads"):
            load_config(config(tmp_path / "hardlink"))
    # any other file, in the directory or beside it, is fine: TNS_ADMIN is
    # often $HOME or the per-user state directory itself
    load_config(config(client_dir / "state.file"))
    load_config(config(tmp_path / "oracle-state" / "state.file"))
    assert (client_dir / name).read_text() == "client file"


@_POSIX_ONLY
def test_f24_doctor_probes_the_lock_even_when_the_log_is_absent(tmp_path: Path) -> None:
    (tmp_path / "elsewhere").write_text("")
    Path(f"{tmp_path / 'audit.jsonl'}.lock").symlink_to(tmp_path / "elsewhere")
    cfg = _yaml(tmp_path, f"application:\n  audit_path: {tmp_path / 'audit.jsonl'}\n")
    check = _doctor_check(run_doctor(str(cfg)), "audit-path")
    assert check["status"] == "fatal", check
    assert ".lock" in check["detail"] and "symlink" in check["detail"]


@_POSIX_ONLY
@pytest.mark.parametrize("link", ["symlink", "hardlink"])
def test_f24_doctor_reports_a_linked_audit_log(tmp_path: Path, link: str) -> None:
    target = _secret(tmp_path, "elsewhere", "")
    audit = tmp_path / "audit.jsonl"
    if link == "symlink":
        audit.symlink_to(target)
    else:
        os.link(target, audit)
    cfg = _yaml(tmp_path, f"application:\n  audit_path: {audit}\n")
    check = _doctor_check(run_doctor(str(cfg)), "audit-path")
    assert check["status"] == "fatal", check
    assert ("symlink" if link == "symlink" else "hard links") in check["detail"]


@_POSIX_ONLY
@pytest.mark.parametrize("log_exists", [True, False])
@pytest.mark.parametrize(("fail_closed", "status"), [(True, "fatal"), (False, "warning")])
def test_f24_doctor_reports_a_filesystem_without_file_locks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, log_exists: bool, fail_closed: bool, status: str
) -> None:
    """An NFS or SMB share mounted without locking answers flock with
    ENOTSUP/ENOLCK: every audited call would fail, so doctor tries the lock."""
    import errno
    import fcntl

    def no_locks(_fd: int, _op: int) -> None:
        raise OSError(errno.ENOTSUP, "Operation not supported")

    state = tmp_path / "state"
    state.mkdir()
    audit = state / "audit.jsonl"
    if log_exists:
        _secret(state, "audit.jsonl", "")
    # the probe creates nothing, not even for a moment (the directory's
    # mtime would move): doctor may run against a user's real state directory
    before = (sorted(p.name for p in state.iterdir()), state.stat().st_mtime_ns)
    cfg = _yaml(tmp_path, f"application:\n  audit_path: {audit}\n  audit_fail_closed: {str(fail_closed).lower()}\n")
    monkeypatch.setattr(fcntl, "flock", no_locks)
    check = _doctor_check(run_doctor(str(cfg)), "audit-path")
    assert check["status"] == status, check
    assert "ENOTSUP" in check["detail"] and "lock" in check["detail"]
    assert (sorted(p.name for p in state.iterdir()), state.stat().st_mtime_ns) == before
    monkeypatch.undo()
    assert _doctor_check(run_doctor(str(cfg)), "audit-path")["status"] == "ok"
    assert (sorted(p.name for p in state.iterdir()), state.stat().st_mtime_ns) == before


@pytest.mark.parametrize(
    ("ace", "reason"),
    [
        ((0, 0, 0x0002, "S-1-5-11"), "writable by Authenticated Users"),  # FILE_WRITE_DATA
        ((0, 0, 0x0004, "S-1-5-32-545"), "writable by Users"),  # FILE_APPEND_DATA
        ((0, 0, 0x40000000, "S-1-1-0"), "writable by Everyone"),  # GENERIC_WRITE
    ],
    ids=["write_data", "append_data", "generic_write"],
)
def test_f51_win32_secret_writable_by_other_users_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ace: tuple[int, int, int, str], reason: str
) -> None:
    """POSIX refuses a group- or world-writable secret; so does Windows: any
    local user could otherwise replace the bearer token with one they know."""
    from universal_db_mcp.config import _check_secret_file_permissions

    token = _secret(tmp_path, "http-token", "x" * 40)
    _fake_acl(monkeypatch, _ME, [*_PROTECTED, ace])
    with pytest.raises(ConfigError, match="unsafe permissions") as info:
        _check_secret_file_permissions(token)
    assert reason in str(info.value)


# =============================================================================
# Integration wave (I32-I37)
# =============================================================================


# --- I32: an Oracle client directory may hold state, just not be its files ----


def _oracle_client_dir_cfg(config_dir: Path, option: str, directory: Path, application: str = "") -> Path:
    options = {
        "tns_admin": f"{{tns_admin: {directory}, tns_alias: X}}",
        "wallet_location": f"{{wallet_location: {directory}}}",
    }
    tls = f"\n    tls: {{enabled: true, ca_file: {config_dir / 'ca.pem'}}}" if option == "wallet_location" else ""
    return _yaml(
        config_dir,
        f"{application}"
        "connections:\n"
        "  o:\n"
        "    type: oracle\n"
        "    host: db.internal\n"
        "    database: ORCLPDB1\n"
        f"    username_env: U{tls}\n"
        f"    options: {options[option]}\n",
        "config.yaml",
    )


@pytest.mark.parametrize(
    ("option", "where"),
    [("tns_admin", "home"), ("tns_admin", "state_dir"), ("wallet_location", "state_dir")],
    ids=["tns_admin_is_home", "tnsnames_in_state_dir", "wallet_in_state_dir"],
)
def test_i32_per_user_audit_default_under_an_oracle_client_directory_loads(
    _private_home: Path, option: str, where: str
) -> None:
    """TNS_ADMIN=$HOME, or tnsnames.ora or the wallet kept in
    ~/.universal-db-mcp: the per-user default audit log and a cache beside
    it are files the Oracle client never reads."""
    state_dir = _private_home / ".universal-db-mcp"
    state_dir.mkdir()
    directory = _private_home if where == "home" else state_dir
    (directory / "tnsnames.ora").write_text("X=(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=h)(PORT=1521)))\n")
    (directory / "cwallet.sso").write_text("wallet")
    cfg = load_config(_oracle_client_dir_cfg(state_dir, option, directory))
    assert cfg.application.audit_path == str(state_dir / "audit.jsonl")
    assert cfg.application.audit_path_default is not None
    cache = f"application:\n  metadata_cache_path: {state_dir / 'metadata.sqlite'}\n"
    assert load_config(_oracle_client_dir_cfg(state_dir, option, directory, cache)).application.metadata_cache_path
    # the client's own files stay refused
    clash = f"application:\n  metadata_cache_path: {directory / 'tnsnames.ora'}\n"
    with pytest.raises(ConfigError, match="Oracle client reads"):
        load_config(_oracle_client_dir_cfg(state_dir, option, directory, clash))


# --- I33: Windows service default audits into a writable logs subfolder --------


def _as_win32_system_config(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    from universal_db_mcp.agents import core as agents_core

    program_data = tmp_path / "ProgramData" / "UniversalDB MCP"
    program_data.mkdir(parents=True)
    monkeypatch.setattr(agents_core, "system_config_dir", lambda: program_data)
    monkeypatch.setattr(sys, "platform", "win32")
    return program_data


def test_i33_win32_system_config_defaults_to_the_logs_subfolder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The service account only reads the config and secrets folder; the MSI
    makes its logs subfolder writable for it."""
    from universal_db_mcp.config import default_audit_path

    program_data = _as_win32_system_config(monkeypatch, tmp_path)
    cfg_path = _yaml(program_data, "application:\n  transport: stdio\n", "config.yaml")
    path, where = default_audit_path(cfg_path)
    assert path == program_data / "logs" / "audit.jsonl"
    assert "service" in where and "logs" in where
    assert load_config(cfg_path).application.audit_path == str(program_data / "logs" / "audit.jsonl")


@pytest.mark.parametrize("logs_exists", [True, False])
def test_i33_win32_doctor_does_not_call_the_service_audit_path_ok(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, logs_exists: bool
) -> None:
    """os.access ignores NTFS ACLs and doctor runs elevated: it cannot know
    whether the service account may write there, so it must not say ok."""
    from universal_db_mcp.diagnostics import doctor as doctor_module

    program_data = _as_win32_system_config(monkeypatch, tmp_path)
    if logs_exists:
        (program_data / "logs").mkdir()
    monkeypatch.setattr(doctor_module, "SERVICE_TOKEN_PATH", tmp_path / "no-service-token")
    cfg_path = _yaml(program_data, "application:\n  transport: stdio\n", "config.yaml")
    check = _doctor_check(run_doctor(str(cfg_path)), "audit-path")
    assert check["status"] == "warning", check
    assert str(program_data / "logs") in check["detail"]
    if logs_exists:
        assert "unverified" in check["detail"] and "service account" in check["detail"], check
    else:
        # a dedicated service account may only read the folder above it
        assert "will be created" not in check["detail"], check
        assert "dedicated service account cannot" in check["detail"], check
        assert "repair or reinstall the MSI" in check["detail"], check


def test_i33_doctor_still_says_ok_for_a_per_user_config_on_win32(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, _private_home: Path
) -> None:
    from universal_db_mcp.diagnostics import doctor as doctor_module

    _as_win32_system_config(monkeypatch, tmp_path)
    monkeypatch.setattr(doctor_module, "SERVICE_TOKEN_PATH", tmp_path / "no-service-token")
    check = _doctor_check(run_doctor(str(_yaml(tmp_path, "application:\n  transport: stdio\n"))), "audit-path")
    assert check["status"] == "ok", check


# --- I34: doctor as a user who cannot look into the service's folder ----------


@_POSIX_ONLY
@pytest.mark.parametrize("transport", ["stdio", "http"])
def test_i34_doctor_survives_a_service_token_it_may_not_inspect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, transport: str
) -> None:
    """The MSI makes %ProgramData%\\UniversalDB MCP SYSTEM/Administrators-only
    and Python 3.12's is_file() re-raises access denied; this is the POSIX
    analog: a directory the current user cannot search."""
    from universal_db_mcp.diagnostics import doctor as doctor_module

    service_dir = tmp_path / "service"
    service_dir.mkdir()
    token = _secret(service_dir, "http-token", "x" * 40)
    monkeypatch.setattr(doctor_module, "SERVICE_TOKEN_PATH", token)
    http = f"  transport: http\n  http_bearer_token_file: {token}\n" if transport == "http" else ""
    cfg = _yaml(tmp_path, f"application:\n  audit_path: {tmp_path / 'audit.jsonl'}\n{http}")
    service_dir.chmod(0)
    try:
        try:
            token.is_file()
        except PermissionError:
            pass
        else:
            pytest.skip("running with privileges that ignore directory modes")
        report = run_doctor(str(cfg))
    finally:
        service_dir.chmod(0o700)
    check = _doctor_check(report, "service-bearer-token")
    assert check["status"] == "warning", check
    assert "not verifiable by this user" in check["detail"] and str(token) in check["detail"]
    if transport == "http":
        check = _doctor_check(report, "http-bearer-token")
        assert check["status"] == "fatal", check
        assert "cannot be inspected by this user" in check["detail"]
    else:
        assert not [c for c in report["checks"] if c["check"] == "http-bearer-token"]


def test_i34_doctor_survives_a_service_token_probe_that_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same without directory modes (Windows, or a run as root)."""
    from universal_db_mcp.diagnostics import doctor as doctor_module

    class _Denied(type(Path())):  # type: ignore[misc]
        def is_file(self, *args: Any, **kwargs: Any) -> bool:
            raise PermissionError(13, "Access is denied", str(self))

    monkeypatch.setattr(doctor_module, "SERVICE_TOKEN_PATH", _Denied(tmp_path / "service" / "http-token"))
    cfg = _yaml(tmp_path, f"application:\n  audit_path: {tmp_path / 'audit.jsonl'}\n")
    report = run_doctor(str(cfg))
    check = _doctor_check(report, "service-bearer-token")
    assert check["status"] == "warning", check
    assert "not verifiable by this user" in check["detail"]
    assert report["healthy"] is True, [c for c in report["checks"] if c["status"] == "fatal"]


# --- I35: the lock-file reopen loop is bounded --------------------------------


def test_i35_a_lock_file_that_never_matches_its_path_fails_closed_promptly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """On a filesystem whose inode identities are unstable (network, FUSE)
    fstat and stat never agree; each call must fail, not hang holding the
    thread lock."""
    import threading

    calls = []

    def never_same(_a: os.stat_result, _b: os.stat_result) -> bool:
        calls.append(1)
        return False

    log = AuditLog(str(tmp_path / "audit.jsonl"), fail_closed=True)
    monkeypatch.setattr(os.path, "samestat", never_same)
    outcome: list[BaseException | None] = []

    def call() -> None:
        try:
            log.record({"event": "x"})
        except BaseException as exc:  # noqa: BLE001 - reported to the test thread
            outcome.append(exc)
        else:
            outcome.append(None)

    worker = threading.Thread(target=call, daemon=True)
    worker.start()
    worker.join(timeout=10)
    alive = worker.is_alive()
    monkeypatch.undo()  # lets a spinning worker finish
    assert not alive, f"record() still spinning after {len(calls)} lock reopen attempts"
    assert len(outcome) == 1 and isinstance(outcome[0], AuditWriteFailure), outcome
    assert "keeps changing" in str(outcome[0])
    assert len(calls) <= 100

    fail_open = AuditLog(str(tmp_path / "open.jsonl"), fail_closed=False)
    monkeypatch.setattr(os.path, "samestat", never_same)
    fail_open.record({"event": "x"})
    assert fail_open.dropped_records == 1
    monkeypatch.undo()
    log.record({"event": "y"})
    assert json.loads(_audit_lines(tmp_path / "audit.jsonl")[-1])["event"] == "y"


# --- I36: behaviours claimed without tests ----------------------------------


def test_i36_no_home_directory_asks_for_an_explicit_audit_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def no_home() -> Path:
        raise RuntimeError("Could not determine home directory.")

    monkeypatch.setattr(Path, "home", staticmethod(no_home))
    with pytest.raises(ConfigError, match="set application.audit_path") as info:
        load_config(_yaml(tmp_path, "application:\n  transport: stdio\n"))
    assert "cannot be derived" in str(info.value) and "home directory" in str(info.value)
    # an explicit path needs no home directory
    assert load_config(_yaml(tmp_path, f"application:\n  audit_path: {tmp_path / 'a.jsonl'}\n")).application.audit_path


def test_i36_relative_bearer_token_env_override_stays_as_given(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The service manager sets UDBMCP_HTTP_BEARER_TOKEN_FILE relative to its
    own working directory, not the config's: it is not rewritten."""
    conf_dir = tmp_path / "D"
    conf_dir.mkdir()
    monkeypatch.setenv("UDBMCP_HTTP_BEARER_TOKEN_FILE", "rel/token")
    cfg = load_config(_yaml(conf_dir, f"application:\n  audit_path: {tmp_path / 'a.jsonl'}\n"))
    assert cfg.application.http_bearer_token_file == "rel/token"
    # a relative path in the file itself follows the file
    body = f"application:\n  audit_path: {tmp_path / 'a.jsonl'}\n  http_bearer_token_file: rel/token\n"
    cfg = load_config(_yaml(conf_dir, body))
    assert cfg.application.http_bearer_token_file == str(conf_dir / "rel" / "token")


# --- I37: connection ids are ASCII, as the error message says -----------------


@pytest.mark.parametrize(
    "name",
    ["café", "\u0661\u0662", "ｐｒｏｄ", "db\u200b", "a" * 65, ""],
    ids=["latin1", "arabic_digits", "fullwidth", "zero_width_space", "too_long", "empty"],
)
def test_i37_non_ascii_connection_id_is_refused(tmp_path: Path, name: str) -> None:
    import yaml

    body = {
        "application": {"audit_path": str(tmp_path / "a.jsonl")},
        "connections": {name: {"type": "sqlite", "database": "/x"}},
    }
    cfg = tmp_path / "c.yaml"
    cfg.write_text(yaml.safe_dump(body, allow_unicode=True), encoding="utf-8")
    with pytest.raises(ConfigError, match=r"must be 1-64 chars of \[A-Za-z0-9_-\]"):
        load_config(cfg)


def test_i37_canonically_equivalent_ids_are_refused(tmp_path: Path) -> None:
    """U+1F71 and U+03AC are one character to APFS and HFS+ (distinct under
    casefold), so they would share one pair of secret files."""
    import yaml

    body = {
        "application": {"audit_path": str(tmp_path / "a.jsonl")},
        "connections": {
            "\u1f71x": {"type": "sqlite", "database": "/x"},
            "\u03acx": {"type": "sqlite", "database": "/y"},
        },
    }
    cfg = tmp_path / "c.yaml"
    cfg.write_text(yaml.safe_dump(body, allow_unicode=True), encoding="utf-8")
    with pytest.raises(ConfigError, match=r"\[A-Za-z0-9_-\]"):
        load_config(cfg)


def test_i37_every_ascii_id_shape_still_loads(tmp_path: Path) -> None:
    ids = ["prod", "PROD_2", "fin-ro", "_x", "9lives", "a" * 64]
    body = "connections:\n" + "".join(f"  {i}: {{type: sqlite, database: /{n}}}\n" for n, i in enumerate(ids))
    cfg = load_config(_yaml(tmp_path, f"application:\n  audit_path: {tmp_path / 'a.jsonl'}\n{body}"))
    assert list(cfg.connections) == ids


@pytest.mark.parametrize("value", ["udbmcp\n", "é", "a b"])
def test_i37_session_application_name_is_held_to_its_character_set_too(value: str) -> None:
    """The same rule for the name written into driver connection strings: a
    '$' anchor let a trailing newline through."""
    from pydantic import ValidationError

    from universal_db_mcp.config import ConnectionConfig

    conn = {"type": "postgres", "host": "h", "database": "d", "username_env": "U"}
    with pytest.raises(ValidationError, match="session.application_name may contain only"):
        ConnectionConfig.model_validate({**conn, "session": {"application_name": value}})
    ConnectionConfig.model_validate({**conn, "session": {"application_name": "udbmcp-reports:1.0@host_a"}})


# --- I34 (round 2): no doctor probe of a configured path may raise --------------


def _doctor_as_a_user_denied(cfg: Path, denied: Path, how: str, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """run_doctor(cfg) while the entries below *denied* cannot be inspected: a
    directory this user cannot search (POSIX), or stat() answering access
    denied, which is how a non-administrator sees the entries of the MSI's
    %ProgramData%\\UniversalDB MCP (Python 3.12's Path.exists(), is_dir(),
    is_file() and is_symlink() re-raise it)."""
    if how == "access_denied":
        real_stat = Path.stat

        def stat(self: Path, *args: Any, **kwargs: Any) -> os.stat_result:
            if denied in Path(os.path.abspath(self)).parents:
                raise PermissionError(errno.EACCES, "Access is denied", str(self))
            return real_stat(self, *args, **kwargs)

        with monkeypatch.context() as m:
            m.setattr(Path, "stat", stat)
            return run_doctor(str(cfg))
    denied.chmod(0)
    try:
        try:
            (denied / "probe").stat()
        except PermissionError:
            pass
        except FileNotFoundError:
            pytest.skip("directory modes do not restrict this user (root, or Windows)")
        return run_doctor(str(cfg))
    finally:
        denied.chmod(0o700)


@pytest.mark.parametrize("how", ["mode_0_directory", "access_denied"])
def test_i34_doctor_reports_a_config_it_may_not_inspect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, how: str
) -> None:
    """`udbmcp doctor --config "%ProgramData%\\UniversalDB MCP\\config.yaml"` in
    a non-elevated shell: a fatal check that says why, not a traceback."""
    from universal_db_mcp.diagnostics import doctor as doctor_module

    monkeypatch.setattr(doctor_module, "SERVICE_TOKEN_PATH", tmp_path / "no-service-token")
    service_dir = tmp_path / "service"
    service_dir.mkdir()
    cfg = _yaml(service_dir, f"application:\n  audit_path: {tmp_path / 'a.jsonl'}\n", "config.yaml")
    report = _doctor_as_a_user_denied(cfg, service_dir, how, monkeypatch)
    check = _doctor_check(report, "config")
    assert check["status"] == "fatal", check
    assert f"config file '{cfg}' cannot be inspected by this user" in check["detail"], check
    assert "administrator" in check["detail"], check
    assert report["healthy"] is False


_APP = "application:\n  audit_path: {t}/a.jsonl\n"
_PG = "connections:\n  c: {{type: postgres, host: h, database: d, "
_PG_TLS = _PG + "username_env: U, password_env: P, tls: {{enabled: true, ca_file: {d}/ca.pem}}}}\n"
_ORA = "connections:\n  c: {{type: oracle, host: h, database: d, username_env: U, password_env: P, "


@pytest.mark.parametrize(
    ("check_name", "body"),
    [
        ("audit-path", "application:\n  audit_path: {d}/logs/audit.jsonl\n"),
        ("metadata-cache-path", _APP + "  metadata_cache_path: {d}/logs/metadata.sqlite\n"),
        ("connection-c-files", _APP + _PG_TLS),
        ("connection-c-files", _APP + "connections:\n  c: {{type: sqlite, database: {d}/data.sqlite}}\n"),
        ("connection-c-files", _APP + _ORA + "options: {{tns_admin: {d}/tns, tns_alias: X}}}}\n"),
        ("connection-c-files", _APP + _ORA + "options: {{thick_mode: true, lib_dir: {d}/instantclient}}}}\n"),
        ("connection-c-secret-perms", _APP + _PG + "username_env: U, password_file: {d}/pw}}\n"),
        ("connection-c-secret-perms", _APP + _PG + "username_file: {d}/user, password_env: P}}\n"),
    ],
    ids=["audit_path", "metadata_cache_path", "ca_file", "sqlite_file", "tns_admin", "lib_dir", "password_file",
         "username_file"],
)
@pytest.mark.parametrize("how", ["mode_0_directory", "access_denied"])
def test_i34_doctor_reports_a_configured_path_it_may_not_inspect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, check_name: str, body: str, how: str
) -> None:
    """A per-user config naming a file below the service's folder (or a 0750
    secrets directory): each probe reports the path, the report goes on."""
    from universal_db_mcp.diagnostics import doctor as doctor_module

    monkeypatch.setattr(doctor_module, "SERVICE_TOKEN_PATH", tmp_path / "no-service-token")
    monkeypatch.setenv("U", "u")
    monkeypatch.setenv("P", "p")
    denied = tmp_path / "service"
    (denied / "logs").mkdir(parents=True)
    for name in ("ca.pem", "pw", "user", "data.sqlite"):
        _secret(denied, name, "x")
    cfg = _yaml(tmp_path, body.format(d=denied, t=tmp_path))
    report = _doctor_as_a_user_denied(cfg, denied, how, monkeypatch)
    found = [
        c for c in report["checks"] if c["check"] == check_name and "cannot be inspected by this user" in c["detail"]
    ]
    assert found, [c for c in report["checks"] if c["status"] != "ok"]
    assert found[0]["status"] == "fatal" and str(denied) in found[0]["detail"], found
    # the checks after it still ran
    assert [c for c in report["checks"] if c["check"] == "audit-path"]


@_POSIX_ONLY
@pytest.mark.parametrize("key", ["audit_path", "metadata_cache_path"])
def test_i34_a_state_path_with_a_name_too_long_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, key: str
) -> None:
    """Path.is_dir() re-raises ENAMETOOLONG as well; that is no reason to
    run doctor as an administrator."""
    from universal_db_mcp.diagnostics import doctor as doctor_module

    monkeypatch.setattr(doctor_module, "SERVICE_TOKEN_PATH", tmp_path / "no-service-token")
    audit = f"  audit_path: {tmp_path / 'a.jsonl'}\n" if key != "audit_path" else ""
    body = f"application:\n{audit}  {key}: {tmp_path / ('x' * 300) / 'f'}\n"
    report = run_doctor(str(_yaml(tmp_path, body)))
    check = _doctor_check(report, key.replace("_", "-"))
    assert check["status"] == "fatal", check
    assert "cannot be inspected (" in check["detail"] and "administrator" not in check["detail"], check


@pytest.mark.parametrize("how", ["mode_0_directory", "access_denied"])
def test_i34_a_bundle_manifest_override_it_may_not_inspect_is_not_a_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, how: str
) -> None:
    from universal_db_mcp.diagnostics import doctor as doctor_module

    monkeypatch.setattr(doctor_module, "SERVICE_TOKEN_PATH", tmp_path / "no-service-token")
    denied = tmp_path / "service"
    denied.mkdir()
    (denied / "manifest.json").write_text('{"profile": "p", "release": "r"}', encoding="utf-8")
    monkeypatch.setenv("UDBMCP_BUNDLE_MANIFEST", str(denied / "manifest.json"))
    cfg = _yaml(tmp_path, f"application:\n  audit_path: {tmp_path / 'a.jsonl'}\n")
    report = _doctor_as_a_user_denied(cfg, denied, how, monkeypatch)
    assert _doctor_check(report, "installed-release")["status"] == "ok"
    assert _doctor_check(report, "config")["status"] == "ok"


def test_i34_a_probe_that_raises_still_ends_in_a_report(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The net under every probe: an OSError none of them handles is a fatal
    check naming the path, never a traceback."""
    from universal_db_mcp.diagnostics import doctor as doctor_module

    def denied() -> None:
        raise PermissionError(errno.EACCES, "Access is denied", str(tmp_path / "pyvenv.cfg"))

    monkeypatch.setattr(doctor_module, "_venv_interpreter_check", denied)
    report = run_doctor(str(_yaml(tmp_path, f"application:\n  audit_path: {tmp_path / 'a.jsonl'}\n")))
    check = _doctor_check(report, "doctor")
    assert check["status"] == "fatal", check
    assert f"'{tmp_path / 'pyvenv.cfg'}' cannot be inspected by this user" in check["detail"], check
    assert report["healthy"] is False


# --- I33 (round 2): the cache in the service's read-only folder ----------------


@pytest.mark.parametrize("where", ["config_folder", "logs"])
def test_i33_win32_doctor_does_not_call_the_service_cache_path_ok(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, where: str
) -> None:
    """The MSI's template puts the cache beside the audit log; in the config
    folder a dedicated service account may only read, and SQLite then fails
    at startup. doctor cannot evaluate the ACL for that account either way."""
    from universal_db_mcp.diagnostics import doctor as doctor_module

    program_data = _as_win32_system_config(monkeypatch, tmp_path)
    (program_data / "logs").mkdir()
    monkeypatch.setattr(doctor_module, "SERVICE_TOKEN_PATH", tmp_path / "no-service-token")
    cache_dir = program_data if where == "config_folder" else program_data / "logs"
    cfg_path = _yaml(
        program_data, f"application:\n  metadata_cache_path: {cache_dir / 'metadata.sqlite'}\n", "config.yaml"
    )
    check = _doctor_check(run_doctor(str(cfg_path)), "metadata-cache-path")
    assert check["status"] == "warning", check
    assert "unverified" in check["detail"] and f"write access to '{cache_dir}'" in check["detail"], check
    assert f"Modify on '{program_data / 'logs'}' only" in check["detail"], check


def test_i33_doctor_still_says_ok_for_a_per_user_cache_on_win32(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from universal_db_mcp.diagnostics import doctor as doctor_module

    _as_win32_system_config(monkeypatch, tmp_path)
    monkeypatch.setattr(doctor_module, "SERVICE_TOKEN_PATH", tmp_path / "no-service-token")
    body = f"application:\n  metadata_cache_path: {tmp_path / 'metadata.sqlite'}\n"
    check = _doctor_check(run_doctor(str(_yaml(tmp_path, body))), "metadata-cache-path")
    assert check["status"] == "ok", check


# --- I35 (round 2): the create-or-open loop is bounded too ---------------------


def test_i35_a_name_that_exists_only_for_o_excl_fails_closed_promptly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """O_CREAT|O_EXCL says the lock exists and the plain open says it does
    not, every time (a network or FUSE filesystem with inconsistent lookups):
    the call fails instead of spinning with the thread lock held."""
    import threading

    real_open = os.open
    lock = str(tmp_path / "audit.jsonl.lock")
    calls = []

    def flapping_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        if os.fspath(path) == lock:
            calls.append(flags)
            if flags & os.O_EXCL:
                raise FileExistsError(errno.EEXIST, os.strerror(errno.EEXIST), lock)
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), lock)
        return real_open(path, flags, *args, **kwargs)

    log = AuditLog(str(tmp_path / "audit.jsonl"), fail_closed=True)
    monkeypatch.setattr(os, "open", flapping_open)
    outcome: list[BaseException | None] = []

    def call() -> None:
        try:
            log.record({"event": "x"})
        except BaseException as exc:  # noqa: BLE001 - reported to the test thread
            outcome.append(exc)
        else:
            outcome.append(None)

    worker = threading.Thread(target=call, daemon=True)
    worker.start()
    worker.join(timeout=10)
    alive = worker.is_alive()
    monkeypatch.undo()  # lets a spinning worker finish
    assert not alive, f"record() still spinning after {len(calls)} opens of the lock file"
    assert len(outcome) == 1 and isinstance(outcome[0], AuditWriteFailure), outcome
    assert "keeps appearing and disappearing" in str(outcome[0])
    assert len(calls) <= 200
    log.record({"event": "y"})
    assert json.loads(_audit_lines(tmp_path / "audit.jsonl")[-1])["event"] == "y"


# --- I37 (round 2): env names are ASCII identifiers; ids never start with '-' ---


@pytest.mark.parametrize(
    "name",
    ["PWD_É", "X١", "ＰWD", "9X", "A-B", "A\n", "A B", ""],
    ids=["latin1", "arabic_digit", "fullwidth", "leading_digit", "dash", "newline", "space", "empty"],
)
def test_i37_env_names_are_ascii_identifiers(name: str) -> None:
    from universal_db_mcp.config import resolve_env_name

    with pytest.raises(ConfigError, match="invalid environment variable name for password_env"):
        resolve_env_name(name, kind="password_env")


def test_i37_ascii_env_names_still_resolve() -> None:
    from universal_db_mcp.config import resolve_env_name

    for name in ("PWD", "_X", "db2_pw_1", "a"):
        assert resolve_env_name(name, kind="password_env") == name


def test_i37_a_non_ascii_env_reference_is_refused_where_it_is_resolved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from universal_db_mcp.config import ResolvedConnection

    monkeypatch.setenv("PWD_É", "secret")
    monkeypatch.setenv("U", "u")
    body = (
        f"application:\n  audit_path: {tmp_path / 'a.jsonl'}\n"
        "connections:\n  pg: {type: postgres, host: h, database: d, username_env: U, password_env: PWD_É}\n"
    )
    cfg = load_config(_yaml(tmp_path, body))
    with pytest.raises(ConfigError, match="invalid environment variable name for password_env"):
        ResolvedConnection("pg", cfg.connections["pg"])


@pytest.mark.parametrize("name", ["-rf", "-", "--help"])
def test_i37_connection_id_starting_with_a_dash_is_refused(tmp_path: Path, name: str) -> None:
    """Every command line that takes the id (the wizard's --name, scripts)
    would read it as an option, and the wizard cannot create one."""
    import yaml

    body = {
        "application": {"audit_path": str(tmp_path / "a.jsonl")},
        "connections": {name: {"type": "sqlite", "database": "/x"}},
    }
    cfg = tmp_path / "c.yaml"
    cfg.write_text(yaml.safe_dump(body), encoding="utf-8")
    with pytest.raises(ConfigError, match=r"must be 1-64 chars of \[A-Za-z0-9_-\], not starting with '-'"):
        load_config(cfg)


# =============================================================================
# Integration wave, fix-up round 1
# =============================================================================


# --- I32: an Instant Client directory holds no state at all --------------------


def _thick_cfg(tmp_path: Path, lib_dir: Path, state_key: str, state_path: Path) -> Path:
    import yaml

    options = {"thick_mode": True, "lib_dir": str(lib_dir)}
    conn = {"type": "oracle", "host": "db.internal", "database": "ORCLPDB1", "username_env": "U", "options": options}
    app = {"audit_path": str(tmp_path / "audit.jsonl"), state_key: str(state_path)}
    cfg = tmp_path / "c.yaml"
    cfg.write_text(yaml.safe_dump({"application": app, "connections": {"ora": conn}}), encoding="utf-8")
    return cfg


@pytest.mark.parametrize(
    ("state_key", "name"),
    [
        ("audit_path", "libclntsh.so.23.1"),
        ("metadata_cache_path", "libnnz.dylib"),
        ("audit_path", "oci.dll"),
        ("audit_path", "network/admin/tnsnames.ora"),
        ("audit_path", "network/admin/oraaccess.xml"),
        ("metadata_cache_path", "new-cache.sqlite"),
        ("audit_path", "network/admin/new-audit.jsonl"),
    ],
)
def test_i32_state_inside_the_instant_client_directory_is_refused(tmp_path: Path, state_key: str, name: str) -> None:
    """The log would append into libclntsh.so and rotation would rename it to
    .1, so Thick mode would no longer start. The client loads the files in
    lib_dir itself and in lib_dir/network/admin (its default TNS_ADMIN):
    nothing the server writes belongs in either, even under a new name."""
    lib_dir = tmp_path / "instantclient_23_1"
    target = lib_dir / name
    target.parent.mkdir(parents=True)
    if "new-" not in name:
        target.write_text("client file")
    with pytest.raises(ConfigError, match="Oracle client loads") as info:
        load_config(_thick_cfg(tmp_path, lib_dir, state_key, target))
    assert "connections.ora.options.lib_dir" in str(info.value)
    if sys.platform != "win32":  # a symlink needs a privilege on Windows
        # reached through a symlinked directory it is still inside
        (tmp_path / "ic-link").symlink_to(lib_dir, target_is_directory=True)
        with pytest.raises(ConfigError, match="Oracle client loads"):
            load_config(_thick_cfg(tmp_path, lib_dir, state_key, tmp_path / "ic-link" / name))
    # beside the directory, including a sibling that shares its name as a prefix
    load_config(_thick_cfg(tmp_path, lib_dir, state_key, tmp_path / "instantclient_23_1-state" / "state.file"))
    load_config(_thick_cfg(tmp_path, lib_dir, state_key, tmp_path / "state.file"))
    if "new-" not in name:
        assert target.read_text() == "client file"


# --- I33: a symlinked system config is still the service's config --------------


@pytest.mark.skipif(sys.platform == "win32", reason="creating a symlink needs a privilege on Windows")
@pytest.mark.parametrize("platform", ["linux", "win32"])
def test_i33_a_symlinked_system_config_keeps_the_service_audit_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, _private_home: Path, platform: str
) -> None:
    """/etc/universal-db-mcp/config.yaml -> /srv/udbmcp/config.yaml is the
    config the service is started with. Classified by its real path alone it
    was a per-user run, auditing to the service account's home, which
    ProtectHome=true hides: every audited call failed closed."""
    from universal_db_mcp.agents import core as agents_core
    from universal_db_mcp.config import SYSTEM_AUDIT_DIR, default_audit_path, is_system_config

    system = tmp_path / "etc-udbmcp"
    system.mkdir()
    site = tmp_path / "srv"
    site.mkdir()
    (site / "config.yaml").write_text("application:\n  transport: stdio\n")
    (system / "config.yaml").symlink_to(site / "config.yaml")
    monkeypatch.setattr(agents_core, "system_config_dir", lambda: system)
    monkeypatch.setattr(sys, "platform", platform)
    service = system / "logs" / "audit.jsonl" if platform == "win32" else SYSTEM_AUDIT_DIR / "audit.jsonl"

    assert is_system_config(system / "config.yaml")
    path, where = default_audit_path(system / "config.yaml")
    assert (path, where.startswith("service state directory")) == (service, True)
    # the same file opened by its own name is a per-user run
    assert not is_system_config(site / "config.yaml")
    assert default_audit_path(site / "config.yaml")[0] == _private_home / ".universal-db-mcp" / "audit.jsonl"
    # a per-user link to a system config runs the service's config: its
    # records go to the service's audit trail, not a second one
    (system / "regular.yaml").write_text("application:\n  transport: stdio\n")
    (_private_home / "config.yaml").symlink_to(system / "regular.yaml")
    assert default_audit_path(_private_home / "config.yaml")[0] == service
    # a relative spelling of the system config is the same file
    monkeypatch.chdir(tmp_path)
    assert default_audit_path(Path("etc-udbmcp") / "config.yaml")[0] == service


# --- I35: waiting for the audit lock is bounded --------------------------------


def _hold_audit_lock(lock_path: Path) -> int:
    """Take <audit_path>.lock through a descriptor of its own, as another
    server process would (a flock or a Windows byte-range lock held by one
    open file excludes every other one, in this process too)."""
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    if sys.platform == "win32":
        import msvcrt

        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
    else:
        import fcntl

        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    return fd


def _release_audit_lock(fd: int) -> None:
    if sys.platform == "win32":
        import msvcrt

        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
    os.close(fd)


def test_i35_an_audit_lock_that_is_never_released_fails_the_call_after_the_wait(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A server process suspended mid-append, or stuck in fsync on a dead
    mount, holds the lock for good: every audited call must fail closed
    after a bounded wait, not hang."""
    import threading

    from universal_db_mcp.services import audit

    monkeypatch.setattr(audit, "_LOCK_WAIT_SECONDS", 0.5, raising=False)
    path = tmp_path / "audit.jsonl"
    holder = _hold_audit_lock(Path(f"{path}.lock"))
    log = AuditLog(str(path), fail_closed=True)
    outcome: list[BaseException | None] = []

    def call() -> None:
        try:
            log.record({"event": "x"})
        except BaseException as exc:  # noqa: BLE001 - reported to the test thread
            outcome.append(exc)
        else:
            outcome.append(None)

    try:
        start = time.monotonic()
        worker = threading.Thread(target=call, daemon=True)
        worker.start()
        worker.join(timeout=10)
        alive, elapsed = worker.is_alive(), time.monotonic() - start
    finally:
        _release_audit_lock(holder)  # lets a blocked worker finish
    assert not alive, "record() still waiting for the audit lock after 10 s"
    assert 0.4 <= elapsed < 5, elapsed
    assert len(outcome) == 1 and isinstance(outcome[0], AuditWriteFailure), outcome
    assert "held by another process" in str(outcome[0]) and "operation refused" in str(outcome[0])
    # nothing was written, and the log works again once the lock is free
    assert not path.exists() or path.read_text() == ""
    log.record({"event": "y"})
    assert [json.loads(line)["event"] for line in _audit_lines(path)] == ["y"]


def test_i35_threads_queued_behind_a_held_audit_lock_share_one_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every thread of the server queues on the log's thread lock behind the
    one waiting for the file lock: each call's wait is bounded as a whole,
    not once per thread ahead of it. Fail-open, each one is a dropped record."""
    import threading

    from universal_db_mcp.services import audit

    monkeypatch.setattr(audit, "_LOCK_WAIT_SECONDS", 0.5, raising=False)
    path = tmp_path / "audit.jsonl"
    holder = _hold_audit_lock(Path(f"{path}.lock"))
    log = AuditLog(str(path), fail_closed=False)
    try:
        start = time.monotonic()
        workers = [threading.Thread(target=log.record, args=({"event": n},), daemon=True) for n in range(8)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=max(0.0, start + 15 - time.monotonic()))
        waiting, elapsed = sum(w.is_alive() for w in workers), time.monotonic() - start
    finally:
        _release_audit_lock(holder)
    assert waiting == 0, f"{waiting} of 8 record() calls still waiting for the audit lock"
    # one after another they would take 8 x 0.5 s
    assert elapsed < 2.5, elapsed
    assert log.dropped_records == 8
    log.record({"event": "after"})
    assert [json.loads(line)["event"] for line in _audit_lines(path)] == ["after"]


# --- I37: the stated character sets are the whole rule ---------------------------


def test_i37_ids_and_env_names_made_of_underscores_and_dashes_follow_the_stated_rule(tmp_path: Path) -> None:
    """Ids are [A-Za-z0-9_-] not starting with '-', env names
    [A-Za-z_][A-Za-z0-9_]*: '_' and '__-' are ids and '_' is an env name,
    as the messages say (the old isalnum() test refused them by accident)."""
    from universal_db_mcp.config import resolve_env_name

    ids = ["_", "__-", "_-_"]
    body = "connections:\n" + "".join(f"  '{i}': {{type: sqlite, database: /{n}}}\n" for n, i in enumerate(ids))
    cfg = load_config(_yaml(tmp_path, f"application:\n  audit_path: {tmp_path / 'a.jsonl'}\n{body}"))
    assert list(cfg.connections) == ids
    assert resolve_env_name("_", kind="password_env") == "_"
    assert resolve_env_name("__", kind="password_env") == "__"


@pytest.mark.parametrize("fail_closed", [True, False])
def test_i35_a_record_stuck_in_its_write_does_not_hang_the_other_threads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fail_closed: bool
) -> None:
    """A thread stuck in write or fsync on a dead mount keeps the log's
    thread lock: the other threads of the server give up after the wait
    instead of queueing behind it for good. Fail-open, counting the dropped
    record must not wait for that lock either."""
    import threading

    from universal_db_mcp.services import audit

    monkeypatch.setattr(audit, "_LOCK_WAIT_SECONDS", 0.5)
    inside, release = threading.Event(), threading.Event()
    real_write = audit._write_record

    def stuck_write(fd: int, line: bytes) -> None:
        if b'"stuck"' in line:
            inside.set()
            release.wait(30)
        real_write(fd, line)

    monkeypatch.setattr(audit, "_write_record", stuck_write)
    path = tmp_path / "audit.jsonl"
    log = AuditLog(str(path), fail_closed=fail_closed)
    stuck = threading.Thread(target=log.record, args=({"event": "stuck"},), daemon=True)
    stuck.start()
    assert inside.wait(10)
    outcome: list[BaseException | None] = []

    def call() -> None:
        try:
            log.record({"event": "next"})
        except BaseException as exc:  # noqa: BLE001 - reported to the test thread
            outcome.append(exc)
        else:
            outcome.append(None)

    try:
        worker = threading.Thread(target=call, daemon=True)
        worker.start()
        worker.join(timeout=10)
        alive = worker.is_alive()
    finally:
        release.set()
        stuck.join(timeout=10)
    assert not alive, "record() still queued behind a write that never returns"
    if fail_closed:
        assert len(outcome) == 1 and isinstance(outcome[0], AuditWriteFailure), outcome
        assert "another thread of this process" in str(outcome[0])
    else:
        assert outcome == [None]
        assert log.dropped_records == 1
    assert [json.loads(line)["event"] for line in _audit_lines(path)] == ["stuck"]


# =============================================================================
# Integration wave, fix-up round 2
# =============================================================================


# --- I35: a held log costs one full wait, not one per record ---------------------


@pytest.mark.parametrize("holder", ["another process", "a stuck thread"])
def test_i35_after_one_record_gave_up_the_next_ones_wait_briefly_until_the_log_is_free(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, holder: str
) -> None:
    """db_query writes two records per call (the statement, or the refusal
    after a failure): with the log held for good, each call waited the full
    wait twice, and fail-open every call was slowed by it. After one record
    gave up, the next ones wait only briefly; once the log is free again,
    the full wait is back."""
    import threading

    from universal_db_mcp.services import audit

    monkeypatch.setattr(audit, "_LOCK_WAIT_SECONDS", 1.0)
    monkeypatch.setattr(audit, "_CONTENDED_WAIT_SECONDS", 0.1, raising=False)
    path = tmp_path / "audit.jsonl"
    log = AuditLog(str(path), fail_closed=True)

    def hold() -> int | None:
        if holder == "another process":
            return _hold_audit_lock(Path(f"{path}.lock"))
        assert log._lock.acquire(timeout=5)  # what a thread stuck in fsync holds
        return None

    def release(fd: int | None) -> None:
        if fd is None:
            log._lock.release()
        else:
            _release_audit_lock(fd)

    def timed_refusal() -> float:
        # in a worker: a wait that never ends fails this test, not the run
        outcome: list[BaseException | None] = []

        def call() -> None:
            try:
                log.record({"event": "held"})
            except BaseException as exc:  # noqa: BLE001 - reported to the test thread
                outcome.append(exc)
            else:
                outcome.append(None)

        start = time.monotonic()
        worker = threading.Thread(target=call, daemon=True)
        worker.start()
        worker.join(timeout=10)
        assert not worker.is_alive(), "record() still waiting for the held audit log after 10 s"
        elapsed = time.monotonic() - start
        assert len(outcome) == 1 and isinstance(outcome[0], AuditWriteFailure), outcome
        assert "operation refused" in str(outcome[0])
        return elapsed

    fd = hold()
    try:
        waits = [timed_refusal() for _ in range(3)]
    finally:
        release(fd)
    assert 0.9 <= waits[0] < 5, waits
    assert max(waits[1:]) < 0.6, waits
    # the brief wait is enough for a log that is free again
    log.record({"event": "free"})
    fd = hold()
    try:
        again = timed_refusal()
    finally:
        release(fd)
    assert again >= 0.9, again
    assert [json.loads(line)["event"] for line in _audit_lines(path)] == ["free"]


# --- I32: lib_dir holds state only in the two directories the client reads -----


def test_i32_state_below_the_instant_client_directory_but_not_in_what_it_reads_loads(
    tmp_path: Path, _private_home: Path
) -> None:
    """lib_dir=$HOME with Thick mode and audit_path unset loaded before:
    ~/.universal-db-mcp/audit.jsonl is below lib_dir, but the client reads
    only the files in lib_dir itself and in lib_dir/network/admin."""
    oracle = (
        "connections:\n"
        "  o:\n"
        "    type: oracle\n"
        "    host: db.internal\n"
        "    database: ORCLPDB1\n"
        "    username_env: U\n"
        "    options: {{thick_mode: true, lib_dir: {lib_dir}}}\n"
    )
    cfg = load_config(_yaml(tmp_path, oracle.format(lib_dir=_private_home)))
    assert cfg.application.audit_path == str(_private_home / ".universal-db-mcp" / "audit.jsonl")
    for state in ("sub/deeper/state.file", "network/state.file", "network/admin/sub/state.file"):
        body = f"application:\n  metadata_cache_path: {_private_home / state}\n" + oracle
        assert load_config(_yaml(tmp_path, body.format(lib_dir=_private_home))).application.metadata_cache_path


def test_i32_a_defaulted_audit_path_in_lib_dir_is_named_as_the_default(tmp_path: Path, _private_home: Path) -> None:
    """The message blamed 'application.audit_path', which the file never
    set: it says the key is unset and which default was used."""
    body = (
        "connections:\n"
        "  o:\n"
        "    type: oracle\n"
        "    host: db.internal\n"
        "    database: ORCLPDB1\n"
        "    username_env: U\n"
        f"    options: {{thick_mode: true, lib_dir: {_private_home / '.universal-db-mcp'}}}\n"
    )
    with pytest.raises(ConfigError, match="Oracle client loads") as info:
        load_config(_yaml(tmp_path, body))
    message = str(info.value)
    assert "application.audit_path is unset" in message
    assert f"per-user state directory {_private_home / '.universal-db-mcp'}" in message
    # an audit_path the file sets is named as before
    explicit = f"application:\n  audit_path: {_private_home / '.universal-db-mcp' / 'a.jsonl'}\n" + body
    with pytest.raises(ConfigError, match="Oracle client loads") as info:
        load_config(_yaml(tmp_path, explicit))
    assert "'application.audit_path' (" in str(info.value) and "unset" not in str(info.value)


# --- I36: a home directory that is '/' or relative derives no audit default ------


@pytest.mark.skipif(sys.platform == "win32", reason="HOME is the POSIX home directory; Windows reads USERPROFILE")
@pytest.mark.parametrize("home", ["", "/", "rel", "./rel"], ids=["empty", "root", "relative", "dot-relative"])
def test_i36_a_home_that_is_the_root_or_relative_asks_for_an_explicit_audit_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, home: str
) -> None:
    """HOME='' makes Path.home() '/', so the default was
    /.universal-db-mcp/audit.jsonl (refused on every call as a plain user,
    created at the filesystem root as root); a relative HOME made it follow
    each stdio client's working directory."""
    monkeypatch.setenv("HOME", home)
    monkeypatch.chdir(tmp_path)
    with pytest.raises(ConfigError, match="set application.audit_path") as info:
        load_config(_yaml(tmp_path, "application:\n  transport: stdio\n"))
    assert "cannot be derived" in str(info.value)
    assert not (tmp_path / "rel").exists()
    assert load_config(_yaml(tmp_path, f"application:\n  audit_path: {tmp_path / 'a.jsonl'}\n")).application.audit_path


def test_i36_a_home_reported_as_a_filesystem_root_or_relative_derives_no_audit_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same rule on every OS: a USERPROFILE of 'C:\\' or a relative one
    derives no default either."""
    from universal_db_mcp.config import default_audit_path

    for root in (Path(tmp_path.anchor), Path("relative-home")):
        monkeypatch.setattr(Path, "home", staticmethod(lambda root=root: root))
        with pytest.raises(ConfigError, match="set application.audit_path"):
            default_audit_path(tmp_path / "c.yaml")
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path / "home"))
    assert default_audit_path(tmp_path / "c.yaml")[0] == tmp_path / "home" / ".universal-db-mcp" / "audit.jsonl"


# =============================================================================
# Integration wave, final round
# =============================================================================


# --- I32: a full Oracle Client reads ORACLE_HOME/network/admin ------------------


@pytest.mark.parametrize(
    ("home_dir", "state_key", "name"),
    [("lib", "audit_path", "tnsnames.ora"), ("bin", "metadata_cache_path", "sqlnet.ora")],
    ids=["posix_lib", "windows_bin"],
)
def test_i32_state_that_is_a_full_oracle_client_network_file_is_refused(
    tmp_path: Path, home_dir: str, state_key: str, name: str
) -> None:
    """With a full Oracle Client, lib_dir is ORACLE_HOME/lib (ORACLE_HOME\\bin
    on Windows) and the client's default network configuration is
    ORACLE_HOME/network/admin, one level up: its files are the client's
    files there too. Only those files: the directory is not lib_dir's."""
    oracle_home = tmp_path / "dbhome_1"
    lib_dir = oracle_home / home_dir
    lib_dir.mkdir(parents=True)
    admin = oracle_home / "network" / "admin"
    admin.mkdir(parents=True)
    (admin / "tnsnames.ora").write_text("client file")
    with pytest.raises(ConfigError, match="Oracle client reads") as info:
        load_config(_thick_cfg(tmp_path, lib_dir, state_key, admin / name))
    assert "connections.ora.options.lib_dir" in str(info.value)
    load_config(_thick_cfg(tmp_path, lib_dir, state_key, admin / "state.file"))
    assert (admin / "tnsnames.ora").read_text() == "client file"
    assert not (admin / "sqlnet.ora").exists()


# --- I33: the system config directory compares case-folded where names do --------


@pytest.mark.parametrize(("platform", "system"), [("darwin", True), ("win32", True), ("linux", False)])
def test_i33_a_case_variant_of_the_system_config_directory_is_the_system_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, _private_home: Path, platform: str, system: bool
) -> None:
    """realpath keeps the case it is given: on macOS's (and Windows')
    case-insensitive filesystem /ETC/Universal-DB-MCP/config.yaml is the
    service's config, and was classed per-user by a case-sensitive
    comparison. On Linux it names another directory."""
    from universal_db_mcp.agents import core as agents_core
    from universal_db_mcp.config import is_system_config

    if sys.platform == "win32" and platform == "linux":
        pytest.skip("Windows paths compare case-insensitively whatever sys.platform says")
    system_dir = tmp_path / "universal-db-mcp"
    system_dir.mkdir()
    (system_dir / "config.yaml").write_text("application:\n  transport: stdio\n")
    monkeypatch.setattr(agents_core, "system_config_dir", lambda: system_dir)
    monkeypatch.setattr(sys, "platform", platform)
    variant = tmp_path / "Universal-DB-MCP" / "config.yaml"
    assert is_system_config(system_dir / "config.yaml")
    assert is_system_config(variant) is system
    assert not is_system_config(tmp_path / "Universal-DB-MCP-site" / "config.yaml")
