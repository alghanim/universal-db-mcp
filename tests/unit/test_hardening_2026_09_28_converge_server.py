"""Hardening wave 4 (2026-09-28), server and audit group, pinned end to end.

Audit retention: a statement is sent once the executor's worker thread
begins its driver call. A call that sent nothing (an unknown connection id,
a guard refusal, invalid arguments, the executor's own refusals, a
cancellation in line) is one record without its SQL text (its digest and
length are kept), and so is db_validate_query, which never sends one. Failed
calls of one kind (caller, action, outcome, category, connection id,
fingerprint) past the first few in a window are counted into one summary
record instead of written one by one, so a flood of cheap refusals cannot
rotate the evidence of an earlier read away, while distinct probes are still
written one by one up to the window's total. A db_query that ran keeps its
text once (its ':statement' record), every statement sent keeps its records
in full whatever the outcome, and the SQL text written per window is capped
(past it a record keeps the text's digest).

Metadata cache: an entry belongs to what the connection reaches (engine,
host, port, database, login, target options), not only to its id and
policy, so a connection id pointed at another database, or two configs
sharing one cache file, never serve each other's table list.

db_get_query_history says it holds the whole server process's history.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

import universal_db_mcp.server as srv
from universal_db_mcp.config import ConnectionConfig, ResolvedConnection, load_resolved
from universal_db_mcp.connectors.base import QuerySpec, TableSummary
from universal_db_mcp.connectors.sqlite import SQLiteConnector
from universal_db_mcp.errors import ToolFailure
from universal_db_mcp.models.responses import ErrorCategory
from universal_db_mcp.server import AppContext, build_server
from universal_db_mcp.services import audit, executor, metadata
from universal_db_mcp.services.audit import AuditLog, AuditWriteFailure
from universal_db_mcp.services.metadata import MetadataCache


def _db(path: Path, script: str) -> Path:
    c = sqlite3.connect(path)
    c.executescript(script)
    c.commit()
    c.close()
    return path


def _app(
    tmp_path: Path, databases: dict[str, Path], *, application: str = "", security: str = "", state: Path | None = None
) -> tuple[Any, AppContext]:
    state = state or tmp_path
    conns = "".join(f"  {name}:\n    type: sqlite\n    database: {db}\n" for name, db in databases.items())
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "application:\n  transport: stdio\n"
        f"  audit_path: {state / 'audit.jsonl'}\n"
        f"  metadata_cache_path: {state / 'cache.sqlite'}\n{application}"
        f"security:\n  max_concurrent_queries: 4\n{security}"
        f"connections:\n{conns}",
        encoding="utf-8",
    )
    app_cfg, resolved = load_resolved(cfg)
    app = AppContext(app_cfg, resolved)
    return build_server(app), app


_ORDERS = "CREATE TABLE orders (id INTEGER PRIMARY KEY, v TEXT); INSERT INTO orders VALUES (1, 'a');"


def _shop(tmp_path: Path, **kw: Any) -> tuple[Any, AppContext]:
    db = _db(tmp_path / "shop.db", _ORDERS)
    return _app(tmp_path, {"shop": db}, **kw)


def _call(server: Any, name: str, args: dict[str, Any]) -> dict[str, Any]:
    result = asyncio.run(server.call_tool(name, args))
    assert result.structured_content is not None
    return result.structured_content


def _call_error(server: Any, name: str, args: dict[str, Any]) -> str:
    with pytest.raises(Exception) as info:  # noqa: PT011 - the ToolError text is what is asserted
        _call(server, name, args)
    return str(info.value)


def _records(path: Path) -> list[dict[str, Any]]:
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    return [json.loads(line) for line in lines]


def _close_window(log: AuditLog, *, left: float = 0.0) -> None:
    """Age the log's current window so it closes in ``left`` seconds, however
    long the writes before took (a slow fsync on a loaded disk)."""
    window = log._coalescer._window
    assert window is not None
    log._coalescer._window = time.monotonic() - audit._COALESCE_WINDOW_SECONDS + left


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


# ------------------------------------------------ one record, no text, for a refusal


_BIG_SQL = "SELECT v FROM orders WHERE v = '" + "q" * 70_000 + "'"


@pytest.mark.parametrize(
    ("connection_id", "sql", "category"),
    [
        ("nope", _BIG_SQL, "AUTHORIZATION_DENIED"),  # an unknown connection id
        ("shop", "SELECT v FROM payroll WHERE v = 'secret-literal'", "POLICY_VIOLATION"),  # the guard's refusal
        ("shop", _BIG_SQL + " -- " + "z" * 10, "VALIDATION_ERROR"),  # over the statement ceiling
    ],
)
def test_a_statement_refused_before_it_ran_is_one_record_without_its_text(
    tmp_path: Path, connection_id: str, sql: str, category: str
) -> None:
    server, _ = _shop(tmp_path, security="  audit_sql_text: true\n")
    text = _call_error(server, "db_query", {"connection_id": connection_id, "sql": sql})
    assert category in text, text
    records = _records(tmp_path / "audit.jsonl")
    assert [(r["action"], r["outcome"], r["category"]) for r in records] == [("db_query", "deny", category)], records
    (record,) = records
    assert "sql_text" not in record and "secret-literal" not in json.dumps(record)
    assert record["sql_sha256"] == hashlib.sha256(sql.encode()).hexdigest()
    assert record["sql_len"] == len(sql)
    assert record["sql_fingerprint"].startswith("sha256:")


def test_a_statement_that_ran_keeps_both_records_and_its_text_once(tmp_path: Path) -> None:
    """The ':statement' record keeps the text; the call's own record names
    the same statement by the request id they share, its fingerprint and
    length. No unsalted digest of the unredacted statement sits beside the
    redacted text (it would confirm a guess of a scrubbed literal)."""
    server, _ = _shop(tmp_path, security="  audit_sql_text: true\n")
    sql = "SELECT v FROM orders WHERE id = 1 AND v <> 'password=hunter2'"
    env = _call(server, "db_query", {"connection_id": "shop", "sql": sql})
    # a statement the database refused ran all the same: its text is kept
    failed = "SELECT v FROM orders WHERE 1 = abs(-9223372036854775808)"
    _call_error(server, "db_query", {"connection_id": "shop", "sql": failed})
    records = _records(tmp_path / "audit.jsonl")
    ran = [(r["action"], r["outcome"], "sql_text" in r, r.get("sql_len")) for r in records]
    assert ran == [
        ("db_query:statement", "allow", True, None), ("db_query", "allow", False, len(sql)),
        ("db_query:statement", "error", True, None), ("db_query", "error", False, len(failed)),
    ], ran
    assert records[2]["sql_text"] == failed
    assert "hunter2" not in records[0]["sql_text"]
    assert not any("sql_sha256" in r for r in records), records
    assert records[0]["request_id"] == records[1]["request_id"] == env["request_id"]
    assert records[0]["sql_fingerprint"] == records[1]["sql_fingerprint"]


def test_db_validate_query_never_sends_its_statement_and_keeps_no_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An allowed call all the same: every one is written, none keeps text."""
    monkeypatch.setattr(audit, "_COALESCE_WINDOW_SECONDS", 3600.0)
    server, app = _shop(tmp_path, security="  audit_sql_text: true\n")
    sql = "SELECT v FROM orders -- " + "x" * 65_000
    for _ in range(audit._COALESCE_BURST + 3):
        assert _call(server, "db_validate_query", {"connection_id": "shop", "sql": sql})["data"]["valid"] is True
    app.audit.flush()
    records = _records(tmp_path / "audit.jsonl")
    assert [(r["action"], r["outcome"]) for r in records] == [("db_validate_query", "allow")] * 13, records
    assert all("sql_text" not in r and r["sql_sha256"] == _sha(sql) and r["sql_len"] == len(sql) for r in records)
    assert sum(len(line) for line in (tmp_path / "audit.jsonl").read_bytes().splitlines()) < 13 * 1024


def test_a_refusal_after_a_federated_statement_ran_keeps_that_statement(tmp_path: Path) -> None:
    """Each connection's statement is its own record; the one refused before
    it ran carries no text, the one that ran keeps it."""
    shop = _db(tmp_path / "shop.db", "CREATE TABLE orders (id INTEGER, v TEXT);")
    crm = _db(tmp_path / "crm.db", "CREATE TABLE accounts (id INTEGER);")
    server, _ = _app(tmp_path, {"shop": shop, "crm": crm}, security="  audit_sql_text: true\n")
    sql = "SELECT id FROM orders"
    _call(server, "db_federated_query", {"sql": sql})
    statements = sorted(
        (r["connection_id"], r["outcome"], "sql_text" in r)
        for r in _records(tmp_path / "audit.jsonl")
        if r["action"] == "db_federated_query:statement"
    )
    assert statements == [("crm", "deny", False), ("shop", "allow", True)], statements


def test_a_call_the_sdk_refused_is_one_record(tmp_path: Path) -> None:
    server, _ = _shop(tmp_path)
    _call_error(server, "db_query", {"connection_id": "shop", "sql": "SELECT 1", "max_rows": "lots"})
    records = _records(tmp_path / "audit.jsonl")
    assert [(r["action"], r["reason"]) for r in records] == [("db_query", "invalid arguments")]


# ------------------------------------------------ repeated refusals are coalesced


def test_repeated_refusals_are_counted_into_one_summary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(audit, "_COALESCE_WINDOW_SECONDS", 3600.0)
    server, app = _shop(tmp_path)
    for _ in range(300):
        text = _call_error(server, "db_query", {"connection_id": "nope", "sql": "SELECT * FROM t"})
        assert "AUTHORIZATION_DENIED" in text  # every caller still gets its refusal
    written = _records(tmp_path / "audit.jsonl")
    assert len(written) == audit._COALESCE_BURST, len(written)
    app.audit.flush()  # what the process does at exit
    summary = _records(tmp_path / "audit.jsonl")[-1]
    assert summary["event"] == "tool_call_summary"
    assert (summary["action"], summary["outcome"], summary["category"]) == ("db_query", "deny", "AUTHORIZATION_DENIED")
    assert summary["count"] == 300 - audit._COALESCE_BURST
    assert summary["caller"] == app.identity
    assert summary["connection_ids"] == ["nope"]
    assert summary["sql_fingerprints"] == [written[0]["sql_fingerprint"]]
    assert summary["first_ts"] <= summary["last_ts"] <= summary["ts"]
    # the history keeps every call, as it did
    assert len(app.history) == min(300, srv._HISTORY_CAP) and app.history[-1]["connection_id"] == "nope"


def test_distinct_probes_are_not_hidden_behind_a_repeated_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The kind names the statement and the connection: a caller that spends
    one kind's allowance on a cheap repeat has not bought silence for the
    probes after it. Each is written in full up to the window's total, and
    each counted one keeps its fingerprint in a summary of its own."""
    monkeypatch.setattr(audit, "_COALESCE_WINDOW_SECONDS", 3600.0)
    server, app = _shop(tmp_path)
    for _ in range(audit._COALESCE_BURST + 5):
        _call_error(server, "db_query", {"connection_id": "shop", "sql": "SELECT v FROM nothing_here"})
    probes = [f"SELECT v FROM secret_{i} WHERE id = {i}" for i in range(100)]
    for sql in probes:
        assert "POLICY_VIOLATION" in _call_error(server, "db_query", {"connection_id": "shop", "sql": sql})
    app.audit.flush()
    records = _records(tmp_path / "audit.jsonl")
    full = [r for r in records if r["event"] == "tool_call"]
    summaries = [r for r in records if r["event"] == "tool_call_summary"]
    assert len(full) == audit._COALESCE_FULL
    probe_prints = {srv.sql_fingerprint(sql) for sql in probes}
    assert len(probe_prints) == 100
    traced = {r["sql_fingerprint"] for r in full} | {f for s in summaries for f in s["sql_fingerprints"]}
    assert probe_prints <= traced, len(probe_prints - traced)
    assert all(len(s["sql_fingerprints"]) == 1 and s["connection_ids"] == ["shop"] for s in summaries)
    assert sum(s["count"] for s in summaries) == len(probes) + audit._COALESCE_BURST + 5 - audit._COALESCE_FULL


def test_the_full_records_of_a_window_are_capped_across_kinds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every kind within its own allowance, the window's total still holds."""
    monkeypatch.setattr(audit, "_COALESCE_WINDOW_SECONDS", 3600.0)
    path = tmp_path / "audit.jsonl"
    log = AuditLog(str(path))
    kinds = audit._COALESCE_FULL // audit._COALESCE_BURST + 1
    for k in range(kinds):
        for _ in range(audit._COALESCE_BURST + 1):
            log.record_refusal({"event": "tool_call", "caller": "svc", "action": f"db_{k}", "outcome": "deny",
                                "category": "POLICY_VIOLATION"})
    assert len(_records(path)) == audit._COALESCE_FULL
    log.flush()
    summaries = [r for r in _records(path) if r["event"] == "tool_call_summary"]
    assert sum(r["count"] for r in summaries) == kinds * (audit._COALESCE_BURST + 1) - audit._COALESCE_FULL


def test_the_summary_is_written_with_the_next_record_once_its_window_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(audit, "_COALESCE_WINDOW_SECONDS", 3600.0)
    server, app = _shop(tmp_path)
    for _ in range(audit._COALESCE_BURST + 5):
        _call_error(server, "db_list_tables", {"connection_id": "nope"})
    _close_window(app.audit)
    env = _call(server, "db_list_tables", {"connection_id": "shop"})
    records = _records(tmp_path / "audit.jsonl")
    assert [r.get("event") for r in records[-2:]] == ["tool_call_summary", "tool_call"]
    assert records[-2]["count"] == 5 and records[-1]["request_id"] == env["request_id"]
    # a new window writes the next refusals in full again
    _call_error(server, "db_list_tables", {"connection_id": "nope"})
    assert _records(tmp_path / "audit.jsonl")[-1]["action"] == "db_list_tables"


def test_the_summary_is_written_once_its_window_closed_even_when_nothing_else_comes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An idle server, or an HTTP server stopped by SIGTERM (uvicorn re-raises
    it, so no exit handler runs), still gets the counts on disk. The records
    written in full go under a long window, which is then made to close in
    0.2 s: the counted ones write nothing, so they fit however slow fsync is."""
    monkeypatch.setattr(audit, "_COALESCE_WINDOW_SECONDS", 3600.0)
    path = tmp_path / "audit.jsonl"
    log = AuditLog(str(path))
    event = {"event": "tool_call", "caller": "svc", "action": "db_query", "outcome": "deny", "category": "X"}
    for _ in range(audit._COALESCE_BURST):
        log.record_refusal(dict(event))
    _close_window(log, left=0.2)
    for _ in range(4):
        log.record_refusal(dict(event))
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and _records(path)[-1]["event"] != "tool_call_summary":
        time.sleep(0.05)
    assert _records(path)[-1]["event"] == "tool_call_summary" and _records(path)[-1]["count"] == 4
    # the next window's counts get a timer of their own
    for _ in range(audit._COALESCE_BURST):
        log.record_refusal(dict(event))
    _close_window(log, left=0.2)
    for _ in range(2):
        log.record_refusal(dict(event))
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and _records(path)[-1].get("count") != 2:
        time.sleep(0.05)
    assert [r.get("count") for r in _records(path) if r["event"] == "tool_call_summary"] == [4, 2]


@pytest.mark.parametrize("fail_closed", [True, False])
def test_a_summary_that_cannot_be_written_alone_is_kept_not_dropped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fail_closed: bool
) -> None:
    """A summary written on its own (the timer, the exit) that fails is
    kept for the next record: no call waits on it, nothing was lost."""
    path = tmp_path / "audit.jsonl"
    log = AuditLog(str(path), fail_closed=fail_closed)
    event = {"event": "tool_call", "caller": "svc", "action": "db_query", "outcome": "deny", "category": "X"}
    for _ in range(audit._COALESCE_BURST + 3):
        log.record_refusal(dict(event))
    real = log._append
    monkeypatch.setattr(log, "_append", lambda _line: (_ for _ in ()).throw(OSError(28, "No space left on device")))
    log.flush()  # no AuditWriteFailure: no call is waiting on it
    assert log.dropped_records == 0
    monkeypatch.setattr(log, "_append", real)
    log.record({"event": "tool_call", "action": "db_list_connections"})
    assert [r.get("count") for r in _records(path) if r["event"] == "tool_call_summary"] == [3]


def test_a_flood_of_refusals_cannot_rotate_the_evidence_of_a_read_away(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The reattack harness, scaled down: with audit_sql_text on, each refused
    call used to write two records of 66 KB each."""
    monkeypatch.setattr(audit, "_COALESCE_WINDOW_SECONDS", 3600.0)  # one window, however slow the host
    server, app = _shop(
        tmp_path, application="  audit_max_bytes: 262144\n  audit_max_backups: 1\n", security="  audit_sql_text: true\n"
    )
    evidence = _call(server, "db_query", {"connection_id": "shop", "sql": "SELECT v FROM orders"})["request_id"]
    for i in range(400):
        _call_error(server, "db_query", {"connection_id": "nope", "sql": _BIG_SQL + str(i)})
        _call_error(server, "db_list_tables", {"connection_id": f"x{i}"})  # a kind of its own, every one
        _call_error(server, "db_nope", {})
    app.audit.flush()
    kept = "".join(p.read_text(encoding="utf-8") for p in tmp_path.glob("audit.jsonl*") if not p.name.endswith(".lock"))
    assert evidence in kept
    records = [json.loads(line) for line in kept.splitlines()]
    refusals = [r for r in records if r["event"] == "tool_call" and r["outcome"] == "deny"]
    summaries = [r for r in records if r["event"] == "tool_call_summary"]
    assert len(refusals) == audit._COALESCE_FULL
    assert len(summaries) <= audit._COALESCE_KINDS + 1
    assert len(refusals) + sum(r["count"] for r in summaries) == 3 * 400  # every call written or counted
    counted = Counter()
    for r in summaries:
        counted[r["action"]] += r["count"]
    assert counted["db_query"] == counted["<unknown tool>"] == 400 - audit._COALESCE_BURST, counted


def test_repeated_guard_refusals_are_coalesced(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(audit, "_COALESCE_WINDOW_SECONDS", 3600.0)
    server, app = _shop(tmp_path)
    for _ in range(3 * audit._COALESCE_BURST):
        _call_error(server, "db_query", {"connection_id": "shop", "sql": "SELECT v FROM payroll"})
    app.audit.flush()
    records = _records(tmp_path / "audit.jsonl")
    assert [r.get("category") for r in records if r["event"] == "tool_call"] == ["POLICY_VIOLATION"] * 10
    assert records[-1]["event"] == "tool_call_summary" and records[-1]["count"] == 2 * audit._COALESCE_BURST


def test_coalescing_memory_is_bounded_whatever_the_kinds(tmp_path: Path) -> None:
    log = AuditLog(str(tmp_path / "audit.jsonl"))
    for i in range(5000):
        log.record_refusal({"event": "tool_call", "caller": "svc", "action": f"db_{i}", "outcome": "deny",
                            "category": "VALIDATION_ERROR", "connection_id": f"c{i}", "sql_fingerprint": f"sha256:{i}"})
    coalescer = log._coalescer
    assert len(coalescer._written) <= audit._COALESCE_KINDS
    assert len(coalescer._counted) <= audit._COALESCE_KINDS + 1
    assert all(len(t.connection_ids) <= audit._COALESCE_SAMPLES for t in coalescer._counted.values())
    assert len(_records(tmp_path / "audit.jsonl")) == audit._COALESCE_FULL
    log.flush()
    summaries = [r for r in _records(tmp_path / "audit.jsonl") if r["event"] == "tool_call_summary"]
    assert sum(r["count"] for r in summaries) == 5000 - audit._COALESCE_FULL
    assert len(summaries) <= audit._COALESCE_KINDS + 1
    assert any(r["action"] == "<other kinds>" for r in summaries)


def test_the_summaries_kept_while_the_log_cannot_be_written_stay_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Summaries whose write failed are kept for the next record: window
    after window of new kinds, with the disk full, they still fold into at
    most _COALESCE_KINDS + 1 tallies, and no count is lost."""
    monkeypatch.setattr(audit, "_COALESCE_WINDOW_SECONDS", 3600.0)
    log = AuditLog(str(tmp_path / "audit.jsonl"), fail_closed=False)
    monkeypatch.setattr(log, "_append", lambda _line: (_ for _ in ()).throw(OSError(28, "No space left on device")))
    per_window = audit._COALESCE_FULL + audit._COALESCE_KINDS + 10
    for window in range(4):
        for i in range(per_window):
            log.record_refusal({"event": "tool_call", "caller": "svc", "action": f"db_{window}_{i}", "outcome": "deny",
                                "category": "VALIDATION_ERROR"})
            assert len(log._coalescer._closed) <= audit._COALESCE_KINDS + 1
        _close_window(log)
    log.record_refusal({"event": "tool_call", "caller": "svc", "action": "db_last", "outcome": "deny"})
    closed = log._coalescer._closed
    assert len(closed) <= audit._COALESCE_KINDS + 1
    assert sum(t.count for t in closed.values()) == 4 * (per_window - audit._COALESCE_FULL)


def test_the_summary_timer_does_not_create_a_removed_audit_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Review round 2: the exit path left a removed directory alone, the
    timer created it again (a fresh audit.jsonl and lock) about a window
    later. Summaries alone never create it; their counts wait for the next
    record, which does."""
    # The burst (10 records written in full, 5 counted) must fit in one
    # window: a slow runner took longer than 0.3 s to write it, the window
    # rolled mid-burst and split the count. 2 s leaves room and still closes soon.
    monkeypatch.setattr(audit, "_COALESCE_WINDOW_SECONDS", 2.0)
    state = tmp_path / "state"
    log = AuditLog(str(state / "audit.jsonl"))
    event = {"event": "tool_call", "caller": "svc", "action": "db_query", "outcome": "deny", "category": "X"}
    for _ in range(audit._COALESCE_BURST + 5):
        log.record_refusal(dict(event))
    shutil.rmtree(state)
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline and not (state.exists() or log._coalescer._closed):
        time.sleep(0.02)
    assert not state.exists(), sorted(p.name for p in state.iterdir())
    assert [t.count for t in log._coalescer._closed.values()] == [5]
    log.flush()  # what the exit handler runs
    assert not state.exists()
    log.record({"event": "tool_call", "action": "db_list_connections"})
    assert [(r["event"], r.get("count")) for r in _records(state / "audit.jsonl")] == [
        ("tool_call_summary", 5), ("tool_call", None)
    ]


def test_the_counted_refusals_are_written_when_the_process_exits(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    script = (
        "from universal_db_mcp.services.audit import AuditLog, _COALESCE_BURST\n"
        f"log = AuditLog({str(path)!r})\n"
        "for i in range(_COALESCE_BURST + 5):\n"
        "    log.record_refusal({'event': 'tool_call', 'caller': 'svc', 'action': 'db_query', 'outcome': 'deny',"
        " 'category': 'X', 'connection_id': 'c1', 'request_id': f'r{i}'})\n"
    )
    src = Path(__file__).resolve().parents[2] / "src"
    subprocess.run(  # noqa: S603 - this interpreter, a fixed script
        [sys.executable, "-c", script], env={**os.environ, "PYTHONPATH": str(src)}, check=True, timeout=60
    )
    records = _records(path)
    assert len(records) == audit._COALESCE_BURST + 1
    assert records[-1]["event"] == "tool_call_summary" and records[-1]["count"] == 5
    assert records[-1]["connection_ids"] == ["c1"]


def test_a_refusal_whose_record_cannot_be_written_is_refused_every_time(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fail-closed: a record that was not written does not open the window;
    every call is refused until one is written."""
    log = AuditLog(str(tmp_path / "audit.jsonl"), fail_closed=True)

    def disk_full(_line: bytes) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(log, "_append", disk_full)
    event = {"event": "tool_call", "caller": "svc", "action": "db_query", "outcome": "deny", "category": "X"}
    for _ in range(3 * audit._COALESCE_BURST):
        with pytest.raises(AuditWriteFailure):
            log.record_refusal(dict(event))
    assert not log._coalescer._counted


def test_a_summary_whose_write_failed_is_written_later(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(audit, "_COALESCE_WINDOW_SECONDS", 3600.0)
    path = tmp_path / "audit.jsonl"
    log = AuditLog(str(path), fail_closed=True)
    event = {"event": "tool_call", "caller": "svc", "action": "db_query", "outcome": "deny", "category": "X"}
    for _ in range(audit._COALESCE_BURST + 3):
        log.record_refusal(dict(event))
    _close_window(log)
    real = log._append
    monkeypatch.setattr(log, "_append", lambda _line: (_ for _ in ()).throw(OSError(28, "No space left on device")))
    with pytest.raises(AuditWriteFailure):
        log.record({"event": "tool_call", "action": "db_list_connections"})
    monkeypatch.setattr(log, "_append", real)
    log.record({"event": "tool_call", "action": "db_list_connections"})
    summaries = [r for r in _records(path) if r["event"] == "tool_call_summary"]
    assert [s["count"] for s in summaries] == [3]


# ------------------------------------------------ sent means the driver call began

_PADDED = "SELECT v FROM orders -- " + "x" * 65_000


def _slow_statements(monkeypatch: pytest.MonkeyPatch) -> tuple[threading.Event, threading.Event]:
    """(started, release): a statement naming 'slow' holds its worker, and
    so its connection's gate, from ``started`` until ``release``."""
    started, release = threading.Event(), threading.Event()
    real = SQLiteConnector.execute_query

    def execute(self: SQLiteConnector, spec: QuerySpec) -> Any:
        if "slow" in spec.sql:
            started.set()
            release.wait(10)
        return real(self, spec)

    monkeypatch.setattr(SQLiteConnector, "execute_query", execute)
    return started, release


@pytest.mark.parametrize(
    ("category", "outcome"),
    [(ErrorCategory.LIMIT, "deny"), (ErrorCategory.CONNECTION, "error")],
)
def test_a_call_the_executor_refused_is_one_coalesced_record_without_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, category: str, outcome: str
) -> None:
    """What the fail-fast breaker raises (a poisoned connector, an abandoned
    worker, a hung server, a full stuck-connect budget) before any worker
    starts: nothing reached the database."""
    monkeypatch.setattr(audit, "_COALESCE_WINDOW_SECONDS", 3600.0)
    server, app = _shop(tmp_path, security="  audit_sql_text: true\n")
    _call(server, "db_list_tables", {"connection_id": "shop"})  # the guard's listing: the statement is what is refused

    def refuse(_self: Any, _connector: Any) -> None:
        raise ToolFailure(category, "refused by the executor; retry later")

    monkeypatch.setattr(executor.ExecutionService, "_refuse_if_unusable", refuse)
    for _ in range(audit._COALESCE_BURST + 3):
        assert category in _call_error(server, "db_query", {"connection_id": "shop", "sql": _PADDED})
    app.audit.flush()
    records = _records(tmp_path / "audit.jsonl")[1:]
    assert [(r["event"], r["action"], r["outcome"]) for r in records] == (
        [("tool_call", "db_query", outcome)] * audit._COALESCE_BURST + [("tool_call_summary", "db_query", outcome)]
    ), records
    assert records[-1]["count"] == 3
    assert all("sql_text" not in r and r["sql_sha256"] == _sha(_PADDED) for r in records[:-1])


def test_a_call_refused_in_line_for_a_busy_connection_sent_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The reviewer's LIMIT flood: one slow statement holds the connection's
    gate, and the calls queued behind it give up. Only the slow one ran."""
    monkeypatch.setattr(audit, "_COALESCE_WINDOW_SECONDS", 3600.0)
    monkeypatch.setattr(executor, "_MIN_QUEUE_SECONDS", 0.05)
    server, app = _shop(tmp_path, security="  audit_sql_text: true\n")
    started, release = _slow_statements(monkeypatch)
    slow_sql = "SELECT v AS slow FROM orders"
    queued = {"connection_id": "shop", "sql": _PADDED, "timeout_seconds": 0.01}

    async def main() -> list[str]:
        slow = asyncio.ensure_future(server.call_tool("db_query", {"connection_id": "shop", "sql": slow_sql}))
        try:
            assert await asyncio.to_thread(started.wait, 10)
            texts = []
            for _ in range(audit._COALESCE_BURST + 3):
                with pytest.raises(Exception) as info:  # noqa: PT011 - the ToolError text is asserted
                    await server.call_tool("db_query", queued)
                texts.append(str(info.value))
        finally:
            release.set()
            await slow
        return texts

    texts = asyncio.run(main())
    assert all("LIMIT_EXCEEDED" in t and "busy" in t for t in texts), texts
    app.audit.flush()
    records = _records(tmp_path / "audit.jsonl")
    shapes = Counter((r["event"], r["action"], r["outcome"], "sql_text" in r) for r in records)
    assert shapes == {
        ("tool_call", "db_query", "deny", False): audit._COALESCE_BURST,
        ("tool_call_summary", "db_query", "deny", False): 1,
        ("tool_call", "db_query:statement", "allow", True): 1,
        ("tool_call", "db_query", "allow", False): 1,
    }, shapes


def test_a_call_cancelled_in_line_keeps_no_text(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(audit, "_COALESCE_WINDOW_SECONDS", 3600.0)
    server, _ = _shop(tmp_path, security="  audit_sql_text: true\n")
    started, release = _slow_statements(monkeypatch)

    async def main() -> None:
        slow = asyncio.ensure_future(
            server.call_tool("db_query", {"connection_id": "shop", "sql": "SELECT v AS slow FROM orders"})
        )
        try:
            assert await asyncio.to_thread(started.wait, 10)
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(server.call_tool("db_query", {"connection_id": "shop", "sql": _PADDED}), 0.2)
        finally:
            release.set()
            await slow

    asyncio.run(main())
    (cancelled,) = [r for r in _records(tmp_path / "audit.jsonl") if r["outcome"] == "cancelled"]
    assert cancelled["action"] == "db_query" and "sql_text" not in cancelled
    assert cancelled["sql_sha256"] == _sha(_PADDED)


@pytest.mark.parametrize("tool", ["db_query", "db_federated_query"])
def test_a_statement_cancelled_in_flight_keeps_its_record_and_its_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tool: str
) -> None:
    """The worker had begun the driver call when the caller cancelled: the
    statement reached the database, and its record says so."""
    monkeypatch.setattr(audit, "_COALESCE_WINDOW_SECONDS", 3600.0)
    server, _ = _shop(tmp_path, security="  audit_sql_text: true\n")
    started, release = _slow_statements(monkeypatch)
    sql = "SELECT v AS slow FROM orders"
    args = {"connection_id": "shop", "sql": sql} if tool == "db_query" else {"sql": sql}

    async def main() -> None:
        call = asyncio.ensure_future(server.call_tool(tool, args))
        try:
            assert await asyncio.to_thread(started.wait, 10)
            call.cancel()
            with pytest.raises(asyncio.CancelledError):
                await call
        finally:
            release.set()

    asyncio.run(main())
    records = _records(tmp_path / "audit.jsonl")
    shapes = [(r["action"], r["outcome"], r.get("sql_text")) for r in records]
    assert shapes == [(f"{tool}:statement", "cancelled", sql), (tool, "cancelled", None)], shapes
    if tool == "db_query":
        assert records[1]["sql_len"] == len(sql) and "sql_sha256" not in records[1]


# ------------------------------------------------ a deny after the statement ran is kept whole


def test_a_plan_refused_after_explain_ran_keeps_every_record_and_its_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MySQL's TREE and JSON plans are refused after EXPLAIN reached the
    database: each such call is written in full, with its text."""
    from test_hardening_2026_09_28_final_guard_server import _MYSQL_TREE, _app_server

    monkeypatch.setattr(audit, "_COALESCE_WINDOW_SECONDS", 3600.0)
    catalog = [TableSummary("ocean", "buoys", "table"), TableSummary("ocean", "readings", "table")]
    server, fake = _app_server(tmp_path, monkeypatch, "mysql", ["ocean"], catalog,
                               security="  mask_columns: [station]\n  audit_sql_text: true\n")
    sent: list[str] = []

    def explain(sql: str, _analyze: bool) -> dict[str, Any]:
        sent.append(sql)
        return {"raw": _MYSQL_TREE}

    fake.explain = explain
    sql = ("EXPLAIN FORMAT=TREE SELECT r.buoy_id FROM ocean.buoys b JOIN ocean.readings r ON r.station = b.station"
           " WHERE b.buoy_id = 1")
    calls = audit._COALESCE_BURST + 3
    for _ in range(calls):
        assert "POLICY_VIOLATION" in _call_error(server, "db_explain", {"connection_id": "remote", "sql": sql})
    assert len(sent) == calls
    records = _records(tmp_path / "audit.jsonl")  # counted ones would be missing: none may be
    assert [(r["event"], r["action"], r["outcome"], r.get("sql_text")) for r in records] == (
        [("tool_call", "db_explain", "deny", sql)] * calls
    ), records


def test_a_health_check_that_failed_after_it_started_is_written_every_time(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The health check reached the driver: its failure is not coalesced."""
    monkeypatch.setattr(audit, "_COALESCE_WINDOW_SECONDS", 3600.0)
    server, _ = _app(tmp_path, {"gone": tmp_path / "missing.db"})
    calls = audit._COALESCE_BURST + 3
    for _ in range(calls):
        env = _call(server, "db_test_connection", {"connection_id": "gone"})
        assert env["data"]["healthy"] is False, env

    def unhealthy(_self: SQLiteConnector) -> Any:
        raise RuntimeError("the driver failed mid-check")

    monkeypatch.setattr(SQLiteConnector, "health_check", unhealthy)
    for _ in range(calls):
        assert "INTERNAL_ERROR" in _call_error(server, "db_test_connection", {"connection_id": "gone"})
    records = _records(tmp_path / "audit.jsonl")
    assert Counter((r["event"], r["outcome"]) for r in records) == {
        ("tool_call", "allow"): calls, ("tool_call", "error"): calls,
    }, records


@pytest.mark.parametrize(
    ("tool", "args", "statement_text"),
    [
        ("db_query", {"connection_id": "shop", "sql": "SELECT v FROM orders"}, "SELECT v FROM orders"),
        ("db_sample_table", {"connection_id": "shop", "object_name": "orders"}, None),
    ],
)
def test_a_response_refused_after_the_statement_ran_keeps_every_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tool: str, args: dict[str, Any], statement_text: str | None
) -> None:
    """The response ceiling's backstop refuses a call after its statement
    ran: every call's records are written in full, none is counted."""
    monkeypatch.setattr(audit, "_COALESCE_WINDOW_SECONDS", 3600.0)
    monkeypatch.setattr(srv, "_RESPONSE_SLACK", -(10**9))  # every response is over the ceiling
    server, app = _shop(tmp_path, security="  audit_sql_text: true\n")
    calls = audit._COALESCE_BURST + 3
    for _ in range(calls):
        assert "LIMIT_EXCEEDED" in _call_error(server, tool, args)
    app.audit.flush()
    records = _records(tmp_path / "audit.jsonl")
    shapes = Counter((r["event"], r["action"], r["outcome"], "sql_text" in r) for r in records)
    assert shapes == {
        ("tool_call", f"{tool}:statement", "allow", True): calls,
        ("tool_call", tool, "deny", False): calls,
    }, shapes
    if statement_text is not None:
        assert all(r["sql_text"] == statement_text for r in records if r["action"] == f"{tool}:statement")
        assert all(r["sql_len"] == len(statement_text) for r in records if r["action"] == tool)


# ------------------------------------------------ the SQL text written per window is capped


def _ends_fit(head: str, tail: str) -> bool:
    return all(len(json.dumps(end)) - 2 <= audit._SQL_TEXT_ENDS for end in (head, tail))


def test_the_sql_text_written_per_window_is_capped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Past the window's budget a record keeps its text's head and tail, the
    digest and length of the whole, and says why and how much was left out;
    the statement's own digest and length stay. A new window has the whole
    budget again."""
    monkeypatch.setattr(audit, "_COALESCE_WINDOW_SECONDS", 3600.0)
    path = tmp_path / "audit.jsonl"
    log = AuditLog(str(path))
    text = "SELECT v FROM orders -- " + "x" * 60_000 + " -- the end"
    for i in range(30):
        log.record({"event": "tool_call", "i": i, "sql_text": text, "sql_text_truncated": True,
                    "sql_sha256": "of-the-statement", "sql_len": 70_000})
    records = _records(path)
    whole = [r["i"] for r in records if r["sql_text"] == text]
    assert whole == list(range(len(whole))) and 10 < len(whole) < 30, whole
    assert log._coalescer._text <= audit._SQL_TEXT_BUDGET
    for r, line in zip(records[len(whole):], path.read_bytes().splitlines()[len(whole):], strict=True):
        head, tail = r["sql_text"], r["sql_text_tail"]
        assert text.startswith(head) and text.endswith(tail) and tail.endswith(" -- the end") and _ends_fit(head, tail)
        assert r["sql_text_omitted"] == {
            "reason": "per-window text budget spent", "chars": len(text) - len(head) - len(tail),
            "sha256": _sha(text), "len": len(text),
        }
        assert r["sql_text_truncated"] is True and (r["sql_sha256"], r["sql_len"]) == ("of-the-statement", 70_000)
        assert len(line) < 3 * audit._SQL_TEXT_ENDS
    # a text just past the ends is kept whole: its ends and their marker would take more
    just_past = "SELECT 1 -- " + "y" * (2 * audit._SQL_TEXT_ENDS + 20)
    log.record({"event": "tool_call", "i": "just past", "sql_text": just_past})
    assert _records(path)[-1]["sql_text"] == just_past
    _close_window(log)
    log.record({"event": "tool_call", "i": "next", "sql_text": text})
    assert _records(path)[-1]["sql_text"] == text


def test_text_spent_in_a_closed_window_is_not_refunded_from_the_next() -> None:
    coalescer = audit._Coalescer()
    first = coalescer.spend_text(1000)
    assert first is not None
    coalescer._window = time.monotonic() - audit._COALESCE_WINDOW_SECONDS  # the window closes
    assert coalescer.spend_text(300) is not None
    coalescer.refund_text(1000, first)  # the first window's write failed late
    assert coalescer._text == 300
    assert coalescer.spend_text(audit._SQL_TEXT_BUDGET) is None


def test_a_caller_that_spent_the_text_budget_cannot_strip_the_text_of_a_short_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Review round 2: padded allowed calls (halving the padding each time a
    record lost its text) spent the window's whole SQL text budget in under
    a second, and every statement run in the window after them, a real read
    included, lost its text. The ends of every statement sent are kept
    whatever the budget: a short one whole, a padded one its head and tail."""
    monkeypatch.setattr(audit, "_COALESCE_WINDOW_SECONDS", 3600.0)
    server, app = _shop(tmp_path, security="  audit_sql_text: true\n")
    path = tmp_path / "audit.jsonl"

    def statement_record(sql: str) -> dict[str, Any]:
        _call(server, "db_query", {"connection_id": "shop", "sql": sql})
        return [r for r in _records(path) if r["action"] == "db_query:statement"][-1]

    size = 64_000
    for i in range(60):
        if statement_record("SELECT v FROM orders --" + "x" * size + f" {i}").get("sql_text_omitted"):
            size //= 2
    assert audit._SQL_TEXT_BUDGET - 8 * 1024 < app.audit._coalescer._text <= audit._SQL_TEXT_BUDGET
    padded = "SELECT v FROM orders -- " + "x" * 64_000 + " -- last"
    record = statement_record(padded)
    assert padded.startswith(record["sql_text"]) and record["sql_text_tail"].endswith(" -- last")
    assert record["sql_text_omitted"]["sha256"] == _sha(padded)
    for sql in ("SELECT v FROM orders WHERE id = 1 -- the marker",
                "SELECT v FROM orders WHERE v IN (" + ", ".join(f"'v{i}'" for i in range(200)) + ")"):
        record = statement_record(sql)
        assert record["sql_text"] == sql and "sql_text_omitted" not in record, record


def test_the_text_budget_is_charged_the_bytes_written_not_the_characters(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Review round 2: non-ASCII text is written escaped (six bytes for an
    'é'); charged by characters, a site's Arabic statements would overrun
    the budget six times over."""
    monkeypatch.setattr(audit, "_COALESCE_WINDOW_SECONDS", 3600.0)
    path = tmp_path / "audit.jsonl"
    log = AuditLog(str(path))
    text = "SELECT 1 -- " + "é" * 10_000
    log.record({"event": "tool_call", "sql_text": text})
    assert _records(path)[-1]["sql_text"] == text
    written = len(json.dumps(text)) - 2  # 60,012 bytes for 10,012 characters
    assert written - 2 * audit._SQL_TEXT_ENDS - 512 < log._coalescer._text <= written - 2 * audit._SQL_TEXT_ENDS
    # fewer characters than the ends hold, more bytes than they take
    before, short = log._coalescer._text, "é" * audit._SQL_TEXT_ENDS
    log.record({"event": "tool_call", "sql_text": short})
    assert _records(path)[-1]["sql_text"] == short
    assert log._coalescer._text - before > 6 * audit._SQL_TEXT_ENDS - 2 * audit._SQL_TEXT_ENDS - 512


def test_a_text_too_long_for_one_record_keeps_its_ends_and_costs_no_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Review round 2: 64,000 'é' (384 KB written) are past the 128 KiB line
    cap, which replaced the text with its digest, and the budget was charged
    the full 384 KB all the same: three such calls spent it and wrote no
    text at all."""
    monkeypatch.setattr(audit, "_COALESCE_WINDOW_SECONDS", 3600.0)
    path = tmp_path / "audit.jsonl"
    log = AuditLog(str(path))
    text = "SELECT 1 -- " + "é" * 64_000
    for _ in range(5):
        log.record({"event": "tool_call", "sql_text": text})
    assert log._coalescer._text == 0
    lines = path.read_bytes().splitlines()
    assert len(lines) == 5 and all(len(line) < 3 * audit._SQL_TEXT_ENDS for line in lines)
    for r in _records(path):
        assert r["sql_text"].startswith("SELECT 1 -- é") and r["sql_text_tail"] == "é" * len(r["sql_text_tail"])
        assert _ends_fit(r["sql_text"], r["sql_text_tail"]) and len(r["sql_text_tail"]) > 100
        assert r["sql_text_omitted"]["sha256"] == _sha(text)
        assert r["sql_text_omitted"]["reason"] == "longer than one record holds (128 KiB)"


@pytest.mark.parametrize("fail_closed", [True, False])
def test_a_record_that_was_not_written_spends_no_text_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fail_closed: bool
) -> None:
    monkeypatch.setattr(audit, "_COALESCE_WINDOW_SECONDS", 3600.0)
    log = AuditLog(str(tmp_path / "audit.jsonl"), fail_closed=fail_closed)
    real = log._append
    monkeypatch.setattr(log, "_append", lambda _line: (_ for _ in ()).throw(OSError(28, "No space left on device")))
    text = "SELECT v FROM orders -- " + "x" * 60_000
    for _ in range(40):
        try:
            log.record({"event": "tool_call", "sql_text": text})
        except AuditWriteFailure:
            assert fail_closed
    assert log._coalescer._text == 0
    monkeypatch.setattr(log, "_append", real)
    log.record({"event": "tool_call", "sql_text": text})
    assert _records(tmp_path / "audit.jsonl")[-1]["sql_text"] == text


def test_a_flood_of_allowed_padded_statements_cannot_rotate_the_evidence_away(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The reviewer's allowed-db_query amplifier: a trivial statement padded
    to 64 KiB wrote its text twice per call. What a window writes is its
    text budget and, per call, the two records with the ends of the text."""
    monkeypatch.setattr(audit, "_COALESCE_WINDOW_SECONDS", 3600.0)
    retention = 2 * audit._SQL_TEXT_BUDGET
    server, _ = _shop(
        tmp_path, application=f"  audit_max_bytes: {retention // 2}\n  audit_max_backups: 1\n",
        security="  audit_sql_text: true\n",
    )
    evidence = _call(server, "db_query", {"connection_id": "shop", "sql": "SELECT v FROM orders"})["request_id"]
    for i in range(60):
        _call(server, "db_query", {"connection_id": "shop", "sql": _PADDED + str(i)})
    kept = "".join(p.read_text(encoding="utf-8") for p in tmp_path.glob("audit.jsonl*") if not p.name.endswith(".lock"))
    assert evidence in kept
    assert len(kept) < audit._SQL_TEXT_BUDGET + 61 * (2 * audit._SQL_TEXT_ENDS + 2048)
    records = [json.loads(line) for line in kept.splitlines()]
    assert len(records) == 2 * 61
    assert any(r.get("sql_text_omitted") for r in records)


# ------------------------------------------------ the audit lock messages (I35 report)


def test_a_record_that_waits_briefly_says_an_earlier_one_waited_the_full_time(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The caller of a two-record call sees the second record's failure: it
    says the full wait was spent by an earlier record."""
    monkeypatch.setattr(audit, "_LOCK_WAIT_SECONDS", 0.3)
    monkeypatch.setattr(audit, "_CONTENDED_WAIT_SECONDS", 0.1)
    path = tmp_path / "audit.jsonl"
    log = AuditLog(str(path), fail_closed=True)
    assert log._lock.acquire(timeout=5)  # what a thread stuck in fsync holds
    try:
        with pytest.raises(AuditWriteFailure) as first:
            log.record({"event": "a"})
        with pytest.raises(AuditWriteFailure) as second:
            log.record({"event": "b"})
    finally:
        log._lock.release()
    assert "for more than 0.3 s" in str(first.value) and "earlier record" not in str(first.value)
    assert "for more than 0.1 s, after an earlier record gave up waiting 0.3 s" in str(second.value), second.value


# ------------------------------------------------ the metadata cache knows its target


def test_a_repointed_connection_id_never_serves_the_other_databases_listing(tmp_path: Path) -> None:
    """The reattack harness: one cache file, connection 'lite' first a.db
    (orders), then b.db (payroll), within the TTL."""
    a = _db(tmp_path / "a.db", _ORDERS)
    b = _db(tmp_path / "b.db", "CREATE TABLE payroll (id INTEGER, v TEXT); INSERT INTO payroll VALUES (1, 'b');")
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    def listed(server: Any) -> list[str]:
        return [t["name"] for t in _call(server, "db_list_tables", {"connection_id": "lite"})["data"]["tables"]]

    assert listed(_app(tmp_path, {"lite": a}, state=state)[0]) == ["orders"]
    second, _ = _app(tmp_path, {"lite": b}, state=state)
    assert listed(second) == ["payroll"]
    rows = _call(second, "db_query", {"connection_id": "lite", "sql": "SELECT v FROM payroll"})["data"]["rows"]
    assert rows == [["b"]]
    # and the first target's entry is still its own
    assert listed(_app(tmp_path, {"lite": a}, state=state)[0]) == ["orders"]


def _resolved(**config: Any) -> ResolvedConnection:
    return ResolvedConnection("c1", ConnectionConfig(**config))


_BASE: dict[str, Any] = {"type": "postgres", "host": "db.example", "port": 5432, "database": "prod",
                         "username_env": "UDBMCP_TEST_TARGET_USER"}
_MYSQL = {**_BASE, "type": "mysql", "port": 3306, "options": {"unix_socket": "/run/mysqld/a.sock"}}
_ALIAS = {**_BASE, "type": "oracle", "host": "tns", "port": None,
          "options": {"tns_alias": "FINPROD", "tns_admin": "/etc/udbmcp/tns"}}
_SID = {**_BASE, "type": "oracle", "port": 1521, "options": {"sid": "FIN"}}


@pytest.mark.parametrize(
    ("base", "change"),
    [
        (_BASE, {"host": "db2.example"}),
        (_BASE, {"port": 5433}),
        (_BASE, {"database": "staging"}),
        (_BASE, {"username_env": "UDBMCP_TEST_TARGET_OTHER"}),
        (_BASE, {"options": {"service": "reports"}}),
        (_MYSQL, {"options": {"unix_socket": "/run/mysqld/b.sock"}}),
        (_ALIAS, {"options": {"tns_alias": "HRPROD", "tns_admin": "/etc/udbmcp/tns"}}),
        (_ALIAS, {"options": {"tns_alias": "FINPROD", "tns_admin": "/etc/udbmcp/other"}}),
        (_SID, {"options": {"sid": "HR"}}),
    ],
)
def test_the_cache_target_changes_with_what_the_connection_reaches(
    monkeypatch: pytest.MonkeyPatch, base: dict[str, Any], change: dict[str, Any]
) -> None:
    monkeypatch.setenv("UDBMCP_TEST_TARGET_USER", "reporter")
    monkeypatch.setenv("UDBMCP_TEST_TARGET_OTHER", "reporter")
    assert metadata.connection_target(_resolved(**base)) == metadata.connection_target(_resolved(**base))
    assert metadata.connection_target(_resolved(**base)) != metadata.connection_target(_resolved(**{**base, **change}))


def test_the_cache_target_follows_the_login_and_the_sqlite_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("UDBMCP_TEST_TARGET_USER", "reporter")
    before = metadata.connection_target(_resolved(**_BASE))
    monkeypatch.setenv("UDBMCP_TEST_TARGET_USER", "auditor")  # the same variable, another login
    assert metadata.connection_target(_resolved(**_BASE)) != before
    monkeypatch.chdir(tmp_path)
    (tmp_path / "one").mkdir()
    relative = metadata.connection_target(_resolved(type="sqlite", database="data.db"))
    monkeypatch.chdir(tmp_path / "one")  # the connector resolves a relative path against the working directory
    assert metadata.connection_target(_resolved(type="sqlite", database="data.db")) != relative
    absolute = metadata.connection_target(_resolved(type="sqlite", database=str(tmp_path / "one" / "data.db")))
    assert absolute == metadata.connection_target(_resolved(type="sqlite", database="data.db"))


def test_the_cache_target_leaves_out_the_wallet_password(monkeypatch: pytest.MonkeyPatch) -> None:
    """The resolved Oracle wallet password is handed to the connector in
    options; an unsalted digest of it must not reach the cache file's keys
    (it would confirm a guess), so a new password is the same target."""
    monkeypatch.setenv("UDBMCP_TEST_TARGET_USER", "reporter")
    monkeypatch.setenv("UDBMCP_TEST_TARGET_WALLET", "first-wallet-secret")
    config = {**_SID, "options": {"sid": "FIN", "wallet_password_env": "UDBMCP_TEST_TARGET_WALLET"}}
    first = _resolved(**config)
    monkeypatch.setenv("UDBMCP_TEST_TARGET_WALLET", "second-wallet-secret")
    second = _resolved(**config)
    assert (first.config.options["wallet_password"], second.config.options["wallet_password"]) == (
        "first-wallet-secret", "second-wallet-secret"
    )
    assert metadata.connection_target(first) == metadata.connection_target(second)
    assert metadata.connection_target(first) != metadata.connection_target(_resolved(**_SID))


def test_a_cache_entry_is_served_only_to_its_target(tmp_path: Path) -> None:
    cache = MetadataCache(str(tmp_path / "cache.sqlite"))
    tables = [TableSummary(schema="main", name="orders", kind="table")]
    cache.put_tables("c1", "fp", tables, target="t-a")
    assert cache.get_tables("c1", "fp", target="t-a") == tables
    assert cache.get_tables("c1", "fp", target="t-b") is None
    assert cache.get_tables("c1", "fp") is None


def test_invalidating_one_connection_leaves_the_others(tmp_path: Path) -> None:
    """A '_' in a connection id is a LIKE wildcard."""
    path = tmp_path / "cache.sqlite"
    cache = MetadataCache(str(path))
    tables = [TableSummary(schema="main", name="orders", kind="table")]
    for cid in ("a_b", "aXb", "a_b2"):
        cache.put_tables(cid, "fp", tables, target="t")
    cache.invalidate_connection("a_b")
    assert cache.get_tables("a_b", "fp", target="t") is None
    assert cache.get_tables("aXb", "fp", target="t") == tables
    assert cache.get_tables("a_b2", "fp", target="t") == tables


# ------------------------------------------------ db_get_query_history is per process


def test_the_history_tool_says_it_holds_the_whole_process(tmp_path: Path) -> None:
    server, _ = _shop(tmp_path)
    tools = {t.name: t for t in asyncio.run(server.list_tools())}
    description = tools["db_get_query_history"].description or ""
    for text in (description, _call(server, "db_get_query_history", {})["data"]["note"]):
        assert "caller-scoped" not in text.lower(), text
        assert "server process" in text and "every client's calls" in text, text
