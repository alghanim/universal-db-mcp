"""Audit log redaction/fail-closed and metadata cache scoping."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from universal_db_mcp.connectors.base import TableSummary
from universal_db_mcp.security.redact import SecretMark, sql_fingerprint
from universal_db_mcp.services.audit import AuditLog, AuditWriteFailure
from universal_db_mcp.services.metadata import MetadataCache, rank_search


def test_audit_redacts_and_fingerprints(tmp_path: Path) -> None:
    log = AuditLog(str(tmp_path / "audit.jsonl"))
    log.record(
        {
            "event": "tool_call",
            "caller": "alice",
            "password": SecretMark("hunter2"),
            "sql_fingerprint": sql_fingerprint("SELECT * FROM t WHERE a = 1"),
        }
    )
    rec = json.loads((tmp_path / "audit.jsonl").read_text())
    assert rec["password"] == "<redacted>"
    assert rec["caller"] == "alice"
    assert rec["sql_fingerprint"].startswith("sha256:")


def test_audit_fail_closed(tmp_path: Path) -> None:
    log = AuditLog(str(tmp_path / "missing_dir_sub" / "audit.jsonl"), fail_closed=True)
    # make the write fail by pointing at a directory that cannot exist
    log = AuditLog("/proc/definitely/not/writable/audit.jsonl", fail_closed=True)
    with pytest.raises(AuditWriteFailure):
        log.record({"event": "x"})


def test_audit_fail_open(tmp_path: Path) -> None:
    log = AuditLog("/proc/definitely/not/writable/audit.jsonl", fail_closed=False)
    log.record({"event": "x"})  # must not raise


def test_audit_rotation(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    log = AuditLog(str(p), max_bytes=200, max_backups=2)
    for i in range(20):
        log.record({"event": "x", "i": i, "pad": "z" * 30})
    assert p.with_suffix(".jsonl.1").exists()
    assert not p.with_suffix(".jsonl.3").exists()


def test_metadata_cache_policy_scoped(tmp_path: Path) -> None:
    cache = MetadataCache(str(tmp_path / "cache.sqlite"))
    tables = [TableSummary(schema="main", name="customers", kind="table")]
    cache.put_tables("c1", "policyA", tables)
    assert cache.get_tables("c1", "policyA") == tables
    # different policy fingerprint must not see the entry
    assert cache.get_tables("c1", "policyB") is None
    assert cache.get_tables("c2", "policyA") is None


def test_metadata_cache_ttl(tmp_path: Path) -> None:
    cache = MetadataCache(str(tmp_path / "cache.sqlite"), ttl_seconds=0.05)
    tables = [TableSummary(schema="main", name="customers", kind="table")]
    cache.put_tables("c1", "p", tables)
    time.sleep(0.08)
    assert cache.get_tables("c1", "p") is None


def test_rank_search_deterministic() -> None:
    items = [
        ("c1", "main", "customer_accounts", "table"),
        ("c1", "main", "customers", "table"),
        ("c2", "main", "customer_events", "table"),
    ]
    r1 = rank_search("customer", items, 10)
    r2 = rank_search("customer", list(reversed(items)), 10)
    assert [x["name"] for x in r1] == [x["name"] for x in r2]  # deterministic
    assert all("matched_because" in x for x in r1)
    exact = rank_search("customers", items, 10)
    assert exact[0]["name"] == "customers"  # exact match outranks prefix
    assert exact[0]["matched_because"] == ["exact name match"]


def test_rank_search_no_results() -> None:
    assert rank_search("zzz", [("c", "s", "t", "table")], 10) == []
