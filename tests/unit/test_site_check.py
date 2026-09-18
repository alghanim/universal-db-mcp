"""site-check: a structured first run that never carries a row value."""
from __future__ import annotations

import json
from pathlib import Path

from test_discovery_tools import _seed

from universal_db_mcp.diagnostics.site_check import render_summary, run_site_check


def test_site_check_runs_every_step_on_sqlite_and_leaks_no_values(tmp_path: Path) -> None:
    db = tmp_path / "shop.db"
    _seed(db)
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "application:\n  transport: stdio\n"
        f"  audit_path: {tmp_path / 'audit.jsonl'}\n"
        f"  metadata_cache_path: {tmp_path / 'cache.sqlite'}\n"
        "security:\n  mask_columns: ['(?i)ssn']\n"
        f"connections:\n  shop:\n    type: sqlite\n    database: {db}\n",
        encoding="utf-8",
    )
    report = run_site_check(str(cfg), sample_rows=20, review_tables=2)
    assert report["ok"] is True, report["summary"]
    steps = {s["step"]: s for s in report["connections"]["shop"]["steps"]}
    assert set(steps) == {"connection", "list_tables", "catalog", "profile", "explain", "review", "search"}
    assert all(s["status"] == "ok" for s in steps.values())
    assert steps["connection"]["summary"]["read_only_enforced"] is True
    assert steps["list_tables"]["summary"]["tables"] >= 4  # tables plus the seeded view
    assert steps["profile"]["summary"]["columns_profiled"] >= 1
    assert steps["search"]["summary"]["hits"] == 0
    text = json.dumps(report)
    for value in ("user12@", "123-45-0007", "SKU-7"):
        assert value not in text, f"row value {value!r} leaked into the site-check report"
    summary = render_summary(report)
    assert "shop (sqlite): connection=ok list_tables=ok catalog=ok profile=ok explain=ok review=ok search=ok" in summary
    assert "connections healthy 1/1" in summary


def test_site_check_reports_an_unreachable_connection_as_failed(tmp_path: Path) -> None:
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "application:\n  transport: stdio\n"
        f"  audit_path: {tmp_path / 'audit.jsonl'}\n"
        f"  metadata_cache_path: {tmp_path / 'cache.sqlite'}\n"
        f"connections:\n  ghost:\n    type: sqlite\n    database: {tmp_path / 'missing.db'}\n",
        encoding="utf-8",
    )
    report = run_site_check(str(cfg))
    assert report["ok"] is False
    steps = report["connections"]["ghost"]["steps"]
    assert steps[0]["step"] == "connection" and len(steps) == 1
    assert report["summary"]["connections_healthy"] == 0
