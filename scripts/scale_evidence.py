#!/usr/bin/env python3
"""Scale evidence: the discovery tools against a large schema.

    .venv/bin/python scripts/scale_evidence.py --config config.scale.yaml

Times each tool on the `scale` schema (2,000 narrow tables, a 900-column
table, a 2,000,000-row table) through the same code path the MCP server
uses, records whether every ceiling and budget engaged the way the docs
promise, and writes test-evidence/scale/results.txt. Nothing here is
mocked; a slow or failing call is recorded as such.
"""
from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import json
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from universal_db_mcp.config import load_resolved  # noqa: E402
from universal_db_mcp.server import AppContext, build_server  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config.scale.yaml")
    ap.add_argument("--connection", default="scale_pg")
    args = ap.parse_args()
    app_cfg, resolved = load_resolved(Path(args.config))
    server = build_server(AppContext(app_cfg, resolved))
    cid = args.connection
    out: list[str] = [
        "# Scale evidence: discovery tools against a 2,000-table schema (PostgreSQL fixture, database scaledb)",
        f"date_utc: {dt.datetime.now(dt.UTC).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        f"policy: hard_query_timeout={app_cfg.security.hard_query_timeout_seconds}s "
        f"discovery_time_budget={app_cfg.security.discovery_time_budget_seconds}s "
        f"max_response_bytes={app_cfg.security.max_response_bytes} "
        f"profile_max_sample_rows={app_cfg.security.profile_max_sample_rows}",
        "",
    ]

    def timed(name: str, tool: str, params: dict[str, Any]) -> dict[str, Any] | None:
        t0 = time.monotonic()
        try:
            env = asyncio.run(server.call_tool(tool, params)).structured_content
        except Exception as exc:  # noqa: BLE001 - recorded, not hidden
            out.append(f"== {name}: FAILED after {time.monotonic() - t0:.1f}s: {type(exc).__name__}: {str(exc)[:200]}")
            return None
        size = len(json.dumps(env, default=str))
        out.append(f"== {name}: {time.monotonic() - t0:.2f}s, response {size:,} bytes"
                   + (f", warnings={env.get('warnings')}" if env.get("warnings") else ""))
        return env

    # 1. first listing (cold cache) and the catalog paged to the end
    env = timed("db_list_tables (cold metadata cache)", "db_list_tables", {"connection_id": cid, "schema": "scale"})
    env = timed("db_list_tables (warm)", "db_list_tables", {"connection_id": cid, "schema": "scale"})
    pages, tables, cursor, t0 = 0, 0, None, time.monotonic()
    while True:
        params = {"connection_id": cid, "schema": "scale", "page_size": 200, "cursor": cursor}
        env = asyncio.run(server.call_tool("db_get_catalog", params)).structured_content
        pages += 1
        tables += len(env["data"]["tables"])
        cursor = env.get("next_cursor")
        if not cursor or pages > 50:
            break
    total = time.monotonic() - t0
    out.append(
        f"== db_get_catalog paged to the end: {pages} pages of 200, {tables} tables, {total:.2f}s total "
        f"({total / pages:.2f}s per page)"
    )

    # 2. the wide and the tall table
    env = timed("db_profile_table wide (900 columns)", "db_profile_table",
                {"connection_id": cid, "object_name": "scale.wide"})
    if env:
        codes = [f["code"] for f in env["data"]["findings"]][:6]
        out.append(f"   columns profiled: {len(env['data']['columns'])} (cap applies), findings={codes}")
    env = timed("db_profile_table tall (2,000,000 rows, sample 50,000)", "db_profile_table",
                {"connection_id": cid, "object_name": "scale.tall", "sample_rows": 50000})
    if env:
        d = env["data"]
        codes = [f["code"] for f in d["findings"]]
        out.append(f"   sample={d['sample']['rows']} row_estimate={d['row_estimate']} findings={codes}")
    env = timed("db_explain tall by customer_id", "db_explain",
                {"connection_id": cid, "sql": "EXPLAIN SELECT * FROM scale.tall WHERE customer_id = 42"})
    if env:
        out.append(f"   plan: {str(env['data'].get('plan', {}).get('raw'))[:160]}")

    # 3. schema-wide review under the budget, paged
    env = timed("db_review_schema (max_tables=100, sample 1000)", "db_review_schema",
                {"connection_id": cid, "schema": "scale", "max_tables": 100, "sample_rows": 1000})
    if env:
        d = env["data"]
        sm = d["summary"]
        out.append(
            f"   reviewed={sm['tables_reviewed']}/{sm['tables_in_scope']} by_code={sm['by_code']} "
            f"budget_exhausted={d['budget_exhausted']} next_cursor={'yes' if env.get('next_cursor') else 'no'}"
        )
    env = timed("db_document_schema (page 100)", "db_document_schema",
                {"connection_id": cid, "schema": "scale", "page_size": 100})
    if env:
        out.append(
            f"   tables rendered={env['data']['tables']} chars={len(env['data']['markdown']):,} "
            f"next_cursor={'yes' if env.get('next_cursor') else 'no'}"
        )

    # 4. value search across 2,000 tables under the budget
    env = timed("db_search_values 'label-7' (max_tables=500, budget 60s)", "db_search_values",
                {"query": "label-7", "connections": [cid], "max_tables": 500, "time_budget_seconds": 60,
                 "max_hits_per_table": 1})
    if env:
        d = env["data"]
        out.append(f"   hits={len(d['hits'])} tables_searched={d['tables_searched']} "
                   f"not_searched={d.get('tables_not_searched')} budget_exhausted={d['budget_exhausted']}")
    env = timed("db_search_values 'note 1999999', whole schema (2,002 tables, per_table_timeout 5s, budget 120s)",
                "db_search_values",
                {"query": "note 1999999", "connections": [cid], "schemas": ["scale"], "max_tables": 500,
                 "per_table_timeout_seconds": 5, "time_budget_seconds": 120, "max_hits_per_table": 1})
    if env:
        d = env["data"]
        out.append(f"   hits={len(d['hits'])} tables_searched={d['tables_searched']} "
                   f"not_searched={d.get('tables_not_searched')} budget_exhausted={d['budget_exhausted']}")

    # 5. relationship inference over 2,000 tables (metadata only, capped)
    env = timed("db_infer_relationships (schema scale)", "db_infer_relationships",
                {"connections": [cid], "schemas": ["scale"]})
    if env:
        d = env["data"]
        out.append(f"   relationships={len(d['relationships'])} tables_considered={d.get('tables_considered')}")

    ev = ROOT / "test-evidence" / "scale"
    ev.mkdir(parents=True, exist_ok=True)
    text = "\n".join(out) + "\n"
    (ev / "results.txt").write_text(text, encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
