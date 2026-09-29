"""`site-check`: a structured, read-only first run at a site.

Runs the tools an agent would use, on every configured connection, through
the same server code path, and records for each step whether it passed,
how long it took and a summary made only of counts, codes, names and
server versions. No row value, no MIN/MAX, no top value and no secret ever
enters the report, so the JSON can leave the site for diagnosis.
"""
from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import json
import os
import stat
import tempfile
import time
from pathlib import Path
from typing import Any

from universal_db_mcp.config import load_resolved
from universal_db_mcp.server import AppContext, build_server

SEARCH_NEEDLE = "zz-udbmcp-site-check-needle"  # deliberately absent: exercises the search path, returns nothing


def _short(exc: BaseException) -> str:
    text = str(exc)
    return text[:240]


class _Runner:
    def __init__(self, server: Any) -> None:
        self.server = server

    def call(self, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        result = asyncio.run(self.server.call_tool(tool, args))
        if result.structured_content is None:
            raise RuntimeError(f"{tool} returned no structured content")
        return dict(result.structured_content)


def _check_connection(
    runner: _Runner, cid: str, engine: str, *, sample_rows: int, review_tables: int, search_budget_seconds: float
) -> dict[str, Any]:
    entry: dict[str, Any] = {"engine": engine, "steps": []}
    ctx: dict[str, Any] = {}

    def step(name: str, tool: str, args: dict[str, Any], summarize: Any, *, optional: bool = False) -> bool:
        t0 = time.monotonic()
        rec: dict[str, Any] = {"step": name, "tool": tool}
        try:
            env = runner.call(tool, args)
            summary = summarize(env)
            rec["summary"] = summary
            rec["status"] = "failed" if summary.get("healthy") is False else "ok"
            if rec["status"] == "failed":
                rec["error"] = str(env["data"].get("detail") or "connection reported unhealthy")[:240]
            if env.get("warnings"):
                rec["warnings"] = [str(w)[:200] for w in env["warnings"]][:5]
        except Exception as exc:  # noqa: BLE001 - every failure is a finding here
            text = _short(exc)
            unsupported = "CAPABILITY_UNSUPPORTED" in text or "not supported" in text.lower()
            rec["status"] = "skipped" if (optional and unsupported) else "failed"
            rec["error"] = text
        rec["elapsed_ms"] = int((time.monotonic() - t0) * 1000)
        entry["steps"].append(rec)
        return bool(rec["status"] == "ok")

    def s_health(env: dict[str, Any]) -> dict[str, Any]:
        d = env["data"]
        s = d.get("session") or {}
        return {
            "healthy": bool(d.get("healthy")),
            "server_version": str(d.get("server_version"))[:60],
            "isolation": s.get("isolation"),
            "read_only_enforced": s.get("read_only_enforced"),
            "read_only_verified": s.get("read_only_verified"),
            "lock_timeout_seconds": s.get("lock_timeout_seconds"),
        }

    def s_tables(env: dict[str, Any]) -> dict[str, Any]:
        tables = env["data"].get("tables", [])
        ctx["first"] = next(((t.get("schema"), t["name"]) for t in tables if t.get("kind") == "table"), None)
        return {"tables": len(tables), "truncated": bool(env.get("truncated", False))}

    def s_catalog(env: dict[str, Any]) -> dict[str, Any]:
        tables = env["data"]["tables"]
        first = tables[0] if tables else None
        first_name = None
        if first:
            first_name = f"{first['schema']}.{first['name']}" if first.get("schema") else first["name"]
        return {
            "tables_on_page": len(tables),
            "table_count": env["data"].get("table_count"),
            "first_table": first_name,
            "first_table_columns": len(first["columns"]) if first else 0,
            "first_table_primary_key": bool(first and first.get("primary_key")),
        }

    def s_profile(env: dict[str, Any]) -> dict[str, Any]:
        d = env["data"]
        return {
            "sample_rows": d["sample"]["rows"],
            "row_estimate": d.get("row_estimate"),
            "columns_profiled": len(d["columns"]),
            "finding_codes": sorted({f["code"] for f in d["findings"]}),
        }

    def s_explain(env: dict[str, Any]) -> dict[str, Any]:
        plan = env["data"].get("plan") or {}
        raw = plan.get("raw")
        return {"plan_lines": len(str(raw).splitlines()) if raw else 0, "method": plan.get("method")}

    def s_review(env: dict[str, Any]) -> dict[str, Any]:
        sm = env["data"]["summary"]
        return {
            "tables_reviewed": sm["tables_reviewed"],
            "tables_in_scope": sm["tables_in_scope"],
            "by_code": sm["by_code"],
            "budget_exhausted": env["data"]["budget_exhausted"],
        }

    def s_search(env: dict[str, Any]) -> dict[str, Any]:
        d = env["data"]
        return {
            "hits": len(d["hits"]),
            "tables_searched": d["tables_searched"],
            "tables_not_searched": d.get("tables_not_searched"),
            "connections_not_searched": d.get("connections_not_searched"),
            "budget_exhausted": d["budget_exhausted"],
        }

    if not step("connection", "db_test_connection", {"connection_id": cid}, s_health):
        return entry
    if not step("list_tables", "db_list_tables", {"connection_id": cid}, s_tables):
        return entry
    step("catalog", "db_get_catalog", {"connection_id": cid, "page_size": 10}, s_catalog)
    first = ctx.get("first")
    if first:
        schema, name = first
        obj = f"{schema}.{name}" if schema else name
        step(
            "profile", "db_profile_table",
            {"connection_id": cid, "object_name": obj, "sample_rows": int(sample_rows),
             "include_top_values": False},
            s_profile,
        )
        # obj is the catalog's own spelling of the first table; the guard
        # validates and the connector quotes it like every other tool call
        step(
            "explain", "db_explain",
            {"connection_id": cid, "sql": f"EXPLAIN SELECT * FROM {obj}"},  # noqa: S608
            s_explain, optional=True,
        )
    step(
        "review", "db_review_schema",
        {"connection_id": cid, "max_tables": int(review_tables), "sample_rows": int(sample_rows)},
        s_review,
    )
    step(
        "search", "db_search_values",
        {"query": SEARCH_NEEDLE, "connections": [cid], "max_tables": 20,
         "time_budget_seconds": float(search_budget_seconds), "max_hits_per_table": 1},
        s_search,
    )
    return entry


def run_site_check(
    config_path: str, *, sample_rows: int = 200, review_tables: int = 3, search_budget_seconds: float = 20.0
) -> dict[str, Any]:
    app_cfg, resolved = load_resolved(Path(config_path))
    app = AppContext(app_cfg, resolved)
    runner = _Runner(build_server(app))
    report: dict[str, Any] = {
        "kind": "udbmcp-site-check",
        "date_utc": dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "config": str(config_path),
        "connections": {},
    }
    for cid in sorted(resolved):
        report["connections"][cid] = _check_connection(
            runner, cid, resolved[cid].config.type, sample_rows=sample_rows, review_tables=review_tables,
            search_budget_seconds=search_budget_seconds,
        )
    conns = report["connections"]
    healthy = sum(1 for e in conns.values() if e["steps"] and e["steps"][0]["status"] == "ok")
    steps = [s for e in conns.values() for s in e["steps"]]
    failures = [
        f"{cid}/{s['step']}: {s.get('error', '')}"
        for cid, e in conns.items() for s in e["steps"] if s["status"] == "failed"
    ]
    report["summary"] = {
        "connections": len(conns),
        "connections_healthy": healthy,
        "steps": len(steps),
        "steps_ok": sum(1 for s in steps if s["status"] == "ok"),
        "steps_skipped": sum(1 for s in steps if s["status"] == "skipped"),
        "steps_failed": sum(1 for s in steps if s["status"] == "failed"),
        "failures": failures[:20],
    }
    report["ok"] = report["summary"]["steps_failed"] == 0 and healthy == len(conns)
    return report


def render_summary(report: dict[str, Any]) -> str:
    lines = [f"site-check {report['date_utc']} config={report['config']}"]
    for cid, e in report["connections"].items():
        marks = " ".join(f"{s['step']}={'ok' if s['status'] == 'ok' else s['status'].upper()}" for s in e["steps"])
        lines.append(f"  {cid} ({e['engine']}): {marks}")
    sm = report["summary"]
    lines.append(
        f"  connections healthy {sm['connections_healthy']}/{sm['connections']}; steps ok {sm['steps_ok']}, "
        f"skipped {sm['steps_skipped']}, failed {sm['steps_failed']}"
    )
    for f in sm["failures"]:
        lines.append(f"  FAILED {f}")
    return "\n".join(lines)


def write_report(report: dict[str, Any], out: str | None, *, force: bool = False) -> None:
    """Write the report privately (0600) and never over an existing file
    unless `force`: a report is evidence an operator carries off-site, and
    a path typo must not silently replace an earlier run.

    Nothing at `out` is ever followed or written through. Without `force`
    the file is created exclusively. With `force` the report goes to a new
    temp file beside `out` that then replaces it, and an existing `out` must
    be a regular file this user owns: a symlink planted at a shared path
    such as /tmp is refused, so no other file is truncated or chmodded."""
    if not out:
        return
    path = Path(out)
    data = json.dumps(report, indent=2, default=str)
    if not force:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(path, flags, 0o600)
        except FileExistsError:
            raise SystemExit(f"refusing to overwrite {path}; pass --force or choose another --out") from None
        except OSError as exc:
            raise SystemExit(f"cannot write {path}: {exc}") from None
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(data)
        return
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        pass
    else:
        if not stat.S_ISREG(st.st_mode):
            raise SystemExit(f"refusing to overwrite {path}: not a regular file (a symlink?); choose another --out")
        if hasattr(os, "geteuid") and st.st_uid != os.geteuid():
            raise SystemExit(f"refusing to overwrite {path}: it belongs to another user; choose another --out")
    try:
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    except OSError as exc:
        raise SystemExit(f"cannot write {path}: {exc}") from None
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            if hasattr(os, "fchmod"):
                os.fchmod(fh.fileno(), 0o600)
            fh.write(data)
        os.replace(tmp, path)  # replaces a link swapped in meanwhile, never follows it
    except BaseException as exc:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        if isinstance(exc, OSError):
            raise SystemExit(f"cannot write {path}: {exc}") from None
        raise
