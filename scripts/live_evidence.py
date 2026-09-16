#!/usr/bin/env python3
"""Regenerate the two live-fixture evidence files from the CURRENT code.

    .venv/bin/python scripts/live_evidence.py --config config.mockdbs.yaml

Writes

    test-evidence/session-safety/results.txt   (session profile read-back per connection)
    test-evidence/discovery-tools/results.txt  (catalog / profile / search / inference per connection)

through the same code path the MCP server uses (``build_server`` +
``call_tool``), so what lands in the files is what an agent would see.
Nothing here is mocked; a connection that cannot be reached is recorded
as such instead of being skipped silently.
"""
from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import json
import platform
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from universal_db_mcp.config import load_resolved  # noqa: E402
from universal_db_mcp.server import AppContext, build_server  # noqa: E402


def _call(server: Any, name: str, args: dict[str, Any]) -> dict[str, Any]:
    result = asyncio.run(server.call_tool(name, args))
    if result.structured_content is None:
        raise RuntimeError(f"{name} returned no structured content")
    return result.structured_content


def _pt(col: dict[str, Any]) -> dict[str, Any]:
    """PortableType.as_dict() is flattened into the column: portable_type=name, kind=kind."""
    return {"name": col.get("portable_type"), "kind": col.get("kind")}


def _short(value: Any, n: int = 60) -> str:
    text = json.dumps(value, default=str)
    return text if len(text) <= n else text[: n - 3] + "..."


def session_evidence(server: Any, conn_ids: list[str], policy_note: str) -> str:
    out = [
        "# Session safety profile: live read-back through the connectors' health_check",
        f"date_utc: {dt.datetime.now(dt.UTC).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        f"host: native {platform.system()} {platform.machine()}; fixtures on loopback; {policy_note}",
        "",
    ]
    for cid in conn_ids:
        try:
            env = _call(server, "db_test_connection", {"connection_id": cid})
        except Exception as exc:  # noqa: BLE001 - recorded, not hidden
            out.append(f"== {cid}: FAILED {type(exc).__name__}: {str(exc)[:200]}")
            out.append("")
            continue
        data = env.get("data", env)
        s = data.get("session") or {}
        out.append(f"== {cid}: healthy={data.get('healthy')} version={_short(data.get('server_version'), 40)}")
        if data.get("detail"):
            out.append(f"   detail={_short(data.get('detail'), 160)}")
        out.append(
            f"   isolation={s.get('isolation')} lock_timeout_seconds={s.get('lock_timeout_seconds')} "
            f"read_only_enforced={s.get('read_only_enforced')} read_only_verified={s.get('read_only_verified')} "
            f"app={s.get('application_name')}"
        )
        out.append(f"   applied={s.get('applied')}")
        if s.get("skipped"):
            out.append(f"   skipped={s.get('skipped')}")
        out.append(f"   server_reports={s.get('server_reports')}")
        out.append("")
    return "\n".join(out) + "\n"


SERVER_SIDE_READ_ONLY = ("postgres", "mysql", "clickhouse", "sqlite")


def write_refusal_evidence(app: AppContext, server: Any, conn_ids: list[str]) -> str:
    """Send a CREATE TABLE straight to the connector (guard bypassed on
    purpose) where the session profile pins a SERVER-side read-only; on the
    engines without one the guard is the only barrier and no write is ever
    attempted against the fixture."""
    from universal_db_mcp.connectors.base import QuerySpec

    out = ["== server-side write refusal (SQL guard bypassed on purpose)"]
    for cid in conn_ids:
        conn = app.connectors.get(cid)
        engine = app.resolved[cid].config.type
        if conn is None:
            out.append(f"   {cid}: not probed (connection never came up)")
            continue
        if engine not in SERVER_SIDE_READ_ONLY:
            out.append(
                f"   {cid} ({engine}): not applicable, no session-level read-only exists; the SQL guard enforces"
            )
            continue
        ddl = "CREATE TABLE udbmcp_ro_probe_zz (x INT)"
        try:
            if engine == "postgres":
                # the query path wraps statements in a server-side cursor, which
                # rejects DDL at parse time; the session profile is on the
                # connection itself, so send the DDL straight to it
                with conn._shared_meta_conn() as raw:  # noqa: SLF001 - evidence probe, on purpose
                    raw.execute(ddl)
            else:
                conn.execute_query(QuerySpec(sql=ddl, max_rows=1, timeout_seconds=15))
            out.append(f"   {cid} ({engine}): NOT REFUSED - the server accepted a write (investigate)")
        except Exception as exc:  # noqa: BLE001 - the refusal IS the evidence
            out.append(f"   {cid} ({engine}): refused -> {type(exc).__name__}: {str(exc)[:150]}")
    if "mock_db2" in conn_ids and app.connectors.get("mock_db2") is not None:
        try:
            got = app.connectors["mock_db2"].execute_query(
                QuerySpec(sql="VALUES (CURRENT ISOLATION, CURRENT LOCK TIMEOUT)", max_rows=1, timeout_seconds=15)
            )
            out.append(f"   mock_db2: connector VALUES (CURRENT ISOLATION, CURRENT LOCK TIMEOUT) -> {got.rows}")
            rows = _call(
                server, "db_query",
                {"connection_id": "mock_db2", "sql": "SELECT COUNT(*) FROM MOI.CITIZENS WITH UR"},
            )
            out.append(f"   mock_db2: a statement ending in WITH UR is accepted -> {rows['data']['rows']}")
        except Exception as exc:  # noqa: BLE001
            out.append(f"   mock_db2: FAILED {type(exc).__name__}: {str(exc)[:160]}")
    return "\n".join(out) + "\n"


def discovery_evidence(server: Any, conn_ids: list[str], search_query: str) -> str:
    out = [
        "# Discovery tools: live run through the MCP server against the local fixtures",
        f"date_utc: {dt.datetime.now(dt.UTC).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        "",
    ]
    for cid in conn_ids:
        out.append(f"== {cid}")
        try:
            cat = _call(server, "db_get_catalog", {"connection_id": cid, "page_size": 50})
            tables = cat["data"]["tables"]
            first = tables[0] if tables else None
            out.append(
                f"  catalog: {len(tables)} tables"
                + (
                    f"; {first['name']}: pk={first.get('primary_key')} cols={len(first.get('columns', []))} "
                    f"idx={len(first.get('indexes', []))} fks={[k.get('name') for k in first.get('foreign_keys', [])]}"
                    if first else ""
                )
            )
            if first:
                types_seen = sorted({_pt(c).get("name", "?") for c in first.get("columns", [])})
                out.append(f"  portable types in {first['name']}: {types_seen}")
                decl = [c["data_type"] for c in first.get("columns", [])][:6]
                out.append(f"  declared types (first 6): {decl}")
                obj = f"{first['schema']}.{first['name']}" if first.get("schema") else first["name"]
                prof = _call(server, "db_profile_table", {"connection_id": cid, "object_name": obj, "sample_rows": 500})
                pd = prof["data"]
                out.append(
                    f"  profile: sample={(pd.get('sample') or {}).get('rows')} row_estimate={pd.get('row_estimate')} "
                    f"findings={[f['code'] for f in pd.get('findings', [])]}"
                    + (f" warnings={prof.get('warnings')}" if prof.get("warnings") else "")
                )
                for col in pd.get("columns", [])[:4]:
                    out.append(
                        f"     {col['name']} [{_pt(col).get('kind')}] "
                        f"null={col.get('null_ratio')} distinct={col.get('distinct')} "
                        f"maxlen={col.get('max_length')} min={_short(col.get('min'), 24)} "
                        f"top={_short([t.get('value') for t in col.get('top_values', [])], 60)}"
                    )
            idx = _call(server, "db_list_indexes", {"connection_id": cid})["data"]["indexes"]
            out.append(f"  indexes in schema: {len(idx)}")
        except Exception as exc:  # noqa: BLE001 - recorded, not hidden
            out.append(f"  FAILED {type(exc).__name__}: {str(exc)[:240]}")
        out.append("")
    out.append("== cross-connection search")
    try:
        hits = _call(
            server, "db_search_values", {"query": search_query, "max_hits_per_table": 2, "time_budget_seconds": 60}
        )
        d = hits["data"]
        out.append(f"  query={search_query!r} hits={len(d['hits'])} tables_searched={d.get('tables_searched')} "
                   f"warnings={hits.get('warnings')}")
        for h in d["hits"][:6]:
            out.append(f"     {h['connection']}.{h.get('schema')}.{h['table']} matched={h['matched_columns']}")
        for literal in ("100%", "gu_f"):
            lit = _call(
                server, "db_search_values", {"query": literal, "max_hits_per_table": 1, "time_budget_seconds": 30}
            )
            out.append(
                f"  literal query {literal!r}: hits={len(lit['data']['hits'])} "
                f"(wildcard characters are data; 'gulf' rows must not match) warnings={lit.get('warnings')}"
            )
    except Exception as exc:  # noqa: BLE001
        out.append(f"  FAILED {type(exc).__name__}: {str(exc)[:240]}")
    out.append("")
    out.append("== relationship inference (all connections)")
    try:
        rel_env = _call(server, "db_infer_relationships", {})
        rel = rel_env["data"]
        kinds: dict[str, int] = {}
        for r in rel.get("relationships", []):
            kinds[r.get("kind", "?")] = kinds.get(r.get("kind", "?"), 0) + 1
        out.append(
            f"  relationships={len(rel.get('relationships', []))} by kind={kinds} warnings={rel_env.get('warnings')}"
        )
        for r in rel.get("relationships", [])[:5]:
            src, tgt = r.get("source") or {}, r.get("target") or {}
            out.append(
                f"     {r.get('kind')}: {src.get('connection')}.{src.get('table')}{r.get('source_columns')} -> "
                f"{tgt.get('connection')}.{tgt.get('table')}{r.get('target_columns')} confidence={r.get('confidence')}"
            )
    except Exception as exc:  # noqa: BLE001
        out.append(f"  FAILED {type(exc).__name__}: {str(exc)[:240]}")
    return "\n".join(out) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config.mockdbs.yaml")
    ap.add_argument("--search", default="user12@", help="value to look for across every connection")
    ap.add_argument("--only", nargs="*", help="connection ids (default: all)")
    args = ap.parse_args()
    app_cfg, resolved = load_resolved(Path(args.config))
    app = AppContext(app_cfg, resolved)
    server = build_server(app)
    conn_ids = args.only or sorted(resolved)
    sec = app_cfg.security
    note = f"policy hard_query_timeout={sec.hard_query_timeout_seconds}s, max_response_bytes={sec.max_response_bytes}"
    ev = ROOT / "test-evidence"
    (ev / "session-safety").mkdir(parents=True, exist_ok=True)
    (ev / "discovery-tools").mkdir(parents=True, exist_ok=True)
    s = session_evidence(server, conn_ids, note) + "\n" + write_refusal_evidence(app, server, conn_ids)
    (ev / "session-safety" / "results.txt").write_text(s, encoding="utf-8")
    print(s)
    d = discovery_evidence(server, conn_ids, args.search)
    (ev / "discovery-tools" / "results.txt").write_text(d, encoding="utf-8")
    print(d)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
