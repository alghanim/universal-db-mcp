"""site/index.html makes claims about this product; keep them true.

The landing page lists every tool, quotes the version-matrix result, and
its "try to break it" panel shows verdicts said to be the SQL guard's real
output. These tests re-derive each of those from the code and the evidence
so the page cannot drift: a new tool, a changed matrix or a guard message
that changes wording fails here until the page is updated.
"""
from __future__ import annotations

import asyncio
import glob
import json
import re
from pathlib import Path
from typing import Any

import pytest

from universal_db_mcp.config import ConnectionConfig, SecurityConfig, load_resolved
from universal_db_mcp.connectors import clickhouse
from universal_db_mcp.errors import ToolFailure
from universal_db_mcp.security.policy import EffectivePolicy
from universal_db_mcp.security.sql_guard import SqlGuard
from universal_db_mcp.server import AppContext, build_server

ROOT = Path(__file__).resolve().parents[2]
PAGE = (ROOT / "site" / "index.html").read_text(encoding="utf-8")
CASES: list[dict[str, Any]] = json.loads(
    re.search(r'<script type="application/json" id="guard-cases">(.*?)</script>', PAGE, re.S).group(1)  # type: ignore[union-attr]
)


def _registered_tools(tmp_path: Path) -> set[str]:
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "application:\n  transport: stdio\n"
        f"  audit_path: {tmp_path / 'audit.jsonl'}\n"
        f"  metadata_cache_path: {tmp_path / 'cache.sqlite'}\n"
        f"connections:\n  demo:\n    type: sqlite\n    database: {tmp_path / 'demo.db'}\n",
        encoding="utf-8",
    )
    app_cfg, resolved = load_resolved(cfg)
    tools = asyncio.run(build_server(AppContext(app_cfg, resolved)).list_tools())
    return {t.name for t in tools}


def test_the_page_lists_exactly_the_registered_tools(tmp_path: Path) -> None:
    listed = re.findall(r"<li><code>(db_[a-z_]+)</code></li>", PAGE)
    registered = _registered_tools(tmp_path)
    assert len(listed) == len(set(listed)), "a tool is listed twice"
    assert set(listed) == registered
    count = len(registered)
    assert f"See all {count} tools" in PAGE and f"{count} tools · 8 databases" in PAGE and f"{count} tools turn" in PAGE


def test_the_version_matrix_figures_match_the_evidence() -> None:
    files = glob.glob(str(ROOT / "test-evidence/version-matrix/*.json"))
    rows = [json.loads(Path(p).read_text(encoding="utf-8")) for p in files]
    passed = [r for r in rows if r.get("healthy") and not r["summary"]["failed"]]
    assert (len(passed), len(rows)) == (26, 26), "update the page's version-matrix figures"
    assert "26 of 26 images pass" in PAGE and 'data-count="26" data-suffix="/26"' in PAGE


def _guard(engine: str, **security: Any) -> SqlGuard:
    # the policy the page states under the panel: connection 'warehouse', schema allowlist 'sales'
    body: dict[str, Any] = {"type": engine, "database": "d", "username_env": "U", "allowed_schemas": ["sales"]}
    if engine != "sqlite":
        body["host"] = "h"
    cfg = ConnectionConfig.model_validate(body)
    policy = EffectivePolicy.build(
        SecurityConfig(default_deny_objects=False, **security), type("R", (), {"config": cfg, "name": "warehouse"})()
    )
    return SqlGuard(engine, policy, None)


@pytest.mark.parametrize("case", CASES, ids=[c["key"] for c in CASES])
def test_every_verdict_on_the_page_is_the_guards_real_output(case: dict[str, Any]) -> None:
    guard = _guard(case["engine"])
    validate = guard.validate_explain if case.get("kind") == "explain" else guard.validate_select
    if case["allowed"]:
        validate(case["sql"])
        return
    with pytest.raises(ToolFailure) as refused:
        validate(case["sql"])
    assert str(refused.value) == case["message"]


def test_the_panel_covers_one_allowed_read_and_the_attacks() -> None:
    assert sum(1 for c in CASES if c["allowed"]) == 1
    assert len(CASES) == 12 and "Twelve ways" in PAGE
    assert 'connection <code>warehouse</code>, schema allowlist <code>sales</code>' in PAGE


def test_the_plan_card_holds_explain_analyze_is_refused_whatever_the_config() -> None:
    card = re.search(r"Query plans on every engine, never executed</h3>(.*?)</p>", PAGE, re.S)
    assert card is not None
    assert "EXPLAIN ANALYZE is refused whatever the configuration says" in card.group(1)
    for allow in (False, True):
        with pytest.raises(ToolFailure):
            _guard("postgres", allow_explain_analyze=allow).validate_explain(
                "EXPLAIN ANALYZE SELECT id FROM sales.customers"
            )
    # ClickHouse evaluates subqueries while it plans; the card names the ceiling on that
    assert f"{clickhouse._EXPLAIN_MAX_ROWS_TO_READ:,}-row" in card.group(1)


@pytest.mark.parametrize(
    ("engine", "opened", "sql"),
    [
        ("postgres", "pg_catalog", "SELECT query FROM pg_catalog.pg_stat_activity"),
        ("mysql", "information_schema", "SELECT info FROM information_schema.PROCESSLIST"),
        ("mssql", "sys", "SELECT * FROM sys.dm_exec_requests"),
        ("oracle", "SYS", "SELECT sql_text FROM SYS.V_$SQL"),
        ("oracle", "SYS", "SELECT sql_text FROM SYS.UNIFIED_AUDIT_TRAIL"),
    ],
    ids=["pg_stat_activity", "processlist", "dm_exec_requests", "v$sql", "unified_audit_trail"],
)
def test_the_masking_answer_holds_other_sessions_sql_is_refused_on_every_connection(
    engine: str, opened: str, sql: str
) -> None:
    faq = re.search(
        r"<summary>Does masking stop an agent from learning a sensitive value\?</summary><p>(.*?)</p>", PAGE
    )
    assert faq is not None and "show other sessions' SQL" in faq.group(1)
    # refused even where the administrator opened the system schema that holds the view
    with pytest.raises(ToolFailure) as refused:
        _guard(engine, allowed_system_schemas=[opened]).validate_select(sql)
    assert str(refused.value).startswith("POLICY_VIOLATION: ") and "other sessions' SQL" in str(refused.value)


def test_the_headline_claim_holds_there_is_no_write_mode() -> None:
    with pytest.raises(ValueError, match="not supported"):
        SecurityConfig(allow_write_operations=True)
    with pytest.raises(ValueError, match="not supported"):
        SecurityConfig(read_only=False)


def test_the_fonts_and_preview_image_the_page_loads_ship_with_it() -> None:
    for font in re.findall(r"url\((fonts/[^)]+)\)", PAGE):
        assert (ROOT / "site" / font).is_file(), font
    for licence in ("OFL-geist.txt", "OFL-geistmono.txt", "OFL-instrumentserif.txt"):
        assert "SIL OPEN FONT LICENSE" in (ROOT / "site/fonts" / licence).read_text(encoding="utf-8").upper()
    assert (ROOT / "site/og.png").read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"
    assert '__SITE_URL__/og.png' in PAGE, "the Pages workflow fills in the absolute preview URL"


def test_the_pages_workflow_fills_every_placeholder_the_page_uses() -> None:
    workflow = (ROOT / ".github/workflows/pages.yml").read_text(encoding="utf-8")
    placeholders = set(re.findall(r"__[A-Z_]+__", PAGE))
    assert placeholders == {"__REPO_URL__", "__SITE_URL__"}
    for placeholder in placeholders:
        assert f"s#{placeholder}#" in workflow
    assert "path: site" in workflow
