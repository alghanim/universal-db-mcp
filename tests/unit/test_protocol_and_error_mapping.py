"""Protocol surface and error classification.

Audit 2026-09-15:

* `policy_fingerprint` called `model_dump` on a dataclass, so EVERY call took
  the `except` fallback to `repr()`. Frozenset repr order follows per-process
  string hashing, so the metadata cache key changed in every process and the
  on-disk cache could never produce a hit - it only ever grew.
* No tool carried annotations, so a spec-conformant client must treat all 25
  read-only tools as destructive (readOnlyHint defaults false, destructiveHint
  defaults true).
* `udbmcp version` printed "mcp-sdk unknown": the package defines no
  __version__, so the one command whose job is to report the pinned SDK
  reported nothing.
* `except LookupError` caught KeyError/IndexError from driver and catalog
  code, telling the model its own arguments were invalid and recording the
  audit outcome as "deny" for what is a server-side bug.
* Db2 `db_explain` raised NotImplementedError, surfacing as INTERNAL_ERROR for
  a limitation db_get_capabilities already declares.
* A JSON integer larger than a float could carry made `math.isfinite` raise
  OverflowError -> INTERNAL_ERROR, where the NaN sibling was already handled.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from universal_db_mcp.config import load_resolved
from universal_db_mcp.models.responses import ErrorCategory
from universal_db_mcp.server import AppContext, build_server, tool_span

ROOT = Path(__file__).resolve().parents[2]

FINGERPRINT_PROBE = "import sys\nsys.path.insert(0, " + repr(str(ROOT / "src")) + ")" + """
from universal_db_mcp.config import ConnectionConfig, SecurityConfig
from universal_db_mcp.security.policy import EffectivePolicy
from universal_db_mcp.security.cursors import policy_fingerprint

cfg = ConnectionConfig.model_validate({
    "type": "postgres", "host": "h", "database": "d", "username_env": "U",
    "allowed_schemas": ["reporting", "analytics", "finance", "ops", "staging"],
})
policy = EffectivePolicy.build(SecurityConfig(), type("R", (), {"config": cfg, "name": "x"})())
print(policy_fingerprint(policy))
"""


def _fingerprint_in_new_process() -> str:
    out = subprocess.run(  # noqa: S603
        [sys.executable, "-c", FINGERPRINT_PROBE],
        capture_output=True, text=True, check=True, cwd=str(ROOT),
    )
    return out.stdout.strip()


def test_policy_fingerprint_is_stable_across_processes() -> None:
    """Hash randomization differs per process; the cache key must not."""
    first = _fingerprint_in_new_process()
    second = _fingerprint_in_new_process()
    assert first and first == second, (
        f"fingerprint changed between processes ({first} vs {second}): the persistent "
        "metadata cache can never produce a hit"
    )


def test_policy_fingerprint_refuses_an_unsupported_object() -> None:
    from universal_db_mcp.security.cursors import policy_fingerprint

    with pytest.raises(TypeError):
        policy_fingerprint(object())


@pytest.fixture
def app_and_server(tmp_path: Path) -> tuple[Any, Any]:
    db = tmp_path / "demo.db"
    db.touch()
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(
        "application:\n  transport: stdio\n"
        f"  audit_path: {tmp_path / 'audit.jsonl'}\n"
        f"  metadata_cache_path: {tmp_path / 'cache.sqlite'}\n"
        f"connections:\n  demo:\n    type: sqlite\n    database: {db}\n",
        encoding="utf-8",
    )
    cfg, resolved = load_resolved(cfg_path)
    app = AppContext(cfg, resolved)
    return app, build_server(app)


def test_tools_declare_they_are_read_only(app_and_server: tuple[Any, Any]) -> None:
    _app, server = app_and_server
    tools = asyncio.run(server.list_tools())
    assert tools, "no tools registered"
    for tool in tools:
        assert tool.annotations is not None, f"{tool.name} carries no annotations"
        assert tool.annotations.read_only_hint is True, tool.name
        assert tool.annotations.destructive_hint is False, tool.name


def test_version_command_reports_the_pinned_mcp_sdk() -> None:
    out = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "universal_db_mcp", "version"],
        capture_output=True, text=True, check=True, cwd=str(ROOT),
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
    )
    assert "mcp-sdk unknown" not in out.stdout, out.stdout
    assert "mcp-sdk 2." in out.stdout, out.stdout


def _raise_in_span(app: Any, exc: BaseException) -> str:
    from mcp.server.mcpserver.exceptions import ToolError

    async def go() -> str:
        try:
            async with tool_span(app, "db_probe"):
                raise exc
        except ToolError as err:
            return str(err)
        return ""

    return asyncio.run(go())


def test_object_not_found_is_a_validation_error(app_and_server: tuple[Any, Any]) -> None:
    from universal_db_mcp.connectors.base import ObjectNotFound

    app, _server = app_and_server
    message = _raise_in_span(app, ObjectNotFound("table 'app.customers' not found or not visible"))
    assert message.startswith(ErrorCategory.VALIDATION), message


def test_a_key_error_is_not_blamed_on_the_caller(app_and_server: tuple[Any, Any]) -> None:
    app, _server = app_and_server
    message = _raise_in_span(app, KeyError("row_count"))
    assert message.startswith(ErrorCategory.INTERNAL), (
        f"a server-side KeyError must not be reported as the caller's validation error: {message}"
    )


def test_unimplemented_capability_is_reported_as_such(app_and_server: tuple[Any, Any]) -> None:
    app, _server = app_and_server
    message = _raise_in_span(app, NotImplementedError("Db2 EXPLAIN requires explain tables"))
    assert message.startswith(ErrorCategory.CAPABILITY), message


def test_enormous_row_limit_is_a_validation_error() -> None:
    from universal_db_mcp.config import ConnectionConfig, SecurityConfig
    from universal_db_mcp.errors import ToolFailure
    from universal_db_mcp.security.policy import EffectivePolicy

    cfg = ConnectionConfig.model_validate(
        {"type": "postgres", "host": "h", "database": "d", "username_env": "U"}
    )
    policy = EffectivePolicy.build(SecurityConfig(), type("R", (), {"config": cfg, "name": "x"})())

    with pytest.raises(ToolFailure) as exc:
        policy.clamp_row_limit(10**400)
    assert ErrorCategory.VALIDATION in str(exc.value)


def test_doctor_does_not_claim_safe_permissions_it_never_checked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """On Windows the permission check is skipped; doctor still reported the
    token 'present with safe permissions' for a file it never inspected."""
    from universal_db_mcp.diagnostics import doctor as doctor_module

    token = tmp_path / "http-token"
    token.write_text("x" * 40, encoding="utf-8")
    token.chmod(0o600)
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(
        "application:\n  transport: http\n"
        f"  http_bearer_token_file: {token}\n"
        "connections: {}\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(doctor_module.sys, "platform", "win32")
    report = doctor_module.run_doctor(str(cfg_path))
    checks = [c for c in report["checks"] if c["check"] == "http-bearer-token"]
    assert checks, report
    detail = str(checks[0]["detail"]).lower()
    assert "safe permissions" not in detail, detail
    assert "not verified" in detail or "windows" in detail, detail


EXPECTED_TOOLS = {
    "db_list_connections", "db_test_connection", "db_get_capabilities", "db_list_catalogs",
    "db_list_databases", "db_list_schemas", "db_list_tables", "db_get_table", "db_list_columns",
    "db_list_views", "db_list_synonyms", "db_list_routines", "db_search_metadata",
    "db_get_relationships", "db_get_statistics", "db_validate_query", "db_query", "db_sample_table",
    "db_explain", "db_get_query_history",
    "db_list_indexes", "db_get_catalog", "db_profile_table", "db_search_values", "db_infer_relationships",
    "db_review_schema", "db_document_schema", "db_federated_query", "db_federated_join",
}


def test_exactly_the_25_documented_tools_are_registered(app_and_server: tuple[Any, Any]) -> None:
    """The tool surface is a contract (BUILD spec section 8 plus its
    2026-09-16 addendum); an accidental addition or loss must fail loudly."""
    _app, server = app_and_server
    names = {t.name for t in asyncio.run(server.list_tools())}
    assert names == EXPECTED_TOOLS, sorted(names ^ EXPECTED_TOOLS)
