"""Gate B test: real stdio MCP protocol client against the real server, no
browser inspector, no npm, no external test dependencies — the client is the
pinned MCP SDK itself (shipped in the bundle's test profile)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parent.parent.parent / "src"
sys.path.insert(0, str(SRC))

from mcp import ClientSession, StdioServerParameters  # noqa: E402
from mcp.client.stdio import stdio_client  # noqa: E402

PROJECT = Path(__file__).resolve().parent.parent.parent

EXPECTED_TOOLS = {
    "db_list_connections",
    "db_test_connection",
    "db_get_capabilities",
    "db_list_catalogs",
    "db_list_databases",
    "db_list_schemas",
    "db_list_tables",
    "db_get_table",
    "db_list_columns",
    "db_list_views",
    "db_list_synonyms",
    "db_list_routines",
    "db_search_metadata",
    "db_get_relationships",
    "db_get_statistics",
    "db_validate_query",
    "db_query",
    "db_sample_table",
    "db_explain",
    "db_get_query_history",
    "db_list_indexes",
    "db_get_catalog",
    "db_profile_table",
    "db_search_values",
    "db_infer_relationships",
    "db_review_schema",
    "db_document_schema",
    "db_federated_query",
    "db_federated_join",
}


def server_params(config: Path) -> StdioServerParameters:
    import os

    env = dict(os.environ)
    env["PYTHONPATH"] = str(SRC)
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "universal_db_mcp", "serve", "--transport", "stdio", "--config", str(config)],
        env=env,
    )


@pytest.mark.anyio
async def test_protocol_lifecycle_and_tools(config_yaml: Path) -> None:
    async with stdio_client(server_params(config_yaml)) as (read, write):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            assert init.protocol_version
            assert init.server_info.name == "universal-db-mcp"

            tools = await session.list_tools()
            names = {t.name for t in tools.tools}
            assert EXPECTED_TOOLS <= names, names

            # discovery
            res = await session.call_tool("db_list_connections", {})
            assert not res.is_error
            payload = _structured(res)
            conns = payload["data"]["connections"]
            assert conns[0]["connection_id"] == "demo_sqlite"
            assert conns[0]["engine"] == "sqlite"

            # bounded query with masking (ssn column matches sensitive pattern)
            res = await session.call_tool(
                "db_query",
                {"connection_id": "demo_sqlite", "sql": "SELECT ssn FROM customers LIMIT 1"},
            )
            payload = _structured(res)
            row = payload["data"]["rows"][0]
            assert row[0] in ("<masked>", None)  # masked by heuristic
            assert any("masked" in w for w in payload.get("warnings", []))

            # write attempt must be denied with a stable category
            res = await session.call_tool(
                "db_query",
                {"connection_id": "demo_sqlite", "sql": "INSERT INTO customers VALUES (1,'a','b','c','d','e')"},
            )
            assert res.is_error
            assert "POLICY_VIOLATION" in _error_text(res)

            # sample table
            res = await session.call_tool(
                "db_sample_table",
                {"connection_id": "demo_sqlite", "object_name": "customers", "limit": 3},
            )
            payload = _structured(res)
            assert len(payload["data"]["rows"]) == 3
            assert payload["returned_row_count"] == 3

            # pagination
            res = await session.call_tool("db_list_tables", {"connection_id": "demo_sqlite"})
            payload = _structured(res)
            assert payload["data"]["tables"]
            if payload.get("next_cursor"):
                res2 = await session.call_tool(
                    "db_list_tables",
                    {"connection_id": "demo_sqlite", "cursor": payload["next_cursor"]},
                )
                assert not res2.is_error

            # capabilities report limitations truthfully
            res = await session.call_tool("db_get_capabilities", {"connection_id": "demo_sqlite"})
            payload = _structured(res)
            assert payload["data"]["capabilities"]["list_synonyms"] == "unsupported"

            # validation without execution
            res = await session.call_tool(
                "db_validate_query",
                {"connection_id": "demo_sqlite", "sql": "SELECT * FROM customers"},
            )
            payload = _structured(res)
            assert payload["data"]["valid"] is True
            assert payload["data"]["statement_kind"] == "select"

            # non-executing explain
            res = await session.call_tool(
                "db_explain",
                {"connection_id": "demo_sqlite", "sql": "EXPLAIN QUERY PLAN SELECT * FROM customers"},
            )
            assert not res.is_error

            # unknown connection: authorization-style refusal (no enumeration)
            res = await session.call_tool(
                "db_query",
                {"connection_id": "not_yours", "sql": "SELECT 1"},
            )
            assert res.is_error
            assert "not available" in _error_text(res)

            # caller-scoped history
            res = await session.call_tool("db_get_query_history", {"limit": 5})
            payload = _structured(res)
            assert payload["data"]["history"]
            assert all("sql_fingerprint" in h or h["sql_fingerprint"] is None for h in payload["data"]["history"])


@pytest.mark.anyio
async def test_unauthorized_metadata_not_leaked(config_yaml: Path) -> None:
    async with stdio_client(server_params(config_yaml)) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            # deny-by-default object
            res = await session.call_tool(
                "db_query",
                {"connection_id": "demo_sqlite", "sql": "SELECT * FROM secret_things"},
            )
            assert res.is_error
            err = _error_text(res)
            assert "could not be resolved" in err
            # error must not leak the DSN/credentials
            assert "demo.db" not in err


def _structured(res) -> dict:  # noqa: ANN001
    assert res.structured_content is not None, res
    return res.structured_content


def _error_text(res) -> str:  # noqa: ANN001
    parts = [c.text for c in res.content if getattr(c, "type", "") == "text"]
    return " ".join(parts)
