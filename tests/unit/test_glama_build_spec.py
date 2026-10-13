"""glama.json is Glama's build spec for its directory check.

Glama builds the repo checkout in /app, starts the command under mcp-proxy
with no credentials and no network, and lists tools, resources and prompts.
The spec installs the checkout (SQLite needs no driver) and serves the
synthetic demo database, so the check needs nothing secret. These tests keep
the spec pointing at files the demo generator really writes.
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = json.loads((ROOT / "glama.json").read_text(encoding="utf-8"))
DEMO = ROOT / "examples" / "sqlite-demo"


def test_spec_claims_the_repo_for_its_owner() -> None:
    assert SPEC["$schema"] == "https://glama.ai/mcp/schemas/server.json"
    assert SPEC["maintainers"] == ["alghanim"]
    assert SPEC["pinnedCommit"] is None


def test_build_installs_the_checkout_and_makes_the_demo_database() -> None:
    install, demo = SPEC["buildSteps"]
    assert install.endswith("/app/.venv/bin/pip install --no-cache-dir .")
    assert demo == (
        "/app/.venv/bin/python examples/sqlite-demo/create_demo.py --path /app/examples/sqlite-demo/finlink_demo.db"
    )
    assert (DEMO / "create_demo.py").is_file() and (DEMO / "config.template.yaml").is_file()
    # create_demo.py writes config.yaml beside itself; the template points it at the --path database
    assert 'Path(__file__).parent / "config.yaml"' in (DEMO / "create_demo.py").read_text(encoding="utf-8")


def test_command_serves_stdio_from_the_demo_config() -> None:
    assert SPEC["cmdArguments"] == [
        "mcp-proxy", "--", "/app/.venv/bin/udbmcp",
        "serve", "--transport", "stdio", "--config", "/app/examples/sqlite-demo/config.yaml",
    ]


def test_demo_config_stays_read_only() -> None:
    template = (DEMO / "config.template.yaml").read_text(encoding="utf-8")
    assert "read_only: true" in template and "allow_write_operations: false" in template
    assert "read_only: false" not in template
