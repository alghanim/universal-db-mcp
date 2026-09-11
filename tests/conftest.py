"""Shared fixtures: synthetic SQLite database + valid config file."""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(SRC))

from universal_db_mcp.config import load_resolved  # noqa: E402
from universal_db_mcp.security.policy import EffectivePolicy  # noqa: E402

SCHEMA = """
CREATE TABLE customers (
    customer_id INTEGER PRIMARY KEY,
    full_name   TEXT NOT NULL,
    email       TEXT NOT NULL,
    ssn TEXT,
    country     TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
CREATE TABLE accounts (
    account_id   INTEGER PRIMARY KEY,
    customer_id  INTEGER NOT NULL REFERENCES customers(customer_id),
    account_type TEXT NOT NULL,
    balance_cents BIGINT NOT NULL,
    opened_at    TEXT NOT NULL
);
CREATE VIEW v_accounts AS
    SELECT a.account_id, c.full_name, a.account_type, a.balance_cents
    FROM accounts a JOIN customers c ON c.customer_id = a.customer_id;
"""


@pytest.fixture()
def sqlite_db(tmp_path: Path) -> Path:
    p = tmp_path / "demo.db"
    conn = sqlite3.connect(p)
    conn.executescript(SCHEMA)
    for i in range(10):
        conn.execute(
            "INSERT INTO customers VALUES (?,?,?,?,?,?)",
            (i + 1, f"User {i}", f"u{i}@example.invalid", f"999-9{i}", "QA", "2025-01-01"),
        )
        conn.execute(
            "INSERT INTO accounts VALUES (?,?,?,?,?)",
            (i + 1, i + 1, "checking", 2**60 + i, "2025-02-01"),
        )
    conn.commit()
    conn.close()
    return p


@pytest.fixture()
def config_yaml(sqlite_db: Path, tmp_path: Path) -> Path:
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        f"""
application:
  airgapped: true
  transport: stdio
  metadata_cache_path: {tmp_path}/meta-cache.sqlite
  audit_path: {tmp_path}/audit.jsonl
  telemetry_enabled: false

security:
  read_only: true
  allow_write_operations: false
  default_deny_objects: true
  max_concurrent_queries: 4

connections:
  demo_sqlite:
    type: sqlite
    database: {sqlite_db}
    read_only: true
""",
        encoding="utf-8",
    )
    return cfg


@pytest.fixture()
def app_ctx(config_yaml: Path):
    from universal_db_mcp.server import AppContext

    cfg, resolved = load_resolved(config_yaml)
    return AppContext(cfg, resolved)


@pytest.fixture()
def demo_policy(app_ctx):
    return EffectivePolicy.build(app_ctx.cfg.security, app_ctx.resolved["demo_sqlite"])


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"
