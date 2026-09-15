"""The wizard must not produce a connection the server will refuse.

Audit 2026-09-15: `add-connection` never asked about TLS and its live test
called the connector directly, bypassing the require_tls gate the server
applies to every tool call. The wizard therefore reported "connection OK" for
a config where every later db_* call fails with CONFIG_ERROR - the worst
possible first-run experience.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from universal_db_mcp.config import load_config
from universal_db_mcp.wizard import apply_connection, build_connection

SEEDED = """\
application:
  transport: stdio

security:
  read_only: true
"""


@pytest.fixture
def cfg_path(tmp_path: Path) -> Path:
    p = tmp_path / "config.yaml"
    p.write_text(SEEDED, encoding="utf-8")
    return p


def test_build_connection_carries_tls(tmp_path: Path) -> None:
    ca = tmp_path / "ca.pem"
    ca.write_text("x", encoding="utf-8")
    conn = build_connection(
        name="pg1", engine="postgres", database="appdb", host="pg.corp", port=5432,
        username_file=str(tmp_path / "u"), password_file=str(tmp_path / "p"),
        tls_enabled=True, tls_ca_file=str(ca),
    )
    assert conn.tls.enabled is True
    assert conn.tls.ca_file == str(ca)
    assert conn.tls.verify_server is True


def test_apply_reports_that_policy_would_refuse_a_plaintext_remote(
    cfg_path: Path, tmp_path: Path
) -> None:
    conn = build_connection(
        name="pg1", engine="postgres", database="appdb", host="pg.corp", port=5432,
        username_file=str(tmp_path / "u"), password_file=str(tmp_path / "p"),
    )
    result = apply_connection(cfg_path, "pg1", conn, run_test=False)

    assert result["policy"]["would_be_refused"] is True
    assert "require_remote_tls" in result["policy"]["detail"]
    # the connection is still written: the operator may be adding TLS next
    assert "pg1" in load_config(cfg_path).connections


def test_apply_is_quiet_when_tls_satisfies_the_policy(cfg_path: Path, tmp_path: Path) -> None:
    ca = tmp_path / "ca.pem"
    ca.write_text("x", encoding="utf-8")
    conn = build_connection(
        name="pg1", engine="postgres", database="appdb", host="pg.corp", port=5432,
        username_file=str(tmp_path / "u"), password_file=str(tmp_path / "p"),
        tls_enabled=True, tls_ca_file=str(ca),
    )
    result = apply_connection(cfg_path, "pg1", conn, run_test=False)
    assert result["policy"]["would_be_refused"] is False


def test_sqlite_is_exempt_from_the_tls_policy(cfg_path: Path, tmp_path: Path) -> None:
    db = tmp_path / "demo.db"
    db.touch()
    conn = build_connection(name="s1", engine="sqlite", database=str(db))
    result = apply_connection(cfg_path, "s1", conn, run_test=False)
    assert result["policy"]["would_be_refused"] is False


def test_policy_respects_an_explicitly_disabled_require_remote_tls(
    tmp_path: Path
) -> None:
    p = tmp_path / "config.yaml"
    p.write_text(
        "application:\n  transport: stdio\n\nsecurity:\n  require_remote_tls: false\n",
        encoding="utf-8",
    )
    conn = build_connection(
        name="pg1", engine="postgres", database="appdb", host="pg.corp", port=5432,
        username_file=str(tmp_path / "u"), password_file=str(tmp_path / "p"),
    )
    result = apply_connection(p, "pg1", conn, run_test=False)
    assert result["policy"]["would_be_refused"] is False
