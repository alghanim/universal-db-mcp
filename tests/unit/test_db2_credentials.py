"""Db2 connector: credentials must travel INSIDE the connection string.

Root cause (reproduced live 2026-09-15 against Db2 11.5.9, and at a user's
air-gapped site): for a connection-string DSN (``DATABASE=...;HOSTNAME=...``)
ibm_db ignores the 2nd/3rd positional ``connect`` arguments, so a connector
that passes the username/password positionally sends NO credentials. The
server then answers SQL30082N reason 17 (UNSUPPORTED FUNCTION) under default
negotiation and reason 3 (PASSWORD MISSING) when SERVER auth is forced - which
was misdiagnosed for weeks as a server/TLS limitation.

The fake below models that real driver behavior, so the test fails for the
positional convention and passes only when UID/PWD are in the string.

A ';' cannot be carried in a CLI connection-string value in ANY quoting form
(raw, braces, doubled braces, single/double quotes were all rejected live with
reason 24 while the stored password hashes verified correct); '=', braces and
spaces work raw. So a ';' in any DSN value is refused before dialing: it would
otherwise split into extra connection keywords.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

from universal_db_mcp.config import ConnectionConfig, ResolvedConnection, SecurityConfig
from universal_db_mcp.connectors import db2 as db2_module
from universal_db_mcp.connectors.base import ConnectorError
from universal_db_mcp.security.policy import EffectivePolicy


class _RealisticFakeIbmDb:
    """Mimics ibm_db.connect's credential handling for connection strings."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str]] = []

    def connect(self, dsn: str, user: str, password: str, *args: object, **kwargs: object) -> str:
        self.calls.append((dsn, user, password))
        if "=" in dsn:  # connection-string DSN: positional credentials are ignored
            fields = dict(part.split("=", 1) for part in dsn.split(";") if part)
            if "UID" not in fields or "PWD" not in fields:
                raise RuntimeError(
                    '[IBM][CLI Driver] SQL30082N  Security processing failed with reason "17" '
                    '("UNSUPPORTED FUNCTION").  SQLSTATE=08001 SQLCODE=-30082'
                )
        return "handle"

    def exec_immediate(self, conn: str, sql: str) -> str:  # session profile statements
        return "stmt"


def _secret(tmp_path: Path, name: str, value: str) -> str:
    path = tmp_path / name
    path.write_text(value + "\n", encoding="utf-8")
    path.chmod(0o600)
    return str(path)


def _connector(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    username: str = "db2admin",
    password: str = "s3cret=x{y} z",  # noqa: S107 - fake credential for a driver fake
    database: str = "SAMPLE",
) -> tuple[db2_module.Db2Connector, _RealisticFakeIbmDb]:
    fake = _RealisticFakeIbmDb()
    monkeypatch.setattr(db2_module, "open_module", lambda *_a, **_k: fake)
    monkeypatch.setitem(sys.modules, "ibm_db_dbi", types.ModuleType("ibm_db_dbi"))
    cfg = ConnectionConfig.model_validate(
        {
            "type": "db2",
            "host": "db.example.internal",
            "port": 50000,
            "database": database,
            "username_file": _secret(tmp_path, "c.username", username),
            "password_file": _secret(tmp_path, "c.password", password),
        }
    )
    resolved = ResolvedConnection("c", cfg)
    return db2_module.Db2Connector(resolved, EffectivePolicy.build(SecurityConfig(), resolved)), fake


def test_credentials_are_sent_inside_the_connection_string(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    connector, fake = _connector(tmp_path, monkeypatch)

    assert connector._connect() == "handle"

    dsn, user_arg, password_arg = fake.calls[0]
    assert (user_arg, password_arg) == ("", ""), "positional credentials are ignored by ibm_db"
    fields = dict(part.split("=", 1) for part in dsn.split(";") if part)
    assert fields["UID"] == "db2admin"
    assert fields["PWD"] == "s3cret=x{y} z", "'=', braces and spaces are carried raw"
    assert fields["DATABASE"] == "SAMPLE"
    assert fields["HOSTNAME"] == "db.example.internal"


@pytest.mark.parametrize("field", ["password", "username", "database"])
def test_semicolon_in_any_dsn_value_is_refused_before_dialing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str
) -> None:
    poisoned = "pa;ss" if field != "database" else "SAMPLE;SECURITY=NONE"
    connector, fake = _connector(tmp_path, monkeypatch, **{field: poisoned})

    with pytest.raises(ConnectorError) as exc:
        connector._connect()

    assert fake.calls == [], "a ';' value must never reach the driver"
    assert "';'" in str(exc.value)
    if field == "password":
        assert "pa;ss" not in str(exc.value), "the password must never appear in the error"
