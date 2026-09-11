"""Redaction, fingerprints, and cursor binding."""

from __future__ import annotations

import json
import time

import pytest

from universal_db_mcp.errors import ToolFailure
from universal_db_mcp.security.cursors import CursorCodec
from universal_db_mcp.security.redact import (
    SecretMark,
    redact_text,
    sql_fingerprint,
)


def test_redact_text() -> None:
    text = "connect failed: password=hunter2 at postgres://u:p@host/db"
    out = redact_text(text)
    assert "hunter2" not in out
    assert "p@" not in out


def test_fingerprint_stable_and_redacting() -> None:
    a = sql_fingerprint("SELECT * FROM t WHERE id = 42 AND name = 'bob'")
    b = sql_fingerprint("select * from t where id = 7 and name = 'alice'")
    assert a == b  # literals normalize away; case is normalized
    assert a.startswith("sha256:")
    assert len(a) == len("sha256:") + 64


def test_secret_mark_never_serializes() -> None:
    s = SecretMark("hunter2")
    assert "hunter2" not in json.dumps({"a": str(s)})
    assert "hunter2" not in repr(s)
    assert "hunter2" not in f"{s}"


def _codec() -> CursorCodec:
    return CursorCodec()


def test_cursor_roundtrip() -> None:
    c = _codec()
    tok = c.encode({"offset": 50, "identity": "me", "connection_id": "c1", "kind": "tables", "policy": "p"})
    body = c.decode(
        tok,
        expect_identity="me",
        expect_connection="c1",
        expect_kind="tables",
        policy_fingerprint="p",
    )
    assert body["offset"] == 50


def test_cursor_rejects_wrong_identity() -> None:
    c = _codec()
    tok = c.encode({"offset": 0, "identity": "me", "connection_id": "c1", "kind": "tables", "policy": "p"})
    with pytest.raises(ToolFailure, match="AUTHORIZATION_DENIED"):
        c.decode(
            tok, expect_identity="someone_else", expect_connection="c1", expect_kind="tables", policy_fingerprint="p"
        )


def test_cursor_rejects_wrong_connection() -> None:
    c = _codec()
    tok = c.encode({"offset": 0, "identity": "me", "connection_id": "c1", "kind": "tables", "policy": "p"})
    with pytest.raises(ToolFailure, match="another connection"):
        c.decode(tok, expect_identity="me", expect_connection="c2", expect_kind="tables", policy_fingerprint="p")


def test_cursor_rejects_tamper() -> None:
    c = _codec()
    tok = c.encode({"offset": 0, "identity": "me", "connection_id": "c1", "kind": "tables", "policy": "p"})
    bad = tok[:-2] + ("aa" if not tok.endswith("aa") else "bb")
    with pytest.raises(ToolFailure, match="invalid cursor"):
        c.decode(bad, expect_identity="me", expect_connection="c1", expect_kind="tables", policy_fingerprint="p")


def test_cursor_expiry() -> None:
    c = _codec()
    c.encode({"offset": 0, "identity": "me", "connection_id": "c1", "kind": "tables", "policy": "p"})
    # fake expiry by monkeypatching time within decode: simpler to test far-future offset
    body = {
        "exp": int(time.time()) - 1,
        "offset": 0,
        "identity": "me",
        "connection_id": "c1",
        "kind": "tables",
        "policy": "p",
    }

    raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    import base64
    import hashlib
    import hmac

    sig = hmac.new(c._key, raw, hashlib.sha256).digest()
    b64 = base64.urlsafe_b64encode
    forged = b64(sig).decode().rstrip("=") + "." + b64(raw).decode().rstrip("=")
    with pytest.raises(ToolFailure, match="expired"):
        c.decode(forged, expect_identity="me", expect_connection="c1", expect_kind="tables", policy_fingerprint="p")
