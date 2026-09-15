"""Opaque, bound pagination cursors.

A cursor is an HMAC-signed, base64url token. The signature binds it to the
caller identity, connection id, object type, policy fingerprint, and an
expiry timestamp. Cursors from a different caller/connection/policy or past
expiry are rejected as invalid input (AUTHORIZATION_DENIED / VALIDATION_ERROR),
so metadata or counts cannot leak across authorization boundaries.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any

from universal_db_mcp.errors import ToolFailure
from universal_db_mcp.models.responses import ErrorCategory

_CURSOR_TTL_SECONDS = 900
_MAX_CURSOR_BYTES = 2048


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _b64d(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


@dataclass(slots=True)
class CursorKey:
    """Per-process HMAC key. Cursors do not survive restarts (documented)."""

    secret: bytes = secrets.token_bytes(32)


class CursorCodec:
    def __init__(self, key: CursorKey | None = None) -> None:
        self._key = (key or CursorKey()).secret

    def encode(self, payload: dict[str, Any]) -> str:
        body = dict(payload)
        body["exp"] = int(time.time()) + _CURSOR_TTL_SECONDS
        raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        sig = hmac.new(self._key, raw, hashlib.sha256).digest()
        return _b64e(sig) + "." + _b64e(raw)

    def decode(
        self,
        token: str,
        *,
        expect_identity: str,
        expect_connection: str | None,
        expect_kind: str,
        policy_fingerprint: str,
    ) -> dict[str, Any]:
        if not token or len(token) > _MAX_CURSOR_BYTES or token.count(".") != 1:
            raise ToolFailure(ErrorCategory.VALIDATION, "invalid cursor")
        sig_b, raw_b = token.split(".", 1)
        try:
            raw = _b64d(raw_b)
            sig = _b64d(sig_b)
        except Exception as exc:  # noqa: BLE001 - invalid cursor is a controlled input
            raise ToolFailure(ErrorCategory.VALIDATION, "invalid cursor") from exc
        good = hmac.new(self._key, raw, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, good):
            raise ToolFailure(ErrorCategory.VALIDATION, "invalid cursor")
        try:
            body = json.loads(raw)
        except Exception as exc:
            raise ToolFailure(ErrorCategory.VALIDATION, "invalid cursor") from exc
        if not isinstance(body, dict):
            raise ToolFailure(ErrorCategory.VALIDATION, "invalid cursor")
        if body.get("exp", 0) < time.time():
            raise ToolFailure(ErrorCategory.VALIDATION, "cursor expired; re-run the query")
        if body.get("identity") != expect_identity:
            raise ToolFailure(ErrorCategory.AUTHZ, "cursor was not issued to this caller")
        if expect_connection is not None and body.get("connection_id") != expect_connection:
            raise ToolFailure(ErrorCategory.AUTHZ, "cursor belongs to another connection")
        if body.get("kind") != expect_kind:
            raise ToolFailure(ErrorCategory.VALIDATION, "cursor does not apply to this operation")
        if body.get("policy") != policy_fingerprint:
            raise ToolFailure(ErrorCategory.AUTHZ, "policy changed since cursor was issued")
        return body


def _normalize(value: Any) -> Any:
    """Order-independent, process-independent view of a policy field.

    Sets are sorted (frozenset repr order follows per-process string hashing)
    and compiled patterns contribute their FULL pattern text: re.Pattern.__repr__
    truncates at 200 characters, so two long mask patterns differing only past
    that point produced the same fingerprint.
    """
    if isinstance(value, (set, frozenset)):
        return sorted(_normalize(v) for v in value)
    if isinstance(value, dict):
        return {str(k): _normalize(v) for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))}
    if isinstance(value, (list, tuple)):
        return [_normalize(v) for v in value]
    pattern = getattr(value, "pattern", None)
    if pattern is not None and hasattr(value, "match"):
        return f"re:{pattern}"
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: _normalize(getattr(value, f.name)) for f in dataclasses.fields(value)}
    return value


def policy_fingerprint(policy: Any) -> str:
    """Short fingerprint of the effective security policy for cursor binding
    and metadata-cache keys.

    This used to call ``model_dump`` inside a try/except that fell back to
    ``repr``. EffectivePolicy is a dataclass, so EVERY call took the fallback,
    and the repr of its frozenset fields varies per process: the cache key
    changed on every restart and the on-disk metadata cache never produced a
    hit. An unsupported object now fails loudly instead of silently hashing
    its repr.
    """
    if hasattr(policy, "model_dump"):
        data: Any = policy.model_dump(mode="json")
    elif dataclasses.is_dataclass(policy) and not isinstance(policy, type):
        data = {f.name: getattr(policy, f.name) for f in dataclasses.fields(policy)}
    else:
        raise TypeError(
            f"policy_fingerprint needs a pydantic model or a dataclass, got {type(policy).__name__}"
        )
    blob = json.dumps(_normalize(data), sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]
