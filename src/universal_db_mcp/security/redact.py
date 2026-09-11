"""Redaction helpers. Central chokepoint: nothing containing a secret may be
logged or echoed without passing through here. ``SecretMark`` values are
replaced at the boundary so raw material never reaches result/log paths."""

from __future__ import annotations

import hashlib
import re
import uuid
from dataclasses import dataclass
from typing import Any

# Marked wrapper produced by the config secret resolver. Any object of this
# type found in responses, errors, or logs is replaced with "<redacted>".
SECRET_SENTINEL = "\x00udbmcp-secret\x00"  # noqa: S105 - internal marker, not a credential


@dataclass(slots=True)
class SecretMark:
    """Carries a secret through internal calls; never serializes its value."""

    value: str

    def __repr__(self) -> str:  # pragma: no cover - safety net
        return "'<redacted>'"

    def __str__(self) -> str:
        return "<redacted>"


def redact_text(text: str) -> str:
    """Best-effort scrub of common credential shapes from free text."""
    if not text:
        return text
    patterns = [
        (re.compile(r"(?i)(password|passwd|pwd|token|secret|api[_-]?key)\s*[=:]\s*\S+"), r"\1=<redacted>"),
        (re.compile(r"(?i)(postgres(?:ql)?|mysql|db2|oracle|mssql|clickhouse)://[^\s]+"), r"\1://<redacted-url>"),
    ]
    out = text
    for pat, repl in patterns:
        out = pat.sub(repl, out)
    return out


def redact_value(value: Any) -> Any:
    if isinstance(value, SecretMark):
        return "<redacted>"
    if isinstance(value, str) and SECRET_SENTINEL in value:
        return "<redacted>"
    if isinstance(value, dict):
        return {k: redact_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_value(v) for v in value]
    return value


def scrub_exception(exc: BaseException) -> str:
    """One-line, redacted representation of an exception for error paths."""
    return redact_text(f"{type(exc).__name__}: {exc}".replace("\n", " "))[:500]


def sql_fingerprint(sql: str) -> str:
    """Stable fingerprint of a statement with literal values removed.

    This is not a parser-grade rewrite: string/number literals are replaced
    with ``?`` by a conservative scanner, then hashed. Raw SQL text is never
    stored when ``audit_sql_text`` is false (the default).
    """
    s = re.sub(r"'(?:[^']|'')*'", "?", sql)
    s = re.sub(r'"(?:[^"]|"")*"', "?", s)
    s = re.sub(r"\b\d+(?:\.\d+)?\b", "?", s)
    s = re.sub(r"\s+", " ", s).strip().lower()
    return "sha256:" + hashlib.sha256(s.encode()).hexdigest()


def new_request_id() -> str:
    return uuid.uuid4().hex
