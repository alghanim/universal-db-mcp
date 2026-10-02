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

# Literal values registered by ``SecretMark`` (and any other secret holder).
# ``redact_text`` scrubs these verbatim — longest first — so that even when a
# secret is embedded in free text by a driver or library, it is replaced
# before anything is logged or echoed. Kept in-process only; never serialized.
_REGISTERED_SECRETS: list[str] = []


def register_secret(value: str) -> None:
    """Record a literal secret value for scrubbing by :func:`redact_text`."""
    if value and value not in _REGISTERED_SECRETS:
        _REGISTERED_SECRETS.append(value)


@dataclass(slots=True)
class SecretMark:
    """Carries a secret through internal calls; never serializes its value."""

    value: str

    def __post_init__(self) -> None:
        # Register the literal so that if the value ever reaches free text
        # (e.g. a driver auth-failure message embedding the username),
        # redact_text scrubs it before anything is logged or echoed.
        register_secret(self.value)

    def __repr__(self) -> str:  # pragma: no cover - safety net
        return "'<redacted>'"

    def __str__(self) -> str:
        return "<redacted>"


def redact_text(text: str) -> str:
    """Best-effort scrub of common credential shapes from free text."""
    if not text:
        return text
    patterns = [
        # MySQL's own "(using password: YES)" is a hint, not a value: cut, it
        # took the closing quote and parenthesis of PyMySQL's (errno, "...")
        # wrapper with it, and the error then lost its errno and message.
        (
            re.compile(
                r"(?i)(password|passwd|pwd|token|secret|api[_-]?key)\s*[=:]\s*(?!(?<=using password: )(?:YES|NO)\))\S+"
            ),
            r"\1=<redacted>",
        ),
        (re.compile(r"(?i)(postgres(?:ql)?|mysql|db2|oracle|mssql|clickhouse)://[^\s]+"), r"\1://<redacted-url>"),
        # Backstop: usernames embedded by driver auth-failure messages.
        # keyword=value / keyword: value / keyword "value" forms.
        (re.compile(r"(?i)\b(user(?:name)?|uid|login)\s*[=:]\s*['\"]?[^'\"\s;@]+"), r"\1=<redacted>"),
        # keyword + quoted value (PG/MSSQL/MySQL style: for user 'svc_ro').
        (re.compile(r"(?i)\b((?:for\s+)?user(?:name)?|uid|login)\s+(['\"])[^'\"\s;@]+\2"), r"\1 <redacted>"),
        # keyword + bare value after the specific "for user" phrasing.
        (re.compile(r"(?i)\b(for user)\s+[^'\"\s;@]+"), r"\1 <redacted>"),
        # ClickHouse names the login first: DB::Exception: svc_ro: Authentication
        # failed (the name may hold spaces and colons, live 26.3).
        (re.compile(r"(DB::Exception: )[^\n]*?(?=: Authentication failed)"), r"\1<redacted>"),
    ]
    out = text
    for pat, repl in patterns:
        out = pat.sub(repl, out)
    # Registered SecretMark literals, longest first. Matched as standalone
    # tokens (no adjacent word characters) so a short or generic secret is
    # still scrubbed wherever it appears as a value, without shredding
    # unrelated text that merely contains it as a substring.
    for secret in sorted(_REGISTERED_SECRETS, key=len, reverse=True):
        if not secret:
            continue
        out = re.sub(
            r"(?<!\w)" + re.escape(secret) + r"(?!\w)",
            "<redacted>",
            out,
        )
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


# Quoted literals in the unrolled form: the old (?:[^']|'')* pushed one
# backtrack frame per character of an unterminated literal (~150 bytes each,
# ~300 MB for a 2M-character statement). This form matches the same text.
_SQ_LITERAL = re.compile(r"'[^']*(?:''[^']*)*'")
_DQ_LITERAL = re.compile(r'"[^"]*(?:""[^"]*)*"')
# The SQL guard refuses statements over 64 KiB, so no longer statement ever
# runs; only this prefix (plus the full length) is fingerprinted, which bounds
# the work done on the event loop for hostile input.
_FINGERPRINT_MAX_CHARS = 65536


def sql_fingerprint(sql: str) -> str:
    """Stable fingerprint of a statement with literal values removed.

    This is not a parser-grade rewrite: string/number literals are replaced
    with ``?`` by a conservative scanner, then hashed. Raw SQL text is never
    stored when ``audit_sql_text`` is false (the default).
    """
    s = _SQ_LITERAL.sub("?", sql[:_FINGERPRINT_MAX_CHARS])
    s = _DQ_LITERAL.sub("?", s)
    s = re.sub(r"\b\d+(?:\.\d+)?\b", "?", s)
    s = re.sub(r"\s+", " ", s).strip().lower()
    if len(sql) > _FINGERPRINT_MAX_CHARS:
        s += f" [{len(sql)} chars]"
    # surrogatepass: a lone surrogate (a JSON \\udcff escape) must not raise
    # here, in the audit path, after the statement ran (R2); the audit
    # digests encode the same way.
    return "sha256:" + hashlib.sha256(s.encode("utf-8", "surrogatepass")).hexdigest()


def new_request_id() -> str:
    return uuid.uuid4().hex
