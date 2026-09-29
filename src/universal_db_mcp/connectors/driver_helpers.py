"""Shared driver plumbing: lazy imports that name the missing artifact,
value adaptation helpers common to remote connectors, and the exact
statement rewrites that let an engine bound values server-side."""

from __future__ import annotations

import base64
import functools
import json
import math
import re
import sqlite3
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from decimal import Decimal
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from pathlib import PurePath
from typing import Any
from uuid import UUID

import sqlglot
from sqlglot import Token, TokenType, exp

from universal_db_mcp.connectors.base import ConnectorError, DriverUnavailableError, SynonymTarget
from universal_db_mcp.discovery.system_schemas import is_session_sql_view
from universal_db_mcp.security.redact import scrub_exception

# ErrorCategory values the server reads from ConnectorError.category.
_QUERY_ERROR = "QUERY_ERROR"
_TIMEOUT = "TIMEOUT"

# Rows asked of the driver per fetch when the row budget allows more.
FETCH_BATCH = 200


def open_module(module_name: str, artifact: str) -> Any:
    """Import an optional driver module or raise the standardized
    'missing local artifact' error. Never downloads."""
    try:
        import importlib

        return importlib.import_module(module_name)
    except ImportError as exc:
        raise DriverUnavailableError(module_name, artifact) from exc


@contextmanager
def translated_driver_errors(phase: str = "connect") -> Iterator[None]:
    """Wrap a driver call so raw driver exceptions become ``ConnectorError``.

    Only PostgreSQL wrapped its driver errors; on every other engine a
    database-side permission denial, missing table or connect failure
    surfaced as ``INTERNAL`` instead of ``CONNECTION``. ``ConnectorError``
    (and its ``DriverUnavailableError`` subclass) pass through untouched —
    messages must already be sanitized — and so does ``TimeoutError``, which
    the executor reports as a driver-level timeout.

    ``phase="execute"`` wraps a statement the engine runs: its failures are
    QUERY_ERROR (the engine rejected the statement or its data) unless the
    connection itself was lost. A statement the engine cancelled at its time
    limit is TIMEOUT in either phase.
    """
    try:
        yield
    except (ConnectorError, TimeoutError):
        raise
    except Exception as exc:  # noqa: BLE001 - deliberately broad: driver boundary
        raise _translated(exc, phase) from exc


def _translated(exc: Exception, phase: str) -> ConnectorError:
    # ibm_db_dbi reports some statement failures (SQL0952N, SQL0801N) as a
    # SystemError from fetchmany; the driver's own error is its context.
    source: BaseException = exc
    if isinstance(exc, SystemError) and exc.__context__ is not None:
        source = exc.__context__
    text = scrub_exception(source)
    if _statement_timed_out(source):
        return ConnectorError(
            f"the statement exceeded its time limit and the database cancelled it ({text})", category=_TIMEOUT
        )
    if phase == "execute" and not _connection_lost(source):
        return ConnectorError(text, category=_QUERY_ERROR)
    return ConnectorError(text)


# ibm_db keeps an error's SQLSTATE only in its message, which the driver
# begins with its own prefix ('[IBM][CLI Driver]', after at most a short
# 'Statement Execute Failed: ' or the ibm_db_dbi class name) and ends with
# 'SQLSTATE=57014 SQLCODE=-952'. What the engine quotes back from the
# statement sits between the two, so only the prefix and the last words count.
_IBM_DB_PREFIX = re.compile(r"[^\[]{0,80}\[IBM\]")
_IBM_DB_SQLSTATE = re.compile(r"SQLSTATE=(\w{5})(?:\s+SQLCODE=-?\d+)?\s*\Z")


def ibm_db_sqlstate(exc: BaseException) -> str | None:
    """The SQLSTATE an ibm_db (or ibm_db_dbi) error ends its message with;
    None for any other message."""
    text = str(exc)
    match = _IBM_DB_SQLSTATE.search(text) if _IBM_DB_PREFIX.match(text) else None
    return match.group(1) if match else None


def _error_code(exc: BaseException) -> tuple[str, Any]:
    """Where the driver keeps the error's code: ('sqlstate', psycopg's
    attribute, or the SQLSTATE ibm_db ends its message with), ('errno',
    PyMySQL's int first argument), ('odbc', pyodbc's SQLSTATE first
    argument), ('oracle', python-oracledb's full_code), ('sqlite', sqlite3's
    result code name) or ('none', None). Engines quote a statement's text
    back in their messages, so a message is never searched for codes."""
    state = getattr(exc, "sqlstate", None)
    if isinstance(state, str):
        return "sqlstate", state
    if isinstance(exc, sqlite3.Error):
        return "sqlite", getattr(exc, "sqlite_errorname", None)
    first = exc.args[0] if exc.args else None
    if isinstance(first, int) and not isinstance(first, bool):
        return "errno", first
    if isinstance(first, str) and re.fullmatch(r"[0-9A-Z]{5}", first) and len(exc.args) > 1:
        return "odbc", first
    full_code = getattr(first, "full_code", None)
    if isinstance(full_code, str):
        return "oracle", full_code
    if (ibm_state := ibm_db_sqlstate(exc)) is not None:
        return "sqlstate", ibm_state
    return "none", None


def _statement_timed_out(exc: BaseException) -> bool:
    """A server- or driver-side statement ceiling fired: SQLSTATE 57014
    (PostgreSQL, Db2 SQL0952N), ODBC HYT00 (not the login timeout), MySQL
    3024 and MariaDB 1969 (max_execution_time / max_statement_time),
    python-oracledb's call timeout, and SQLite's interrupt (the cancel that
    follows a timeout)."""
    kind, code = _error_code(exc)
    if kind == "sqlstate":
        return bool(code == "57014")
    if kind == "errno":
        return code in (3024, 1969)
    if kind == "odbc":
        return code == "HYT00" and "Login timeout" not in str(exc)
    if kind == "oracle":
        return code in ("DPY-4024", "DPI-1067")
    return kind == "sqlite" and code == "SQLITE_INTERRUPT"


def _connection_lost(exc: BaseException) -> bool:
    """The connection failed under a running statement (not the statement
    itself): DB-API InterfaceError, psycopg's client-side OperationalError
    (no SQLSTATE), SQLSTATE classes 08 and 57P (the server ended the
    session), PyMySQL client errors (2000-2999: server gone, connection
    lost) and Oracle's lost-connection errors. A local SQLite file has no
    connection to lose."""
    name = type(exc).__name__
    if name == "InterfaceError" or (name == "OperationalError" and hasattr(exc, "sqlstate") and exc.sqlstate is None):
        return True
    kind, code = _error_code(exc)
    if kind == "sqlstate":
        return bool(code.startswith(("08", "57P")))
    if kind == "errno":
        return bool(2000 <= code < 3000)
    if kind == "odbc":
        return bool(code.startswith("08"))
    if kind == "oracle":
        return code in ("DPY-4011", "ORA-03113", "ORA-03114", "ORA-03135")
    return False


def next_fetch_size(max_rows: int, kept: int) -> int:
    """Rows to ask the driver for next: never more than the one row past
    ``max_rows`` that decides truncation. A fixed batch read up to 200 full
    rows into memory even when only one row could be returned."""
    return max(1, min(FETCH_BATCH, max_rows - kept + 1))


def adapt_row(raw: Any, max_cell_bytes: int) -> tuple[list[Any], list[str], list[int]]:
    """Adapt one driver row to JSON-safe values with per-cell truncation, in
    one pass: the values, their type labels, and the indices of the cells
    cut to the cell limit (so a warning can name their columns).

    Decimal -> string (exact), big ints -> string, datetime/date/time -> ISO
    strings, bytes -> base64 dict, None -> None."""
    vals: list[Any] = []
    labels: list[str] = []
    cut: list[int] = []
    for i, v in enumerate(raw):
        adapted, label, tr = _adapt_one(v, max_cell_bytes)
        vals.append(adapted)
        labels.append(label)
        if tr:
            cut.append(i)
    return vals, labels, cut


def cell_truncated_json(raw: Any, max_cell_bytes: int) -> tuple[list[Any], list[str], bool]:
    """``adapt_row`` with a single truncation flag for the row."""
    vals, labels, cut = adapt_row(raw, max_cell_bytes)
    return vals, labels, bool(cut)


def truncated_cell_indices(raw: Any, max_cell_bytes: int) -> list[int]:
    """Indices of the cells in one driver row whose adapted form exceeded the
    cell limit. This adapts the row again; ``adapt_row`` returns the same
    indices from its single pass."""
    return adapt_row(raw, max_cell_bytes)[2]


def column_names_at(columns: list[tuple[str, str]], indices: list[int]) -> list[str]:
    """Driver-reported column names at ``indices`` (positional fallback when
    the driver reports no name)."""
    names = [c[0] for c in columns]
    return [names[i] if i < len(names) and names[i] else f"column_{i + 1}" for i in indices]


def truncated_column_names(columns: list[tuple[str, str]], raw: Any, max_cell_bytes: int) -> list[str]:
    """Driver-reported column names of the cells in one row that were cut to
    the cell limit. Adapts the row a second time: callers that adapted it
    with ``adapt_row`` pass its indices to ``column_names_at`` instead."""
    return column_names_at(columns, truncated_cell_indices(raw, max_cell_bytes))


def cell_truncation_warning(column_names: list[str], max_cell_bytes: int) -> str:
    """One-line warning naming the columns whose cells were truncated."""
    unique = list(dict.fromkeys(column_names))
    return (
        f"cell value(s) in column(s) {', '.join(repr(n) for n in unique)} exceeded "
        f"the {max_cell_bytes} byte cell limit and were truncated"
    )


def _adapt_one(v: Any, max_cell_bytes: int) -> tuple[Any, str, bool]:
    if v is None:
        return None, "null", False
    if isinstance(v, bool):
        return v, "boolean", False
    if isinstance(v, int):
        if abs(v) < 2**53:
            return v, "integer", False
        return str(v), "bigint", False
    if isinstance(v, float):
        if not math.isfinite(v):
            # inf/NaN are invalid JSON (RFC 8259); exact sentinel strings.
            return ("$nan" if math.isnan(v) else ("$inf" if v > 0 else "-$inf")), "real", False
        return v, "real", False
    if isinstance(v, str):
        text, cut = capped_text(v, max_cell_bytes)
        return text, "text", cut
    if isinstance(v, (bytes, bytearray, memoryview)):
        view = memoryview(v)
        size = view.nbytes
        # a slice of the buffer, never a copy of the whole value
        head = bytes(view.cast("B")[:max_cell_bytes]) if view.c_contiguous else view.tobytes()[:max_cell_bytes]
        if size > max_cell_bytes:
            return {"$binary_b64": base64.b64encode(head).decode(), "$truncated": True}, "blob", True
        return {"$binary_b64": base64.b64encode(head).decode()}, "blob", False
    if isinstance(v, (int,)) is False and hasattr(v, "isoformat"):
        # datetime.datetime / date / time
        return v.isoformat(), "datetime" if hasattr(v, "year") and hasattr(v, "hour") else "date", False
    if isinstance(v, (dict, list, tuple)):
        # psycopg (json/jsonb, arrays), clickhouse-connect (Array/Tuple/Map),
        # python-oracledb (native JSON): the Python repr is NOT JSON (single
        # quotes); emit real JSON so the value round-trips for the consuming
        # agent. Serialized piece by piece, only up to the cell limit: a
        # decoded 30 MB document is never encoded whole.
        label = "json" if isinstance(v, dict) else "array"
        try:
            text, cut = _capped_json(v, max_cell_bytes)
        except (TypeError, ValueError, RecursionError):
            text, cut = capped_text(str(v), max_cell_bytes)
        return text, label, cut
    if isinstance(v, (UUID, IPv4Address, IPv6Address, IPv4Network, IPv6Network, PurePath)):
        return str(v), "text", False
    if isinstance(v, Decimal):
        # Exact string form for fixed-precision values, under the same cap
        # as text: a PostgreSQL numeric carries up to 147455 digits.
        text, cut = capped_text(str(v), max_cell_bytes)
        return text, "decimal", cut
    # Unknown driver-specific objects: string form with the honest generic
    # label — never a fabricated type — under the same cap as text. One value
    # without a usable string form must not fail the whole row.
    try:
        text = str(v)
    except Exception:  # noqa: BLE001 - any __str__ failure
        try:
            text = repr(v)
        except Exception:  # noqa: BLE001 - nor any __repr__ failure
            text = object.__repr__(v)
    text, cut = capped_text(text, max_cell_bytes)
    return text, "text", cut


def _capped_json(v: Any, max_cell_bytes: int) -> tuple[str, bool]:
    """``json.dumps(v, default=str)`` cut like ``capped_text``, produced only
    until it is longer than the cell limit. No circular-reference check: a
    decoded value has no cycles, and the check's markers would keep an
    encoding stopped part-way (and the value) alive in a reference cycle."""
    parts: list[str] = []
    size = 0
    for chunk in json.JSONEncoder(default=str, check_circular=False).iterencode(v):
        parts.append(chunk)
        size += len(chunk)
        if size > max_cell_bytes:
            break
    return capped_text("".join(parts), max_cell_bytes)


def capped_text(v: str, max_cell_bytes: int) -> tuple[str, bool]:
    """``v`` cut to at most ``max_cell_bytes`` UTF-8 bytes, and whether it was
    cut. Only the first ``max_cell_bytes`` characters are encoded: a
    character is at least one byte, so nothing past them can survive, and a
    10 MB value is never encoded (or copied) whole."""
    head = v[:max_cell_bytes]
    data = head.encode("utf-8", errors="replace")
    if len(data) > max_cell_bytes:
        return data[:max_cell_bytes].decode("utf-8", errors="ignore"), True
    return head, len(v) > max_cell_bytes


def synonym_names_refused_view(
    engine: str,
    name: tuple[str, str],
    target: tuple[str, str],
    targets: Mapping[tuple[str, str], tuple[str, str]],
    fallback: str | None = None,
) -> bool:
    """Whether the synonym (Db2: alias) ``name``, its ``target``, or what
    that target names in turn is a view is_session_sql_view refuses;
    ``targets`` holds each synonym's target as the listing read them, so a
    chain is followed through them (APP.S2 -> APP.S1 -> PUBLIC.V$SQL), and
    through the synonym of a target's name in ``fallback`` where the target
    is no synonym (Oracle reads TRAVEL.ALL_DB_LINKS, which is no object, as
    PUBLIC.ALL_DB_LINKS: live). A cycle names nothing more."""
    if is_session_sql_view(engine, *name):
        return True
    seen = {name}
    step: tuple[str, str] | None = target
    while step is not None and step not in seen:
        if is_session_sql_view(engine, *step):
            return True
        seen.add(step)
        nxt = targets.get(step)
        if nxt is None and fallback is not None and (fallback, step[1]) not in seen:
            nxt = targets.get((fallback, step[1]))
            seen.add((fallback, step[1]))
        step = nxt
    return False


SynonymName = tuple[str | None, str]


def synonym_chains(
    names: Sequence[SynonymName],
    targets: Mapping[tuple[str, str], SynonymName | SynonymTarget],
    fold: Callable[[str], str],
    fallback: str | None = None,
) -> dict[SynonymName, list[SynonymTarget]]:
    """What each of ``names`` (as the engine looks them up; None for no
    schema) names through ``targets`` (each synonym's target, as the catalog
    holds them), to the end of its chain: the synonyms whose schema and name
    ``fold`` to the looked-up ones' (a bare name: of any schema; ``fold``
    only what the engine ignores, as Db2 a delimited name's trailing blanks,
    or a namesake in another case is taken for the name), their
    targets, and each target's own in turn, the synonym of its name in
    ``fallback`` too (Oracle reads a synonym for TRAVEL.ALL_DB_LINKS, which
    is no object, through the PUBLIC synonym ALL_DB_LINKS: live). A target
    in another database (SynonymTarget.elsewhere) ends its chain: this
    database's synonyms say nothing of it. Names that name no synonym are
    left out; a cycle names nothing more."""
    keyed: dict[tuple[str, str], list[tuple[str, str]]] = {}  # namesakes once folded: each is followed
    for key in targets:
        keyed.setdefault((fold(key[0]), fold(key[1])), []).append(key)
    by_name: dict[str, list[tuple[str, str]]] = {}
    for folded in keyed:
        by_name.setdefault(folded[1], []).append(folded)
    out: dict[SynonymName, list[SynonymTarget]] = {}
    for schema, name in names:
        frontier = [k for k in by_name.get(fold(name), []) if schema is None or k[0] == fold(schema)]
        seen = set(frontier)
        chain: list[SynonymTarget] = []
        while frontier:
            for key in keyed[frontier.pop(0)]:
                target = SynonymTarget(*targets[key])
                if target not in chain:
                    chain.append(target)
                if target.elsewhere is not None:
                    continue
                for owner in (target[0], fallback):
                    step = (fold(owner), fold(target[1])) if owner is not None else None
                    if step is not None and step in keyed and step not in seen:
                        seen.add(step)
                        frontier.append(step)
        if chain:
            out[(schema, name)] = chain
    return out


# ------------------------------------------------------------------------
# Statement rewrites that bound values server-side. Each is exact or not
# made: the rewritten text is parsed again and must be the statement's own
# tree with only the intended select-list entries changed.

# Tokens that end a SELECT list at parenthesis depth 0.
_SELECT_LIST_END = frozenset({
    TokenType.FROM, TokenType.INTO, TokenType.WHERE, TokenType.GROUP_BY, TokenType.HAVING, TokenType.ORDER_BY,
    TokenType.LIMIT, TokenType.UNION, TokenType.EXCEPT, TokenType.INTERSECT, TokenType.FOR, TokenType.WINDOW,
    TokenType.QUALIFY, TokenType.FETCH, TokenType.OFFSET, TokenType.OPTION, TokenType.LOCK, TokenType.SEMICOLON,
})
_OPENING = frozenset({TokenType.L_PAREN, TokenType.L_BRACKET, TokenType.L_BRACE})
_CLOSING = frozenset({TokenType.R_PAREN, TokenType.R_BRACKET, TokenType.R_BRACE})


@functools.lru_cache(maxsize=8)
def statement_body(sql: str, dialect: str) -> str:
    """``sql`` cut after its last token. Whatever follows it (one ';' or
    several, with whitespace or comments around them: the guard and the
    engines accept 'SELECT ...;;') is a syntax error once the statement is
    nested in parentheses or followed by more text. When the text does not
    tokenize, trailing ';' and whitespace are stripped. Cached: a value cap
    asks for the same statement's body several times."""
    try:
        tokens = sqlglot.Dialect.get_or_raise(dialect).tokenize(sql)
    except Exception:  # noqa: BLE001 - sqlglot's TokenError, and whatever else a tokenizer raises
        return re.sub(r"[;\s]+\Z", "", sql)
    for token in reversed(tokens):
        if token.token_type != TokenType.SEMICOLON:
            return sql[: token.end + 1]
    return sql


def _is_star(node: exp.Expression) -> bool:
    return isinstance(node, exp.Star) or (isinstance(node, exp.Column) and isinstance(node.this, exp.Star))


@dataclass(frozen=True)
class _Entry:
    """One select-list entry: its span in the statement text (end
    exclusive), the span of its expression without the alias, and its
    parsed form."""

    start: int
    end: int
    expr_start: int
    expr_end: int
    node: exp.Expression


# Tokens a first select-list entry may follow (DISTINCT, TOP (n) PERCENT
# WITH TIES, HIGH_PRIORITY SQL_BUFFER_RESULT ...), at most; the one-word
# modifiers, tried first to find where the entry begins.
_MAX_MODIFIER_TOKENS = 16
_SELECT_MODIFIER_WORDS = frozenset({
    "ALL", "DISTINCT", "DISTINCTROW", "HIGH_PRIORITY", "STRAIGHT_JOIN", "SQL_SMALL_RESULT", "SQL_BIG_RESULT",
    "SQL_BUFFER_RESULT", "SQL_CACHE", "SQL_NO_CACHE", "SQL_CALC_FOUND_ROWS",
})


class SelectList:
    """The select list of a statement that is one SELECT, located exactly in
    its text, so that entries can be replaced and nothing else touched."""

    def __init__(
        self, sql: str, tree: exp.Select, tokens: list[Token], segments: list[list[Token]],
        parse: Callable[[str], exp.Expr],
    ) -> None:
        self.sql = sql
        self.tree = tree
        self.tokens = tokens
        self._segments = segments
        self._parse = parse

    @classmethod
    def locate(
        cls, sql: str, dialect: str, *, mask: Callable[[str], str] | None = None, tree: exp.Expr | None = None
    ) -> SelectList | None:
        """The select list of ``sql``, or None when ``sql`` is not one SELECT
        (a UNION, say) or its entries cannot be told apart. ``mask`` rewrites
        the text before parsing (a driver's placeholders that the dialect
        does not read); offsets are always those of ``sql``. ``tree`` is the
        caller's own parse of that text, when it has one."""

        def parse(text: str) -> exp.Expr:
            return sqlglot.parse_one(mask(text) if mask else text, read=dialect)

        try:
            tree = parse(sql) if tree is None else tree
            tokens = sqlglot.Dialect.get_or_raise(dialect).tokenize(sql)
        except Exception:  # noqa: BLE001 - not rewritten: the caller runs the statement as written
            return None
        if not isinstance(tree, exp.Select):
            return None
        # the statement's own SELECT: the first at depth 0 (a WITH clause's
        # queries are in parentheses)
        depth = 0
        first: int | None = None
        for i, token in enumerate(tokens):
            if token.token_type in _OPENING:
                depth += 1
            elif token.token_type in _CLOSING:
                depth -= 1
            elif depth == 0 and token.token_type == TokenType.SELECT:
                first = i
                break
        if first is None:
            return None
        segments: list[list[Token]] = [[]]
        depth = 0
        for token in tokens[first + 1:]:
            if depth == 0 and token.token_type in _SELECT_LIST_END:
                break
            if depth == 0 and token.token_type == TokenType.COMMA:
                segments.append([])
                continue
            if token.token_type in _OPENING:
                depth += 1
            elif token.token_type in _CLOSING:
                depth -= 1
            segments[-1].append(token)
        if len(segments) != len(tree.expressions) or not all(segments):
            return None
        return cls(sql, tree, tokens, segments, parse)

    @functools.cached_property
    def entries(self) -> list[_Entry] | None:
        """Each entry's span, or None when one cannot be delimited; found
        only when a rewrite is asked for. Only what the tokens cannot tell
        is parsed on its own (where the first entry's modifiers end, an
        alias split two ways): parsing every entry again cost about ten
        times the statement's own parse (0.66 s for 1500 entries), and
        ``rewrite`` checks the whole result against the tree anyway."""
        entries: list[_Entry] = []
        for i, (segment, node) in enumerate(zip(self._segments, self.tree.expressions, strict=True)):
            if i == 0:  # the first entry follows the modifiers
                words = next(
                    (k for k, t in enumerate(segment) if t.text.upper() not in _SELECT_MODIFIER_WORDS), len(segment)
                )
                skip = [words, *(k for k in range(min(len(segment), _MAX_MODIFIER_TOKENS)) if k != words)]
                own = next(
                    (segment[k:] for k in skip if self._parses_to(self._parse, self.sql, segment[k:], node)), None
                )
            else:  # a later one is everything between its commas
                own = segment
            if own is None:
                return None
            span = self._expression_span(self._parse, self.sql, own, node)
            if span is None:
                return None
            entries.append(_Entry(own[0].start, own[-1].end + 1, span[0], span[1], node))
        return entries

    def outer_tokens(self) -> list[Token]:
        """The statement's tokens outside any parentheses: its own clauses."""
        depth = 0
        outer: list[Token] = []
        for token in self.tokens:
            if token.token_type in _OPENING:
                depth += 1
            elif token.token_type in _CLOSING:
                depth -= 1
            elif depth == 0:
                outer.append(token)
        return outer

    @staticmethod
    def _parses_to(
        parse: Callable[[str], exp.Expr], sql: str, tokens: list[Token], node: exp.Expression
    ) -> bool:
        """Whether the text of ``tokens`` is exactly ``node`` as a later
        select-list entry (where no modifier can stand)."""
        if not tokens:
            return False
        try:
            probe = parse("SELECT 1, " + sql[tokens[0].start : tokens[-1].end + 1])
        except Exception:  # noqa: BLE001 - not an entry
            return False
        return (
            isinstance(probe, exp.Select)
            and len(probe.expressions) == 2
            and probe.expressions[1] == node
            and not any(v for k, v in probe.args.items() if k != "expressions")
        )

    @classmethod
    def _expression_span(
        cls, parse: Callable[[str], exp.Expr], sql: str, tokens: list[Token], node: exp.Expression
    ) -> tuple[int, int] | None:
        if not isinstance(node, exp.Alias):
            return tokens[0].start, tokens[-1].end + 1
        trailing = tokens[:-1]  # expr [AS] alias
        if trailing and trailing[-1].token_type == TokenType.ALIAS:
            trailing = trailing[:-1]
        leading = tokens[2:] if len(tokens) > 2 and tokens[1].token_type == TokenType.EQ else []  # alias = expr
        if trailing and not leading:
            return trailing[0].start, trailing[-1].end + 1  # the one reading: rewrite() checks it
        for candidate in (trailing, leading):
            if cls._parses_to(parse, sql, candidate, node.this):
                return candidate[0].start, candidate[-1].end + 1
        return None

    def rewrite(
        self, names: Sequence[str | None], wrapped: set[int], wrap: Callable[[str], str], quote: Callable[[str], str]
    ) -> str | None:
        """The statement with each output column at a position in
        ``wrapped`` replaced by ``wrap(<its expression>) AS <its name>``;
        None when that cannot be done exactly. ``names`` are the output
        column names as the engine described them (one per column; a star
        entry stands for several, spelled out when one of them is wrapped).
        """
        entries = self.entries
        if entries is None:
            return None
        stars = [i for i, e in enumerate(entries) if _is_star(e.node)]
        width = len(names) - len(entries) + 1
        if len(stars) > 1 or (stars and width < 1) or (not stars and width != 1):
            return None
        try:
            template = self._parse("SELECT " + wrap("udbmcp_x")).expressions[0]
        except Exception:  # noqa: BLE001 - a wrapper the dialect does not read
            return None

        # every output name as the dialect reads it back, in one parse
        spelled_names = list(dict.fromkeys(str(n) for n in names if n))
        try:
            aliases = self._parse("SELECT " + ", ".join(f"1 AS {quote(n)}" for n in spelled_names)).expressions
            known = {n: a.args["alias"] for n, a in zip(spelled_names, aliases, strict=True)}
        except Exception:  # noqa: BLE001 - one name at a time below, as before
            known = {}

        def identifier(name: str) -> Any:
            if name in known:
                return known[name].copy()
            return self._parse("SELECT 1 AS " + quote(name)).expressions[0].args["alias"]

        def wrapped_node(inner: exp.Expression, name: str | None) -> exp.Expression:
            node = template.copy().transform(
                lambda n: inner.copy() if isinstance(n, exp.Column) and n.name == "udbmcp_x" else n
            )
            return exp.Alias(this=node, alias=identifier(name)) if name else node

        texts: list[str | None] = []  # None: the entry stays as written
        expected: list[exp.Expression] = []
        position = 0
        for i, entry in enumerate(entries):
            span = range(position, position + (width if i in stars else 1))
            position = span.stop
            if not wrapped & set(span):
                texts.append(None)
                expected.append(entry.node.copy())
                continue
            if i not in stars:
                name = names[span.start]
                text = self.sql[entry.expr_start : entry.expr_end]
                inner = entry.node.this if isinstance(entry.node, exp.Alias) else entry.node
                texts.append(wrap(text) + (f" AS {quote(name)}" if name else ""))
                expected.append(wrapped_node(inner, name))
                continue
            # a star is spelled out: only under a qualifier or over a single
            # source can its columns be named unambiguously
            spelled = [names[j] for j in span]
            if (
                (isinstance(entry.node, exp.Star) and self.tree.args.get("joins"))
                or not all(spelled)
                or len({str(n).lower() for n in spelled}) != len(spelled)
            ):
                return None
            prefix = self.sql[entry.start : entry.end - 1]  # 't.' of 't.*'; the entry ends with the star
            parts: list[str] = []
            for j in span:
                name = str(names[j])
                column = exp.Column(this=identifier(name))
                for key in ("table", "db", "catalog"):
                    if isinstance(entry.node, exp.Column) and entry.node.args.get(key) is not None:
                        column.set(key, entry.node.args[key].copy())
                if j in wrapped:
                    parts.append(f"{wrap(prefix + quote(name))} AS {quote(name)}")
                    expected.append(wrapped_node(column, name))
                else:
                    parts.append(prefix + quote(name))
                    expected.append(column)
            texts.append(", ".join(parts))
        rewritten = self.sql
        for entry, replacement in reversed(list(zip(entries, texts, strict=True))):
            if replacement is not None:
                rewritten = rewritten[: entry.start] + replacement + rewritten[entry.end :]
        want = self.tree.copy()
        want.set("expressions", expected)
        try:
            return rewritten if self._parse(rewritten) == want else None
        except Exception:  # noqa: BLE001 - not what was meant: not used
            return None
