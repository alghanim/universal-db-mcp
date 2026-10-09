"""Regression tests for the third /code-review max pass (review of
9c457ec..0ad054b) on the guard, the system-schema lists and the redaction
helpers.

Ids are the review's (cr3 FINAL.md / VERDICTS.md): VD-2 (non-ASCII names on
Oracle, Db2 and PostgreSQL; owner decision 2026-10-03: refuse, do not model
the engines' Unicode case folding), VD-1 (information_schema.STATISTICS
.EXPRESSION through NATURAL JOIN), VC-2 (SQLite x IN 'table'), A4-5/E-2/D-4
(catalog caches retained hundreds of MiB), A6-7 (long errors lost their
message), C-1/F-1 (the guard's lexer was quadratic on comments).
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import time
from typing import Any

import pytest

from universal_db_mcp.config import ConnectionConfig, ResolvedConnection, SecurityConfig
from universal_db_mcp.errors import ToolFailure
from universal_db_mcp.models.responses import ErrorCategory
from universal_db_mcp.security.policy import EffectivePolicy
from universal_db_mcp.security.sql_guard import SqlGuard, StaticResolver, code_view, cte_key

_DUMMY = {"oracle": " FROM DUAL", "db2": " FROM SYSIBM.SYSDUMMY1"}


def _guard(
    engine: str,
    listed: set[tuple[str | None, str]],
    *,
    allowed: list[str] | None = None,
    database: str = "d",
) -> SqlGuard:
    os.environ["UDBMCP_TEST_U"] = "x"
    body: dict[str, Any] = {"type": engine, "host": "h", "database": database, "username_env": "UDBMCP_TEST_U"}
    if engine == "sqlite":
        body = {"type": "sqlite", "database": "/nonexistent/x.sqlite"}
    if allowed is not None:
        body["allowed_schemas"] = allowed
    resolved = ResolvedConnection("c", ConnectionConfig.model_validate(body))
    # StaticResolver compares lower-cased names
    objects = {(s.lower() if s else s, n.lower()) for s, n in listed}
    return SqlGuard(engine, EffectivePolicy.build(SecurityConfig(), resolved), StaticResolver(objects))


def _refused(guard: SqlGuard, sql: str) -> ToolFailure:
    with pytest.raises(ToolFailure) as info:
        guard.validate_select(sql)
    return info.value


# --------------------------------------------------------------------------
# VD-2 (and review 2 V1-a, review 1 M4): non-ASCII CTE names and unquoted
# non-ASCII table/schema names are refused on Oracle, Db2 and PostgreSQL
# --------------------------------------------------------------------------

_NON_ASCII_ENGINES = ["oracle", "db2", "postgres"]


@pytest.mark.parametrize("engine", _NON_ASCII_ENGINES)
@pytest.mark.parametrize(
    ("cte", "ref"),
    [
        ('"ᾳ"', "ᾳ"),  # VD-2: U+1FB3, Oracle folds it to ᾼ, Python's upper() to ΑΙ
        ('"ƛ"', "ƛ"),  # VD-2: U+019B
        ("σ", "ς"),  # review 2 V1-a: final sigma
        ("θ", "ϑ"),
        ("μ", "µ"),  # micro sign
        ('"é"', "é"),  # review 1 M4: Oracle reads FROM é as the table É
        ("é", '"é"'),
        ('"tσ"', "tς"),
    ],
)
def test_vd2_a_non_ascii_cte_name_is_refused(engine: str, cte: str, ref: str) -> None:
    guard = _guard(engine, {("HR", "EMPLOYEES")}, allowed=["HR"])
    sql = f"WITH {cte} AS (SELECT 1 AS x{_DUMMY.get(engine, '')}) SELECT x FROM {ref}"
    failure = _refused(guard, sql)
    assert failure.category == ErrorCategory.POLICY
    assert "ASCII" in str(failure)


@pytest.mark.parametrize("engine", _NON_ASCII_ENGINES)
def test_v1a_masking_variant_is_refused(engine: str) -> None:
    """Review 2 V1-a's masking variant (SSN in clear at 2140348's parent)."""
    guard = _guard(engine, {("HR", "PEOPLE")}, allowed=["HR"])
    sql = "WITH σ AS (SELECT 'x' AS ssn FROM HR.PEOPLE UNION ALL SELECT ssn FROM HR.PEOPLE) SELECT * FROM ς"
    assert "ASCII" in str(_refused(guard, sql))


@pytest.mark.parametrize("engine", _NON_ASCII_ENGINES)
@pytest.mark.parametrize("sql", ["SELECT * FROM HR.é", "SELECT * FROM é.EMPLOYEES", "SELECT * FROM HR.EMPLOYEES, ᾳ"])
def test_vd2_an_unquoted_non_ascii_table_or_schema_is_refused(engine: str, sql: str) -> None:
    failure = _refused(_guard(engine, {("HR", "EMPLOYEES"), ("HR", "é")}, allowed=["HR"]), sql)
    assert failure.category == ErrorCategory.POLICY
    assert "ASCII" in str(failure) and "quote" in str(failure)


@pytest.mark.parametrize("engine", _NON_ASCII_ENGINES)
def test_vd2_a_quoted_non_ascii_table_stays_readable(engine: str) -> None:
    guard = _guard(engine, {("HR", "ÉMPLOYÉS"), ("HR", "EMPLOYEES")}, allowed=["HR"])
    result = guard.validate_select('SELECT "nom" FROM HR."ÉMPLOYÉS"')
    assert [(t.schema, t.name) for t in result.tables] == [("HR", "ÉMPLOYÉS")]
    # a quoted non-ASCII name next to an ASCII CTE is never that CTE
    result = guard.validate_select(
        f'WITH e AS (SELECT 1 AS x{_DUMMY.get(engine, "")}) SELECT x FROM e, HR."ÉMPLOYÉS"'
    )
    assert [t.name for t in result.tables if t.schema == "HR"] == ["ÉMPLOYÉS"]


@pytest.mark.parametrize("engine", _NON_ASCII_ENGINES)
def test_vd2_non_ascii_columns_and_literals_stay_allowed(engine: str) -> None:
    guard = _guard(engine, {("HR", "EMPLOYEES")}, allowed=["HR"])
    guard.validate_select('SELECT "prénom", \'café\' AS "boisson" FROM HR.EMPLOYEES')


@pytest.mark.parametrize(
    ("engine", "cte", "ref"),
    [
        ("oracle", "e", "E"),
        ("oracle", '"E"', "e"),
        ("db2", '"E"', "e"),
        ("postgres", "E", "e"),
        ("postgres", '"e"', "E"),
        ("postgres", "Recent_Orders", "recent_orders"),
    ],
)
def test_vd2_ascii_ctes_bind_as_the_engine_folds(engine: str, cte: str, ref: str) -> None:
    guard = _guard(engine, {("HR", "EMPLOYEES")}, allowed=["HR"])
    result = guard.validate_select(f"WITH {cte} AS (SELECT 1 AS x{_DUMMY.get(engine, '')}) SELECT x FROM {ref}")
    assert not [t for t in result.tables if t.schema is None and t.name.lower() == ref.strip('"').lower()]


@pytest.mark.parametrize(
    ("engine", "cte", "ref"),
    [("postgres", '"E"', "e"), ("oracle", '"e"', "e"), ("db2", '"e"', "E")],
)
def test_vd2_an_ascii_reference_the_engine_folds_away_from_the_cte_is_a_table(
    engine: str, cte: str, ref: str
) -> None:
    """PostgreSQL reads FROM e as the table e, not the CTE "E": the guard
    authorizes it as the table (refused: not listed, not qualified)."""
    guard = _guard(engine, {("HR", "EMPLOYEES")}, allowed=["HR"])
    failure = _refused(guard, f"WITH {cte} AS (SELECT 1 AS x{_DUMMY.get(engine, '')}) SELECT x FROM {ref}")
    assert failure.category == ErrorCategory.AUTHZ


@pytest.mark.parametrize("engine", ["mysql", "sqlite", "clickhouse"])
def test_vd2_other_engines_keep_non_ascii_ctes(engine: str) -> None:
    guard = _guard(engine, set())
    guard.validate_select("WITH é AS (SELECT 1 AS x) SELECT x FROM é")


def test_vd2_cte_key_contract() -> None:
    """One key per name: ASCII-exact folding where the engine folds unquoted
    names (Oracle and Db2 upper, PostgreSQL lower), the name as written when
    quoted; elsewhere the name with ASCII letters lowered, quoted or not. No
    Unicode case model: non-ASCII letters are kept as written."""
    from sqlglot import exp

    assert cte_key("oracle", "abc") == "ABC"
    assert cte_key("oracle", exp.to_identifier("abc", quoted=True)) == "abc"
    assert cte_key("oracle", exp.to_identifier("Abc", quoted=False)) == "ABC"
    assert cte_key("db2", "abc") == "ABC"
    assert cte_key("postgres", "AbC") == "abc"
    assert cte_key("postgres", exp.to_identifier("AbC", quoted=True)) == "AbC"
    for engine in ("mysql", "sqlite", "mssql", "clickhouse"):
        assert cte_key(engine, "AbC") == "abc"
        assert cte_key(engine, exp.to_identifier("AbC", quoted=True)) == "abc"
    # no Unicode folding anywhere
    assert cte_key("oracle", "ς") == "ς" != cte_key("oracle", "σ")
    assert cte_key("postgres", "É") == "É" and cte_key("mysql", "É") == "É"
    assert cte_key("oracle", "ıd") == "ıD"


# --------------------------------------------------------------------------
# VD-1: value columns of a catalog view through NATURAL JOIN (or any shape
# whose implicit columns are not named)
# --------------------------------------------------------------------------

_STATS = "information_schema.statistics"


@pytest.mark.parametrize(
    "sql",
    [
        # the verdict's live repro: a blind equality oracle on a denied schema's index literal
        f"SELECT s.index_name, g.zz FROM {_STATS} s NATURAL JOIN "
        "(SELECT 'EXPRESSION', 'zz' UNION ALL SELECT '(`pin` = 4821)', 'hit') g",
        f"SELECT s.index_name FROM {_STATS} s NATURAL LEFT JOIN (SELECT 'x' AS `EXPRESSION`) g",
        f"SELECT g.k FROM (SELECT 1 AS k) g NATURAL JOIN {_STATS} s",
        f"SELECT s.index_name FROM {_STATS} s NATURAL RIGHT JOIN (SELECT 1 AS k) g",
        # the view inside a derived table that still carries it, joined naturally
        f"SELECT 1 FROM (SELECT index_name FROM {_STATS}) s NATURAL JOIN (SELECT 'x' AS index_name) g",
        f"SELECT s.index_name FROM {_STATS} s JOIN (SELECT 'x' AS c) g USING (expression)",
    ],
)
def test_vd1_statistics_natural_join_is_refused(sql: str) -> None:
    guard = _guard("mysql", {("information_schema", "statistics"), ("information_schema", "tables")})
    failure = _refused(guard, sql)
    assert failure.category == ErrorCategory.POLICY and "EXPRESSION" in str(failure), sql


@pytest.mark.parametrize(
    ("engine", "sql"),
    [
        ("oracle", "SELECT c.column_name FROM ALL_TAB_COLUMNS c NATURAL JOIN (SELECT 'x' AS low_value FROM DUAL) g"),
        ("oracle", "SELECT column_name FROM COLS NATURAL JOIN (SELECT 1 AS k FROM DUAL) g"),
        ("db2", "SELECT c.colname FROM SYSCAT.COLUMNS c NATURAL JOIN (SELECT 1 AS k FROM SYSIBM.SYSDUMMY1) g"),
        ("clickhouse", f"SELECT COLUMNS('expr') FROM {_STATS}"),
    ],
)
def test_vd1_other_value_column_views_close_the_same_class(engine: str, sql: str) -> None:
    guard = _guard(engine, {("SYS", "ALL_TAB_COLUMNS"), ("SYSCAT", "COLUMNS"), ("information_schema", "statistics")})
    failure = _refused(guard, sql)
    assert failure.category == ErrorCategory.POLICY


@pytest.mark.parametrize(
    "sql",
    [
        f"SELECT index_name, column_name, seq_in_index FROM {_STATS} WHERE table_schema = 'shop'",
        f"SELECT COUNT(*) FROM {_STATS}",
        f"SELECT s.index_name, t.table_rows FROM {_STATS} s JOIN information_schema.tables t "
        "USING (table_schema, table_name)",
        f"SELECT s.index_name FROM {_STATS} s JOIN information_schema.tables t "
        "ON t.table_schema = s.table_schema AND t.table_name = s.table_name",
    ],
)
def test_vd1_explicit_non_value_columns_stay_readable(sql: str) -> None:
    guard = _guard("mysql", {("information_schema", "statistics"), ("information_schema", "tables")})
    guard.validate_select(sql)


def test_vd1_natural_join_elsewhere_is_unchanged() -> None:
    guard = _guard("mysql", {("shop", "orders"), ("shop", "customers")}, database="shop")
    guard.validate_select("SELECT * FROM shop.orders NATURAL JOIN shop.customers")


# --------------------------------------------------------------------------
# VC-2: SQLite reads x IN 'name' as a table
# --------------------------------------------------------------------------


@pytest.mark.parametrize("sql", ["SELECT 1 WHERE 'x' IN 'docs_content'", "SELECT 1 WHERE 'x' IN 'sqlite_master'",
                                 "SELECT 1 WHERE 'x' NOT IN 'docs'"])
def test_vc2_a_string_after_in_is_refused(sql: str) -> None:
    guard = _guard("sqlite", {(None, "docs")})
    failure = _refused(guard, sql)
    assert failure.category == ErrorCategory.POLICY and "IN" in str(failure)


@pytest.mark.parametrize("sql", ["SELECT 1 FROM docs WHERE body IN ('docs_content')",
                                 "SELECT 1 FROM docs WHERE body IN ('a', 'b')",
                                 "SELECT 1 FROM docs WHERE body IN (SELECT body FROM docs)"])
def test_vc2_value_lists_stay_allowed(sql: str) -> None:
    _guard("sqlite", {(None, "docs")}).validate_select(sql)


# --------------------------------------------------------------------------
# A4-5 / E-2 / D-4: the catalog caches are bounded by what they store
# --------------------------------------------------------------------------


def test_catalog_caches_are_bounded_by_stored_size() -> None:
    from universal_db_mcp.discovery import system_schemas as ss

    expanding = "ﷺ" * 100  # NFKD expands U+FDFA 18-fold
    folded = ss.loose_name(expanding + "x")
    assert len(folded) > 1000
    assert ss._LOOSE_CACHE.get(expanding + "x") is None, "a large expansion is computed, not kept"
    for i in range(5000):
        ss.loose_name(f"é{i:05d}" + "ﬁ" * 100)
        ss.is_session_sql_view("oracle", "é" * 120, f"T{i}")
    for cache in (ss._LOOSE_CACHE, ss._SESSION_SQL_CACHE):
        assert cache.stored <= cache.budget
        assert len(cache) <= cache.max_entries
    # still answers the same, cached or not
    assert ss.loose_name("PROCESSLıST") == "processlist" == ss.loose_name("PROCESSLıST")
    assert ss.is_session_sql_view("mysql", "information_schema", "PROCESSLıST")


def test_catalog_cache_memory_stays_bounded_for_the_ufdfa_repro() -> None:
    """The verdict's repro grew RSS by ~349 MiB, never released: distinct
    128-character names of U+FDFA through loose_name and is_session_sql_view."""
    script = textwrap.dedent(
        """
        import gc, resource, sys
        from universal_db_mcp.discovery import system_schemas as ss
        def rss():
            r = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            return r / (1 << 20) if sys.platform == "darwin" else r / 1024
        ss.loose_name("warm"); gc.collect(); before = rss()
        base = "\\ufdfa" * 118
        for k in range(70):
            for j in range(150):
                name = f"{base}{k:04d}{j:03d}\\U0001F600"
                ss.loose_name(name)
                ss.is_session_sql_view("mysql", "information_schema", name)
        gc.collect()
        print(rss() - before)
        """
    )
    out = subprocess.run(  # noqa: S603 - this interpreter, a fixed script
        [sys.executable, "-c", script], capture_output=True, text=True, check=True, timeout=120
    )
    grown = float(out.stdout.strip())
    assert grown < 40, f"RSS grew {grown:.0f} MiB"


# --------------------------------------------------------------------------
# A6-7: a long error keeps the head of its message, redacted
# --------------------------------------------------------------------------


class InvalidTextRepresentation(Exception):
    pass


@pytest.mark.parametrize(
    "param",
    ["password=" + "a" * 20000, "postgres://" + "u" * 20000, "token:" + "Z" * 17000 + " tail", "x" * 20000],
)
def test_a67_long_errors_keep_their_message(param: str) -> None:
    from universal_db_mcp.security.redact import scrub_exception

    shown = scrub_exception(InvalidTextRepresentation(f'invalid input syntax for type integer: "{param}"'))
    assert shown.startswith("InvalidTextRepresentation: invalid input syntax for type integer: ")
    assert "aaaa" not in shown and "uuuu" not in shown and "ZZZZ" not in shown
    assert len(shown) <= 506


def test_a67_a_secret_cut_at_the_head_is_never_shown(monkeypatch: pytest.MonkeyPatch) -> None:
    from universal_db_mcp.security import redact

    secret = "S3cr3t-Value-0123456789"
    monkeypatch.setattr(redact, "_REGISTERED_SECRETS", [secret])
    prefix = "RuntimeError: "
    head = redact._SCRUB_HEAD_CHARS
    for cut in range(1, len(secret)):
        # the head ends inside the secret, after a value redaction shrank it
        pad = head - len(prefix) - len("token=") - 1 - cut
        text = "token=" + "A" * pad + " " + secret + " " + "y" * 20000
        assert (prefix + text)[:head].endswith(" " + secret[:cut])
        shown = redact.scrub_exception(RuntimeError(text))
        assert shown == prefix + "token=<redacted> [...]", (cut, shown)
    # the verbatim case: plain text up to a cut secret
    for cut in range(1, len(secret)):
        text = "w" * (head - len(prefix) - 1 - cut) + " " + secret + "q" * 20000
        assert (prefix + text)[:head].endswith(" " + secret[:cut])
        shown = redact.scrub_exception(RuntimeError(text))
        assert shown == (prefix + text)[:500] and "S" not in shown.removeprefix("RuntimeError")


def test_a67_scrub_is_linear_on_huge_errors() -> None:
    from universal_db_mcp.security.redact import scrub_exception

    for size in (1 << 20, 4 << 20):
        start = time.perf_counter()
        scrub_exception(RuntimeError("password=" + "a" * size))
        scrub_exception(RuntimeError("for user '" + "x " * (size // 2)))
        assert time.perf_counter() - start < 2.0


# --------------------------------------------------------------------------
# C-1 / F-1 (guard side): the literal/comment scanner is linear
# --------------------------------------------------------------------------


@pytest.mark.parametrize("engine", ["postgres", "clickhouse", "mysql"])
@pytest.mark.parametrize(
    "sql",
    [
        "--\n" * 350_000 + "SELECT 1",  # 1 MiB of line comments (PostgreSQL looked for a CR to the end each time)
        "--\r" * 350_000 + "SELECT 1",
        "/* " * 350_000 + "*/",  # nested openers, one close
        "/* " * 175_000 + "*/ " * 175_000,
        "# x\n" * 260_000 + "SELECT 1",
    ],
)
def test_c1_code_view_is_linear(engine: str, sql: str) -> None:
    start = time.perf_counter()
    view = code_view(sql, engine)
    assert time.perf_counter() - start < 1.0
    assert len(view) == len(sql)


@pytest.mark.parametrize(
    ("engine", "sql", "view"),
    [
        ("postgres", "a --x\r\nb /* c /* d */ e */ f", "a      \nb                       f"),
        ("clickhouse", "a /* /* */ */ b -- c\nd", "a             b     \nd"),
        ("mysql", "a /* /* */ b */ c", "a          b */ c"),
        ("postgres", "a --x\rb --y\nc", "a    \rb    \nc"),
    ],
)
def test_c1_code_view_reads_comments_as_before(engine: str, sql: str, view: str) -> None:
    got = code_view(sql, engine)
    # comments are blanked to spaces; compare the visible code only
    assert got.split() == view.split(), (got, view)
