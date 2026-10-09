"""Whether this SQLite build lets the connector read a virtual table.

SQLite row estimates come from the dbstat virtual table, and full-text search
from FTS4/FTS5. A build without the module has no such table, and SQLite 3.40
(Debian 12's) cannot build either under the connector's read-only authorizer:
the table's constructor runs an internal UPDATE check on sqlite_master, which
the authorizer denies. 3.45 (Ubuntu 24.04's) and later do not. Either way the
connector fails closed (no estimate, a refused MATCH), so a test that needs the
table to work asks this rather than whether the build has the module.
"""

from __future__ import annotations

import sqlite3
import tempfile
from contextlib import closing
from functools import cache
from pathlib import Path

from universal_db_mcp.connectors.sqlite import SQLiteConnector


def _reads_under_the_authorizer(setup: str, query: str) -> bool:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "probe.db"
        try:
            with closing(sqlite3.connect(path)) as writer:
                writer.executescript(setup)
        except sqlite3.OperationalError:
            return False  # the build lacks the module
        with closing(sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)) as conn:
            # the connector's own rule; it reads nothing from the instance
            conn.set_authorizer(lambda *args: SQLiteConnector._authorizer(None, *args))  # type: ignore[arg-type]
            try:
                conn.execute(query).fetchall()
            except sqlite3.OperationalError:
                return False
            return True


@cache
def connector_reads_dbstat() -> bool:
    return _reads_under_the_authorizer("CREATE TABLE t (a);", "SELECT 1 FROM dbstat LIMIT 1")


@cache
def connector_reads_fts() -> bool:
    return _reads_under_the_authorizer(
        "CREATE VIRTUAL TABLE f5 USING fts5(a); CREATE VIRTUAL TABLE f4 USING fts4(a);"
        "INSERT INTO f5 VALUES ('ann'); INSERT INTO f4 VALUES ('ann');",
        "SELECT (SELECT a FROM f5 WHERE f5 MATCH 'ann'), (SELECT a FROM f4 WHERE f4 MATCH 'ann')",
    )
