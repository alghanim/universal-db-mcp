"""Whether this SQLite build lets the connector read the dbstat virtual table.

SQLite row estimates come from dbstat. A build without SQLITE_ENABLE_DBSTAT_VTAB
has no such table, and SQLite 3.40 (Debian 12's) cannot build it under the
connector's read-only authorizer: the table's constructor runs an internal
UPDATE check on sqlite_master, which the authorizer denies. 3.45 (Ubuntu
24.04's) and later do not. Either way the estimates are None, by design, so a
test that needs one asks this rather than whether the build has dbstat.
"""

from __future__ import annotations

import sqlite3
import tempfile
from contextlib import closing
from functools import cache
from pathlib import Path

from universal_db_mcp.connectors.sqlite import SQLiteConnector


@cache
def connector_reads_dbstat() -> bool:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "probe.db"
        with closing(sqlite3.connect(path)) as writer:
            writer.execute("CREATE TABLE t (a)")
        with closing(sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)) as conn:
            # the connector's own rule; it reads nothing from the instance
            conn.set_authorizer(lambda *args: SQLiteConnector._authorizer(None, *args))  # type: ignore[arg-type]
            try:
                conn.execute("SELECT 1 FROM dbstat LIMIT 1").fetchall()
            except sqlite3.OperationalError:
                return False
            return True
