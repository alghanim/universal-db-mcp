"""Local metadata cache and deterministic metadata search.

Cache: local SQLite file (separate from queried data sources), keyed by
connection + policy fingerprint + target, versioned, TTL-bounded,
size-limited. Never persists sampled rows or query results. Authorization
changes invalidate entries because the policy fingerprint is part of the
key; so does pointing a connection id at another database, or another login
(connection_target), since the file outlives the process and several configs
may share it.

The cached table lists become the guard's permitted-object set, so the file
is only trusted while it is private to this process's user (POSIX: owned by
the effective uid, no group/other bits, not a symlink or a second hard link,
in a directory no one else can write). Anything else disables the cache: every lookup then reads
the live catalog, and no tool call fails because of the cache. A SQLite error
while the server runs (a busy file, one removed or replaced) is a miss too.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
import sys
import threading
import time
from collections.abc import Iterable
from pathlib import Path
from typing import TYPE_CHECKING, Any

from universal_db_mcp.connectors.base import TableSummary

if TYPE_CHECKING:
    from universal_db_mcp.config import ResolvedConnection

# 2: a table list is stored whole or not at all. Version-1 entries may hold a
# silently truncated list and are discarded on open.
_SCHEMA_VERSION = 2
# Cap on one serialized table list (about 500k objects). A larger catalog is
# not cached at all: a cut-off prefix served as the permitted-object set would
# deny every object past the cut on a hit and allow it on a miss.
_MAX_CACHE_PAYLOAD_BYTES = 64 * 1024 * 1024
# An entry dated further ahead than this was forged or written before the
# clock stepped back; it would never expire, so it is a miss and is removed.
_MAX_CLOCK_SKEW_SECONDS = 60.0

_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)

# The files SQLite keeps beside the cache (WAL mode, or a rollback journal
# when the WAL switch has not happened yet).
_SIDECARS = ("-wal", "-shm", "-journal")


class _CacheDisabled(Exception):
    """The cache file cannot be trusted; the cache is off for this process."""


def connection_target(connection: ResolvedConnection) -> str:
    """Digest of what a connection reaches, and as whom: engine, host, port,
    database (a SQLite file resolved as its connector resolves it), the
    username's source and value, and every option (tns_alias and tns_admin,
    sid, service, unix_socket, ...) but the wallet password, a secret."""
    cfg = connection.config
    database = cfg.database
    if cfg.type == "sqlite" and database:
        try:
            database = str(Path(database).expanduser().resolve())
        except (OSError, RuntimeError):
            pass  # compared as written
    identity = {
        "type": cfg.type,
        "family": cfg.family,
        "host": cfg.host,
        "port": cfg.port,
        "database": database,
        "username_env": cfg.username_env,
        "username_file": cfg.username_file,
        "username": connection.username.value if connection.username is not None else None,
        "options": {k: v for k, v in cfg.options.items() if k != "wallet_password"},
    }
    return hashlib.sha256(json.dumps(identity, sort_keys=True, default=str).encode()).hexdigest()[:32]


def _tables_key(connection_id: str, policy_fp: str, target: str) -> str:
    return f"tables:{connection_id}:{policy_fp}" + (f":{target}" if target else "")


def cache_file_problems(path: Path, *, owner_uid: int | None) -> list[str]:
    """Why the metadata cache at *path* must not be trusted (empty when it
    may be): the file and its SQLite sidecars must be regular files with a
    single link, owned by *owner_uid* with no group/other bits, and the
    directory must be owned by *owner_uid* or root and not writable by group
    or others (owners are not compared when *owner_uid* is None). A sticky
    directory such as /tmp is refused too: the sidecar names are
    predictable, so another user could plant one between this check and
    SQLite opening it. POSIX only: on Windows the state directory's ACL is
    the control (docs/offline-deployment.md)."""
    if sys.platform == "win32":
        return []
    problems: list[str] = []
    try:
        dst = os.stat(path.parent)
    except FileNotFoundError:
        return []  # nothing there to trust yet; the cache creates it 0700
    except OSError as exc:
        return [f"cannot inspect directory '{path.parent}': {exc}"]
    if dst.st_mode & 0o022:
        problems.append(
            f"directory '{path.parent}' is writable by other users ({stat.filemode(dst.st_mode)}, "
            f"owner uid {dst.st_uid})"
        )
    elif owner_uid is not None and dst.st_uid not in (owner_uid, 0):
        problems.append(f"directory '{path.parent}' is owned by uid {dst.st_uid}, not uid {owner_uid} or root")
    for suffix in ("", *_SIDECARS):
        f = f"{path}{suffix}"
        try:
            st = os.lstat(f)
        except FileNotFoundError:
            continue
        except OSError as exc:
            problems.append(f"cannot inspect '{f}': {exc}")
            continue
        if stat.S_ISLNK(st.st_mode):
            problems.append(f"'{f}' is a symlink")
        elif not stat.S_ISREG(st.st_mode):
            problems.append(f"'{f}' is not a regular file")
        elif st.st_nlink > 1:
            problems.append(f"'{f}' has {st.st_nlink} hard links (another name for the same file)")
        else:
            if owner_uid is not None and st.st_uid != owner_uid:
                problems.append(f"'{f}' is owned by uid {st.st_uid}, not uid {owner_uid}")
            if st.st_mode & 0o077:
                problems.append(f"'{f}' is accessible to group/other ({stat.filemode(st.st_mode)})")
    return problems


class MetadataCache:
    def __init__(self, path: str | None, ttl_seconds: float = 300.0) -> None:
        self._path = Path(path) if path else None
        self._ttl = ttl_seconds
        self._lock = threading.Lock()
        self._oversize_reported: set[str] = set()
        self._schema_ready = False
        if self._path:
            self._path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            try:
                with self._lock, self._connect():
                    pass
            except _CacheDisabled:
                pass
            except sqlite3.OperationalError as exc:
                # Another server process is creating the same file right now
                # (the WAL switch answers SQLITE_BUSY); the first lookup
                # finishes the job. Anything else, such as a file that is not
                # SQLite, still fails startup, as doctor reports beforehand.
                if not _busy(exc):
                    raise

    def _disable(self, reason: str) -> _CacheDisabled:
        print(
            f"universal-db-mcp: metadata cache disabled (every lookup reads the live catalog): {reason}",
            file=sys.stderr,
        )
        self._path = None
        return _CacheDisabled(reason)

    def _refuse_if_unsafe(self, path: Path) -> None:
        owner_uid = None if sys.platform == "win32" else os.geteuid()
        problems = cache_file_problems(path, owner_uid=owner_uid)
        if problems:
            raise self._disable("; ".join(problems))

    def _connect(self) -> sqlite3.Connection:
        path = self._path
        if path is None:
            raise _CacheDisabled("disabled")
        # Checked before anything is created: as root, in a directory the
        # service account owns, a root-owned cache file would disable the
        # service's cache for good.
        self._refuse_if_unsafe(path)
        # Create a missing file 0600 without following a planted symlink
        # (O_EXCL also refuses a dangling one). Other errors are left to
        # sqlite3.connect, which reports them as before.
        try:
            os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW, 0o600))
        except OSError:
            pass
        conn = sqlite3.connect(path, check_same_thread=False)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            # 0600: the cache reflects authorization-relevant metadata and must
            # never be group/world readable, regardless of the process umask.
            # Applied after connect (main db) and after the WAL pragma (-wal and
            # -shm sidecars are created lazily), idempotently on every open.
            # Windows: os.chmod is effectively a no-op on NTFS — there are no
            # POSIX mode bits, and the cache file's protection comes from the ACLs
            # it inherits from the state directory; the real hardening on Windows
            # is provisioning the state directory ACL. Any failure other than a
            # missing sidecar means the file is not ours to trust.
            for suffix in ("", *_SIDECARS):
                sidecar = Path(str(path) + suffix)
                try:
                    os.chmod(sidecar, 0o600)
                except FileNotFoundError:
                    pass  # sidecar may not exist yet; not a cache-consistency error
                except OSError as exc:
                    raise self._disable(f"cannot make '{sidecar}' private: {exc}") from exc
            self._refuse_if_unsafe(path)
            if not self._schema_ready:
                self._create_schema(conn)
                self._schema_ready = True
        except BaseException:
            conn.close()
            raise
        return conn

    def _sqlite_failed(self) -> None:
        """A SQLite error makes a lookup a miss and a write a no-op. The next
        call re-runs the (idempotent) schema setup, in case the file was
        removed or replaced."""
        self._schema_ready = False

    @staticmethod
    def _create_schema(conn: sqlite3.Connection) -> None:
        with conn:
            conn.execute("CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT)")
            row = None
            try:
                row = conn.execute("SELECT v FROM meta WHERE k = 'schema_version'").fetchone()
            except sqlite3.Error:
                row = None
            stale = row is not None and row[0] != str(_SCHEMA_VERSION)
            if stale:
                # A cache file written by a different build must be discarded,
                # not decoded (the cache is versioned; spec §10).
                conn.execute("DROP TABLE IF EXISTS cache_entries")
            conn.execute(
                "CREATE TABLE IF NOT EXISTS cache_entries ("
                " cache_key TEXT PRIMARY KEY,"
                " schema_version INTEGER NOT NULL,"
                " policy_fingerprint TEXT NOT NULL,"
                " retrieved_at REAL NOT NULL,"
                " payload TEXT NOT NULL)"
            )
            if row is None or stale:
                conn.execute(
                    "INSERT OR REPLACE INTO meta (k, v) VALUES ('schema_version', ?)",
                    (str(_SCHEMA_VERSION),),
                )

    def get_tables(self, connection_id: str, policy_fp: str, *, target: str = "") -> list[TableSummary] | None:
        """The table list cached for the connection under this policy and
        target (connection_target), or None."""
        if not self._path:
            return None
        key = _tables_key(connection_id, policy_fp, target)
        now = time.time()
        try:
            with self._lock, self._connect() as conn:
                row = conn.execute(
                    "SELECT retrieved_at, payload FROM cache_entries WHERE cache_key = ? AND schema_version = ?",
                    (key, _SCHEMA_VERSION),
                ).fetchone()
                if row and row[0] > now + _MAX_CLOCK_SKEW_SECONDS:
                    conn.execute("DELETE FROM cache_entries WHERE cache_key = ?", (key,))
                    return None
        except _CacheDisabled:
            return None
        except sqlite3.Error:
            self._sqlite_failed()
            return None
        if not row:
            return None
        retrieved_at, payload = row
        if now - retrieved_at > self._ttl:
            return None
        try:
            return [TableSummary(**item) for item in json.loads(payload)]
        except (TypeError, ValueError):
            return None  # undecodable entry is a cache miss, never an error

    def put_tables(
        self, connection_id: str, policy_fp: str, tables: list[TableSummary], *, target: str = ""
    ) -> None:
        if not self._path:
            return
        key = _tables_key(connection_id, policy_fp, target)
        payload = json.dumps([t.__dict__ for t in tables])
        oversized = len(payload) > _MAX_CACHE_PAYLOAD_BYTES
        now = time.time()
        try:
            with self._lock, self._connect() as conn:
                if oversized:
                    # never cache part of the list; drop an older whole one too
                    conn.execute("DELETE FROM cache_entries WHERE cache_key = ?", (key,))
                else:
                    conn.execute(
                        "INSERT OR REPLACE INTO cache_entries "
                        "(cache_key, schema_version, policy_fingerprint, retrieved_at, payload) "
                        "VALUES (?, ?, ?, ?, ?)",
                        (key, _SCHEMA_VERSION, policy_fp, now, payload),
                    )
                conn.execute(
                    "DELETE FROM cache_entries WHERE retrieved_at < ? OR retrieved_at > ?",
                    (now - self._ttl * 10, now + _MAX_CLOCK_SKEW_SECONDS),
                )
                if oversized and connection_id not in self._oversize_reported:
                    self._oversize_reported.add(connection_id)
                    print(
                        f"universal-db-mcp: metadata of connection '{connection_id}' not cached: "
                        f"{len(tables)} objects serialize to {len(payload)} bytes "
                        f"(cap {_MAX_CACHE_PAYLOAD_BYTES}); every lookup reads the live catalog",
                        file=sys.stderr,
                    )
        except _CacheDisabled:
            return
        except sqlite3.Error:
            self._sqlite_failed()

    def invalidate_connection(self, connection_id: str) -> None:
        if not self._path:
            return
        try:
            with self._lock, self._connect() as conn:
                # a prefix, not LIKE: '_' in a connection id is a wildcard there
                prefix = f"tables:{connection_id}:"
                conn.execute(
                    "DELETE FROM cache_entries WHERE substr(cache_key, 1, ?) = ?",
                    (len(prefix), prefix),
                )
        except _CacheDisabled:
            return
        except sqlite3.Error:
            self._sqlite_failed()


def _busy(exc: sqlite3.Error) -> bool:
    """SQLITE_BUSY or SQLITE_LOCKED (extended codes included): another
    connection holds the lock right now."""
    return (getattr(exc, "sqlite_errorcode", 0) & 0xFF) in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED)


def rank_search(
    query: str,
    items: Iterable[tuple[str, str, str, str]],
    cap: int,
) -> list[dict[str, Any]]:
    """Deterministic lexical ranking. Items: (connection, schema, name, kind).
    Scores are ranking scores, not calibrated probabilities.

    Ranking: exact name > prefix > substring > token match; secondary sort by
    (connection, schema, name) for determinism. Match reasons are returned."""
    q = query.lower().strip()
    if not q:
        return []
    tokens = set(q.replace("_", " ").split())
    scored: list[tuple[float, str, str, str, str, list[str]]] = []
    for connection, schema, name, kind in items:
        low = name.lower()
        reasons: list[str] = []
        score = 0.0
        if low == q:
            score = 100.0
            reasons.append("exact name match")
        elif low.startswith(q):
            score = 80.0
            reasons.append("name starts with query")
        elif q in low:
            score = 60.0
            reasons.append("name contains query")
        else:
            name_tokens = set(low.replace("_", " ").split())
            hits = tokens & name_tokens
            if hits:
                score = 30.0 * len(hits) / max(len(tokens), 1)
                reasons.append("token overlap: " + ", ".join(sorted(hits)))
        if score > 0:
            scored.append((score, connection, schema, name, kind, reasons))
    scored.sort(key=lambda t: (-t[0], t[1], t[2] or "", t[3]))
    return [
        {
            "connection_id": c,
            "schema": s,
            "name": n,
            "kind": k,
            "score": round(sc, 1),
            "matched_because": rs,
        }
        for sc, c, s, n, k, rs in scored[:cap]
    ]
