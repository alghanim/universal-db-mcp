"""Local metadata cache and deterministic metadata search.

Cache: local SQLite file (separate from queried data sources), keyed by
connection + policy fingerprint, versioned, TTL-bounded, size-limited. Never
persists sampled rows or query results. Authorization changes invalidate
entries because the policy fingerprint is part of the key.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from universal_db_mcp.connectors.base import TableSummary

_SCHEMA_VERSION = 1
_MAX_CACHE_ROWS = 50_000


class MetadataCache:
    def __init__(self, path: str | None, ttl_seconds: float = 300.0) -> None:
        self._path = Path(path) if path else None
        self._ttl = ttl_seconds
        self._lock = threading.Lock()
        if self._path:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._init_db()

    def _connect(self) -> sqlite3.Connection:
        assert self._path is not None
        conn = sqlite3.connect(self._path, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        # 0600: the cache reflects authorization-relevant metadata and must
        # never be group/world readable, regardless of the process umask.
        # Applied after connect (main db) and after the WAL pragma (-wal and
        # -shm sidecars are created lazily), idempotently on every open.
        # Windows: os.chmod is effectively a no-op on NTFS — there are no
        # POSIX mode bits, and the cache file's protection comes from the ACLs
        # it inherits from the state directory. The `except OSError` below
        # already tolerates that, so no platform guard is needed here; the
        # real hardening on Windows is provisioning the state directory ACL.
        for suffix in ("", "-wal", "-shm"):
            sidecar = Path(str(self._path) + suffix)
            try:
                os.chmod(sidecar, 0o600)
            except OSError:
                pass  # sidecar may not exist yet; not a cache-consistency error
        return conn

    def _init_db(self) -> None:
        with self._lock, self._connect() as conn:
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

    def get_tables(self, connection_id: str, policy_fp: str) -> list[TableSummary] | None:
        if not self._path:
            return None
        key = f"tables:{connection_id}:{policy_fp}"
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT retrieved_at, payload FROM cache_entries WHERE cache_key = ? AND schema_version = ?",
                (key, _SCHEMA_VERSION),
            ).fetchone()
        if not row:
            return None
        retrieved_at, payload = row
        if time.time() - retrieved_at > self._ttl:
            return None
        try:
            return [TableSummary(**item) for item in json.loads(payload)]
        except (TypeError, ValueError):
            return None  # undecodable entry is a cache miss, never an error

    def put_tables(self, connection_id: str, policy_fp: str, tables: list[TableSummary]) -> None:
        if not self._path:
            return
        key = f"tables:{connection_id}:{policy_fp}"
        payload = json.dumps([t.__dict__ for t in tables][:_MAX_CACHE_ROWS])
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO cache_entries "
                "(cache_key, schema_version, policy_fingerprint, retrieved_at, payload) "
                "VALUES (?, ?, ?, ?, ?)",
                (key, _SCHEMA_VERSION, policy_fp, time.time(), payload),
            )
            conn.execute(
                "DELETE FROM cache_entries WHERE retrieved_at < ?",
                (time.time() - self._ttl * 10,),
            )

    def invalidate_connection(self, connection_id: str) -> None:
        if not self._path:
            return
        with self._lock, self._connect() as conn:
            conn.execute(
                "DELETE FROM cache_entries WHERE cache_key LIKE ?",
                (f"tables:{connection_id}:%",),
            )


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
