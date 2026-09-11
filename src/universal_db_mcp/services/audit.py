"""Local JSONL audit log with size rotation.

Records: connection id, authenticated caller, action/tool, timing, row count,
policy outcome, and a redacted SQL fingerprint. Raw SQL text, bound values,
and rows are recorded only when explicitly enabled by policy (off by
default). Never records credentials or connection objects.

``audit_fail_closed=true`` (default) means a failure to write a required
audit record fails the operation (operations fail closed).
"""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any

from universal_db_mcp.security.redact import redact_value


class AuditWriteFailure(RuntimeError):
    pass


class AuditLog:
    def __init__(
        self,
        path: str | None,
        max_bytes: int = 50 * 1024 * 1024,
        max_backups: int = 5,
        fail_closed: bool = True,
    ) -> None:
        self._path = Path(path) if path else None
        self._max_bytes = max_bytes
        self._max_backups = max_backups
        self._fail_closed = fail_closed
        # Audit writes come from worker threads (anyio.to_thread), so the
        # size-check + rotation + append sequence must be atomic. Without
        # this lock, two threads can both decide to rotate and the second
        # rename fails (source already moved), which under fail-closed
        # wrongly refuses a legitimate request.
        self._lock = threading.Lock()

    def record(self, event: dict[str, Any]) -> None:
        """Append one audit record. Raises AuditWriteFailure when fail-closed
        is enabled and the write did not succeed."""
        if self._path is None:
            return
        event = redact_value(event)
        event = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), **event}
        line = json.dumps(event, separators=(",", ":"), default=str) + "\n"
        try:
            with self._lock:
                self._rotate_if_needed()
                self._path.parent.mkdir(parents=True, exist_ok=True)
                with open(self._path, "a", encoding="utf-8") as fh:
                    fh.write(line)
                    fh.flush()
                    os.fsync(fh.fileno())
        except OSError as exc:
            if self._fail_closed:
                raise AuditWriteFailure(
                    f"audit log write to '{self._path}' failed and "
                    f"application.audit_fail_closed=true; operation refused "
                    f"({exc})"
                ) from exc

    def _rotate_if_needed(self) -> None:
        if not self._path or self._max_backups <= 0:
            return
        try:
            if self._path.stat().st_size < self._max_bytes:
                return
        except OSError:
            return
        for i in range(self._max_backups - 1, 0, -1):
            src = self._path.with_suffix(self._path.suffix + f".{i}")
            dst = self._path.with_suffix(self._path.suffix + f".{i + 1}")
            if src.exists():
                src.replace(dst)
        self._path.replace(self._path.with_suffix(self._path.suffix + ".1"))
