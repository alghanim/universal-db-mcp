"""A connection double that tolerates the session safety profile.

Connectors configure the server session right after connecting (SET ...,
attribute assignment, cursor use). Fakes that returned a bare string as the
connection handle broke on that; this handle accepts everything the hooks do
and records the statements.
"""

from __future__ import annotations

from typing import Any


class SessionHandle:
    def __init__(self) -> None:
        object.__setattr__(self, "statements", [])
        object.__setattr__(self, "attrs", {})

    def execute(self, sql: str, *_a: Any, **_k: Any) -> SessionHandle:
        self.statements.append(sql)
        return self

    def fetchone(self) -> Any:
        return None

    def fetchall(self) -> list[Any]:
        return []

    def cursor(self, *_a: Any, **_k: Any) -> SessionHandle:
        return self

    def close(self) -> None:
        return None

    def __enter__(self) -> SessionHandle:
        return self

    def __exit__(self, *_a: Any) -> None:
        return None

    def __setattr__(self, key: str, value: Any) -> None:
        self.attrs[key] = value
