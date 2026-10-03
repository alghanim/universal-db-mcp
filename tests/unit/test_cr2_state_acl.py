"""Second code review (V2-d, server side): on macOS the audit log, its lock and
the metadata cache refuse a file or directory whose extended ACL grants
anyone but the owner access, the rule doctor's audit-path-acl and
metadata-cache-acl checks report. Deny entries only take access away and stay
accepted."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from universal_db_mcp.services import audit as audit_module
from universal_db_mcp.services.metadata import cache_file_problems

pytestmark = pytest.mark.skipif(sys.platform != "darwin", reason="macOS extended ACLs (chmod +a)")


_ACLED: list[Path] = []


def _acl(path: Path, entry: str) -> None:
    subprocess.run(["/bin/chmod", "+a", entry, str(path)], check=True, capture_output=True)  # noqa: S603
    _ACLED.append(path)


@pytest.fixture(autouse=True)
def _strip_acls():  # type: ignore[no-untyped-def]
    """A 'deny delete' entry would stop pytest removing its temp directories."""
    yield
    while _ACLED:
        subprocess.run(["/bin/chmod", "-N", str(_ACLED.pop())], check=False, capture_output=True)  # noqa: S603


def _private_dir(tmp_path: Path) -> Path:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    return state


def test_an_audit_log_an_acl_lets_others_read_is_refused(tmp_path: Path) -> None:
    log = _private_dir(tmp_path) / "audit.jsonl"
    log.write_text("")
    log.chmod(0o600)
    _acl(log, "everyone allow read")
    with pytest.raises(OSError, match="access control list"):
        audit_module._open_state_file(log, audit_module.os.O_RDWR | audit_module.os.O_APPEND)


def test_an_audit_log_with_only_a_deny_entry_opens(tmp_path: Path) -> None:
    log = _private_dir(tmp_path) / "audit.jsonl"
    log.write_text("")
    log.chmod(0o600)
    _acl(log, "everyone deny delete")
    fd = audit_module._open_state_file(log, audit_module.os.O_RDWR | audit_module.os.O_APPEND)
    audit_module.os.close(fd)


def test_a_cache_an_acl_lets_others_read_is_not_trusted(tmp_path: Path) -> None:
    cache = _private_dir(tmp_path) / "metadata.sqlite"
    cache.write_bytes(b"")
    cache.chmod(0o600)
    assert cache_file_problems(cache, owner_uid=None) == []
    _acl(cache, "everyone allow read")
    problems = cache_file_problems(cache, owner_uid=None)
    assert problems and any("access control list" in p for p in problems), problems


def test_a_cache_directory_an_acl_lets_others_write_is_not_trusted(tmp_path: Path) -> None:
    state = _private_dir(tmp_path)
    cache = state / "metadata.sqlite"
    _acl(state, "everyone allow add_file,delete_child")
    problems = cache_file_problems(cache, owner_uid=None)
    assert problems and any("access control list" in p for p in problems), problems


def test_a_cache_with_only_deny_entries_is_trusted(tmp_path: Path) -> None:
    state = _private_dir(tmp_path)
    cache = state / "metadata.sqlite"
    cache.write_bytes(b"")
    cache.chmod(0o600)
    _acl(state, "everyone deny delete")
    _acl(cache, "everyone deny delete")
    assert cache_file_problems(cache, owner_uid=None) == []
