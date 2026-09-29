"""Interactive ``add-connection`` wizard: add a database connection to a
config file, step by step, without hand-editing YAML.

Invariants (never broken):

* Secrets are REFERENCED, never inlined: the username and password are
  written as private files under ``<config dir>/secrets/`` (0600 in a 0700
  dir on POSIX, a protected DACL on Windows) and the config carries only
  ``username_file`` / ``password_file`` pointers. Run as root, the files
  belong to the account that owns the config (the service account), and
  nothing at all (config, backup, secrets) is written unless every directory
  up to the config's, and to the file a symlinked config points to, is one
  only root can change.
* Nothing is written until every answer is in and the merged config is
  valid: credentials go to staging files first and are moved into place
  together with the config; a failed, refused or interrupted run leaves the
  config and the old secret files byte for byte.
* The edited config is never rewritten in place: a timestamped ``.bak``
  precedes every write, the merged YAML is written to a temp file beside it,
  schema-validated (``load_config``) and then ``os.replace``d over the
  original. The leading comment header is preserved; a config
  ``load_config`` rejects (malformed YAML, a repeated key, a schema error)
  is refused - never rewritten.
* Re-adding an existing connection updates only the fields the wizard
  manages and keeps the rest (``allowed_schemas``, ``session``, ...).
* The optional live test uses the SAME connector + policy machinery as the
  server (``build_connector`` + ``EffectivePolicy.build``), then closes the
  connector.
"""

from __future__ import annotations

import contextlib
import copy
import errno
import getpass
import os
import re
import secrets
import stat
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from universal_db_mcp.config import AppConfig, ConnectionConfig, ResolvedConnection, load_config
from universal_db_mcp.connectors.registry import build_connector
from universal_db_mcp.errors import ConfigError
from universal_db_mcp.security.policy import EffectivePolicy

ENGINES = ["sqlite", "postgres", "mysql", "clickhouse", "oracle", "mssql", "db2"]
DEFAULT_PORTS: dict[str, int] = {
    "postgres": 5432,
    "mysql": 3306,
    "clickhouse": 8123,
    "oracle": 1521,
    "mssql": 1433,
    "db2": 50000,
}

MINIMAL_CONFIG = """\
# universal-db-mcp configuration (created by the add-connection wizard).
# Add connections with: udbmcp add-connection
application:
  transport: stdio
"""

# The fields a wizard run sets. Re-adding an existing connection overwrites
# only these; everything else in its block was written by hand (the schema
# allowlist, session and engine options, timeouts, client certificates) and
# is kept. read_only is not one: every connection is read-only (v1).
_MANAGED_KEYS = ("type", "host", "port", "database", "username_file", "password_file")
_MANAGED_TLS_KEYS = ("enabled", "verify_server", "ca_file")
_MANAGED_FIELDS = frozenset(_MANAGED_KEYS) | {f"tls.{key}" for key in _MANAGED_TLS_KEYS}
# Managed fields a run may leave out without meaning to remove them: --port
# is optional (the engine default), so a password rotation without it must
# not move the connection off its port.
_KEPT_WHEN_OMITTED = ("port",)
# A run that writes credentials writes the whole pair as files, so both
# environment-variable forms go: a password_env left next to a new username
# file (a password-less account) would pair the new login with the old password.
_CREDENTIAL_ENV_KEYS = ("username_env", "password_env")
# Letters, digits, '_' and '-' only, ASCII: the name derives file names, and on
# a normalization-insensitive filesystem (APFS) canonically equivalent Unicode
# names would share one pair of secret files.
_CONNECTION_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_-]{0,63}")
# Windows device names: '<secrets>\NUL.username' is the NUL device whatever
# the extension. Refused on every platform, since a config moves between hosts.
_DEVICE_NAMES = frozenset(
    {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(10)), *(f"lpt{i}" for i in range(10))}
)
# --password-file: a first line longer than this is not a password
PASSWORD_FILE_LIMIT = 64 * 1024

# The accounts the packaged services run as: udbmcp (deb), _udbmcp (pkg).
SERVICE_ACCOUNTS = ("udbmcp", "_udbmcp")


class WizardError(Exception):
    """Fail-closed wizard error: the config is left untouched."""


def _stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%S%f") + "Z"


def validate_connection_name(name: str) -> str:
    if not _CONNECTION_NAME.fullmatch(name):
        raise WizardError(
            f"invalid connection name {name!r}: use 1-64 ASCII letters, digits, '-' or '_', "
            "starting with a letter or '_'"
        )
    if name.lower() in _DEVICE_NAMES:
        raise WizardError(f"invalid connection name {name!r}: it is a reserved Windows device name")
    return name


def _absolute(path: str | None) -> str | None:
    """A path answer made absolute against the wizard's working directory.
    The server resolves what the config names from its own (``/`` for a
    service), so a relative answer would name another file there."""
    return os.path.abspath(os.path.expanduser(path)) if path else path


def secrets_dir_for(config_path: Path) -> Path:
    return Path(os.path.abspath(config_path)).parent / "secrets"


def secret_paths(config_path: Path, name: str, *, has_password: bool) -> tuple[Path, Path | None]:
    """Where a connection's username and password files go (nothing is written)."""
    validate_connection_name(name)
    sdir = secrets_dir_for(config_path)
    return sdir / f"{name}.username", sdir / f"{name}.password" if has_password else None


def _is_root() -> bool:
    return sys.platform != "win32" and os.geteuid() == 0


def _is_system_config(config_path: Path) -> bool:
    from universal_db_mcp.agents import core as agents_core

    parent = Path(os.path.realpath(config_path)).parent
    return parent == Path(os.path.realpath(agents_core.system_config_dir()))


def _config_ownership(config_path: Path, dir_fd: int | None = None) -> tuple[int, int]:
    """(uid, gid) of the config; with *dir_fd*, of the config found in that
    directory (the one _open_root_only_directory checked)."""
    st = os.stat(config_path.name, dir_fd=dir_fd) if dir_fd is not None else config_path.stat()
    return st.st_uid, st.st_gid


def secret_owner(config_path: Path, name: str, dir_fd: int | None = None) -> tuple[int, int] | None:
    """(uid, gid) the secret files must belong to, or None to keep this
    process's own.

    Only root needs one: ``sudo udbmcp add-connection`` on the system config
    would otherwise leave root-only secrets that the service account cannot
    read, and the service would refuse to start. The account comes from the
    config's ownership (read through *dir_fd*, the config's directory, when
    given): its owner when that is not root (deb: udbmcp:udbmcp), else the
    service account its group names (pkg: root:_udbmcp). Raises WizardError,
    before anything is written, when the system config names no account.
    """
    if not _is_root():
        return None
    uid, gid = _config_ownership(config_path, dir_fd)
    if uid != 0:
        return uid, gid
    import grp
    import pwd

    try:
        group = grp.getgrgid(gid).gr_name
    except KeyError:
        group = str(gid)
    if group in SERVICE_ACCOUNTS:
        try:
            account = pwd.getpwnam(group)
        except KeyError:
            pass
        else:
            return account.pw_uid, account.pw_gid
    if not _is_system_config(config_path):
        return None  # root's own config: root-owned secrets are right
    sdir = secrets_dir_for(config_path)
    raise WizardError(
        f"cannot tell which account the service runs as: {config_path} belongs to root:{group}, and "
        f"neither its owner nor its group is a service account ({', '.join(SERVICE_ACCOUNTS)}). Nothing "
        "was written. Give the config to the service account, or create the secret files for it and add "
        "the connection to the config by hand:\n"
        f"  install -d -o <service-account> -g <service-account> -m 700 {sdir}\n"
        f"  install -o <service-account> -g <service-account> -m 600 /dev/null {sdir / (name + '.username')}\n"
        f"  install -o <service-account> -g <service-account> -m 600 /dev/null {sdir / (name + '.password')}"
    )


def _win32_restrict(path: Path, *, directory: bool) -> None:
    """Give *path* a protected DACL, so nothing is inherited from a folder
    another user may have created: full control for SYSTEM, Administrators
    and this account, plus the access its parent directory grants any other
    named account (the service account the MSI lets read the config
    directory), but never an entry for a trustee the secret-file check
    refuses (Everyone, Users, Domain Users, ...). A directory passes the
    entries on to what is created in it."""
    if sys.platform != "win32":
        raise OSError(f"cannot set a Windows DACL on {sys.platform}")
    import ntsecuritycon  # type: ignore[import-untyped]
    import win32api  # type: ignore[import-untyped]
    import win32security  # type: ignore[import-untyped]

    from universal_db_mcp.config import _win32_broad_trustee

    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32security.TOKEN_QUERY)
    grants = [
        (win32security.ConvertStringSidToSid("S-1-5-18"), ntsecuritycon.FILE_ALL_ACCESS),  # SYSTEM
        (win32security.ConvertStringSidToSid("S-1-5-32-544"), ntsecuritycon.FILE_ALL_ACCESS),  # Administrators
        (win32security.GetTokenInformation(token, win32security.TokenUser)[0], ntsecuritycon.FILE_ALL_ACCESS),
    ]
    parent = win32security.GetFileSecurity(str(path.parent), win32security.DACL_SECURITY_INFORMATION)
    parent_dacl = parent.GetSecurityDescriptorDacl()
    for i in range(parent_dacl.GetAceCount() if parent_dacl is not None else 0):
        (ace_type, ace_flags), mask, *rest = parent_dacl.GetAce(i)
        if ace_type != win32security.ACCESS_ALLOWED_ACE_TYPE or ace_flags & win32security.INHERIT_ONLY_ACE:
            continue
        if _win32_broad_trustee(win32security.ConvertSidToStringSid(rest[-1])) is None:
            grants.append((rest[-1], mask))
    inherit = win32security.OBJECT_INHERIT_ACE | win32security.CONTAINER_INHERIT_ACE if directory else 0
    dacl = win32security.ACL()
    for sid, mask in grants:
        dacl.AddAccessAllowedAceEx(win32security.ACL_REVISION, inherit, mask, sid)
    win32security.SetNamedSecurityInfo(
        str(path),
        win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
        None,
        None,
        dacl,
        None,
    )


def _win32_make_private(path: Path, *, directory: bool) -> None:
    """Windows ignores the 0700/0600 modes, and any local user may create a
    folder under ProgramData first: never trust what is there. Replace the
    DACL, then refuse what is still readable by other users or owned by
    another account (an owner can always rewrite the DACL)."""
    # imported here like the other Windows helpers: config's Windows checks
    # are not needed to import the wizard on other platforms
    from universal_db_mcp.config import win32_secret_file_problems

    try:
        _win32_restrict(path, directory=directory)
    except Exception as exc:  # noqa: BLE001 - pywin32 errors are not all OSError
        raise WizardError(f"could not restrict access to {path} ({exc}); refusing to write secrets there") from exc
    problems = win32_secret_file_problems(path)
    if problems:
        raise WizardError(
            f"{path} is not private ({'; '.join(problems)}); refusing to write secrets there. "
            "Remove it and re-run add-connection as an administrator"
        )


def _only_root_can_change(st: os.stat_result) -> bool:
    """Whether only root can add, rename or replace entries in the directory
    *st* describes, as far as its mode bits tell (see _has_extended_acl)."""
    return st.st_uid == 0 and not st.st_mode & (stat.S_IWGRP | stat.S_IWOTH)


# acl_type_t ACL_TYPE_EXTENDED (<sys/acl.h>): the only ACL type macOS has
_ACL_TYPE_EXTENDED = 0x00000100


def _has_extended_acl(fd: int) -> bool:
    """Whether the directory *fd* carries a macOS extended ACL. Its entries do
    not show in the mode bits ('everyone allow add_file,delete_child' leaves
    a directory at 0755), so any one is refused, as the pkg's own trust check
    does (find -acl). On Linux a POSIX ACL's mask shows in the group bits,
    which _only_root_can_change reads."""
    if sys.platform != "darwin":
        return False
    import ctypes

    libc = ctypes.CDLL(None, use_errno=True)
    libc.acl_get_fd_np.restype = ctypes.c_void_p
    libc.acl_get_fd_np.argtypes = [ctypes.c_int, ctypes.c_int]
    libc.acl_free.argtypes = [ctypes.c_void_p]
    ctypes.set_errno(0)
    acl = libc.acl_get_fd_np(fd, _ACL_TYPE_EXTENDED)
    if acl:
        libc.acl_free(acl)
        return True
    err = ctypes.get_errno()
    if err != errno.ENOENT:  # ENOENT: no ACL
        raise OSError(err, f"cannot read the access control list of a directory: {os.strerror(err)}")
    return False


# links followed on the way to a directory (the kernel's own limit, MAXSYMLINKS)
_MAX_LINKS = 40


def _open_root_only_directory(directory: Path) -> int:
    """A descriptor of *directory*, reached from ``/`` one component at a time
    without following a link, through directories that only root can change
    (``/`` and *directory* included; see _only_root_can_change and
    _has_extended_acl). Nobody else can then swap any of them for a link. A
    link met on the way sits in such a directory, so root put it there, and
    it is followed (macOS's /etc -> private/etc). Raises WizardError
    otherwise."""
    parts = list(Path(os.path.abspath(directory)).parts[1:])
    stack = [os.open("/", os.O_RDONLY | os.O_DIRECTORY)]
    names: list[str] = []  # the components the stack holds, for the message
    links = 0
    try:
        while True:
            st = os.fstat(stack[-1])
            acl = _has_extended_acl(stack[-1])
            if acl or not _only_root_can_change(st):
                where = "/" + "/".join(names)
                why = (
                    "carries an access control list (ls -led shows it)"
                    if acl
                    else f"belongs to uid {st.st_uid} with mode {stat.filemode(st.st_mode)}"
                )
                raise WizardError(
                    f"{where} (on the way to {directory}) {why}, so an account other than root can swap what is "
                    "in it for a link; as root, add-connection writes the config and secret files only under "
                    "directories that only root can change, and nothing was written. Run it as the account that "
                    "owns the config instead (sudo -u <account> udbmcp add-connection ...), or keep the config "
                    "in such a directory"
                )
            if not parts:
                break
            part = parts.pop(0)
            if part in ("", "."):
                continue
            if part == "..":
                if len(stack) > 1:
                    os.close(stack.pop())
                    names.pop()
                continue
            try:
                fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=stack[-1])
            except OSError:
                if not stat.S_ISLNK(os.stat(part, dir_fd=stack[-1], follow_symlinks=False).st_mode):
                    raise
                links += 1
                if links > _MAX_LINKS:
                    raise WizardError(f"too many links on the way to {directory}") from None
                target = os.readlink(part, dir_fd=stack[-1])
                if os.path.isabs(target):
                    while len(stack) > 1:
                        os.close(stack.pop())
                    names.clear()
                parts[:0] = Path(target).parts[1:] if os.path.isabs(target) else Path(target).parts
                continue
            stack.append(fd)
            names.append(part)
        return stack.pop()
    finally:
        for fd in stack:
            os.close(fd)


def _refuse_unless_root_only(config_path: Path, target: Path | None = None) -> None:
    """As root, refuse (WizardError) a config that another account could
    redirect, whatever the run writes: every directory on the way to the
    config, and to the file a symlinked config points to (*target*, else
    resolved now), must be one only root can change (see
    _open_root_only_directory). The directory creation, the backup, the temp
    file (given to the config's owner) and the rename then go through
    directories nobody else can swap for a link. A directory that does not
    exist yet is checked through the nearest one that does: only root can
    create anything in it."""
    if not _is_root():
        return
    here = Path(os.path.abspath(config_path)).parent
    for directory in dict.fromkeys((here, (target or Path(os.path.realpath(config_path))).parent)):
        while not os.path.lexists(directory) and directory != directory.parent:
            directory = directory.parent
        os.close(_open_root_only_directory(directory))


def _prepare_secrets_dir(sdir: Path, owner: tuple[int, int] | None, parent_fd: int | None = None) -> int | None:
    """Create the secrets directory, or tighten an existing one (never trust
    it), and return a descriptor of it (None on Windows). With *parent_fd*
    (the config directory, see _open_secrets_dir) it is created and opened
    in that directory, never through its path.

    Every later step works through the returned descriptor, never through
    the path: whoever can write the config directory could otherwise swap
    the directory for a symlink after this check and have the wizard write,
    chmod or rename there."""
    linked = f"{sdir} is a link, not a directory; refusing to write secrets through it"
    if sys.platform == "win32":
        sdir.mkdir(mode=0o700, parents=True, exist_ok=True)
        st = os.lstat(sdir)
        # a junction (mount-point reparse point) reports S_IFDIR too
        reparse = getattr(st, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
        if not stat.S_ISDIR(st.st_mode) or reparse:
            raise WizardError(linked)
        _win32_make_private(sdir, directory=True)
        return None
    if parent_fd is None:
        sdir.mkdir(mode=0o700, parents=True, exist_ok=True)
    else:
        with contextlib.suppress(FileExistsError):
            os.mkdir(sdir.name, 0o700, dir_fd=parent_fd)
    try:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        fd = os.open(sdir.name, flags, dir_fd=parent_fd) if parent_fd is not None else os.open(sdir, flags)
    except OSError as exc:  # ELOOP (a symlink) or ENOTDIR
        raise WizardError(linked) from exc
    try:
        os.fchmod(fd, 0o700)
        if owner is not None:
            os.fchown(fd, *owner)
    except BaseException:
        os.close(fd)
        raise
    return fd


def _open_secrets_dir(config_path: Path, name: str, sdir: Path) -> tuple[tuple[int, int] | None, int | None]:
    """(owner, descriptor) of the prepared secrets directory: see
    secret_owner and _prepare_secrets_dir.

    As root, the config directory is reached through directories only root
    can change, and both the config's owner and the secrets directory are
    looked up in it: root never chmods, chowns or writes through a directory
    another account could swap for a link (the one holding that account's
    own config, say), and never hands such an account a directory elsewhere."""
    if not _is_root():
        return None, _prepare_secrets_dir(sdir, None)
    parent_fd = _open_root_only_directory(sdir.parent)
    try:
        owner = secret_owner(config_path, name, parent_fd)
        return owner, _prepare_secrets_dir(sdir, owner, parent_fd)
    finally:
        os.close(parent_fd)


def _at(path: Path, dir_fd: int | None) -> str | Path:
    """*path*, a file in the secrets directory, as the os functions take it
    along with *dir_fd*: its name relative to the directory's descriptor,
    or the path itself when there is none (Windows)."""
    return path.name if dir_fd is not None else path


def _lstat(path: Path, dir_fd: int | None) -> os.stat_result | None:
    try:
        return os.stat(_at(path, dir_fd), dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _new_file_flags() -> int:
    """An exclusive, no-follow create: an existing file or a planted symlink is
    refused, never written through (O_NOFOLLOW does not exist on Windows)."""
    return os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view) :]
    os.fsync(fd)


def _create_private(path: Path, data: bytes, owner: tuple[int, int] | None, dir_fd: int | None = None) -> None:
    """Create the NEW file *path* (0600) and fill it only once nobody but its
    owner can read it: on Windows a protected DACL, as root *owner* on the
    descriptor. The exclusive, no-follow create refuses an existing file or
    a planted symlink (O_NOFOLLOW does not exist on Windows, where it used
    to escape as a raw AttributeError). A failed write removes the file.
    With *dir_fd* the file is created in that directory."""
    name = _at(path, dir_fd)
    fd = os.open(name, _new_file_flags(), 0o600, dir_fd=dir_fd)
    try:
        if sys.platform == "win32":
            _win32_make_private(path, directory=False)
        elif owner is not None:
            os.fchown(fd, *owner)
        _write_all(fd, data)
    except BaseException:
        os.close(fd)
        with contextlib.suppress(OSError):
            os.unlink(name, dir_fd=dir_fd)
        raise
    os.close(fd)


def _write_secret(path: Path, content: str, owner: tuple[int, int] | None = None, dir_fd: int | None = None) -> None:
    """Create the secret file *path* holding *content* (see _create_private)."""
    _create_private(path, (content + "\n").encode("utf-8"), owner, dir_fd)


def _refuse_linked_secret(path: Path, dir_fd: int | None = None) -> None:
    """A secret file about to be replaced must be a plain file: a symlink,
    reparse point or second hard link could point other readers elsewhere."""
    st = _lstat(path, dir_fd)
    if st is None:
        return
    reparse = getattr(st, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    if not stat.S_ISREG(st.st_mode) or reparse or st.st_nlink > 1:
        raise WizardError(f"{path} is a link or not a regular file; refusing to replace it")


def _read_old_secret(path: Path, dir_fd: int | None) -> tuple[bytes, os.stat_result] | None:
    """The content and status of the secret file *path* about to be
    replaced, or None when there is none. With *dir_fd* (POSIX) it is read
    only from the file that was checked: whoever owns the secrets directory
    could otherwise swap in a FIFO (the open would block; O_NONBLOCK) or a
    hard link to a file only root can read between the check and the open,
    so the descriptor must be a regular file with one link, the one found by
    name."""
    st = _lstat(path, dir_fd)
    if st is None:
        return None
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(_at(path, dir_fd), flags, dir_fd=dir_fd)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as fh:
        opened = os.fstat(fd)
        if dir_fd is not None and (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (st.st_dev, st.st_ino)
        ):
            raise WizardError(
                f"{path} is a link or not a regular file, or was replaced while the wizard ran; refusing to replace it"
            )
        return fh.read(), opened


def _refuse_case_collision(sdir: Path, name: str) -> None:
    """Secret files are named after the connection: on a case-insensitive
    filesystem (macOS, Windows) 'PROD' would reuse the pair of 'prod'."""
    try:
        entries = os.listdir(sdir)
    except FileNotFoundError:
        return
    for entry in sorted(entries):
        stem, _, kind = entry.partition(".")
        if kind in ("username", "password") and stem != name and stem.casefold() == name.casefold():
            raise WizardError(
                f"connection {name!r} differs only in case from the secret file {sdir / entry}; a "
                "case-insensitive filesystem gives both one pair of secret files. Use the existing name, "
                "or pick another one"
            )


def _sudo_uid() -> int | None:
    """The account sudo was run from (SUDO_UID), if any."""
    raw = os.environ.get("SUDO_UID", "")
    return int(raw) if raw.isdigit() else None


def read_password_file(path: str) -> str:
    """The password ``--password-file`` names: the file's first line, less
    its line ending. Raises WizardError.

    Run as root, the password goes into a secret file the config's owner can
    read, so the file must be a regular file with one link, owned by root or
    by the account sudo was run from, and is opened without following a
    symbolic link (O_NONBLOCK: a FIFO is refused, not waited on). A name
    that another account could swap for a link to a root-only file, or for a
    hard link to one, would otherwise hand it that file's first line. The
    directories on the way are not checked: keep the file in a private one."""
    root = _is_root()
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if root:
        flags |= os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        fd = os.open(os.path.expanduser(path), flags)
    except OSError as exc:
        if root and exc.errno == errno.ELOOP:
            raise WizardError(f"password file {path} is a symbolic link; as root, name the file itself") from None
        raise
    with os.fdopen(fd, "rb") as fh:
        if root:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                raise WizardError(f"password file {path} is not a regular file with one link; nothing was written")
            if st.st_uid not in {0, _sudo_uid()}:
                raise WizardError(
                    f"password file {path} belongs to uid {st.st_uid}; as root, add-connection reads a password "
                    "file only from root or the account sudo was run from, and nothing was written"
                )
        line = fh.readline(PASSWORD_FILE_LIMIT + 2).rstrip(b"\r\n")
        if len(line) > PASSWORD_FILE_LIMIT:
            raise WizardError(f"password file {path}: its first line is longer than {PASSWORD_FILE_LIMIT} bytes")
        if not line and fh.read(PASSWORD_FILE_LIMIT).strip():
            # an empty password would register a password-less login
            raise WizardError(f"password file {path} starts with an empty line; the password is its first line")
    try:
        return line.decode("utf-8")
    except UnicodeDecodeError:
        # The codec message would quote a byte of the password.
        raise WizardError(f"password file {path} is not UTF-8 text") from None


class StagedCredentials:
    """A connection's username and password in private staging files
    (``.<name>.<random>.username.tmp``) inside the secrets directory.

    Nothing an existing connection reads changes until :meth:`commit`, which
    runs only once the merged config has been validated; :meth:`discard`
    removes whatever is still staged, so a failed, refused or interrupted
    run leaves the old secret files byte for byte. An omitted or empty
    password produces no password file, and commit then retires the
    connection's old one. Files are created, read, renamed and removed
    through a descriptor of the secrets directory (see
    ``_prepare_secrets_dir``), which :meth:`discard` closes.
    """

    def __init__(self, config_path: Path, name: str, username: str, password: str | None) -> None:
        validate_connection_name(name)  # before any filesystem effect: the name derives paths
        if not username.strip():
            raise WizardError("username must not be empty")
        self.secrets_dir = secrets_dir_for(config_path)
        _refuse_case_collision(self.secrets_dir, name)
        self.username_file, self.password_file = secret_paths(config_path, name, has_password=bool(password))
        self._stale = None if password else self.secrets_dir / f"{name}.password"
        self._staged: list[tuple[Path, Path]] = []  # (staging file, final name)
        self._committed: list[tuple[Path, Path | None]] = []  # (final name, copy of what it replaced)
        self.owner, self._dir_fd = _open_secrets_dir(config_path, name, self.secrets_dir)
        try:
            self._stage(name, "username", username, self.username_file)
            if password and self.password_file is not None:
                self._stage(name, "password", password, self.password_file)
        except BaseException:
            self.discard()
            raise

    def _stage(self, name: str, kind: str, value: str, final: Path) -> None:
        staging = self.secrets_dir / f".{name}.{secrets.token_hex(8)}.{kind}.tmp"
        _write_secret(staging, value, self.owner, self._dir_fd)
        self._staged.append((staging, final))

    def _keep_copy(self, final: Path, stamp: str) -> Path | None:
        """Copy the file *final* is about to replace to ``<final>.bak.<stamp>``.
        As root the copy belongs to the account that owned the original:
        root never hands a file's content to another account."""
        _refuse_linked_secret(final, self._dir_fd)
        old = _read_old_secret(final, self._dir_fd)
        if old is None:
            return None
        content, st = old
        backup = final.with_name(f"{final.name}.bak.{stamp}")
        _create_private(backup, content, (st.st_uid, st.st_gid) if self.owner is not None else None, self._dir_fd)
        return backup

    def _replace(self, src: Path, dst: Path) -> None:
        if self._dir_fd is None:
            os.replace(src, dst)
        elif os.rename in os.supports_dir_fd:
            # renameat (Linux, macOS), which CPython lists under os.rename
            # only; os.replace takes the same descriptors
            os.replace(src.name, dst.name, src_dir_fd=self._dir_fd, dst_dir_fd=self._dir_fd)
        else:
            # no renameat: through the path, once it is seen to still name
            # the directory that was checked
            st, opened = os.lstat(self.secrets_dir), os.fstat(self._dir_fd)
            if not stat.S_ISDIR(st.st_mode) or (st.st_dev, st.st_ino) != (opened.st_dev, opened.st_ino):
                raise WizardError(
                    f"{self.secrets_dir} was replaced while the wizard ran; refusing to write secrets through it"
                )
            os.replace(src, dst)

    def commit(self, stamp: str) -> None:
        """Move the staged files onto their final names, keeping what they
        replace as ``<file>.bak.<stamp>`` (the config's backup stamp)."""
        while self._staged:
            staging, final = self._staged[0]
            backup = self._keep_copy(final, stamp)
            self._committed.append((final, backup))
            self._replace(staging, final)
            self._staged.pop(0)
        if self._stale is not None and _lstat(self._stale, self._dir_fd) is not None:
            _refuse_linked_secret(self._stale, self._dir_fd)
            retired = self._stale.with_name(f"{self._stale.name}.bak.{stamp}")
            self._committed.append((self._stale, retired))
            self._replace(self._stale, retired)
        if self._dir_fd is None:
            _fsync_directory(self.secrets_dir)
        else:
            with contextlib.suppress(OSError):
                os.fsync(self._dir_fd)

    def rollback(self) -> None:
        """Undo :meth:`commit` (the config could not be replaced after all)."""
        while self._committed:
            final, backup = self._committed.pop()
            with contextlib.suppress(OSError, WizardError):
                if backup is None:
                    os.unlink(_at(final, self._dir_fd), dir_fd=self._dir_fd)
                elif _lstat(backup, self._dir_fd) is not None:
                    self._replace(backup, final)

    def discard(self) -> None:
        """Remove every file still staged (after a commit there is none) and
        close the secrets directory."""
        for staging, _final in self._staged:
            with contextlib.suppress(OSError):
                os.unlink(_at(staging, self._dir_fd), dir_fd=self._dir_fd)
        self._staged = []
        if self._dir_fd is not None:
            os.close(self._dir_fd)
            self._dir_fd = None


def store_credentials(
    config_path: Path, name: str, username: str, password: str | None
) -> tuple[Path, Path | None]:
    """Write this connection's username (and password, when provided) as
    private files under ``<config dir>/secrets/`` right away: staged, then
    moved into place (keeping ``.bak`` copies of a replaced pair). Re-running
    for the same connection replaces ITS pair; no other secret file is
    touched. The name is validated before any filesystem effect, an empty
    username is refused, and an omitted/empty password produces no password
    file. ``add-connection`` itself uses :class:`StagedCredentials` and
    commits only once the merged config is valid."""
    staged = StagedCredentials(config_path, name, username, password)
    try:
        staged.commit(_stamp())
    except BaseException:
        staged.rollback()
        raise
    finally:
        staged.discard()
    return staged.username_file, staged.password_file


def build_connection(  # noqa: PLR0913 - explicit wizard answer fields
    *,
    name: str,
    engine: str,
    database: str,
    host: str | None = None,
    port: int | None = None,
    username_file: str | None = None,
    password_file: str | None = None,
    tls_enabled: bool = False,
    tls_ca_file: str | None = None,
    tls_verify_server: bool = True,
) -> ConnectionConfig:
    """Construct (and schema-validate) a ConnectionConfig from wizard answers.
    Path answers (the SQLite file, the secret files, the CA certificate) are
    stored absolute. The connection is read-only, as every one is (v1)."""
    validate_connection_name(name)
    kwargs: dict[str, Any] = {
        "type": engine,
        "database": _absolute(database) if engine == "sqlite" else database,
    }
    if engine != "sqlite":
        kwargs["host"] = host
        if port is not None:
            kwargs["port"] = port
    if username_file:
        kwargs["username_file"] = _absolute(username_file)
    if password_file:
        kwargs["password_file"] = _absolute(password_file)
    if tls_enabled:
        kwargs["tls"] = {
            "enabled": True,
            "verify_server": tls_verify_server,
            "ca_file": _absolute(tls_ca_file),
        }
    return ConnectionConfig(**kwargs)


def _split_header(raw: str) -> tuple[list[str], list[str]]:
    """Split leading comment/blank lines from the YAML body. Returns
    (header_lines, body_lines): comments in the body cannot survive the
    safe_dump rewrite (see :func:`_comment_lines`)."""
    lines = raw.splitlines(keepends=True)
    header: list[str] = []
    body_start = 0
    for i, line in enumerate(lines):
        if line.strip().startswith("#") or not line.strip():
            header.append(line)
            body_start = i + 1
        else:
            break
    return header, lines[body_start:]


def _comment_lines(body: list[str]) -> int:
    """How many lines of the YAML body carry a comment, whole-line or
    trailing: a '#' outside every token (a '#' inside a value is not one)."""
    text = "".join(body)
    if "#" not in text:
        return 0
    spans: list[tuple[int, int]] = []
    try:
        for token in yaml.scan(text):
            start, end = token.start_mark.index, token.end_mark.index
            if isinstance(token, yaml.ScalarToken) and token.style in ("|", ">"):
                # a block scalar's token starts at its '|' or '>': a comment
                # on that indicator line is not part of the value
                line_end = text.find("\n", start, end)
                start = end if line_end < 0 else line_end + 1
            spans.append((start, end))
    except yaml.YAMLError:
        return sum(1 for line in body if line.lstrip().startswith("#"))
    lines = {
        text.count("\n", 0, match.start())
        for match in re.finditer("#", text)
        if not any(start <= match.start() < end for start, end in spans)
    }
    return len(lines)


def _fields(block: dict[str, Any]) -> dict[str, Any]:
    """A connection block's values by field name, the tls ones as ``tls.<key>``."""
    fields: dict[str, Any] = {}
    for key, value in block.items():
        if key == "tls" and isinstance(value, dict):
            fields.update({f"tls.{sub}": sub_value for sub, sub_value in value.items()})
        else:
            fields[str(key)] = value
    return fields


def _update_block(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    """*old* with the wizard-managed fields taken from *new* (an omitted
    port is kept); client certificate settings stay while TLS stays on."""
    block = copy.deepcopy(old)
    for key in _MANAGED_KEYS:
        if key in new:
            block[key] = new[key]
        elif key not in _KEPT_WHEN_OMITTED:
            block.pop(key, None)
    if "username_file" in new:
        for env_key in _CREDENTIAL_ENV_KEYS:
            block.pop(env_key, None)
    new_tls = new.get("tls") or {}
    old_tls = old.get("tls")
    if new_tls.get("enabled") and isinstance(old_tls, dict):
        tls = copy.deepcopy(old_tls)
        for key in _MANAGED_TLS_KEYS:
            if key in new_tls:
                tls[key] = new_tls[key]
            else:
                tls.pop(key, None)
        block["tls"] = tls
    else:
        block["tls"] = new_tls
    return block


@dataclass
class MergePlan:
    """What adding one connection to a config file will change, worked out
    before anything is written."""

    config_path: Path
    name: str
    original: bytes
    header: str
    data: dict[str, Any]
    action: str  # "added", "updated" (in place) or "replaced" (--replace)
    preserved_fields: list[str]  # fields of the existing block this run did not set, kept as they were
    dropped_fields: list[str]
    comment_lines: int
    warnings: list[str] = field(default_factory=list)
    # managed fields an update gives another value: name -> (old, new)
    changes: dict[str, tuple[Any, Any]] = field(default_factory=dict)

    @property
    def replaced(self) -> bool:
        """Whether the connection already existed."""
        return self.action != "added"

    @property
    def changed_fields(self) -> list[str]:
        return sorted(self.changes)

    @property
    def comments_dropped(self) -> bool:
        return self.comment_lines > 0


def _reason(exc: BaseException) -> str:
    """*exc*'s message without its category prefix, which the CLI adds again."""
    category = getattr(exc, "category", None)
    return str(exc).removeprefix(f"{category}: ") if category else str(exc)


def plan_merge(config_path: Path, name: str, connection: ConnectionConfig, *, replace: bool = False) -> MergePlan:
    """Work out the merged config without writing anything.

    An existing connection is updated in place: only the fields the wizard
    manages change (an omitted port is kept), and the ones that change
    value, and the ones it would drop (e.g. ``username_env`` once a username
    file takes over), are listed. A change of engine replaces the whole
    block, so it needs *replace*, which lists everything it drops.

    Refuses (WizardError) a config that is missing, not writable, or that
    ``load_config`` rejects (malformed YAML, a repeated key, a schema
    error), a name that differs only in case from an existing one, and, as
    root, a config another account could redirect (see
    _refuse_unless_root_only).
    """
    _refuse_unless_root_only(config_path)
    if not config_path.is_file():
        raise WizardError(f"config file not found: {config_path}")
    # a symlinked config: the file it points to is the one replaced
    target = Path(os.path.realpath(config_path))
    if not all(
        os.access(path, mode)
        for path, mode in (
            (config_path, os.W_OK),
            (config_path.parent, os.W_OK | os.X_OK),
            (target.parent, os.W_OK | os.X_OK),
        )
    ):
        # The wizard WRITES (config + secret files beside it): defaulting into
        # a readable-but-not-writable config (the root-owned system
        # deployment) would fail halfway through (seen live 2026-09-15).
        raise WizardError(
            f"config {config_path} is not writable by this user; pass --config with a "
            "per-user config (e.g. ~/.universal-db-mcp/config.yaml), or re-run with "
            "sudo to edit the system config (the secret files are then given to the "
            "account that owns the config, the service account)"
        )
    original = config_path.read_bytes()
    try:
        load_config(config_path)
    except (ConfigError, UnicodeDecodeError) as exc:
        raise WizardError(f"config is not valid; refusing to edit ({_reason(exc)})") from exc
    header, body = _split_header(original.decode("utf-8"))
    try:
        data = yaml.safe_load("".join(body))
    except yaml.YAMLError as exc:
        raise WizardError(f"config is not valid YAML; refusing to edit ({exc})") from exc
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise WizardError("config top level must be a mapping; refusing to edit")
    connections = data.get("connections")
    if connections is None:
        connections = {}
        data["connections"] = connections
    if not isinstance(connections, dict):
        raise WizardError("'connections' is not a mapping; refusing to edit")
    for other in connections:
        if other != name and str(other).casefold() == name.casefold():
            raise WizardError(
                f"connection {name!r} differs only in case from the existing {other!r}; secret files are "
                "named after the connection, and a case-insensitive filesystem gives both one pair. Use "
                f"{other!r} to update that connection, or pick another name"
            )

    # read_only is not written: the default is the only value the config accepts
    new = connection.model_dump(mode="json", exclude_none=True, exclude={"read_only"})
    old = connections.get(name)
    preserved: list[str] = []
    warnings: list[str] = []
    changes: dict[str, tuple[Any, Any]] = {}
    old_tls = old.get("tls") if isinstance(old, dict) else None
    if isinstance(old_tls, dict) and old_tls.get("enabled") and not new.get("tls", {}).get("enabled"):
        warnings.append(
            f"TLS for connection {name!r} is turned off by this run (its CA and client certificate settings "
            "are dropped); pass --tls-ca-file, or answer yes to the TLS question, to keep it"
        )
    if not isinstance(old, dict):
        action, block, dropped = "added", new, []
    else:
        old_fields, new_fields = _fields(old), _fields(new)
        replaced_drops = sorted(
            field for field in old_fields if field not in _MANAGED_FIELDS or field not in new_fields
        )
        if replace:
            action, block, dropped = "replaced", new, replaced_drops
        elif old.get("type") != new["type"]:
            raise WizardError(
                f"connection {name!r} is a {old.get('type')} connection; changing its engine to "
                f"{new['type']} replaces the whole block and drops {', '.join(replaced_drops) or 'nothing'}. "
                "Pass --replace to do that"
            )
        else:
            action, block = "updated", _update_block(old, new)
            kept = _fields(block)
            preserved = sorted(
                field
                for field in old_fields
                if field in kept and (field not in _MANAGED_FIELDS or field not in new_fields)
            )
            dropped = sorted(field for field in old_fields if field not in kept)
            changes = {
                field: (value, kept[field])
                for field, value in sorted(old_fields.items())
                if field in _MANAGED_FIELDS and field in new_fields and kept.get(field) != value
            }
    connections[name] = block
    return MergePlan(
        config_path=config_path,
        name=name,
        original=original,
        header="".join(header),
        data=data,
        action=action,
        preserved_fields=preserved,
        dropped_fields=dropped,
        comment_lines=_comment_lines(body),
        warnings=warnings,
        changes=changes,
    )


def _win32_set_owner(path: Path, sid: str) -> None:
    if sys.platform != "win32":
        raise OSError(f"cannot set a Windows owner on {sys.platform}")
    import win32security

    win32security.SetNamedSecurityInfo(
        str(path),
        win32security.SE_FILE_OBJECT,
        win32security.OWNER_SECURITY_INFORMATION,
        win32security.ConvertStringSidToSid(sid),
        None,
        None,
        None,
    )


def _win32_keep_trusted_owner(original: Path, replacement: Path, unchanged: str) -> None:
    """The replacement config belongs to whoever ran the wizard; one that
    replaces a config owned by SYSTEM or Administrators (the MSI's
    machine-wide one, which service.ps1 refuses otherwise on a repair or
    upgrade) is given to Administrators, which an elevated administrator
    may always do. Other owners are left as they are."""
    from universal_db_mcp.config import _WIN32_TRUSTED_OWNERS, _win32_file_security

    try:
        if _win32_file_security(original)[0] not in _WIN32_TRUSTED_OWNERS:
            return
        if _win32_file_security(replacement)[0] not in _WIN32_TRUSTED_OWNERS:
            _win32_set_owner(replacement, "S-1-5-32-544")
    except Exception as exc:  # noqa: BLE001 - pywin32 errors are not all OSError
        raise WizardError(
            f"could not give the new {original.name} to Administrators ({exc}); {unchanged}. Run "
            "add-connection from an elevated prompt"
        ) from exc


def _fsync_directory(directory: Path) -> None:
    if sys.platform == "win32":
        return
    with contextlib.suppress(OSError):
        fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def _create_file(path: Path, data: bytes, mode: int) -> None:
    """Create the NEW file *path* holding *data*, with *mode*. The create is
    exclusive and no-follow, so a file or symlink planted at the path (the
    stamped backup name, a config not created yet) is refused: root would
    otherwise truncate, chmod or create what it points to. A failed write
    removes the file; a file this run did not create is never removed."""
    fd = os.open(path, _new_file_flags(), mode)
    try:
        if sys.platform != "win32":
            os.fchmod(fd, mode)  # the umask narrowed the create
        _write_all(fd, data)
    except BaseException:
        os.close(fd)
        with contextlib.suppress(OSError):
            os.unlink(path)
        raise
    os.close(fd)


def commit_merge(plan: MergePlan, credentials: StagedCredentials | None = None) -> Path:
    """Write the planned config and return its backup path.

    The ``.bak`` copy comes first. The merged YAML then goes to a temp file
    beside the config with the config's mode and group (and owner, as
    root), is fsynced and schema-validated, and replaces the config with
    ``os.replace`` (for a symlinked config, the file the link points to).
    The config itself is never opened for writing, so a
    failure at any step (ENOSPC, a kill) leaves it as it was. Staged
    credentials move into place just before the config and are moved back
    if the config cannot be replaced.
    """
    path = plan.config_path
    # A symlinked config (a dotfile manager, config management) stays a
    # link: the file it points to is the one replaced, and keeps its mode.
    target = Path(os.path.realpath(path))
    # the file the link leads to now, which plan_merge may not have seen: a
    # link target can pass through a directory another account changes
    _refuse_unless_root_only(path, target)
    if path.read_bytes() != plan.original:
        raise WizardError(f"{path} changed while the wizard ran; nothing was written, run add-connection again")
    st = target.stat()
    stamp = _stamp()
    backup = path.with_name(path.name + ".bak." + stamp)
    payload = (plan.header + yaml.safe_dump(plan.data, sort_keys=False)).encode("utf-8")
    unchanged = "the config is unchanged"
    if credentials is not None:
        unchanged = "the config and the connection's secret files are unchanged"
    # The backup takes the config's permission bits only: never setuid, setgid
    # or sticky, and as root (which owns the copy) no write bit for others.
    backup_mode = stat.S_IMODE(st.st_mode) & (0o755 if _is_root() else 0o777)
    try:
        _create_file(backup, plan.original, backup_mode)
    except OSError as exc:
        raise WizardError(f"could not back up {path} ({exc}); {unchanged}") from exc
    tmp: Path | None = None
    try:
        fd, tmp_name = tempfile.mkstemp(dir=target.parent, prefix=f".{target.name}.", suffix=".tmp")
        tmp = Path(tmp_name)
        with os.fdopen(fd, "wb") as fh:
            if _is_root():
                os.fchown(fh.fileno(), st.st_uid, st.st_gid)
            elif sys.platform != "win32" and os.fstat(fh.fileno()).st_gid != st.st_gid:
                # keep the group a service account may read it through (a
                # member of that group may give the file to it)
                with contextlib.suppress(PermissionError):
                    os.fchown(fh.fileno(), -1, st.st_gid)
            if sys.platform != "win32":
                os.fchmod(fh.fileno(), stat.S_IMODE(st.st_mode))
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        try:
            load_config(tmp)
        except ConfigError as exc:
            # a wizard bug must not leave a config the server would refuse
            raise WizardError(f"merged config failed schema validation; {unchanged}: {_reason(exc)}") from exc
        if sys.platform == "win32":
            _win32_keep_trusted_owner(target, tmp, unchanged)
        try:
            if credentials is not None:
                credentials.commit(stamp)
            os.replace(tmp, target)
        except BaseException:
            if credentials is not None:
                credentials.rollback()
            raise
        tmp = None
        _fsync_directory(target.parent)
    except OSError as exc:
        raise WizardError(f"could not write {path} ({exc}); {unchanged} (backup: {backup})") from exc
    finally:
        if tmp is not None:
            with contextlib.suppress(OSError):
                tmp.unlink()
    return backup


def merge_connection(config_path: Path, name: str, connection: ConnectionConfig, *, replace: bool = False) -> Path:
    """Add or update one connection in the config file (see
    :func:`plan_merge` and :func:`commit_merge`). Keeps the leading comment
    header, every other key and the file's mode (a 0640 service-owned config
    must not silently lose its group-read bit). Returns the backup path."""
    return commit_merge(plan_merge(config_path, name, connection, replace=replace))


def ensure_config_exists(config_path: Path) -> bool:
    """Create a minimal valid config when absent. Returns True when created.
    As root, a config another account could redirect is refused first,
    whether or not it exists (see _refuse_unless_root_only)."""
    _refuse_unless_root_only(config_path)
    if config_path.is_file():
        return False
    config_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _create_file(config_path, MINIMAL_CONFIG.encode("utf-8"), 0o600)
    return True


def agent_credentials_notice(secrets_dir: Path, user: str | None = None) -> str:
    """What a stdio registration means for the credentials (names the
    directory, never a file's content). *user* is the account the agents run
    the server as, by default this process's."""
    if user is None:
        try:
            user = getpass.getuser()
        except Exception:  # noqa: BLE001 - no login name: describe it instead
            user = "your user account"
    return (
        f"NOTICE: agents start this server as {user}, so an agent tool that can run shell commands or "
        f"read files can read the database credentials in {secrets_dir} and connect directly, outside "
        "the SQL guard, masking and audit. Give each connection a SELECT-only database login limited to "
        "its allowed schemas, or run the server in HTTP mode under a separate service account."
    )


def test_connection(cfg: AppConfig, name: str) -> dict[str, Any]:
    """Live health check using the same machinery as the server's
    db_test_connection tool (connector + effective policy)."""
    resolved = ResolvedConnection(name, cfg.connections[name])
    policy = EffectivePolicy.build(cfg.security, resolved)
    connector = build_connector(resolved, policy)
    try:
        health = connector.health_check()
    finally:
        close = getattr(connector, "close", None)
        if callable(close):
            close()
    out: dict[str, Any] = {
        "healthy": health.healthy,
        "server_version": health.server_version,
        "latency_ms": health.latency_ms,
    }
    if health.detail:
        out["detail"] = health.detail
    return out


def _ask(prompt: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default is not None else ""
    answer = input(f"{prompt}{suffix}: ").strip()
    return answer or (default or "")


def _default(value: Any) -> str | None:
    """A config value as a prompt default."""
    return None if value is None or value == "" else str(value)


def _existing_block(cfg_path: Path, name: str, engine: str) -> dict[str, Any]:
    """Connection *name* as the config has it now, when it is an *engine*
    connection, for the prompt defaults; {} otherwise. Nothing is validated
    here: plan_merge refuses a config that load_config rejects."""
    try:
        data = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError):
        return {}
    connections = data.get("connections") if isinstance(data, dict) else None
    block = connections.get(name) if isinstance(connections, dict) else None
    return block if isinstance(block, dict) and block.get("type") == engine else {}


def _ask_bool(prompt: str, default: bool = True) -> bool:
    suffix = "Y/n" if default else "y/N"
    answer = input(f"{prompt} [{suffix}]: ").strip().lower()
    if not answer:
        return default
    return answer in ("y", "yes")


def collect_answers_interactive(
    cfg_path: Path,
) -> tuple[str, ConnectionConfig, bool, tuple[str, str | None] | None]:
    """Prompt for every wizard answer on the terminal. The password is read
    via getpass (never echoed, never written to the transcript).

    Nothing is written here: returns (name, connection, run_test,
    credentials), where credentials is (username, password or None) for a
    server-backed engine, for the caller to stage once the merge is known
    to be valid; the connection already names their final files."""
    print(f"Adding a database connection to: {cfg_path}")
    print("Engines:", ", ".join(f"{i + 1}) {e}" for i, e in enumerate(ENGINES)))
    while True:
        choice = _ask("Engine", "1")
        if choice.isdigit() and 1 <= int(choice) <= len(ENGINES):
            engine = ENGINES[int(choice) - 1]
            break
        if choice in ENGINES:
            engine = choice
            break
        print("  pick a number from the list (or type an engine name)")

    name = ""
    while True:
        name = _ask("Connection name")
        try:
            validate_connection_name(name)
            break
        except WizardError as exc:
            print(f"  {exc}")

    # re-adding a connection (a password rotation): offer what it has now
    existing = _existing_block(cfg_path, name, engine)
    tls_block = existing.get("tls")
    existing_tls: dict[str, Any] = tls_block if isinstance(tls_block, dict) else {}

    host: str | None = None
    port: int | None = None
    if engine == "sqlite":
        database = _ask("Database file (absolute path)", _default(existing.get("database")))
    else:
        host = _ask("Host", _default(existing.get("host")) or "127.0.0.1")
        default_port = _default(existing.get("port")) or str(DEFAULT_PORTS[engine])
        while True:
            port_raw = _ask("Port", default_port)
            if port_raw.isdigit() and 1 <= int(port_raw) <= 65535:
                port = int(port_raw)
                break
            print("  port must be a number between 1 and 65535")
        database = _ask("Database", _default(existing.get("database")))

    credentials: tuple[str, str | None] | None = None
    username_file = password_file = None
    if engine != "sqlite":
        while True:
            username = _ask("Username")
            if username.strip():
                break
            print("  username must not be empty")
        password = getpass.getpass("Password (input hidden): ")
        # An empty password simply produces no password file (some databases
        # allow passwordless accounts); a HALF-filled pair is never written.
        credentials = (username, password or None)
        username_file, password_file = secret_paths(cfg_path, name, has_password=bool(password))

    tls_enabled = False
    tls_ca_file: str | None = None
    if engine != "sqlite":
        # Without this the wizard writes a connection the server refuses on
        # every tool call whenever security.require_remote_tls is on.
        tls_enabled = _ask_bool("Use TLS for this connection?", bool(existing_tls.get("enabled", True)))
        while tls_enabled:
            tls_ca_file = _ask("CA certificate file (absolute path)", _default(existing_tls.get("ca_file")))
            if tls_ca_file and Path(tls_ca_file).is_file():
                break
            print("  that file does not exist; TLS verification needs the CA certificate")
            if not _ask_bool("Try another path?", True):
                tls_enabled = False
                tls_ca_file = None

    connection = build_connection(
        name=name,
        engine=engine,
        database=database,
        host=host,
        port=port,
        username_file=str(username_file) if username_file else None,
        password_file=str(password_file) if password_file else None,
        tls_enabled=tls_enabled,
        tls_ca_file=tls_ca_file,
    )
    run_test = _ask_bool("Test the connection now?", True)
    return name, connection, run_test, credentials


def _describe_plan(plan: MergePlan) -> list[str]:
    """What happens to an existing connection's fields (for the prompt and
    the human-readable result)."""
    lines = [f"changed {name}: {old!r} -> {new!r}" for name, (old, new) in plan.changes.items()]
    if plan.preserved_fields:
        lines.append(f"kept as they are: {', '.join(plan.preserved_fields)}")
    if plan.dropped_fields:
        lines.append(f"dropped: {', '.join(plan.dropped_fields)}")
    lines += [f"WARNING: {warning}" for warning in plan.warnings]
    return lines


def confirm_merge(plan: MergePlan, *, accept_comment_loss: bool, ask: bool) -> bool:
    """Whether to go ahead with *plan*.

    Comments after the config's leading header do not survive the rewrite:
    that needs *accept_comment_loss*, or a yes when *ask* (else WizardError).
    When *ask*, updating or replacing an existing connection is confirmed
    too, after showing which fields are kept and which are dropped. Both
    questions default to no."""
    if plan.comments_dropped and not accept_comment_loss:
        loss = (
            f"{plan.config_path} has {plan.comment_lines} comment line(s) after its leading header; "
            "rewriting it keeps only the header (the .bak keeps everything)"
        )
        if not ask:
            raise WizardError(f"{loss}. Pass --accept-comment-loss to go ahead, or move them into the header")
        print(loss)
        if not _ask_bool("Rewrite it without those comments?", False):
            return False
    if plan.replaced and ask:
        how = "replaced as a whole" if plan.action == "replaced" else "updated in place"
        print(f"Connection {plan.name!r} already exists in {plan.config_path}; it will be {how}.")
        for line in _describe_plan(plan) or ["no other field is kept or dropped"]:
            print(f"  {line}")
        if not _ask_bool(f"{'Replace' if plan.action == 'replaced' else 'Update'} {plan.name!r}?", False):
            return False
    return True


def _account_name(owner: tuple[int, int] | None) -> str | None:
    """The login name of the account the secret files were given to (as
    root), or None when they belong to this process's account."""
    if owner is None:
        return None
    import pwd

    try:
        return pwd.getpwuid(owner[0]).pw_name
    except KeyError:
        return f"uid {owner[0]}"


def service_restart_command() -> str:
    """How to restart the packaged service so it loads the edited system config."""
    if sys.platform == "win32":
        return "Restart-Service udbmcp (in an elevated PowerShell)"
    if sys.platform == "darwin":
        return "sudo launchctl kickstart -k system/com.udbmcp.server"
    return "sudo systemctl restart universal-db-mcp"


def apply_connection(
    cfg_path: Path,
    name: str,
    connection: ConnectionConfig,
    *,
    run_test: bool,
    replace: bool = False,
    plan: MergePlan | None = None,
    credentials: StagedCredentials | None = None,
) -> dict[str, Any]:
    """Merge + validate + optionally live-test. Returns a result dict used by
    both the human and --json outputs. *plan* is the already confirmed
    :func:`plan_merge` result; *credentials* are committed together with the
    config."""
    existing = Path(cfg_path)
    if plan is None:
        plan = plan_merge(existing, name, connection, replace=replace)
    backup = commit_merge(plan, credentials)
    cfg = load_config(existing)  # schema-valid (merge already verified)

    # The server refuses a tool call on a non-sqlite connection without TLS
    # whenever security.require_remote_tls is on (the default). The wizard's
    # own live test talks to the connector directly and would NOT hit that
    # gate, so without this preview the wizard could report a healthy
    # connection that fails on every later db_* call.
    require_tls = connection.type != "sqlite" and (
        cfg.security.require_remote_tls or connection.tls.enabled
    )
    would_be_refused = require_tls and not connection.tls.enabled
    policy = {
        "require_tls": require_tls,
        "would_be_refused": would_be_refused,
        "detail": (
            "security.require_remote_tls is true and this connection has no tls block, so the "
            "server will refuse every db_* call on it: add tls.enabled with a ca_file, or set "
            "security.require_remote_tls: false deliberately"
            if would_be_refused
            else "the connection satisfies the server's TLS policy"
        ),
    }
    warnings = list(plan.warnings)
    if not cfg.connections[name].allowed_schemas:
        warnings.append(
            f"connection {name!r} has no allowed_schemas, so agents can read every schema its database "
            f"account can see; list the ones they may read under connections.{name}.allowed_schemas"
        )
    notices: list[str] = []
    result: dict[str, Any] = {
        "config": str(existing),
        "connection": name,
        "engine": connection.type,
        "policy": policy,
        "replaced": plan.replaced,
        "action": plan.action,
        "preserved_fields": plan.preserved_fields,
        "changed_fields": plan.changed_fields,
        "dropped_fields": plan.dropped_fields,
        "kept": True,
        "comments_dropped": plan.comments_dropped,
        "backup": str(backup),
        "tested": False,
        "warnings": warnings,
        "notices": notices,
    }
    system_config = _is_system_config(existing)
    if credentials is not None:
        result["secrets_dir"] = str(credentials.secrets_dir)
        # The system config runs the server as the service account. Any other
        # config is one a stdio agent runs as the account the secret files
        # belong to, whatever its transport says: every registration starts
        # `serve --transport stdio`, and an HTTP server started from it runs
        # as that account too.
        if not system_config:
            notices.append(agent_credentials_notice(credentials.secrets_dir, _account_name(credentials.owner)))
    if system_config:
        result["service_restart"] = service_restart_command()
    if run_test:
        try:
            result["test"] = test_connection(cfg, name)
            result["tested"] = True
        except Exception as exc:
            # A failed live test does NOT roll back the add: the database may
            # simply be down. Report honestly; doctor validates the rest.
            result["test"] = {"healthy": False, "error": f"{type(exc).__name__}: {exc}"}
            result["tested"] = True
        if credentials is not None and credentials.owner is not None:
            notices.append(
                "NOTE: the live test ran as root; the service reads the secret files as their owner (uid "
                f"{credentials.owner[0]}), so run `udbmcp doctor --connectivity` as that account to confirm"
            )
    return result
