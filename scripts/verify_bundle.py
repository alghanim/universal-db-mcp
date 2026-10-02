#!/usr/bin/env python3
"""Stage B, step 1: validate the offline bundle before installation.

Runs on the air-gapped target with no network. Checks:
- manifest present and parses; profile matches this machine
- the bundle holds regular files and directories only, and each file is read
  once, never through a link: the checks below all use those bytes
- every file matches SHA256SUMS (integrity)
- SIGNATURE verifies against an independently distributed Ed25519 public key
  (authenticity; --pubkey is REQUIRED — without it the verdict is always
  FAILED, because integrity alone proves nothing against an attacker who can
  rewrite SHA256SUMS)
- the bundle is not an older release than the one installed (anti-rollback;
  --allow-downgrade overrides it explicitly): the release --installed-manifest
  names, or on the install target itself this platform's installed release,
  so a .pkg or .msi whose own install script predates the check is refused
  too (release gates on a build machine pass --no-installed-manifest)
- wheelhouse satisfies runtime.lock: every pinned requirement has a wheel
  with the exact recorded hash
- declared os_packages (.deb closure) exist and match the manifest hashes,
  and no undeclared .deb is present
- declared administrator-supplied artifacts are listed, not silently absent

Fails before anything is installed; prints actionable failures.

The Ed25519 check runs in this file (RFC 8032 verification, standard library
only). The verifier runs as root, LocalSystem or under the macOS installer, so
it never executes a PATH-resolved binary such as openssl, and it does not
depend on the host's crypto tooling (macOS LibreSSL cannot verify Ed25519).

--verify-file/--signature/--pubkey checks one detached signature with the same
code; the trust bootstrap uses it for the signed checksum list on the stick.
"""

from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import json
import os
import platform
import re
import stat
import sys
from pathlib import Path, PurePath
from types import ModuleType

WHEEL_RE = re.compile(r"^(?P<name>[^-]+)-(?P<ver>[^-]+)-[^-]+-[^-]+-[^-]+\.whl$")

# --- Ed25519 verification (RFC 8032 section 5.1.7), verify only -------------
# Extended homogeneous coordinates (X, Y, Z, T) on edwards25519, as in the
# RFC's section 6 reference code. Signatures are public data and nothing
# secret is handled here, so constant time does not matter.
_Point = tuple[int, int, int, int]
_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493  # group order
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)
# DER prefix of an Ed25519 SubjectPublicKeyInfo (RFC 8410), then the 32-byte key
_ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


def _point_add(p: _Point, q: _Point) -> _Point:
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = 2 * p[3] * q[3] * _D % _P
    d = 2 * p[2] * q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _point_mul(s: int, p: _Point) -> _Point:
    q: _Point = (0, 1, 1, 0)  # the neutral element
    while s > 0:
        if s & 1:
            q = _point_add(q, p)
        p = _point_add(p, p)
        s >>= 1
    return q


def _point_equal(p: _Point, q: _Point) -> bool:
    return (p[0] * q[2] - q[0] * p[2]) % _P == 0 and (p[1] * q[2] - q[1] * p[2]) % _P == 0


def _recover_x(y: int, sign: int) -> int | None:
    if y >= _P:
        return None  # non-canonical encoding
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if x & 1 != sign:
        x = _P - x
    return x


def _point_decompress(s: bytes) -> _Point | None:
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


_G_Y = 4 * pow(5, _P - 2, _P) % _P
_G_X = _recover_x(_G_Y, 0)
assert _G_X is not None
_G: _Point = (_G_X, _G_Y, 1, _G_X * _G_Y % _P)


def ed25519_verify(public: bytes, msg: bytes, signature: bytes) -> bool:
    """RFC 8032 Ed25519 verification of *signature* over *msg* by the raw 32-byte *public* key."""
    if len(public) != 32 or len(signature) != 64:
        return False
    a = _point_decompress(public)
    r = _point_decompress(signature[:32])
    if a is None or r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False  # non-canonical S (signature malleability)
    h = int.from_bytes(hashlib.sha512(signature[:32] + public + msg).digest(), "little") % _L
    return _point_equal(_point_mul(s, _G), _point_add(r, _point_mul(h, a)))


def ed25519_public_key_from_pem(pem: bytes) -> bytes | None:
    """The raw key of an Ed25519 SubjectPublicKeyInfo PEM ('BEGIN PUBLIC KEY'), else None."""
    m = re.search(rb"-----BEGIN PUBLIC KEY-----(.*?)-----END PUBLIC KEY-----", pem, re.DOTALL)
    if not m:
        return None
    try:
        der = base64.b64decode(b"".join(m.group(1).split()), validate=True)
    except ValueError:
        return None
    if len(der) != 44 or not der.startswith(_ED25519_SPKI_PREFIX):
        return None
    return der[len(_ED25519_SPKI_PREFIX):]


class SignatureRejected(Exception):
    """The signature does not verify, or cannot be checked, with the given key."""


def verify_ed25519_signature(pubkey_path: str, data: bytes, signature: bytes) -> str:
    """Verify a detached Ed25519 *signature* over *data*; return the implementation used.

    The built-in RFC 8032 code decides whenever the key is a plain Ed25519
    SubjectPublicKeyInfo PEM, which is what openssl and the python
    cryptography package write. Only a key in another encoding falls back to
    the cryptography package of THIS interpreter. Its verdict is never asked
    to overturn a built-in rejection. Raises SignatureRejected (and OSError
    for an unreadable key file).
    """
    pem = Path(pubkey_path).read_bytes()
    raw = ed25519_public_key_from_pem(pem)
    if raw is not None:
        if not ed25519_verify(raw, data, signature):
            raise SignatureRejected("the signature does not match the provided public key")
        return "built-in Ed25519, RFC 8032"
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
    except ImportError:
        raise SignatureRejected(
            "the public key is not an Ed25519 'BEGIN PUBLIC KEY' PEM and no cryptography "
            "fallback is installed to read it"
        ) from None
    try:
        pub = load_pem_public_key(pem)
    except ValueError as exc:
        raise SignatureRejected(f"the public key cannot be read ({exc})") from None
    if not isinstance(pub, Ed25519PublicKey):
        raise SignatureRejected("the public key is not an Ed25519 key")
    try:
        pub.verify(signature, data)
    except InvalidSignature:
        raise SignatureRejected("the signature does not match the provided public key") from None
    return "python cryptography"


# --- reading the bundle: regular files only, each read once, no link followed -
# The installers copy a verified bundle with cp -RP into a root-only staging
# directory and verify THAT copy, so that nothing on the (possibly writable)
# bundle path is consulted afterwards. cp -P keeps a symlink a symlink: a link
# in the copy still leads where whoever could write the bundle path decides,
# and a file opened twice (the listing once for the hashes, once for the
# signature) can give the two checks different bytes. So a bundle holds
# regular files and directories only, as bootstrap.sh requires of the stick;
# every name is opened relative to its directory without following a link at
# any step; and each file is read once: the integrity, signature, lock and
# package checks all use those bytes, or the sha256 taken while reading them.
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_NONBLOCK = getattr(os, "O_NONBLOCK", 0)  # a FIFO opens at once instead of blocking, and is refused
_BINARY = getattr(os, "O_BINARY", 0)
_OPEN_BELOW = bool(_NOFOLLOW) and os.open in os.supports_dir_fd  # POSIX; Windows checks with lstat
_NAME_SURROGATE = 0x20000000  # a Windows reparse point that names another path (a symlink or junction)
_CHUNK = 1 << 20


class BundleFileRefused(Exception):
    """A bundle file that cannot be read as a plain regular file, or changed while it was verified."""


def _plain(st: os.stat_result) -> bool:
    """A directory or a regular file in its own right: not a link, junction, FIFO, socket or device."""
    if getattr(st, "st_reparse_tag", 0) & _NAME_SURROGATE:
        return False
    return stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode)


def bundle_entries(root: Path) -> tuple[set[str], set[str], set[str]]:
    """The regular files, the directories and every other entry below *root*, as '/'-joined paths.

    Nothing is followed: a symlink (to a file or a directory), a junction, a FIFO, a socket or a
    device is an 'other' entry, and nothing below a linked directory is listed.
    """
    files: set[str] = set()
    dirs: set[str] = set()
    other: set[str] = set()
    pending = [""]
    while pending:
        below = pending.pop()
        with os.scandir(root / below) as entries:
            for entry in entries:
                rel = f"{below}/{entry.name}" if below else entry.name
                st = entry.stat(follow_symlinks=False)
                if not _plain(st):
                    other.add(rel)
                elif stat.S_ISDIR(st.st_mode):
                    dirs.add(rel)
                    pending.append(rel)
                else:
                    files.add(rel)
    return files, dirs, other


def bundle_key(rel: str) -> str | None:
    """*rel*, a path SHA256SUMS or the manifest names, as a '/'-joined path below the bundle root.

    None when it leads outside the bundle: absolute, or up past the root with '..'. No link is
    looked through (the bundle holds none), so this is where the name leads.
    """
    pure = PurePath(rel)
    if pure.is_absolute() or pure.drive or pure.root:
        return None
    parts: list[str] = []
    for part in pure.parts:
        if part == "..":
            if not parts:
                return None
            parts.pop()
        elif part != ".":
            parts.append(part)
    return "/".join(parts)


def _open_regular(path: str) -> int:
    """A descriptor for *path*, opened without following a symlink as its last component."""
    if not _NOFOLLOW and not _plain(os.lstat(path)):
        raise OSError(f"{path} is a link or not a regular file")
    return os.open(path, os.O_RDONLY | _NOFOLLOW | _NONBLOCK | _BINARY)


def _read_fd(fd: int, what: str, single_link: bool, keep: bool) -> tuple[str, bytes | None]:
    """The sha256 of the regular file open on *fd* (and its bytes when *keep*), read once."""
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        raise BundleFileRefused(f"{what} is not a regular file")
    if single_link and st.st_nlink != 1:
        raise BundleFileRefused(f"{what} has {st.st_nlink} links: whoever holds another name of it can change it")
    digest = hashlib.sha256()
    chunks: list[bytes] = []
    while chunk := os.read(fd, _CHUNK):
        digest.update(chunk)
        if keep:
            chunks.append(chunk)
    return digest.hexdigest(), b"".join(chunks) if keep else None


def read_regular_file(path: str) -> bytes:
    """The bytes of *path*, a regular file, read once; a symlink as its last component is refused
    (--verify-file). A link to a directory on the way is followed: the callers pass paths no other
    account can change (bootstrap.sh's root-only private copy, the stick release_usb.sh just signed)."""
    fd = _open_regular(path)
    try:
        try:
            _digest, data = _read_fd(fd, path, single_link=False, keep=True)
        except BundleFileRefused as exc:
            raise OSError(str(exc)) from None
    finally:
        os.close(fd)
    assert data is not None
    return data


class BundleReader:
    """Reads the files of one bundle, each once, without following a link at any step.

    sha256() streams a file and remembers its digest; read() keeps the bytes too, as does the first
    read of a name in *keep* (the files whose content the checks parse). A second read of the same
    file (read() after sha256() of a name not in *keep*) must give the digest of the first, or it
    is refused.
    """

    def __init__(self, root: Path, keep: frozenset[str] = frozenset()) -> None:
        self.root = root
        self.keep = keep
        self._digests: dict[str, str] = {}
        self._contents: dict[str, bytes] = {}

    def _open(self, rel: str) -> int:
        parts = rel.split("/")
        if _OPEN_BELOW:
            fd = os.open(self.root, os.O_RDONLY | _DIRECTORY)
            try:
                for part in parts[:-1]:
                    below = os.open(part, os.O_RDONLY | _DIRECTORY | _NOFOLLOW, dir_fd=fd)
                    os.close(fd)
                    fd = below
                return os.open(parts[-1], os.O_RDONLY | _NOFOLLOW | _NONBLOCK, dir_fd=fd)
            finally:
                os.close(fd)
        # no openat (Windows): every step is checked with lstat, and the file opened must be the
        # one checked
        path = self.root
        for part in parts:
            path = path / part
            checked = os.lstat(path)
            if not _plain(checked):
                raise BundleFileRefused(f"{rel} is a link or below one, or not a regular file")
        fd = os.open(path, os.O_RDONLY | _BINARY)
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (checked.st_dev, checked.st_ino):
            os.close(fd)
            raise BundleFileRefused(f"{rel} changed while it was opened")
        return fd

    def _consume(self, rel: str, keep: bool, single_link: bool) -> None:
        try:
            fd = self._open(rel)
        except FileNotFoundError:
            raise
        except OSError as exc:
            raise BundleFileRefused(f"{rel} cannot be opened as a regular file without following a link "
                                    f"({exc.strerror or exc})") from None
        try:
            digest, data = _read_fd(fd, rel, single_link, keep)
        finally:
            os.close(fd)
        if self._digests.setdefault(rel, digest) != digest:
            raise BundleFileRefused(f"{rel} changed while the bundle was verified")
        if data is not None:
            self._contents[rel] = data

    def sha256(self, rel: str) -> str:
        if rel not in self._digests:
            self._consume(rel, keep=rel in self.keep, single_link=False)
        return self._digests[rel]

    def read(self, rel: str, single_link: bool = False) -> bytes:
        if rel not in self._contents:
            self._consume(rel, keep=True, single_link=single_link)
        return self._contents[rel]


def load_profiles_module() -> ModuleType:
    """Import scripts/profiles.py (the target-profile registry).

    The verifier travels on the trusted channel, outside this repository, so
    the registry is located next to this file (as shipped in trusted-tools/)
    or in its lib/ directory. Missing registry = fail closed.
    """
    here = Path(__file__).resolve().parent
    for base in (here, here / "lib"):
        if (base / "profiles.py").is_file():
            if str(base) not in sys.path:
                sys.path.insert(0, str(base))
            import profiles  # type: ignore[import-not-found,unused-ignore]

            return profiles
    raise ImportError("profiles.py not found next to this verifier or in its lib/ directory")


def one_line(text: object) -> str:
    """*text* as one line of output: a name or value the bundle chose (a file name with a line break,
    a manifest field) never starts a line of its own, so it never reads as a verdict or a FAIL line."""
    shown = str(text)
    return shown if shown.isprintable() else ascii(shown)[1:-1]


def fail(msg: str) -> None:
    print(f"FAIL: {one_line(msg)}")
    global failed
    failed = True


failed = False


def _release_seq(manifest: object) -> int | None:
    value = manifest.get("release_seq") if isinstance(manifest, dict) else None
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return None


def _created(manifest: object) -> datetime.datetime | None:
    value = manifest.get("created") if isinstance(manifest, dict) else None
    try:
        created = datetime.datetime.fromisoformat(str(value))
    except ValueError:
        return None
    return created if created.tzinfo else created.replace(tzinfo=datetime.UTC)


def _source_rev(manifest: object) -> str | None:
    value = manifest.get("source_rev") if isinstance(manifest, dict) else None
    if isinstance(value, str) and value.strip() and value.strip().lower() != "unknown":
        return value.strip()
    return None


def _same_release(manifest: dict[str, object], installed: dict[str, object]) -> bool:
    """Whether a bundle with the installed release's release_seq can be that release: not when
    both name a source revision and the two differ (a rebuild of one commit is the same release).
    Without a revision on both sides nothing tells them apart, as before release_seq had a
    default: such a release_seq was given explicitly (--release-seq), by whoever built both."""
    new_rev, old_rev = _source_rev(manifest), _source_rev(installed)
    return new_rev is None or old_rev is None or new_rev == old_rev


def platform_installed_manifest() -> Path | None:
    """Where this platform's installer records the installed release's manifest.json.

    install_offline.sh and the .deb publish it in /opt/universal-db-mcp, the
    .pkg in /usr/local/universal-db-mcp and the MSI in
    <Program Files>\\UniversalDB MCP ([ProgramFiles64Folder] in udbmcp.wxs).
    None where no installer of this project runs.
    """
    system = platform.system()
    if system == "Linux":
        return Path("/opt/universal-db-mcp/manifest.json")
    if system == "Darwin":
        return Path("/usr/local/universal-db-mcp/manifest.json")
    if system == "Windows":
        # ProgramW6432 is the 64-bit folder even in a 32-bit process
        program_files = os.environ.get("ProgramW6432") or os.environ.get("ProgramFiles")
        return Path(program_files) / "UniversalDB MCP" / "manifest.json" if program_files else None
    return None


def _rosetta_translated() -> bool:
    """Whether this process is an x86_64 process that Rosetta 2 translates on arm64 hardware."""
    try:
        import ctypes  # noqa: PLC0415 - macOS only, and only when platform.machine() says x86_64

        libc = ctypes.CDLL(None, use_errno=True)
        value = ctypes.c_int(0)
        size = ctypes.c_size_t(ctypes.sizeof(value))
        rc = libc.sysctlbyname(b"sysctl.proc_translated", ctypes.byref(value), ctypes.byref(size), None,
                               ctypes.c_size_t(0))
    except (OSError, AttributeError, ImportError):
        return False
    return bool(rc == 0 and value.value == 1)


def host_machine() -> str:
    """This machine's architecture, as the hardware has it.

    platform.machine() describes the running process. Under Rosetta 2 that is x86_64 on an arm64
    Mac: the macOS Installer runs a package's scripts translated unless its Distribution declares
    the arm64 host, and a universal2 python started by a translated parent runs as x86_64, which
    would refuse the macos-arm64 bundle of the very Mac it is on.
    """
    machine = platform.machine()
    if platform.system() == "Darwin" and machine == "x86_64" and _rosetta_translated():
        return "arm64"
    return machine


def host_profile_mismatches(profiles: ModuleType, prof: object) -> list[str]:
    """How this machine differs from the profile *prof*: the registry's check of the running
    interpreter, with the architecture judged by the hardware (host_machine) under Rosetta 2."""
    mismatches = list(profiles.profile_host_mismatches(prof))
    machine = host_machine()
    if machine != platform.machine():
        translated = f"machine architecture {platform.machine()} ("
        mismatches = [m for m in mismatches if not m.startswith(translated)]
        if machine not in getattr(prof, "host_machines", ()):
            target = getattr(prof, "manifest_target", {}).get("arch")
            mismatches.append(f"machine architecture {machine} (target {target})")
    return mismatches


def _target_os_arch(manifest: object) -> tuple[str, str] | None:
    """The os and arch of a manifest's signed 'target' block (every registry-built manifest has one)."""
    target = manifest.get("target") if isinstance(manifest, dict) else None
    if isinstance(target, dict) and isinstance(target.get("os"), str) and isinstance(target.get("arch"), str):
        return target["os"], target["arch"]
    return None


def unknown_profile_on_target(manifest: dict[str, object], installed_path: Path, profiles: object) -> bool:
    """Whether this machine is the install target of a bundle whose profile the registry does not know.

    A later release may rename or retire a profile, which the .pkg and .msi built before it still
    carry. Such a bundle is on target when the release installed at *installed_path* names the same
    profile, or when the bundle's signed target block (os and arch) is the installed release's, or
    this host's as the registry describes it: once a site has installed the release that renamed the
    profile, its record names the new one.
    """
    try:
        installed = json.loads(installed_path.read_text())
    except (OSError, ValueError):
        installed = None
    profile = manifest.get("profile")
    if isinstance(profile, str) and isinstance(installed, dict) and installed.get("profile") == profile:
        return True
    target = _target_os_arch(manifest)
    if target is None:
        return False
    if target == _target_os_arch(installed):
        return True
    system, machine = platform.system(), host_machine()
    return any(
        system in p.host_systems and machine in p.host_machines
        and (p.manifest_target.get("os"), p.manifest_target.get("arch")) == target
        for p in getattr(profiles, "PROFILES", {}).values()
    )


def check_release_order(
    manifest: dict[str, object], installed_path: Path, allow_downgrade: bool, by_default: bool = False
) -> None:
    """Anti-rollback: refuse a bundle that is an older release than the installed one.

    Releases are ordered by the signed manifest's integer release_seq. When
    neither manifest has one (both builds predate it), the signed 'created'
    timestamp orders them. A missing value counts as older. An equal one is
    allowed for the same release only (a reinstall, or a rebuild of the same
    source revision, see _same_release): release_seq defaults to a commit
    timestamp, which a rebase can give two releases alike, so it cannot order
    them. *by_default*: the caller named no installed manifest and
    *installed_path* is this platform's (platform_installed_manifest).
    """
    if by_default:
        print(f"release order: no --installed-manifest given; checking this machine's installed release "
              f"{installed_path}")
    if not installed_path.exists():
        print(f"release order: nothing installed yet ({installed_path} absent)")
        return
    try:
        installed = json.loads(installed_path.read_text())
        if not isinstance(installed, dict):
            raise ValueError("not a JSON object")
    except (OSError, ValueError) as exc:
        if allow_downgrade:
            print(f"WARNING: the installed manifest {installed_path} is unreadable ({exc}); "
                  "release order NOT checked (--allow-downgrade)")
        else:
            fail(f"rollback check impossible: the installed manifest {installed_path} is unreadable "
                 f"({exc}). If you mean to install this bundle anyway, re-run with --allow-downgrade")
        return
    new_seq, old_seq = _release_seq(manifest), _release_seq(installed)
    other = False
    if old_seq is not None:
        older = new_seq is None or new_seq < old_seq
        what = (f"bundle release_seq {'missing' if new_seq is None else new_seq}, "
                f"installed release_seq {old_seq}")
        if new_seq == old_seq and not _same_release(manifest, installed):
            older = other = True
            what += (f", but another release (source_rev {_source_rev(manifest) or 'missing'}, installed "
                     f"source_rev {_source_rev(installed) or 'missing'}), which release_seq cannot order")
    elif new_seq is not None:
        older = False
        what = f"bundle release_seq {new_seq}, the installed release predates release_seq"
    else:
        new_created, old_created = _created(manifest), _created(installed)
        older = old_created is not None and (new_created is None or new_created < old_created)
        what = (f"bundle created {manifest.get('created', 'missing')}, "
                f"installed created {installed.get('created', 'missing')}")
    if not older:
        print(f"release order: {one_line(what)} (not a downgrade)")
    elif allow_downgrade:
        print(f"WARNING: DOWNGRADE allowed by --allow-downgrade: {one_line(what)}")
    else:
        # an installer whose own script predates the check cannot pass the switch
        stuck = (f". An installer that cannot pass it (a .pkg or .msi built before this check) is refused "
                 f"until an administrator moves {installed_path} aside; the install records it again"
                 if by_default else "")
        if by_default and platform.system() == "Darwin":
            # such a .pkg has no check in its preinstall, and the Installer keeps what it wrote
            stuck += ("; such a .pkg is refused only after the Installer has written its payload (the bundle "
                      "folder, the share scripts and the LaunchDaemon plist), which it does not put back: "
                      "re-install the current release's .pkg to restore them")
        which = ("another release with the installed release's release_seq, which may be the older one"
                 if other else "an OLDER release than the one installed")
        fail(f"rollback refused: this bundle is {which} ({what}; "
             f"installed manifest {installed_path}). It would bring back code that later releases "
             "fixed. If the downgrade is intended, re-run with --allow-downgrade (the install "
             f"scripts and the .deb take UDBMCP_ALLOW_DOWNGRADE=1){stuck}")


def verify_detached(data_path: str, signature_path: str, pubkey_path: str) -> int:
    """--verify-file mode: one detached Ed25519 signature, same proof rules as a bundle."""
    try:
        impl = verify_ed25519_signature(pubkey_path, read_regular_file(data_path), read_regular_file(signature_path))
    except (SignatureRejected, OSError) as exc:
        fail(f"signature verification FAILED for {data_path}: {exc}")
        return 1
    print(f"signature: {data_path} verified against the provided public key ({impl})")
    print("signature verification PASSED")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bundle", default=None, help="bundle directory to verify (required unless --verify-file)")
    ap.add_argument("--pubkey", default=None, help="Ed25519 public key PEM; required to verify signatures")
    ap.add_argument("--allow-platform-mismatch", action="store_true",
                    help="staging-side verification on a machine whose platform differs from "
                         "the bundle profile; prints a loud warning and skips the local "
                         "python-version check. NEVER use this on the install target.")
    installed = ap.add_mutually_exclusive_group()
    installed.add_argument("--installed-manifest", default=None,
                           help="manifest.json of the installed release (e.g. /opt/universal-db-mcp/manifest.json); "
                                "a bundle that is an older release is refused. Absent file = first install. "
                                "Without it, a bundle whose profile is this machine's (in the profile registry, "
                                "or the installed release's) is checked against this platform's installed "
                                "release (unless --allow-platform-mismatch)")
    installed.add_argument("--no-installed-manifest", action="store_true",
                           help="do not compare with this machine's installed release: for release gates "
                                "that verify on a build machine, never on the install target")
    ap.add_argument("--allow-downgrade", action="store_true",
                    help="accept a bundle older than the installed release (--installed-manifest, or "
                         "without it this platform's installed release): an intended rollback; "
                         "prints a loud warning")
    ap.add_argument("--verify-file", default=None,
                    help="verify one detached signature over this file instead of a bundle "
                         "(needs --signature and --pubkey)")
    ap.add_argument("--signature", default=None, help="detached Ed25519 signature for --verify-file")
    args = ap.parse_args()

    if args.verify_file:
        if not args.signature or not args.pubkey:
            ap.error("--verify-file needs --signature and --pubkey")
        return verify_detached(args.verify_file, args.signature, args.pubkey)
    if not args.bundle:
        ap.error("--bundle is required")

    bundle = Path(args.bundle)
    try:
        files, dirs, other = bundle_entries(bundle)
    except OSError as exc:
        # every check below needs the whole listing: name what could not be listed
        fail(f"the bundle cannot be listed: {exc.filename}: {exc.strerror or exc}; nothing in it was checked")
        return 1
    reader = BundleReader(bundle, keep=frozenset({"requirements/runtime.lock"}))
    try:
        manifest = json.loads(reader.read("manifest.json"))
        profile = manifest["profile"]
    except FileNotFoundError:
        fail(f"manifest.json missing in {bundle}")
        return 1
    except (BundleFileRefused, OSError, ValueError, KeyError, TypeError) as exc:
        fail(f"manifest.json is unreadable or not a valid manifest ({exc}); "
             "re-copy the bundle from your trusted channel and re-run")
        return 1

    # profile compatibility: registry lookup (scripts/profiles.py) replaces the
    # previously hardcoded 'linux-x86_64' branch. Known profiles are checked
    # against their declared target; unknown profiles (not from this registry)
    # only draw a loud warning — integrity/authenticity above still cover them.
    # on_target: this machine is the bundle's install target (the anti-rollback
    # default below applies)
    on_target = False
    try:
        profiles = load_profiles_module()
        prof = profiles.PROFILES.get(profile)
        if prof is None:
            print(f"WARNING: unknown bundle profile '{one_line(profile)}' (this verifier knows: "
                  f"{', '.join(sorted(profiles.PROFILES))}); skipping platform compatibility check")
            # A later release may rename or retire a profile, which the .pkg
            # and .msi built before it still carry: this machine is still their
            # install target when its installed release, or the host, is the
            # platform the bundle's signed target block names.
            default = platform_installed_manifest()
            on_target = (not args.allow_platform_mismatch and default is not None
                         and unknown_profile_on_target(manifest, default, profiles))
        else:
            mismatches = host_profile_mismatches(profiles, prof)
            on_target = not mismatches and not args.allow_platform_mismatch
            if mismatches:
                if args.allow_platform_mismatch:
                    print(
                        f"WARNING: verifying a {profile} bundle on "
                        f"{platform.system()}/{host_machine()}. This is a STAGING-side "
                        f"integrity/authenticity check only. The bundle must still be verified "
                        f"WITHOUT this flag on the actual install target."
                    )
                else:
                    fail(f"bundle profile '{profile}' does not match this machine "
                         f"({platform.system()}/{host_machine()}/"
                         f"{platform.python_version()}): {'; '.join(mismatches)}; pass "
                         f"--allow-platform-mismatch only when verifying on a staging machine")
    except Exception as exc:  # pragma: no cover - fail closed on any registry problem
        fail(f"cannot load the target-profile registry: {exc}. Install profiles.py "
             f"next to this verifier (trusted-tools ships it) and re-run")

    # integrity: a bundle holds regular files and directories only, none read
    # through a link; the listing is read once, and the signature below is
    # checked over those same bytes
    for rel in sorted(other):
        fail(f"not a regular file or directory in the bundle: {rel} (a link, a FIFO or a device); a bundle "
             "holds regular files and directories only. Re-copy it from your trusted channel")
    sums_bytes: bytes | None = None
    if "SHA256SUMS" not in files | other:
        fail("SHA256SUMS missing")
    else:
        try:
            sums_bytes = reader.read("SHA256SUMS", single_link=True)
            listing = sums_bytes.decode("utf-8")
        except (BundleFileRefused, OSError, ValueError) as exc:
            fail(f"SHA256SUMS cannot be used: {exc}")
            sums_bytes = None
    if sums_bytes is not None:
        checked = 0
        listed: set[str] = set()
        for line in listing.splitlines():
            if not line.strip():
                continue
            digest, _, rel = line.partition("  ")
            key = bundle_key(rel)
            if key is None:
                fail(f"SHA256SUMS path escapes the bundle directory: {rel}")
                continue
            listed.add(key)
            if key in other:
                continue  # refused above, and never read through
            try:
                if key not in files:
                    raise FileNotFoundError(key)
                actual = reader.sha256(key)
            except FileNotFoundError:
                fail(f"missing artifact: {rel}")
                continue
            except BundleFileRefused as exc:
                fail(f"artifact not verified: {exc}")
                continue
            if actual != digest:
                fail(f"tampered artifact: {rel} (sha256 mismatch)")
            checked += 1
        # every file on disk must be accounted for: an unlisted file (planted
        # or left by a partial regeneration) is a failure. Exempt: checksum
        # listings named SHA256SUMS (the trusted build tool writes a per-image
        # images/SHA256SUMS next to the tars; these listings are inert — only
        # the root one is ever the verification basis) and the bundle-root
        # SIGNATURE. A file merely NAMED "SIGNATURE" in a subdirectory is NOT
        # exempt and must be covered like any other payload.
        for rel in sorted(files - listed):
            if rel.rsplit("/", 1)[-1] == "SHA256SUMS" or rel == "SIGNATURE":
                continue
            fail(f"file present in bundle but NOT covered by SHA256SUMS: {rel}")
        print(f"integrity: {checked} artifacts checked, full coverage verified")

    # authenticity
    signed = "SIGNATURE" in files | other
    if args.pubkey:
        if not signed:
            fail("SIGNATURE missing but a public key was provided for verification")
        elif sums_bytes is None:
            # already reported above ("SHA256SUMS missing", or not usable);
            # there is no signed data left to verify against
            pass
        else:
            # The canonical diagnostic appears on EVERY rejection path:
            # operators and the failure-mode gate match on it.
            try:
                impl = verify_ed25519_signature(args.pubkey, sums_bytes, reader.read("SIGNATURE", single_link=True))
            except (SignatureRejected, BundleFileRefused, OSError) as exc:
                fail(f"signature verification FAILED (untrusted or corrupted bundle): {exc}")
            else:
                print(f"signature: verified against provided public key ({impl})")
    else:
        # Fail closed, unconditionally: integrity alone proves nothing, since
        # an attacker who can touch the bundle can also regenerate unsigned
        # SHA256SUMS (and delete SIGNATURE). Without --pubkey this verifier
        # must never certify the bundle — no PASSED verdict, exit nonzero.
        if signed:
            # A signed bundle MUST be verifiable: refusing to proceed without
            # the key prevents 'verify without authenticity' becoming the norm.
            fail("bundle is signed but no --pubkey was provided; obtain the release "
                 "public key through your trusted channel and verify before installing")
        else:
            print("signature: NOT verified (no --pubkey given); authenticity unproven")
        fail("authenticity NOT verified: obtain the release public key through "
             "your trusted channel and re-run with --pubkey before installing")

    # anti-rollback: every older signed build still verifies, so the install
    # paths pass the installed release's manifest and an older bundle is
    # refused unless the operator asks for the downgrade. A .pkg or .msi runs
    # its own install script, and one built before this check calls the site's
    # verifier with neither, so on the install target the platform's installed
    # release is checked without being named.
    if args.installed_manifest:
        check_release_order(manifest, Path(args.installed_manifest), args.allow_downgrade)
    elif on_target and not args.no_installed_manifest:
        default = platform_installed_manifest()
        if default is not None:
            check_release_order(manifest, default, args.allow_downgrade, by_default=True)

    # wheelhouse satisfies runtime.lock (the digests and bytes read above)
    lock = "requirements/runtime.lock"
    wheels = sorted(k for k in files if k.startswith("wheelhouse/") and k.count("/") == 1 and k.endswith(".whl"))
    if lock not in files or "wheelhouse" not in dirs:
        fail("requirements/runtime.lock or wheelhouse missing")
    else:
        by_hash: dict[str, str] = {}
        for key in wheels:
            try:
                by_hash[reader.sha256(key)] = key.rsplit("/", 1)[1]
            except (BundleFileRefused, OSError) as exc:
                fail(f"wheel not verified: {exc}")
        try:
            lock_text = reader.read(lock).decode("utf-8", errors="replace")
        except (BundleFileRefused, OSError) as exc:
            fail(f"runtime.lock cannot be used: {exc}")
            lock_text = ""
        n = 0
        for line in lock_text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"^([A-Za-z0-9._-]+)==(\S+) --hash=sha256:([0-9a-f]{64})$", line)
            if not m:
                fail(f"runtime.lock line is not a pinned+hashed requirement: {line[:60]}")
                continue
            name, ver, digest = m.groups()
            w = by_hash.get(digest)
            if w is None:
                fail(f"wheel missing from wheelhouse: {name}=={ver}")
            else:
                wm = WHEEL_RE.match(w)
                if not wm or wm.group("name").replace("_", "-").lower() != name or wm.group("ver") != ver:
                    fail(f"wheelhouse artifact does not match lock: {line[:40]} vs {w}")
            n += 1
        print(f"runtime.lock: {n} pinned requirements checked against wheelhouse")
        app_wheel = [k for k in wheels if k.rsplit("/", 1)[1].startswith("universal_db_mcp-")]
        if not app_wheel:
            fail("application wheel is not in the wheelhouse (source installs are not permitted)")

    # declared-but-missing artifacts
    missing = manifest.get("connector_wheel_status", {}).get("missing_from_closure", [])
    if missing:
        print("WARN: manifest declares missing driver artifacts (affected connectors "
              f"cannot pass readiness checks): {one_line(', '.join(map(str, missing)))}")

    admin = manifest.get("administrator_supplied", {})
    if admin:
        print("NOTE: administrator-supplied prerequisites (not distributable):")
        for k, v in admin.items():
            print(f"  - {one_line(k)}: {one_line(v)}")

    # os-packages: every declared .deb must exist with the manifest hash, and
    # every .deb shipped on disk must be declared (nothing extra, nothing
    # swapped after signing). Enforced even when the manifest declares no
    # packages: os_packages.sh falls back to running every .deb found in
    # os-packages/, so an undeclared .deb must never slip through a manifest
    # with an empty os_packages section.
    os_packages = manifest.get("os_packages") or {}
    entries = os_packages.get("packages") if isinstance(os_packages, dict) else None
    entries = list(entries) if entries else []
    declared_files: set[str] = set()
    declared_names: set[str] = set()
    ok_count = 0
    for entry in entries:
        fname = str(entry.get("file", ""))
        rel = str(entry.get("path") or f"os-packages/{fname}")
        key = bundle_key(rel)
        if key is not None:
            declared_files.add(key)
        declared_names.add(str(entry.get("package", "")))
        if not fname or key not in files:
            fail(f"os package declared in manifest but missing from bundle: {rel}")
            continue
        try:
            actual = reader.sha256(key)
        except (BundleFileRefused, OSError) as exc:
            fail(f"os package not verified: {exc}")
            continue
        if actual != entry.get("sha256"):
            fail(f"tampered os package: {rel} (manifest sha256 mismatch)")
            continue
        ok_count += 1
    for key in sorted(files | other):
        if key.startswith("os-packages/") and key.count("/") == 1 and key.endswith(".deb") \
                and key not in declared_files:
            fail(f".deb present in os-packages but not declared in manifest.json: {key.rsplit('/', 1)[1]}")
    print(f"os-packages: {ok_count}/{len(entries)} declared .deb artifacts hash-checked")
    if entries:
        # dependency closure sanity: msodbcsql18 cannot be configured without
        # the unixODBC stack, and a selected mssql connector without the driver
        # deb means the shipped closure is incomplete (not admin-supplied).
        # (Only meaningful when the manifest declares deb packages at all:
        # macOS/Windows bundles legitimately ship none.)
        if "msodbcsql18" in declared_names and "unixodbc" not in declared_names:
            fail("os_packages closure incomplete: msodbcsql18 requires unixodbc")
        if "mssql" in manifest.get("selected_connectors", []) and "msodbcsql18" not in declared_names:
            fail("os_packages closure incomplete: mssql connector is selected but "
                 "msodbcsql18 is not among the declared os_packages")

    if failed:
        print("\nbundle verification FAILED; do not install")
        return 1
    print("\nbundle verification PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
