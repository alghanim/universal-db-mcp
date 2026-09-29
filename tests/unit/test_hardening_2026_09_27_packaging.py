"""Packaging and release-trust regressions from the 2026-09-27 security/production review.

Each section names the finding it pins. Every key is a throwaway Ed25519 pair
generated under tmp_path; no release or demo key is ever read, and the
scripts under test only ever write below tmp_path (bootstrap.sh through
UDBMCP_BOOTSTRAP_ROOT, the installers through a target and staging dir there).
"""

from __future__ import annotations

import ast
import base64
import functools
import hashlib
import http.server
import importlib.util
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import tomllib
import zipfile
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="bash-based POSIX test")

REPO = Path(__file__).resolve().parents[2]
VERIFIER = REPO / "scripts" / "verify_bundle.py"
BUILDER = REPO / "scripts" / "prepare_offline_bundle.py"
INSTALL = REPO / "scripts" / "install_offline.sh"
UPGRADE = REPO / "scripts" / "upgrade_offline.sh"
RELEASE_USB = REPO / "scripts" / "package" / "release_usb.sh"
UPGRADE_GATE = REPO / "scripts" / "package" / "test_upgrade_offline.sh"
BOOTSTRAP = REPO / "packaging" / "trust-bootstrap-linux" / "bootstrap.sh"
POSTINST = REPO / "packaging" / "deb" / "postinst"
PREINST = REPO / "packaging" / "deb" / "preinst"
LOADER = REPO / "scripts" / "load_images_offline.sh"
PYPROJECT = REPO / "pyproject.toml"
RUNTIME_IN = REPO / "requirements" / "runtime.in"
UV_LOCK = REPO / "uv.lock"
DEB_NAME = "universal-db-mcp_0.1.0+202609270000.gabc1234_amd64.deb"
ORACLE_DEBS = (
    "oracle-instantclient/libaio1t64_0.3.113-6build1.1_amd64.deb",
    "oracle-instantclient/unzip_6.0-28ubuntu4.1_amd64.deb",
)


# ---- helpers ----------------------------------------------------------------


@pytest.fixture(autouse=True)
def _permissive_umask() -> Iterator[None]:
    """Every test here runs under umask 002, Debian's per-user default (pam_umask): the scripts
    refuse group-writable trust material, so a test whose root-only setup leaned on this host's
    umask would fail only on a Debian-style account. Here it fails everywhere."""
    old = os.umask(0o002)
    try:
        yield
    finally:
        os.umask(old)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _keypair(tmp_path: Path, name: str = "release") -> tuple[Ed25519PrivateKey, Path, Path]:
    key = Ed25519PrivateKey.generate()
    priv = tmp_path / f"{name}.pem"
    pub = tmp_path / f"{name}.pub.pem"
    priv.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    priv.chmod(0o600)
    pub.write_bytes(
        key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    return key, priv, pub


def _bundle_sums(root: Path) -> bytes:
    """SHA256SUMS exactly as scripts/prepare_offline_bundle.py writes it."""
    lines = [
        f"{_sha256(f)}  {f.relative_to(root)}"
        for f in sorted(root.rglob("*"))
        if f.is_file() and f.name not in ("SHA256SUMS", "SIGNATURE")
    ]
    return ("\n".join(lines) + "\n").encode()


def _sign_bundle(root: Path, key: Ed25519PrivateKey) -> None:
    sums = _bundle_sums(root)
    (root / "SHA256SUMS").write_bytes(sums)
    (root / "SIGNATURE").write_bytes(key.sign(sums))


def _bundle(root: Path, key: Ed25519PrivateKey, **manifest: Any) -> Path:
    """A minimal signed bundle the real verifier accepts."""
    wheelhouse = root / "wheelhouse"
    wheelhouse.mkdir(parents=True)
    (wheelhouse / "universal_db_mcp-0.1.0-py3-none-any.whl").write_bytes(b"application wheel")
    dep = wheelhouse / "sqlglot-30.18.0-py3-none-any.whl"
    dep.write_bytes(b"dependency wheel")
    (root / "requirements").mkdir()
    (root / "requirements" / "runtime.lock").write_text(
        f"sqlglot==30.18.0 --hash=sha256:{_sha256(dep)}\n", encoding="utf-8"
    )
    (root / "manifest.json").write_text(json.dumps({"profile": "test-profile", **manifest}), encoding="utf-8")
    _sign_bundle(root, key)
    return root


def _verify(*args: object, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - repo script under test, fixed interpreter
        [sys.executable, str(VERIFIER), *(str(a) for a in args)],
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
        check=False,
    )


def _load_verifier() -> ModuleType:
    spec = importlib.util.spec_from_file_location("verify_bundle_under_test", VERIFIER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _openssl3() -> str | None:
    """An OpenSSL 3 binary (Ed25519 pkeyutl -rawin); macOS /usr/bin/openssl is LibreSSL."""
    for cand in (shutil.which("openssl"), "/opt/homebrew/bin/openssl", "/usr/local/bin/openssl", "/usr/bin/openssl"):
        if cand and Path(cand).exists():
            out = subprocess.run([cand, "version"], capture_output=True, text=True, check=False).stdout  # noqa: S603
            if out.startswith("OpenSSL 3"):
                return cand
    return None


def _tool_env(tmp_path: Path, **extra: str) -> dict[str, str]:
    """A hermetic environment: system PATH plus an OpenSSL 3 and this python as python3."""
    openssl = _openssl3()
    if openssl is None:
        pytest.skip("no OpenSSL 3 binary on this host (release_usb.sh and bootstrap.sh fingerprint keys with it)")
    tools = tmp_path / "tools"
    if not tools.exists():
        tools.mkdir()
        (tools / "openssl").symlink_to(openssl)
        py = tools / "python3"
        py.write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n', encoding="utf-8")
        py.chmod(0o755)
    env = {k: v for k, v in os.environ.items() if not k.startswith("UDBMCP_")}
    env["PATH"] = f"{tools}:/usr/bin:/bin:/usr/sbin:/sbin"
    env["TMPDIR"] = str(tmp_path)
    env.update(extra)
    return env


def _snapshot(root: Path) -> dict[str, bytes]:
    return {str(p.relative_to(root)): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


# ---- F93: the root-run verifier never runs a PATH-resolved openssl ----------

RFC8032_VECTORS = [
    # RFC 8032 section 7.1, TEST 1 and TEST 2: (public key, message, signature)
    (
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
]


def test_f93_verifier_certifies_a_signed_bundle_with_no_openssl_anywhere_on_path(tmp_path: Path) -> None:
    key, _, pub = _keypair(tmp_path)
    bundle = _bundle(tmp_path / "bundle", key)
    proc = _verify("--bundle", bundle, "--pubkey", pub, env={**os.environ, "PATH": "/nonexistent"})
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "bundle verification PASSED" in proc.stdout
    assert "signature: verified against provided public key" in proc.stdout


def test_f93_a_planted_openssl_that_exits_0_cannot_certify_a_forged_bundle(tmp_path: Path) -> None:
    _release, _, pub = _keypair(tmp_path)
    attacker = Ed25519PrivateKey.generate()
    bundle = _bundle(tmp_path / "bundle", attacker)  # consistent SHA256SUMS, attacker SIGNATURE
    planted = tmp_path / "planted"
    planted.mkdir()
    (planted / "openssl").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    (planted / "openssl").chmod(0o755)
    proc = _verify("--bundle", bundle, "--pubkey", pub, env={**os.environ, "PATH": f"{planted}:/usr/bin:/bin"})
    assert proc.returncode != 0, proc.stdout
    assert "signature verification FAILED" in proc.stdout
    assert "bundle verification PASSED" not in proc.stdout


def test_f93_verifier_source_has_no_bare_openssl_invocation() -> None:
    tree = ast.parse(VERIFIER.read_text(encoding="utf-8"))
    bare = [n.lineno for n in ast.walk(tree) if isinstance(n, ast.Constant) and n.value == "openssl"]
    assert bare == [], f"verify_bundle.py still names a bare 'openssl' (lines {bare})"


def test_f93_builtin_ed25519_accepts_rfc8032_vectors_and_rejects_every_mutation() -> None:
    mod = _load_verifier()
    order = 2**252 + 27742317777372353535851937790883648493
    for pk_hex, msg_hex, sig_hex in RFC8032_VECTORS:
        pk, msg, sig = bytes.fromhex(pk_hex), bytes.fromhex(msg_hex), bytes.fromhex(sig_hex)
        assert mod.ed25519_verify(pk, msg, sig)
        assert not mod.ed25519_verify(pk, msg + b"x", sig)
        for i in (0, 31, 32, 63):  # R and S halves
            bad = bytearray(sig)
            bad[i] ^= 0x01
            assert not mod.ed25519_verify(pk, msg, bytes(bad))
        bad_pk = bytearray(pk)
        bad_pk[0] ^= 0x01
        assert not mod.ed25519_verify(bytes(bad_pk), msg, sig)
        # S + L is the same scalar mod L but a non-canonical encoding: RFC 8032 rejects it
        s = int.from_bytes(sig[32:], "little") + order
        assert not mod.ed25519_verify(pk, msg, sig[:32] + s.to_bytes(32, "little"))
        assert not mod.ed25519_verify(pk, msg, sig[:63])
    for n in range(8):
        key = Ed25519PrivateKey.generate()
        raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        msg = os.urandom(n * 37)
        sig = key.sign(msg)
        assert mod.ed25519_verify(raw, msg, sig)
        other = Ed25519PrivateKey.generate().public_key()
        assert not mod.ed25519_verify(
            other.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw), msg, sig
        )


def test_f93_pem_reader_takes_only_an_ed25519_subject_public_key_info(tmp_path: Path) -> None:
    mod = _load_verifier()
    key, _, pub = _keypair(tmp_path)
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    assert mod.ed25519_public_key_from_pem(pub.read_bytes()) == raw
    assert mod.ed25519_public_key_from_pem(b"-----BEGIN PUBLIC KEY-----\n!!\n-----END PUBLIC KEY-----\n") is None
    assert mod.ed25519_public_key_from_pem(b"not a key") is None


# ---- F14: the stick's checksum list is signed and bootstrap.sh checks it ----


def _stick(tmp_path: Path, pub: Path) -> Path:
    """The release_usb.sh stick layout, with the repo's own trust tools."""
    stick = tmp_path / "stick"
    tb = stick / "trust-bootstrap-linux"
    (tb / "lib").mkdir(parents=True)
    shutil.copy2(BOOTSTRAP, tb / "bootstrap.sh")
    for name in ("install_offline.sh", "verify_bundle.py", "profiles.py"):
        shutil.copy2(REPO / "scripts" / name, tb / name)
    shutil.copy2(REPO / "scripts" / "lib" / "os_packages.sh", tb / "lib" / "os_packages.sh")
    shutil.copy2(pub, tb / "release.pub.pem")
    (stick / DEB_NAME).write_bytes(b"!<arch>\ndebian-binary 2.0\ncontrol.tar preinst\n")
    (stick / "oracle-instantclient").mkdir()
    (stick / "oracle-instantclient" / "README.txt").write_text("instant client\n", encoding="utf-8")
    for name in ORACLE_DEBS:  # the runbook's thick-mode step installs them with dpkg -i
        (stick / name).write_bytes(f"!<arch>\n{name} preinst\n".encode())
    (stick / "UPGRADE-README.md").write_text("# runbook\n", encoding="utf-8")
    (stick / "RELEASE-KEY-FINGERPRINT.txt").write_text("fingerprint\n", encoding="utf-8")
    return stick


def _sign_stick(tmp_path: Path, stick: Path, priv: Path, pub: Path) -> subprocess.CompletedProcess[str]:
    env = _tool_env(tmp_path, UDBMCP_RELEASE_KEY=str(priv), UDBMCP_PUBKEY=str(pub))
    return subprocess.run(  # noqa: S603 - repo script under test
        ["/bin/bash", str(RELEASE_USB), "--sign-stick", str(stick)],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def _signed_stick(tmp_path: Path) -> tuple[Ed25519PrivateKey, Path, Path]:
    key, priv, pub = _keypair(tmp_path)
    stick = _stick(tmp_path, pub)
    proc = _sign_stick(tmp_path, stick, priv, pub)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return key, pub, stick


def _regenerate_plain_sums(stick: Path) -> None:
    """What an attacker does after editing the stick: the old unsigned recipe."""
    files = sorted(
        p for p in stick.rglob("*") if p.is_file() and p.name not in ("SHA256SUMS", "SHA256SUMS.sig")
    )
    (stick / "SHA256SUMS").write_text(
        "".join(f"{_sha256(p)}  {p.relative_to(stick)}\n" for p in files), encoding="utf-8"
    )


def _flip_byte(path: Path) -> None:
    data = bytearray(path.read_bytes())
    data[len(data) // 2] ^= 0x20
    path.write_bytes(bytes(data))


def test_f14_release_usb_signs_a_checksum_list_that_covers_every_file_on_the_stick(tmp_path: Path) -> None:
    key, pub, stick = _signed_stick(tmp_path)
    sums_path, sig_path = stick / "SHA256SUMS", stick / "SHA256SUMS.sig"
    key.public_key().verify(sig_path.read_bytes(), sums_path.read_bytes())
    openssl = _openssl3()
    assert openssl is not None
    ossl = subprocess.run(  # noqa: S603
        [openssl, "pkeyutl", "-verify", "-pubin", "-inkey", str(pub), "-rawin",
         "-in", str(sums_path), "-sigfile", str(sig_path)],
        capture_output=True, text=True, check=False,
    )
    assert ossl.returncode == 0, ossl.stdout + ossl.stderr
    listed = {line.split("  ", 1)[1] for line in sums_path.read_text(encoding="utf-8").splitlines()}
    on_stick = {
        str(p.relative_to(stick)) for p in stick.rglob("*")
        if p.is_file() and p.name not in ("SHA256SUMS", "SHA256SUMS.sig")
    }
    assert listed == on_stick
    assert {"trust-bootstrap-linux/bootstrap.sh", "trust-bootstrap-linux/install_offline.sh", DEB_NAME} <= listed


def test_f14_release_usb_lists_what_bootstrap_checks_and_refuses_a_symlink(tmp_path: Path) -> None:
    """Both sides agree on what a stick holds: the metadata bootstrap.sh skips is never signed (Finder
    rewrites .DS_Store later), and a symlink, which the site refuses, fails the release instead."""
    _key, priv, pub = _keypair(tmp_path)
    stick = _stick(tmp_path, pub)
    (stick / ".DS_Store").write_bytes(b"\0Bud1")
    (stick / f"._{DEB_NAME}").write_bytes(b"\0\5\26\7")
    assert _sign_stick(tmp_path, stick, priv, pub).returncode == 0
    listed = (stick / "SHA256SUMS").read_text(encoding="utf-8")
    assert ".DS_Store" not in listed and f"._{DEB_NAME}" not in listed and f"  {DEB_NAME}\n" in listed
    (stick / "oracle-instantclient" / "instantclient.zip").symlink_to(tmp_path / "elsewhere.zip")
    proc = _sign_stick(tmp_path, stick, priv, pub)
    assert proc.returncode != 0, proc.stdout
    assert "oracle-instantclient/instantclient.zip" in proc.stderr and "not a regular file" in proc.stderr


def test_f14_a_regenerated_checksum_list_still_passes_sha256sum_but_fails_the_signature(tmp_path: Path) -> None:
    key, pub, stick = _signed_stick(tmp_path)
    _flip_byte(stick / "trust-bootstrap-linux" / "install_offline.sh")
    _regenerate_plain_sums(stick)
    check = subprocess.run(  # noqa: S603
        ["shasum", "-a", "256", "-c", "SHA256SUMS"],  # noqa: S607 - the operator's step-0 tool
        cwd=stick, capture_output=True, text=True, check=False,
    )
    assert check.returncode == 0, check.stdout  # integrity alone is satisfied: the attacker rewrote it
    with pytest.raises(InvalidSignature):
        key.public_key().verify((stick / "SHA256SUMS.sig").read_bytes(), (stick / "SHA256SUMS").read_bytes())
    proc = _verify("--verify-file", stick / "SHA256SUMS", "--signature", stick / "SHA256SUMS.sig", "--pubkey", pub)
    assert proc.returncode == 1
    assert "signature verification FAILED" in proc.stdout
    assert "signature verification PASSED" not in proc.stdout


def test_f14_detached_verification_fails_closed_on_a_wrong_or_absent_key(tmp_path: Path) -> None:
    _key, pub, stick = _signed_stick(tmp_path)
    args = ("--verify-file", stick / "SHA256SUMS", "--signature", stick / "SHA256SUMS.sig")
    ok = _verify(*args, "--pubkey", pub)
    assert ok.returncode == 0 and "signature verification PASSED" in ok.stdout, ok.stdout
    _other, _, wrong = _keypair(tmp_path, "other")
    for pubkey in (wrong, tmp_path / "absent.pub.pem"):
        proc = _verify(*args, "--pubkey", pubkey)
        assert proc.returncode == 1, proc.stdout
        assert "FAIL: signature verification FAILED" in proc.stdout
        assert "PASSED" not in proc.stdout
    no_key = _verify(*args)
    assert no_key.returncode != 0 and "PASSED" not in no_key.stdout


def _site(tmp_path: Path, pub: Path) -> Path:
    """A site root (UDBMCP_BOOTSTRAP_ROOT) bootstrapped earlier: trust dir + release key."""
    root = tmp_path / "site"
    trust = root / "usr" / "local" / "lib" / "udbmcp-trust"
    (trust / "lib").mkdir(parents=True)
    shutil.copy2(VERIFIER, trust / "verify_bundle.py")
    (trust / "profiles.py").write_text("# the previous release's registry\n", encoding="utf-8")
    (trust / "install_offline.sh").write_text("# the previous release's installer\n", encoding="utf-8")
    (trust / "lib" / "os_packages.sh").write_text("# the previous release's helper\n", encoding="utf-8")
    keys = root / "etc" / "universal-db-mcp" / "keys"
    keys.mkdir(parents=True)
    shutil.copy2(pub, keys / "release.pub.pem")
    (root / "var" / "tmp").mkdir(parents=True)  # where bootstrap.sh stages its private copy
    return root


def _bootstrap(tmp_path: Path, stick: Path, root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return _bootstrap_by(tmp_path, str(stick / "trust-bootstrap-linux" / "bootstrap.sh"), root, *args)


def _bootstrap_by(
    tmp_path: Path, script: str, root: Path, *args: str, cwd: Path | None = None
) -> subprocess.CompletedProcess[str]:
    """Run bootstrap.sh by the path *script*, as the operator typed it (relative to *cwd*)."""
    return subprocess.run(  # noqa: S603 - repo script under test
        ["/bin/bash", script, *args],
        env=_tool_env(tmp_path, UDBMCP_BOOTSTRAP_ROOT=str(root)),
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        cwd=cwd,
    )


def _installed_bootstrap(root: Path) -> Path:
    return root / "usr" / "local" / "lib" / "udbmcp-trust" / "bootstrap.sh"


def _deb_dir(root: Path) -> Path:
    """Where bootstrap.sh keeps the checked copy of the .deb that it names for dpkg -i."""
    return root / "var" / "cache" / "udbmcp-trust"


def test_f14_bootstrap_installs_the_tools_of_a_correctly_signed_stick(tmp_path: Path) -> None:
    _key, pub, stick = _signed_stick(tmp_path)
    root = _site(tmp_path, pub)
    stale = _deb_dir(root) / "universal-db-mcp_0.0.9_amd64.deb"  # an earlier bootstrap's copy
    stale.parent.mkdir(parents=True)
    stale.write_bytes(b"!<arch>\nthe previous release\n")
    proc = _bootstrap(tmp_path, stick, root)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "signature verification PASSED" in proc.stdout
    trust = root / "usr" / "local" / "lib" / "udbmcp-trust"
    tb = stick / "trust-bootstrap-linux"
    for name in ("bootstrap.sh", "verify_bundle.py", "profiles.py", "install_offline.sh", "lib/os_packages.sh"):
        assert (trust / name).read_bytes() == (tb / name).read_bytes(), name
    assert (trust / "bootstrap.sh").stat().st_mode & 0o777 == 0o755
    # the exact package the signed list covers, as a copy only root can change: dpkg -i reads the
    # .deb again and runs its preinst as root, and the stick may have changed since it was checked
    copy = _deb_dir(root) / DEB_NAME
    assert f"sudo dpkg -i {copy}\n" in proc.stdout, proc.stdout
    assert f"{stick}/" not in proc.stdout.split("now install the package", 1)[1], proc.stdout
    assert copy.read_bytes() == (stick / DEB_NAME).read_bytes()
    assert copy.parent.stat().st_mode & 0o777 == 0o700
    assert not stale.exists(), "an earlier release's copy is removed"
    for name in ORACLE_DEBS:  # the runbook's thick-mode packages, which dpkg -i runs as root as well
        assert (_deb_dir(root) / name).read_bytes() == (stick / name).read_bytes(), name
        assert f"    {_deb_dir(root) / name}\n" in proc.stdout, proc.stdout
    # the next upgrade runs this installed copy, which checks the next stick before anything on it runs
    assert f"sudo bash {trust}/bootstrap.sh --stick <the next stick>" in proc.stdout, proc.stdout


@pytest.mark.parametrize("attack", ["regenerated-sums", "other-key", "unsigned", "swapped-deb"])
def test_f14_bootstrap_refuses_a_tampered_stick_and_leaves_the_trust_dir_byte_identical(
    tmp_path: Path, attack: str
) -> None:
    _key, pub, stick = _signed_stick(tmp_path)
    root = _site(tmp_path, pub)
    if attack == "regenerated-sums":  # the review's trigger
        _flip_byte(stick / "trust-bootstrap-linux" / "install_offline.sh")
        _regenerate_plain_sums(stick)
    elif attack == "other-key":  # consistent list, signed by a key the site does not trust
        _flip_byte(stick / "trust-bootstrap-linux" / "verify_bundle.py")
        _regenerate_plain_sums(stick)
        attacker = Ed25519PrivateKey.generate()
        (stick / "SHA256SUMS.sig").write_bytes(attacker.sign((stick / "SHA256SUMS").read_bytes()))
    elif attack == "unsigned":
        (stick / "SHA256SUMS.sig").unlink()
    else:  # the .deb (and its preinst) swapped under an intact, signed list
        _flip_byte(stick / DEB_NAME)
    before = _snapshot(root)
    proc = _bootstrap(tmp_path, stick, root)
    assert proc.returncode != 0, proc.stdout
    assert "FAIL:" in proc.stderr and "stick" in proc.stderr, proc.stderr
    assert _snapshot(root) == before


@pytest.mark.parametrize(
    "added",
    [
        "oracle-instantclient/libaio1t64_9.9-evil_amd64.deb",  # the runbook's `dpkg -i libaio1t64_*.deb` picks it up
        "universal-db-mcp_9.9.9+evil_amd64.deb",
        "trust-bootstrap-linux/lib/evil.sh",
    ],
    ids=["libaio-glob", "second-deb", "trust-tools"],
)
def test_f14_bootstrap_refuses_a_file_the_signed_list_does_not_name(tmp_path: Path, added: str) -> None:
    """sha256sum -c checks only the files the list names: a file added to a correctly signed
    stick is on nobody's list, so it is refused, not ignored."""
    _key, pub, stick = _signed_stick(tmp_path)
    root = _site(tmp_path, pub)
    extra = stick / added
    extra.parent.mkdir(parents=True, exist_ok=True)
    extra.write_bytes(b"!<arch>\ndebian-binary 2.0\ncontrol.tar attacker preinst\n")
    before = _snapshot(root)
    proc = _bootstrap(tmp_path, stick, root)
    assert proc.returncode != 0, proc.stdout
    assert f"FAIL: {added} is on the stick but not on its signed SHA256SUMS" in proc.stderr, proc.stderr
    assert "Nothing was installed" in proc.stderr, proc.stderr
    assert "every file on the stick matches" not in proc.stdout
    assert _snapshot(root) == before


@pytest.mark.parametrize("link", ["added", "listed"])
def test_f14_bootstrap_refuses_a_symlink_on_the_stick(tmp_path: Path, link: str) -> None:
    """A release stick holds regular files only (release_usb.sh lists `find -type f`): a symlink,
    even one standing in for a listed file with the same bytes, can change after the check."""
    _key, pub, stick = _signed_stick(tmp_path)
    root = _site(tmp_path, pub)
    elsewhere = tmp_path / "elsewhere.deb"
    if link == "added":
        elsewhere.write_bytes(b"!<arch>\nattacker preinst\n")
        path = stick / "oracle-instantclient" / "libaio1t64_9.9_amd64.deb"
    else:
        path = stick / DEB_NAME
        shutil.copy2(path, elsewhere)
        path.unlink()
    path.symlink_to(elsewhere)
    before = _snapshot(root)
    proc = _bootstrap(tmp_path, stick, root)
    assert proc.returncode != 0, proc.stdout
    rel = path.relative_to(stick)
    assert f"FAIL: {rel} is not a regular file" in proc.stderr, proc.stderr
    assert _snapshot(root) == before


@pytest.mark.parametrize(
    "added",
    [
        "oracle-instantclient/a/b/c/libaio1t64_9.9-evil_amd64.deb",  # deeper than any listed file
        "oracle-instantclient/libaio1t64_9.9 evil_amd64.deb",
        "oracle-instantclient/.Trashes/libaio1t64_9.9-evil_amd64.deb",  # skipped only at the stick root
        "oracle-instantclient/.ds_store",  # the skip rule is exact: Finder writes .DS_Store
        "._folder/libaio1t64_9.9-evil_amd64.deb",  # an AppleDouble name skips a file, not a directory
        "hardlink",  # a second name for the listed .deb
    ],
    ids=["deeper", "space", "trashes-below-root", "ds-store-case", "appledouble-dir", "hard-link"],
)
def test_f14_bootstrap_refuses_every_unlisted_look_alike(tmp_path: Path, added: str) -> None:
    _key, pub, stick = _signed_stick(tmp_path)
    root = _site(tmp_path, pub)
    if added == "hardlink":
        added = "oracle-instantclient/libaio1t64_9.9_amd64.deb"
        os.link(stick / DEB_NAME, stick / added)
    else:
        (stick / added).parent.mkdir(parents=True, exist_ok=True)
        (stick / added).write_bytes(b"!<arch>\nattacker\n")
    before = _snapshot(root)
    proc = _bootstrap(tmp_path, stick, root)
    assert proc.returncode != 0, proc.stdout
    assert f"FAIL: {added} is on the stick but not on its signed SHA256SUMS" in proc.stderr, proc.stderr
    assert _snapshot(root) == before


@pytest.mark.parametrize(
    "added",
    [
        "oracle-instantclient/libaio1t64_x\n.deb",
        "UPGRADE-README.md\nRELEASE-KEY-FINGERPRINT.txt",  # each line alone is a listed name
    ],
    ids=["new-name", "listed-names"],
)
def test_f14_bootstrap_refuses_a_file_name_with_a_line_break(tmp_path: Path, added: str) -> None:
    """find prints such a name as two lines: the coverage check must not depend on how those lines
    happen to compare with the list, and the refusal must name the real problem."""
    _key, pub, stick = _signed_stick(tmp_path)
    root = _site(tmp_path, pub)
    extra = stick / added
    extra.parent.mkdir(parents=True, exist_ok=True)
    extra.write_bytes(b"!<arch>\nattacker\n")
    before = _snapshot(root)
    proc = _bootstrap(tmp_path, stick, root)
    assert proc.returncode != 0, proc.stdout
    assert "FAIL: the stick holds a file name with a line break" in proc.stderr, proc.stderr
    assert "is on the stick but not on its signed SHA256SUMS" not in proc.stderr, proc.stderr
    assert _snapshot(root) == before


def _bootstrap_bounded(tmp_path: Path, stick: Path, root: Path) -> subprocess.CompletedProcess[str] | None:
    """_bootstrap, but a run that blocks is killed with every process it started: None then."""
    proc = subprocess.Popen(  # noqa: S603 - repo script under test
        ["/bin/bash", str(stick / "trust-bootstrap-linux" / "bootstrap.sh")],
        env=_tool_env(tmp_path, UDBMCP_BOOTSTRAP_ROOT=str(root)),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        out, err = proc.communicate(timeout=60)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.communicate()
        return None
    return subprocess.CompletedProcess(proc.args, proc.returncode, out, err)


@pytest.mark.parametrize("kind", ["fifo", "endless-device"])
@pytest.mark.parametrize("rel", ["UPGRADE-README.md", "trust-bootstrap-linux/README"], ids=["listed", "in-the-tools"])
def test_f14_bootstrap_refuses_what_is_not_a_regular_file_before_reading_the_stick(
    tmp_path: Path, rel: str, kind: str
) -> None:
    """A FIFO, or a link to /dev/zero, where a stick holds regular files: `sha256sum -c` would block on
    the FIFO or read the device forever. The refusal comes first."""
    _key, pub, stick = _signed_stick(tmp_path)
    root = _site(tmp_path, pub)
    target = stick / rel
    target.unlink(missing_ok=True)
    if kind == "fifo":
        os.mkfifo(target)
    else:
        target.symlink_to("/dev/zero")
    before = _snapshot(root)
    proc = _bootstrap_bounded(tmp_path, stick, root)
    assert proc is not None, f"bootstrap.sh blocked on the {kind} at {rel} instead of refusing it"
    assert proc.returncode != 0, proc.stdout
    assert f"FAIL: {rel} is not a regular file" in proc.stderr, proc.stderr
    assert "stick signature verified" not in proc.stdout, proc.stdout
    assert _snapshot(root) == before


@pytest.mark.parametrize("which", ["stick", "installed"])
def test_f14_bootstrap_names_a_key_openssl_cannot_read(tmp_path: Path, which: str) -> None:
    """Under pipefail the fingerprint pipeline fails with openssl; the refusal must still be printed."""
    _key, pub, stick = _signed_stick(tmp_path)
    root = _site(tmp_path, pub)
    key = (
        stick / "trust-bootstrap-linux" / "release.pub.pem"
        if which == "stick"
        else root / "etc" / "universal-db-mcp" / "keys" / "release.pub.pem"
    )
    key.write_text("not a key\n", encoding="utf-8")
    before = _snapshot(root)
    proc = _bootstrap(tmp_path, stick, root)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    expected = (
        f"FAIL: {stick}/trust-bootstrap-linux/release.pub.pem is not a readable public key."
        if which == "stick"
        else f"FAIL: the installed release key {key} is not a readable public key"
    )
    assert expected in proc.stderr, proc.stdout + proc.stderr
    assert _snapshot(root) == before


def test_f14_bootstrap_skips_the_metadata_a_mac_or_windows_writes_to_the_stick(tmp_path: Path) -> None:
    """Copying the stick on a Mac adds AppleDouble ._* files, .DS_Store and the volume's Spotlight,
    fseventsd and Trashes folders; Windows adds System Volume Information. Nothing reads them."""
    _key, pub, stick = _signed_stick(tmp_path)
    root = _site(tmp_path, pub)
    for rel in (
        f"._{DEB_NAME}", ".DS_Store", "trust-bootstrap-linux/._bootstrap.sh", "oracle-instantclient/.DS_Store",
        ".Spotlight-V100/Store-V2/store.db", ".fseventsd/fseventsd-uuid", ".Trashes/501/x.deb",
        ".TemporaryItems/folders.501/x", "System Volume Information/IndexerVolumeGuid",
    ):
        path = stick / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"\0\5\26\7metadata")
    proc = _bootstrap(tmp_path, stick, root)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "every file on the stick matches the signed SHA256SUMS" in proc.stdout


def _logging_cp(tmp_path: Path) -> Path:
    """A cp first on bootstrap.sh's PATH that records each run: the first is the staging copy."""
    log = tmp_path / "cp.log"
    cp = tmp_path / "tools" / "cp"
    cp.write_text(f'#!/bin/sh\necho "cp $*" >> "{log}"\nexec /bin/cp "$@"\n', encoding="utf-8")
    cp.chmod(0o755)
    return log


@pytest.mark.parametrize("kind", ["dir-link", "endless-device", "fifo"])
@pytest.mark.parametrize("name", ["._x", ".DS_Store"])
def test_f14_bootstrap_skips_only_regular_files_by_a_metadata_name(tmp_path: Path, name: str, kind: str) -> None:
    """The metadata a Mac writes is regular files. A link or FIFO by such a name in the trust tools
    is refused like any other, before anything on the stick is copied."""
    _key, pub, stick = _signed_stick(tmp_path)
    root = _site(tmp_path, pub)
    log = _logging_cp(tmp_path)
    rel = f"trust-bootstrap-linux/{name}"
    if kind == "dir-link":
        tree = tmp_path / "elsewhere"
        tree.mkdir()
        (tree / "large.bin").write_bytes(b"\0" * 65536)
        (stick / rel).symlink_to(tree)
    elif kind == "endless-device":
        (stick / rel).symlink_to("/dev/zero")
    else:
        os.mkfifo(stick / rel)
    before = _snapshot(root)
    proc = _bootstrap_bounded(tmp_path, stick, root)
    assert proc is not None, f"bootstrap.sh blocked on the {kind} at {rel} instead of refusing it"
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert f"FAIL: {rel} is not a regular file" in proc.stderr, proc.stderr
    assert not log.exists(), log.read_text(encoding="utf-8")  # nothing on the stick was copied
    assert "release public key on this stick" not in proc.stdout, proc.stdout
    assert _snapshot(root) == before


@pytest.mark.parametrize("name", ["._x", ".DS_Store"])
def test_f14_release_usb_refuses_a_symlink_by_a_metadata_name(tmp_path: Path, name: str) -> None:
    """release_usb.sh skips the same names bootstrap.sh does, so a link by one fails the release
    instead of the site."""
    _key, priv, pub = _keypair(tmp_path)
    stick = _stick(tmp_path, pub)
    (stick / "trust-bootstrap-linux" / name).symlink_to(tmp_path)
    proc = _sign_stick(tmp_path, stick, priv, pub)
    assert proc.returncode != 0, proc.stdout
    assert f"trust-bootstrap-linux/{name}" in proc.stderr and "not a regular file" in proc.stderr, proc.stderr
    assert not (stick / "SHA256SUMS.sig").exists()


def _site_that_predates_detached_verification(tmp_path: Path, pub: Path) -> Path:
    """_site, but its verifier has no --verify-file: the stick is checked with the site's openssl."""
    root = _site(tmp_path, pub)
    trust = root / "usr" / "local" / "lib" / "udbmcp-trust"
    (trust / "verify_bundle.py").write_text("# the previous release's verifier (bundle mode only)\n", encoding="utf-8")
    (root / "usr" / "bin").mkdir(parents=True)
    openssl = _openssl3()
    assert openssl is not None  # _signed_stick skips the test without one
    (root / "usr" / "bin" / "openssl").symlink_to(openssl)
    return root


@pytest.mark.parametrize("attack", ["none", "regenerated-sums", "swapped-deb"])
def test_f14_bootstrap_over_a_trust_dir_that_predates_detached_verification_uses_the_system_openssl(
    tmp_path: Path, attack: str
) -> None:
    """The first upgrade to this release: the installed verifier has no --verify-file, so the
    installed key is checked with the site's own openssl by absolute path, never the stick's tools."""
    _key, pub, stick = _signed_stick(tmp_path)
    root = _site_that_predates_detached_verification(tmp_path, pub)
    trust = root / "usr" / "local" / "lib" / "udbmcp-trust"
    if attack == "regenerated-sums":
        _flip_byte(stick / "trust-bootstrap-linux" / "verify_bundle.py")
        _regenerate_plain_sums(stick)
    elif attack == "swapped-deb":
        _flip_byte(stick / DEB_NAME)
    before = _snapshot(root)
    proc = _bootstrap(tmp_path, stick, root)
    if attack == "none":
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "checking the stick's SHA256SUMS.sig with the INSTALLED release key" in proc.stdout
        assert "Signature Verified Successfully" in proc.stdout  # the site's openssl answered
        refreshed = (stick / "trust-bootstrap-linux" / "verify_bundle.py").read_bytes()
        assert (trust / "verify_bundle.py").read_bytes() == refreshed
        return
    assert proc.returncode != 0, proc.stdout
    assert "FAIL:" in proc.stderr and "stick" in proc.stderr, proc.stderr
    assert _snapshot(root) == before


def _fresh_site(tmp_path: Path) -> Path:
    """A site with nothing installed yet; its system openssl is an OpenSSL 3 (Ubuntu's is)."""
    root = tmp_path / "fresh-site"
    (root / "usr" / "bin").mkdir(parents=True)
    (root / "var" / "tmp").mkdir(parents=True)
    openssl = _openssl3()
    assert openssl is not None  # _tool_env skips the test without one
    (root / "usr" / "bin" / "openssl").symlink_to(openssl)
    return root


@pytest.mark.parametrize("attack", ["none", "regenerated-sums", "swapped-deb"])
def test_f14_bootstrap_first_install_checks_the_signature_with_the_stick_key(tmp_path: Path, attack: str) -> None:
    _key, _pub, stick = _signed_stick(tmp_path)
    root = _fresh_site(tmp_path)
    if attack == "regenerated-sums":  # no installed verifier yet: the system openssl must catch it
        _flip_byte(stick / "trust-bootstrap-linux" / "verify_bundle.py")
        _regenerate_plain_sums(stick)
    elif attack == "swapped-deb":
        _flip_byte(stick / DEB_NAME)
    before = _snapshot(root)
    proc = _bootstrap(tmp_path, stick, root)
    if attack == "none":
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "first install: checking the stick's SHA256SUMS.sig with the stick's own key" in proc.stdout
        assert (root / "etc" / "universal-db-mcp" / "keys" / "release.pub.pem").is_file()
        return
    assert proc.returncode != 0, proc.stdout
    assert "FAIL:" in proc.stderr and "stick" in proc.stderr, proc.stderr
    assert _snapshot(root) == before
    assert not (root / "etc").exists() and not (root / "usr" / "local").exists()


def _decoy(stick: Path, tmp_path: Path) -> None:
    """trust-bootstrap-linux on the stick becomes a symlink into decoy/, a verbatim copy of the signed
    stick, and an unlisted libaio .deb (the runbook's `dpkg -i libaio1t64_*.deb` installs it) is added
    at the real stick root."""
    shutil.copytree(stick, tmp_path / "decoy-copy", symlinks=True)
    (tmp_path / "decoy-copy").rename(stick / "decoy")
    shutil.rmtree(stick / "trust-bootstrap-linux")
    (stick / "trust-bootstrap-linux").symlink_to("decoy/trust-bootstrap-linux")
    (stick / "oracle-instantclient" / "libaio1t64_9.9-evil_amd64.deb").write_bytes(b"!<arch>\nattacker\n")


@pytest.mark.parametrize("run", ["stick-path", "dotdot-path", "installed-copy"])
def test_f14_bootstrap_checks_the_stick_it_was_run_from_not_where_its_folder_leads(tmp_path: Path, run: str) -> None:
    """The stick is the folder the operator named, never where a symlinked trust-bootstrap-linux
    leads: resolved, it would move every check into the decoy and never look at the real root."""
    _key, pub, stick = _signed_stick(tmp_path)
    root = _site(tmp_path, pub)
    if run == "installed-copy":  # an earlier bootstrap left its own copy in the trust dir
        assert _bootstrap(tmp_path, stick, root).returncode == 0
    _decoy(stick, tmp_path)
    before = _snapshot(root)
    if run == "stick-path":
        proc = _bootstrap(tmp_path, stick, root)
    elif run == "dotdot-path":
        proc = _bootstrap_by(tmp_path, f"{stick}/oracle-instantclient/../trust-bootstrap-linux/bootstrap.sh", root)
    else:
        proc = _bootstrap_by(tmp_path, str(_installed_bootstrap(root)), root, "--stick", str(stick))
    assert proc.returncode != 0, proc.stdout
    assert "FAIL: trust-bootstrap-linux is not a regular file" in proc.stderr, proc.stderr
    assert "every file on the stick matches" not in proc.stdout
    assert _snapshot(root) == before


def test_f14_bootstrap_refuses_a_path_that_does_not_name_the_stick(tmp_path: Path) -> None:
    """Run as `bash bootstrap.sh` from inside the folder, the script cannot tell which stick the
    operator stands on (sudo drops the logical $PWD, so '..' is wherever the folder really is)."""
    _key, pub, stick = _signed_stick(tmp_path)
    root = _site(tmp_path, pub)
    before = _snapshot(root)
    proc = _bootstrap_by(tmp_path, "bootstrap.sh", root, cwd=stick / "trust-bootstrap-linux")
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "sudo bash <stick>/trust-bootstrap-linux/bootstrap.sh" in proc.stderr, proc.stderr
    assert _snapshot(root) == before
    ok = _bootstrap_by(tmp_path, "trust-bootstrap-linux/bootstrap.sh", root, cwd=stick)
    assert ok.returncode == 0, ok.stdout + ok.stderr
    for args in (["--stick"], ["--stick", str(stick), "extra"], ["--bogus"]):
        bad = _bootstrap_by(tmp_path, str(_installed_bootstrap(root)), root, *args)
        assert bad.returncode == 2 and "usage:" in bad.stderr, (args, bad.stdout + bad.stderr)


def test_f14_the_installed_bootstrap_checks_the_next_stick_before_anything_on_it_runs(tmp_path: Path) -> None:
    """On an upgrade the stick's own bootstrap.sh is attacker-controlled under F14's threat model:
    edited, with SHA256SUMS regenerated, it passes `sha256sum -c` and would run as root. The copy an
    earlier release installed checks the stick's signature with the INSTALLED key first."""
    _key, pub, stick = _signed_stick(tmp_path)
    root = _site(tmp_path, pub)
    assert _bootstrap(tmp_path, stick, root).returncode == 0
    installed = _installed_bootstrap(root)
    ran = tmp_path / "stick-bootstrap-ran"
    tb = stick / "trust-bootstrap-linux"
    body = (tb / "bootstrap.sh").read_text(encoding="utf-8")
    (tb / "bootstrap.sh").write_text(body.replace("set -euo pipefail\n", f"set -euo pipefail\ntouch {ran}\n", 1))
    _regenerate_plain_sums(stick)
    before = _snapshot(root)
    proc = _bootstrap_by(tmp_path, str(installed), root, "--stick", str(stick))
    assert proc.returncode != 0, proc.stdout
    assert "checking the stick's SHA256SUMS.sig with the INSTALLED release key" in proc.stdout, proc.stdout
    assert "NOT signed by the release key" in proc.stderr, proc.stderr
    assert not ran.exists(), "nothing from the stick may run before its signature is checked"
    assert _snapshot(root) == before


def test_f14_the_installed_bootstrap_installs_a_correctly_signed_next_stick(tmp_path: Path) -> None:
    _key, pub, stick = _signed_stick(tmp_path)
    root = _site(tmp_path, pub)
    assert _bootstrap(tmp_path, stick, root).returncode == 0
    installed = _installed_bootstrap(root)
    tb = stick / "trust-bootstrap-linux"
    (tb / "profiles.py").write_text("# the next release's registry\n", encoding="utf-8")
    (tb / "bootstrap.sh").write_text((tb / "bootstrap.sh").read_text(encoding="utf-8") + "# next release\n")
    assert _sign_stick(tmp_path, stick, tmp_path / "release.pem", pub).returncode == 0  # _signed_stick's key
    proc = _bootstrap_by(tmp_path, str(installed), root, "--stick", str(stick))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "checking the stick's SHA256SUMS.sig with the INSTALLED release key" in proc.stdout
    trust = installed.parent
    for name in ("bootstrap.sh", "profiles.py"):
        assert (trust / name).read_bytes() == (tb / name).read_bytes(), name
    assert f"sudo dpkg -i {_deb_dir(root) / DEB_NAME}\n" in proc.stdout, proc.stdout


def _staging_cp(tmp_path: Path, after: str = ":", after_list: str = ":", before: str = ":") -> None:
    """A cp first on bootstrap.sh's PATH: the shell code *before* (cp's arguments in "$@"), the real
    copy, then *after* with $dst set to the staged folder once the trust tools are copied, or
    *after_list* with $dst set to the stage once the signed list is: the moments a stick that changes
    while it is read would strike."""
    cp = tmp_path / "tools" / "cp"
    cp.write_text(
        "#!/bin/bash\n"
        f"{before}\n"
        '/bin/cp "$@" || exit\n'
        'dst="${!#}"\n'
        f'case "$dst" in */trust-bootstrap-linux) {after} ;; */) {after_list} ;; esac\n',
        encoding="utf-8",
    )
    cp.chmod(0o755)


def _changed_verifier(tmp_path: Path, stick: Path) -> tuple[Path, Path]:
    """The stick's verifier with a line added, and the stick's signed SHA256SUMS rewritten to name it
    (no longer the list the release key signed)."""
    signed = stick / "trust-bootstrap-linux" / "verify_bundle.py"
    changed = tmp_path / "changed-verify_bundle.py"
    changed.write_bytes(signed.read_bytes() + b'\nprint("STAGED-MARKER")\n')
    lines = (stick / "SHA256SUMS").read_text(encoding="utf-8").splitlines(keepends=True)
    rewritten = tmp_path / "rewritten-SHA256SUMS"
    rewritten.write_text(
        "".join(
            f"{_sha256(changed)}  trust-bootstrap-linux/verify_bundle.py\n"
            if line.rstrip("\n").endswith("  trust-bootstrap-linux/verify_bundle.py")
            else line
            for line in lines
        ),
        encoding="utf-8",
    )
    assert rewritten.read_bytes() != (stick / "SHA256SUMS").read_bytes()
    return changed, rewritten


@pytest.mark.parametrize("sticks_list", ["as-signed", "rewritten-once-copied"])
def test_f14_bootstrap_checks_its_private_copy_of_the_trust_tools(tmp_path: Path, sticks_list: str) -> None:
    """A stick that holds a changed verifier while the private copy is taken, and the signed one again
    when `sha256sum -c` reads the stick: only the check of the copy keeps it out of the trust dir. The
    copy is checked against the private copy of the signed list, never the stick's, which may name the
    changed verifier by the time it is read."""
    _key, pub, stick = _signed_stick(tmp_path)
    root = _site(tmp_path, pub)
    _tool_env(tmp_path)  # the tools directory the cp goes into
    changed, rewritten = _changed_verifier(tmp_path, stick)
    _staging_cp(
        tmp_path,
        after=f'/bin/cp "{changed}" "$dst/verify_bundle.py"',
        after_list=f'/bin/cp "{rewritten}" "{stick}/SHA256SUMS"' if sticks_list != "as-signed" else ":",
    )
    before = _snapshot(root)
    proc = _bootstrap(tmp_path, stick, root)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "stick signature verified" in proc.stdout, proc.stdout  # the copy of the list is the signed one
    assert "trust-bootstrap-linux/verify_bundle.py: FAILED" in proc.stdout + proc.stderr
    assert "FAIL: the trust tools on the stick do not match its signed SHA256SUMS" in proc.stderr, proc.stderr
    assert _snapshot(root) == before
    assert b"STAGED-MARKER" not in b"".join(_snapshot(root).values())


@pytest.mark.parametrize("checker", ["installed-verifier", "system-openssl"])
def test_f14_bootstrap_checks_the_signature_of_its_private_copy_of_the_list(tmp_path: Path, checker: str) -> None:
    """While the private copy is taken, the stick holds a changed verifier and a list that names it;
    then the signed list again, the verifier still changed. The stick's own list and signature pass,
    and the stick's verifier matches the copied list: only a signature check of the copy refuses it."""
    _key, pub, stick = _signed_stick(tmp_path)
    if checker == "installed-verifier":
        root = _site(tmp_path, pub)
    else:
        root = _site_that_predates_detached_verification(tmp_path, pub)
    _tool_env(tmp_path)
    changed, rewritten = _changed_verifier(tmp_path, stick)
    _staging_cp(
        tmp_path,
        after=f'/bin/cp "{changed}" "$dst/verify_bundle.py"',
        after_list=f'/bin/cp "{rewritten}" "$dst/SHA256SUMS"; '
        f'/bin/cp "{changed}" "{stick}/trust-bootstrap-linux/verify_bundle.py"',
    )
    before = _snapshot(root)
    proc = _bootstrap(tmp_path, stick, root)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "FAIL: the stick's SHA256SUMS is NOT signed by the release key" in proc.stderr, proc.stderr
    assert "stick signature verified" not in proc.stdout, proc.stdout
    assert _snapshot(root) == before
    assert b"STAGED-MARKER" not in b"".join(_snapshot(root).values())


_TRUST_TOOLS = ("bootstrap.sh", "verify_bundle.py", "profiles.py", "install_offline.sh", "lib/os_packages.sh")


@pytest.mark.parametrize("site", ["upgrade", "first-install"])
def test_f14_bootstrap_installs_its_checked_private_copy_never_the_stick(tmp_path: Path, site: str) -> None:
    """Every check has passed, and the stick changes right before the first install: the trust dir
    gets the private copy those checks read, never the stick's files (a first install takes the
    release key from it too)."""
    _key, pub, stick = _signed_stick(tmp_path)
    root = _site(tmp_path, pub) if site == "upgrade" else _fresh_site(tmp_path)
    tools = _tool_env(tmp_path)["PATH"].split(":", 1)[0]
    tb = stick / "trust-bootstrap-linux"
    signed = {name: (tb / name).read_bytes() for name in (*_TRUST_TOOLS, "release.pub.pem")}
    _other, _, other_pub = _keypair(tmp_path, "other")
    changed = tmp_path / "stick-changed"
    shim = Path(tools) / "install"
    shim.write_text(
        "#!/bin/bash\n"
        f'if [ ! -e "{changed}" ]; then\n'
        f'  : > "{changed}"\n'
        f'  for f in {" ".join(shlex.quote(str(tb / name)) for name in _TRUST_TOOLS)}; do\n'
        "    printf '\\n# STICK-CHANGED\\n' >> \"$f\"\n"
        "  done\n"
        f'  /bin/cp "{other_pub}" "{tb / "release.pub.pem"}"\n'
        "fi\n"
        'exec /usr/bin/install "$@"\n',
        encoding="utf-8",
    )
    shim.chmod(0o755)
    proc = _bootstrap(tmp_path, stick, root)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert all(b"# STICK-CHANGED" in (tb / name).read_bytes() for name in _TRUST_TOOLS)  # the change did happen
    trust = root / "usr" / "local" / "lib" / "udbmcp-trust"
    for name in _TRUST_TOOLS:
        assert (trust / name).read_bytes() == signed[name], f"{name} was installed from the stick"
    assert (root / "etc" / "universal-db-mcp" / "keys" / "release.pub.pem").read_bytes() == signed["release.pub.pem"]


def test_f14_bootstrap_checks_the_stick_against_its_private_copy_of_the_signed_list(tmp_path: Path) -> None:
    """Once the signed list is copied, the stick holds a changed .deb and a list that names it: only the
    private copy of the list, never the stick's, may decide whether the .deb matches."""
    _key, pub, stick = _signed_stick(tmp_path)
    root = _site(tmp_path, pub)
    _tool_env(tmp_path)
    deb = stick / DEB_NAME
    evil = tmp_path / "evil.deb"
    evil.write_bytes(b"!<arch>\ndebian-binary 2.0\ncontrol.tar evil preinst\n")
    rewritten = tmp_path / "rewritten-SHA256SUMS"
    rewritten.write_text(
        "".join(
            f"{_sha256(evil)}  {DEB_NAME}\n" if line.rstrip("\n").endswith(f"  {DEB_NAME}") else line
            for line in (stick / "SHA256SUMS").read_text(encoding="utf-8").splitlines(keepends=True)
        ),
        encoding="utf-8",
    )
    _staging_cp(tmp_path, after_list=f'/bin/cp "{evil}" "{deb}"; /bin/cp "{rewritten}" "{stick}/SHA256SUMS"')
    before = _snapshot(root)
    proc = _bootstrap(tmp_path, stick, root)
    assert deb.read_bytes() == evil.read_bytes()  # the change did happen
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "stick signature verified" in proc.stdout, proc.stdout  # the copy of the list is the signed one
    assert "FAIL: a file on the stick does not match its signed SHA256SUMS" in proc.stderr, proc.stderr
    assert "sudo dpkg -i" not in proc.stdout, proc.stdout
    assert _snapshot(root) == before


@pytest.mark.parametrize(
    ("name", "change"),
    [
        (DEB_NAME, "swapped"),
        (DEB_NAME, "link-to-a-signed-copy"),
        (DEB_NAME, "fifo"),
        (ORACLE_DEBS[0], "swapped"),
    ],
    ids=["deb-swapped", "deb-link-to-a-signed-copy", "deb-fifo", "libaio-swapped"],
)
def test_f14_bootstrap_names_for_dpkg_only_a_copy_it_checked(tmp_path: Path, name: str, change: str) -> None:
    """Every check has passed, and a .deb on the stick changes as it is copied for dpkg -i (which reads
    it again and runs its preinst as root): another package, a link (to a verbatim copy, which a
    followed link would pass) or a FIFO (which a read would block on). Only a regular copy that matches
    the private copy of the signed list is named; otherwise nothing is installed or kept."""
    _key, pub, stick = _signed_stick(tmp_path)
    root = _site(tmp_path, pub)
    _tool_env(tmp_path)
    deb = stick / name
    signed_copy = tmp_path / "signed.deb"
    shutil.copy2(deb, signed_copy)
    if change == "swapped":
        evil = tmp_path / "evil.deb"
        evil.write_bytes(b"!<arch>\ndebian-binary 2.0\ncontrol.tar evil preinst\n")
        swap = f'/bin/cp "{evil}" "{deb}"'
    elif change == "link-to-a-signed-copy":
        swap = f'/bin/rm -f "{deb}"; /bin/ln -s "{signed_copy}" "{deb}"'
    else:
        swap = f'/bin/rm -f "{deb}"; /usr/bin/mkfifo "{deb}"'
    _staging_cp(tmp_path, before=f'case "$*" in *"/{name}"*) {swap} ;; esac')
    before = _snapshot(root)
    proc = _bootstrap(tmp_path, stick, root)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "every file on the stick matches the signed SHA256SUMS" in proc.stdout, proc.stdout  # checked first
    if change == "swapped":
        assert f"{name}: FAILED" in proc.stdout + proc.stderr
        assert "FAIL: a package copied from the stick does not match its signed SHA256SUMS" in proc.stderr
    else:
        assert f"FAIL: {name} is not a regular file" in proc.stderr, proc.stderr
    assert "sudo dpkg -i" not in proc.stdout, proc.stdout
    assert _snapshot(root) == before  # the trust dir as it was
    assert [p.name for p in _deb_dir(root).glob("*")] == [], "no copy of a changed package is kept"


@pytest.mark.parametrize(
    ("rel", "leads_to"),
    [
        ("SHA256SUMS", "fifo"),
        ("SHA256SUMS.sig", "fifo"),
        ("SHA256SUMS.sig", "signed-copy"),
        ("trust-bootstrap-linux/verify_bundle.py", "signed-copy"),
    ],
    ids=["list-to-a-fifo", "signature-to-a-fifo", "signature-to-its-copy", "trust-tool-to-its-copy"],
)
def test_f14_bootstrap_copies_a_link_on_the_stick_as_a_link(tmp_path: Path, rel: str, leads_to: str) -> None:
    """An entry of the stick turns into a link after the check that it is a regular file, right before
    the private copy is taken. The copy takes the link, never what it leads to, and refuses it: read
    through, a link to a FIFO would block the copy as root (and one to a device would be read
    forever), and one to a copy of the signed file would be installed without a word."""
    _key, pub, stick = _signed_stick(tmp_path)
    root = _site(tmp_path, pub)
    _tool_env(tmp_path)
    entry = stick / rel
    target = tmp_path / leads_to
    if leads_to == "fifo":
        os.mkfifo(target)
    else:
        shutil.copy2(entry, target)
    copying = "*/trust-bootstrap-linux" if rel.startswith("trust-bootstrap-linux/") else "*/"
    _staging_cp(tmp_path, before=f'case "${{!#}}" in {copying}) rm -f "{entry}"; ln -s "{target}" "{entry}" ;; esac')
    before = _snapshot(root)
    proc = _bootstrap_bounded(tmp_path, stick, root)
    assert proc is not None, f"bootstrap.sh blocked reading through the link at {rel}"
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert entry.is_symlink()  # the change did happen
    assert f"FAIL: {rel} is not a regular file" in proc.stderr, proc.stderr
    assert "stick signature verified" not in proc.stdout, proc.stdout
    assert _snapshot(root) == before


@pytest.mark.parametrize("planted", ["link-to-the-stick", "link-to-a-device", "fifo"])
def test_f14_bootstrap_refuses_what_is_not_a_regular_file_in_its_private_copy(tmp_path: Path, planted: str) -> None:
    """Whatever the stick turns into after the check (a link to its own signed verifier, which the
    staged check would read through and `install` would follow later, a device, a FIFO) is copied
    as it is, never followed, and refused before any staged file is read."""
    _key, pub, stick = _signed_stick(tmp_path)
    root = _site(tmp_path, pub)
    _tool_env(tmp_path)
    target = {
        "link-to-the-stick": f'rm "$dst/verify_bundle.py"; ln -s "{stick}/trust-bootstrap-linux/verify_bundle.py" '
        '"$dst/verify_bundle.py"',
        "link-to-a-device": 'ln -s /dev/zero "$dst/lib/zero"',
        "fifo": 'mkfifo "$dst/lib/fifo"',
    }[planted]
    _staging_cp(tmp_path, target)
    before = _snapshot(root)
    proc = _bootstrap_bounded(tmp_path, stick, root)
    assert proc is not None, f"bootstrap.sh blocked on the staged {planted}"
    assert proc.returncode == 1, proc.stdout + proc.stderr
    rel = {"link-to-the-stick": "verify_bundle.py", "link-to-a-device": "lib/zero", "fifo": "lib/fifo"}[planted]
    assert f"FAIL: trust-bootstrap-linux/{rel} is not a regular file" in proc.stderr, proc.stderr
    assert "stick signature verified" not in proc.stdout, proc.stdout
    assert _snapshot(root) == before


def test_f14_bootstrap_stages_below_the_sites_var_tmp_whatever_tmpdir_says(tmp_path: Path) -> None:
    """Root's TMPDIR (sudo -E, or a root shell that sets it) can name a directory another account
    owns, which could rename the stage and put its own in place between the check and the install."""
    _key, pub, stick = _signed_stick(tmp_path)
    root = _site(tmp_path, pub)
    log = _logging_cp(tmp_path)
    user_tmp = tmp_path / "users-tmp"
    user_tmp.mkdir(mode=0o777)
    proc = subprocess.run(  # noqa: S603 - repo script under test
        ["/bin/bash", str(stick / "trust-bootstrap-linux" / "bootstrap.sh")],
        env=_tool_env(tmp_path, UDBMCP_BOOTSTRAP_ROOT=str(root), TMPDIR=str(user_tmp)),
        capture_output=True, text=True, timeout=120, check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    staged = log.read_text(encoding="utf-8").splitlines()[0].split()[-1]
    assert staged.startswith(str(root / "var" / "tmp" / "udbmcp-bootstrap.")), staged
    assert list(user_tmp.iterdir()) == [] and list((root / "var" / "tmp").iterdir()) == []


@pytest.mark.parametrize("name", ["SHA256SUMS", "SHA256SUMS.sig"])
def test_f14_bootstrap_names_a_checksum_list_that_is_a_directory(tmp_path: Path, name: str) -> None:
    _key, pub, stick = _signed_stick(tmp_path)
    root = _site(tmp_path, pub)
    (stick / name).unlink()
    (stick / name).mkdir()
    (stick / name / "inside").write_text("x\n", encoding="utf-8")
    before = _snapshot(root)
    proc = _bootstrap(tmp_path, stick, root)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert f"FAIL: the stick has no {stick}/{name}." in proc.stderr, proc.stderr
    assert "Nothing was installed." in proc.stderr, proc.stderr
    assert _snapshot(root) == before


@pytest.mark.parametrize(
    "verifier",
    [
        "# accepts --verify-file\nimport sys\nsys.exit(0)\n",
        "# accepts --verify-file\nprint('FAIL: not verified')\nprint('signature verification PASSED')\n",
        "# accepts --verify-file\nprint('signature verification PASSED, probably')\n",
    ],
    ids=["exit-0-alone", "passed-and-a-fail-line", "no-exact-passed-line"],
)
def test_f14_bootstrap_takes_only_the_installed_verifiers_explicit_proof(tmp_path: Path, verifier: str) -> None:
    """Exit 0 alone proves nothing: an empty or no-op verifier exits 0 too."""
    _key, pub, stick = _signed_stick(tmp_path)
    root = _site(tmp_path, pub)
    (root / "usr" / "local" / "lib" / "udbmcp-trust" / "verify_bundle.py").write_text(verifier, encoding="utf-8")
    before = _snapshot(root)
    proc = _bootstrap(tmp_path, stick, root)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "FAIL: the stick's SHA256SUMS is NOT signed by the release key" in proc.stderr, proc.stderr
    assert _snapshot(root) == before


def test_f14_maintainer_script_headers_state_they_are_outside_the_bundle_signature() -> None:
    for script in (PREINST, POSTINST):
        head = script.read_text(encoding="utf-8").split("set -e", 1)[0]
        assert "SHA256SUMS.sig" in head, script.name
        assert "NOT covered by the bundle signature" in head, script.name


def test_f14_the_headers_never_claim_a_check_the_documented_flow_does_not_make() -> None:
    """`sha256sum -c` (runbook step 0) checks a list an attacker can regenerate, and the stick's own
    bootstrap.sh checks itself: only tools the site already trusts vouch for the stick."""
    heads = {script.name: script.read_text(encoding="utf-8").split("set -e", 1)[0] for script in (PREINST, POSTINST)}
    heads[RELEASE_USB.name] = RELEASE_USB.read_text(encoding="utf-8").split("set -euo pipefail", 1)[0]
    for name, head in heads.items():
        flat = " ".join(line.lstrip("# ").strip() for line in head.splitlines())
        assert "runbook step 0" not in flat, name
        assert "/usr/local/lib/udbmcp-trust/bootstrap.sh --stick" in flat, name


# ---- F55: anti-rollback (release_seq) ---------------------------------------


def _installed(tmp_path: Path, **manifest: Any) -> Path:
    path = tmp_path / "installed-manifest.json"
    path.write_text(json.dumps({"profile": "test-profile", **manifest}), encoding="utf-8")
    return path


def test_f55_verifier_refuses_an_older_release_unless_the_downgrade_is_explicit(tmp_path: Path) -> None:
    key, _, pub = _keypair(tmp_path)
    installed = _installed(tmp_path, release_seq=5)
    older = _bundle(tmp_path / "b4", key, release_seq=4)
    proc = _verify("--bundle", older, "--pubkey", pub, "--installed-manifest", installed)
    assert proc.returncode == 1, proc.stdout
    assert "FAIL: rollback refused" in proc.stdout
    assert "bundle verification PASSED" not in proc.stdout
    allowed = _verify("--bundle", older, "--pubkey", pub, "--installed-manifest", installed, "--allow-downgrade")
    assert allowed.returncode == 0, allowed.stdout
    assert "bundle verification PASSED" in allowed.stdout and "downgrade" in allowed.stdout
    for seq in (5, 6):  # a reinstall and an upgrade
        bundle = _bundle(tmp_path / f"b{seq}", key, release_seq=seq)
        ok = _verify("--bundle", bundle, "--pubkey", pub, "--installed-manifest", installed)
        assert ok.returncode == 0, ok.stdout
        assert "bundle verification PASSED" in ok.stdout


def test_f55_a_bundle_without_release_seq_is_older_than_a_sequenced_install(tmp_path: Path) -> None:
    key, _, pub = _keypair(tmp_path)
    installed = _installed(tmp_path, release_seq=5, created="2026-09-20T04:01:00+00:00")
    legacy = _bundle(tmp_path / "legacy", key, created="2026-09-30T00:00:00+00:00")
    proc = _verify("--bundle", legacy, "--pubkey", pub, "--installed-manifest", installed)
    assert proc.returncode == 1 and "FAIL: rollback refused" in proc.stdout, proc.stdout


def test_f55_created_orders_releases_that_both_predate_release_seq(tmp_path: Path) -> None:
    key, _, pub = _keypair(tmp_path)
    installed = _installed(tmp_path, created="2026-09-20T04:01:02.123456+00:00")
    stale = _bundle(tmp_path / "stale", key, created="2026-09-15T10:00:00+00:00")
    proc = _verify("--bundle", stale, "--pubkey", pub, "--installed-manifest", installed)
    assert proc.returncode == 1 and "FAIL: rollback refused" in proc.stdout, proc.stdout
    newer = _bundle(tmp_path / "newer", key, created="2026-09-21T00:00:00+00:00")
    assert _verify("--bundle", newer, "--pubkey", pub, "--installed-manifest", installed).returncode == 0


def test_f55_first_installs_and_pre_release_seq_installs_are_not_refused(tmp_path: Path) -> None:
    key, _, pub = _keypair(tmp_path)
    bundle = _bundle(tmp_path / "b", key, release_seq=7, created="2026-09-01T00:00:00+00:00")
    absent = _verify("--bundle", bundle, "--pubkey", pub, "--installed-manifest", tmp_path / "none.json")
    assert absent.returncode == 0, absent.stdout
    legacy = _installed(tmp_path, created="2026-09-20T04:01:00+00:00")  # the live site today
    upgrade = _verify("--bundle", bundle, "--pubkey", pub, "--installed-manifest", legacy)
    assert upgrade.returncode == 0, upgrade.stdout


def test_f55_release_seq_is_covered_by_the_signature(tmp_path: Path) -> None:
    key, _, pub = _keypair(tmp_path)
    installed = _installed(tmp_path, release_seq=5)
    bundle = _bundle(tmp_path / "b", key, release_seq=4)
    (bundle / "manifest.json").write_text(json.dumps({"profile": "test-profile", "release_seq": 9}), encoding="utf-8")
    tampered = _verify("--bundle", bundle, "--pubkey", pub, "--installed-manifest", installed)
    assert tampered.returncode == 1 and "tampered artifact: manifest.json" in tampered.stdout
    (bundle / "SHA256SUMS").write_bytes(_bundle_sums(bundle))  # rewritten list, old SIGNATURE
    resummed = _verify("--bundle", bundle, "--pubkey", pub, "--installed-manifest", installed)
    assert resummed.returncode == 1 and "signature verification FAILED" in resummed.stdout


# A .pkg or .msi runs its OWN embedded install script. One built before the rollback check calls the
# site's trusted verifier as '--bundle B --pubkey P' (HEAD:packaging/pkg/postinstall, the MSI's
# verify.ps1), so the verifier itself must look up the installed release on the install target.
_TARGET_PROFILE = "linux-x86_64-ubuntu24.04-cp312"


def _verify_on_target(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    installed: Path | None,
    *args: object,
    matches: bool = True,
) -> tuple[int, str]:
    """The verifier's main() on a machine where the bundle's profile matches (or not, *matches*) and
    this platform's installed manifest is *installed* (the real one is in a root-owned prefix)."""
    verifier = _load_verifier()
    profiles = verifier.load_profiles_module()
    mismatch = [] if matches else ["operating system Plan9 (target ubuntu-24.04)"]
    monkeypatch.setattr(profiles, "profile_host_mismatches", lambda _profile: mismatch)
    monkeypatch.setattr(verifier, "platform_installed_manifest", lambda: installed)
    monkeypatch.setattr(sys, "argv", ["verify_bundle.py", *(str(a) for a in args)])
    rc = verifier.main()
    return rc, capsys.readouterr().out


def test_f55_on_the_install_target_an_older_release_is_refused_without_being_asked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The argv of a .pkg built before the rollback check: no --installed-manifest, no override."""
    key, _, pub = _keypair(tmp_path)
    installed = _installed(tmp_path, release_seq=5)
    older = _bundle(tmp_path / "b4", key, profile=_TARGET_PROFILE, release_seq=4)
    rc, out = _verify_on_target(monkeypatch, capsys, installed, "--bundle", older, "--pubkey", pub)
    assert rc == 1, out
    assert f"release order: no --installed-manifest given; checking this machine's installed release {installed}" in out
    assert "FAIL: rollback refused" in out and "bundle verification PASSED" not in out, out
    # the one way past it for an installer that cannot pass --allow-downgrade
    assert f"until an administrator moves {installed} aside" in out, out
    rc, out = _verify_on_target(monkeypatch, capsys, installed, "--bundle", older, "--pubkey", pub, "--allow-downgrade")
    assert rc == 0 and "WARNING: DOWNGRADE allowed by --allow-downgrade" in out, out
    for seq in (5, 6):  # a reinstall and an upgrade
        bundle = _bundle(tmp_path / f"b{seq}", key, profile=_TARGET_PROFILE, release_seq=seq)
        rc, out = _verify_on_target(monkeypatch, capsys, installed, "--bundle", bundle, "--pubkey", pub)
        assert rc == 0 and "(not a downgrade)" in out and "bundle verification PASSED" in out, out
    # the bundle of every .pkg and .msi built before release_seq existed: the very case this default is for
    for name, fields in (("legacy", {"created": "2026-09-30T00:00:00+00:00"}), ("bare", {})):
        legacy = _bundle(tmp_path / name, key, profile=_TARGET_PROFILE, **fields)
        rc, out = _verify_on_target(monkeypatch, capsys, installed, "--bundle", legacy, "--pubkey", pub)
        assert rc == 1 and "FAIL: rollback refused" in out and "bundle release_seq missing" in out, (name, out)
    rc, out = _verify_on_target(monkeypatch, capsys, tmp_path / "absent.json", "--bundle", older, "--pubkey", pub)
    assert rc == 0 and "nothing installed yet" in out, out  # a first install


_PKG_PAYLOAD_NOTE = "refused only after the Installer has written its payload"


@pytest.mark.parametrize("system", ["Darwin", "Linux", "Windows"])
def test_f55_a_refused_old_pkg_names_the_payload_the_installer_already_wrote(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], system: str
) -> None:
    """A .pkg built before the rollback check has none in its preinstall: the macOS Installer writes its
    payload (the bundle folder, the share scripts, the LaunchDaemon plist) before its postinstall runs
    this verifier, and keeps it when the install fails. On a Mac the refusal says so, and how to put
    them back; an explicit --installed-manifest is this release's own installers, which check first."""
    key, _, pub = _keypair(tmp_path)
    installed = _installed(tmp_path, release_seq=5)
    older = _bundle(tmp_path / "b4", key, profile=_TARGET_PROFILE, release_seq=4)
    monkeypatch.setattr(_load_verifier().platform, "system", lambda: system)
    rc, out = _verify_on_target(monkeypatch, capsys, installed, "--bundle", older, "--pubkey", pub)
    assert rc == 1 and "FAIL: rollback refused" in out, out
    if system == "Darwin":
        assert _PKG_PAYLOAD_NOTE in out, out
        assert "the bundle folder, the share scripts and the LaunchDaemon plist" in out, out
        assert "re-install the current release's .pkg to restore them" in out, out
    else:
        assert _PKG_PAYLOAD_NOTE not in out, out
    rc, out = _verify_on_target(
        monkeypatch, capsys, installed, "--bundle", older, "--pubkey", pub, "--installed-manifest", installed
    )
    assert rc == 1 and "FAIL: rollback refused" in out and _PKG_PAYLOAD_NOTE not in out, out


def test_f55_the_installed_manifest_default_applies_only_on_the_install_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Release gates verify on a build machine (--no-installed-manifest, or the staging mode
    --allow-platform-mismatch); an explicit --installed-manifest names the record to compare with."""
    key, _, pub = _keypair(tmp_path)
    installed = _installed(tmp_path, profile=_TARGET_PROFILE, release_seq=5)
    older = _bundle(tmp_path / "b4", key, profile=_TARGET_PROFILE, release_seq=4)
    base = ("--bundle", older, "--pubkey", pub)
    for extra, matches in (
        (("--no-installed-manifest",), True),
        (("--allow-platform-mismatch",), True),
        (("--allow-platform-mismatch",), False),
    ):
        rc, out = _verify_on_target(monkeypatch, capsys, installed, *base, *extra, matches=matches)
        assert rc == 0 and "bundle verification PASSED" in out, (extra, out)
        assert "release order" not in out, (extra, out)
    rc, out = _verify_on_target(monkeypatch, capsys, installed, *base, matches=False)
    assert rc == 1 and "does not match this machine" in out and "release order" not in out, out
    # a profile this verifier does not know, and not the installed release's (a test bundle)
    unknown = _bundle(tmp_path / "unknown", key, release_seq=4)
    rc, out = _verify_on_target(monkeypatch, capsys, installed, "--bundle", unknown, "--pubkey", pub)
    assert rc == 0 and "WARNING: unknown bundle profile 'test-profile'" in out and "release order" not in out, out
    (tmp_path / "other").mkdir()
    other = _installed(tmp_path / "other", release_seq=3)
    rc, out = _verify_on_target(monkeypatch, capsys, installed, *base, "--installed-manifest", other)
    assert rc == 0 and "no --installed-manifest given" not in out and "(not a downgrade)" in out, out
    with pytest.raises(SystemExit) as usage:
        _verify_on_target(
            monkeypatch, capsys, installed, *base, "--installed-manifest", other, "--no-installed-manifest"
        )
    assert usage.value.code == 2
    assert "not allowed with argument" in capsys.readouterr().err


def test_f55_a_profile_the_registry_no_longer_knows_is_still_checked_where_that_release_is_installed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A later release may rename or retire a profile (a move to cp313). The .pkg and .msi that call the
    verifier with no --installed-manifest keep the old name, and so does this machine's installed
    release: where that release was built for the bundle's profile, it still orders them."""
    key, _, pub = _keypair(tmp_path)
    retired = "macos-arm64-cp311"  # in no registry
    installed = _installed(tmp_path, profile=retired, release_seq=5)
    older = _bundle(tmp_path / "b4", key, profile=retired, release_seq=4)
    base = ("--bundle", older, "--pubkey", pub)
    rc, out = _verify_on_target(monkeypatch, capsys, installed, *base)
    assert rc == 1, out
    assert f"WARNING: unknown bundle profile '{retired}'" in out, out
    assert f"no --installed-manifest given; checking this machine's installed release {installed}" in out, out
    assert "FAIL: rollback refused" in out and "bundle verification PASSED" not in out, out
    legacy = _bundle(tmp_path / "legacy", key, profile=retired, created="2026-09-30T00:00:00+00:00")
    rc, out = _verify_on_target(monkeypatch, capsys, installed, "--bundle", legacy, "--pubkey", pub)
    assert rc == 1 and "FAIL: rollback refused" in out, out
    rc, out = _verify_on_target(monkeypatch, capsys, installed, *base, "--allow-downgrade")
    assert rc == 0 and "WARNING: DOWNGRADE allowed by --allow-downgrade" in out, out
    for extra in ("--no-installed-manifest", "--allow-platform-mismatch"):  # a build machine, as for a known one
        rc, out = _verify_on_target(monkeypatch, capsys, installed, *base, extra)
        assert rc == 0 and "release order" not in out, (extra, out)
    newer = _bundle(tmp_path / "b6", key, profile=retired, release_seq=6)
    rc, out = _verify_on_target(monkeypatch, capsys, installed, "--bundle", newer, "--pubkey", pub)
    assert rc == 0 and "(not a downgrade)" in out and "bundle verification PASSED" in out, out
    # the installed release was built for another profile, names none, or cannot be read: not this
    # bundle's install target as far as anything shows
    for name, text in (("other", json.dumps({"profile": "test-profile", "release_seq": 5})),
                       ("nameless", json.dumps({"release_seq": 5})), ("unreadable", "{not json")):
        (tmp_path / name).mkdir()
        record = tmp_path / name / "manifest.json"
        record.write_text(text, encoding="utf-8")
        rc, out = _verify_on_target(monkeypatch, capsys, record, *base)
        assert rc == 0 and "release order" not in out, (name, out)


@pytest.mark.parametrize(
    ("system", "script", "pattern"),
    [
        ("Linux", INSTALL, r'^TARGET="\$\{2:-(/opt/universal-db-mcp)\}"$'),
        ("Linux", POSTINST, r"^TARGET=(/opt/universal-db-mcp)$"),
        ("Darwin", REPO / "packaging" / "pkg" / "postinstall", r'^PREFIX="(/usr/local/universal-db-mcp)"$'),
    ],
    ids=["install_offline", "deb-postinst", "pkg-postinstall"],
)
def test_f55_the_default_is_where_the_platforms_installer_records_the_release(
    monkeypatch: pytest.MonkeyPatch, system: str, script: Path, pattern: str
) -> None:
    verifier = _load_verifier()
    match = re.search(pattern, script.read_text(encoding="utf-8"), flags=re.MULTILINE)
    assert match is not None, script
    monkeypatch.setattr(verifier.platform, "system", lambda: system)
    assert verifier.platform_installed_manifest() == Path(match.group(1)) / "manifest.json"


def test_f55_the_downgrade_switch_names_what_it_overrides() -> None:
    """--allow-downgrade overrides the check against this platform's installed release too, which
    runs with no --installed-manifest at all."""
    proc = _verify("--help")
    assert proc.returncode == 0, proc.stderr
    usage = " ".join(proc.stdout.split())
    switch = usage[usage.index("--allow-downgrade ") : usage.index("--verify-file VERIFY_FILE ")]
    assert "the installed release" in switch and "this platform's" in switch, switch
    assert "older than --installed-manifest" not in switch, switch


def test_f55_the_windows_default_is_the_msis_installed_release_record(monkeypatch: pytest.MonkeyPatch) -> None:
    wxs = (REPO / "packaging" / "msi" / "udbmcp.wxs").read_text(encoding="utf-8")
    assert r"INSTALLED_MANIFEST=[ProgramFiles64Folder]UniversalDB MCP\manifest.json;" in wxs
    verifier = _load_verifier()
    monkeypatch.setattr(verifier.platform, "system", lambda: "Windows")
    monkeypatch.setenv("ProgramW6432", r"C:\Program Files")
    monkeypatch.setenv("ProgramFiles", r"C:\Program Files (x86)")  # a 32-bit process's view
    assert verifier.platform_installed_manifest() == Path(r"C:\Program Files") / "UniversalDB MCP" / "manifest.json"
    monkeypatch.delenv("ProgramW6432")
    monkeypatch.setenv("ProgramFiles", r"C:\Program Files")
    assert verifier.platform_installed_manifest() == Path(r"C:\Program Files") / "UniversalDB MCP" / "manifest.json"
    monkeypatch.setattr(verifier.platform, "system", lambda: "FreeBSD")
    assert verifier.platform_installed_manifest() is None


def _shell_commands(text: str) -> list[str]:
    """The script's commands with backslash-newline continuations joined."""
    return re.sub(r"\\\n\s*", " ", text).splitlines()


# The release gates verify on a build machine, which may have the service installed: its installed
# release must never decide whether a build passes.
_RELEASE_GATES = ("build_deb.sh", "build_pkg.sh", "test_package_deb.sh", "test_package_pkg.sh",
                  "test_upgrade_offline.sh")


@pytest.mark.parametrize("gate", _RELEASE_GATES)
def test_f55_release_gates_never_compare_with_the_build_machines_installed_release(gate: str) -> None:
    calls = [
        line for line in _shell_commands((REPO / "scripts" / "package" / gate).read_text(encoding="utf-8"))
        if re.search(r"verify_bundle\.py\S*\s|VERIFIER\"?\s", line) and "--bundle" in line
        # the zero-length verifier baseline: an empty script never reads its arguments
        and "--bundle /nonexistent" not in line
    ]
    assert calls, gate
    for call in calls:
        assert "--no-installed-manifest" in call, call


def _shims(tmp_path: Path) -> Path:
    shims = tmp_path / "shims"
    shims.mkdir(exist_ok=True)
    (shims / "sudo").write_text('#!/bin/sh\nexec "$@"\n', encoding="utf-8")
    (shims / "python3").write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n', encoding="utf-8")
    for shim in shims.iterdir():
        shim.chmod(0o755)
    return shims


def _run_installer(
    tmp_path: Path, script: Path, args: list[str], verifier: Path, **env_extra: str
) -> subprocess.CompletedProcess[str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("UDBMCP_")}
    env["PATH"] = f"{_shims(tmp_path)}:{os.environ.get('PATH', '')}"
    env["UDBMCP_RELEASE_PUBKEY"] = str(tmp_path / "release.pub.pem")
    env["UDBMCP_VERIFIER"] = str(verifier)
    env["UDBMCP_STAGING_DIR"] = str(tmp_path / "staging")
    env["TMPDIR"] = str(tmp_path)
    env.update(env_extra)
    return subprocess.run(  # noqa: S603 - repo script under test
        ["/bin/bash", str(script), *args], env=env, capture_output=True, text=True, timeout=120, check=False
    )


@pytest.mark.parametrize("script", [INSTALL, UPGRADE], ids=["install_offline", "upgrade_offline"])
def test_f55_install_scripts_refuse_a_downgrade_before_anything_is_staged(tmp_path: Path, script: Path) -> None:
    key, _, _pub = _keypair(tmp_path)
    bundle = _bundle(tmp_path / "bundle", key, release_seq=4)
    target = tmp_path / "target"
    target.mkdir()
    (target / "manifest.json").write_text(json.dumps({"profile": "test-profile", "release_seq": 5}), encoding="utf-8")
    extra = [str(tmp_path / "backups")] if script == UPGRADE else []
    before = _snapshot(target)
    proc = _run_installer(tmp_path, script, [str(bundle), str(target), *extra], VERIFIER)
    assert proc.returncode != 0, proc.stdout
    assert "FAIL: rollback refused" in proc.stdout
    assert not (tmp_path / "staging").exists() or not list((tmp_path / "staging").iterdir())
    assert not (tmp_path / "backups").exists()
    assert _snapshot(target) == before


def _argv_recording_verifier(tmp_path: Path) -> tuple[Path, Path]:
    """A verifier stub that records its argv and refuses: the script stops at the first verify."""
    log = tmp_path / "verifier-argv.jsonl"
    stub = tmp_path / "trust" / "verify_bundle.py"
    stub.parent.mkdir(parents=True, exist_ok=True)
    stub.write_text(
        "import json, sys\n"
        f"open({str(log)!r}, 'a').write(json.dumps(sys.argv[1:]) + '\\n')\n"
        "print('FAIL: stub verifier')\n"
        "sys.exit(1)\n",
        encoding="utf-8",
    )
    return stub, log


def _recorded(log: Path) -> list[list[str]]:
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]


@pytest.mark.parametrize("script", [INSTALL, UPGRADE], ids=["install_offline", "upgrade_offline"])
def test_f55_install_scripts_pass_the_installed_manifest_and_honour_the_override(
    tmp_path: Path, script: Path
) -> None:
    bundle = tmp_path / "bundle"
    (bundle / "requirements").mkdir(parents=True)
    target = tmp_path / "target"
    extra = [str(tmp_path / "backups")] if script == UPGRADE else []
    stub, log = _argv_recording_verifier(tmp_path)
    manifest_arg = ["--installed-manifest", str(target / "manifest.json")]

    _run_installer(tmp_path, script, [str(bundle), str(target), *extra], stub)
    plain = _recorded(log)[-1]
    assert plain[:4] == ["--bundle", str(bundle), "--pubkey", str(tmp_path / "release.pub.pem")]
    assert plain[4:] == manifest_arg

    _run_installer(tmp_path, script, [str(bundle), str(target), *extra], stub, UDBMCP_ALLOW_DOWNGRADE="1")
    assert _recorded(log)[-1][4:] == [*manifest_arg, "--allow-downgrade"]

    for args in (
        [str(bundle), str(target), *extra, "--allow-downgrade"],
        ["--allow-downgrade", str(bundle), str(target), *extra],
    ):
        _run_installer(tmp_path, script, args, stub)
        assert _recorded(log)[-1][4:] == [*manifest_arg, "--allow-downgrade"], args

    _run_installer(tmp_path, script, [str(bundle), str(target), *extra], stub, UDBMCP_ALLOW_DOWNGRADE="yes")
    assert _recorded(log)[-1][4:] == manifest_arg  # only the documented value 1 switches it on


def _postinst_sandbox(tmp_path: Path) -> Path:
    """postinst with every absolute path constant rewritten into tmp_path."""
    lines = []
    for line in POSTINST.read_text(encoding="utf-8").splitlines():
        match = re.match(r"^([A-Z_]+)=/.+$", line)
        if match:
            line = f"{match.group(1)}={tmp_path / match.group(1).lower()}"
        lines.append(line)
    script = tmp_path / "postinst_sbx.sh"
    script.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return script


def _postinst_trust_dir(tmp_path: Path, verifier_body: str) -> None:
    trust = tmp_path / "trust_dir"
    (trust / "lib").mkdir(parents=True)
    (trust / "verify_bundle.py").write_text(verifier_body, encoding="utf-8")
    (trust / "profiles.py").write_text("# admin profiles\n", encoding="utf-8")
    (trust / "install_offline.sh").write_text("# admin installer\n", encoding="utf-8")
    (trust / "lib" / "os_packages.sh").write_text("# admin lib\n", encoding="utf-8")
    (tmp_path / "pubkey").write_text("-----BEGIN PUBLIC KEY-----\nsbx\n-----END PUBLIC KEY-----\n", encoding="utf-8")
    (tmp_path / "bundle").mkdir()


def test_f55_postinst_verifies_against_the_installed_manifest(tmp_path: Path) -> None:
    log = tmp_path / "argv.jsonl"
    _postinst_trust_dir(
        tmp_path,
        "import json, sys\n"
        f"open({str(log)!r}, 'a').write(json.dumps(sys.argv[1:]) + '\\n')\n"
        "sys.exit(1)\n",
    )
    env = {**os.environ, "PATH": f"{_shims(tmp_path)}:{os.environ.get('PATH', '')}", "TMPDIR": str(tmp_path)}
    env.pop("UDBMCP_ALLOW_DOWNGRADE", None)
    script = _postinst_sandbox(tmp_path)
    proc = subprocess.run(["/bin/bash", str(script)], env=env, capture_output=True, text=True, timeout=60, check=False)  # noqa: S603
    assert proc.returncode != 0, proc.stdout
    manifest_arg = ["--installed-manifest", str(tmp_path / "target" / "manifest.json")]
    assert _recorded(log)[-1][4:] == manifest_arg
    env["UDBMCP_ALLOW_DOWNGRADE"] = "1"
    subprocess.run(["/bin/bash", str(script)], env=env, capture_output=True, text=True, timeout=60, check=False)  # noqa: S603
    assert _recorded(log)[-1][4:] == [*manifest_arg, "--allow-downgrade"]


def test_f55_postinst_refuses_a_trusted_verifier_that_predates_the_rollback_check(tmp_path: Path) -> None:
    _postinst_trust_dir(tmp_path, 'ap.add_argument("--pubkey", default=None)\nprint("bundle verification PASSED")\n')
    env = {**os.environ, "PATH": f"{_shims(tmp_path)}:{os.environ.get('PATH', '')}", "TMPDIR": str(tmp_path)}
    proc = subprocess.run(  # noqa: S603
        ["/bin/bash", str(_postinst_sandbox(tmp_path))],
        env=env, capture_output=True, text=True, timeout=60, check=False,
    )
    assert proc.returncode != 0
    assert "OUTDATED" in proc.stderr and "--installed-manifest" in proc.stderr and "bootstrap.sh" in proc.stderr


# An older verifier the text check above misses (it names the option in a comment only): its
# argparse stops on the option, which is the same outdated copy, not a tampered payload.
_OUTDATED_VERIFIER_NAMING_THE_OPTION = (
    "import argparse\n"
    '# "--installed-manifest" arrives in the next release\n'
    "ap = argparse.ArgumentParser()\n"
    'ap.add_argument("--bundle", required=True)\n'
    'ap.add_argument("--pubkey")\n'
    "ap.parse_args()\n"
    "print('bundle verification PASSED')\n"
)


def test_f55_postinst_names_an_outdated_verifier_its_argparse_gives_away(tmp_path: Path) -> None:
    _postinst_trust_dir(tmp_path, _OUTDATED_VERIFIER_NAMING_THE_OPTION)
    env = {**os.environ, "PATH": f"{_shims(tmp_path)}:{os.environ.get('PATH', '')}", "TMPDIR": str(tmp_path)}
    proc = subprocess.run(  # noqa: S603
        ["/bin/bash", str(_postinst_sandbox(tmp_path))],
        env=env, capture_output=True, text=True, timeout=60, check=False,
    )
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "unrecognized arguments: --installed-manifest" in proc.stdout, proc.stdout  # forwarded verbatim
    assert "is an OUTDATED copy" in proc.stderr and "bootstrap.sh" in proc.stderr, proc.stderr
    assert "the unpacked payload is UNTRUSTED" not in proc.stderr, proc.stderr


def test_f55_rollback_names_the_explicit_switch_for_reinstalling_the_older_bundle(tmp_path: Path) -> None:
    """rollback_offline.sh restores the previous venv but leaves the newer release's manifest
    installed, so reinstalling the older bundle afterwards is a downgrade the operator must name."""
    target = tmp_path / "target"
    venv_bin = target / "venv.previous" / "bin"
    venv_bin.mkdir(parents=True)
    (venv_bin / "python").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    (venv_bin / "python").chmod(0o755)
    (target / "venv.previous.sha256").write_text(
        f"{_sha256(venv_bin / 'python')}  ./bin/python\n", encoding="utf-8"
    )
    env = {k: v for k, v in os.environ.items() if not k.startswith("UDBMCP_")}
    env["UDBMCP_CONFIG_DIR"] = str(tmp_path / "etc")
    env["UDBMCP_STATE_DIR"] = str(tmp_path / "varlib")
    proc = subprocess.run(  # noqa: S603 - repo script under test
        ["/bin/bash", str(REPO / "scripts" / "rollback_offline.sh"), str(target), str(tmp_path / "backups")],
        env=env, capture_output=True, text=True, timeout=120, check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "rollback complete" in proc.stdout
    assert "--allow-downgrade" in proc.stdout and "UDBMCP_ALLOW_DOWNGRADE=1" in proc.stdout


def test_f55_builder_records_release_seq_from_the_source_commit(monkeypatch: pytest.MonkeyPatch) -> None:
    if str(REPO) not in sys.path:
        sys.path.insert(0, str(REPO))
    from scripts import prepare_offline_bundle as builder
    head = subprocess.run(  # noqa: S603
        ["git", "-C", str(REPO), "rev-parse", "HEAD"], capture_output=True, text=True, check=False  # noqa: S607
    ).stdout.strip()
    if not head:
        pytest.skip("not a git checkout")
    commit_time = subprocess.run(  # noqa: S603
        ["git", "-C", str(REPO), "show", "-s", "--format=%ct", head],  # noqa: S607
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    assert builder.resolve_release_seq(None, head) == int(commit_time)
    assert builder.resolve_release_seq(42, head) == 42
    assert builder.resolve_release_seq(None, "unknown") is None
    parser = builder.build_arg_parser()
    assert parser.parse_args(["--out", "o", "--release-seq", "7"]).release_seq == 7
    with pytest.raises(SystemExit):
        parser.parse_args(["--out", "o", "--release-seq", "-1"])
    monkeypatch.setenv("UDBMCP_RELEASE_SEQ", "11")
    assert builder.build_arg_parser().parse_args(["--out", "o"]).release_seq == 11
    assert '"release_seq": release_seq' in BUILDER.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("manifest", "reused"),
    [
        ({"source_rev": "abc1234"}, False),  # built before release_seq: rebuild it
        ({"source_rev": "abc1234", "release_seq": None}, False),
        ({"source_rev": "abc1234", "release_seq": 1790000000}, True),
    ],
)
def test_f55_release_usb_never_reuses_a_bundle_without_release_seq(
    tmp_path: Path, manifest: dict[str, Any], reused: bool
) -> None:
    text = RELEASE_USB.read_text(encoding="utf-8")
    bundle_rev = next(line for line in text.splitlines() if line.startswith("bundle_rev()"))
    out = tmp_path / "out" / "bundle"
    (out / "universal-db-mcp-0.1.0").mkdir(parents=True)
    (out / "universal-db-mcp-0.1.0" / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    proc = subprocess.run(  # noqa: S603 - the release script's own reuse check
        ["/bin/bash", "-c", f'PY="{sys.executable}"\n{bundle_rev}\nbundle_rev "$1"', "bundle_rev", str(out)],
        capture_output=True, text=True, timeout=60, check=True,
    )
    assert proc.stdout.strip() == ("abc1234" if reused else "")


def test_f55_upgrade_gate_uses_only_ephemeral_keys_and_bumps_release_seq() -> None:
    text = UPGRADE_GATE.read_text(encoding="utf-8")
    assert "demo-keys" not in text and "udbmcp-release-demo" not in text
    assert "UDBMCP_RELEASE_KEY" not in text.split("set -euo pipefail", 1)[1]
    assert "Ed25519PrivateKey.generate()" in text
    assert 'manifest["release_seq"]' in text
    assert "production anchor" in text
    assert "rollback refused" in text  # the container gate exercises the refusal
    subprocess.run(["bash", "-n", str(UPGRADE_GATE)], check=True)  # noqa: S603, S607


# ---- F54: the image loader is a trusted tool that loads only a verified copy --

APP_TAR = "universal-db-mcp.tar"
BASELINE_TAR = "udbmcp-baseline-ubuntu24.04-cp312.tar"


def _image_bundle(
    tmp_path: Path, name: str = "bundle", signer: tuple[Ed25519PrivateKey, Path] | None = None, **manifest: Any
) -> tuple[Path, Path]:
    """A signed bundle with both image tars, the in-bundle reference copies and a key inside it.

    *signer* (key, public key PEM) signs it, else a new release key; *manifest* adds manifest fields."""
    if signer is None:
        key, _, pub = _keypair(tmp_path)
    else:
        key, pub = signer
    root = tmp_path / name
    (root / "images").mkdir(parents=True)
    (root / "images" / BASELINE_TAR).write_bytes(b"GOOD-BASELINE-TAR" * 64)
    (root / "images" / APP_TAR).write_bytes(b"GOOD-APP-IMAGE-TAR" * 64)
    (root / "operations").mkdir()
    shutil.copy2(LOADER, root / "operations" / "load_images_offline.sh")
    (root / "installers").mkdir()
    for name in ("verify_bundle.py", "profiles.py"):
        shutil.copy2(REPO / "scripts" / name, root / "installers" / name)
    shutil.copy2(pub, root / "release.pub.pem")
    _bundle(root, key, image_identity={"application_image": "udbmcp/universal-db-mcp:test"}, **manifest)
    return root, pub


def _release_record(tmp_path: Path) -> Path:
    """The container host's release record (/var/lib/universal-db-mcp/release.json) in _loader_env."""
    return tmp_path / "var-lib" / "universal-db-mcp" / "release.json"


def _loader_env(tmp_path: Path, pub: Path, **extra: str) -> dict[str, str]:
    """sudo/python3 shims, a mock docker that logs the sha256 of every tar it loads, a trust dir, and a
    find that counts this test account's files as root's (the loader writes its release record as root).
    SUDO_SWAP_FROM is copied over SUDO_SWAP_TO (recursively: a file, or a whole bundle as <dir>/.) when
    the loader takes its private copy."""
    shims = _shims(tmp_path)
    if not (shims / "find").exists():
        (shims / "find").symlink_to(_find_as_root(tmp_path))
    (shims / "sudo").write_text(
        '#!/bin/sh\n'
        'if [ "$1" = cp ] && [ -n "${SUDO_SWAP_FROM:-}" ]; then cp -R "$SUDO_SWAP_FROM" "$SUDO_SWAP_TO"; fi\n'
        'exec "$@"\n',
        encoding="utf-8",
    )
    (shims / "docker").write_text(
        "#!/bin/sh\n"
        'if [ "$1" = load ] && [ "$2" = -i ]; then\n'
        '  if [ -n "${MOCK_DOCKER_FAIL:-}" ]; then echo "docker: load failed" >&2; exit 1; fi\n'
        f'  "{sys.executable}" -c \'import hashlib, os, sys; '
        'print(os.path.basename(sys.argv[1]), hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())\' '
        '"$3" >> "$MOCK_DOCKER_LOG"\n'
        '  if [ -n "${MOCK_SWAP_FROM:-}" ]; then cp "$MOCK_SWAP_FROM" "$MOCK_SWAP_TO"; fi\n'
        '  echo "Loaded image: mock"\n'
        "  exit 0\n"
        "fi\n"
        'if [ "$1" = image ] && [ "$2" = inspect ]; then exit 0; fi\n'
        "exit 2\n",
        encoding="utf-8",
    )
    (shims / "docker").chmod(0o755)
    trust = tmp_path / "trust"
    trust.mkdir(exist_ok=True)
    for name in ("verify_bundle.py", "profiles.py"):
        shutil.copy2(REPO / "scripts" / name, trust / name)
    env = {k: v for k, v in os.environ.items() if not k.startswith("UDBMCP_")}
    env.update(
        PATH=f"{shims}:/usr/bin:/bin:/usr/sbin:/sbin",
        UDBMCP_TRUST_DIR=str(trust),
        UDBMCP_RELEASE_PUBKEY=str(pub),
        UDBMCP_STAGING_DIR=str(tmp_path / "staging"),
        UDBMCP_RELEASE_RECORD=str(_release_record(tmp_path)),
        MOCK_DOCKER_LOG=str(tmp_path / "docker.log"),
        TMPDIR=str(tmp_path),
    )
    env.update(extra)
    return env


def _run_loader(loader: Path, bundle: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - repo script under test
        ["/bin/bash", str(loader), str(bundle)], env=env, capture_output=True, text=True, timeout=120, check=False
    )


def _loaded(tmp_path: Path) -> dict[str, str]:
    log = tmp_path / "docker.log"
    if not log.exists():
        return {}
    return dict(line.split() for line in log.read_text(encoding="utf-8").splitlines())


def test_f54_a_tar_swapped_on_the_bundle_while_images_load_is_never_the_one_loaded(tmp_path: Path) -> None:
    bundle, pub = _image_bundle(tmp_path)
    signed = _sha256(bundle / "images" / APP_TAR)
    evil = tmp_path / "evil.tar"
    evil.write_bytes(b"EVIL-APP-IMAGE-TAR" * 64)
    # the attacker swaps the verified app tar on the bundle path once the baseline load starts
    env = _loader_env(tmp_path, pub, MOCK_SWAP_FROM=str(evil), MOCK_SWAP_TO=str(bundle / "images" / APP_TAR))
    proc = _run_loader(LOADER, bundle, env)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert _sha256(bundle / "images" / APP_TAR) == _sha256(evil)  # the swap did happen
    loaded = _loaded(tmp_path)
    assert loaded[APP_TAR] == signed, "the loader loaded a tar that is not the signed one"
    assert loaded[BASELINE_TAR] == _sha256(evil.parent / "bundle" / "images" / BASELINE_TAR)
    assert list((tmp_path / "staging").iterdir()) == []  # the private copy is removed on exit


@pytest.mark.skipif(os.getuid() == 0, reason="the swap rides on the sudo the loader runs only for a non-root caller")
def test_f54_a_swap_before_the_private_copy_is_caught_by_verifying_the_copy(tmp_path: Path) -> None:
    bundle, pub = _image_bundle(tmp_path)
    evil = tmp_path / "evil.tar"
    evil.write_bytes(b"EVIL-APP-IMAGE-TAR" * 64)
    # the attacker swaps right after the first verification, before the copy is taken
    env = _loader_env(tmp_path, pub, SUDO_SWAP_FROM=str(evil), SUDO_SWAP_TO=str(bundle / "images" / APP_TAR))
    proc = _run_loader(LOADER, bundle, env)
    assert proc.returncode != 0, proc.stdout
    assert f"tampered artifact: images/{APP_TAR}" in proc.stdout
    assert _loaded(tmp_path) == {}, "nothing may be loaded from a copy that failed verification"
    assert list((tmp_path / "staging").iterdir()) == []


@pytest.mark.parametrize("inside", ["loader", "verifier", "pubkey"])
def test_f54_the_loader_refuses_trust_material_from_inside_the_bundle(tmp_path: Path, inside: str) -> None:
    bundle, pub = _image_bundle(tmp_path)
    env = _loader_env(tmp_path, pub)
    loader = LOADER
    if inside == "loader":
        loader = bundle / "operations" / "load_images_offline.sh"
    elif inside == "verifier":
        env["UDBMCP_TRUST_DIR"] = str(bundle / "installers")
    else:
        env["UDBMCP_RELEASE_PUBKEY"] = str(bundle / "release.pub.pem")
    proc = _run_loader(loader, bundle, env)
    assert proc.returncode != 0, proc.stdout
    assert "inside the bundle" in proc.stderr
    assert "bundle verification PASSED" not in proc.stdout
    assert _loaded(tmp_path) == {}


def test_f54_after_verifying_the_copy_the_loader_reads_only_the_staging_directory() -> None:
    code = "\n".join(
        line for line in LOADER.read_text(encoding="utf-8").splitlines() if not line.lstrip().startswith("#")
    )
    first_verify = code.index('verify_with_proof "$BUNDLE"')
    copy_verify = code.index('verify_with_proof "$STAGING"')
    first_load = code.index("docker load")
    assert first_verify < copy_verify
    staged = code[first_verify:copy_verify]
    assert 'mktemp -d "$STAGING_BASE/udbmcp-images.XXXXXX"' in staged
    assert 'STAGING="$(private_copy "$BUNDLE" "$STAGING_DIR" "No image was loaded.")" || exit 1' in staged
    after = code[copy_verify:]
    assert '"$BUNDLE' not in after, "the bundle path must not be read after its private copy is verified"
    loads = re.findall(r'^\s*load_one\s+"([^"]+)"', after, flags=re.MULTILINE)
    assert loads and all(arg.startswith("$STAGING/images/") for arg in loads), loads
    assert '"$STAGING/manifest.json"' in after
    assert code.index("load_one()") < first_load  # docker load only inside load_one, fed from $STAGING
    assert "UDBMCP_TRUST_DIR:-/usr/local/lib/udbmcp-trust" in code and "/trusted-tools" not in code


def test_f54_the_bundle_builder_ships_the_loader_as_a_trusted_tool() -> None:
    main = next(
        node for node in ast.parse(BUILDER.read_text(encoding="utf-8")).body
        if isinstance(node, ast.FunctionDef) and node.name == "main"
    )
    trusted_names = next(
        node.value for node in ast.walk(main)
        if isinstance(node, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "trusted_names" for t in node.targets)
    )
    copied = next(
        node.iter for node in ast.walk(main)
        if isinstance(node, ast.For) and isinstance(node.iter, ast.Tuple)
        and "verify_bundle.py" in ast.literal_eval(node.iter)
    )
    assert "load_images_offline.sh" in ast.literal_eval(trusted_names)
    assert "load_images_offline.sh" in ast.literal_eval(copied)


# ---- container hosts: a root-owned release record orders the loaded releases ------
# A container host installs nothing natively, so it has no installed manifest.json for the verifier
# to compare with. load_images_offline.sh keeps /var/lib/universal-db-mcp/release.json instead: the
# manifest of the last bundle whose images it loaded.


def _loader_run(tmp_path: Path, bundle: Path, pub: Path, *args: str, **extra: str) -> subprocess.CompletedProcess[str]:
    (tmp_path / "docker.log").unlink(missing_ok=True)
    return subprocess.run(  # noqa: S603 - repo script under test
        ["/bin/bash", str(LOADER), str(bundle), *args],
        env=_loader_env(tmp_path, pub, **extra),
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def test_container_host_records_every_loaded_release(tmp_path: Path) -> None:
    key, _, pub = _keypair(tmp_path)
    record = _release_record(tmp_path)
    first, _ = _image_bundle(tmp_path, "b5", (key, pub), release_seq=5)
    proc = _loader_run(tmp_path, first, pub)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert f"release order: nothing installed yet ({record} absent)" in proc.stdout, proc.stdout
    assert set(_loaded(tmp_path)) == {APP_TAR, BASELINE_TAR}
    assert record.read_bytes() == (first / "manifest.json").read_bytes()
    assert record.stat().st_mode & 0o777 == 0o644 and record.parent.stat().st_mode & 0o777 == 0o755
    assert f"release record {record}: release_seq 5" in proc.stdout, proc.stdout
    for seq in (5, 6):  # a reload and an upgrade
        bundle, _ = _image_bundle(tmp_path, f"b{seq}-again" if seq == 5 else f"b{seq}", (key, pub), release_seq=seq)
        proc = _loader_run(tmp_path, bundle, pub)
        assert proc.returncode == 0 and "(not a downgrade)" in proc.stdout, proc.stdout + proc.stderr
        assert json.loads(record.read_text(encoding="utf-8"))["release_seq"] == seq
    assert list((tmp_path / "staging").iterdir()) == []


def test_container_host_refuses_an_older_release_before_anything_is_staged_or_loaded(tmp_path: Path) -> None:
    key, _, pub = _keypair(tmp_path)
    record = _release_record(tmp_path)
    newer, _ = _image_bundle(tmp_path, "b5", (key, pub), release_seq=5)
    assert _loader_run(tmp_path, newer, pub).returncode == 0
    before = record.read_bytes()
    older, _ = _image_bundle(tmp_path, "b4", (key, pub), release_seq=4)
    proc = _loader_run(tmp_path, older, pub)
    assert proc.returncode != 0, proc.stdout
    assert "FAIL: rollback refused" in proc.stdout and "bundle verification PASSED" not in proc.stdout, proc.stdout
    assert f"OLDER release than the one whose images this host last loaded (release record {record})" in proc.stderr
    assert "--allow-downgrade" in proc.stderr and "UDBMCP_ALLOW_DOWNGRADE=1" in proc.stderr, proc.stderr
    assert _loaded(tmp_path) == {}
    assert list((tmp_path / "staging").iterdir()) == []
    assert record.read_bytes() == before


@pytest.mark.parametrize("how", ["argument", "environment"])
def test_container_host_loads_an_older_release_only_when_asked(tmp_path: Path, how: str) -> None:
    key, _, pub = _keypair(tmp_path)
    record = _release_record(tmp_path)
    newer, _ = _image_bundle(tmp_path, "b5", (key, pub), release_seq=5)
    assert _loader_run(tmp_path, newer, pub).returncode == 0
    older, _ = _image_bundle(tmp_path, "b4", (key, pub), release_seq=4)
    if how == "argument":
        proc = _loader_run(tmp_path, older, pub, "--allow-downgrade")
    else:
        proc = _loader_run(tmp_path, older, pub, UDBMCP_ALLOW_DOWNGRADE="1")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "WARNING: DOWNGRADE allowed by --allow-downgrade" in proc.stdout, proc.stdout
    assert set(_loaded(tmp_path)) == {APP_TAR, BASELINE_TAR}
    assert json.loads(record.read_text(encoding="utf-8"))["release_seq"] == 4


def test_container_host_keeps_its_record_when_a_load_fails(tmp_path: Path) -> None:
    key, _, pub = _keypair(tmp_path)
    record = _release_record(tmp_path)
    first, _ = _image_bundle(tmp_path, "b5", (key, pub), release_seq=5)
    assert _loader_run(tmp_path, first, pub).returncode == 0
    before = record.read_bytes()
    broken, _ = _image_bundle(tmp_path, "b6", (key, pub), release_seq=6)
    proc = _loader_run(tmp_path, broken, pub, MOCK_DOCKER_FAIL="1")
    assert proc.returncode != 0 and "docker: load failed" in proc.stderr, proc.stdout + proc.stderr
    assert record.read_bytes() == before


def test_container_host_names_a_trusted_verifier_that_predates_the_rollback_check(tmp_path: Path) -> None:
    bundle, pub = _image_bundle(tmp_path, release_seq=5)
    env = _loader_env(tmp_path, pub)
    # an earlier release's verifier: its argparse knows no --installed-manifest
    (tmp_path / "trust" / "verify_bundle.py").write_text(
        "import argparse\nap = argparse.ArgumentParser()\nap.add_argument('--bundle')\nap.add_argument('--pubkey')\n"
        "ap.parse_args()\nprint('bundle verification PASSED')\n",
        encoding="utf-8",
    )
    proc = _run_loader(LOADER, bundle, env)
    assert proc.returncode != 0, proc.stdout
    assert f"FAIL: the trusted verifier at {tmp_path / 'trust' / 'verify_bundle.py'} is an OUTDATED copy" in proc.stderr
    assert _loaded(tmp_path) == {} and not _release_record(tmp_path).exists()


def _record_not_root_only(case: str) -> Any:
    """Arrange the release record (or its directory) so that an account other than root could change it."""

    def arrange(tmp_path: Path, record: Path) -> None:
        record.parent.mkdir(parents=True)
        for directory in (record.parent.parent, record.parent):  # root's alone but for the case
            directory.chmod(0o755)
        record.write_text(json.dumps({"profile": "test-profile", "release_seq": 5}), encoding="utf-8")
        record.chmod(0o644)
        if case == "dir-group-writable":
            record.parent.chmod(0o775)
        elif case == "dir-world-writable":
            record.parent.chmod(0o1777)
        elif case == "dir-not-root":
            (tmp_path / "shims" / "find").unlink()
            (tmp_path / "shims" / "find").symlink_to(_find_as_root_except(tmp_path, record.parent))
        elif case == "record-not-root":
            (tmp_path / "shims" / "find").unlink()
            (tmp_path / "shims" / "find").symlink_to(_find_as_root_except(tmp_path, record))
        elif case == "record-world-writable":
            record.chmod(0o666)
        elif case == "record-symlink":
            elsewhere = tmp_path / "elsewhere.json"
            record.rename(elsewhere)
            record.symlink_to(elsewhere)
        else:  # the record's directory is a link another account could re-point
            real = tmp_path / "real-dir"
            record.parent.rename(real)
            record.parent.symlink_to(real)
        link = record if case == "record-symlink" else record.parent
        if link.is_symlink() and hasattr(os, "lchmod"):
            # a macOS link has modes of its own (umask 002 makes it group-writable); a Linux one is
            # always 0777, so its write bits alone refuse it
            os.lchmod(link, 0o755)

    return arrange


@pytest.mark.skipif(os.getuid() == 0, reason="needs files a non-root account owns")
@pytest.mark.parametrize(
    "case",
    ["dir-group-writable", "dir-world-writable", "dir-not-root", "record-not-root", "record-world-writable",
     "record-symlink", "dir-symlink"],
)
def test_container_host_trusts_a_release_record_only_root_can_change(tmp_path: Path, case: str) -> None:
    """Whoever can lower or delete the record can load an older release's images without a word."""
    key, _, pub = _keypair(tmp_path)
    record = _release_record(tmp_path)
    _loader_env(tmp_path, pub)  # the shims, find among them
    _record_not_root_only(case)(tmp_path, record)
    bundle, _ = _image_bundle(tmp_path, "b6", (key, pub), release_seq=6)
    before = _snapshot(tmp_path / "var-lib")
    proc = _loader_run(tmp_path, bundle, pub)
    assert proc.returncode != 0, proc.stdout
    assert "FAIL: the release record" in proc.stderr and "root alone" in proc.stderr, proc.stderr
    untrusted = record if case.startswith("record-") else record.parent
    assert f"\n      {untrusted} is not root's alone" in proc.stderr, proc.stderr
    assert "bundle verification PASSED" not in proc.stdout, proc.stdout
    assert _loaded(tmp_path) == {}
    assert _snapshot(tmp_path / "var-lib") == before


@pytest.mark.skipif(os.getuid() == 0, reason="needs files a non-root account owns")
@pytest.mark.parametrize(
    "case", ["parent-world-writable", "parent-group-writable", "parent-not-root", "higher-world-writable",
             "parent-symlink"],
)
def test_container_host_trusts_a_release_record_only_below_directories_root_alone_can_write(
    tmp_path: Path, case: str
) -> None:
    """A rename needs write on the parent only: whoever can write a directory above the record's could
    move the record's directory away, and the next load of an older release would read as a first load.
    UDBMCP_RELEASE_RECORD can name a record anywhere, so every directory above it counts."""
    key, _, pub = _keypair(tmp_path)
    _loader_env(tmp_path, pub)
    home = tmp_path / "admin-home"
    record = home / "sites" / "records" / "release.json"
    record.parent.mkdir(parents=True)
    for directory in (home, home / "sites", record.parent):
        directory.chmod(0o755)
    record.write_text(json.dumps({"profile": "test-profile", "release_seq": 5}), encoding="utf-8")
    record.chmod(0o644)
    untrusted = home / "sites"
    if case == "parent-world-writable":
        untrusted.chmod(0o777)
    elif case == "parent-group-writable":
        untrusted.chmod(0o775)
    elif case == "parent-not-root":
        (tmp_path / "shims" / "find").unlink()
        (tmp_path / "shims" / "find").symlink_to(_find_as_root_except(tmp_path, untrusted))
    elif case == "higher-world-writable":
        untrusted = home
        home.chmod(0o777)
    else:  # a link on the way, which whoever can write where it leads (or its directory) re-points
        real = tmp_path / "real-sites"
        untrusted.rename(real)
        untrusted.symlink_to(real)
        if hasattr(os, "lchmod"):
            os.lchmod(untrusted, 0o755)  # refused for being a link, not for a macOS link's mode
    bundle, _ = _image_bundle(tmp_path, "b6", (key, pub), release_seq=6)
    before = _snapshot(tmp_path)
    proc = _loader_run(tmp_path, bundle, pub, UDBMCP_RELEASE_RECORD=str(record))
    assert proc.returncode != 0, proc.stdout
    assert f"FAIL: the release record {record} orders the releases this host loads" in proc.stderr, proc.stderr
    assert f"\n      {untrusted} is not root's alone" in proc.stderr, proc.stderr
    assert "every directory above it" in proc.stderr, proc.stderr
    assert "bundle verification PASSED" not in proc.stdout, proc.stdout
    assert _loaded(tmp_path) == {}
    assert _snapshot(tmp_path) == before


@pytest.mark.skipif(os.getuid() == 0, reason="the directories a non-root account creates stand in for root's")
def test_container_host_keeps_its_record_below_a_sticky_directory_and_creates_it_root_only(tmp_path: Path) -> None:
    """In a sticky directory (/tmp) nobody else can rename what root owns, so a record below one
    orders the releases like any other; and the directories the loader creates for it are root's
    alone whatever the caller's umask (these tests run under 002)."""
    key, _, pub = _keypair(tmp_path)
    shared = tmp_path / "shared-tmp"
    shared.mkdir()
    shared.chmod(0o1777)
    record = shared / "udbmcp" / "records" / "release.json"
    newer, _ = _image_bundle(tmp_path, "b5", (key, pub), release_seq=5)
    proc = _loader_run(tmp_path, newer, pub, UDBMCP_RELEASE_RECORD=str(record))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert record.read_bytes() == (newer / "manifest.json").read_bytes()
    for directory in (shared / "udbmcp", record.parent):
        assert directory.stat().st_mode & 0o777 == 0o755, directory
    older, _ = _image_bundle(tmp_path, "b4", (key, pub), release_seq=4)
    proc = _loader_run(tmp_path, older, pub, UDBMCP_RELEASE_RECORD=str(record))
    assert proc.returncode != 0, proc.stdout
    assert "FAIL: rollback refused" in proc.stdout, proc.stdout + proc.stderr
    assert _loaded(tmp_path) == {}


def test_container_host_leaves_the_mode_of_an_existing_record_directory_alone(tmp_path: Path) -> None:
    """The record may live in a directory root keeps to itself (/root, or a /var/lib/universal-db-mcp
    tightened to 0700): writing it there never opens that directory to every account."""
    key, _, pub = _keypair(tmp_path)
    home = tmp_path / "root-home"
    home.mkdir()
    home.chmod(0o700)
    record = home / "release.json"
    for seq in (5, 6):  # the first load creates the record, the next one replaces it
        bundle, _ = _image_bundle(tmp_path, f"b{seq}", (key, pub), release_seq=seq)
        proc = _loader_run(tmp_path, bundle, pub, UDBMCP_RELEASE_RECORD=str(record))
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert json.loads(record.read_text(encoding="utf-8"))["release_seq"] == seq
        assert home.stat().st_mode & 0o777 == 0o700, oct(home.stat().st_mode)


@pytest.mark.parametrize("value", ["0", "yes", "true"])
def test_container_host_takes_only_the_documented_value_as_consent_to_a_downgrade(
    tmp_path: Path, value: str
) -> None:
    """UDBMCP_ALLOW_DOWNGRADE=1 is the documented override, as for the install scripts and the .deb:
    a 0 left in the environment (or any other value) is not a request to load an older release."""
    key, _, pub = _keypair(tmp_path)
    record = _release_record(tmp_path)
    newer, _ = _image_bundle(tmp_path, "b5", (key, pub), release_seq=5)
    assert _loader_run(tmp_path, newer, pub).returncode == 0
    before = record.read_bytes()
    older, _ = _image_bundle(tmp_path, "b4", (key, pub), release_seq=4)
    proc = _loader_run(tmp_path, older, pub, UDBMCP_ALLOW_DOWNGRADE=value)
    assert proc.returncode != 0, proc.stdout
    assert "FAIL: rollback refused" in proc.stdout and "DOWNGRADE allowed" not in proc.stdout, proc.stdout
    assert _loaded(tmp_path) == {}
    assert record.read_bytes() == before


def _find_owned_by_udbmcp(tmp_path: Path, directory: Path) -> Path:
    """find(1) that sees *directory* as the udbmcp service account's (this test account stands in for
    it), not root's; every other file of this account counts as root's (_find_as_root)."""
    real = _find_as_root_except(tmp_path, directory)
    shim = tmp_path / "find-udbmcp"
    shim.write_text(
        "#!/bin/bash\n"
        "args=()\n"
        "while [ $# -gt 0 ]; do\n"
        '  if [ "$1" = -user ] && [ "${2:-}" = udbmcp ]; then\n'
        f"    args+=(-user {os.getuid()}); shift 2\n"
        "  else\n"
        '    args+=("$1"); shift\n'
        "  fi\n"
        "done\n"
        f'exec "{real}" "${{args[@]}}"\n',
        encoding="utf-8",
    )
    shim.chmod(0o755)
    return shim


@pytest.mark.skipif(os.getuid() == 0, reason="needs files a non-root account owns")
def test_container_host_never_advises_taking_the_service_accounts_state_directory(tmp_path: Path) -> None:
    """On a host that also runs the native package, /var/lib/universal-db-mcp is the udbmcp account's
    state directory (install_offline.sh creates it so, and hands it back on every install): chowning
    it to root would take it from the service, so the loader names a record path of its own."""
    key, _, pub = _keypair(tmp_path)
    record = _release_record(tmp_path)
    _loader_env(tmp_path, pub)  # the shims, find among them
    record.parent.mkdir(parents=True)
    for directory in (record.parent.parent, record.parent):
        directory.chmod(0o755)
    (tmp_path / "shims" / "find").unlink()
    (tmp_path / "shims" / "find").symlink_to(_find_owned_by_udbmcp(tmp_path, record.parent))
    bundle, _ = _image_bundle(tmp_path, "b5", (key, pub), release_seq=5)
    proc = _loader_run(tmp_path, bundle, pub)
    assert proc.returncode != 0, proc.stdout
    assert f"\n      {record.parent} is not root's alone" in proc.stderr, proc.stderr
    assert "belongs to the udbmcp service account" in proc.stderr, proc.stderr
    assert "UDBMCP_RELEASE_RECORD=/var/lib/udbmcp-images/release.json" in proc.stderr, proc.stderr
    assert "chown" not in proc.stderr and "No image was loaded." in proc.stderr, proc.stderr
    assert _loaded(tmp_path) == {} and not record.exists()


@pytest.mark.skipif(os.getuid() == 0, reason="needs files a non-root account owns")
def test_container_host_advises_making_any_other_record_directory_root_only(tmp_path: Path) -> None:
    key, _, pub = _keypair(tmp_path)
    record = _release_record(tmp_path)
    _loader_env(tmp_path, pub)
    _record_not_root_only("dir-not-root")(tmp_path, record)
    bundle, _ = _image_bundle(tmp_path, "b6", (key, pub), release_seq=6)
    proc = _loader_run(tmp_path, bundle, pub)
    assert proc.returncode != 0, proc.stdout
    assert f"sudo chown root {record.parent}; sudo chmod go-w {record.parent}" in proc.stderr, proc.stderr
    assert "udbmcp service account" not in proc.stderr, proc.stderr


def test_container_host_takes_only_an_absolute_release_record_path(tmp_path: Path) -> None:
    """A relative record would be wherever the loader happens to run, and the directories above it
    could not be checked."""
    key, _, pub = _keypair(tmp_path)
    bundle, _ = _image_bundle(tmp_path, "b5", (key, pub), release_seq=5)
    work = tmp_path / "cwd"
    work.mkdir()
    proc = subprocess.run(  # noqa: S603 - repo script under test
        ["/bin/bash", str(LOADER), str(bundle)],
        env=_loader_env(tmp_path, pub, UDBMCP_RELEASE_RECORD="records/release.json"),
        capture_output=True, text=True, timeout=120, check=False, cwd=work,
    )
    assert proc.returncode != 0, proc.stdout
    assert "FAIL: UDBMCP_RELEASE_RECORD (records/release.json) must be an absolute path" in proc.stderr, proc.stderr
    assert "bundle verification PASSED" not in proc.stdout, proc.stdout
    assert _loaded(tmp_path) == {} and list(work.iterdir()) == []


def test_container_host_names_a_release_without_a_release_seq(tmp_path: Path) -> None:
    key, _, pub = _keypair(tmp_path)
    bundle, _ = _image_bundle(tmp_path, "b0", (key, pub), release_seq=None)
    proc = _loader_run(tmp_path, bundle, pub)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "release_seq none (the bundle predates release_seq)" in proc.stdout, proc.stdout
    assert "release_seq None" not in proc.stdout, proc.stdout


@pytest.mark.skipif(os.getuid() == 0, reason="the swap rides on the sudo the loader runs only for a non-root caller")
def test_container_host_checks_the_release_order_of_its_private_copy_too(tmp_path: Path) -> None:
    """The bundle path may be writable: once the first check passed, a legitimately signed OLDER
    release is copied over the bundle before the private copy is taken. The check of the copy is
    all that stands between it and the images."""
    key, _, pub = _keypair(tmp_path)
    record = _release_record(tmp_path)
    first, _ = _image_bundle(tmp_path, "b5", (key, pub), release_seq=5)
    assert _loader_run(tmp_path, first, pub).returncode == 0
    before = record.read_bytes()
    bundle, _ = _image_bundle(tmp_path, "b5-again", (key, pub), release_seq=5)
    older, _ = _image_bundle(tmp_path, "b4", (key, pub), release_seq=4)
    proc = _loader_run(tmp_path, bundle, pub, SUDO_SWAP_FROM=f"{older}/.", SUDO_SWAP_TO=str(bundle))
    assert json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))["release_seq"] == 4  # swapped
    assert proc.returncode != 0, proc.stdout
    assert proc.stdout.count("bundle verification PASSED") == 1, proc.stdout  # the bundle's check, not the copy's
    assert "FAIL: rollback refused" in proc.stdout, proc.stdout
    assert "OLDER release than the one whose images this host last loaded" in proc.stderr, proc.stderr
    assert _loaded(tmp_path) == {}
    assert list((tmp_path / "staging").iterdir()) == []
    assert record.read_bytes() == before


# ---- F56: the dependency closure is locked, hash-checked and index-independent


def _builder() -> ModuleType:
    if str(REPO) not in sys.path:
        sys.path.insert(0, str(REPO))
    from scripts import prepare_offline_bundle

    return prepare_offline_bundle


def _profiles() -> dict[str, Any]:
    if str(REPO) not in sys.path:
        sys.path.insert(0, str(REPO))
    from scripts.profiles import PROFILES

    return dict(PROFILES)


LINUX_PROFILE = "linux-x86_64-ubuntu24.04-cp312"
WINDOWS_PROFILE = "windows-x86_64-cp312"


def _wheel(dest: Path, name: str, version: str, extra: dict[str, str] | None = None) -> Path:
    """A minimal, installable py3-none-any wheel."""
    dist = f"{name}-{version}.dist-info"
    files = {f"{name}/__init__.py": f"__version__ = {version!r}\n", **(extra or {})}
    files[f"{dist}/METADATA"] = f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"
    files[f"{dist}/WHEEL"] = "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    record = [
        f"{path},sha256={base64.urlsafe_b64encode(hashlib.sha256(body.encode()).digest()).rstrip(b'=').decode()},"
        f"{len(body.encode())}"
        for path, body in files.items()
    ]
    files[f"{dist}/RECORD"] = "\n".join([*record, f"{dist}/RECORD,,"]) + "\n"
    dest.mkdir(parents=True, exist_ok=True)
    wheel = dest / f"{name}-{version}-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as zf:
        for path, body in files.items():
            zf.writestr(path, body)
    return wheel


def _index(root: Path, wheels: list[Path]) -> Path:
    """A PEP 503 simple index over *wheels*, laid out for http.server."""
    pool = root / "pool"
    pool.mkdir(parents=True)
    projects: dict[str, list[str]] = {}
    for wheel in wheels:
        shutil.copy2(wheel, pool / wheel.name)
        projects.setdefault(wheel.name.split("-")[0].replace("_", "-").lower(), []).append(wheel.name)
    for project, names in projects.items():
        page = root / "simple" / project
        page.mkdir(parents=True)
        links = "".join(f'<a href="../../pool/{n}#sha256={_sha256(pool / n)}">{n}</a>\n' for n in names)
        (page / "index.html").write_text(f"<html><body>{links}</body></html>", encoding="utf-8")
    return root


class _QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - http.server's signature
        pass


@pytest.fixture
def serve_index() -> Iterator[Any]:
    servers: list[http.server.ThreadingHTTPServer] = []

    def serve(root: Path) -> str:
        handler = functools.partial(_QuietHandler, directory=str(root))
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return f"http://127.0.0.1:{server.server_address[1]}/simple"

    yield serve
    for server in servers:
        server.shutdown()
        server.server_close()


def _lock_text(wheels: dict[str, Path], via: dict[str, str]) -> str:
    """A lock in the committed format (uv pip compile --generate-hashes, split annotations)."""
    out = ["# This file was autogenerated by uv via the following command:", "#    test"]
    for name in sorted(wheels):
        version = wheels[name].name.split("-")[1]
        out += [f"{name}=={version} \\", f"    --hash=sha256:{_sha256(wheels[name])}", f"    # via {via[name]}"]
    return "\n".join(out) + "\n"


def test_f56_the_download_is_isolated_hash_checked_and_names_its_index() -> None:
    builder = _builder()
    for name, profile in _profiles().items():
        cmd = builder.pip_download_command(profile, Path("wh"), Path("closure.txt"), "https://pypi.org/simple")
        for flag in ("--isolated", "--require-hashes", "--no-deps", "--only-binary=:all:"):
            assert flag in cmd, (name, flag)
        assert cmd[cmd.index("-r") + 1] == "closure.txt"
        assert cmd[cmd.index("--index-url") + 1] == "https://pypi.org/simple"
        assert "-c" not in cmd  # constraints only bound versions; the lock fixes the whole closure
    assert builder.PYPI_SIMPLE == "https://pypi.org/simple"


def test_f56_pip_and_build_subprocesses_never_inherit_pip_settings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    builder = _builder()
    profile = _profiles()[LINUX_PROFILE]
    monkeypatch.setenv("PIP_INDEX_URL", "http://127.0.0.1:9/evil/simple")
    monkeypatch.setenv("PIP_EXTRA_INDEX_URL", "http://127.0.0.1:9/evil2/simple")
    monkeypatch.setenv("PIP_FIND_LINKS", str(tmp_path))
    monkeypatch.setenv("PIP_CONFIG_FILE", str(tmp_path / "pip.conf"))
    monkeypatch.setenv("UV_INDEX_URL", "http://127.0.0.1:9/evil3/simple")
    calls: list[tuple[list[str], dict[str, str] | None]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append((list(cmd), kwargs.get("env")))
        if "--outdir" in cmd:  # python -m build: leave a wheel behind
            _wheel(Path(cmd[cmd.index("--outdir") + 1]), "universal_db_mcp", "0.1.0")
        return subprocess.CompletedProcess(cmd, 0, "pip 26.2.1 from x\n", "")

    monkeypatch.setattr(builder.subprocess, "run", fake_run)
    app = builder.build_app_wheel(tmp_path / "build", builder.PYPI_SIMPLE)
    assert app.name == "universal_db_mcp-0.1.0-py3-none-any.whl"
    entries = builder.parse_lock(builder.lock_path(profile).read_text(encoding="utf-8"))
    with pytest.raises(SystemExit, match="does not match the lock"):  # nothing arrived
        builder.download_closure(profile, list(entries.values()), tmp_path / "dl", builder.PYPI_SIMPLE)

    install = next(cmd for cmd, _ in calls if "install" in cmd)
    assert {"--isolated", "--require-hashes", "--no-deps"} <= set(install)
    assert install[install.index("-r") + 1] == str(builder.BUILD_LOCK)
    build = next(cmd for cmd, _ in calls if "--outdir" in cmd)
    assert "--no-isolation" in build and build[0] != sys.executable  # the build venv's python, not ours
    assert any("download" in cmd for cmd, _ in calls)
    for cmd, env in calls:
        assert env is not None, cmd
        assert [k for k in env if k.startswith(("PIP_", "UV_")) and k != "PIP_CONFIG_FILE"] == [], cmd
        assert env["PIP_CONFIG_FILE"] == os.devnull, cmd


def test_f56_the_downloaded_wheelhouse_must_be_exactly_the_lock(tmp_path: Path) -> None:
    builder = _builder()
    idna = _wheel(tmp_path / "wh", "idna", "3.20")
    sqlglot = _wheel(tmp_path / "wh", "sqlglot", "30.18.0")
    entries = builder.parse_lock(_lock_text({"idna": idna, "sqlglot": sqlglot}, {"idna": "mcp", "sqlglot": "-r x"}))
    assert set(entries) == {"idna", "sqlglot"} and entries["idna"].via == ("mcp",)
    locked = list(entries.values())
    assert builder.wheelhouse_problems([idna, sqlglot], locked) == []
    newer = _wheel(tmp_path / "other", "idna", "3.99", {"zz_hook.pth": "import os\n"})
    assert any("idna-3.99" in p for p in builder.wheelhouse_problems([newer, sqlglot], locked))
    assert any("sqlglot" in p for p in builder.wheelhouse_problems([idna], locked))
    stray = _wheel(tmp_path / "other", "evil", "1.0")
    assert any("evil-1.0" in p for p in builder.wheelhouse_problems([idna, sqlglot, stray], locked))
    idna.write_bytes(idna.read_bytes() + b"\0")  # same name and version, other bytes
    assert any("sha256" in p for p in builder.wheelhouse_problems([idna, sqlglot], locked))


def _require_pip() -> None:
    """The builder downloads with `sys.executable -m pip`; a venv made by `uv sync` (CI) has no pip."""
    probe = subprocess.run(  # noqa: S603 - this interpreter, fixed argv
        [sys.executable, "-m", "pip", "--version"], capture_output=True, text=True, timeout=60, check=False
    )
    if probe.returncode != 0:
        pytest.skip(f"no pip in {sys.executable} (a `uv sync` venv); the bundle builder runs `python -m pip`")


def test_f56_a_hostile_index_or_pip_setting_cannot_get_a_wheel_into_a_signed_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], serve_index: Any
) -> None:
    _require_pip()
    builder = _builder()
    genuine = {
        "mcp": _wheel(tmp_path / "genuine", "mcp", "2.2.0"),
        "pyyaml": _wheel(tmp_path / "genuine", "pyyaml", "6.0.3"),
        "sqlglot": _wheel(tmp_path / "genuine", "sqlglot", "30.18.0"),
        "idna": _wheel(tmp_path / "genuine", "idna", "3.20"),
    }
    hook = {"zz_idna_hook.pth": "import os; os.environ['UDBMCP_PTH_RAN'] = '1'\n"}
    hostile = [
        genuine["mcp"], genuine["pyyaml"], genuine["sqlglot"],
        _wheel(tmp_path / "hostile", "idna", "3.99", hook),
        _wheel(tmp_path / "hostile", "idna", "3.20", hook),  # the locked version, other bytes
    ]
    good_index = serve_index(_index(tmp_path / "good-index", list(genuine.values())))
    evil_index = serve_index(_index(tmp_path / "evil-index", hostile))
    lock = tmp_path / "lock.txt"
    lock.write_text(
        _lock_text(genuine, {"mcp": "-r runtime.in", "pyyaml": "-r runtime.in", "sqlglot": "-r runtime.in",
                             "idna": "mcp"}),
        encoding="utf-8",
    )
    _, priv, pub = _keypair(tmp_path)

    def fake_build(workdir: Path, index_url: str) -> Path:
        return _wheel(workdir / "dist", "universal_db_mcp", "0.1.0")

    monkeypatch.setattr(builder, "lock_path", lambda profile: lock)
    monkeypatch.setattr(builder, "lock_problems", lambda profile, runtime_in=None, lock=None: [])
    monkeypatch.setattr(builder, "build_app_wheel", fake_build)
    (tmp_path / "pip.conf").write_text(f"[global]\nindex-url = {evil_index}\n", encoding="utf-8")
    monkeypatch.setenv("PIP_CONFIG_FILE", str(tmp_path / "pip.conf"))
    monkeypatch.setenv("PIP_INDEX_URL", evil_index)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))  # pip's http cache stays in tmp_path

    def build(out: Path, index_url: str) -> None:
        monkeypatch.setattr(sys, "argv", [
            "prepare_offline_bundle.py", "--profile", WINDOWS_PROFILE, "--connectors", "core",
            "--out", str(out), "--signing-key", str(priv), "--source-rev", "abc1234", "--release-seq", "1",
            "--index-url", index_url,
        ])
        builder.main()

    with pytest.raises(SystemExit) as refused:
        build(tmp_path / "out-evil", evil_index)
    assert refused.value.code not in (0, None)
    # refused by the hash check, not by a pip that is missing or broken
    assert "pip download failed" in str(refused.value.code), refused.value.code
    assert "DO NOT MATCH THE HASHES" in capsys.readouterr().err
    assert list((tmp_path / "out-evil").rglob("SIGNATURE")) == []
    assert not [w for w in (tmp_path / "out-evil").rglob("*.whl") if "idna" in w.name]

    # the inherited PIP_INDEX_URL and pip.conf still point at the hostile index: they are ignored
    build(tmp_path / "out-good", good_index)
    bundle = next((tmp_path / "out-good").glob("universal-db-mcp-*"))
    public = serialization.load_pem_public_key(pub.read_bytes())
    public.verify((bundle / "SIGNATURE").read_bytes(), (bundle / "SHA256SUMS").read_bytes())  # type: ignore[union-attr]
    runtime_lock = (bundle / "requirements" / "runtime.lock").read_text(encoding="utf-8")
    assert f"idna==3.20 --hash=sha256:{_sha256(genuine['idna'])}" in runtime_lock
    tools = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))["build_tools"]
    assert tools["runtime_lock_sha256"] == _sha256(lock)
    assert tools["build_lock_sha256"] == _sha256(builder.BUILD_LOCK)
    assert tools["hatchling"] and tools["build"] and "uv" in tools


@pytest.mark.parametrize("name", [LINUX_PROFILE, WINDOWS_PROFILE, "macos-arm64-cp312"])
def test_f56_every_profile_has_a_current_hashed_lock_of_the_runtime_pins(name: str) -> None:
    builder = _builder()
    profile = _profiles()[name]
    assert builder.lock_problems(profile) == []
    entries = builder.parse_lock(builder.lock_path(profile).read_text(encoding="utf-8"))
    assert all(entry.hashes for entry in entries.values())
    pins = builder.runtime_pins()
    assert {n: entries[n].version for n in pins} == pins  # the lock's top-level pins ARE runtime.in's
    assert {"pynacl", "cryptography"} <= set(entries)  # the MySQL auth plugins ship
    # the default connector set downloads the whole lock and nothing else
    everything = builder.lock_closure(entries, list(builder.CONNECTOR_WHEELS))
    assert {entry.name for entry in everything} == set(entries)
    core = {entry.name for entry in builder.lock_closure(entries, ["core"])}
    assert {"mcp", "sqlglot", "pyyaml", "idna"} <= core and not {"pymysql", "pynacl", "oracledb"} & core
    assert "pynacl" in {entry.name for entry in builder.lock_closure(entries, ["core", "mysql"])}
    # mcp needs pywin32 on Windows only; the old marker-blind download never fetched it
    assert ("pywin32" in entries) == (name == WINDOWS_PROFILE)


def test_f56_the_build_backend_is_locked_with_hashes() -> None:
    builder = _builder()
    assert builder.build_lock_problems() == []
    entries = builder.parse_lock(builder.BUILD_LOCK.read_text(encoding="utf-8"))
    assert {"build", "hatchling"} <= set(entries)
    assert all(entry.hashes for entry in entries.values())


def test_f56_a_stale_or_missing_lock_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    builder = _builder()
    profile = _profiles()[LINUX_PROFILE]
    bumped = tmp_path / "runtime.in"
    bumped.write_text(RUNTIME_IN.read_text(encoding="utf-8").replace("sqlglot==30.18.0", "sqlglot==30.19.0"))
    assert any("sqlglot" in p for p in builder.lock_problems(profile, runtime_in=bumped))
    assert any("missing" in p for p in builder.lock_problems(profile, lock=tmp_path / "absent.txt"))
    # an extras change leaves every pin alone; the recorded input digest still catches it
    monkeypatch.setitem(builder.CONNECTOR_WHEELS, "postgres", ["psycopg[binary,pool]"])
    assert any("input-sha256" in p for p in builder.lock_problems(profile))


def test_f56_check_locks_is_the_release_gate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ok = subprocess.run(  # noqa: S603 - repo script under test
        [sys.executable, str(BUILDER), "--check-locks"], capture_output=True, text=True, timeout=120, check=False
    )
    assert ok.returncode == 0, ok.stdout + ok.stderr
    builder = _builder()
    bumped = tmp_path / "runtime.in"
    bumped.write_text(RUNTIME_IN.read_text(encoding="utf-8").replace("PyYAML==6.0.3", "PyYAML==6.0.4"))
    monkeypatch.setattr(builder, "RUNTIME_IN", bumped)
    monkeypatch.setattr(sys, "argv", ["prepare_offline_bundle.py", "--check-locks"])
    with pytest.raises(SystemExit) as stale:
        builder.main()
    assert stale.value.code == 1
    text = RELEASE_USB.read_text(encoding="utf-8")
    assert text.index("prepare_offline_bundle.py --check-locks") < text.index("prepare_offline_bundle.py --out")


# ---- F59: dependency floors are the tested releases ----------------------------


def _pyproject_requirements() -> list[Any]:
    from packaging.requirements import Requirement

    project = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]
    extras = project["optional-dependencies"]
    return [Requirement(r) for r in project["dependencies"]] + [
        Requirement(r) for extra, reqs in extras.items() if extra != "dev" for r in reqs
    ]


def _canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def test_f59_the_mysql_extra_requires_the_patched_pymysql_and_its_auth_plugins() -> None:
    req = _requirement("pymysql", "mysql")
    assert req.extras == {"ed25519", "rsa"}
    for affected in ("1.0.2", "1.1.0", "1.1.1"):  # CVE-2024-36039 below 1.1.1; 1.2.0 is the tested pin
        assert not req.specifier.contains(affected), affected
    assert req.specifier.contains("1.2.0") and not req.specifier.contains("2.0.0")


def test_f59_sqlglot_is_held_to_the_tested_parser_series() -> None:
    (req,) = [r for r in _pyproject_requirements() if _canonical(r.name) == "sqlglot"]
    for untested in [f"30.{minor}.0" for minor in range(18)] + ["30.17.9", "30.19.0", "31.0.0"]:
        assert not req.specifier.contains(untested), untested
    assert req.specifier.contains("30.18.0") and req.specifier.contains("30.18.3")


def test_f59_every_shipped_pin_satisfies_the_package_requirements() -> None:
    pins = _builder().runtime_pins(RUNTIME_IN)
    for req in _pyproject_requirements():
        pin = pins[_canonical(req.name)]
        assert req.specifier.contains(pin), f"{req} rejects the shipped {req.name}=={pin}"


def _requirement(name: str, extra: str | None = None) -> Any:
    from packaging.requirements import Requirement

    project = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]
    specs = project["optional-dependencies"][extra] if extra else project["dependencies"]
    (req,) = [Requirement(s) for s in specs if _canonical(Requirement(s).name) == name]
    return req


@pytest.mark.parametrize(
    ("name", "extra", "tested", "unreviewed"),
    [
        # http_protocol.py subclasses uvicorn's H11Protocol and reads h11 state: both were only
        # transitive (through mcp), so any mcp-compatible release could replace them unseen
        ("uvicorn", None, ["0.52.4", "0.53.0"], ["0.52.3", "0.54.0", "1.0.0"]),
        ("h11", None, ["0.16.0"], ["0.15.0", "0.17.0"]),
        # the stream-budget meter wraps a clickhouse-connect 1.8 seam
        ("clickhouse-connect", "clickhouse", ["1.8.0"], ["0.8.0", "1.7.9", "1.9.0", "2.0.0"]),
    ],
)
def test_i70_the_dependencies_whose_internals_the_code_uses_are_held_to_the_reviewed_series(
    name: str, extra: str | None, tested: list[str], unreviewed: list[str]
) -> None:
    req = _requirement(name, extra)
    assert all(req.specifier.contains(v) for v in tested), req
    assert not [v for v in unreviewed if req.specifier.contains(v)], req
    shipped = _builder().parse_lock(_builder().lock_path(_profiles()[LINUX_PROFILE]).read_text(encoding="utf-8"))
    assert req.specifier.contains(shipped[name].version), f"{req} rejects the shipped {name}=={shipped[name].version}"


@pytest.mark.parametrize(
    ("name", "extra", "vulnerable"),
    [
        # CVE-2025-69277; PyMySQL[ed25519] alone accepts older PyNaCl
        ("pynacl", "mysql", ["1.5.0", "1.6.1"]),
        # mcp's pyjwt[crypto] and PyMySQL[rsa] both accept older cryptography
        ("cryptography", None, ["43.0.3", "49.0.0"]),
    ],
)
def test_i74_a_source_install_cannot_keep_a_vulnerable_transitive_crypto_library(
    name: str, extra: str | None, vulnerable: list[str]
) -> None:
    req = _requirement(name, extra)
    assert not [v for v in vulnerable if req.specifier.contains(v)], req
    assert req.specifier.contains(_builder().runtime_pins(RUNTIME_IN)[name]), req


def test_i71_uv_builds_the_project_with_the_locked_build_backend() -> None:
    """`uv sync --locked` builds the editable project in an isolated environment; without a
    constraint it resolves hatchling (and what hatchling needs) fresh from the index."""
    from packaging.requirements import Requirement

    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    constraints = [Requirement(c) for c in data["tool"]["uv"]["build-constraint-dependencies"]]
    entries = _builder().parse_lock(_builder().BUILD_LOCK.read_text(encoding="utf-8"))
    pinned = {}
    for req in constraints:
        (spec,) = req.specifier
        assert spec.operator == "==", req
        pinned[_canonical(req.name)] = spec.version
    backend = {"hatchling"} | {name for name, entry in entries.items() if "hatchling" in entry.via}
    assert backend <= set(pinned), f"unconstrained build dependencies: {sorted(backend - set(pinned))}"
    assert pinned == {name: entries[name].version for name in pinned}, "must be requirements/locks/build.txt's pins"
    manifest = tomllib.loads(UV_LOCK.read_text(encoding="utf-8"))["manifest"]
    locked = {_canonical(c["name"]): c["specifier"] for c in manifest["build-constraints"]}
    assert locked == {name: f"=={version}" for name, version in pinned.items()}, "re-lock: uv.lock records them"


def test_f59_uv_lock_resolves_the_shipped_closure() -> None:
    """CI installs from uv.lock: it must test the versions the bundle ships."""
    from packaging.specifiers import SpecifierSet

    builder = _builder()
    packages = tomllib.loads(UV_LOCK.read_text(encoding="utf-8"))["package"]
    versions = {p["name"]: p["version"] for p in packages}
    for name, pin in builder.runtime_pins(RUNTIME_IN).items():
        assert versions.get(name) == pin, f"uv.lock has {name} {versions.get(name)}, runtime.in pins {pin}"
    shipped = builder.parse_lock(builder.lock_path(_profiles()[LINUX_PROFILE]).read_text(encoding="utf-8"))
    for name, entry in shipped.items():
        assert versions.get(name) == entry.version, f"uv.lock has {name} {versions.get(name)}, lock {entry.version}"
    project = next(p for p in packages if p["name"] == "universal-db-mcp")
    requires = {r["name"]: r for r in project["metadata"]["requires-dist"]}
    assert SpecifierSet(requires["sqlglot"]["specifier"]) == SpecifierSet("~=30.18.0")
    assert SpecifierSet(requires["pymysql"]["specifier"]) == SpecifierSet(">=1.2.0,<2")
    assert sorted(requires["pymysql"]["extras"]) == ["ed25519", "rsa"]


# ---- F53: root runs only a root-owned interpreter, isolated, from / -----------

PKG_PREINSTALL = REPO / "packaging" / "pkg" / "preinstall"
PKG_POSTINSTALL = REPO / "packaging" / "pkg" / "postinstall"
ROLLBACK = REPO / "scripts" / "rollback_offline.sh"
DOCTOR_SH = REPO / "scripts" / "doctor.sh"
PY_CANDIDATES = ("FRAMEWORK_PY", "USR_LOCAL_PY", "BREW_ARM_PY", "BREW_INTEL_PY")
PKG_SCRIPTS = pytest.mark.parametrize("script", [PKG_PREINSTALL, PKG_POSTINSTALL], ids=["preinstall", "postinstall"])
_NOT_ROOT = pytest.mark.skipif(os.getuid() == 0, reason="needs files a non-root account owns")


_PY_ORG = "Library/Frameworks/Python.framework"
_VERSION = f"{_PY_ORG}/Versions/3.12"
_BREW = "homebrew"


def _candidate_stub(path: Path, marker: Path) -> None:
    """A CPython 3.12 stand-in that logs every execution ($0 and argv).

    The interpreter probes (the version and ensurepip `-c` checks) pass; anything else (the
    verifier, another `-c` program) runs under this python."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "#!/bin/sh\n"
        f'printf "%s %s\\n" "$0" "$*" >> "{marker}"\n'
        'if [ "$1" = "-I" ]; then shift; fi\n'
        'if [ "$1" = "-S" ]; then shift; fi\n'
        'if [ "$1" = "-c" ]; then case "$2" in *version_info*|*ensurepip*) exit 0 ;; esac; fi\n'
        f'exec "{sys.executable}" "$@"\n',
        encoding="utf-8",
    )
    path.chmod(0o755)


def _python_org(host: Path, marker: Path) -> tuple[str, Path]:
    """The python.org 3.12 layout below *host*; the candidate is the bin/python3 symlink."""
    version = host / "Library" / "Frameworks" / "Python.framework" / "Versions" / "3.12"
    _candidate_stub(version / "bin" / "python3.12", marker)
    (version / "bin" / "python3").symlink_to("python3.12")
    stdlib = version / "lib" / "python3.12"
    (stdlib / "lib-dynload").mkdir(parents=True)
    (stdlib / "site-packages").mkdir()
    (stdlib / "os.py").write_text("# stdlib\n", encoding="utf-8")
    (stdlib / "lib-dynload" / "_hashlib.so").write_bytes(b"\0")
    (version / "Python").write_bytes(b"\0")  # the framework dylib
    # the framework's own symlinks, all inside it
    (version / "lib" / "libpython3.12.dylib").symlink_to("../Python")
    (version.parent / "Current").symlink_to("3.12")
    (version.parent.parent / "Python").symlink_to("Versions/Current/Python")
    return "FRAMEWORK_PY", version / "bin" / "python3"


def _homebrew(host: Path, marker: Path) -> tuple[str, Path]:
    """A Homebrew prefix: bin -> Cellar keg -> framework binary, site-packages linked out to
    <prefix>/lib, and the openssl@3 keg the stdlib's _ssl/_hashlib load through <prefix>/opt."""
    prefix = host / "homebrew"
    keg = prefix / "Cellar" / "python@3.12" / "3.12.14"
    version = keg / "Frameworks" / "Python.framework" / "Versions" / "3.12"
    _candidate_stub(version / "bin" / "python3.12", marker)
    (keg / "bin").mkdir()
    (keg / "bin" / "python3.12").symlink_to("../Frameworks/Python.framework/Versions/3.12/bin/python3.12")
    (prefix / "bin").mkdir()
    (prefix / "bin" / "python3.12").symlink_to("../Cellar/python@3.12/3.12.14/bin/python3.12")
    stdlib = version / "lib" / "python3.12"
    (stdlib / "lib-dynload").mkdir(parents=True)
    (stdlib / "sitecustomize.py").write_text("# brew\n", encoding="utf-8")
    site = prefix / "lib" / "python3.12" / "site-packages"
    site.mkdir(parents=True)
    (stdlib / "site-packages").symlink_to(os.path.relpath(site, stdlib))
    openssl = prefix / "Cellar" / "openssl@3" / "3.5.0" / "lib"
    openssl.mkdir(parents=True)
    (openssl / "libcrypto.3.dylib").write_bytes(b"\0")
    (prefix / "opt").mkdir()
    (prefix / "opt" / "openssl@3").symlink_to("../Cellar/openssl@3/3.5.0")
    return "BREW_ARM_PY", prefix / "bin" / "python3.12"


def _linked_site_packages(host: Path, marker: Path) -> tuple[str, Path]:
    """python.org layout whose site-packages is a symlink out of the framework."""
    slot, candidate = _python_org(host, marker)
    stdlib = host / _VERSION / "lib" / "python3.12"
    (stdlib / "site-packages").rmdir()
    outside = host / "shared" / "site-packages"
    outside.mkdir(parents=True)
    (stdlib / "site-packages").symlink_to(os.path.relpath(outside, stdlib))
    return slot, candidate


def _venv(host: Path, marker: Path) -> tuple[str, Path]:
    """A --copies virtual environment in a candidate slot: its stdlib comes from pyvenv.cfg's home."""
    venv = host / "venv"
    _candidate_stub(venv / "bin" / "python3.12", marker)
    (venv / "lib" / "python3.12" / "site-packages").mkdir(parents=True)
    (venv / "pyvenv.cfg").write_text("home = /opt/pyenv/versions/3.12.14/bin\n", encoding="utf-8")
    return "BREW_INTEL_PY", venv / "bin" / "python3.12"


def _go_minus_w(tree: Path) -> None:
    """The modes of a root-only install (group and other write removed); ownership is mocked separately."""
    for path in [tree, *tree.rglob("*")]:
        if not path.is_symlink():
            path.chmod(path.stat().st_mode & ~0o022)


def _find_as_root(tmp_path: Path, as_root: bool = True) -> Path:
    """find(1) with stat mocked: files of this test account count as owned by root (uid 0).

    Modes and ACLs are the real ones, so group/other write is still seen. GNU find (Linux CI)
    has no -acl primary; a Linux file carries no macOS ACL, so there it is false. With
    as_root=False the owners are the real ones too (see _real_find)."""
    shim = tmp_path / ("find-as-root" if as_root else "find-real-owners")
    no_acl = sys.platform != "darwin"
    owner = f'"(" -user 0 -o -user {os.getuid()} ")"' if as_root else "-user 0"
    shim.write_text(
        "#!/bin/bash\n"
        "args=()\n"
        "while [ $# -gt 0 ]; do\n"
        '  if [ "$1" = -user ] && [ "${2:-}" = 0 ]; then\n'
        f"    args+=({owner}); shift 2\n"
        + ('  elif [ "$1" = -acl ]; then\n    args+=(-false); shift\n' if no_acl else "")
        + "  else\n"
        '    args+=("$1"); shift\n'
        "  fi\n"
        "done\n"
        'exec /usr/bin/find "${args[@]}"\n',
        encoding="utf-8",
    )
    shim.chmod(0o755)
    return shim


def _find_as_root_except(tmp_path: Path, *real: Path) -> Path:
    """_find_as_root, except that a search starting at a path in *real* sees the real owners (this
    test account's, not root's)."""
    as_root, real_owners = _find_as_root(tmp_path), _real_find(tmp_path)
    shim = tmp_path / "find-as-root-except"
    starts = " | ".join(shlex.quote(str(path)) for path in real)
    shim.write_text(
        f'#!/bin/bash\ncase "$1" in\n  {starts}) exec "{real_owners}" "$@" ;;\nesac\nexec "{as_root}" "$@"\n',
        encoding="utf-8",
    )
    shim.chmod(0o755)
    return shim


def _real_find(tmp_path: Path) -> Path | str:
    """find(1) with the real owners: the BSD find the pkg scripts use on a Mac, or, where GNU find
    rejects -acl (and a check would fail for that reason alone), a shim that maps it to -false."""
    return "/usr/bin/find" if sys.platform == "darwin" else _find_as_root(tmp_path, as_root=False)


_PKG_BLOCK = ("# >>> root-owned CPython 3.12", "# <<< root-owned CPython 3.12")


@_NOT_ROOT
@pytest.mark.parametrize("as_root", [False, True], ids=["real-owners", "as-root"])
def test_the_find_the_pkg_tests_use_answers_the_ownership_question(tmp_path: Path, as_root: bool) -> None:
    """A check that fails because find rejects a primary reports every directory as untrusted, which
    would let the refusal tests pass without ever evaluating ownership (GNU find has no -acl)."""
    text = PKG_PREINSTALL.read_text(encoding="utf-8")
    block = text[text.index(_PKG_BLOCK[0]) : text.index(_PKG_BLOCK[1])]
    find = _find_as_root(tmp_path) if as_root else _real_find(tmp_path)
    mine, writable = tmp_path / "mine", tmp_path / "writable"
    mine.mkdir(mode=0o755)
    writable.mkdir()
    writable.chmod(0o777)
    probe = tmp_path / "probe.sh"
    loop = f'for d in / "{mine}" "{writable}"; do printf "[%s]\\n" "$(untrusted_dir "$d")"; done'
    probe.write_text(f'{block}\nFIND="{find}"\n{loop}\n', encoding="utf-8")
    proc = subprocess.run(  # noqa: S603 - the pkg scripts' own functions
        ["/bin/bash", str(probe)], capture_output=True, text=True, timeout=60, check=False
    )
    # "/" is root's alone on every host these tests run on (every accepting pkg test relies on it)
    assert proc.stdout.splitlines() == ["[]", "[]" if as_root else f"[{mine}]", f"[{writable}]"], proc.stderr


def _pkg_sandbox(tmp_path: Path, script: Path, slot: str, candidate: Path, find: Path | str) -> Path:
    """The pkg script with its fixed paths (trust material, prefix, candidates, find) rewritten into tmp_path.

    dscl and launchctl are tripwires that fail: should a sandboxed postinstall ever get past its
    verifier, it stops at account provisioning instead of reaching this host's directory service
    or launchd."""
    tripwire = tmp_path / "tripwire"
    tripwire.mkdir(exist_ok=True)
    for tool in ("dscl", "launchctl"):
        (tripwire / tool).write_text(f'#!/bin/sh\necho "TRIPWIRE: {tool} $*" >&2\nexit 97\n', encoding="utf-8")
        (tripwire / tool).chmod(0o755)
    values: dict[str, Path | str] = {
        "PATH": f"{tripwire}:/usr/bin:/bin:/usr/sbin:/sbin",
        "TRUST_DIR": tmp_path / "trust",
        "PUBKEY": tmp_path / "keys" / "release.pub.pem",
        "PREFIX": tmp_path / "prefix",
        "CONFIG_DIR": tmp_path / "etc",
        "STATE_DIR": tmp_path / "state",
        "LOG_DIR": tmp_path / "log",
        "PLIST": tmp_path / "server.plist",
        "FIND": find,
        **{name: tmp_path / "absent" / name.lower() for name in PY_CANDIDATES},
        slot: candidate,
    }
    text = script.read_text(encoding="utf-8")
    for name, value in values.items():
        # the definition, not a later value derived from a checked one (PUBKEY="$key_dir/...")
        text, count = re.subn(rf'^{name}="(?!\$[a-z_])[^\n]*"$', f'{name}="{value}"', text, flags=re.MULTILINE)
        assert count <= 1, name
        assert count == 1 or name in ("PREFIX", "CONFIG_DIR", "STATE_DIR", "LOG_DIR", "PLIST"), name
    sandbox = tmp_path / f"{script.name}_sbx.sh"
    sandbox.write_text(text, encoding="utf-8")
    trust = tmp_path / "trust"
    trust.mkdir(exist_ok=True)
    (trust / "verify_bundle.py").write_text(
        "import sys\nprint('SIGNATURE MISMATCH: sandbox payload')\nsys.exit(3)\n", encoding="utf-8"
    )
    (tmp_path / "keys").mkdir(exist_ok=True)
    (tmp_path / "keys" / "release.pub.pem").write_text(
        "-----BEGIN PUBLIC KEY-----\nsbx\n-----END PUBLIC KEY-----\n", encoding="utf-8"
    )
    # the modes of a root-only trust bootstrap, whatever the umask (Debian's 002 makes new
    # directories group-writable, which postinstall rightly refuses)
    _go_minus_w(trust)
    _go_minus_w(tmp_path / "keys")
    (tmp_path / "prefix" / "bundle").mkdir(parents=True, exist_ok=True)
    (tmp_path / "prefix" / "bundle" / "manifest.json").write_text("{}\n", encoding="utf-8")
    return sandbox


def _run_pkg(
    tmp_path: Path, script: Path, layout: Any, find: Path | str, writable: str = "", bits: int = 0, tweak: Any = None
) -> Any:
    """Run the sandboxed pkg script; *tweak(tmp_path)* adjusts the sandbox (trust dir, keys, prefix) first."""
    marker = tmp_path / "interpreter-runs.log"
    host = tmp_path / "host"
    slot, candidate = layout(host, marker)
    _go_minus_w(host)
    if writable:
        target = host / writable
        target.chmod(target.stat().st_mode | bits)
    sandbox = _pkg_sandbox(tmp_path, script, slot, candidate, find)
    if tweak is not None:
        tweak(tmp_path)
    env = {k: v for k, v in os.environ.items() if not k.startswith("UDBMCP_")}
    env["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin"
    env["TMPDIR"] = str(tmp_path)
    proc = subprocess.run(  # noqa: S603 - sandboxed copy of a repo script
        ["/bin/bash", str(sandbox)], env=env, capture_output=True, text=True, timeout=120, check=False
    )
    runs = marker.read_text(encoding="utf-8").splitlines() if marker.exists() else []
    return proc, runs, host


@_NOT_ROOT
@PKG_SCRIPTS
def test_f53_pkg_scripts_never_run_an_interpreter_another_account_owns(tmp_path: Path, script: Path) -> None:
    proc, runs, _ = _run_pkg(tmp_path, script, _python_org, _real_find(tmp_path))
    out = proc.stdout + proc.stderr
    assert proc.returncode == 1, out
    assert runs == [], f"the candidate ran before its ownership was checked: {runs}"
    assert "FAIL:" in proc.stderr and "not owned by root" in proc.stderr, out
    assert "sudo chown" in proc.stderr and "root:wheel" in proc.stderr and "chmod" in proc.stderr, out
    assert "https://www.python.org/downloads/macos/" in proc.stderr, out


@_NOT_ROOT
@PKG_SCRIPTS
@pytest.mark.parametrize(
    ("layout", "writable", "bits", "fix_root", "recursive"),
    [
        (_python_org, f"{_VERSION}/bin/python3.12", 0o020, _PY_ORG, True),
        (_python_org, f"{_VERSION}/lib/python3.12/os.py", 0o002, _PY_ORG, True),
        (_python_org, f"{_VERSION}/lib/python3.12/lib-dynload", 0o020, _PY_ORG, True),
        (_python_org, f"{_VERSION}/lib/python3.12/site-packages", 0o002, _PY_ORG, True),
        (_python_org, f"{_VERSION}/Python", 0o020, _PY_ORG, True),
        (_python_org, "Library/Frameworks", 0o002, "Library/Frameworks", False),
        (_homebrew, f"{_BREW}/lib/python3.12/site-packages", 0o020, _BREW, True),
        (_homebrew, f"{_BREW}/Cellar/openssl@3/3.5.0/lib/libcrypto.3.dylib", 0o020, _BREW, True),
        (_linked_site_packages, "shared/site-packages", 0o002, "shared/site-packages", True),
        (_linked_site_packages, "shared", 0o020, "shared", False),
    ],
    ids=["binary", "stdlib", "lib-dynload", "site-packages", "dylib", "parent-dir", "brew-site-packages",
         "brew-openssl-keg", "linked-site-packages", "linked-site-packages-parent"],
)
def test_f53_pkg_scripts_refuse_an_interpreter_another_account_can_write(
    tmp_path: Path, script: Path, layout: Any, writable: str, bits: int, fix_root: str, recursive: bool
) -> None:
    proc, runs, host = _run_pkg(tmp_path, script, layout, _find_as_root(tmp_path), writable, bits)
    out = proc.stdout + proc.stderr
    assert proc.returncode == 1, out
    assert runs == [], f"the candidate ran before its ownership was checked: {runs}"
    offender = os.path.realpath(host / writable)
    assert f"{offender} is not owned by root" in proc.stderr, out
    fixed = os.path.realpath(host / fix_root)
    flag = "-R " if recursive else ""
    assert f"sudo chown {flag}root:wheel {fixed}; sudo chmod {flag}go-w {fixed}" in proc.stderr, out


@PKG_SCRIPTS
def test_f53_pkg_scripts_refuse_a_virtual_environment_as_the_interpreter(tmp_path: Path, script: Path) -> None:
    proc, runs, host = _run_pkg(tmp_path, script, _venv, _find_as_root(tmp_path))
    assert proc.returncode == 1 and runs == [], proc.stdout + proc.stderr
    cfg = os.path.realpath(host / "venv" / "pyvenv.cfg")
    assert f"{cfg} makes it a virtual environment" in proc.stderr, proc.stderr


_SITE = f"{_VERSION}/lib/python3.12/site-packages"
_STDLIB = f"{_VERSION}/lib/python3.12"


def _planted_link(kind: str) -> Any:
    """The python.org layout with one symlink planted while the framework was still admin-writable.

    `chown -R` and `chmod -R` do not follow symlinks, so it survives the printed fix; a .pth
    file or sitecustomize.py reached through it runs as root, -I or not."""

    def layout(host: Path, marker: Path) -> tuple[str, Path]:
        slot, candidate = _python_org(host, marker)
        site, stdlib, attacker = host / _SITE, host / _STDLIB, host / "attacker"
        (attacker / "x").mkdir(parents=True)
        evil = attacker / "evil.pth"
        evil.write_text("import os; os.environ['UDBMCP_PTH_RAN'] = '1'\n", encoding="utf-8")
        if kind == "pth-out":
            (site / "zz_hook.pth").symlink_to(os.path.relpath(evil, site))
        elif kind == "sitecustomize-absolute":
            (stdlib / "sitecustomize.py").symlink_to(evil)
        elif kind == "package-dir-out":
            (site / "evilpkg").symlink_to(attacker)
        elif kind == "dangling":  # the attacker creates the target later
            (site / "zz_hook.pth").symlink_to(attacker / "planted-later.pth")
        elif kind == "dangling-inside":  # inside the tree, but to a name nothing holds yet
            (site / "zz_hook.pth").symlink_to("../planted-later.pth")
        elif kind == "sibling-prefix":  # a sibling whose name starts with the tree's: not inside it
            backup = host / f"{_PY_ORG}.bak"
            backup.mkdir()
            shutil.copy2(evil, backup / "evil.pth")
            (site / "zz_hook.pth").symlink_to(os.path.relpath(backup / "evil.pth", site))
        else:  # resolves inside today, but through a symlink the attacker can re-point
            (attacker / "hop").symlink_to("x")
            up = os.path.relpath(host, site)
            (site / "zz_hook.pth").symlink_to(f"{up}/attacker/hop/../../{_STDLIB}/os.py")
        return slot, candidate

    return layout


_LINKS = {
    "pth-out": f"{_SITE}/zz_hook.pth",
    "sitecustomize-absolute": f"{_STDLIB}/sitecustomize.py",
    "package-dir-out": f"{_SITE}/evilpkg",
    "dangling": f"{_SITE}/zz_hook.pth",
    "dangling-inside": f"{_SITE}/zz_hook.pth",
    "dotdot-through-outside": f"{_SITE}/zz_hook.pth",
    "sibling-prefix": f"{_SITE}/zz_hook.pth",
}


@PKG_SCRIPTS
@pytest.mark.parametrize("kind", list(_LINKS))
def test_f53_pkg_scripts_refuse_a_symlink_that_leads_out_of_the_interpreter(
    tmp_path: Path, script: Path, kind: str
) -> None:
    proc, runs, host = _run_pkg(tmp_path, script, _planted_link(kind), _find_as_root(tmp_path), "attacker", 0o777)
    out = proc.stdout + proc.stderr
    assert proc.returncode == 1, out
    assert runs == [], f"the candidate ran although a symlink leads out of its installation: {runs}"
    link = os.path.join(os.path.realpath((host / _LINKS[kind]).parent), Path(_LINKS[kind]).name)
    assert f"{link} is a symlink to " in proc.stderr, out
    assert "leads out of " in proc.stderr and " or to nothing" in proc.stderr, out
    assert f"sudo rm {link}" in proc.stderr, out


def _link_text_with_line_break(host: Path, marker: Path) -> tuple[str, Path]:
    """A link whose text holds a line break: readlink prints it as two lines."""
    slot, candidate = _python_org(host, marker)
    (host / _SITE / "zz_hook.pth").symlink_to("../os.py\n../../../../../../../../attacker.pth")
    return slot, candidate


@PKG_SCRIPTS
def test_f53_pkg_scripts_refuse_a_symlink_text_with_a_line_break(tmp_path: Path, script: Path) -> None:
    """Link texts are read in batches, one per line: a text with a line break is refused up front,
    so no text can ever be paired with the wrong link."""
    proc, runs, host = _run_pkg(tmp_path, script, _link_text_with_line_break, _find_as_root(tmp_path))
    out = proc.stdout + proc.stderr
    assert proc.returncode == 1 and runs == [], out
    root = os.path.realpath(host / _PY_ORG)
    assert f"{root} holds a name or a symlink text with a line break" in proc.stderr, out


def _many_links(total: int, bad: Path | None = None) -> Any:
    """The python.org layout (4 links of its own) with site-packages links up to *total* in all."""

    def layout(host: Path, marker: Path) -> tuple[str, Path]:
        slot, candidate = _python_org(host, marker)
        many = host / _SITE / "many"
        many.mkdir()
        for k in range(total - 4 - (bad is not None)):
            (many / f"l{k:05d}").symlink_to("../../os.py")
        if bad is not None:
            (many / "zz_hook.pth").symlink_to(bad)
        return slot, candidate

    return layout


@pytest.mark.parametrize("total", [999, 1000, 1001, 2001])
def test_f53_pkg_scripts_pair_every_link_with_its_text_across_readlink_batches(tmp_path: Path, total: int) -> None:
    """Link texts are read 1000 per readlink call: at every batch boundary each link must still get
    its own text (a dropped or repeated line would shift every later pairing)."""
    proc, runs, _ = _run_pkg(tmp_path, PKG_PREINSTALL, _many_links(total), _find_as_root(tmp_path))
    assert proc.returncode == 0 and runs, proc.stdout + proc.stderr
    outside = tmp_path / "outside.pth"
    outside.write_text("import os\n", encoding="utf-8")
    shutil.rmtree(tmp_path / "host")
    (tmp_path / "interpreter-runs.log").unlink()
    proc, runs, _ = _run_pkg(tmp_path, PKG_PREINSTALL, _many_links(total, outside), _find_as_root(tmp_path))
    assert proc.returncode == 1 and runs == [], proc.stdout + proc.stderr
    assert "zz_hook.pth is a symlink to " in proc.stderr, proc.stderr


def test_f53_pkg_scripts_refuse_when_readlink_answers_for_fewer_links_than_it_was_given(tmp_path: Path) -> None:
    """One text short and every later link would be paired with its neighbour's text."""

    def short_readlink(tmp: Path) -> None:
        shim = tmp / "tripwire" / "readlink"  # first on the sandboxed script's PATH
        shim.write_text(
            "#!/bin/sh\n"
            'if [ "$#" -gt 1 ]; then /usr/bin/readlink "$@" | sed \'$d\'; else exec /usr/bin/readlink "$@"; fi\n',
            encoding="utf-8",
        )
        shim.chmod(0o755)

    proc, runs, host = _run_pkg(
        tmp_path, PKG_PREINSTALL, _python_org, _find_as_root(tmp_path), tweak=short_readlink
    )
    assert proc.returncode == 1 and runs == [], proc.stdout + proc.stderr
    assert f"the symlinks in {os.path.realpath(host / _PY_ORG)} could not be read" in proc.stderr, proc.stderr


_DARWIN = pytest.mark.skipif(sys.platform != "darwin", reason="macOS ACLs (chmod +a)")
_WRITE_ACL = "everyone allow add_file,add_subdirectory,write,delete_child,file_inherit,directory_inherit"


def _with_acl(rel: str) -> Any:
    """The python.org layout with an 'everyone may write' ACL on *rel*: chmod -R go-w leaves it."""

    def layout(host: Path, marker: Path) -> tuple[str, Path]:
        slot, candidate = _python_org(host, marker)
        subprocess.run(["/bin/chmod", "+a", _WRITE_ACL, str(host / rel)], check=True)  # noqa: S603
        return slot, candidate

    return layout


@_DARWIN
@PKG_SCRIPTS
@pytest.mark.parametrize(
    ("rel", "fix_root", "recursive"),
    [(_SITE, _PY_ORG, True), ("Library/Frameworks", "Library/Frameworks", False)],
    ids=["site-packages", "parent-dir"],
)
def test_f53_pkg_scripts_refuse_an_interpreter_an_acl_lets_another_account_write(
    tmp_path: Path, script: Path, rel: str, fix_root: str, recursive: bool
) -> None:
    proc, runs, host = _run_pkg(tmp_path, script, _with_acl(rel), _find_as_root(tmp_path))
    out = proc.stdout + proc.stderr
    assert proc.returncode == 1, out
    assert runs == [], f"the candidate ran although an ACL lets another account write: {runs}"
    assert f"{os.path.realpath(host / rel)} is not owned by root" in proc.stderr, out
    fixed = os.path.realpath(host / fix_root)
    flag = "-R " if recursive else ""
    assert f"sudo chmod {flag}go-w {fixed}; sudo chmod {flag}-N {fixed}" in proc.stderr, out


def _trust_symlink_out(tmp: Path) -> None:
    outside = tmp / "elsewhere"
    outside.mkdir()
    (outside / "profiles.py").write_text("PROFILES = {}\n", encoding="utf-8")
    (tmp / "trust" / "profiles.py").symlink_to(outside / "profiles.py")


@_NOT_ROOT
@pytest.mark.parametrize(
    ("offender", "tweak"),
    [
        ("trust", lambda tmp: (tmp / "trust").chmod(0o775)),
        ("trust/verify_bundle.py", lambda tmp: (tmp / "trust" / "verify_bundle.py").chmod(0o666)),
        ("keys", lambda tmp: (tmp / "keys").chmod(0o777)),
        ("trust/profiles.py", _trust_symlink_out),
    ],
    ids=["trust-dir", "verifier", "key-dir", "trust-symlink"],
)
def test_f53_postinstall_runs_the_verifier_only_from_root_only_trust_material(
    tmp_path: Path, offender: str, tweak: Any
) -> None:
    """The verifier, the profiles.py it imports and the release key decide what root installs."""
    proc, runs, _ = _run_pkg(tmp_path, PKG_POSTINSTALL, _python_org, _find_as_root(tmp_path), tweak=tweak)
    out = proc.stdout + proc.stderr
    assert proc.returncode == 1, out
    assert not [run for run in runs if "verify_bundle.py" in run], f"the verifier ran: {runs}"
    path = os.path.join(os.path.realpath((tmp_path / offender).parent), Path(offender).name)
    assert f"{path} is not owned by root" in proc.stderr or f"{path} is a symlink to " in proc.stderr, out
    assert "refusing to run the trusted verifier" in proc.stderr, out


def _trust_material_linked_from_a_writable_dir(tmp: Path) -> None:
    """The trust dir and the key dir moved to a root-only place and linked back from a directory
    any account can write (an admin's workaround where Homebrew owns /usr/local/lib)."""
    rootonly, writable = tmp / "rootonly", tmp / "w"
    rootonly.mkdir()
    rootonly.chmod(0o755)  # root-only whatever the umask (mkdir's mode is masked by it too)
    writable.mkdir()
    writable.chmod(0o777)
    sandbox = tmp / "postinstall_sbx.sh"
    text = sandbox.read_text(encoding="utf-8")
    for name, var in (("trust", "TRUST_DIR"), ("keys", "PUBKEY")):
        (tmp / name).rename(rootonly / name)
        (writable / name).symlink_to(rootonly / name)
        text, count = re.subn(rf'^{var}="{re.escape(str(tmp))}/{name}', f'{var}="{writable}/{name}', text, flags=re.M)
        assert count == 1, var
    sandbox.write_text(text, encoding="utf-8")


def test_f53_postinstall_uses_the_trust_material_it_checked_not_a_link_to_it(tmp_path: Path) -> None:
    """The check proves the RESOLVED directories root-only; the names given lead through a directory
    another account can write, whose links it could re-point between the check and the use."""
    linked = _trust_material_linked_from_a_writable_dir
    proc, runs, _ = _run_pkg(tmp_path, PKG_POSTINSTALL, _python_org, _find_as_root(tmp_path), tweak=linked)
    out = proc.stdout + proc.stderr
    assert proc.returncode == 1 and "SIGNATURE MISMATCH" in out, out  # accepted: the (refusing) verifier ran
    (verify,) = [run for run in runs if "verify_bundle.py" in run]
    rootonly = tmp_path / "rootonly"
    assert f" {rootonly}/trust/verify_bundle.py --bundle " in verify, verify
    assert f" --pubkey {rootonly}/keys/release.pub.pem " in verify, verify
    assert f"{tmp_path}/w/" not in verify, verify


# F55 on macOS: the .pkg postinstall refuses an older signed release as well.


def _older_signed_pkg_payload(tmp: Path) -> None:
    """The real trusted verifier, a throwaway release key, release_seq 5 installed, release_seq 4 unpacked."""
    shutil.copy2(VERIFIER, tmp / "trust" / "verify_bundle.py")
    shutil.copy2(REPO / "scripts" / "profiles.py", tmp / "trust" / "profiles.py")
    key, _, pub = _keypair(tmp)
    shutil.copy2(pub, tmp / "keys" / "release.pub.pem")
    _go_minus_w(tmp / "trust")  # copy2 keeps the umask-dependent modes of the copied files
    _go_minus_w(tmp / "keys")
    shutil.rmtree(tmp / "prefix" / "bundle")
    _bundle(tmp / "prefix" / "bundle", key, release_seq=4)
    (tmp / "prefix" / "manifest.json").write_text(
        json.dumps({"profile": "test-profile", "release_seq": 5}), encoding="utf-8"
    )


def test_f55_pkg_postinstall_refuses_an_older_signed_release(tmp_path: Path) -> None:
    proc, runs, _ = _run_pkg(
        tmp_path, PKG_POSTINSTALL, _python_org, _find_as_root(tmp_path), tweak=_older_signed_pkg_payload
    )
    out = proc.stdout + proc.stderr
    assert proc.returncode == 1, out
    assert "FAIL: rollback refused" in proc.stdout, out
    assert "bundle verification PASSED" not in proc.stdout, out
    assert "is an OLDER release than the one installed" in proc.stderr, out
    assert f"sudo touch {tmp_path / 'etc' / 'allow-downgrade'}" in proc.stderr, out
    (verify,) = [run for run in runs if "verify_bundle.py" in run]
    assert f"--installed-manifest {tmp_path / 'prefix' / 'manifest.json'}" in verify, verify


def _pkg_argv_recorder(tmp: Path) -> None:
    (tmp / "trust" / "verify_bundle.py").write_text(
        "import json, sys\n"
        f"open({str(tmp / 'verifier-argv.jsonl')!r}, 'a').write(json.dumps(sys.argv[1:]) + '\\n')\n"
        "print('FAIL: stub verifier')\n"
        "sys.exit(1)\n",
        encoding="utf-8",
    )


def test_f55_pkg_postinstall_honours_a_root_owned_downgrade_flag_once(tmp_path: Path) -> None:
    """The Installer drops the caller's environment, so the override is a flag file root must create."""
    flag = tmp_path / "etc" / "allow-downgrade"
    manifest_arg = ["--installed-manifest", str(tmp_path / "prefix" / "manifest.json")]

    def plain(tmp: Path) -> None:
        _pkg_argv_recorder(tmp)

    def flagged(tmp: Path) -> None:
        _pkg_argv_recorder(tmp)
        _config_dir(tmp)
        flag.write_text("", encoding="utf-8")

    def linked(tmp: Path) -> None:
        _pkg_argv_recorder(tmp)
        _config_dir(tmp)
        (tmp / "somewhere").write_text("", encoding="utf-8")
        flag.symlink_to(tmp / "somewhere")

    for tweak, expected in ((plain, manifest_arg), (flagged, [*manifest_arg, "--allow-downgrade"]),
                            (plain, manifest_arg), (linked, manifest_arg)):
        shutil.rmtree(tmp_path / "host", ignore_errors=True)
        proc, _, _ = _run_pkg(tmp_path, PKG_POSTINSTALL, _python_org, _find_as_root(tmp_path), tweak=tweak)
        assert proc.returncode == 1, proc.stdout + proc.stderr
        argv = _recorded(tmp_path / "verifier-argv.jsonl")[-1]
        assert argv[:2] == ["--bundle", str(tmp_path / "prefix" / "bundle")], argv
        assert argv[4:] == expected, (tweak.__name__, argv)
        assert not flag.exists() and not flag.is_symlink(), "the flag is used once and removed"


@_NOT_ROOT
@pytest.mark.parametrize("script", [PKG_PREINSTALL, PKG_POSTINSTALL], ids=["preinstall", "postinstall"])
def test_f55_a_failed_install_attempt_still_uses_up_the_downgrade_flag(tmp_path: Path, script: Path) -> None:
    """The flag authorises one install attempt. Left armed by an attempt that failed before the
    verifier ran, it would let a later, unrelated older .pkg downgrade without a word."""
    flag = tmp_path / "etc" / "allow-downgrade"

    def armed(tmp: Path) -> None:
        _config_dir(tmp)
        flag.write_text("", encoding="utf-8")

    # the real find: the test account's interpreter is refused before anything runs
    proc, runs, _ = _run_pkg(tmp_path, script, _python_org, _real_find(tmp_path), tweak=armed)
    assert proc.returncode == 1 and runs == [], proc.stdout + proc.stderr
    assert not flag.exists(), "a failed attempt must not leave the downgrade flag armed"


def test_f55_pkg_preinstall_leaves_the_flag_for_its_own_postinstall(tmp_path: Path) -> None:
    flag = tmp_path / "etc" / "allow-downgrade"

    def armed(tmp: Path) -> None:
        _config_dir(tmp)
        flag.write_text("", encoding="utf-8")

    proc, _, _ = _run_pkg(tmp_path, PKG_PREINSTALL, _python_org, _find_as_root(tmp_path), tweak=armed)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert flag.exists(), "the postinstall of this same attempt reads it"


def test_f55_pkg_postinstall_names_the_flag_when_the_installed_manifest_is_unreadable(tmp_path: Path) -> None:
    """The verifier stops ('rollback check impossible') and suggests --allow-downgrade, which a
    .pkg cannot pass: the admin needs the flag file, not 'the payload may be tampered'."""
    def corrupt(tmp: Path) -> None:
        _older_signed_pkg_payload(tmp)
        (tmp / "prefix" / "manifest.json").write_text("{not json", encoding="utf-8")

    proc, _, _ = _run_pkg(tmp_path, PKG_POSTINSTALL, _python_org, _find_as_root(tmp_path), tweak=corrupt)
    assert proc.returncode == 1 and "bundle verification PASSED" not in proc.stdout, proc.stdout
    assert "FAIL: rollback check impossible" in proc.stdout, proc.stdout
    assert f"sudo touch {tmp_path / 'etc' / 'allow-downgrade'}" in proc.stderr, proc.stderr
    assert "may be tampered" not in proc.stderr, proc.stderr


def _config_dir(tmp: Path, mode: int = 0o755) -> Path:
    """The sandbox's /etc/universal-db-mcp with an explicit mode (Debian's umask 002 would make a new
    directory group-writable)."""
    config = tmp / "etc"
    config.mkdir(exist_ok=True)
    config.chmod(mode)
    return config


def _payload_release_seq(tmp: Path, script: Path, seq: str) -> None:
    """What build_pkg.sh does: write the payload's release_seq into the sandboxed pkg script."""
    sandbox = tmp / f"{script.name}_sbx.sh"
    text, count = re.subn(
        r'^PAYLOAD_RELEASE_SEQ=""$', f'PAYLOAD_RELEASE_SEQ="{seq}"', sandbox.read_text(encoding="utf-8"), flags=re.M
    )
    assert count == 1, script.name
    sandbox.write_text(text, encoding="utf-8")


@_NOT_ROOT
@pytest.mark.parametrize(
    ("case", "honoured"),
    [
        ("names-this-release", True),
        ("names-another-release", False),
        ("empty", False),
        ("second-link", False),
        ("config-dir-world-writable", False),
        ("config-dir-sticky", False),
        ("config-dir-group-writable", False),
    ],
)
def test_f55_the_downgrade_flag_counts_only_when_root_alone_wrote_it_for_this_release(
    tmp_path: Path, case: str, honoured: bool
) -> None:
    """The flag names the release_seq it authorises (a flag left from an earlier attempt cannot
    authorise another package), and it counts only as a single-link root-owned file in a directory
    root alone can write: in a sticky world-writable one any account can hard-link a root-owned
    file under that name. The key directory's check does not cover it when keys/ is a symlink."""
    flag = tmp_path / "etc" / "allow-downgrade"

    def arrange(tmp: Path) -> None:
        _pkg_argv_recorder(tmp)
        _payload_release_seq(tmp, PKG_POSTINSTALL, "4")
        modes = {"config-dir-world-writable": 0o777, "config-dir-sticky": 0o1777, "config-dir-group-writable": 0o775}
        config = _config_dir(tmp, modes.get(case, 0o755))
        if case == "second-link":
            (config / "kept").write_text("4\n", encoding="utf-8")
            os.link(config / "kept", flag)
        else:
            flag.write_text({"names-another-release": "3\n", "empty": ""}.get(case, "4\n"), encoding="utf-8")

    proc, _, _ = _run_pkg(tmp_path, PKG_POSTINSTALL, _python_org, _find_as_root(tmp_path), tweak=arrange)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    argv = _recorded(tmp_path / "verifier-argv.jsonl")[-1]
    assert ("--allow-downgrade" in argv) is honoured, (case, argv)
    assert not flag.exists(), "used once and removed"


@_NOT_ROOT
@pytest.mark.parametrize(
    ("case", "honoured"), [("root-alone", True), ("flag-not-root", False), ("ancestor-not-root", False)]
)
def test_f55_the_downgrade_flag_counts_only_when_root_owns_it_and_every_directory_above_it(
    tmp_path: Path, case: str, honoured: bool
) -> None:
    """The configuration directory is reached through a link here, so the one directory above it
    that is not root's is looked at by the flag check alone (the trust material has its own)."""
    flag = tmp_path / "etc" / "allow-downgrade"
    nest = tmp_path / "nest"
    keep_owner = {"flag-not-root": nest / "etc" / "allow-downgrade", "ancestor-not-root": nest}.get(case)
    find = _find_as_root_except(tmp_path, keep_owner) if keep_owner else _find_as_root(tmp_path)

    def arrange(tmp: Path) -> None:
        _pkg_argv_recorder(tmp)
        _payload_release_seq(tmp, PKG_POSTINSTALL, "4")
        (nest / "etc").mkdir(parents=True)
        nest.chmod(0o755)
        (nest / "etc").chmod(0o755)
        (tmp / "etc").symlink_to(nest / "etc")
        flag.write_text("4\n", encoding="utf-8")

    proc, _, _ = _run_pkg(tmp_path, PKG_POSTINSTALL, _python_org, find, tweak=arrange)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    argv = _recorded(tmp_path / "verifier-argv.jsonl")[-1]
    assert ("--allow-downgrade" in argv) is honoured, (case, argv)
    assert not (nest / "etc" / "allow-downgrade").exists(), "used once and removed"


def test_f55_pkg_postinstall_names_this_release_in_the_downgrade_command(tmp_path: Path) -> None:
    def older(tmp: Path) -> None:
        _older_signed_pkg_payload(tmp)
        _payload_release_seq(tmp, PKG_POSTINSTALL, "4")

    proc, _, _ = _run_pkg(tmp_path, PKG_POSTINSTALL, _python_org, _find_as_root(tmp_path), tweak=older)
    assert proc.returncode == 1 and "FAIL: rollback refused" in proc.stdout, proc.stdout + proc.stderr
    assert f"echo 4 | sudo tee {tmp_path / 'etc' / 'allow-downgrade'}" in proc.stderr, proc.stderr


def _installed_release(installed: int | str | None, flag: str | None) -> Any:
    """Release_seq 4 in the package; *installed* in the installed manifest ("absent": none yet)."""

    def arrange(tmp: Path) -> None:
        _payload_release_seq(tmp, PKG_PREINSTALL, "4")
        if installed != "absent":
            manifest: dict[str, Any] = {"profile": "test-profile"}
            if installed is not None:
                manifest["release_seq"] = installed
            (tmp / "prefix" / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        if flag is not None:
            (_config_dir(tmp) / "allow-downgrade").write_text(flag, encoding="utf-8")

    return arrange


@pytest.mark.parametrize(
    ("installed", "flag", "refused"),
    [
        (5, None, True),
        (5, "4\n", False),
        (5, "3\n", True),
        (5, "", True),
        (4, None, False),
        (3, None, False),
        (None, None, False),  # predates release_seq: the verifier orders it in postinstall
        ("absent", None, False),  # a first install
    ],
    ids=["older", "older-flagged", "flag-for-another", "flag-empty", "same", "newer", "unsequenced", "first"],
)
def test_f55_pkg_preinstall_refuses_an_older_release_before_the_payload_lands(
    tmp_path: Path, installed: int | str | None, flag: str | None, refused: bool
) -> None:
    """Refused in postinstall, an older package has already written its plist and share/ files over
    the newer ones (the older plist takes effect at the next boot, over the newer venv)."""
    proc, _, _ = _run_pkg(
        tmp_path, PKG_PREINSTALL, _python_org, _find_as_root(tmp_path), tweak=_installed_release(installed, flag)
    )
    out = proc.stdout + proc.stderr
    path = tmp_path / "etc" / "allow-downgrade"
    if not refused:
        assert proc.returncode == 0, out
        assert path.exists() is (flag is not None), "the postinstall of this same attempt reads the flag"
        return
    assert proc.returncode == 1, out
    assert f"release_seq 4, OLDER than the installed release_seq {installed}" in proc.stderr, out
    assert f"echo 4 | sudo tee {path}" in proc.stderr, out
    assert not path.exists(), "a failed attempt uses the flag up"


_BUILD_PKG = REPO / "scripts" / "package" / "build_pkg.sh"


@pytest.mark.skipif(sys.platform != "darwin", reason="build_pkg.sh is macOS-only (BSD sed -i '', pkgbuild)")
def test_f55_build_pkg_writes_the_payload_release_seq_into_the_pkg_scripts(tmp_path: Path) -> None:
    key, _, pub = _keypair(tmp_path)
    bundle = _bundle(tmp_path / "bundle", key, release="0.1.0", release_seq=7, profile="macos-arm64-cp312")
    shims, capture = tmp_path / "shims", tmp_path / "scripts-captured"
    shims.mkdir()
    (shims / "pkgbuild").write_text(
        '#!/bin/bash\nwhile [ $# -gt 1 ]; do [ "$1" = --scripts ] && cp -Rp "$2" "' + str(capture) + '"; shift; done\n'
        'echo pkg > "$1"\n',
        encoding="utf-8",
    )
    (shims / "productbuild").write_text('#!/bin/bash\nfor last; do :; done\necho pkg > "$last"\n', encoding="utf-8")
    for tool in ("pkgbuild", "productbuild"):
        (shims / tool).chmod(0o755)
    env = {k: v for k, v in os.environ.items() if not k.startswith("UDBMCP_")}
    env.update(
        PATH=f"{shims}:/usr/bin:/bin:/usr/sbin:/sbin", TMPDIR=str(tmp_path), UDBMCP_PYTHON=sys.executable,
        UDBMCP_PACKAGE_EVIDENCE_DIR=str(tmp_path / "evidence"),
    )
    proc = subprocess.run(  # noqa: S603 - repo script under test, pkgbuild/productbuild mocked
        ["/bin/bash", str(_BUILD_PKG), str(bundle), "--pubkey", str(pub), "--out", str(tmp_path / "dist")],
        env=env, capture_output=True, text=True, timeout=300, check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    for script in (PKG_PREINSTALL, PKG_POSTINSTALL):
        built = capture / script.name
        assert os.access(built, os.X_OK), script.name
        source = script.read_text(encoding="utf-8")
        assert source.count('\nPAYLOAD_RELEASE_SEQ=""\n') == 1, script.name  # the repository copy stays generic
        expected = source.replace('\nPAYLOAD_RELEASE_SEQ=""\n', '\nPAYLOAD_RELEASE_SEQ="7"\n')
        assert built.read_text(encoding="utf-8") == expected, script.name


def test_f55_pkg_scripts_share_one_downgrade_flag_block() -> None:
    blocks = []
    for script in (PKG_PREINSTALL, PKG_POSTINSTALL):
        text = script.read_text(encoding="utf-8")
        start = text.index("# >>> one-shot downgrade flag")
        blocks.append(text[start : text.index("# <<< one-shot downgrade flag", start)])
    assert blocks[0] == blocks[1], "preinstall and postinstall must honour the flag with the same code"


def test_f55_pkg_postinstall_refuses_a_trusted_verifier_that_predates_the_rollback_check(tmp_path: Path) -> None:
    def outdated(tmp: Path) -> None:
        (tmp / "trust" / "verify_bundle.py").write_text(
            'ap.add_argument("--pubkey", default=None)\nprint("bundle verification PASSED")\n', encoding="utf-8"
        )

    proc, runs, _ = _run_pkg(tmp_path, PKG_POSTINSTALL, _python_org, _find_as_root(tmp_path), tweak=outdated)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "OUTDATED" in proc.stderr and "--installed-manifest" in proc.stderr, proc.stderr
    assert not [run for run in runs if "verify_bundle.py" in run], runs


def test_f55_pkg_postinstall_names_an_outdated_verifier_its_argparse_gives_away(tmp_path: Path) -> None:
    def outdated(tmp: Path) -> None:
        (tmp / "trust" / "verify_bundle.py").write_text(_OUTDATED_VERIFIER_NAMING_THE_OPTION, encoding="utf-8")

    proc, _runs, _ = _run_pkg(tmp_path, PKG_POSTINSTALL, _python_org, _find_as_root(tmp_path), tweak=outdated)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "is an OUTDATED copy (no --installed-manifest option)" in proc.stderr, proc.stderr
    assert "may be tampered" not in proc.stderr, proc.stderr


def _pth_leading_out(kind: str) -> Any:
    """The python.org layout with a .pth file whose CONTENTS lead out of the installation.

    The ownership checks prove who owns the .pth, not what it names: a path line puts a directory
    another account writes on sys.path (a sitecustomize.py there is imported) and an import line
    runs code. An editable `sudo pip install -e` writes the first kind; admin-group malware can plant
    either while the framework is admin-writable, and chown -R keeps it. site.py reads them unless
    the interpreter runs with -S."""

    def layout(host: Path, marker: Path) -> tuple[str, Path]:
        slot, candidate = _python_org(host, marker)
        attacker = host / "attacker"
        attacker.mkdir()
        (attacker / "sitecustomize.py").write_text("import os\n", encoding="utf-8")
        site = host / _SITE
        if kind == "path-line":
            (site / "__editable__.tool-0.1.pth").write_text(f"{attacker}\n", encoding="utf-8")
        else:
            (site / "zz_hook.pth").write_text(
                f"import runpy; runpy.run_path({str(attacker / 'sitecustomize.py')!r})\n", encoding="utf-8"
            )
        return slot, candidate

    return layout


@PKG_SCRIPTS
@pytest.mark.parametrize(
    "layout",
    [_python_org, _homebrew, _pth_leading_out("path-line"), _pth_leading_out("import-line")],
    ids=["python.org", "homebrew", "pth-path-line", "pth-import-line"],
)
def test_f53_pkg_scripts_accept_a_root_only_interpreter_and_run_it_isolated(
    tmp_path: Path, script: Path, layout: Any
) -> None:
    """Every root-side run of the base interpreter is -I -S: site.py never reads its site-packages, so
    a .pth there (whatever it names) is inert; see test_f53_isolated_mode_alone_still_reads_pth_files."""
    proc, runs, host = _run_pkg(tmp_path, script, layout, _find_as_root(tmp_path))
    out = proc.stdout + proc.stderr
    if script == PKG_PREINSTALL:
        assert proc.returncode == 0, out
    else:  # accepted: it went on to run the (refusing) trusted verifier under the interpreter
        assert proc.returncode == 1 and "FAIL: bundle verification FAILED" in out and "SIGNATURE MISMATCH" in out, out
        assert any("verify_bundle.py --bundle" in run for run in runs), runs
    binary = next(p for p in host.rglob("python3.12") if p.is_file() and not p.is_symlink())
    assert runs, "the accepted interpreter never ran"
    for run in runs:
        executable, _, args = run.partition(" ")
        assert executable == os.path.realpath(binary), f"a symlinked candidate must run as its resolved binary: {run}"
        assert args.startswith("-I -S "), f"root-side python must run isolated and without site.py: {run}"


def test_f53_isolated_mode_alone_still_reads_pth_files(tmp_path: Path) -> None:
    """Why root runs the BASE interpreter with -I -S: -I drops PYTHON* variables, the user site and the
    working directory, but site.py still reads the installation's own site-packages, whose .pth files
    put directories on sys.path and run their `import` lines. -S skips site.py altogether."""
    env_dir = tmp_path / "py"
    subprocess.run(  # noqa: S603 - a throwaway interpreter tree for this test
        [sys.executable, "-m", "venv", "--without-pip", str(env_dir)], check=True, capture_output=True, timeout=120
    )
    (site,) = (env_dir / "lib").glob("python3*/site-packages")
    outside, ran = tmp_path / "outside", tmp_path / "import-line-ran"
    outside.mkdir()
    (site / "__editable__.tool-0.1.pth").write_text(f"{outside}\n", encoding="utf-8")
    (site / "zz_hook.pth").write_text(f"import os; open({str(ran)!r}, 'w').close()\n", encoding="utf-8")
    probe = "import sys; print(sys.flags.isolated, sys.flags.no_site, *sys.path, sep='\\n')"
    for flags, loaded in ((["-I"], True), (["-I", "-S"], False)):
        ran.unlink(missing_ok=True)
        proc = subprocess.run(  # noqa: S603
            [str(env_dir / "bin" / "python"), *flags, "-c", probe], cwd="/", capture_output=True, text=True,
            timeout=60, check=True,
        )
        isolated, no_site, *path = proc.stdout.splitlines()
        assert (isolated, no_site) == ("1", str(int(not loaded))), proc.stdout
        assert (str(outside) in path) is loaded, (flags, path)
        assert ran.exists() is loaded, flags


_AUDIT_REPAIR_START = "# >>> hand root-owned audit files back"
_AUDIT_REPAIR_END = "# <<< hand root-owned audit files back"


def _audit_repair_block(script: Path) -> str:
    text = script.read_text(encoding="utf-8")
    start = text.index(_AUDIT_REPAIR_START)
    return text[text.index("\n", start) + 1 : text.index(_AUDIT_REPAIR_END, start)]


@_NOT_ROOT
def test_upgrade_hands_root_owned_audit_files_back_on_macos_too(tmp_path: Path) -> None:
    """CGR#84 in the .pkg: the same repair as the deb postinst, after step 6 made the log
    directory the service account's and before launchd starts the daemon."""
    import pwd

    deb_block, pkg_block = _audit_repair_block(POSTINST), _audit_repair_block(PKG_POSTINSTALL)
    python = pkg_block.split("\n", 1)[1].split("\nPYEOF\n", 1)[0]
    assert deb_block.split("\n", 1)[1].split("\nPYEOF\n", 1)[0] == python, "one repair, identical in both packages"
    call = pkg_block.split("\n", 1)[0].strip()
    assert call.startswith('"$PY" -I -S - "$LOG_DIR" "$SERVICE_USER" <<\'PYEOF\' || echo "WARNING: '), call
    text = PKG_POSTINSTALL.read_text(encoding="utf-8")
    at = text.index(_AUDIT_REPAIR_START)
    assert text.index('-m 0750 "$STATE_DIR" "$LOG_DIR"') < at < text.index('launchctl bootstrap system "$PLIST"')
    logs = tmp_path / "log"
    logs.mkdir()
    for name in ("audit.jsonl", "audit.jsonl.lock", "audit.jsonl.5", "udbmcp.err.log"):
        (logs / name).write_text("x\n", encoding="utf-8")
    other = tmp_path / "other"
    other.write_text("y\n", encoding="utf-8")
    os.link(other, logs / "audit.jsonl.1")
    (logs / "audit.jsonl.2").symlink_to(other)
    os.mkfifo(logs / "audit.jsonl.3")
    (logs / "audit.jsonl.5").chmod(0o444)  # read-only for its owner, but the writer opens it read-write
    # the service account links a name to a file only root may change (/etc/sudoers): root's,
    # with one link, so only O_NOFOLLOW keeps the repair from handing it over
    sudoers = tmp_path / "sudoers"
    sudoers.write_text("root ALL=(ALL) ALL\n", encoding="utf-8")
    sudoers.chmod(0o440)
    (logs / "audit.jsonl.9").symlink_to(sudoers)
    me = pwd.getpwuid(os.getuid()).pw_name
    proc = _run_audit_repair(_audit_repair_python(os.getuid()), logs, me)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.splitlines() == [
        f"==> {logs}/{name} was owned by root; handed back to {me}"
        for name in ("audit.jsonl", "audit.jsonl.5", "audit.jsonl.lock")
    ]
    assert (logs / "audit.jsonl.5").stat().st_mode & 0o777 == 0o600  # the writer's own mode
    assert (logs / "udbmcp.err.log").stat().st_mode & 0o777 == 0o664  # not an audit file: untouched
    assert sudoers.stat().st_mode & 0o777 == 0o440 and sudoers.stat().st_nlink == 1


def _audit_repair_python(uid: int) -> str:
    """The repair's python (identical in both packages), with *uid* standing in for root's."""
    python = _audit_repair_block(PKG_POSTINSTALL).split("\n", 1)[1].split("\nPYEOF\n", 1)[0]
    assert python.count("ROOT = 0\n") == 1
    return python.replace("ROOT = 0\n", f"ROOT = {uid}\n")


def _run_audit_repair(python: str, log_dir: Path, account: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - the postinstalls' own repair code
        [sys.executable, "-I", "-S", "-", str(log_dir), account],
        input=python,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


@_NOT_ROOT
def test_the_audit_repair_follows_only_a_log_directory_link_root_made(tmp_path: Path) -> None:
    """An admin who moved the logs to a data volume links the old name to them. That link, root's
    in a root-owned directory, is followed; one another account could have made or re-pointed is
    not. Either way the refusal is one line, never a traceback."""
    import pwd

    me = pwd.getpwuid(os.getuid()).pw_name
    real = tmp_path / "volume" / "universal-db-mcp"
    real.mkdir(parents=True)
    (real / "audit.jsonl").write_text("x\n", encoding="utf-8")
    link = tmp_path / "log"
    link.symlink_to(real)
    followed = _run_audit_repair(_audit_repair_python(os.getuid()), link, me)
    assert followed.returncode == 0, followed.stderr
    assert followed.stdout.splitlines() == [f"==> {real}/audit.jsonl was owned by root; handed back to {me}"]
    # the real root: this test account owns the link and the directory it is in
    refused = _run_audit_repair(_audit_repair_python(0), link, me)
    assert (refused.returncode, refused.stdout) == (1, ""), refused.stdout + refused.stderr
    assert refused.stderr.strip() == f"{link}: a symlink another account could have made or re-pointed"
    (tmp_path / "not-a-dir").write_text("", encoding="utf-8")
    broken = _run_audit_repair(_audit_repair_python(os.getuid()), tmp_path / "not-a-dir", me)
    assert broken.returncode == 1 and broken.stderr.strip() == f"{tmp_path}/not-a-dir: Not a directory"


@_NOT_ROOT
def test_the_audit_repair_hands_back_only_what_root_owns(tmp_path: Path) -> None:
    """With the real root's uid, a file this test account owns is another account's: left alone."""
    import pwd

    logs = tmp_path / "log"
    logs.mkdir()
    (logs / "audit.jsonl").write_text("x\n", encoding="utf-8")
    (logs / "audit.jsonl").chmod(0o640)
    proc = _run_audit_repair(_audit_repair_python(0), logs, pwd.getpwuid(os.getuid()).pw_name)
    assert (proc.returncode, proc.stdout, proc.stderr) == (0, "", "")
    assert (logs / "audit.jsonl").stat().st_mode & 0o777 == 0o640


def test_the_audit_repair_opens_the_log_directory_without_following_a_link(tmp_path: Path) -> None:
    """The name can become a link between the islink() check and the open. Skipping the check stands
    in for that race here: the open itself must refuse the link."""
    import pwd

    real = tmp_path / "elsewhere"
    real.mkdir()
    (real / "audit.jsonl").write_text("x\n", encoding="utf-8")
    (real / "audit.jsonl").chmod(0o640)
    link = tmp_path / "log"
    link.symlink_to(real)
    python = _audit_repair_python(os.getuid())
    check = "    if os.path.islink(log_dir):\n"
    assert python.count(check) == 1
    raced = python.replace(check, "    if False:  # the name became a link after this check\n")
    proc = _run_audit_repair(raced, link, pwd.getpwuid(os.getuid()).pw_name)
    assert proc.returncode == 1 and proc.stdout == "", proc.stdout + proc.stderr
    assert proc.stderr.startswith(f"{link}: "), proc.stderr
    assert (real / "audit.jsonl").stat().st_mode & 0o777 == 0o640


_AUDIT_REPAIR_WARNING = (
    '|| echo "WARNING: could not hand root-owned audit files in $LOG_DIR back to the service account" >&2'
)
_SERVICE_LOG_DIR = "LOG_DIR=/var/log/universal-db-mcp\n"


def test_the_audit_repair_is_one_block_in_both_packages_and_both_installers() -> None:
    """A site upgraded with the tarball's upgrade_offline.sh (or by re-running install_offline.sh)
    gets the same repair as one upgraded with the .deb or the .pkg."""
    pythons = {
        script.name: _audit_repair_block(script).split("\n", 1)[1].split("\nPYEOF\n", 1)[0]
        for script in (POSTINST, PKG_POSTINSTALL, INSTALL, UPGRADE)
    }
    assert len(set(pythons.values())) == 1, "one repair, identical in every copy"
    for script in (INSTALL, UPGRADE):
        call = _audit_repair_block(script).split("\n", 1)[0].strip()
        assert call == f'$sudo_ok "$PY" -I -S - "$LOG_DIR" udbmcp <<\'PYEOF\' {_AUDIT_REPAIR_WARNING}', call
        text = script.read_text(encoding="utf-8")
        at = text.index(_AUDIT_REPAIR_START)
        assert text.index('PY="$(command -v "$PY")"') < text.index(_SERVICE_LOG_DIR) < at
    install = INSTALL.read_text(encoding="utf-8")
    # after the log directory is (re)made the service account's
    assert install.index("install -d -o udbmcp -g udbmcp /var/lib/universal-db-mcp /var/log/universal-db-mcp") \
        < install.index(_AUDIT_REPAIR_START)
    upgrade = UPGRADE.read_text(encoding="utf-8")
    at = upgrade.index(_AUDIT_REPAIR_START)
    # with the service stopped, and before it (or the release a failed check restores) starts again
    switch = upgrade.index('$sudo_ok mv "$NEWVENV" "$TARGET/venv"')
    assert upgrade.index("systemctl stop universal-db-mcp") < at < switch
    assert all(m.start() > at for m in re.finditer(r"systemctl start universal-db-mcp", upgrade))


def _installer_audit_repair(script: Path, log_dir: Path, account: str, root: int) -> str:
    """The installer's own lines, from the log directory it names through the repair, with *log_dir*,
    *account* and the uid *root* standing in for the service's directory, account and root."""
    text = script.read_text(encoding="utf-8")
    start = text.rindex(_SERVICE_LOG_DIR, 0, text.index(_AUDIT_REPAIR_START))
    end = text.index("\n", text.index(_AUDIT_REPAIR_END, start)) + 1
    after = text[end:].split("\n", 1)[0]
    lines = text[start:end] + (after + "\n" if after.strip() == "fi" else "")
    assert lines.count(" udbmcp") in (1, 2) and lines.count("\nROOT = 0\n") == 1, lines
    return (
        lines.replace(_SERVICE_LOG_DIR, f"LOG_DIR={log_dir}\n")
        .replace(" udbmcp", f" {account}")
        .replace("\nROOT = 0\n", f"\nROOT = {root}\n")
    )


@_NOT_ROOT
@pytest.mark.parametrize("script", [INSTALL, UPGRADE], ids=["install_offline", "upgrade_offline"])
def test_the_installers_hand_root_owned_audit_files_back(tmp_path: Path, script: Path) -> None:
    """CGR#84 on the tarball path: the installer's own lines, run the way it runs them (set -euo
    pipefail, its $sudo_ok and $PY), hand back only regular single-link root-owned audit files, and
    a repair that cannot run warns without aborting the install or upgrade."""
    import pwd

    me = pwd.getpwuid(os.getuid()).pw_name
    logs = tmp_path / "log"
    logs.mkdir()
    for name in ("audit.jsonl", "audit.jsonl.lock", "audit.jsonl.1", "server.log"):
        (logs / name).write_text("x\n", encoding="utf-8")
    (logs / "audit.jsonl.1").chmod(0o444)
    sudoers = tmp_path / "sudoers"
    sudoers.write_text("root ALL=(ALL) ALL\n", encoding="utf-8")
    sudoers.chmod(0o440)
    (logs / "audit.jsonl.9").symlink_to(sudoers)

    def run(lines: str) -> subprocess.CompletedProcess[str]:
        prologue = f'set -euo pipefail\nsudo_ok=""\nPY="{sys.executable}"\n'
        return subprocess.run(  # noqa: S603 - the installer's own lines
            ["/bin/bash", "-c", prologue + lines + 'echo "==> carried on"\n'],
            capture_output=True, text=True, timeout=60, check=False,
        )

    proc = run(_installer_audit_repair(script, logs, me, os.getuid()))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.stdout.splitlines() == [
        *(f"==> {logs}/{name} was owned by root; handed back to {me}"
          for name in ("audit.jsonl", "audit.jsonl.1", "audit.jsonl.lock")),
        "==> carried on",
    ], proc.stdout
    assert (logs / "audit.jsonl.1").stat().st_mode & 0o777 == 0o600
    assert (logs / "server.log").stat().st_mode & 0o777 == 0o664
    assert sudoers.stat().st_mode & 0o777 == 0o440
    # the real root: a log directory this account links elsewhere is refused, with a warning only
    link = tmp_path / "linked-log"
    link.symlink_to(logs)
    warned = run(_installer_audit_repair(script, link, me, 0))
    assert warned.returncode == 0 and warned.stdout == "==> carried on\n", warned.stdout + warned.stderr
    assert "WARNING: could not hand root-owned audit files" in warned.stderr, warned.stderr


_DEMO_DB_START = "# >>> create the demo database"
_DEMO_DB_END = "# <<< create the demo database"


def _demo_db_block(script: Path) -> tuple[str, str]:
    """(the shell call, the python it runs) of the demo-database step."""
    text = script.read_text(encoding="utf-8")
    start = text.index(_DEMO_DB_START)
    block = text[text.index("\n", start) + 1 : text.index(_DEMO_DB_END, start)]
    call, rest = block.split("\n", 1)
    return call.strip(), rest.split("\nPYEOF\n", 1)[0]


def _run_demo_db(python: str, state: Path) -> subprocess.CompletedProcess[str]:
    import pwd

    me = pwd.getpwuid(os.getuid()).pw_name  # the test account stands in for the service account
    return subprocess.run(  # noqa: S603 - the install scripts' own demo-database code
        [sys.executable, "-I", "-S", "-", str(state), me], input=python, capture_output=True, text=True,
        timeout=60, check=False,
    )


@_NOT_ROOT
@pytest.mark.parametrize("planted", ["dangling-link", "link-to-a-file", "demo-dir-link", "fifo", "none", "seeded"])
def test_the_demo_database_step_never_follows_what_the_service_account_planted(tmp_path: Path, planted: str) -> None:
    """Root creates the demo database inside the state directory, which the service account owns: a
    symlink planted there must not make root create (and hand over) a file anywhere else."""
    (pkg_call, python), (deb_call, deb_python) = _demo_db_block(PKG_POSTINSTALL), _demo_db_block(INSTALL)
    assert python == deb_python, "one demo-database step, identical in both installers"
    assert pkg_call.startswith('"$PY" -I -S - "$STATE_DIR" "$SERVICE_USER" <<\'PYEOF\''), pkg_call
    assert deb_call.startswith('$sudo_ok "$PY" -I -S - /var/lib/universal-db-mcp udbmcp <<\'PYEOF\''), deb_call
    state, elsewhere = tmp_path / "state", tmp_path / "rootonly"
    (state / "demo").mkdir(parents=True)
    elsewhere.mkdir()
    victim = elsewhere / "victim.conf"
    db = state / "demo" / "finlink_demo.db"
    if planted == "dangling-link":
        db.symlink_to(victim)
    elif planted == "link-to-a-file":
        victim.write_text("root's\n", encoding="utf-8")
        victim.chmod(0o600)
        db.symlink_to(victim)
    elif planted == "demo-dir-link":
        (state / "demo").rmdir()
        (state / "demo").symlink_to(elsewhere)
        db = elsewhere / "finlink_demo.db"
    elif planted == "fifo":
        os.mkfifo(db)
    elif planted == "seeded":
        db.write_bytes(b"SQLite format 3\0seeded")
    proc = _run_demo_db(python, state)
    if planted in ("none", "seeded"):
        assert proc.returncode == 0, proc.stderr
        assert db.is_file() and not db.is_symlink()
        assert db.read_bytes() == (b"SQLite format 3\0seeded" if planted == "seeded" else b"")
        if planted == "none":  # an empty file is an empty SQLite database
            assert db.stat().st_mode & 0o777 == 0o640 and (state / "demo").stat().st_mode & 0o777 == 0o750
        return
    assert proc.returncode != 0, "the step must report that it did not create the database"
    assert not victim.exists() or victim.read_text(encoding="utf-8") == "root's\n"
    if victim.exists():
        assert victim.stat().st_mode & 0o777 == 0o600, "nothing outside the demo directory is chmod'ed"
    assert not (elsewhere / "finlink_demo.db").exists()


def test_f53_pkg_scripts_share_one_interpreter_block() -> None:
    blocks = []
    for script in (PKG_PREINSTALL, PKG_POSTINSTALL):
        text = script.read_text(encoding="utf-8")
        start = text.index("# >>> root-owned CPython 3.12")
        blocks.append(text[start : text.index("# <<< root-owned CPython 3.12", start)])
        assert re.findall(r'^(\w+_PY)="', blocks[-1], re.MULTILINE) == list(PY_CANDIDATES)
    assert blocks[0] == blocks[1], "preinstall and postinstall must select the interpreter with the same code"


def test_f53_pkg_scripts_initialise_every_array_they_declare() -> None:
    """Under set -u, bash 4.4+ (Ubuntu CI's 5.2) treats ${#a[@]} of a declared but never assigned
    array as unbound, while macOS /bin/bash 3.2 prints 0: 'local -a a' alone passes on the Mac
    and aborts the script on Linux."""
    for script in (PKG_PREINSTALL, PKG_POSTINSTALL):
        code = [ln for ln in script.read_text(encoding="utf-8").splitlines() if not ln.lstrip().startswith("#")]
        for line in code:
            for decl in re.findall(r"\b(?:local|declare) -a ([^;]+)", line):
                names = decl.split()
                assert names and all(re.fullmatch(r"\w+=\(.*\)", name) for name in names), (
                    f"{script.name}: every array must be initialised ('name=()'): {line.strip()}"
                )


def test_f53_pkg_scripts_search_the_system_directories_first() -> None:
    for script in (PKG_PREINSTALL, PKG_POSTINSTALL):
        (path,) = re.findall(r'^PATH="([^"]*)"$', script.read_text(encoding="utf-8"), re.MULTILINE)
        dirs = path.split(":")
        assert dirs[:4] == ["/usr/bin", "/bin", "/usr/sbin", "/sbin"], (script.name, path)
        assert "/opt/homebrew/bin" not in dirs and "$PATH" not in path, (script.name, path)


def test_f53_every_root_side_python_in_the_pkg_scripts_runs_isolated() -> None:
    for script in (PKG_PREINSTALL, PKG_POSTINSTALL):
        code = [ln for ln in script.read_text(encoding="utf-8").splitlines() if not ln.lstrip().startswith("#")]
        calls = [ln for ln in code if re.search(r'"\$(PY|PY_REAL|VENV/bin/python)" -', ln)]
        assert calls, script.name
        for line in calls:
            assert re.search(r'"\$(PY|PY_REAL)" -I -S |"\$VENV/bin/python" -I ', line), f"{script.name}: {line.strip()}"
        assert not [ln for ln in code if re.search(r"(^|[\s;(|&])python3(\.12)?\s", ln)], script.name
    assert 'VEXEC="$PY -I -S"' in PKG_POSTINSTALL.read_text(encoding="utf-8")


ROOT_RUN_SHELL = [
    INSTALL, UPGRADE, ROLLBACK, LOADER, DOCTOR_SH, POSTINST, PREINST, BOOTSTRAP, PKG_PREINSTALL, PKG_POSTINSTALL,
    *sorted((REPO / "scripts" / "lib").glob("*.sh")),
]
# A python the script can start: python3[.12], $PY/$py/$PY_REAL, or a path ending in bin/python[3[.12]].
_PY_TOKEN = re.compile(r"\$\{?(?:PY_REAL|PY|py)\b\}?|[^\s\"'=]*/bin/python[0-9.]*\b|\bpython3(?:\.12)?(?![\w./])")
# What may stand right before a command: the line start, an operator, a keyword or prefix command, VAR=value.
_COMMAND_START = re.compile(
    r"(?:^|[;&|(!{]|\$\(|\b(?:then|do|else|exec|sudo|if|env|_udbmcp_rootrun)|\$sudo_ok"
    r"|\w+=(?:\"[^\"]*\"|'[^']*'|[^\s\"']+))\s*$"
)
_PYTHON_OR_TEXT_HEREDOC = re.compile(r"<<-?\s*'?(PYEOF|EOF)'?")


def _open_string_after(line: str, open_string: bool) -> bool:
    """Whether a double-quoted string is still open after *line* (quotes inside single quotes, escaped
    quotes and a trailing # comment do not count)."""
    in_single, i = False, 0
    while i < len(line):
        char = line[i]
        if in_single:
            in_single = char != "'"
        elif char == "\\":
            i += 1
        elif char == '"':
            open_string = not open_string
        elif not open_string and char == "'":
            in_single = True
        elif not open_string and char == "#" and (i == 0 or line[i - 1].isspace()):
            break
        i += 1
    return open_string


def _python_calls(text: str) -> list[tuple[str, str, list[str]]]:
    """(line, interpreter, the words after it) for every python the shell text starts, whatever
    follows it: a call is an interpreter in command position, or the command a VAR="python ..."
    string holds. Comments, echoed text, the lines of a message string, heredoc text, paths
    assigned or tested and arguments are not."""
    calls: list[tuple[str, str, list[str]]] = []
    skip_until = None
    open_string = False
    for raw in text.splitlines():
        line = raw.strip()
        if skip_until is not None:
            skip_until = None if line == skip_until else skip_until
            continue
        heredoc = _PYTHON_OR_TEXT_HEREDOC.search(raw)
        skip_until = heredoc.group(1) if heredoc else None
        inside_string, open_string = open_string, _open_string_after(raw, open_string)
        if inside_string or line.startswith(("#", "echo ")):
            continue
        for match in _PY_TOKEN.finditer(raw):
            before, after = raw[: match.start()], raw[match.end() :]
            if re.search(r'\w+="$', before):  # VAR="<python> ...": a command kept in a variable
                if after.startswith('"'):
                    continue  # VAR="<path>": a path, not a command
                words = after.split('"', 1)[0].split()
            elif _COMMAND_START.search(before.removesuffix('"')):
                words = after.removeprefix('"').split()
            else:
                continue
            calls.append((line, match.group(0), words))
    return calls


def test_f53_the_python_call_scan_sees_every_form_of_call() -> None:
    """The scan must not depend on an option following the interpreter: a call without one is the
    very call that is not isolated."""
    text = "\n".join([
        'python3 "$V"',
        '"$PY" "$x"',
        '"$VENV/bin/python3" -m x',
        'out="$(python3.12 "$T/verify_bundle.py" --verify-file "$S")"',
        'VEXEC="python3"; VEXEC2="python3 -I"',
        "$sudo_ok env A=b \"$TARGET/venv/bin/python\" -I -m x",
        "command -v python3 >/dev/null || PY=python3.12",
        'PY="$(command -v "$PY")"; PY="$PY_REAL"',
        'if [ -x "$VENV/bin/python" ] && [ -e "$prefix/lib/python3.12/site-packages" ]; then',
        'udbmcp_install_os_packages "$BUNDLE" "$PY" "$sudo_ok"',
        'echo "run: $VENV/bin/python -m universal_db_mcp doctor"',
        "cat >&2 <<'EOF'",
        "python3 exits 0 on an empty script",
        "EOF",
    ])
    assert [(interpreter, words[:1]) for _, interpreter, words in _python_calls(text)] == [
        ("python3", ['"$V"']),
        ("$PY", ['"$x"']),
        ("$VENV/bin/python3", ["-m"]),
        ("python3.12", ['"$T/verify_bundle.py"']),
        ("python3", ["-I"]),
        ("$TARGET/venv/bin/python", ["-I"]),
    ]


# Without -I yet: tests/unit/test_audit_batch_2.py (another group's) pins these two lines verbatim.
# They run from / with no caller PYTHON* variables (the script drops them first, see
# test_f53_root_run_install_scripts_drop_python_variables_before_their_first_python).
_PENDING_ISOLATION = {
    UPGRADE.name: [
        '$sudo_ok env UDBMCP_CONFIG=/etc/universal-db-mcp/config.yaml "$NEWVENV/bin/python" -m universal_db_mcp '
        "doctor \\",
        'if ! $sudo_ok "$TARGET/venv/bin/python" -m universal_db_mcp doctor \\',
    ],
}


@pytest.mark.parametrize("script", ROOT_RUN_SHELL, ids=[p.name for p in ROOT_RUN_SHELL])
def test_f53_every_python_the_root_run_shell_scripts_start_runs_isolated(script: Path) -> None:
    """A root shell can carry PYTHONPATH/PYTHONSTARTUP/PYTHONHOME: without -I, python imports
    whatever they name (before -m pip, -m venv or a heredoc runs). The base interpreter also
    runs without site.py (-S): its site-packages .pth files can name code outside the
    installation (test_f53_isolated_mode_alone_still_reads_pth_files). A venv's own interpreter
    needs its site-packages, which pip filled from the verified wheelhouse, so it runs with -I."""
    calls = _python_calls(script.read_text(encoding="utf-8"))
    assert calls or script == PREINST, script.name
    required = {True: ["-I"], False: ["-I", "-S"]}  # is it a venv's interpreter?
    wrong = [
        line for line, interpreter, words in calls
        if words[: len(required["venv" in interpreter.lower()])] != required["venv" in interpreter.lower()]
    ]
    assert wrong == _PENDING_ISOLATION.get(script.name, []), script.name


def _cwd_recording_verifier(tmp_path: Path) -> tuple[Path, Path]:
    log = tmp_path / "verifier-runs.jsonl"
    stub = tmp_path / "trust" / "verify_bundle.py"
    stub.parent.mkdir(parents=True, exist_ok=True)
    stub.write_text(
        "import json, os, sys\n"
        f"open({str(log)!r}, 'a').write(json.dumps(\n"
        "    {'cwd': os.getcwd(), 'isolated': sys.flags.isolated, 'no_site': sys.flags.no_site,\n"
        "     'argv': sys.argv[1:]}) + '\\n')\n"
        "print('FAIL: stub verifier')\n"
        "sys.exit(1)\n",
        encoding="utf-8",
    )
    return stub, log


@pytest.mark.parametrize("script", [INSTALL, UPGRADE], ids=["install_offline", "upgrade_offline"])
def test_f53_install_scripts_run_python_from_root_not_from_the_operators_directory(
    tmp_path: Path, script: Path
) -> None:
    """`python -m pip` / `-m venv` put the working directory first on sys.path: as root, a pip.py
    on the stick the operator stands in would run. Relative arguments still name the same files."""
    stick = tmp_path / "stick"
    (stick / "bundle" / "requirements").mkdir(parents=True)
    for planted in ("pip.py", "venv.py", "universal_db_mcp.py"):
        (stick / planted).write_text("raise SystemExit('planted module imported as root')\n", encoding="utf-8")
    _, log = _cwd_recording_verifier(tmp_path)
    (tmp_path / "release.pub.pem").write_text("key\n", encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if not k.startswith("UDBMCP_")}
    env.update(
        PATH=f"{_shims(tmp_path)}:{os.environ.get('PATH', '')}",
        UDBMCP_RELEASE_PUBKEY="../release.pub.pem",
        UDBMCP_VERIFIER="../trust/verify_bundle.py",
        UDBMCP_STAGING_DIR=str(tmp_path / "staging"),
        TMPDIR=str(tmp_path),
    )
    extra = ["backups"] if script == UPGRADE else []
    proc = subprocess.run(  # noqa: S603 - repo script under test
        ["/bin/bash", str(script), "bundle", "target", *extra],
        cwd=stick, env=env, capture_output=True, text=True, timeout=120, check=False,
    )
    assert proc.returncode != 0 and log.exists(), proc.stdout + proc.stderr
    run = _recorded_runs(log)[-1]
    assert run["cwd"] == "/", f"python ran from the operator's directory: {run}"
    assert run["isolated"] == 1 and run["no_site"] == 1, f"the verifier must run with -I -S: {run}"
    real = os.path.realpath(stick)
    assert run["argv"][:4] == ["--bundle", f"{real}/bundle", "--pubkey", f"{real}/../release.pub.pem"], run
    assert run["argv"][4:6] == ["--installed-manifest", f"{real}/target/manifest.json"], run


def _recorded_runs(log: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]


def test_f53_install_scripts_leave_for_root_before_the_first_python() -> None:
    for script in (INSTALL, UPGRADE):
        text = script.read_text(encoding="utf-8")
        leave = text.index("\ncd /\n")
        assert leave < text.index('verify_with_proof "$'), script.name
        assert 'VEXEC="python3 -I -S"' in text, script.name


def _logging_venv_python(path: Path, log: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f'#!/bin/sh\necho "$*" >> "{log}"\nexit 0\n', encoding="utf-8")
    path.chmod(0o755)


def test_f53_rollback_runs_the_restored_venv_isolated(tmp_path: Path) -> None:
    target = tmp_path / "target"
    log = tmp_path / "venv-python.log"
    _logging_venv_python(target / "venv.previous" / "bin" / "python", log)
    (target / "venv.previous.sha256").write_text(
        f"{_sha256(target / 'venv.previous' / 'bin' / 'python')}  ./bin/python\n", encoding="utf-8"
    )
    backup = tmp_path / "backups" / "pre-upgrade-20260927T000000Z" / "universal-db-mcp"
    backup.mkdir(parents=True)
    (backup / "config.yaml").write_text("connections: {}\n", encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if not k.startswith("UDBMCP_")}
    env["UDBMCP_CONFIG_DIR"] = str(tmp_path / "etc")
    env["UDBMCP_STATE_DIR"] = str(tmp_path / "varlib")
    proc = subprocess.run(  # noqa: S603 - repo script under test
        ["/bin/bash", str(ROLLBACK), str(target), str(tmp_path / "backups"), "--restore-config"],
        env=env, capture_output=True, text=True, timeout=120, check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    runs = log.read_text(encoding="utf-8").splitlines()
    assert len(runs) == 2 and all(run.startswith("-I -m universal_db_mcp doctor") for run in runs), runs


# What a root shell may carry. -I keeps the interpreter it is given from reading them, but not
# the ensurepip child `-m venv` starts (venv runs the new interpreter without -I on purpose,
# gh-98251), nor any python a -I python starts: with PYTHONPYCACHEPREFIX, root writes and then
# reads bytecode wherever it names.
_CALLER_PYTHON_ENV = {
    "PYTHONPYCACHEPREFIX": "/nonexistent/anyone-writes/pycache",
    "PYTHONPATH": "/nonexistent/anyone-writes",
    "PYTHONSTARTUP": "/nonexistent/anyone-writes/startup.py",
    "PYTHONUSERBASE": "/nonexistent/anyone-writes/userbase",
}
_PYTHON_SCRUB = 'for _var in $(compgen -e); do case "$_var" in PYTHON*) unset "$_var" ;; esac; done'


def _env_logging_python(path: Path, log: Path, real: str | None = None) -> None:
    """A python that logs the PYTHON* variables it was started with (one 'run:' line per start),
    then runs *real*, or exits 0."""
    path.parent.mkdir(parents=True, exist_ok=True)
    names = 'env | grep "^PYTHON" | cut -d= -f1 | sort | tr "\\n" " "'
    tail = f'exec "{real}" "$@"\n' if real else "exit 0\n"
    path.write_text(f'#!/bin/sh\nprintf "run:%s\\n" "$({names})" >> "{log}"\n{tail}', encoding="utf-8")
    path.chmod(0o755)


@pytest.mark.parametrize("script", [INSTALL, UPGRADE], ids=["install_offline", "upgrade_offline"])
def test_f53_install_scripts_drop_the_callers_python_variables_before_any_python(
    tmp_path: Path, script: Path
) -> None:
    shims = tmp_path / "shims"
    shims.mkdir()
    (shims / "sudo").write_text('#!/bin/sh\nexec "$@"\n', encoding="utf-8")
    (shims / "sudo").chmod(0o755)
    log = tmp_path / "python-runs.log"
    for name in ("python3", "python3.12"):
        _env_logging_python(shims / name, log, sys.executable)
    verifier, _ = _cwd_recording_verifier(tmp_path)
    (tmp_path / "release.pub.pem").write_text("key\n", encoding="utf-8")
    (tmp_path / "bundle").mkdir()
    env = {k: v for k, v in os.environ.items() if not k.startswith(("UDBMCP_", "PYTHON"))}
    env.update(
        _CALLER_PYTHON_ENV,
        PATH=f"{shims}:/usr/bin:/bin:/usr/sbin:/sbin",
        UDBMCP_RELEASE_PUBKEY=str(tmp_path / "release.pub.pem"),
        UDBMCP_VERIFIER=str(verifier),
        UDBMCP_STAGING_DIR=str(tmp_path / "staging"),
        TMPDIR=str(tmp_path),
    )
    extra = [str(tmp_path / "backups")] if script == UPGRADE else []
    proc = subprocess.run(  # noqa: S603 - repo script under test
        ["/bin/bash", str(script), str(tmp_path / "bundle"), str(tmp_path / "target"), *extra],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    runs = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
    assert proc.returncode != 0 and runs, proc.stdout + proc.stderr  # the stub verifier refused
    assert runs == ["run:"] * len(runs), f"a python started with the caller's PYTHON* variables: {runs}"


def test_f53_rollback_drops_the_callers_python_variables(tmp_path: Path) -> None:
    target = tmp_path / "target"
    log = tmp_path / "venv-python.log"
    _env_logging_python(target / "venv.previous" / "bin" / "python", log)
    (target / "venv.previous.sha256").write_text(
        f"{_sha256(target / 'venv.previous' / 'bin' / 'python')}  ./bin/python\n", encoding="utf-8"
    )
    backup = tmp_path / "backups" / "pre-upgrade-20260927T000000Z" / "universal-db-mcp"
    backup.mkdir(parents=True)
    (backup / "config.yaml").write_text("connections: {}\n", encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if not k.startswith(("UDBMCP_", "PYTHON"))}
    env.update(_CALLER_PYTHON_ENV, UDBMCP_CONFIG_DIR=str(tmp_path / "etc"), UDBMCP_STATE_DIR=str(tmp_path / "varlib"))
    proc = subprocess.run(  # noqa: S603 - repo script under test
        ["/bin/bash", str(ROLLBACK), str(target), str(tmp_path / "backups"), "--restore-config"],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert log.read_text(encoding="utf-8").splitlines() == ["run:", "run:"]


@pytest.mark.parametrize("script", [INSTALL, UPGRADE, ROLLBACK, POSTINST], ids=lambda p: p.name)
def test_f53_root_run_install_scripts_drop_python_variables_before_their_first_python(script: Path) -> None:
    """Also on the paths no sandbox above reaches: the scrub comes before every python call. The deb
    postinst drops them too, before it runs the trust dir's installer, which may be an older copy."""
    text = script.read_text(encoding="utf-8")
    first = min(text.index(line) for line, _, _ in _python_calls(text))
    assert _PYTHON_SCRUB in text and text.index(_PYTHON_SCRUB) < first, script.name


def test_f53_doctor_wrapper_runs_the_venv_isolated(tmp_path: Path) -> None:
    log = tmp_path / "venv-python.log"
    _logging_venv_python(tmp_path / "target" / "venv" / "bin" / "python", log)
    env = {**os.environ, "TARGET": str(tmp_path / "target"), "UDBMCP_CONFIG": str(tmp_path / "config.yaml")}
    proc = subprocess.run(  # noqa: S603 - repo script under test
        ["/bin/bash", str(DOCTOR_SH), "--json"], env=env, capture_output=True, text=True, timeout=60, check=False
    )
    assert proc.returncode == 0, proc.stderr
    assert log.read_text(encoding="utf-8").splitlines() == [
        f"-I -m universal_db_mcp doctor --config {tmp_path / 'config.yaml'} --json"
    ]


def test_f53_image_loader_runs_every_python_isolated(tmp_path: Path) -> None:
    bundle, pub = _image_bundle(tmp_path)
    env = _loader_env(tmp_path, pub)
    log = tmp_path / "python3.log"
    shim = Path(env["PATH"].split(":")[0]) / "python3"
    shim.write_text(f'#!/bin/sh\necho "$1 $2" >> "{log}"\nexec "{sys.executable}" "$@"\n', encoding="utf-8")
    proc = _run_loader(LOADER, bundle, env)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    # two verifications, the manifest read and the release record read, each with -I -S first
    assert log.read_text(encoding="utf-8").splitlines() == ["-I -S"] * 4


def test_f53_deb_postinst_runs_the_verifier_isolated(tmp_path: Path) -> None:
    log = tmp_path / "verifier-runs.jsonl"
    _postinst_trust_dir(
        tmp_path,
        "import json, os, sys\n"
        f"open({str(log)!r}, 'a').write(json.dumps({{'isolated': sys.flags.isolated, "
        "'no_site': sys.flags.no_site}) + '\\n')\n"
        "sys.exit(1)\n",
    )
    env = {**os.environ, "PATH": f"{_shims(tmp_path)}:{os.environ.get('PATH', '')}", "TMPDIR": str(tmp_path)}
    proc = subprocess.run(  # noqa: S603 - sandboxed copy of a repo script
        ["/bin/bash", str(_postinst_sandbox(tmp_path))], env=env, capture_output=True, text=True, timeout=60,
        check=False,
    )
    assert proc.returncode != 0 and log.exists(), proc.stdout + proc.stderr
    assert _recorded_runs(log)[-1] == {"isolated": 1, "no_site": 1}


def test_f53_the_verifier_finds_its_profiles_when_run_isolated(tmp_path: Path) -> None:
    """-I drops the script's own directory from sys.path; the verifier adds it back for profiles.py.
    It needs only the standard library, so it also runs without site.py (-S)."""
    key, _, pub = _keypair(tmp_path)
    bundle = _bundle(tmp_path / "b", key)
    proc = subprocess.run(  # noqa: S603 - repo script under test
        [sys.executable, "-I", "-S", str(VERIFIER), "--bundle", str(bundle), "--pubkey", str(pub)],
        cwd="/", capture_output=True, text=True, timeout=120, check=False,
    )
    assert proc.returncode == 0 and "bundle verification PASSED" in proc.stdout, proc.stdout + proc.stderr


# ---- F61: the release carries the Apache-2.0 license --------------------------

LICENSE = REPO / "LICENSE"
NOTICE = REPO / "NOTICE"
BUILD_DEB = REPO / "scripts" / "package" / "build_deb.sh"
# sha256 of https://www.apache.org/licenses/LICENSE-2.0.txt (11358 bytes)
APACHE_2_0_SHA256 = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"


def test_f61_license_is_the_unmodified_apache_2_0_text() -> None:
    text = LICENSE.read_text(encoding="utf-8")
    assert text.lstrip().startswith("Apache License\n") and "Version 2.0, January 2004" in text[:200]
    assert _sha256(LICENSE) == APACHE_2_0_SHA256, "LICENSE must be the canonical Apache License 2.0 text"


def test_f61_notice_names_the_project_and_the_third_party_licenses() -> None:
    lines = NOTICE.read_text(encoding="utf-8").splitlines()
    assert lines[:2] == ["universal-db-mcp", "Copyright 2026 the universal-db-mcp authors"]
    assert "third parties" in NOTICE.read_text(encoding="utf-8")


def test_f61_the_package_metadata_declares_apache_2_0() -> None:
    from packaging.requirements import Requirement

    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    project = data["project"]
    assert project["license"] == "Apache-2.0"
    assert project["license-files"] == ["LICENSE", "NOTICE"]
    assert not [c for c in project.get("classifiers", []) if c.startswith("License ::")]
    assert "Proprietary" not in PYPROJECT.read_text(encoding="utf-8")
    (backend,) = [Requirement(r) for r in data["build-system"]["requires"] if Requirement(r).name == "hatchling"]
    # PEP 639 license expressions and license-files arrays need hatchling 1.27
    assert not backend.specifier.contains("1.26.3") and backend.specifier.contains("1.32.4")


# F62: one maintainer identity in every package's metadata, with no personal or published address.
# Debian's Maintainer field requires an address, so it carries a reserved (.invalid) one.
MAINTAINER = "universal-db-mcp maintainers"
DEB_MAINTAINER = f"Maintainer: {MAINTAINER} <maintainers@universal-db-mcp.invalid>"


def test_f62_the_python_package_names_the_maintainers_and_no_address_or_repository() -> None:
    project = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]
    assert project["authors"] == [{"name": MAINTAINER}]
    assert "maintainers" not in project  # the same identity, stated once
    assert "urls" not in project, "no repository URL until the public repository exists"


def test_f62_both_deb_control_sources_name_the_same_maintainer() -> None:
    """build_deb.sh renders packaging/deb/control, and writes its own control file when that is absent."""
    control = (REPO / "packaging" / "deb" / "control").read_text(encoding="utf-8")
    assert re.findall(r"^Maintainer: .*$", control, flags=re.MULTILINE) == [DEB_MAINTAINER]
    assert re.findall(r"^Maintainer: .*$", BUILD_DEB.read_text(encoding="utf-8"), flags=re.MULTILINE) == [
        DEB_MAINTAINER
    ]


@pytest.mark.parametrize(
    "path",
    ["pyproject.toml", "packaging/deb/control", "scripts/package/build_deb.sh", "scripts/package/build_pkg.sh",
     "packaging/pkg-resources/conclusion.rtf"],
)
def test_f62_no_earlier_maintainer_identity_is_left(path: str) -> None:
    text = (REPO / path).read_text(encoding="utf-8")
    for earlier in ("Platform Engineering", "Release Engineering", "release-eng@", "release@udbmcp", "udbmcp.invalid"):
        assert earlier not in text, (path, earlier)


def test_f61_the_readme_does_not_state_another_license() -> None:
    readme = (REPO / "README.md").read_text(encoding="utf-8")
    assert "Proprietary" not in readme
    section = re.search(r"(?ims)^#+\s*licen[cs]e\b(.*?)(?=^#+\s|\Z)", readme)
    if section:
        assert "Apache-2.0" in section.group(1) or "Apache License 2.0" in section.group(1)


def _docker_capturing_debroot(shims: Path, capture: Path) -> None:
    """docker for build_deb.sh: `image inspect` succeeds, `run ... dpkg-deb --build` copies the staged root."""
    (shims / "docker").write_text(
        "#!/bin/sh\n"
        'if [ "$1" = image ]; then exit 0; fi\n'
        'root=""; dist=""\n'
        "for arg; do\n"
        '  case "$arg" in *:/debroot:ro) root="${arg%:/debroot:ro}" ;; *:/dist) dist="${arg%:/dist}" ;; esac\n'
        '  last="$arg"\n'
        "done\n"
        f'cp -R "$root" "{capture}"\n'
        'echo deb > "$dist/${last#/dist/}"\n',
        encoding="utf-8",
    )
    (shims / "docker").chmod(0o755)


def test_f61_the_deb_ships_the_license_as_its_copyright_file(tmp_path: Path) -> None:
    stage = tmp_path / "stage"
    bundle = stage / "universal-db-mcp-0.1.0"
    (bundle / "config-templates").mkdir(parents=True)
    (bundle / "config-templates" / "config.yaml").write_text("connections: {}\n", encoding="utf-8")
    (bundle / "manifest.json").write_text(
        json.dumps({"release": "0.1.0", "source_rev": "abc1234def", "created": "2026-09-27T00:00:00+00:00",
                    "target": {"os": "ubuntu24.04", "arch": "x86_64"}}),
        encoding="utf-8",
    )
    (bundle / "SHA256SUMS").write_text("stub\n", encoding="utf-8")
    (bundle / "SIGNATURE").write_bytes(b"stub")
    trusted = stage / "trusted-tools"
    (trusted / "lib").mkdir(parents=True)
    (trusted / "verify_bundle.py").write_text("print('bundle verification PASSED')\n", encoding="utf-8")
    (trusted / "profiles.py").write_text("# profiles\n", encoding="utf-8")
    (trusted / "lib" / "os_packages.sh").write_text("# lib\n", encoding="utf-8")
    (tmp_path / "release.pub.pem").write_text("key\n", encoding="utf-8")
    shims = _shims(tmp_path)
    capture = tmp_path / "debroot"
    _docker_capturing_debroot(shims, capture)
    env = {k: v for k, v in os.environ.items() if not k.startswith("UDBMCP_")}
    env.update(PATH=f"{shims}:/usr/bin:/bin:/usr/sbin:/sbin", TMPDIR=str(tmp_path))
    proc = subprocess.run(  # noqa: S603 - repo script under test, docker mocked
        ["/bin/bash", str(BUILD_DEB), str(bundle), "--pubkey", str(tmp_path / "release.pub.pem"),
         "--out", str(tmp_path / "dist")],
        env=env, capture_output=True, text=True, timeout=120, check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    doc = capture / "usr" / "share" / "doc" / "universal-db-mcp"
    # Debian policy 12.5: the copyright file carries the copyright statement itself (DEP-5). The
    # Apache-2.0 text is one of Debian's common licenses: lintian refuses a copy of it here
    # (copyright-file-contains-full-apache-2-license, copyright-not-using-common-license-for-apache2)
    text = (doc / "copyright").read_text(encoding="utf-8")
    header, files, third_party, license_ = text.split("\n\n")
    assert header == (
        "Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\n"
        "Upstream-Name: universal-db-mcp"
    )
    assert files == "Files: *\nCopyright: 2026 the universal-db-mcp authors\nLicense: Apache-2.0"
    # the wheels (MIT, BSD, LGPL, ...) and OS packages the bundle carries are not Apache-2.0: a later
    # Files paragraph overrides "Files: *" for them and says where each one's license is
    first, *rest = third_party.splitlines()
    assert first == (
        "Files: usr/share/universal-db-mcp/bundle/wheelhouse/* usr/share/universal-db-mcp/bundle/os-packages/*"
    ), third_party
    fields = dict(line.split(": ", 1) for line in rest if not line.startswith(" "))
    assert fields["License"] == "other" and fields["Copyright"], third_party
    explained = " ".join(line.strip() for line in rest if line.startswith(" "))
    assert "sbom/cyclonedx.json" in explained and "own license" in explained, third_party
    first, *body = license_.splitlines()
    assert first == "License: Apache-2.0" and body, license_
    assert all(line == " ." or (line.startswith(" ") and line.strip()) for line in body), "DEP-5 continuation"
    grant = " ".join(line.strip() for line in body if line != " .")
    assert 'Licensed under the Apache License, Version 2.0 (the "License")' in grant
    assert 'can be found in "/usr/share/common-licenses/Apache-2.0"' in grant
    assert "TERMS AND CONDITIONS" not in text, "the full license text belongs in /usr/share/common-licenses"
    assert (doc / "NOTICE").read_bytes() == NOTICE.read_bytes()
    assert oct((doc / "copyright").stat().st_mode & 0o777) == oct(0o644)


def test_f61_the_offline_bundle_carries_the_license_and_notice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, serve_index: Any
) -> None:
    _require_pip()
    builder = _builder()
    wheels = {
        "mcp": _wheel(tmp_path / "wh", "mcp", "2.2.0"),
        "pyyaml": _wheel(tmp_path / "wh", "pyyaml", "6.0.3"),
        "sqlglot": _wheel(tmp_path / "wh", "sqlglot", "30.18.0"),
    }
    index = serve_index(_index(tmp_path / "index", list(wheels.values())))
    lock = tmp_path / "lock.txt"
    lock.write_text(_lock_text(wheels, dict.fromkeys(wheels, "-r runtime.in")), encoding="utf-8")
    _, priv, _ = _keypair(tmp_path)
    monkeypatch.setattr(builder, "lock_path", lambda profile: lock)
    monkeypatch.setattr(builder, "lock_problems", lambda profile, runtime_in=None, lock=None: [])
    monkeypatch.setattr(
        builder, "build_app_wheel", lambda workdir, index_url: _wheel(workdir / "dist", "universal_db_mcp", "0.1.0")
    )
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setattr(sys, "argv", [
        "prepare_offline_bundle.py", "--profile", WINDOWS_PROFILE, "--connectors", "core",
        "--out", str(tmp_path / "out"), "--signing-key", str(priv), "--source-rev", "abc1234", "--release-seq", "1",
        "--index-url", index,
    ])
    builder.main()
    bundle = next((tmp_path / "out").glob("universal-db-mcp-*"))
    assert (bundle / "licenses" / "LICENSE").read_bytes() == LICENSE.read_bytes()
    assert (bundle / "licenses" / "NOTICE").read_bytes() == NOTICE.read_bytes()
    listed = (bundle / "SHA256SUMS").read_text(encoding="utf-8")
    assert f"{_sha256(LICENSE)}  licenses/LICENSE" in listed and f"{_sha256(NOTICE)}  licenses/NOTICE" in listed
