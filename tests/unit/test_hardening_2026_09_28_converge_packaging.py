"""Packaging and release-trust regressions from the 2026-09-28 convergence wave.

Each section names the class of defect it pins. As in test_hardening_2026_09_27_packaging, every key
is a throwaway Ed25519 pair generated under tmp_path and every script under test writes below
tmp_path only.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

import pytest
from test_hardening_2026_09_27_packaging import (
    APP_TAR,
    BASELINE_TAR,
    DEB_NAME,
    ORACLE_DEBS,
    _bootstrap,
    _bootstrap_by,
    _bundle,
    _bundle_sums,
    _deb_dir,
    _find_as_root,
    _image_bundle,
    _installed_bootstrap,
    _keypair,
    _load_verifier,
    _loaded,
    _loader_env,
    _permissive_umask,  # noqa: F401 - the autouse umask fixture applies here too
    _release_record,
    _run_installer,
    _shims,
    _sign_stick,
    _signed_stick,
    _site,
    _snapshot,
    _staging_cp,
    _stick,
    _tool_env,
    _verify,
)

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="bash-based POSIX test")

REPO = Path(__file__).resolve().parents[2]
INSTALL = REPO / "scripts" / "install_offline.sh"
UPGRADE = REPO / "scripts" / "upgrade_offline.sh"
LOADER = REPO / "scripts" / "load_images_offline.sh"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---- the verifier reads a bundle of regular files only, each file once ------------------------
# install_offline.sh, upgrade_offline.sh and load_images_offline.sh copy the bundle with cp -RP into
# a root-only staging directory and re-verify THAT copy: nothing on the (possibly writable) bundle
# path may be consulted afterwards. cp -P keeps a symlink a symlink, so a link in the copy still
# leads to where the party who could write the bundle path decides; and a listing read twice (once
# for the hashes, once for the signature) can be two different listings.


def _signed(tmp_path: Path, name: str = "bundle", **manifest: Any) -> tuple[Path, Path]:
    key, _, pub = _keypair(tmp_path, f"{name}-key")
    return _bundle(tmp_path / name, key, **manifest), pub


def _relink(path: Path, outside: Path) -> None:
    """Move *path* to *outside* (same bytes) and leave a symlink to it in its place."""
    outside.parent.mkdir(parents=True, exist_ok=True)
    path.rename(outside)
    path.symlink_to(outside)


def _refused(proc: subprocess.CompletedProcess[str], rel: str) -> None:
    assert proc.returncode == 1, proc.stdout
    assert "bundle verification PASSED" not in proc.stdout, proc.stdout
    assert f"not a regular file or directory in the bundle: {rel}" in proc.stdout, proc.stdout


@pytest.mark.parametrize("name", ["SHA256SUMS", "SIGNATURE"])
def test_a_symlinked_listing_or_signature_is_refused_even_when_its_bytes_are_the_signed_ones(
    tmp_path: Path, name: str
) -> None:
    """The reattack's trigger: the bundle-root SHA256SUMS (or SIGNATURE) is a link to an identical
    file outside the bundle. Its bytes verify today, and whoever controls the target decides
    tomorrow's: the bundle is refused however right the bytes are."""
    bundle, pub = _signed(tmp_path)
    assert _verify("--bundle", bundle, "--pubkey", pub, "--no-installed-manifest").returncode == 0
    _relink(bundle / name, tmp_path / "attacker" / name)
    proc = _verify("--bundle", bundle, "--pubkey", pub, "--no-installed-manifest")
    _refused(proc, name)
    assert f"FAIL: {name} cannot be used: " in proc.stdout or "signature verification FAILED" in proc.stdout, (
        proc.stdout
    )


@pytest.mark.parametrize("name", ["SHA256SUMS", "SIGNATURE", "manifest.json"])
def test_the_listing_and_signature_survive_the_private_copy_as_links_and_the_staged_copy_is_refused(
    tmp_path: Path, name: str
) -> None:
    """What the installers do: cp -RP into a private directory, then verify the copy."""
    bundle, pub = _signed(tmp_path)
    _relink(bundle / name, tmp_path / "attacker" / name)
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    staging = private / "bundle"
    subprocess.run(["cp", "-RP", "--", f"{bundle}/.", str(staging)], check=True)  # noqa: S603, S607
    assert (staging / name).is_symlink()  # the link survived the private copy
    proc = _verify("--bundle", staging, "--pubkey", pub, "--no-installed-manifest")
    assert proc.returncode == 1 and "bundle verification PASSED" not in proc.stdout, proc.stdout
    assert f"{name}" in proc.stdout and "FAIL:" in proc.stdout, proc.stdout


@pytest.mark.parametrize(
    "planted",
    ["payload-file-link", "payload-dir-link", "dangling-link", "fifo", "subdir-listing-link"],
)
def test_a_link_fifo_or_other_non_regular_entry_anywhere_in_the_bundle_is_refused(
    tmp_path: Path, planted: str
) -> None:
    """Nothing but regular files and directories, as bootstrap.sh requires of the stick: a link to a
    file with the listed bytes, a linked directory, a FIFO (which would block a reader) and a link
    by an exempt name such as images/SHA256SUMS are all refused, and none is read through."""
    bundle, pub = _signed(tmp_path)
    wheel = bundle / "wheelhouse" / "sqlglot-30.18.0-py3-none-any.whl"
    if planted == "payload-file-link":
        _relink(wheel, tmp_path / "attacker" / wheel.name)
        rel = "wheelhouse/sqlglot-30.18.0-py3-none-any.whl"
    elif planted == "payload-dir-link":
        _relink(bundle / "requirements", tmp_path / "attacker" / "requirements")
        rel = "requirements"
    elif planted == "dangling-link":
        (bundle / "wheelhouse" / "extra.whl").symlink_to(tmp_path / "nowhere.whl")
        rel = "wheelhouse/extra.whl"
    elif planted == "fifo":
        os.mkfifo(bundle / "wheelhouse" / "pipe.whl")
        rel = "wheelhouse/pipe.whl"
    else:
        (bundle / "images").mkdir()
        (bundle / "images" / "SHA256SUMS").symlink_to("/dev/zero")
        rel = "images/SHA256SUMS"
    proc = _verify("--bundle", bundle, "--pubkey", pub, "--no-installed-manifest")
    _refused(proc, rel)


def test_a_fifo_listing_is_refused_without_blocking_the_verifier(tmp_path: Path) -> None:
    """The reattack's split view fed the two reads from a FIFO: now nothing waits on one."""
    bundle, pub = _signed(tmp_path)
    (bundle / "SHA256SUMS").unlink()
    os.mkfifo(bundle / "SHA256SUMS")
    proc = _verify("--bundle", bundle, "--pubkey", pub, "--no-installed-manifest")  # timeout=120 inside
    _refused(proc, "SHA256SUMS")


@pytest.mark.parametrize("name", ["SHA256SUMS", "SIGNATURE"])
def test_a_listing_or_signature_with_a_second_hard_link_is_refused(tmp_path: Path, name: str) -> None:
    """Whoever holds the other name of a hard link changes the file the bundle names."""
    bundle, pub = _signed(tmp_path)
    os.link(bundle / name, tmp_path / f"other-{name}")
    proc = _verify("--bundle", bundle, "--pubkey", pub, "--no-installed-manifest")
    assert proc.returncode == 1 and "bundle verification PASSED" not in proc.stdout, proc.stdout
    assert f"{name} has 2 links" in proc.stdout, proc.stdout


def test_the_listing_is_read_once_and_the_signature_is_checked_over_those_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """One open of each trust file: the integrity pass and the Ed25519 check use the same bytes."""
    bundle, pub = _signed(tmp_path)
    verifier = _load_verifier()
    opened: list[str] = []
    real_open = os.open

    def counting_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        opened.append(os.path.basename(os.fspath(path)))
        return real_open(path, flags, *args, **kwargs)

    signed_over: list[bytes] = []
    real_check = verifier.verify_ed25519_signature

    def recording_check(pubkey: str, data: bytes, signature: bytes) -> str:
        signed_over.append(data)
        return str(real_check(pubkey, data, signature))

    monkeypatch.setattr(verifier.os, "open", counting_open)
    monkeypatch.setattr(verifier, "verify_ed25519_signature", recording_check)
    monkeypatch.setattr(sys, "argv", ["verify_bundle.py", "--bundle", str(bundle), "--pubkey", str(pub),
                                      "--no-installed-manifest"])
    assert verifier.main() == 0, capsys.readouterr().out
    for name in ("SHA256SUMS", "SIGNATURE", "manifest.json", "runtime.lock",
                 "sqlglot-30.18.0-py3-none-any.whl", "universal_db_mcp-0.1.0-py3-none-any.whl"):
        assert opened.count(name) == 1, (name, opened)
    assert signed_over == [(bundle / "SHA256SUMS").read_bytes()]


def test_a_file_that_changes_between_its_two_uses_is_refused(tmp_path: Path) -> None:
    """runtime.lock is hashed for the listing and parsed for the wheelhouse check: the verifier keeps
    the bytes it hashed, and any file read a second time must give the hashed bytes again, or it
    fails instead of silently checking other content."""
    bundle, _pub = _signed(tmp_path)
    verifier = _load_verifier()
    lock = bundle / "requirements" / "runtime.lock"
    signed_lock = lock.read_bytes()
    kept = verifier.BundleReader(bundle, keep=frozenset({"requirements/runtime.lock"}))
    assert kept.sha256("requirements/runtime.lock") == _sha256(signed_lock)
    lock.write_text("sqlglot==1.0.0 --hash=sha256:" + "0" * 64 + "\n", encoding="utf-8")
    assert kept.read("requirements/runtime.lock") == signed_lock  # the bytes it hashed, not re-read
    lock.write_bytes(signed_lock)
    reader = verifier.BundleReader(bundle)
    assert reader.sha256("requirements/runtime.lock") == _sha256(signed_lock)
    lock.write_text("sqlglot==1.0.0 --hash=sha256:" + "0" * 64 + "\n", encoding="utf-8")
    with pytest.raises(verifier.BundleFileRefused, match="changed while the bundle was verified"):
        reader.read("requirements/runtime.lock")


def test_a_plain_bundle_still_verifies_and_listing_paths_are_still_contained(tmp_path: Path) -> None:
    bundle, pub = _signed(tmp_path)
    ok = _verify("--bundle", bundle, "--pubkey", pub, "--no-installed-manifest")
    assert ok.returncode == 0 and "integrity: 4 artifacts checked, full coverage verified" in ok.stdout, ok.stdout
    # a listing that names a path outside the bundle, re-signed: refused as before
    outside = tmp_path / "outside.txt"
    outside.write_text("outside\n", encoding="utf-8")
    key, _, pub2 = _keypair(tmp_path, "escape")
    sums = _bundle_sums(bundle) + f"{_sha256(outside.read_bytes())}  ../outside.txt\n".encode()
    (bundle / "SHA256SUMS").write_bytes(sums)
    (bundle / "SIGNATURE").write_bytes(key.sign(sums))
    proc = _verify("--bundle", bundle, "--pubkey", pub2, "--no-installed-manifest")
    assert proc.returncode == 1 and "SHA256SUMS path escapes the bundle directory: ../outside.txt" in proc.stdout


def test_detached_verification_reads_regular_files_only(tmp_path: Path) -> None:
    """--verify-file (the trust bootstrap's stick check) takes a symlink for neither argument."""
    key, _, pub = _keypair(tmp_path)
    data = tmp_path / "SHA256SUMS"
    data.write_bytes(b"listing\n")
    sig = tmp_path / "SHA256SUMS.sig"
    sig.write_bytes(key.sign(data.read_bytes()))
    assert _verify("--verify-file", data, "--signature", sig, "--pubkey", pub).returncode == 0
    for linked in (data, sig):
        link = tmp_path / f"link-{linked.name}"
        link.symlink_to(linked)
        args = {"data": link if linked is data else data, "sig": link if linked is sig else sig}
        proc = _verify("--verify-file", args["data"], "--signature", args["sig"], "--pubkey", pub)
        assert proc.returncode == 1 and "signature verification PASSED" not in proc.stdout, proc.stdout
        assert "FAIL: signature verification FAILED" in proc.stdout, proc.stdout


@pytest.mark.parametrize("script", [INSTALL, UPGRADE, LOADER], ids=["install", "upgrade", "loader"])
def test_the_installers_refuse_a_staged_copy_that_holds_anything_but_files_and_directories(script: Path) -> None:
    """Belt and braces for an older trusted verifier: each installer checks its own private copy, in
    the shared private_copy, between the copy and the verification of it."""
    text = script.read_text(encoding="utf-8")
    copy = text.index('STAGING="$(private_copy "$')
    verify_copy = text.index('verify_with_proof "$STAGING"')
    assert copy < verify_copy and text[copy:verify_copy].count("\n") == 1  # the next line verifies it
    block = _root_only_blocks()[0]
    checks = block[block.index("private_copy() {"):]
    assert checks.index('cp -RP -- "$1"/.') < checks.index('find "$2" ! -type f ! -type d') < checks.index("printf")
    assert "a bundle holds regular files and directories only" in checks, checks




def _passing_verifier(path: Path) -> Path:
    """An older trusted verifier that certifies whatever it is given (no symlink refusal)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "import argparse\nap = argparse.ArgumentParser()\n"
        "for o in ('--bundle', '--pubkey', '--installed-manifest'):\n    ap.add_argument(o)\n"
        "ap.add_argument('--allow-downgrade', action='store_true')\nap.parse_args()\n"
        "print('bundle verification PASSED')\n",
        encoding="utf-8",
    )
    return path


@pytest.mark.parametrize("script", [INSTALL, UPGRADE, LOADER], ids=["install", "upgrade", "loader"])
def test_the_installers_refuse_a_link_in_their_private_copy_whatever_the_verifier_says(
    tmp_path: Path, script: Path
) -> None:
    bundle, pub = _signed(tmp_path)
    _relink(bundle / "SHA256SUMS", tmp_path / "attacker" / "SHA256SUMS")
    target = tmp_path / "target"
    if script == LOADER:
        env = _loader_env(tmp_path, pub)
        _passing_verifier(tmp_path / "trust" / "verify_bundle.py")
        proc = subprocess.run(  # noqa: S603 - repo script under test
            ["/bin/bash", str(script), str(bundle)], env=env, capture_output=True, text=True, timeout=120,
            check=False,
        )
        assert _loaded(tmp_path) == {}
    else:
        extra = [str(tmp_path / "backups")] if script == UPGRADE else []
        stub = _passing_verifier(tmp_path / "trust" / "verify_bundle.py")
        proc = _run_installer(tmp_path, script, [str(bundle), str(target), *extra], stub)
        assert not target.exists() or not list(target.iterdir())
    assert proc.returncode != 0, proc.stdout + proc.stderr
    assert "a bundle holds regular files and directories only" in proc.stderr, proc.stderr
    assert "SHA256SUMS" in proc.stderr.split("directories only", 1)[1], proc.stderr
    assert not list((tmp_path / "staging").iterdir()), "the private copy is removed on exit"


# ---- the private copy keeps nothing of the bundle's owners and modes ----------------------------
# Re-attack, round 1: the three installers made the directory for the private copy with mktemp -d,
# chmod 700, then ran `cp -a BUNDLE/. STAGING/`. With the source written DIR/., GNU and BSD cp take
# the existing STAGING as the copy of the bundle directory, and -a then gives it that directory's
# mode and, as root, its owner: a bundle on world-writable media (0777) or in another account's home
# left the verified copy writable by that party (or anyone), who rewrote a .deb between the second
# verification and dpkg -i (live: GNU cp 9.4 as root, BSD cp on this Mac). The copy is now made under
# a name of its own inside the private directory, which stays 700, and keeps no owner or mode.


def _recording_verifier(path: Path, log: Path) -> Path:
    """A passing verifier that records, for each run, the directory the installer made in the staging
    base for the bundle it was handed, and the mode and owner of that directory and of everything below
    it (None for a bundle outside the staging base)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "import argparse, json, os, stat\nap = argparse.ArgumentParser()\n"
        "for o in ('--bundle', '--pubkey', '--installed-manifest'):\n    ap.add_argument(o)\n"
        "ap.add_argument('--allow-downgrade', action='store_true')\nargs = ap.parse_args()\n"
        "base = os.path.realpath(os.environ['UDBMCP_STAGING_DIR'])\nreal = os.path.realpath(args.bundle)\n"
        "top, seen = None, []\n"
        "if real.startswith(base + os.sep):\n"
        "    top = os.path.join(base, os.path.relpath(real, base).split(os.sep)[0])\n"
        "    for root, dirs, files in os.walk(top):\n"
        "        for p in [root, *(os.path.join(root, n) for n in files)]:\n"
        "            st = os.lstat(p)\n"
        "            seen.append([p, stat.S_IMODE(st.st_mode), st.st_uid])\n"
        f"with open({str(log)!r}, 'a') as fh:\n"
        "    fh.write(json.dumps({'bundle': real, 'top': top, 'entries': seen}) + '\\n')\n"
        "print('bundle verification PASSED')\n",
        encoding="utf-8",
    )
    return path


def _open_to_all(tree: Path) -> None:
    """The bundle as world-writable removable media presents it: every directory 0777, every file 0666."""
    for path in [tree, *tree.rglob("*")]:
        path.chmod(0o777 if path.is_dir() else 0o666)


def _staged_copy(tmp_path: Path, script: Path, bundle: Path, pub: Path) -> dict[str, Any]:
    """Run *script* on *bundle* with the recording verifier; the record of its run on the private copy."""
    log = tmp_path / "verified.jsonl"
    stub = _recording_verifier(tmp_path / "trust" / "verify_bundle.py", log)
    if script == LOADER:
        env = _loader_env(tmp_path, pub)
        _recording_verifier(tmp_path / "trust" / "verify_bundle.py", log)
        proc = subprocess.run(  # noqa: S603 - repo script under test
            ["/bin/bash", str(script), str(bundle)], env=env, capture_output=True, text=True, timeout=120,
            check=False,
        )
    else:
        extra = [str(tmp_path / "backups")] if script == UPGRADE else []
        proc = _run_installer(tmp_path, script, [str(bundle), str(tmp_path / "target"), *extra], stub)
    runs = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()] if log.exists() else []
    assert len(runs) >= 2, proc.stdout + proc.stderr
    assert runs[0]["top"] is None and runs[0]["bundle"] == os.path.realpath(bundle), runs[0]
    assert runs[1]["top"] is not None, runs[1]
    assert not list((tmp_path / "staging").iterdir()), "the private copy is removed on exit"
    return dict(runs[1])


@pytest.mark.parametrize("script", [INSTALL, UPGRADE, LOADER], ids=["install", "upgrade", "loader"])
def test_a_world_writable_bundle_leaves_the_private_copy_private(tmp_path: Path, script: Path) -> None:
    if script == LOADER:
        bundle, pub = _image_bundle(tmp_path)
    else:
        bundle, pub = _signed(tmp_path)
    _open_to_all(bundle)
    copy = _staged_copy(tmp_path, script, bundle, pub)
    top = copy["top"]
    modes = {path: mode for path, mode, _uid in copy["entries"]}
    assert modes[top] == 0o700, oct(modes[top])
    for path, mode, uid in copy["entries"]:
        assert uid == os.getuid(), (path, uid)  # the account the privileged steps run as
        assert not mode & 0o077, (path, oct(mode))
    assert copy["bundle"] != top, "the copy is made inside the private directory, never onto it"
    assert len(modes) > 5 and os.path.join(copy["bundle"], "manifest.json") in modes, sorted(modes)


@pytest.mark.skipif(os.getuid() != 0, reason="another account's bundle needs root to chown it")
@pytest.mark.parametrize("script", [INSTALL, UPGRADE, LOADER], ids=["install", "upgrade", "loader"])
def test_another_accounts_bundle_leaves_the_private_copy_roots(tmp_path: Path, script: Path) -> None:
    """The finding's first case: a bundle another account owns (and made 0777). As root, cp -a gave the
    private directory and every file that account's uid."""
    if script == LOADER:
        bundle, pub = _image_bundle(tmp_path)
    else:
        bundle, pub = _signed(tmp_path)
    _open_to_all(bundle)
    for path in [bundle, *bundle.rglob("*")]:
        os.lchown(path, 65534, 65534)
    copy = _staged_copy(tmp_path, script, bundle, pub)
    for path, mode, uid in copy["entries"]:
        assert uid == 0 and not mode & 0o077, (path, uid, oct(mode))


_ATTRIBUTE_COPY = re.compile(r"\bcp\s+(?:-\w*[ap]\w*|--archive|--preserve\S*)(?:\s+-\S+)*\s+(\S+)\s+(\S+)")


@pytest.mark.parametrize("script", [INSTALL, UPGRADE, LOADER], ids=["install", "upgrade", "loader"])
def test_no_installer_copies_the_bundle_with_its_owners_or_modes(script: Path) -> None:
    """Statically, the class: nothing copies the bundle with cp -a/-p/--preserve, and the copy is made by
    the one shared block under a name of its own inside the private directory."""
    code = "\n".join(
        line for line in script.read_text(encoding="utf-8").splitlines() if not line.lstrip().startswith("#")
    )
    for source, dest in _ATTRIBUTE_COPY.findall(code):
        assert "BUNDLE" not in source and "STAGING" not in dest, (source, dest)
    assert code.count("cp -RP -- ") == 1, "the copy is private_copy's alone"
    block = _root_only_blocks()[0]
    assert 'cp -RP -- "$1"/. "$copy"' in block and 'chmod -R go-rwx "$copy"' in block
    assert 'local copy="$2/bundle"' in block


@pytest.mark.parametrize(
    ("line", "flagged"),
    [('$sudo_ok cp -a "$BUNDLE"/. "$STAGING/"', True), ('cp -p "$NEW_BUNDLE"/x "$STAGING"/x', True),
     ('cp --archive "$BUNDLE"/. "$STAGING/"', True), ('cp -Rp "$BUNDLE" "$STAGING/b"', True),
     ('$sudo_ok cp -RP -- "$1"/. "$copy"', False), ('cp -a /etc/universal-db-mcp "$BACKUP_DIR/"', False)],
)
def test_the_attribute_copy_detector(line: str, flagged: bool) -> None:
    found = any("BUNDLE" in s or "STAGING" in d for s, d in _ATTRIBUTE_COPY.findall(line))
    assert found is flagged, line


# ---- a bundle whose profile the registry does not know: on target by its signed target block ----
# DECISION-2: a later release may rename a profile (macos-arm64-cp312 -> -cp313). Once the site has
# installed that release, its manifest names the NEW profile, and an old .pkg carrying the OLD name
# was off target: no release order was checked and it installed over the newer release.

_MAC = {"os": "macos", "arch": "arm64", "python": "3.12", "abi": "cp312"}


def _unknown_on_target(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    installed: Path,
    *args: object,
    host: tuple[str, str] = ("Plan9", "mips"),
) -> tuple[int, str]:
    verifier = _load_verifier()
    monkeypatch.setattr(verifier, "platform_installed_manifest", lambda: installed)
    monkeypatch.setattr(verifier.platform, "system", lambda: host[0])
    monkeypatch.setattr(verifier.platform, "machine", lambda: host[1])
    monkeypatch.setattr(sys, "argv", ["verify_bundle.py", *(str(a) for a in args)])
    rc = verifier.main()
    return rc, capsys.readouterr().out


def test_a_renamed_profile_is_on_target_where_the_installed_release_has_the_same_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    key, _, pub = _keypair(tmp_path)
    installed = tmp_path / "installed.json"
    installed.write_text(json.dumps({"profile": "macos-arm64-cp313", "target": _MAC, "release_seq": 5}),
                         encoding="utf-8")
    old_pkg = _bundle(tmp_path / "b1", key, profile="macos-arm64-cp311", target=_MAC, release_seq=1)
    rc, out = _unknown_on_target(monkeypatch, capsys, installed, "--bundle", old_pkg, "--pubkey", pub)
    assert rc == 1, out
    assert "WARNING: unknown bundle profile 'macos-arm64-cp311'" in out, out
    assert f"no --installed-manifest given; checking this machine's installed release {installed}" in out, out
    assert "FAIL: rollback refused" in out and "bundle verification PASSED" not in out, out
    for extra in ("--no-installed-manifest", "--allow-platform-mismatch"):  # a build machine
        rc, out = _unknown_on_target(monkeypatch, capsys, installed, "--bundle", old_pkg, "--pubkey", pub, extra)
        assert rc == 0 and "release order" not in out, (extra, out)
    newer = _bundle(tmp_path / "b6", key, profile="macos-arm64-cp311", target=_MAC, release_seq=6)
    rc, out = _unknown_on_target(monkeypatch, capsys, installed, "--bundle", newer, "--pubkey", pub)
    assert rc == 0 and "(not a downgrade)" in out, out
    # another platform's bundle, and a test bundle with no target block, stay off target
    linux = {"os": "ubuntu-24.04", "arch": "x86_64", "python": "3.12", "abi": "cp312"}
    for name, fields in (("linux", {"target": linux}), ("bare", {})):
        bundle = _bundle(tmp_path / name, key, profile="retired-profile", release_seq=1, **fields)
        rc, out = _unknown_on_target(monkeypatch, capsys, installed, "--bundle", bundle, "--pubkey", pub)
        assert rc == 0 and "release order" not in out, (name, out)


def test_a_renamed_profile_is_on_target_on_the_host_its_target_block_names(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The installed record may predate the target block, or be unreadable: this host's own
    platform (as the registry describes it) decides then."""
    key, _, pub = _keypair(tmp_path)
    installed = tmp_path / "installed.json"
    installed.write_text(json.dumps({"profile": "macos-arm64-cp313", "release_seq": 5}), encoding="utf-8")
    old_pkg = _bundle(tmp_path / "b1", key, profile="macos-arm64-cp311", target=_MAC, release_seq=1)
    rc, out = _unknown_on_target(
        monkeypatch, capsys, installed, "--bundle", old_pkg, "--pubkey", pub, host=("Darwin", "arm64")
    )
    assert rc == 1 and "FAIL: rollback refused" in out, out
    rc, out = _unknown_on_target(monkeypatch, capsys, installed, "--bundle", old_pkg, "--pubkey", pub)
    assert rc == 0 and "release order" not in out, out  # a Plan9 host is not a macOS target


# ---- root writes nothing through a name the service account controls ------------------------
# The deb postinst wrote (and trusted) the unit-hash record with a plain shell redirect into
# /var/lib/universal-db-mcp, which belongs to the udbmcp service account: that account decided what
# root's write opened (any file root can write, truncated) and what the record said (whether an
# admin's edited unit was replaced). The record now lives where root alone can write, is read and
# written without following a link, and the old record is taken over only when root wrote it.

POSTINST = REPO / "packaging" / "deb" / "postinst"
POSTRM = REPO / "packaging" / "deb" / "postrm"
_RECORD_START, _RECORD_END = "# >>> shipped-unit hash record", "# <<< shipped-unit hash record"
_NEW_RECORD = "/var/lib/universal-db-mcp-package/shipped-unit.sha256"
_OLD_RECORD = "/var/lib/universal-db-mcp/.shipped-unit.sha256"
_NOT_ROOT = pytest.mark.skipif(os.getuid() == 0, reason="this account stands in for root; another uid for others")


def _record_blocks() -> list[str]:
    text = POSTINST.read_text(encoding="utf-8")
    blocks, at = [], 0
    while (start := text.find(_RECORD_START, at)) != -1:
        end = text.index(_RECORD_END, start)
        blocks.append(text[start:end])
        at = end
    return blocks


def _record_tool(tmp_path: Path, root_uid: int) -> tuple[Path, Path, Path]:
    """The postinst's record block as a script, with tmp paths for the record and the old record and
    *root_uid* standing in for root's uid. Returns (script, record, old record)."""
    record = tmp_path / "var-lib" / "universal-db-mcp-package" / "shipped-unit.sha256"
    old = tmp_path / "var-lib" / "universal-db-mcp" / ".shipped-unit.sha256"
    old.parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / "var-lib").chmod(0o755)
    block = _record_blocks()[0]
    assert block.count(_NEW_RECORD) == 1 and block.count(_OLD_RECORD) == 1 and block.count("ROOT_UID = 0\n") == 1
    block = block.replace(_NEW_RECORD, str(record)).replace(_OLD_RECORD, str(old))
    block = block.replace("ROOT_UID = 0\n", f"ROOT_UID = {root_uid}\n")
    script = tmp_path / "record.sh"
    script.write_text(f'#!/bin/bash\nset -eu\n{block}\nshipped_unit_record "$@"\n', encoding="utf-8")
    return script, record, old


def _record_run(tmp_path: Path, script: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("UDBMCP_", "PYTHON"))}
    env["PATH"] = f"{_shims(tmp_path)}:/usr/bin:/bin"
    return subprocess.run(  # noqa: S603 - the postinst's own record code
        ["/bin/bash", str(script), *args], env=env, capture_output=True, text=True, timeout=60, check=False
    )


_H1, _H2 = "1" * 64, "2" * 64


def test_the_unit_hash_record_is_one_block_in_the_postinst_and_its_worker() -> None:
    blocks = _record_blocks()
    assert len(blocks) == 2 and blocks[0] == blocks[1], "one record implementation, in both install paths"
    text = POSTINST.read_text(encoding="utf-8")
    assert text.count("SHIPPED_UNIT_RECORD=") == 2 and f"SHIPPED_UNIT_RECORD={_NEW_RECORD}\n" in blocks[0]
    for branch in (text[: text.index("\nWORKER_EOF\n")], text[text.index("\nWORKER_EOF\n"):]):
        at = branch.rindex(_RECORD_START)
        assert branch.index('SHIPPED_HASH="$(shipped_unit_record read)"', at) \
            < branch.index('"$SHIPPED_HASH"', at) \
            < branch.index('shipped_unit_record write "$(sha256sum "$UNIT_DST"', at)


_ROOT_RUN = [
    REPO / "packaging" / "deb" / name for name in ("preinst", "postinst", "prerm", "postrm")
] + [REPO / "packaging" / "pkg" / name for name in ("preinstall", "postinstall")] + [
    REPO / "scripts" / name for name in ("install_offline.sh", "upgrade_offline.sh", "rollback_offline.sh")
]


# Every spelling that opens a file for writing by name, and so follows a link there: any redirect
# operator (stdout, a numbered descriptor, &> and >&, the clobbering >|, <>) and tee, then a
# service-owned directory, quoted or not.
_WRITES_INTO_SERVICE_DIR = re.compile(
    r"(?:[0-9]*<?>{1,2}[|&]?|&>{1,2}|\btee\b(?:\s+-[a-z]+)*)\s*"
    r'"?(?:/var/(?:lib|log)/universal-db-mcp"?/|\$\{?(?:STATE_DIR|LOG_DIR|SHIPPED_UNIT_RECORD)\b)'
)


@pytest.mark.parametrize(
    ("code", "writes"),
    [('doctor 2>"$LOG_DIR/doctor.err"', True), ("doctor &> /var/log/universal-db-mcp/doctor.log", True),
     ('echo x >| "$STATE_DIR/metadata.sqlite"', True), ('sha256sum "$U" | tee /var/lib/universal-db-mcp/.x', True),
     ('sha256sum "$U" >"/var/lib/universal-db-mcp"/.x', True), ("sha256sum > /var/lib/universal-db-mcp/.x", True),
     ('x >> "${LOG_DIR}/a"', True), ('y | tee -a "$STATE_DIR/x"', True), ('exec 3<>"$STATE_DIR/lock"', True),
     ('cmd >&"$LOG_DIR/x"', True), ('echo "$H" > "$SHIPPED_UNIT_RECORD"', True),
     ("cmd 2>/dev/null", False), ("echo x >&2", False), ("echo x >> /var/log/universal-db-mcp-install.log", False),
     ('cat < "$STATE_DIR/x"', False), ('grep -q x "$LOG_DIR/y"', False),
     ("install -d -o udbmcp /var/lib/universal-db-mcp /var/log/universal-db-mcp", False)],
)
def test_the_service_directory_write_detector(code: str, writes: bool) -> None:
    assert bool(_WRITES_INTO_SERVICE_DIR.search(code)) is writes


@pytest.mark.parametrize("script", _ROOT_RUN, ids=lambda p: p.name)
def test_no_root_run_script_redirects_into_a_directory_the_service_account_owns(script: Path) -> None:
    """A shell redirect (or tee) opens its target with O_CREAT and follows a link there."""
    for number, line in enumerate(script.read_text(encoding="utf-8").splitlines(), 1):
        code = line.split(" #", 1)[0]
        if code.lstrip().startswith("#"):
            continue
        assert not _WRITES_INTO_SERVICE_DIR.search(code), f"{script.name}:{number}: {line}"


@_NOT_ROOT
def test_the_unit_hash_record_round_trips_in_a_directory_root_alone_can_write(tmp_path: Path) -> None:
    script, record, _old = _record_tool(tmp_path, os.getuid())
    assert _record_run(tmp_path, script, "read").stdout == ""
    proc = _record_run(tmp_path, script, "write", _H1)
    assert proc.returncode == 0, proc.stderr
    assert record.read_text(encoding="utf-8") == f"{_H1}\n"
    assert record.parent.stat().st_mode & 0o777 == 0o700
    assert _record_run(tmp_path, script, "read").stdout == f"{_H1}\n"
    assert _record_run(tmp_path, script, "write", _H2).returncode == 0
    assert _record_run(tmp_path, script, "read").stdout == f"{_H2}\n"
    assert _record_run(tmp_path, script, "write", "not-a-hash").returncode != 0
    assert sorted(p.name for p in record.parent.iterdir()) == ["shipped-unit.sha256"]


@_NOT_ROOT
def test_the_unit_hash_record_write_replaces_a_link_and_never_writes_through_it(tmp_path: Path) -> None:
    script, record, _old = _record_tool(tmp_path, os.getuid())
    record.parent.mkdir(mode=0o700)
    victim = tmp_path / "shadow"
    victim.write_text("root:ROOT-ONLY-CONTENT:0:0\n", encoding="utf-8")
    record.symlink_to(victim)
    assert _record_run(tmp_path, script, "read").stdout == ""
    assert _record_run(tmp_path, script, "write", _H1).returncode == 0
    assert victim.read_text(encoding="utf-8") == "root:ROOT-ONLY-CONTENT:0:0\n"
    assert not record.is_symlink() and record.read_text(encoding="utf-8") == f"{_H1}\n"


@_NOT_ROOT
@pytest.mark.parametrize("case", ["group-writable", "another-owner"])
def test_the_unit_hash_record_counts_only_in_a_directory_root_alone_can_write(tmp_path: Path, case: str) -> None:
    script, record, _old = _record_tool(tmp_path, os.getuid() if case == "group-writable" else os.getuid() + 4242)
    record.parent.mkdir(mode=0o700)
    record.write_text(f"{_H1}\n", encoding="utf-8")
    if case == "group-writable":
        record.parent.chmod(0o770)
    assert _record_run(tmp_path, script, "read").stdout == ""
    proc = _record_run(tmp_path, script, "write", _H2)
    assert proc.returncode != 0 and "not root's alone" in proc.stderr, proc.stderr
    assert record.read_text(encoding="utf-8") == f"{_H1}\n"


@_NOT_ROOT
def test_the_old_record_is_taken_over_once_when_root_wrote_it(tmp_path: Path) -> None:
    """An upgrade from a release that kept the record in the service's directory still recognises the
    unit it deployed, then the old name is removed."""
    script, record, old = _record_tool(tmp_path, os.getuid())
    old.write_text(f"{_H1}\n", encoding="utf-8")
    assert _record_run(tmp_path, script, "read").stdout == f"{_H1}\n"
    assert _record_run(tmp_path, script, "write", _H2).returncode == 0
    assert not old.exists() and record.read_text(encoding="utf-8") == f"{_H2}\n"
    assert _record_run(tmp_path, script, "read").stdout == f"{_H2}\n"


@_NOT_ROOT
@pytest.mark.parametrize("case", ["symlink", "second-link", "service-account-wrote-it", "fifo", "not-a-hash"])
def test_an_old_record_the_service_account_could_have_made_is_not_trusted(tmp_path: Path, case: str) -> None:
    """The reattack: udbmcp wrote the hash of an admin-modified unit into the record, and the next
    upgrade replaced the admin's unit. Only a regular file root owns with one link counts."""
    script, record, old = _record_tool(tmp_path, os.getuid() if case != "service-account-wrote-it" else 4242)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.write_text(f"{_H1}\n", encoding="utf-8")
    if case == "symlink":
        old.symlink_to(elsewhere)
    elif case == "second-link":
        os.link(elsewhere, old)
    elif case == "fifo":
        os.mkfifo(old)
    elif case == "not-a-hash":
        old.write_text(f"{_H1}\nExecStart=/bin/sh\n", encoding="utf-8")
    else:
        old.write_text(f"{_H1}\n", encoding="utf-8")
    proc = _record_run(tmp_path, script, "read")
    assert proc.returncode == 0 and proc.stdout == "", proc.stdout + proc.stderr
    assert elsewhere.read_text(encoding="utf-8") == f"{_H1}\n"
    assert not record.exists(), "nothing untrusted is taken over"


@_NOT_ROOT
def test_the_old_record_is_moved_the_first_time_it_is_read(tmp_path: Path) -> None:
    """An upgrade over an admin-modified unit writes no record (the deployed unit is not the shipped
    one): the old record is moved where root alone can write all the same, never read there again."""
    script, record, old = _record_tool(tmp_path, os.getuid())
    old.write_text(f"{_H1}\n", encoding="utf-8")
    assert _record_run(tmp_path, script, "read").stdout == f"{_H1}\n"
    assert not old.exists() and record.read_text(encoding="utf-8") == f"{_H1}\n"
    assert record.parent.stat().st_mode & 0o777 == 0o700
    assert _record_run(tmp_path, script, "read").stdout == f"{_H1}\n"


def test_postrm_purges_the_record_directory_and_the_old_record() -> None:
    text = POSTRM.read_text(encoding="utf-8")
    purge = text.split("purge)", 1)[1].split("remove)", 1)[0]
    assert 'UNIT_RECORD_DIR="/var/lib/universal-db-mcp-package"' in text
    assert 'rm -rf "$UNIT_RECORD_DIR"' in purge and 'rm -f "$SHIPPED_UNIT_RECORD"' in purge


# The same class on the rollback path: rollback_offline.sh --restore-config copied the backup's
# metadata cache into the service's state directory with cp, as root. cp writes THROUGH a link at
# the destination, so a service account that planted metadata.sqlite (or .pre-rollback) as a link to
# any file root can write had root overwrite that file with content the account chose (its own
# cache, copied aside first). And upgrade_offline.sh backed that cache up with cp, which reads
# through a planted link (any file root can read ends up in the backup, then back in the state
# directory on a restore).

ROLLBACK = REPO / "scripts" / "rollback_offline.sh"


def _rollback_with_cache(tmp_path: Path) -> tuple[Path, Path, dict[str, str]]:
    """A config-only rollback (no venv.previous) whose latest backup holds a metadata cache.
    Returns (state directory, backup cache, env)."""
    target = tmp_path / "target"
    (target / "venv" / "bin").mkdir(parents=True)
    (target / "venv" / "bin" / "python").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    (target / "venv" / "bin" / "python").chmod(0o755)
    backup = tmp_path / "backups" / "pre-upgrade-20260927T000000Z"
    (backup / "universal-db-mcp").mkdir(parents=True)
    (backup / "universal-db-mcp" / "config.yaml").write_text("connections: {}\n", encoding="utf-8")
    (backup / "metadata.sqlite").write_bytes(b"BACKUP-CACHE")
    state = tmp_path / "varlib"
    state.mkdir()
    env = {k: v for k, v in os.environ.items() if not k.startswith(("UDBMCP_", "PYTHON"))}
    env.update(UDBMCP_CONFIG_DIR=str(tmp_path / "etc"), UDBMCP_STATE_DIR=str(state), TMPDIR=str(tmp_path))
    env["PATH"] = f"{_shims(tmp_path)}:{env.get('PATH', '/usr/bin:/bin')}"
    return state, backup / "metadata.sqlite", env


def _rollback(tmp_path: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - repo script under test
        ["/bin/bash", str(ROLLBACK), str(tmp_path / "target"), str(tmp_path / "backups"), "--restore-config"],
        env=env, capture_output=True, text=True, timeout=120, check=False,
    )


@pytest.mark.parametrize("planted", ["metadata.sqlite", "metadata.sqlite.pre-rollback"])
def test_the_cache_restore_never_writes_through_a_link_in_the_state_directory(tmp_path: Path, planted: str) -> None:
    state, _backup, env = _rollback_with_cache(tmp_path)
    victim = tmp_path / "sudoers"
    victim.write_text("root ALL=(ALL) ALL\n", encoding="utf-8")
    if planted == "metadata.sqlite":
        (state / planted).symlink_to(victim)
    else:
        (state / "metadata.sqlite").write_bytes(b"udbmcp ALL=(ALL) NOPASSWD: ALL\n")  # the account's content
        (state / planted).symlink_to(victim)
    proc = _rollback(tmp_path, env)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert victim.read_text(encoding="utf-8") == "root ALL=(ALL) ALL\n"
    cache = state / "metadata.sqlite"
    assert not cache.is_symlink() and cache.read_bytes() == b"BACKUP-CACHE"
    assert cache.stat().st_uid == state.stat().st_uid  # the service's own cache, as before


def test_the_cache_restore_keeps_the_live_cache_aside(tmp_path: Path) -> None:
    state, _backup, env = _rollback_with_cache(tmp_path)
    (state / "metadata.sqlite").write_bytes(b"LIVE-CACHE")
    assert _rollback(tmp_path, env).returncode == 0
    assert (state / "metadata.sqlite").read_bytes() == b"BACKUP-CACHE"
    assert (state / "metadata.sqlite.pre-rollback").read_bytes() == b"LIVE-CACHE"


@pytest.mark.parametrize("kind", ["symlink", "fifo"])
def test_a_backup_cache_that_is_not_a_regular_file_is_never_read(tmp_path: Path, kind: str) -> None:
    """What upgrade_offline.sh's cp -a keeps of a link or FIFO the account planted: not read through."""
    state, backup, env = _rollback_with_cache(tmp_path)
    backup.unlink()
    secret = tmp_path / "shadow"
    secret.write_text("root:$6$hash:0:0\n", encoding="utf-8")
    if kind == "symlink":
        backup.symlink_to(secret)
    else:
        os.mkfifo(backup)
    proc = _rollback(tmp_path, env)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "the metadata cache was not restored" in proc.stderr, proc.stderr
    assert not (state / "metadata.sqlite").exists()


def test_the_upgrade_backs_the_cache_up_without_reading_through_a_link() -> None:
    text = UPGRADE.read_text(encoding="utf-8")
    assert "cp -a /var/lib/universal-db-mcp/metadata.sqlite" in text
    assert "cp /var/lib/universal-db-mcp/metadata.sqlite" not in text


@pytest.mark.parametrize("script", _ROOT_RUN, ids=lambda p: p.name)
def test_no_root_run_script_copies_into_a_directory_the_service_account_owns(script: Path) -> None:
    """cp opens an existing destination and writes through a link there."""
    for number, line in enumerate(script.read_text(encoding="utf-8").splitlines(), 1):
        code = line.split(" #", 1)[0]
        if code.lstrip().startswith("#") or not re.search(r"\bcp\b", code):
            continue
        command = code.split("||")[0].split("&&")[-1]
        try:
            destination = shlex.split(command)[-1]
        except ValueError:  # a continued line: the destination is its last word
            destination = command.split()[-1]
        assert not re.search(r"(/var/(lib|log)/universal-db-mcp|\$\{?(STATE_DIR|LOG_DIR)\b)", destination), (
            f"{script.name}:{number}: {line}"
        )


# ---- the trust bootstrap orders releases -------------------------------------------------------
# bootstrap.sh checked only that the stick is signed by the installed key, then installed the
# stick's trust tools over the installed ones. Every earlier stick signed with that key passes, so
# replaying one put back an older verifier (one without a later fix) without a word.
# release_usb.sh now writes the release_seq into trust-bootstrap-linux/RELEASE, which the signed
# list covers; bootstrap.sh records the value it installed and refuses a lower one.

RELEASE_USB = REPO / "scripts" / "package" / "release_usb.sh"


def _trust_dir(root: Path) -> Path:
    return root / "usr" / "local" / "lib" / "udbmcp-trust"


def _release_stick(tmp_path: Path, keys: tuple[Path, Path], seq: int | str | None) -> Path:
    """A signed stick from the release with *seq* (no RELEASE file when None); its verifier carries
    a marker naming the release."""
    priv, pub = keys
    stick = _stick(tmp_path / f"release-{seq}", pub)
    with (stick / "trust-bootstrap-linux" / "verify_bundle.py").open("a", encoding="utf-8") as f:
        f.write(f"# RELEASE-MARKER-{seq}\n")
    if seq is not None:
        (stick / "trust-bootstrap-linux" / "RELEASE").write_text(f"{seq}\n", encoding="utf-8")
    proc = _sign_stick(tmp_path, stick, priv, pub)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return stick


def _installed_marker(root: Path) -> str:
    return (_trust_dir(root) / "verify_bundle.py").read_text(encoding="utf-8").rsplit("RELEASE-MARKER-", 1)[1].strip()


def _upgrade_with(tmp_path: Path, root: Path, stick: Path, *args: str) -> subprocess.CompletedProcess[str]:
    """The documented upgrade: the INSTALLED bootstrap checks the next stick."""
    return _bootstrap_by(tmp_path, str(_installed_bootstrap(root)), root, "--stick", str(stick), *args)


def _ordered_site(tmp_path: Path) -> tuple[tuple[Path, Path], Path]:
    _key, priv, pub = _keypair(tmp_path)
    root = _site(tmp_path, pub)
    first = _release_stick(tmp_path, (priv, pub), 5)
    proc = _bootstrap(tmp_path, first, root)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert (_trust_dir(root) / "RELEASE").read_text(encoding="utf-8") == "5\n"
    assert "==> release order: stick release 5, nothing recorded yet" in proc.stdout, proc.stdout
    return (priv, pub), root


def test_the_installed_bootstrap_refuses_an_older_signed_stick(tmp_path: Path) -> None:
    keys, root = _ordered_site(tmp_path)
    older = _release_stick(tmp_path, keys, 4)
    before = _snapshot(root)
    proc = _upgrade_with(tmp_path, root, older)
    assert proc.returncode != 0, proc.stdout
    assert "signature verification PASSED" in proc.stdout  # genuinely signed: the order refuses it
    assert "FAIL: this stick is release 4, OLDER than release 5 whose trust tools are installed" in proc.stderr
    assert "--allow-downgrade" in proc.stderr and "Nothing was installed." in proc.stderr, proc.stderr
    assert _snapshot(root) == before, "the trust dir and the checked package copies are byte-identical"
    assert _installed_marker(root) == "5"


def test_an_older_stick_is_installed_only_when_the_downgrade_is_asked_for(tmp_path: Path) -> None:
    keys, root = _ordered_site(tmp_path)
    older = _release_stick(tmp_path, keys, 4)
    proc = _upgrade_with(tmp_path, root, older, "--allow-downgrade")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "WARNING: DOWNGRADE allowed by --allow-downgrade: stick release 4, installed release 5" in proc.stdout
    assert _installed_marker(root) == "4" and (_trust_dir(root) / "RELEASE").read_text(encoding="utf-8") == "4\n"


def test_a_reinstall_and_an_upgrade_pass_and_are_recorded(tmp_path: Path) -> None:
    keys, root = _ordered_site(tmp_path)
    for seq in (5, 6):
        proc = _upgrade_with(tmp_path, root, _release_stick(tmp_path / f"again-{seq}", keys, seq))
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert f"==> release order: stick release {seq}, installed release 5" in proc.stdout, proc.stdout
        assert (_trust_dir(root) / "RELEASE").read_text(encoding="utf-8") == f"{seq}\n"
    assert _installed_marker(root) == "6"


def test_a_stick_that_names_no_release_is_refused_once_one_is_recorded(tmp_path: Path) -> None:
    """Every stick this release builds names its release: one without is from before the order."""
    keys, root = _ordered_site(tmp_path)
    before = _snapshot(root)
    proc = _upgrade_with(tmp_path, root, _release_stick(tmp_path, keys, None))
    assert proc.returncode != 0 and "names no release, OLDER than release 5" in proc.stderr, proc.stderr
    assert _snapshot(root) == before


def test_a_trust_dir_with_no_recorded_release_takes_either_kind_of_stick(tmp_path: Path) -> None:
    """The first run of this bootstrap on a site (installed by an earlier one) has nothing to order by."""
    _key, priv, pub = _keypair(tmp_path)
    root = _site(tmp_path, pub)
    proc = _bootstrap(tmp_path, _release_stick(tmp_path, (priv, pub), None), root)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert not (_trust_dir(root) / "RELEASE").exists()
    proc = _upgrade_with(tmp_path, root, _release_stick(tmp_path, (priv, pub), 3))
    assert proc.returncode == 0 and (_trust_dir(root) / "RELEASE").read_text(encoding="utf-8") == "3\n"


@pytest.mark.parametrize("value", ["5a", "-1", "", "5\n6", "0x10", "9" * 19])
def test_a_stick_release_that_is_not_a_number_is_refused(tmp_path: Path, value: str) -> None:
    _key, priv, pub = _keypair(tmp_path)
    root = _site(tmp_path, pub)
    stick = _stick(tmp_path / "odd", pub)
    (stick / "trust-bootstrap-linux" / "RELEASE").write_text(f"{value}\n", encoding="utf-8")
    signed = _sign_stick(tmp_path, stick, priv, pub)
    assert signed.returncode != 0 and "trust-bootstrap-linux/RELEASE" in signed.stderr, signed.stdout
    # signed anyway (another tool): the site refuses it too
    _sign_with_openssl(tmp_path, stick, priv)
    before = _snapshot(root)
    proc = _bootstrap(tmp_path, stick, root)
    assert proc.returncode != 0 and "is not a release number" in proc.stderr, proc.stdout + proc.stderr
    assert _snapshot(root) == before


def _sign_with_openssl(tmp_path: Path, stick: Path, priv: Path) -> None:
    """SHA256SUMS over every file and its signature, as release_usb.sh writes them, without its checks."""
    files = sorted(p for p in stick.rglob("*") if p.is_file() and p.name not in ("SHA256SUMS", "SHA256SUMS.sig"))
    (stick / "SHA256SUMS").write_text(
        "".join(f"{_sha256(p.read_bytes())}  {p.relative_to(stick)}\n" for p in files), encoding="utf-8"
    )
    env = _tool_env(tmp_path)
    subprocess.run(  # noqa: S603 - the release key's own signature, as release_usb.sh makes it
        [str(tmp_path / "tools" / "openssl"), "pkeyutl", "-sign", "-inkey", str(priv), "-rawin",
         "-in", str(stick / "SHA256SUMS"), "-out", str(stick / "SHA256SUMS.sig")],
        env=env, check=True, capture_output=True,
    )


def test_an_unreadable_installed_release_is_refused_unless_the_downgrade_is_asked_for(tmp_path: Path) -> None:
    keys, root = _ordered_site(tmp_path)
    (_trust_dir(root) / "RELEASE").write_text("garbage\n", encoding="utf-8")
    stick = _release_stick(tmp_path / "next", keys, 6)
    proc = _upgrade_with(tmp_path, root, stick)
    assert proc.returncode != 0 and "cannot be read as a release number" in proc.stderr, proc.stderr
    proc = _upgrade_with(tmp_path, root, stick, "--allow-downgrade")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert (_trust_dir(root) / "RELEASE").read_text(encoding="utf-8") == "6\n"


def test_a_release_changed_on_the_stick_after_signing_is_refused(tmp_path: Path) -> None:
    keys, root = _ordered_site(tmp_path)
    older = _release_stick(tmp_path, keys, 4)
    (older / "trust-bootstrap-linux" / "RELEASE").write_text("9\n", encoding="utf-8")
    before = _snapshot(root)
    proc = _upgrade_with(tmp_path, root, older)
    assert proc.returncode != 0 and "do not match its signed SHA256SUMS" in proc.stderr, proc.stderr
    assert _snapshot(root) == before


@pytest.mark.parametrize("changed", ["1", "99"])
def test_the_release_is_read_from_the_checked_private_copy_never_from_the_stick(tmp_path: Path, changed: str) -> None:
    """The stick's RELEASE changes after every check of the stick (at the `comm` of its file list, the
    last step that reads it before the release order): a lower one would refuse the next legitimate
    stick, a higher one would let older ones be replayed."""
    keys, root = _ordered_site(tmp_path)
    stick = _release_stick(tmp_path / "next", keys, 6)
    on_stick = stick / "trust-bootstrap-linux" / "RELEASE"
    comm = tmp_path / "tools" / "comm"
    comm.write_text(f'#!/bin/sh\nprintf "{changed}\\n" > "{on_stick}"\nexec "{shutil.which("comm")}" "$@"\n',
                    encoding="utf-8")
    comm.chmod(0o755)
    proc = _upgrade_with(tmp_path, root, stick)
    assert on_stick.read_text(encoding="utf-8") == f"{changed}\n", "the stick changed after its checks"
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "==> release order: stick release 6, installed release 5 (not a downgrade)" in proc.stdout, proc.stdout
    assert (_trust_dir(root) / "RELEASE").read_text(encoding="utf-8") == "6\n"
    assert f"    release  : 6 ({_trust_dir(root) / 'RELEASE'})\n" in proc.stdout, proc.stdout


def test_a_downgrade_to_a_stick_that_names_no_release_removes_the_record(tmp_path: Path) -> None:
    """The trust dir then holds tools that name no release: a record left behind would still order the
    next stick by the release it replaced."""
    keys, root = _ordered_site(tmp_path)
    proc = _upgrade_with(tmp_path, root, _release_stick(tmp_path, keys, None), "--allow-downgrade")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "WARNING: DOWNGRADE allowed by --allow-downgrade: stick release none, installed release 5" in proc.stdout
    assert not (_trust_dir(root) / "RELEASE").exists() and _installed_marker(root) == "None"
    assert f"    release  : none named by this stick ({_trust_dir(root) / 'RELEASE'})\n" in proc.stdout, proc.stdout


def test_release_usb_writes_the_release_seq_into_the_signed_trust_folder(tmp_path: Path) -> None:
    text = RELEASE_USB.read_text(encoding="utf-8")
    usb = text[text.index('echo "=== USB folder"'):]
    assert usb.index('> "$USB/trust-bootstrap-linux/RELEASE"') < usb.index('sign_stick "$USB"')
    bundle_seq = next(line for line in text.splitlines() if line.startswith("bundle_seq()"))
    for manifest, expected in (({"release_seq": 12}, "12"), ({"release_seq": "12"}, ""), ({}, ""),
                               ({"release_seq": True}, ""), ({"release_seq": -1}, "")):
        out = tmp_path / str(len(list(tmp_path.iterdir()))) / "bundle"
        (out / "universal-db-mcp-0.1.0").mkdir(parents=True)
        (out / "universal-db-mcp-0.1.0" / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        proc = subprocess.run(  # noqa: S603 - the release script's own function
            ["/bin/bash", "-c", f'PY="{sys.executable}"\n{bundle_seq}\nbundle_seq "$1"', "bundle_seq", str(out)],
            capture_output=True, text=True, timeout=60, check=False,
        )
        assert proc.stdout.strip() == expected, (manifest, proc.stdout)


# ---- I68: the copies named for dpkg -i are all checked, or none is kept ------------------------
# bootstrap.sh emptied /var/cache/udbmcp-trust and copied one .deb at a time into it, checking the
# copies only after the loop: a cp that failed mid-loop ended the script with cp's own error, no
# FAIL line, and the copies made so far (possibly swapped on the stick as they were copied) left
# unchecked exactly where the runbook's thick-mode step runs dpkg -i.


def test_a_failed_copy_for_dpkg_keeps_no_unchecked_package_and_says_so(tmp_path: Path) -> None:
    _key, pub, stick = _signed_stick(tmp_path)
    root = _site(tmp_path, pub)
    earlier = _deb_dir(root) / "universal-db-mcp_0.0.9_amd64.deb"  # an earlier bootstrap's checked copy
    earlier.parent.mkdir(parents=True, mode=0o700)
    earlier.write_bytes(b"!<arch>\nthe previous release\n")
    _tool_env(tmp_path)
    evil = tmp_path / "evil.deb"
    evil.write_bytes(b"!<arch>\ndebian-binary 2.0\ncontrol.tar evil preinst\n")
    libaio, package = stick / ORACLE_DEBS[0], stick / DEB_NAME
    # the libaio .deb (copied first) is swapped as it is copied; the package vanishes before its own copy
    _staging_cp(tmp_path, before=f'case "$*" in *"/{ORACLE_DEBS[0]}"*) /bin/cp "{evil}" "{libaio}" ;; '
                                 f'*"/{DEB_NAME}"*) /bin/rm -f "{package}" ;; esac')
    proc = _bootstrap(tmp_path, stick, root)
    assert proc.returncode != 0, proc.stdout
    assert f"FAIL: {DEB_NAME} could not be copied from the stick" in proc.stderr, proc.stderr
    assert "Nothing was installed." in proc.stderr and "sudo dpkg -i" not in proc.stdout, proc.stderr
    cache = _deb_dir(root).parent
    kept = [p for p in cache.rglob("*") if p.is_file()]
    assert kept == [earlier], "only what an earlier run checked; no unchecked copy anywhere below /var/cache"
    assert evil.read_bytes() not in [p.read_bytes() for p in kept]


@pytest.mark.parametrize("kind", ["symlink", "fifo"])
def test_a_package_that_is_no_regular_file_when_it_is_copied_for_dpkg_is_refused(tmp_path: Path, kind: str) -> None:
    """The listed package becomes a link (to the same bytes, in a file its owner can change later) or a
    FIFO just before its copy: cp -RP copies either as it is. The link's copy would pass the checksum
    and be named for dpkg -i; the FIFO's would block the root checksum run for good."""
    _key, pub, stick = _signed_stick(tmp_path)
    root = _site(tmp_path, pub)
    _tool_env(tmp_path)
    package = stick / DEB_NAME
    elsewhere = tmp_path / "another-account" / DEB_NAME
    elsewhere.parent.mkdir()
    shutil.copy2(package, elsewhere)
    swap = f'/bin/ln -s "{elsewhere}" "{package}"' if kind == "symlink" else f'"{shutil.which("mkfifo")}" "{package}"'
    _staging_cp(tmp_path, before=f'case "$*" in *"{package} "*) /bin/rm -f "{package}"; {swap} ;; esac')
    proc = subprocess.run(  # noqa: S603 - repo script under test
        ["/bin/bash", str(stick / "trust-bootstrap-linux" / "bootstrap.sh")],
        env=_tool_env(tmp_path, UDBMCP_BOOTSTRAP_ROOT=str(root)), capture_output=True, text=True, timeout=60,
        check=False,
    )
    assert package.is_symlink() if kind == "symlink" else package.is_fifo(), "the stick changed as it was copied"
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert f"FAIL: {DEB_NAME} is not a regular file; a release stick holds regular files only." in proc.stderr
    assert "The stick changed while it was read." in proc.stderr and "sudo dpkg -i" not in proc.stdout, proc.stderr
    assert not list(_deb_dir(root).parent.glob(f"{_deb_dir(root).name}.new.*")) and not _deb_dir(root).exists()


def test_the_copies_named_for_dpkg_replace_the_earlier_ones_only_once_checked(tmp_path: Path) -> None:
    text = (REPO / "packaging" / "trust-bootstrap-linux" / "bootstrap.sh").read_text(encoding="utf-8")
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    fresh = code.index('DEB_NEW="$(mktemp -d "$DEB_DIR.new.XXXXXX")"')
    check = code.index('sha256sum -c --strict --quiet "$STAGE/debs"')
    assert fresh < check < code.index('rm -rf -- "$DEB_DIR"') < code.index('mv -- "$DEB_NEW" "$DEB_DIR"')
    assert '"$DEB_NEW"' in code[: fresh].rsplit("trap ", 1)[1].split("\n", 1)[0], "the EXIT trap removes it"


# ---- DECISION-3: the container release record's directory is root's before anything loads ------
# The loader checked the record's directory (and those above it) once, skipping what did not exist
# yet, and created it only after every image had loaded, minutes later. Below a sticky directory
# such as /tmp another account could create it (or one above it) in that window: root's record then
# sat in that account's directory, which later deleted it, and an OLDER release loaded as a first
# load. Now what is missing is created as root first, everything is checked once it exists, and
# checked again right before the record is written.


def _find_with_intruders(tmp_path: Path, intruders: Path) -> Path:
    """find(1) that counts this account's files as root's (_find_as_root), except a search starting
    at a path listed in *intruders* at the time find runs: that one is another account's."""
    from test_hardening_2026_09_27_packaging import _find_as_root, _real_find

    shim = tmp_path / "find-with-intruders"
    shim.write_text(
        "#!/bin/bash\n"
        f'if [ -f "{intruders}" ] && grep -qxF -- "$1" "{intruders}"; then exec "{_real_find(tmp_path)}" "$@"; fi\n'
        f'exec "{_find_as_root(tmp_path)}" "$@"\n',
        encoding="utf-8",
    )
    shim.chmod(0o755)
    return shim


def _intruder_env(tmp_path: Path, pub: Path, record: Path, during_load: str = ":", **extra: str) -> dict[str, str]:
    """_loader_env with the find above, and *during_load* run (as 'another account') when docker
    loads the first image."""
    env = _loader_env(tmp_path, pub, UDBMCP_RELEASE_RECORD=str(record), **extra)
    shims = tmp_path / "shims"
    intruders = tmp_path / "intruders"
    (shims / "find").unlink()
    (shims / "find").symlink_to(_find_with_intruders(tmp_path, intruders))
    docker = shims / "docker"
    text = docker.read_text(encoding="utf-8")
    hook = f'if [ "$1" = load ] && [ ! -e "{tmp_path}/intruded" ]; then : > "{tmp_path}/intruded"; {during_load}; fi\n'
    docker.write_text(text.replace("#!/bin/sh\n", "#!/bin/sh\n" + hook, 1), encoding="utf-8")
    return env


def _run_loader_env(bundle: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - repo script under test
        ["/bin/bash", str(LOADER), str(bundle)], env=env, capture_output=True, text=True, timeout=120, check=False
    )


@_NOT_ROOT
@pytest.mark.parametrize("claimed", ["record-dir", "a-directory-above-it"])
def test_another_account_cannot_take_the_record_directory_while_the_images_load(
    tmp_path: Path, claimed: str
) -> None:
    """The reattack's two-uid run, with the account modelled by the find shim: during the load it
    tries to make the (still absent, before this fix) directory its own."""
    key, _, pub = _keypair(tmp_path)
    shared = tmp_path / "shared-tmp"
    shared.mkdir()
    shared.chmod(0o1777)
    if claimed == "record-dir":  # the reattack's /tmp/udbmcp-rec/release.json
        record = shared / "udbmcp-rec" / "release.json"
        target, created = record.parent, [record.parent]
    else:
        record = shared / "udbmcp" / "records" / "release.json"
        target, created = shared / "udbmcp", [shared / "udbmcp", record.parent]
    grab = f'mkdir "{target}" 2>/dev/null && echo "{target}" >> "{tmp_path}/intruders"'
    env = _intruder_env(tmp_path, pub, record, during_load=grab)
    newer = _bundle(tmp_path / "b5", key, image_identity={"application_image": "udbmcp/universal-db-mcp:test"},
                    release_seq=5)
    (newer / "images").mkdir()
    (newer / "images" / "udbmcp-baseline-ubuntu24.04-cp312.tar").write_bytes(b"BASELINE")
    from test_hardening_2026_09_27_packaging import _sign_bundle

    _sign_bundle(newer, key)
    proc = _run_loader_env(newer, env)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert (tmp_path / "intruded").exists(), "the load ran"
    assert not (tmp_path / "intruders").exists(), "the directory was root's before the load began"
    assert record.read_bytes() == (newer / "manifest.json").read_bytes()
    for directory in created:
        assert directory.stat().st_mode & 0o777 == 0o755, directory


@_NOT_ROOT
def test_a_directory_another_account_made_before_the_loader_created_it_is_refused(tmp_path: Path) -> None:
    """The narrow window between the first check and the creation: the check of what now exists
    finds the other account's directory, before anything is verified or loaded."""
    key, _, pub = _keypair(tmp_path)
    shared = tmp_path / "shared-tmp"
    shared.mkdir()
    shared.chmod(0o1777)
    record = shared / "udbmcp" / "release.json"
    env = _intruder_env(tmp_path, pub, record)
    # the other account wins the race for the directory: sudo runs its mkdir first
    sudo = tmp_path / "shims" / "sudo"
    sudo.write_text(
        '#!/bin/sh\n'
        f'if [ "$1" = mkdir ] && [ ! -e "{record.parent}" ]; then '
        f'/bin/mkdir "{record.parent}" && echo "{record.parent}" >> "{tmp_path}/intruders"; fi\n'
        'exec "$@"\n',
        encoding="utf-8",
    )
    bundle, _ = _image_bundle(tmp_path, "b5", (key, pub), release_seq=5)
    proc = _run_loader_env(bundle, env)
    assert proc.returncode != 0, proc.stdout
    assert f"\n      {record.parent} is not root's alone" in proc.stderr, proc.stderr
    assert "bundle verification PASSED" not in proc.stdout and _loaded(tmp_path) == {}
    assert not record.exists()


@_NOT_ROOT
def test_the_record_is_checked_again_right_before_it_is_written(tmp_path: Path) -> None:
    key, _, pub = _keypair(tmp_path)
    record = _release_record(tmp_path)
    loosen = f'chmod 0777 "{record.parent}"'
    env = _intruder_env(tmp_path, pub, record, during_load=loosen)
    bundle, _ = _image_bundle(tmp_path, "b5", (key, pub), release_seq=5)
    proc = _run_loader_env(bundle, env)
    assert proc.returncode != 0, proc.stdout
    assert set(_loaded(tmp_path)) == {APP_TAR, BASELINE_TAR}
    assert f"\n      {record.parent} is not root's alone" in proc.stderr, proc.stderr
    assert "the record was not written" in proc.stderr, proc.stderr
    assert not record.exists()


@_NOT_ROOT
def test_a_record_below_a_world_writable_directory_draws_a_warning_about_persistent_storage(
    tmp_path: Path,
) -> None:
    """tmpfs empties /tmp at boot and systemd-tmpfiles ages /tmp and /var/tmp out: a lost record lets
    an older release load as a first load, with no attacker at all."""
    key, _, pub = _keypair(tmp_path)
    shared = tmp_path / "shared-tmp"
    shared.mkdir()
    shared.chmod(0o1777)
    record = shared / "udbmcp" / "release.json"
    bundle, _ = _image_bundle(tmp_path, "b5", (key, pub), release_seq=5)
    proc = _run_loader_env(bundle, _loader_env(tmp_path, pub, UDBMCP_RELEASE_RECORD=str(record)))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert f"WARNING: the release record {record} is below {shared}, a directory every account can write" \
        in proc.stdout, proc.stdout
    assert "persistent storage" in proc.stdout and "/var/lib/udbmcp-images/release.json" in proc.stdout
    plain = _run_loader_env(bundle, _loader_env(tmp_path, pub))
    below_world_writable = any(p.stat().st_mode & 0o002 for p in _release_record(tmp_path).parents)
    assert plain.returncode == 0 and ("persistent storage" in plain.stdout) == below_world_writable, plain.stdout


# ---- pkg postinstall: the /Applications wrapper is built where root alone can write -----------
# /Applications is root:admin 0775, so an admin-group process without a password can create
# 'Configure UniversalDB MCP.app' first, with its Contents entries as links: step 9's cat >, chown
# and chmod ran as root and followed them (clobbering, re-owning and re-moding files it chose).

PKG_POSTINSTALL = REPO / "packaging" / "pkg" / "postinstall"
_APP = "/Applications/Configure UniversalDB MCP.app"


def _step9() -> str:
    text = PKG_POSTINSTALL.read_text(encoding="utf-8")
    return text[text.index("# --- step 9") : text.index('echo "==> postinstall complete')]


def _run_step9(tmp_path: Path, app: Path) -> subprocess.CompletedProcess[str]:
    prefix = tmp_path / "prefix"
    (prefix / "share").mkdir(parents=True, exist_ok=True)
    block = _step9()
    assert block.count(f'APP_DIR="{_APP}"') == 1
    block = block.replace(f'APP_DIR="{_APP}"', f'APP_DIR="{app}"')
    assert block.count('APP_BUILD_BASE="/var/tmp"\n') == 1
    block = block.replace('APP_BUILD_BASE="/var/tmp"\n', f'APP_BUILD_BASE="{tmp_path / "root-tmp"}"\n')
    script = tmp_path / "step9.sh"
    script.write_text(
        f'#!/bin/bash\nset -eu\nPREFIX="{prefix}"\nPY="{sys.executable}"\n'
        'APP_SRC="$PREFIX/share/configure_agents_app.sh"\n' + block,
        encoding="utf-8",
    )
    env = {k: v for k, v in os.environ.items() if not k.startswith(("UDBMCP_", "PYTHON"))}
    env["TMPDIR"] = str(tmp_path / "anyone-writes")  # never where the build happens
    (tmp_path / "root-tmp").mkdir(exist_ok=True)
    return subprocess.run(  # noqa: S603 - the postinstall's own step
        ["/bin/bash", str(script)], env=env, capture_output=True, text=True, timeout=60, check=False
    )


def _victim(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    path.chmod(0o600)
    return path


def _assert_app(app: Path, prefix: Path) -> None:
    info, wrapper = app / "Contents" / "Info.plist", app / "Contents" / "MacOS" / "udbmcp-configure"
    for path in (app, app / "Contents", app / "Contents" / "MacOS", info, wrapper):
        assert not path.is_symlink(), path
    assert "com.udbmcp.configure-agents" in info.read_text(encoding="utf-8")
    assert f'exec "{prefix}/share/configure_agents_app.sh" "$@"' in wrapper.read_text(encoding="utf-8")
    assert info.stat().st_mode & 0o777 == 0o644 and wrapper.stat().st_mode & 0o777 == 0o755


def test_the_app_wrapper_never_writes_or_re_modes_through_a_planted_link(tmp_path: Path) -> None:
    app = tmp_path / "Applications" / "Configure UniversalDB MCP.app"
    (app / "Contents" / "MacOS").mkdir(parents=True)
    plist_victim = _victim(tmp_path / "sudoers", "root ALL=(ALL) ALL\n")
    wrapper_victim = _victim(tmp_path / "authorized_keys", "ssh-ed25519 AAAA admin\n")
    (app / "Contents" / "Info.plist").symlink_to(plist_victim)
    (app / "Contents" / "MacOS" / "udbmcp-configure").symlink_to(wrapper_victim)
    proc = _run_step9(tmp_path, app)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert plist_victim.read_text(encoding="utf-8") == "root ALL=(ALL) ALL\n"
    assert wrapper_victim.read_text(encoding="utf-8") == "ssh-ed25519 AAAA admin\n"
    assert plist_victim.stat().st_mode & 0o777 == 0o600 and wrapper_victim.stat().st_mode & 0o777 == 0o600
    _assert_app(app, tmp_path / "prefix")
    assert list((tmp_path / "root-tmp").iterdir()) == [], "the build directory is removed"


def test_the_app_wrapper_replaces_a_linked_app_and_leaves_where_it_led_alone(tmp_path: Path) -> None:
    elsewhere = tmp_path / "LaunchDaemons"
    elsewhere.mkdir()
    (elsewhere / "com.example.plist").write_text("<plist/>\n", encoding="utf-8")
    app = tmp_path / "Applications" / "Configure UniversalDB MCP.app"
    app.parent.mkdir()
    app.symlink_to(elsewhere)
    proc = _run_step9(tmp_path, app)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert sorted(p.name for p in elsewhere.iterdir()) == ["com.example.plist"]
    _assert_app(app, tmp_path / "prefix")


def test_step9_writes_changes_and_re_modes_nothing_below_applications_in_place() -> None:
    code = [line for line in _step9().splitlines() if not line.lstrip().startswith("#")]
    for line in code:
        if re.search(r"(^|[^<>0-9&])>(?!&)|\bchmod\b|\bchown\b|\binstall\b|\bcat\b", line):
            assert "$APP_DIR" not in line, line


# ---- I71: the CI workflow's header says what uv verifies ----------------------------------------


def test_the_ci_header_does_not_claim_uv_verifies_the_build_backends_hashes() -> None:
    """uv verifies uv.lock's hashes for what it installs; the project is built from the checkout by a
    hatchling that build-constraint-dependencies pins by version only (uv.lock records no hash)."""
    header = []
    for line in (REPO / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8").splitlines():
        if not line.startswith("#"):
            break
        header.append(line.lstrip("# "))
    text = " ".join(header)
    assert "The project and its test tools install from uv.lock, whose hashes uv verifies" not in text
    assert "whose hashes uv verifies" in text and "by version only" in text, text
    constraints = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))["tool"]["uv"]
    assert all("--hash" not in c and "==" in c for c in constraints["build-constraint-dependencies"])


# ---- the private copy of the stick holds only what the signed list names -----------------------
# bootstrap.sh compared the files on the STICK with the signed list, but read RELEASE from its private
# copy whenever the file was there. A stick that changes while it is read showed a RELEASE only while
# the trust folder was copied: an unsigned number decided the release order and was recorded. So the
# private copy itself is compared with the list before anything in it is read.


def _present_only_while_copied(tmp_path: Path, path: Path, content: str) -> None:
    """*path* is on the stick while bootstrap.sh copies the trust folder, and gone again right after."""
    _staging_cp(
        tmp_path,
        before=f'case "$*" in *"/trust-bootstrap-linux "*) printf "{content}" > "{path}" ;; esac',
        after=f'/bin/rm -f "{path}"',
    )


def test_a_release_the_signed_list_does_not_name_never_decides_the_order(tmp_path: Path) -> None:
    keys, root = _ordered_site(tmp_path)
    older = _release_stick(tmp_path, keys, None)  # genuinely signed, from before RELEASE
    _present_only_while_copied(tmp_path, older / "trust-bootstrap-linux" / "RELEASE", "999999\\n")
    before = _snapshot(root)
    proc = _upgrade_with(tmp_path, root, older)
    assert proc.returncode != 0, proc.stdout
    assert "FAIL: trust-bootstrap-linux/RELEASE is in the private copy of the stick but not on its signed " \
        "SHA256SUMS" in proc.stderr, proc.stderr
    assert "The stick changed while it was read." in proc.stderr and "release order" not in proc.stdout
    assert _snapshot(root) == before and _installed_marker(root) == "5"


@pytest.mark.parametrize("rel", ["helper.sh", "lib/extra.sh"])
def test_a_file_present_only_while_the_trust_folder_is_copied_is_refused(tmp_path: Path, rel: str) -> None:
    _key, pub, stick = _signed_stick(tmp_path)
    root = _site(tmp_path, pub)
    _present_only_while_copied(tmp_path, stick / "trust-bootstrap-linux" / rel, "echo planted\\n")
    before = _snapshot(root)
    proc = _bootstrap(tmp_path, stick, root)
    assert proc.returncode != 0, proc.stdout
    assert f"FAIL: trust-bootstrap-linux/{rel} is in the private copy of the stick but not on its signed " \
        "SHA256SUMS" in proc.stderr, proc.stderr
    assert _snapshot(root) == before


def test_mac_metadata_in_the_private_copy_is_skipped_as_it_is_on_the_stick(tmp_path: Path) -> None:
    _key, pub, stick = _signed_stick(tmp_path)
    root = _site(tmp_path, pub)
    _present_only_while_copied(tmp_path, stick / "trust-bootstrap-linux" / "._verify_bundle.py", "x")
    proc = _bootstrap(tmp_path, stick, root)
    assert proc.returncode == 0, proc.stdout + proc.stderr


# ---- no gate copies a bundle as hard links ------------------------------------------------------
# The verifier refuses a SHA256SUMS or SIGNATURE with a second link (whoever holds the other name can
# change it). test_package_deb.sh's copy_tree fell back to `cp -al` where cp has no -c (GNU cp, every
# Linux host): build_deb.sh then refused the gate's own copy, and the original with it.

_COPYING_SCRIPTS = [REPO / "scripts" / "package" / name for name in (
    "build_deb.sh", "build_pkg.sh", "build_msi.sh", "release_usb.sh", "test_package_deb.sh",
    "test_package_pkg.sh", "test_upgrade_offline.sh",
)] + [INSTALL, UPGRADE, LOADER, REPO / "scripts" / "rollback_offline.sh",
      REPO / "packaging" / "trust-bootstrap-linux" / "bootstrap.sh"]


def _hard_link_copies(text: str) -> list[str]:
    """The lines of *text* that make a hard link: cp -l/-al/--link, ln without -s, rsync --link-dest."""
    hits = []
    for line in text.splitlines():
        code = line.split(" #", 1)[0]
        if code.lstrip().startswith("#"):
            continue
        for match in re.finditer(r"\bcp((?:\s+--?[A-Za-z][-A-Za-z=]*)+)", code):
            if any(o == "--link" or (not o.startswith("--") and "l" in o[1:]) for o in match.group(1).split()):
                hits.append(line)
        command = r"(?:^|[;&|]|\bthen|\bdo|\bsudo|\$sudo_ok)\s*"  # ln where a command starts
        for match in re.finditer(command + r"ln((?:\s+--?[A-Za-z][-A-Za-z]*)*)\s+[\"$/.~\w]", code):
            if not any(o == "--symbolic" or (not o.startswith("--") and "s" in o[1:]) for o in match.group(1).split()):
                hits.append(line)
        if re.search(r"--link-dest|\bos\.link\(", code):
            hits.append(line)
    return hits


@pytest.mark.parametrize(
    ("line", "hard"),
    [('  if cp -al "$1" "$2" 2>/dev/null; then', True), ('cp -l "$a" "$b"', True), ("cp --link -R a b", True),
     ("ln a b", True), ("  sudo ln -f a b", True), ("rsync -a --link-dest=../prev a b", True),
     ('if cp -cR "$1" "$2"; then', False), ('cp -R --reflink=auto "$1" "$2"', False), ('cp -a "$B"/. "$S/"', False),
     ('$sudo_ok ln -sfn "$V" "$A"', False), ("text = '\\n'.join(ln for ln in lines)", False)],
)
def test_the_hard_link_detector(line: str, hard: bool) -> None:
    assert bool(_hard_link_copies(line)) is hard


@pytest.mark.parametrize("script", _COPYING_SCRIPTS, ids=lambda p: p.name)
def test_no_gate_builder_or_installer_copies_with_hard_links(script: Path) -> None:
    assert _hard_link_copies(script.read_text(encoding="utf-8")) == []


def _copy_tree() -> str:
    text = (REPO / "scripts" / "package" / "test_package_deb.sh").read_text(encoding="utf-8")
    start = text.index("copy_tree() {")
    return text[start : text.index("\n}\n", start) + 3]


@pytest.mark.parametrize("flavour", ["gnu-cp", "this-hosts-cp"])
def test_the_deb_gates_bundle_copy_is_one_the_verifier_accepts(tmp_path: Path, flavour: str) -> None:
    """GNU cp has no -c (APFS clone): the copy made there must still be one link per file."""
    bundle, pub = _signed(tmp_path)
    env = {k: v for k, v in os.environ.items() if not k.startswith("UDBMCP_")}
    if flavour == "gnu-cp":
        shims = tmp_path / "gnu"
        shims.mkdir()
        (shims / "cp").write_text(
            '#!/bin/bash\ncase "$1" in -c*) echo "cp: invalid option -- \'c\'" >&2; exit 1 ;; esac\n'
            'args=()\nfor a in "$@"; do [ "$a" = --reflink=auto ] || args+=("$a"); done\n'
            'exec /bin/cp "${args[@]}"\n',
            encoding="utf-8",
        )
        (shims / "cp").chmod(0o755)
        env["PATH"] = f"{shims}:{env.get('PATH', '/usr/bin:/bin')}"
    copy = tmp_path / "neg" / "bundle"
    copy.parent.mkdir()
    subprocess.run(  # noqa: S603 - the gate's own function
        ["/bin/bash", "-c", f'{_copy_tree()}\ncopy_tree "$1" "$2"', "copy_tree", str(bundle), str(copy)],
        env=env, check=True, capture_output=True, timeout=60,
    )
    for name in ("SHA256SUMS", "SIGNATURE", "manifest.json"):
        assert (copy / name).stat().st_nlink == 1 and (bundle / name).stat().st_nlink == 1, name
    for tree in (bundle, copy):
        proc = _verify("--bundle", tree, "--pubkey", pub, "--no-installed-manifest")
        assert proc.returncode == 0, proc.stdout


# ---- the staging base is root's alone -----------------------------------------------------------
# The installers and the loader verify a private root-only copy of the bundle, then use it as root for
# minutes. The copy was made in UDBMCP_STAGING_DIR as given: below a directory another account can
# write, that account renamed the verified copy away and put its own in its place, and docker load,
# dpkg -i and pip read THAT. The base, and every directory above it, must now be root's alone (or a
# root-owned sticky directory such as /var/tmp), as the loader's release record directory must be.

_REFUSED_BASE = "FAIL: the private copy of the bundle would be made in "


def _another_accounts(tmp_path: Path, hidden: Path, fallthrough: Path | str) -> None:
    """A find(1) first on the scripts' PATH that finds nothing at *hidden* (another account owns it,
    so no root-owned directory is there) and asks *fallthrough* about everything else."""
    shim = tmp_path / "shims" / "find"
    shim.parent.mkdir(exist_ok=True)
    if shim.is_symlink() or shim.exists():
        shim.unlink()
    shim.write_text(
        f'#!/bin/bash\n[ "$1" = "{os.path.realpath(hidden)}" ] && exit 0\nexec "{fallthrough}" "$@"\n',
        encoding="utf-8",
    )
    shim.chmod(0o755)


def _base_for(tmp_path: Path, case: str) -> tuple[Path, Path]:
    """(the staging base, the directory the refusal must name) for *case*."""
    if case == "writable-parent":
        shared = tmp_path / "shared"
        shared.mkdir()
        shared.chmod(0o777)  # not sticky: whoever can write it renames what is in it
        base = shared / "disk"
        base.mkdir()
        base.chmod(0o755)
        return base, shared
    base = tmp_path / "operator-big-disk"
    base.mkdir()
    base.chmod(0o777 if case == "world-writable" else 0o755)  # another-owner: only the owner differs
    return base, base


def _system_find() -> str:
    return "/usr/bin/find" if Path("/usr/bin/find").exists() else str(shutil.which("find"))


@_NOT_ROOT
@pytest.mark.parametrize("case", ["world-writable", "another-owner", "writable-parent"])
def test_the_loader_refuses_a_staging_base_another_account_can_write(tmp_path: Path, case: str) -> None:
    """The reviewer's probe: once both verifications pass, the account that can write the base swaps
    the verified copy for its own (the sudo shim's first `test -f` of a tar)."""
    bundle, pub = _image_bundle(tmp_path)
    evil = tmp_path / "evil-copy"
    shutil.copytree(bundle, evil)
    (evil / "images" / APP_TAR).write_bytes(b"EVIL-APP-IMAGE-TAR" * 64)
    base, untrusted = _base_for(tmp_path, case)
    env = _loader_env(tmp_path, pub, UDBMCP_STAGING_DIR=str(base))
    if case == "another-owner":
        _another_accounts(tmp_path, base, _find_as_root(tmp_path))
    (tmp_path / "shims" / "sudo").write_text(
        "#!/bin/sh\n"
        f'if [ "$1" = test ] && [ "$2" = -f ] && [ ! -e "{tmp_path}/swapped" ]; then\n'
        f'  : > "{tmp_path}/swapped"; s="$(dirname "$(dirname "$3")")"\n'
        f'  /bin/mv "$s" "$s.gone" && /bin/mkdir "$s" && /bin/cp -R "{evil}/." "$s/"\n'
        "fi\n"
        'exec "$@"\n',
        encoding="utf-8",
    )
    proc = _run_loader_env(bundle, env)
    assert proc.returncode != 0, proc.stdout
    assert f"{_REFUSED_BASE}{base}, and {untrusted} is not root's alone" in proc.stderr, proc.stderr
    assert "No image was loaded." in proc.stderr and _loaded(tmp_path) == {}
    assert not list(base.glob("udbmcp-*")) and not (tmp_path / "swapped").exists()


@_NOT_ROOT
def test_the_loader_stages_below_a_sticky_directory_and_by_the_real_path_of_a_link(tmp_path: Path) -> None:
    """The default staging base is a root-owned sticky directory: nobody else renames what root makes
    there. A base named through a link is used where the link leads, and checked there."""
    bundle, pub = _image_bundle(tmp_path)
    sticky = tmp_path / "var-tmp"
    sticky.mkdir()
    sticky.chmod(0o1777)
    link = tmp_path / "staging-link"
    link.symlink_to(sticky)
    for base in (sticky / "udbmcp-stage", link):
        env = _loader_env(tmp_path, pub, UDBMCP_STAGING_DIR=str(base))
        log = tmp_path / f"sudo-{base.name}.log"
        (tmp_path / "shims" / "sudo").write_text(f'#!/bin/sh\necho "$*" >> "{log}"\nexec "$@"\n', encoding="utf-8")
        proc = _run_loader_env(bundle, env)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        made = [line for line in log.read_text(encoding="utf-8").splitlines() if line.startswith("mktemp -d ")]
        assert made == [f"mktemp -d {os.path.realpath(base)}/udbmcp-images.XXXXXX"], made
    assert (sticky / "udbmcp-stage").is_dir() and not list(sticky.rglob("udbmcp-images.*"))


@_NOT_ROOT
@pytest.mark.parametrize("script", [INSTALL, UPGRADE], ids=["install", "upgrade"])
@pytest.mark.parametrize("case", ["world-writable", "another-owner", "writable-parent"])
def test_the_installers_refuse_a_staging_base_another_account_can_write(
    tmp_path: Path, script: Path, case: str
) -> None:
    key, _, _pub = _keypair(tmp_path)
    bundle = _bundle(tmp_path / "bundle", key)
    base, untrusted = _base_for(tmp_path, case)
    if case == "another-owner":
        _another_accounts(tmp_path, base, _system_find())
    target = tmp_path / "target"
    extra = [str(tmp_path / "backups")] if script == UPGRADE else []
    proc = _run_installer(tmp_path, script, [str(bundle), str(target), *extra], REPO / "scripts" / "verify_bundle.py",
                          UDBMCP_STAGING_DIR=str(base))
    assert proc.returncode != 0, proc.stdout
    assert "bundle verification PASSED" in proc.stdout  # the refusal is the base's, not the bundle's
    assert f"{_REFUSED_BASE}{base}, and {untrusted} is not root's alone" in proc.stderr, proc.stderr
    assert ("Installation ABORTED." if script == INSTALL else "Upgrade ABORTED.") in proc.stderr
    assert not list(base.glob("udbmcp-*")) and not (tmp_path / "backups").exists()


def _root_only_blocks() -> list[str]:
    start, end = "# >>> directories root alone can change", "# <<< directories root alone can change"
    blocks = []
    for script in (INSTALL, UPGRADE, LOADER):
        text = script.read_text(encoding="utf-8")
        assert text.count(start) == 1 and text.count(end) == 1, script.name
        blocks.append(text[text.index(start) : text.index(end)])
    return blocks


def test_the_installers_and_the_loader_share_one_root_only_check() -> None:
    blocks = _root_only_blocks()
    assert blocks[0] == blocks[1] == blocks[2]
    for script, done in ((INSTALL, "Installation ABORTED."), (UPGRADE, "Upgrade ABORTED."),
                         (LOADER, "No image was loaded.")):
        code = script.read_text(encoding="utf-8")
        assert f'STAGING_BASE="$(staging_base "${{UDBMCP_STAGING_DIR:-/var/tmp}}" "{done}")" || exit 1' in code
        assert code.index("STAGING_BASE=") < code.index('mktemp -d "$STAGING_BASE/')
        assert "mkdir -p \"$STAGING_BASE\"" not in code


# ---- root keeps nothing in a TMPDIR another account controls ------------------------------------
# The verifier's output went to mktemp "${TMPDIR:-/tmp}/..." and root's shell redirect then opened it
# by name. `sudo -E` keeps the caller's TMPDIR: the account that owns it swapped the fresh file for a
# link, and root wrote the verifier's output (bundle file names included, line breaks and all) into
# whatever file the link named. Output is now kept in the shell, the verifier prints a name the bundle
# chose on one line, and a TMPDIR that is not root's alone is not used by the installers at all (pip,
# python -m venv and bash's here-documents would otherwise make root's files there too).

_ALL_ROOT_RUN = [*_ROOT_RUN, LOADER, REPO / "packaging" / "deb" / "prerm",
                 REPO / "packaging" / "trust-bootstrap-linux" / "bootstrap.sh"]


@pytest.mark.parametrize("script", sorted(set(_ALL_ROOT_RUN)), ids=lambda p: p.name)
def test_no_root_run_script_makes_a_file_in_tmpdir(script: Path) -> None:
    for number, line in enumerate(script.read_text(encoding="utf-8").splitlines(), 1):
        code = line.split(" #", 1)[0]
        if code.lstrip().startswith("#") or not re.search(r"\bmktemp\b", code):
            continue
        assert "TMPDIR" not in code and "-t" not in code.split("mktemp", 1)[1].split(")")[0].split(), \
            f"{script.name}:{number}: {line}"
        assert re.search(r"\bmktemp(\s+-d)?\s+\"?[$/][^\s\"]*XXXXXX", code), f"{script.name}:{number}: {line}"


def _swapping_mktemp(shims: Path, victim: Path) -> None:
    """mktemp as it is, then the account that owns TMPDIR wins the race: a fresh file there becomes a
    link to *victim*."""
    shims.mkdir(exist_ok=True)
    real = shutil.which("mktemp") or "/usr/bin/mktemp"
    shim = shims / "mktemp"
    shim.write_text(
        f'#!/bin/sh\nf="$("{real}" "$@")" || exit\n'
        f'case "$f" in "$TMPDIR"/*) [ -d "$f" ] || {{ /bin/rm -f "$f"; /bin/ln -s "{victim}" "$f"; }} ;; esac\n'
        'printf "%s\\n" "$f"\n',
        encoding="utf-8",
    )
    shim.chmod(0o755)


_INJECTED = "ALIAS_LINE_CHOSEN_BY_THE_BUNDLE_AUTHOR=1  # "


@pytest.mark.parametrize("script", [INSTALL, UPGRADE, LOADER], ids=["install", "upgrade", "loader"])
def test_root_writes_the_verifiers_output_nowhere_a_tmpdir_link_leads(tmp_path: Path, script: Path) -> None:
    victim = tmp_path / "etc-profile.d-zz.sh"
    victim.write_text("# root's file\n", encoding="utf-8")
    operator_tmp = tmp_path / "operator-tmp"  # sudo -E keeps the caller's TMPDIR
    operator_tmp.mkdir()
    if script == LOADER:
        bundle, pub = _image_bundle(tmp_path)
        env = _loader_env(tmp_path, pub, TMPDIR=str(operator_tmp))
    else:
        key, _, _pub = _keypair(tmp_path)
        bundle = _bundle(tmp_path / "bundle", key)
    (bundle / f"x\n{_INJECTED}\n").write_text("planted\n", encoding="utf-8")
    _swapping_mktemp(tmp_path / "shims", victim)
    if script == LOADER:
        proc = _run_loader_env(bundle, env)
    else:
        extra = [str(tmp_path / "backups")] if script == UPGRADE else []
        proc = _run_installer(tmp_path, script, [str(bundle), str(tmp_path / "target"), *extra],
                              REPO / "scripts" / "verify_bundle.py", TMPDIR=str(operator_tmp))
    assert proc.returncode != 0, proc.stdout
    assert "NOT covered by SHA256SUMS: x\\nALIAS_LINE" in proc.stdout, proc.stdout
    assert victim.read_text(encoding="utf-8") == "# root's file\n"
    assert not any(line.startswith("ALIAS_LINE") for line in proc.stdout.splitlines()), proc.stdout


def test_the_verifier_prints_a_name_the_bundle_chose_on_one_line(tmp_path: Path) -> None:
    bundle, pub = _signed(tmp_path)
    for name in (f"x\n{_INJECTED}", "tab\there", "cr\rbundle verification PASSED"):
        (bundle / name).write_text("planted\n", encoding="utf-8")
    (bundle / "manifest.json").write_text(json.dumps({
        "profile": "p\nFAKE-PROFILE-LINE", "created": "2026\nFAKE-CREATED-LINE",
        "connector_wheel_status": {"missing_from_closure": ["a\nFAKE-MISSING-LINE"]},
        "administrator_supplied": {"k\nFAKE-KEY-LINE": "v\nFAKE-VALUE-LINE"},
    }), encoding="utf-8")
    installed = tmp_path / "installed.json"
    installed.write_text(json.dumps({"created": "2026-01-01T00:00:00+00:00"}), encoding="utf-8")
    proc = _verify("--bundle", bundle, "--pubkey", pub, "--installed-manifest", installed)
    assert proc.returncode == 1
    lines = proc.stdout.replace("\r", "\n").splitlines()
    assert not [line for line in lines if line.startswith(("ALIAS_LINE", "FAKE-", "bundle verification PASSED"))], \
        proc.stdout
    assert "NOT covered by SHA256SUMS: x\\nALIAS_LINE" in proc.stdout and "tab\\there" in proc.stdout


# What the scripts start as root (pip, python -m venv's ensurepip, bash's here-documents, podman) makes
# its temporary files in TMPDIR, and python's tempfile takes TEMP, then TMP, when TMPDIR is unset;
# `sudo -E` and a plain su keep all three. Dropping only TMPDIR sent ensurepip's copy of pip into a
# TEMP another account could write, and a TMPDIR that was a link there was checked by its target but
# used by its name, which that account could re-point afterwards.

_TEMP_VARS = ("TMPDIR", "TEMP", "TMP")


def _root_python_sees(
    tmp_path: Path, script: Path, stub_code: str, **temp_env: str
) -> tuple[subprocess.CompletedProcess[str], dict[str, Any]]:
    """Run *script* to its first root python: a verifier stub that runs *stub_code*, makes a temporary
    file as ensurepip and pip do, records where and what it was given, and refuses. Each of TMPDIR,
    TEMP and TMP not in *temp_env* is empty."""
    seen = tmp_path / "root-python-saw.json"
    env = {var: "" for var in _TEMP_VARS} | temp_env
    if script == LOADER:
        bundle, pub = _image_bundle(tmp_path)
        loader_env = _loader_env(tmp_path, pub, **env)
    else:
        key, _, _pub = _keypair(tmp_path)
        bundle = _bundle(tmp_path / "bundle", key)
    stub = tmp_path / "trust" / "verify_bundle.py"
    stub.parent.mkdir(parents=True, exist_ok=True)
    stub.write_text(
        "import json, os, tempfile\n"
        f"{stub_code}\n"
        "fd, made = tempfile.mkstemp()\n"
        "os.close(fd)\n"
        f"saw = {{'env': {{v: os.environ.get(v) for v in {_TEMP_VARS!r}}}, "
        "'made_in': os.path.dirname(os.path.realpath(made))}\n"
        "os.unlink(made)\n"
        f"json.dump(saw, open({str(seen)!r}, 'w'))\n"
        "raise SystemExit(1)\n",
        encoding="utf-8",
    )
    if script == LOADER:
        proc = _run_loader_env(bundle, loader_env)
    else:
        extra = [str(tmp_path / "backups")] if script == UPGRADE else []
        proc = _run_installer(tmp_path, script, [str(bundle), str(tmp_path / "target"), *extra], stub, **env)
    assert proc.returncode != 0, proc.stdout
    return proc, json.loads(seen.read_text(encoding="utf-8"))


@pytest.mark.parametrize("var", _TEMP_VARS)
@pytest.mark.parametrize("script", [INSTALL, UPGRADE, LOADER], ids=["install", "upgrade", "loader"])
def test_root_makes_no_temporary_file_in_a_directory_another_account_can_write(
    tmp_path: Path, script: Path, var: str
) -> None:
    world = tmp_path / "world"
    world.mkdir()
    world.chmod(0o777)  # another account can write it: not root's alone
    proc, saw = _root_python_sees(tmp_path, script, "", **{var: str(world)})
    assert saw["env"] == dict.fromkeys(_TEMP_VARS), saw
    assert not saw["made_in"].startswith(os.path.realpath(world)), saw
    assert f"NOTE: {var} ({world}) is not root's alone; root's temporary files are not made there" in proc.stdout, \
        proc.stdout


@pytest.mark.parametrize("var", _TEMP_VARS)
@pytest.mark.parametrize("script", [INSTALL, UPGRADE, LOADER], ids=["install", "upgrade", "loader"])
def test_a_temporary_directory_root_alone_can_change_is_used_by_the_real_path_that_was_checked(
    tmp_path: Path, script: Path, var: str
) -> None:
    """A link to it from a directory another account can write passes the check (its target is root's
    alone). That account re-points the link afterwards, as the stub does first: root's temporary
    files still go where the check looked."""
    world, own, evil = tmp_path / "world", tmp_path / "own", tmp_path / "evil"
    world.mkdir()
    world.chmod(0o777)
    own.mkdir(mode=0o700)  # root's alone (this account stands in for root)
    evil.mkdir()
    link = world / "t"
    link.symlink_to(own)
    repoint = f"os.unlink({str(link)!r}); os.symlink({str(evil)!r}, {str(link)!r})"
    proc, saw = _root_python_sees(tmp_path, script, repoint, **{var: str(link)})
    assert link.resolve() == evil.resolve(), "the stub re-pointed the link"
    assert saw["env"] == {v: os.path.realpath(own) if v == var else None for v in _TEMP_VARS}, saw
    assert saw["made_in"] == os.path.realpath(own), saw
    assert f"NOTE: {var}" not in proc.stdout, proc.stdout


def _recording_python3(tools: Path, log: Path) -> None:
    """python3 first on PATH: this python, after it logs the temporary-directory variables it got."""
    tools.mkdir(exist_ok=True)
    shim = tools / "python3"
    shim.write_text(
        "#!/bin/sh\n"
        f'echo "TMPDIR=${{TMPDIR-<unset>}} TEMP=${{TEMP-<unset>}} TMP=${{TMP-<unset>}}" >> "{log}"\n'
        f'exec "{sys.executable}" "$@"\n',
        encoding="utf-8",
    )
    shim.chmod(0o755)


_NONE_KEPT = "TMPDIR=<unset> TEMP=<unset> TMP=<unset>"


def test_the_rollback_makes_no_temporary_file_where_the_caller_points(tmp_path: Path) -> None:
    """rollback_offline.sh runs as root, and the python that restores the cache reads its code from a
    here-document, which bash may write to a file in TMPDIR and then reopen by name."""
    state, _backup, env = _rollback_with_cache(tmp_path)
    world = tmp_path / "world"
    world.mkdir()
    world.chmod(0o777)
    env.update(dict.fromkeys(_TEMP_VARS, str(world)))
    _recording_python3(tmp_path / "shims", tmp_path / "python-saw")
    proc = _rollback(tmp_path, env)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert (state / "metadata.sqlite").read_bytes() == b"BACKUP-CACHE"  # the here-document's python ran
    saw = (tmp_path / "python-saw").read_text(encoding="utf-8").splitlines()
    assert saw and set(saw) == {_NONE_KEPT}, saw


def test_the_trust_bootstrap_makes_no_temporary_file_where_the_caller_points(tmp_path: Path) -> None:
    _key, pub, stick = _signed_stick(tmp_path)
    root = _site(tmp_path, pub)
    world = tmp_path / "world"
    world.mkdir()
    world.chmod(0o777)
    _recording_python3(tmp_path / "tools", tmp_path / "python-saw")  # runs the installed verifier
    proc = subprocess.run(  # noqa: S603 - repo script under test
        ["/bin/bash", str(stick / "trust-bootstrap-linux" / "bootstrap.sh")],
        env=_tool_env(tmp_path, UDBMCP_BOOTSTRAP_ROOT=str(root), **dict.fromkeys(_TEMP_VARS, str(world))),
        capture_output=True, text=True, timeout=120, check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    saw = (tmp_path / "python-saw").read_text(encoding="utf-8").splitlines()
    assert saw and set(saw) == {_NONE_KEPT}, saw


@pytest.mark.parametrize(
    "script", [ROLLBACK, POSTINST, REPO / "packaging" / "trust-bootstrap-linux" / "bootstrap.sh"],
    ids=lambda p: p.name,
)
def test_root_run_scripts_drop_the_callers_temporary_directories_before_anything_runs(script: Path) -> None:
    """The scripts without the installers' root-only check (the postinst as dpkg runs it: `sudo -E dpkg
    -i` keeps the caller's) drop all three before their first python or here-document."""
    code = [line.strip() for line in script.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")]
    first = next(i for i, line in enumerate(code) if re.search(r"\bpython3?\b|<<|\bpip\b|install_offline", line))
    assert "unset TMPDIR TEMP TMP" in code[:first], code[first]


# ---- the signature is checked over the bytes the integrity pass read ---------------------------
# The two tests above count opens and compare with the file on disk, which holds the same bytes as
# long as nothing changes it: a verifier that read SHA256SUMS again for the signature passed them.
# These change the bundle between the two uses.


def _run_main(verifier: Any, monkeypatch: pytest.MonkeyPatch, *args: object) -> int:
    monkeypatch.setattr(sys, "argv", ["verify_bundle.py", *(str(a) for a in args)])
    return int(verifier.main())


def test_the_signature_is_checked_over_the_listing_the_integrity_pass_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    bundle, pub = _signed(tmp_path)
    verifier = _load_verifier()
    original = (bundle / "SHA256SUMS").read_bytes()
    real_key = verifier.bundle_key

    def key_then_rewrite(rel: str) -> str | None:  # first called for the first listed path
        if (bundle / "SHA256SUMS").read_bytes() == original:
            (bundle / "SHA256SUMS").write_bytes(b"0" * 64 + b"  wheelhouse/other.whl\n")
        return real_key(rel)  # type: ignore[no-any-return]

    signed_over: list[bytes] = []
    real_check = verifier.verify_ed25519_signature

    def recording_check(pubkey: str, data: bytes, signature: bytes) -> str:
        signed_over.append(data)
        return str(real_check(pubkey, data, signature))

    monkeypatch.setattr(verifier, "bundle_key", key_then_rewrite)
    monkeypatch.setattr(verifier, "verify_ed25519_signature", recording_check)
    rc = _run_main(verifier, monkeypatch, "--bundle", bundle, "--pubkey", pub, "--no-installed-manifest")
    assert (bundle / "SHA256SUMS").read_bytes() != original, "the listing on disk changed mid-run"
    assert rc == 0, capsys.readouterr().out
    assert signed_over == [original]


def test_no_directory_on_the_way_to_a_file_is_followed_when_it_becomes_a_link_after_listing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    bundle, pub = _signed(tmp_path)
    verifier = _load_verifier()
    real_entries = verifier.bundle_entries

    def entries_then_relink(root: Path) -> Any:
        listed = real_entries(root)
        _relink(bundle / "wheelhouse", tmp_path / "attacker" / "wheelhouse")  # identical bytes
        return listed

    monkeypatch.setattr(verifier, "bundle_entries", entries_then_relink)
    rc = _run_main(verifier, monkeypatch, "--bundle", bundle, "--pubkey", pub, "--no-installed-manifest")
    out = capsys.readouterr().out
    assert rc == 1 and "bundle verification PASSED" not in out, out
    assert "artifact not verified: wheelhouse/sqlglot-30.18.0-py3-none-any.whl cannot be opened as a regular " \
        "file without following a link" in out, out


# ---- a directory the verifier cannot list is named ----------------------------------------------


@_NOT_ROOT
def test_a_bundle_directory_the_verifier_cannot_list_is_named(tmp_path: Path) -> None:
    bundle, pub = _signed(tmp_path)
    (bundle / "requirements").chmod(0)
    try:
        proc = _verify("--bundle", bundle, "--pubkey", pub, "--no-installed-manifest")
    finally:
        (bundle / "requirements").chmod(0o755)
    assert proc.returncode == 1 and "bundle verification PASSED" not in proc.stdout, proc.stdout
    fails = [line for line in proc.stdout.splitlines() if line.startswith("FAIL:")]
    assert fails == [f"FAIL: the bundle cannot be listed: {bundle / 'requirements'}: Permission denied; "
                     "nothing in it was checked"], proc.stdout
