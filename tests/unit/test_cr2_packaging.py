"""Packaging regressions from the second /code-review max pass (review of 33a8477).

Each section names the verdict it pins:
V3-d  the deb's refused upgrade runs the INSTALLED release's postinst (abort-upgrade), which before this
      release ignored its argument and spawned a deferred worker for the old payload;
V3-m  the installer-format marker moved 3 -> 4 and older packages' preinst refused the current installer;
V3-n  an x86_64-only interpreter under Rosetta 2 passed the macos-arm64 profile check;
V3-a  the trust bootstrap accepted another release with the installed RELEASE number;
V3-c  the image loader under the documented `sudo` invocation loaded into root's docker daemon;
V3-b  the deb gate's key scan missed key layouts the earlier grep caught.

The dpkg sequences run in a throwaway ubuntu:24.04 container (UDBMCP_DOCKER_TESTS=1): dpkg's maintainer-
script order, flock(1) and setsid(1) are what is under test there. Everything else runs on the host and
writes only below tmp_path.
"""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import pytest
from test_cr_fix_packaging import _between, _deb_like_tree, _deb_preinst, _pem_key_files, _run_preinst
from test_hardening_2026_09_27_packaging import _bundle, _keypair, _load_verifier, _snapshot
from test_hardening_2026_09_28_converge_packaging import (
    _installed_marker,
    _ordered_site,
    _release_stick,
    _trust_dir,
    _upgrade_with,
)

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="bash-based POSIX test")

REPO = Path(__file__).resolve().parents[2]
SCRIPTS = REPO / "scripts"
VERIFIER = SCRIPTS / "verify_bundle.py"
INSTALL = SCRIPTS / "install_offline.sh"
LOADER = SCRIPTS / "load_images_offline.sh"
DEB_GATE = SCRIPTS / "package" / "test_package_deb.sh"
PREINST = REPO / "packaging" / "deb" / "preinst"
POSTINST = REPO / "packaging" / "deb" / "postinst"
POSTRM = REPO / "packaging" / "deb" / "postrm"


def _git_show(rev_path: str) -> str | None:
    git = shutil.which("git")
    if git is None:
        return None
    proc = subprocess.run(  # noqa: S603 - read-only git object lookup
        [git, "-C", str(REPO), "show", rev_path], capture_output=True, text=True, timeout=60, check=False
    )
    return proc.stdout if proc.returncode == 0 else None


# ---- V3-m: older packages' preinst accepts the current trusted installer ----------------------------


def test_v3m_the_installer_still_carries_the_format_3_marker_after_the_current_one() -> None:
    lines = INSTALL.read_text(encoding="utf-8").splitlines()
    assert lines[1] == "# udbmcp-installer-format: 4"  # the first marker is the current format
    assert "# udbmcp-installer-format: 3" in lines[:6]  # what every earlier package's preinst greps for


@pytest.mark.parametrize("rev", ["main", "3867e4c", "33a8477"])
def test_v3m_an_earlier_packages_preinst_accepts_the_current_trusted_tools(tmp_path: Path, rev: str) -> None:
    """The runbook's package rollback keeps the current trust tools and runs `dpkg -i` of the older .deb,
    whose preinst tests for its own format number: refused, it left the site without a venv."""
    text = _git_show(f"{rev}:packaging/deb/preinst")
    if text is None:
        pytest.skip(f"git object {rev} not available (shallow clone)")
    trust, keys = tmp_path / "trust", tmp_path / "keys"
    (trust / "lib").mkdir(parents=True)
    keys.mkdir()
    for name in ("verify_bundle.py", "profiles.py", "install_offline.sh"):
        shutil.copy2(SCRIPTS / name, trust / name)
    (keys / "release.pub.pem").write_text("-----BEGIN PUBLIC KEY-----\nAA==\n-----END PUBLIC KEY-----\n")
    text = text.replace('TRUST_DIR="/usr/local/lib/udbmcp-trust"', f'TRUST_DIR="{trust}"')
    text = text.replace('PUBKEY="/etc/universal-db-mcp/keys/release.pub.pem"', f'PUBKEY="{keys}/release.pub.pem"')
    text = text.replace('INSTALLED_MANIFEST="/opt/universal-db-mcp/manifest.json"',
                        f'INSTALLED_MANIFEST="{tmp_path}/absent.json"')
    script = tmp_path / "preinst"
    script.write_text(text, encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if not k.startswith(("UDBMCP_", "DPKG_"))}
    proc = subprocess.run(  # noqa: S603 - an earlier release's preinst, sandboxed
        ["/bin/bash", str(script), "upgrade", "0.1.0+999"], env=env, capture_output=True, text=True,
        timeout=60, check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "trust prerequisites present" in proc.stdout


def test_v3m_a_format_3_only_installer_is_still_refused_by_this_preinst(tmp_path: Path) -> None:
    script, _ = _deb_preinst(tmp_path)
    installer = tmp_path / "udbmcp-trust" / "install_offline.sh"
    text = INSTALL.read_text(encoding="utf-8")
    installer.write_text(re.sub(r"(?m)^# udbmcp-installer-format: 4\n", "", text), encoding="utf-8")
    proc = _run_preinst(tmp_path, script)
    assert proc.returncode == 1 and "udbmcp-installer-format: 4" in proc.stderr, proc.stderr


def _abort_block(tmp_path: Path, venv: bool) -> tuple[str, Path]:
    status = tmp_path / "status"
    status.write_text("success\n", encoding="utf-8")
    venv_python = tmp_path / "opt" / "venv" / "bin" / "python"
    if venv:
        venv_python.parent.mkdir(parents=True)
        venv_python.write_text("#!/bin/sh\n", encoding="utf-8")
        venv_python.chmod(0o755)
    block = _between(POSTINST.read_text(encoding="utf-8"), 'case "${1:-}" in', "esac")
    block = block.replace("/opt/universal-db-mcp/venv/bin/python", str(venv_python))
    block = block.replace("/var/log/universal-db-mcp-install.status", str(status))
    return block, status


def test_v3m_a_refused_rollback_without_a_venv_says_failed_and_fails(tmp_path: Path) -> None:
    """The runbook deletes the venv, then the older package's preinst refuses: dpkg runs this release's
    postinst abort-upgrade. 'success' in the status file, and dpkg's 'installed', were both false."""
    block, status = _abort_block(tmp_path, venv=False)
    proc = subprocess.run(  # noqa: S603 - postinst's own block
        ["/bin/bash", "-c", block + 'echo "FELL THROUGH"\n', "postinst", "abort-upgrade", "0.1.0+1"],
        capture_output=True, text=True, timeout=60, check=False,
    )
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "FELL THROUGH" not in proc.stdout
    assert status.read_text(encoding="utf-8") == "failed\n"
    assert "now says 'failed'" in proc.stderr and "sudo dpkg --configure universal-db-mcp" in proc.stderr


def test_v3m_with_the_venv_in_place_abort_upgrade_still_changes_nothing(tmp_path: Path) -> None:
    block, status = _abort_block(tmp_path, venv=True)
    proc = subprocess.run(  # noqa: S603 - postinst's own block
        ["/bin/bash", "-c", block, "postinst", "abort-upgrade", "0.1.0+1"],
        capture_output=True, text=True, timeout=60, check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert status.read_text(encoding="utf-8") == "success\n"


# ---- V3-n: the interpreter pip installs for must run the bundle's architecture ---------------------

_X86_64, _ARM64 = 0x01000007, 0x0100000C


def _thin(cpu: int) -> bytes:
    return struct.pack("<II", 0xFEEDFACF, cpu) + b"\0" * 56


def _fat(*cpus: int) -> bytes:
    head = struct.pack(">II", 0xCAFEBABE, len(cpus))
    return head + b"".join(struct.pack(">iiIII", cpu, 3, 4096, 4096, 12) for cpu in cpus) + b"\0" * 64


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (_thin(_X86_64), {"x86_64"}),
        (_thin(_ARM64), {"arm64"}),
        (_fat(_X86_64, _ARM64), {"x86_64", "arm64"}),
        (b"\x7fELF" + b"\0" * 60, None),
        (b"", None),
        (struct.pack(">II", 0xCAFEBABE, 4000) + b"\0" * 64, None),  # not a plausible fat header
    ],
    ids=["thin-x86_64", "thin-arm64", "universal2", "elf", "empty", "huge-count"],
)
def test_v3n_the_verifier_reads_which_architectures_an_executable_has(
    tmp_path: Path, data: bytes, expected: set[str] | None
) -> None:
    exe = tmp_path / "python3"
    exe.write_bytes(data)
    assert _load_verifier().macho_machines(exe) == expected


def _rosetta(monkeypatch: pytest.MonkeyPatch, verifier: Any, exe: Path) -> None:
    monkeypatch.setattr(platform, "system", lambda: "Darwin")
    monkeypatch.setattr(platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(verifier, "_rosetta_translated", lambda: True)
    monkeypatch.setattr(sys, "executable", str(exe))
    monkeypatch.setattr(sys, "_base_executable", str(exe), raising=False)


def test_v3n_an_x86_64_only_interpreter_under_rosetta_fails_the_macos_arm64_profile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    verifier = _load_verifier()
    profiles = verifier.load_profiles_module()
    mac = profiles.PROFILES["macos-arm64-cp312"]
    intel_only, universal = tmp_path / "intel" / "python3.12", tmp_path / "universal" / "python3.12"
    for path, data in ((intel_only, _thin(_X86_64)), (universal, _fat(_X86_64, _ARM64))):
        path.parent.mkdir()
        path.write_bytes(data)
    _rosetta(monkeypatch, verifier, intel_only)
    mismatches = verifier.host_profile_mismatches(profiles, mac)
    assert len(mismatches) == 1 and str(intel_only) in mismatches[0] and "no arm64 code" in mismatches[0], mismatches
    # a universal2 interpreter runs natively once nothing translates it: the hardware decides, as before
    _rosetta(monkeypatch, verifier, universal)
    assert verifier.host_profile_mismatches(profiles, mac) == []
    # an executable that cannot be read is not taken for an arm64 one
    _rosetta(monkeypatch, verifier, tmp_path / "missing")
    assert verifier.host_profile_mismatches(profiles, mac), "fail closed on an unreadable interpreter"


def test_v3n_the_verifier_refuses_the_bundle_before_the_pkg_touches_the_venv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    key, _, pub = _keypair(tmp_path)
    bundle = _bundle(tmp_path / "bundle", key, profile="macos-arm64-cp312", release_seq=5)
    verifier = _load_verifier()
    intel_only = tmp_path / "python3.12"
    intel_only.write_bytes(_thin(_X86_64))
    monkeypatch.setattr(verifier, "platform_installed_manifest", lambda: tmp_path / "absent.json")
    monkeypatch.setattr(sys, "argv", ["verify_bundle.py", "--bundle", str(bundle), "--pubkey", str(pub)])
    _rosetta(monkeypatch, verifier, intel_only)
    assert verifier.main() == 1
    out = capsys.readouterr().out
    assert "no arm64 code" in out and "bundle verification PASSED" not in out
    # the .pkg postinstall verifies (step 1) with the interpreter it builds the venv with, before the venv
    post = (REPO / "packaging" / "pkg" / "postinstall").read_text(encoding="utf-8")
    assert post.index('VEXEC="$PY -I -S"') < post.index('"$PY" -I -S -m venv --copies "$VENV"')


@pytest.mark.skipif(sys.platform != "darwin", reason="reads this Mac's own python executable")
def test_v3n_this_macs_interpreter_is_read() -> None:
    machines = _load_verifier().macho_machines(Path(os.path.realpath(sys.executable)))
    assert machines and platform.machine() in machines


# ---- V3-a: the trust bootstrap's equal RELEASE ------------------------------------------------------


def test_v3a_another_release_with_the_installed_release_number_is_refused(tmp_path: Path) -> None:
    keys, root = _ordered_site(tmp_path)
    other = _release_stick(tmp_path / "other", keys, 5)  # same RELEASE, other tools (a rebase twin)
    with (other / "trust-bootstrap-linux" / "verify_bundle.py").open("a", encoding="utf-8") as f:
        f.write("# the other release's verifier\n")
    from test_hardening_2026_09_27_packaging import _sign_stick  # noqa: PLC0415 - re-sign after the change

    proc = _sign_stick(tmp_path, other, *keys)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    before = _snapshot(root)
    proc = _upgrade_with(tmp_path, root, other)
    assert proc.returncode != 0, proc.stdout
    assert "FAIL: this stick is release 5, the release whose trust tools are installed, but its tools differ" in (
        proc.stderr
    ), proc.stderr
    assert "--allow-downgrade" in proc.stderr and "Nothing was installed." in proc.stderr
    assert _snapshot(root) == before
    # intended: the override installs it, and says so
    proc = _upgrade_with(tmp_path, root, other, "--allow-downgrade")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "WARNING: another release with the installed release number allowed by --allow-downgrade" in proc.stdout
    assert (_trust_dir(root) / "verify_bundle.py").read_text(encoding="utf-8").endswith(
        "# the other release's verifier\n"
    )


def test_v3a_the_same_release_is_still_reinstallable_from_its_own_stick(tmp_path: Path) -> None:
    keys, root = _ordered_site(tmp_path)
    again = _release_stick(tmp_path / "again", keys, 5)  # byte-identical tools
    proc = _upgrade_with(tmp_path, root, again)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "==> release order: stick release 5, installed release 5 (the same release)" in proc.stdout
    assert _installed_marker(root) == "5"


# ---- V3-c: the images go to the operator's daemon under `sudo` too ---------------------------------


def _docker_choice_block() -> str:
    text = LOADER.read_text(encoding="utf-8")
    return _between(text, "# >>> which docker daemon gets the images", "# <<< which docker daemon gets the images")


def _loader_tail(tmp_path: Path, *, context: str = "default", rootless: bool = True, user_info: bool = True,
                 docker_host: str | None = None, sudo_user: str | None = "alice", sudo_uid: str = "1234",
                 real_uid: str = "1234") -> tuple[subprocess.CompletedProcess[str], list[str]]:
    """The loader's daemon choice and load_one, run as 'root' (a shimmed id) with mock docker/sudo."""
    shims = tmp_path / "shims"
    shims.mkdir(exist_ok=True)
    log = tmp_path / "calls.log"
    (shims / "id").write_text(
        "#!/bin/sh\n"
        f'if [ "$1" = -u ] && [ "$#" -eq 1 ]; then echo 0; exit 0; fi\n'
        f'if [ "$1" = -u ] && [ "$2" = alice ]; then echo {real_uid}; exit 0; fi\n'
        "exit 1\n", encoding="utf-8")
    (shims / "sudo").write_text(
        "#!/bin/sh\n"
        f'echo "sudo $*" >> "{log}"\n'
        'while [ "$#" -gt 0 ]; do case "$1" in --) shift; break ;; -u) shift 2 ;; -*) shift ;; *) break ;; esac; done\n'
        'SUDO_AS=alice exec "$@"\n', encoding="utf-8")
    run_user = Path(tempfile.mkdtemp(prefix="ru"))  # AF_UNIX paths are short: not below tmp_path
    sock_dir = run_user / "1234"
    sock_dir.mkdir()
    sock_path = sock_dir / "docker.sock"
    server = None
    if rootless:
        server = socket.socket(socket.AF_UNIX)
        server.bind(str(sock_path))
    user_ok = "exit 0" if user_info else "exit 1"
    (shims / "docker").write_text(
        "#!/bin/sh\n"
        f'echo "docker[${{SUDO_AS:-root}}] $* DOCKER_HOST=${{DOCKER_HOST:-}}" >> "{log}"\n'
        f'if [ "$1 $2" = "context show" ]; then echo {context}; exit 0; fi\n'
        f'if [ "$1" = info ]; then [ "${{SUDO_AS:-}}" = alice ] && {{ {user_ok}; }}; exit 0; fi\n'
        'if [ "$1" = load ] && [ "$#" -eq 1 ]; then cat > /dev/null; exit 0; fi\n'
        "exit 0\n", encoding="utf-8")
    for shim in shims.iterdir():
        shim.chmod(0o755)
    tar = tmp_path / "img.tar"
    tar.write_bytes(b"TAR")
    block = _docker_choice_block().replace("/run/user/", f"{run_user}/")
    load_one = _between(LOADER.read_text(encoding="utf-8"), "load_one() {", "\n}\n")
    env = {k: v for k, v in os.environ.items() if not k.startswith(("SUDO_", "DOCKER_"))}
    env["PATH"] = f"{shims}:/usr/bin:/bin"
    if sudo_user is not None:
        env.update(SUDO_USER=sudo_user, SUDO_UID=sudo_uid)
    if docker_host is not None:
        env["DOCKER_HOST"] = docker_host
    script = f'set -euo pipefail\nsudo_ok=""\n{block}\n{load_one}\nload_one "{tar}" "img:tag"\n'
    try:
        proc = subprocess.run(  # noqa: S603 - the loader's own code, shimmed
            ["/bin/bash", "-c", script], env=env, capture_output=True, text=True, timeout=60, check=False
        )
    finally:
        if server is not None:
            server.close()
        shutil.rmtree(run_user, ignore_errors=True)
    calls = [line.replace(str(run_user), "<run-user>") for line in (
        log.read_text(encoding="utf-8").splitlines() if log.exists() else [])]
    return proc, calls


def test_v3c_under_sudo_the_rootless_daemon_of_the_invoking_operator_gets_the_images(tmp_path: Path) -> None:
    proc, calls = _loader_tail(tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    sock = "unix://<run-user>/1234/docker.sock"
    loads = [c for c in calls if c.startswith("docker[") and " load" in c]
    assert loads == [f"docker[alice] load DOCKER_HOST={sock}"], calls  # streamed: root reads, alice loads
    assert f"docker[alice] image inspect img:tag DOCKER_HOST={sock}" in calls
    assert not [c for c in calls if c.startswith("docker[root]")], calls
    assert "alice" in proc.stdout


def test_v3c_under_sudo_the_operators_docker_context_is_kept(tmp_path: Path) -> None:
    proc, calls = _loader_tail(tmp_path, context="rootless-ctx")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "docker[alice] load DOCKER_HOST=" in calls, calls  # their context, no socket forced over it


def test_v3c_a_docker_host_given_on_the_sudo_line_is_used(tmp_path: Path) -> None:
    proc, calls = _loader_tail(tmp_path, docker_host="tcp://127.0.0.1:2376")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "docker[alice] load DOCKER_HOST=tcp://127.0.0.1:2376" in calls, calls


@pytest.mark.parametrize(
    "case",
    [
        {"user_info": False, "rootless": False},  # the operator reaches no daemon: root's, as before
        {"sudo_user": None},  # plain root shell
        {"sudo_user": "root"},
        {"real_uid": "999"},  # SUDO_UID does not name SUDO_USER
        {"sudo_uid": "12x"},
    ],
    ids=["operator-has-none", "no-sudo", "sudo-from-root", "uid-mismatch", "bad-uid"],
)
def test_v3c_otherwise_root_loads_into_roots_daemon(tmp_path: Path, case: dict[str, Any]) -> None:
    proc, calls = _loader_tail(tmp_path, **case)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert f"docker[root] load -i {tmp_path}/img.tar DOCKER_HOST=" in calls, calls
    assert not [c for c in calls if c.startswith("docker[alice]") and (" load" in c or " image " in c)], calls


def test_v3c_the_unprivileged_paths_are_unchanged() -> None:
    block = _docker_choice_block()
    assert 'if [ -n "$sudo_ok" ]; then' in block
    assert "DOCKER=(sudo docker)" in block


# ---- V3-b: the deb gate's key scan --------------------------------------------------------------------


def _pem_pair() -> tuple[str, str]:
    from cryptography.hazmat.primitives import serialization  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: PLC0415

    ed = Ed25519PrivateKey.generate()
    pub = ed.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    priv = ed.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    return pub.decode(), priv.decode()


def _layouts() -> dict[str, bytes]:
    """Every layout of the second review's samples that the earlier `grep 'BEGIN PUBLIC KEY'` caught."""
    pub, priv = _pem_pair()
    body, pbody = pub.splitlines()[1], priv.splitlines()[1]
    nl = "\\n"
    out = {
        "03_single_line_pub.txt": f"-----BEGIN PUBLIC KEY-----{body}-----END PUBLIC KEY-----\n",
        "04_implicit_concat.py": f'K = (\n    "-----BEGIN PUBLIC KEY-----{nl}"\n    "{body}{nl}"\n'
                                 f'    "-----END PUBLIC KEY-----{nl}"\n)\n',
        "05_plus_concat.py": f'K = "-----BEGIN PUBLIC KEY-----{nl}" + "{body}{nl}" + "-----END PUBLIC KEY-----{nl}"\n',
        "06_json_line_array.json": json.dumps({"release_pubkey": pub.splitlines()}, indent=2),
        "09_xml_entity.xml": f"<key>-----BEGIN PUBLIC KEY-----&#10;{body}&#10;-----END PUBLIC KEY-----</key>\n",
        "10_shell_printf.sh": f"printf '%s\\n' '-----BEGIN PUBLIC KEY-----' '{body}' '-----END PUBLIC KEY-----'\n",
        "11_double_escaped.json": json.dumps({"cfg": json.dumps({"k": pub})}),
        "13_list_join.py": f'K = "{nl}".join([\n    "-----BEGIN PUBLIC KEY-----",\n    "{body}",\n'
                           '    "-----END PUBLIC KEY-----",\n])\n',
        "14_single_line_priv.txt": f"-----BEGIN PRIVATE KEY-----{pbody}-----END PRIVATE KEY-----\n",
        "17_comment_prefixed.py": "".join("# " + line + "\n" for line in pub.splitlines()),
        "19_html_br.html": "<p>" + "<br>".join(pub.splitlines()) + "</p>\n",
        "20_chunked.txt": "-----BEGIN PUBLIC KEY-----\n" + "\n".join(body[i:i + 8] for i in range(0, len(body), 8))
                          + "\n-----END PUBLIC KEY-----\n",
        "01_standard.pem.txt": pub,
        "02_standard_priv.txt": priv,
    }
    return {name: text.encode() for name, text in out.items()}


@pytest.mark.parametrize("name", sorted(_layouts()))
def test_v3b_every_key_layout_the_earlier_grep_caught_fails_the_gate(tmp_path: Path, name: str) -> None:
    tree = _deb_like_tree(tmp_path / "inspect")
    planted = tree / "usr/share/universal-db-mcp" / name
    planted.write_bytes(_layouts()[name])
    assert _pem_key_files(tmp_path, tree) == [str(planted)]


@pytest.mark.parametrize(
    "text",
    [
        'm = re.search(rb"-----BEGIN PUBLIC KEY-----(.*?)-----END PUBLIC KEY-----", pem, re.DOTALL)\n',
        "Install the key that starts with -----BEGIN PUBLIC KEY----- and ends with -----END PUBLIC KEY-----.\n",
        'PEM = "-----BEGIN PUBLIC KEY-----\\n" + body + "\\n-----END PUBLIC KEY-----\\n"\n',
        "-----BEGIN PUBLIC KEY-----\n<base64 body from the release administrator>\n-----END PUBLIC KEY-----\n",
        "BEGIN PUBLIC KEY then sha256 " + "0123456789abcdef" * 4 + " and the rest of the guide\n",
    ],
    ids=["verifier-parser", "prose", "assembled-at-run-time", "placeholder", "hex-digest-nearby"],
)
def test_v3b_naming_the_armour_without_a_key_body_passes(tmp_path: Path, text: str) -> None:
    tree = _deb_like_tree(tmp_path / "inspect")
    (tree / "usr/share/universal-db-mcp/notes.txt").write_text(text, encoding="utf-8")
    assert _pem_key_files(tmp_path, tree) == []


def test_v3b_the_repository_sources_hold_no_key_by_the_gate(tmp_path: Path) -> None:
    """A proxy for the payload: the shipped sources, scripts and docs carry no key."""
    tree = tmp_path / "inspect"
    for sub in ("src", "scripts", "packaging", "docs"):
        shutil.copytree(REPO / sub, tree / sub, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    assert _pem_key_files(tmp_path, tree) == []


def test_v3b_the_scan_is_linear_on_adversarial_input(tmp_path: Path) -> None:
    tree = tmp_path / "inspect"
    tree.mkdir()
    (tree / "a.txt").write_bytes(b"-----BEGIN " + b"A " * 40 + b"KEY-----" + b" \\n" * 30000)
    (tree / "b.txt").write_bytes((b"-----BEGIN PUBLIC KEY-----" + b"Ab1+" * 3) * 2600)
    (tree / "c.txt").write_bytes(b"BEGIN " * 11000)
    pub, _ = _pem_pair()
    (tree / "d.txt").write_bytes((b"-----BEGIN PUBLIC KEY-----" + b"Ab1+" * 3) * 2500 + pub.encode())
    start = time.monotonic()
    found = _pem_key_files(tmp_path, tree)
    assert time.monotonic() - start < 10
    assert found == [str(tree / "d.txt")]  # only the file that holds a key body after its armour


# ---- V3-d: the refused upgrade and the installed release's postinst --------------------------------

_DOCKER_IMAGE = "ubuntu:24.04"
_DOCKER = pytest.mark.skipif(
    os.environ.get("UDBMCP_DOCKER_TESTS") != "1" or shutil.which("docker") is None,
    reason="runs dpkg in a throwaway container: set UDBMCP_DOCKER_TESTS=1 (needs docker and ubuntu:24.04)",
)

# What every postinst before this release did, whatever dpkg asked (main and 3867e4c read no $1): the
# single-flight check verbatim, then a deferred worker that holds the lock while it 'installs'.
_OLD_POSTINST = r"""#!/bin/bash
echo "old-postinst $*" >> /tmp/maint.log
if ! (exec 8>/run/udbmcp-deferred-install.lock && flock -n 8); then
    echo "WARNING: a deferred install from a previous configure is still running;" >&2
    echo "old-postinst-no-worker $*" >> /tmp/maint.log
    exit 0
fi
cat > /var/tmp/oldworker <<'EOF'
#!/bin/bash
exec 9>/run/udbmcp-deferred-install.lock
flock -n 9 || exit 1
echo running > /tmp/status
echo "old-worker-started" >> /tmp/maint.log
sleep "$(cat /tmp/worker-seconds)"
echo "old-worker-done" >> /tmp/maint.log
echo success > /tmp/status
EOF
chmod 700 /var/tmp/oldworker
echo deferred > /tmp/status
setsid --fork /var/tmp/oldworker </dev/null >/dev/null 2>&1
for _ in $(seq 1 25); do [ "$(cat /tmp/status)" = running ] && break; sleep 0.2; done
exit 0
"""

_SCENARIO = r"""#!/bin/bash
set -u
W=/w
check() { if eval "$2"; then echo "CHECK $1 ok"; else echo "CHECK $1 FAIL"; fi; }
state() { dpkg-query -W -f='${Version} ${db:Status-Abbrev}' universal-db-mcp 2>/dev/null | tr -d ' '; }
mkpkg() {  # version, maintainer-script dir, output
    local d; d=$(mktemp -d); mkdir -p "$d/DEBIAN"
    printf 'Package: universal-db-mcp\nVersion: %s\nArchitecture: all\nMaintainer: t <t@example.invalid>\nDescription: simulated\n' "$1" > "$d/DEBIAN/control"
    for s in preinst postinst prerm postrm; do [ ! -f "$2/$s" ] || install -m 755 "$2/$s" "$d/DEBIAN/$s"; done
    dpkg-deb --build --root-owner-group "$d" "$3" >/dev/null
}
wait_for() { for _ in $(seq 1 "$2"); do eval "$1" && return 0; sleep 1; done; return 1; }
mkpkg 1.0 $W/old /tmp/old.deb
mkpkg 2.0 $W/new /tmp/new.deb
[ ! -d $W/new33 ] || mkpkg 2.0 $W/new33 /tmp/new33.deb
mkpkg 3.0 $W/cur /tmp/cur.deb
mkpkg 1.5 $W/refusing /tmp/refusing.deb

T=/usr/local/lib/udbmcp-trust
mkdir -p $T/lib /etc/universal-db-mcp/keys
cp $W/verify_bundle.py $W/profiles.py $T/
echo key > /etc/universal-db-mcp/keys/release.pub.pem
sed '/^# udbmcp-installer-format: /d; 1a # udbmcp-installer-format: 3' $W/install_offline.sh > $T/install_offline.sh

echo 1 > /tmp/worker-seconds
dpkg -i /tmp/old.deb >/dev/null 2>&1
wait_for 'grep -q old-worker-done /tmp/maint.log' 20
check installed_old '[ "$(state)" = 1.0ii ]'

if [ -f /tmp/new33.deb ]; then
    : > /tmp/maint.log
    dpkg -i /tmp/new33.deb > /tmp/a.out 2>&1; rc=$?
    sleep 3
    check baseline_33a8477_refused '[ $rc -ne 0 ]'
    check baseline_33a8477_spawns_the_old_worker 'grep -q old-worker-started /tmp/maint.log'
    wait_for 'grep -q old-worker-done /tmp/maint.log' 20
fi

# B: the new preinst refuses (format-3 trust tools); the old postinst runs abort-upgrade
: > /tmp/maint.log
dpkg -i /tmp/new.deb > /tmp/b.out 2>&1; rc=$?
check B_refused '[ $rc -ne 0 ] && grep -q "udbmcp-installer-format: 4" /tmp/b.out'
check B_old_postinst_ran_abort 'grep -q "old-postinst abort-upgrade" /tmp/maint.log'
check B_no_worker_spawned 'grep -q "old-postinst-no-worker abort-upgrade" /tmp/maint.log'
sleep 3
check B_still_no_worker '! grep -q old-worker-started /tmp/maint.log'
check B_lock_released 'flock -n -w 5 /run/udbmcp-deferred-install.lock true'
check B_still_old_installed '[ "$(state)" = 1.0ii ]'

# C: an old worker still runs when the admin retries with refreshed trust tools
echo 40 > /tmp/worker-seconds
: > /tmp/maint.log
/var/lib/dpkg/info/universal-db-mcp.postinst configure 1.0 >/dev/null 2>&1
wait_for 'grep -q old-worker-started /tmp/maint.log' 10
cp $W/install_offline.sh $T/install_offline.sh
dpkg -i /tmp/new.deb > /tmp/c.out 2>&1; rc=$?
check C_refused_while_the_worker_runs '[ $rc -ne 0 ] && grep -q "deferred install started by an earlier configure is still running" /tmp/c.out'
check C_still_old_installed '[ "$(state)" = 1.0ii ]'
check C_one_worker_only '[ "$(grep -c old-worker-started /tmp/maint.log)" = 1 ]'
wait_for 'grep -q old-worker-done /tmp/maint.log' 70
dpkg -i /tmp/new.deb > /tmp/d.out 2>&1; rc=$?
check D_upgrades_once_it_ended '[ $rc -eq 0 ] && [ "$(state)" = 2.0ii ] && grep -q "new-postinst configure" /tmp/maint.log'

# E: this release's postinst while a worker of another payload, or of this one, holds the lock
FN=$W/one_install.sh
( exec 9>>/run/udbmcp-deferred-install.lock; flock 9; sleep 60 ) &
holder=$!
sleep 1
rm -f /run/udbmcp-deferred-install.owner
bash -c "set -e; . $FN; refuse_while_another_install_runs abc same-ok; echo PASSED" > /tmp/e1.out 2>&1; rc=$?
check E_unnamed_worker_refuses '[ $rc -eq 1 ] && grep -q "ANOTHER payload" /tmp/e1.out'
echo "$holder abc" > /run/udbmcp-deferred-install.owner
bash -c "set -e; . $FN; refuse_while_another_install_runs abc same-ok; echo PASSED" > /tmp/e2.out 2>&1; rc=$?
check E_same_payload_left_to_finish '[ $rc -eq 0 ] && grep -q "this same payload" /tmp/e2.out && ! grep -q PASSED /tmp/e2.out'
bash -c "set -e; . $FN; refuse_while_another_install_runs xyz same-ok; echo PASSED" > /tmp/e3.out 2>&1; rc=$?
check E_other_payload_refuses '[ $rc -eq 1 ]'
bash -c "set -e; . $FN; refuse_while_another_install_runs abc; echo PASSED" > /tmp/e4.out 2>&1; rc=$?
check E_sync_mode_refuses_any '[ $rc -eq 1 ]'
kill $holder; wait $holder 2>/dev/null
bash -c "set -e; . $FN; refuse_while_another_install_runs xyz same-ok; echo PASSED" > /tmp/e5.out 2>&1; rc=$?
check E_free_lock_passes '[ $rc -eq 0 ] && grep -q PASSED /tmp/e5.out'

# F: the worker installs only what dpkg records
WF=$W/worker_check.sh
mkdir -p /tmp/bundle && echo '{"release_seq": 1}' > /tmp/bundle/manifest.json
ID=$(sha256sum /tmp/bundle/manifest.json | cut -d' ' -f1)
bash -c "set -eu; BUNDLE=/tmp/bundle PAYLOAD_ID=$ID EXPECT_VERSION=2.0; . $WF; still_what_dpkg_records now; echo PASSED" > /tmp/f1.out 2>&1
check F_recorded_version_passes 'grep -q PASSED /tmp/f1.out'
bash -c "set -eu; BUNDLE=/tmp/bundle PAYLOAD_ID=$ID EXPECT_VERSION=1.0; . $WF; still_what_dpkg_records now; echo PASSED" > /tmp/f2.out 2>&1
check F_changed_version_stops '! grep -q PASSED /tmp/f2.out && grep -q "dpkg records universal-db-mcp 2.0" /tmp/f2.out'
bash -c "set -eu; BUNDLE=/tmp/bundle PAYLOAD_ID=0000 EXPECT_VERSION=2.0; . $WF; still_what_dpkg_records now; echo PASSED" > /tmp/f3.out 2>&1
check F_changed_payload_stops '! grep -q PASSED /tmp/f3.out'

# G: a refused rollback with the venv deleted leaves dpkg 'unpacked' and the status 'failed'
dpkg -i /tmp/cur.deb >/dev/null 2>&1
mkdir -p /opt/universal-db-mcp/venv/bin && printf '#!/bin/sh\n' > /opt/universal-db-mcp/venv/bin/python && chmod 755 /opt/universal-db-mcp/venv/bin/python
echo success > /var/log/universal-db-mcp-install.status
dpkg -i /tmp/refusing.deb > /tmp/g1.out 2>&1
check G_with_venv_stays_installed '[ "$(state)" = 3.0ii ] && grep -qx success /var/log/universal-db-mcp-install.status'
rm -rf /opt/universal-db-mcp/venv
dpkg -i /tmp/refusing.deb > /tmp/g2.out 2>&1
check G_without_venv_unpacked '[ "$(state)" = 3.0iU ]'
check G_status_failed 'grep -qx failed /var/log/universal-db-mcp-install.status'
dpkg --configure universal-db-mcp > /tmp/g3.out 2>&1
check G_configure_recovers '[ "$(state)" = 3.0ii ] && grep -q "cur-postinst configure" /tmp/maint.log'
"""  # noqa: E501 - shell lines


def _container_inputs(tmp_path: Path) -> Path:
    w = tmp_path / "w"
    for name in ("old", "new", "cur", "refusing"):
        (w / name).mkdir(parents=True)
    for name in ("verify_bundle.py", "profiles.py", "install_offline.sh"):
        shutil.copy2(SCRIPTS / name, w / name)
    log_line = 'echo "{tag} $*" >> /tmp/maint.log\n'
    (w / "old" / "postinst").write_text(_OLD_POSTINST, encoding="utf-8")
    (w / "old" / "prerm").write_text("#!/bin/bash\n" + log_line.format(tag="old-prerm") + "exit 0\n")
    shutil.copy2(PREINST, w / "new" / "preinst")  # this release's preinst, verbatim
    shutil.copy2(POSTRM, w / "new" / "postrm")  # and its postrm, which holds the lock for dpkg's unwind
    (w / "new" / "postinst").write_text("#!/bin/bash\n" + log_line.format(tag="new-postinst") + "exit 0\n")
    (w / "new" / "prerm").write_text("#!/bin/bash\n" + log_line.format(tag="new-prerm") + "exit 0\n")
    previous = _git_show("33a8477:packaging/deb/preinst")
    if previous is not None:
        (w / "new33").mkdir()
        (w / "new33" / "preinst").write_text(previous, encoding="utf-8")
        shutil.copy2(w / "new" / "postinst", w / "new33" / "postinst")
    post = POSTINST.read_text(encoding="utf-8")
    # 'cur': this release's abort-* handling verbatim; its configure only logs
    abort = _between(post, 'case "${1:-}" in', "esac")
    (w / "cur" / "postinst").write_text(
        "#!/bin/bash\nset -e\n" + abort + log_line.format(tag="cur-postinst") + "exit 0\n", encoding="utf-8"
    )
    (w / "refusing" / "preinst").write_text("#!/bin/bash\necho 'older preinst: refused' >&2\nexit 1\n")
    # this release's one-install-at-a-time functions, with its constants (the wait shortened)
    consts = "".join(line + "\n" for line in post.splitlines()
                     if re.match(r"(DEFERRED_LOCK|DEFERRED_OWNER|STATUS|LOG)=/", line))
    block = _between(post, "# $1: a file; prints its sha256", "# <<< one install at a time")
    assert "for _ in $(seq 1 30); do" in block
    (w / "one_install.sh").write_text(consts + block.replace("$(seq 1 30)", "$(seq 1 2)"), encoding="utf-8")
    worker = _between(post, "#!/bin/bash\n# Deferred payload installer", "WORKER_EOF")
    check = _between(worker, "# $1: a file; prints its sha256", "\n}\n")
    check += _between(worker, "still_what_dpkg_records() {", "\n}\n")
    (w / "worker_check.sh").write_text(check, encoding="utf-8")
    (w / "scenario.sh").write_text(_SCENARIO, encoding="utf-8")
    return w


@_DOCKER
def test_v3d_dpkg_sequences_in_a_container(tmp_path: Path) -> None:
    w = _container_inputs(tmp_path)
    docker = shutil.which("docker")
    assert docker is not None
    proc = subprocess.run(  # noqa: S603 - throwaway container, no network
        [docker, "run", "--rm", "--network", "none", "-v", f"{w}:/w:ro", _DOCKER_IMAGE, "bash", "/w/scenario.sh"],
        capture_output=True, text=True, timeout=600, check=False,
    )
    checks = dict(line.split()[1:3] for line in proc.stdout.splitlines() if line.startswith("CHECK "))
    failed = sorted(name for name, result in checks.items() if result != "ok")
    assert checks and not failed, proc.stdout + proc.stderr
    expected = {"B_no_worker_spawned", "C_refused_while_the_worker_runs", "D_upgrades_once_it_ended",
                "E_unnamed_worker_refuses", "F_changed_version_stops", "G_without_venv_unpacked"}
    assert expected <= set(checks), sorted(checks)


def test_v3d_dpkgs_abort_upgrade_hands_the_lock_on(tmp_path: Path) -> None:
    """The holder moved from the preinst's EXIT trap to the postrm's abort-upgrade (review 3, A7-1): dpkg
    runs the new postrm with abort-upgrade, before the installed postinst, on every path that undoes an
    upgrade, a failed unpack after the preinst passed included."""
    assert not re.search(r"(?m)^\s*trap\s", PREINST.read_text(encoding="utf-8"))
    text = POSTRM.read_text(encoding="utf-8")
    holder = _between(text, "hold_the_unwind() {", "\n}\n")
    assert '"${DPKG_MAINTSCRIPT_NAME:-}" = postrm' in holder
    assert 'setsid --fork /bin/bash -c "$UNWIND_HOLDER" udbmcp-unwind-holder "$PPID"' in holder
    assert "    abort-upgrade)\n" in text and "hold_the_unwind || true" in _between(text, "    abort-upgrade)", ";;")


def test_v3d_outside_dpkg_a_refusal_spawns_nothing(tmp_path: Path) -> None:
    script, _ = _deb_preinst(tmp_path, verifier='ap.add_argument("--pubkey", default=None)\n')
    text = script.read_text(encoding="utf-8").replace(
        "/run/udbmcp-deferred-install.lock", str(tmp_path / "deferred.lock")
    )
    script.write_text(text, encoding="utf-8")
    proc = _run_preinst(tmp_path, script)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert not (tmp_path / "deferred.lock").exists()
    assert "kept from starting an install worker" not in proc.stderr


def test_v3d_postinst_checks_for_another_install_before_it_changes_anything() -> None:
    text = POSTINST.read_text(encoding="utf-8")
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    deferred = code.index('refuse_while_another_install_runs "$PAYLOAD_ID" same-ok')
    assert code.index("verify_payload_with_proof\n", code.index("compgen -G")) < deferred
    assert deferred < code.index('install -d -m 755 -o root -g root "$UNIT_DROPIN_DIR"') < code.index("setsid --fork")
    sync = code.index('refuse_while_another_install_runs "$(manifest_id "$BUNDLE/manifest.json")"')
    assert sync < code.rindex('bash "$TRUST_DIR/install_offline.sh" "$BUNDLE" "$TARGET"')
    assert "not spawning a second worker" in text  # the same payload's worker is still left to finish
    worker = _between(text, "#!/bin/bash\n# Deferred payload installer", "WORKER_EOF")
    w = "\n".join(line for line in worker.splitlines() if not line.lstrip().startswith("#"))
    assert w.index('printf \'%s %s\\n\' "$$" "$PAYLOAD_ID" > "$OWNER"') < w.index("echo running >")
    assert w.index('still_what_dpkg_records "before the install"') < w.index('bash "$TRUST_DIR/install_offline.sh"')
    assert w.index('still_what_dpkg_records "after the install"') < w.index("echo success >")
    assert w.index('manifest_id "$TARGET/manifest.json"') < w.index("echo success >")
