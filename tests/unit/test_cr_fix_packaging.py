"""Packaging regressions from the /code-review max pass on the 2026-09 hardening branch.

Each section names the finding it pins (ids from the review's verdicts):
D1 the deb gate's key scan, D2 the image loader's docker daemon, M1 the .pkg under Rosetta 2,
I1-I3 the installers' release record and verifier guard, K1/K2 the deb preinst, K4 the bootstrap
test hook, Z1-Z3 rollback and the installer format marker. Every key is a throwaway Ed25519 pair
under tmp_path; the scripts under test only ever write below tmp_path.
"""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from test_deb_packaging import _preinst_sandbox_script
from test_hardening_2026_09_27_packaging import (
    _NOT_ROOT,
    APP_TAR,
    BASELINE_TAR,
    PKG_POSTINSTALL,
    PKG_PREINSTALL,
    _bundle,
    _config_dir,
    _find_as_root,
    _image_bundle,
    _keypair,
    _load_verifier,
    _loaded,
    _loader_env,
    _payload_release_seq,
    _python_org,
    _run_installer,
    _run_pkg,
    _sha256,
    _shims,
    _site,
    _verify,
)

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="bash-based POSIX test")

REPO = Path(__file__).resolve().parents[2]
SCRIPTS = REPO / "scripts"
VERIFIER = SCRIPTS / "verify_bundle.py"
INSTALL = SCRIPTS / "install_offline.sh"
UPGRADE = SCRIPTS / "upgrade_offline.sh"
ROLLBACK = SCRIPTS / "rollback_offline.sh"
LOADER = SCRIPTS / "load_images_offline.sh"
DEB_GATE = SCRIPTS / "package" / "test_package_deb.sh"
BUILD_DEB = SCRIPTS / "package" / "build_deb.sh"
BUILD_PKG = SCRIPTS / "package" / "build_pkg.sh"
PREINST = REPO / "packaging" / "deb" / "preinst"
POSTINST = REPO / "packaging" / "deb" / "postinst"
BOOTSTRAP = REPO / "packaging" / "trust-bootstrap-linux" / "bootstrap.sh"

ARM64_MAC = sys.platform == "darwin" and platform.machine() == "arm64"


def _between(text: str, start: str, end: str) -> str:
    """The text from the line holding *start* through the line where the first *end* after it ends."""
    at = text.index(start)
    first = text.rfind("\n", 0, at) + 1
    stop = text.index(end, at + len(start)) + len(end)
    if not end.endswith("\n"):
        newline = text.find("\n", stop)
        stop = len(text) if newline < 0 else newline + 1
    return text[first:stop]


def _bash(script: str, env: dict[str, str] | None = None, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - a test harness around repo script text
        ["/bin/bash", "-c", script], env=env, cwd=cwd, capture_output=True, text=True, timeout=120, check=False
    )


def _py_shims(tmp_path: Path) -> Path:
    shims = tmp_path / "py-shims"
    shims.mkdir(exist_ok=True)
    (shims / "python3").write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n', encoding="utf-8")
    (shims / "python3").chmod(0o755)
    return shims


# ---- D1: the deb gate looks for key material, not for the words in a parser --------


def _pem_key_files(tmp_path: Path, tree: Path) -> list[str]:
    gate = DEB_GATE.read_text(encoding="utf-8")
    fn = _between(gate, "pem_key_files() {", "PYEOF\n}")
    assert fn.rstrip().endswith("PYEOF\n}"), fn[-60:]
    env = {**os.environ, "PATH": f"{_py_shims(tmp_path)}:/usr/bin:/bin"}
    proc = subprocess.run(  # noqa: S603 - the gate's own function
        ["/bin/bash", "-c", f'{fn}\npem_key_files "$1"', "bash", str(tree)],
        env=env, capture_output=True, text=True, timeout=120, check=False,
    )
    assert proc.returncode == 0, proc.stderr
    return [line for line in proc.stdout.splitlines() if line]


def _deb_like_tree(root: Path) -> Path:
    """The two verify_bundle.py copies a .deb ships (trusted-tools/ and the bundle's installers/)."""
    for sub in ("usr/share/universal-db-mcp/trusted-tools", "usr/share/universal-db-mcp/bundle/installers"):
        (root / sub).mkdir(parents=True)
        shutil.copy2(VERIFIER, root / sub / "verify_bundle.py")
        shutil.copy2(SCRIPTS / "profiles.py", root / sub / "profiles.py")
    (root / "usr/share/universal-db-mcp/bundle/wheelhouse").mkdir(parents=True)
    (root / "usr/share/universal-db-mcp/bundle/wheelhouse/x-1-py3-none-any.whl").write_bytes(b"PK\x03\x04\0\0binary")
    return root


def test_d1_the_shipped_verifier_names_the_pem_armour_and_is_not_key_material(tmp_path: Path) -> None:
    assert "BEGIN PUBLIC KEY" in VERIFIER.read_text(encoding="utf-8")  # the case the gate tripped on
    tree = _deb_like_tree(tmp_path / "inspect")
    assert _pem_key_files(tmp_path, tree) == []


def _pem_variants() -> dict[str, bytes]:
    ed = Ed25519PrivateKey.generate()
    pub = ed.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    priv = ed.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    rsa = generate_private_key(public_exponent=65537, key_size=2048)
    rsa_trad = rsa.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.BestAvailableEncryption(b"pw"),
    )
    openssh = ed.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()
    )
    in_source = ("RELEASE_KEY = " + json.dumps(pub.decode()) + "\n").encode()  # the line breaks written \n
    return {
        "notes.txt": pub,
        "config/default.yaml": b"key: |\n  " + pub.replace(b"\n", b"\n  "),
        "private.txt": priv,
        "legacy-rsa.txt": rsa_trad,  # Proc-Type/DEK-Info headers before the body
        "id_ed25519": openssh,
        "embedded.py": b"# a module\n" + in_source,
        "crlf.txt": pub.replace(b"\n", b"\r\n"),
    }


@pytest.mark.parametrize("name", list(_pem_variants()))
def test_d1_real_key_material_anywhere_in_the_package_fails_the_gate(tmp_path: Path, name: str) -> None:
    tree = _deb_like_tree(tmp_path / "inspect")
    planted = tree / "usr/share/universal-db-mcp" / name
    planted.parent.mkdir(parents=True, exist_ok=True)
    planted.write_bytes(_pem_variants()[name])
    assert _pem_key_files(tmp_path, tree) == [str(planted)]


def test_d1_the_gate_scans_for_pem_bodies_not_the_armour_text() -> None:
    gate = DEB_GATE.read_text(encoding="utf-8")
    leak_line = next(line for line in gate.splitlines() if line.startswith("TEXT_LEAKS="))
    assert "pem_key_files /tmp/inspect" in leak_line, leak_line
    assert "grep" not in leak_line and "BEGIN PUBLIC KEY" not in leak_line, leak_line
    # the name-based scan stays as strict as before
    assert "-name '*.pem' -o -name '*.pub' -o -name '*.key'" in gate


# ---- D2: images go to the daemon the operator's docker reaches ---------------------


def _loader_env_with_user_docker(tmp_path: Path, pub: Path, user_docker: bool) -> dict[str, str]:
    """_loader_env with a sudo that logs what it runs, and a docker whose `info` answers only when the
    invoking account reaches a daemon (rootless, DOCKER_HOST); `load` from stdin is logged as 'stdin'."""
    env = _loader_env(tmp_path, pub)
    shims = tmp_path / "shims"
    (shims / "sudo").write_text(
        f'#!/bin/sh\necho "$*" >> "{tmp_path}/sudo.log"\nexec "$@"\n', encoding="utf-8"
    )
    docker = shims / "docker"
    text = docker.read_text(encoding="utf-8")
    hook = (
        'if [ "$1" = info ]; then ' + ("exit 0" if user_docker else "exit 1") + "; fi\n"
        'if [ "$1" = load ] && [ "$#" -eq 1 ]; then\n'
        f'  "{sys.executable}" -c \'import hashlib, sys; '
        'print("stdin", hashlib.sha256(sys.stdin.buffer.read()).hexdigest())\' >> "$MOCK_DOCKER_LOG"\n'
        "  exit 0\n"
        "fi\n"
    )
    docker.write_text(text.replace("#!/bin/sh\n", "#!/bin/sh\n" + hook, 1), encoding="utf-8")
    return env


def _stdin_loads(tmp_path: Path) -> list[str]:
    log = tmp_path / "docker.log"
    return [line.split()[1] for line in log.read_text(encoding="utf-8").splitlines() if line.startswith("stdin ")]


@_NOT_ROOT
def test_d2_an_operator_with_a_docker_daemon_of_their_own_gets_the_verified_images(tmp_path: Path) -> None:
    bundle, pub = _image_bundle(tmp_path, release_seq=5)
    env = _loader_env_with_user_docker(tmp_path, pub, user_docker=True)
    proc = subprocess.run(  # noqa: S603 - repo script under test
        ["/bin/bash", str(LOADER), str(bundle)], env=env, capture_output=True, text=True, timeout=120, check=False
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    # both tars, byte-identical to the signed ones, streamed into the operator's own docker
    assert sorted(_stdin_loads(tmp_path)) == sorted(
        [_sha256(bundle / "images" / BASELINE_TAR), _sha256(bundle / "images" / APP_TAR)]
    )
    sudo_runs = (tmp_path / "sudo.log").read_text(encoding="utf-8").splitlines()
    assert not [run for run in sudo_runs if run.startswith("docker")], sudo_runs  # never root's daemon
    assert [run for run in sudo_runs if run.startswith("cat -- ") and "/images/" in run], sudo_runs


@_NOT_ROOT
def test_d2_without_a_daemon_of_their_own_root_loads_into_roots_daemon(tmp_path: Path) -> None:
    bundle, pub = _image_bundle(tmp_path, release_seq=5)
    env = _loader_env_with_user_docker(tmp_path, pub, user_docker=False)
    proc = subprocess.run(  # noqa: S603 - repo script under test
        ["/bin/bash", str(LOADER), str(bundle)], env=env, capture_output=True, text=True, timeout=120, check=False
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert set(_loaded(tmp_path)) == {APP_TAR, BASELINE_TAR}
    sudo_runs = (tmp_path / "sudo.log").read_text(encoding="utf-8").splitlines()
    assert [run for run in sudo_runs if run.startswith("docker load -i ")], sudo_runs
    assert [run for run in sudo_runs if run.startswith("docker image inspect ")], sudo_runs


# ---- M1: the .pkg on Apple silicon, whatever Installer translates ------------------


def test_m1_build_pkg_declares_the_arm64_host_for_a_macos_arm64_bundle(tmp_path: Path) -> None:
    text = BUILD_PKG.read_text(encoding="utf-8")
    profile_case = _between(text, 'HOST_ARCHS="arm64,x86_64"', "esac")
    dist = _between(text, 'cat >"$DIST_XML" <<EOF', "</installer-gui-script>") + "EOF\n"
    for profile, archs in (("macos-arm64-cp312", "arm64"), ("linux-x86_64-ubuntu24.04-cp312", "arm64,x86_64")):
        script = f'warn() {{ :; }}\nPROFILE="{profile}"\nVERSION=1\nDIST_XML="$1"\n{profile_case}\n{dist}'
        out = tmp_path / f"{profile}.xml"
        proc = subprocess.run(  # noqa: S603 - build_pkg.sh text under test
            ["/bin/bash", "-c", script, "bash", str(out)], capture_output=True, text=True, timeout=60, check=False
        )
        assert proc.returncode == 0, proc.stderr
        options = ET.parse(out).getroot().find("options")  # noqa: S314 - XML this test just generated
        assert options is not None, out.read_text(encoding="utf-8")
        assert options.get("hostArchitectures") == archs, (profile, options.attrib)


def _native_block(script: Path) -> str:
    text = script.read_text(encoding="utf-8")
    return _between(text, "# >>> run natively on Apple silicon", "# <<< run natively on Apple silicon")


def test_m1_both_pkg_scripts_start_over_natively_with_the_same_code() -> None:
    pre, post = _native_block(PKG_PREINSTALL), _native_block(PKG_POSTINSTALL)
    assert pre == post
    for script in (PKG_PREINSTALL, PKG_POSTINSTALL):
        text = script.read_text(encoding="utf-8")
        # first thing after set -euo pipefail: before any python, trap or file is touched
        assert text.index("set -euo pipefail") < text.index("# >>> run natively") < text.index("PREFIX=")
        assert text.index("# <<< run natively") < text.index("trap ")


@pytest.mark.skipif(not ARM64_MAC, reason="needs Apple silicon with Rosetta 2")
def test_m1_a_translated_pkg_script_runs_its_python_natively(tmp_path: Path) -> None:
    """Live: the block, run under Rosetta as the Installer runs the scripts, re-runs the script as
    arm64, so a universal2 python it starts (here /usr/bin/python3) reports arm64."""
    if subprocess.run(["/usr/bin/arch", "-x86_64", "/usr/bin/true"], check=False).returncode != 0:  # noqa: S603
        pytest.skip("Rosetta 2 is not installed")
    script = tmp_path / "postinstall"
    script.write_text(
        "#!/bin/bash\nset -euo pipefail\n" + _native_block(PKG_POSTINSTALL)
        + f'echo "args=$*"\n/usr/bin/python3 -I -S -c "{_PRINT_MACHINE}"\n',
        encoding="utf-8",
    )
    proc = subprocess.run(  # noqa: S603 - test script under Rosetta
        ["/usr/bin/arch", "-x86_64", "/bin/bash", str(script), "/pkg", "/", "/"],
        capture_output=True, text=True, timeout=60, check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.splitlines() == ["args=/pkg / /", "arm64"], proc.stdout
    # without the block the same python runs translated: the failure the review saw
    bare = subprocess.run(  # noqa: S603
        ["/usr/bin/arch", "-x86_64", "/usr/bin/python3", "-I", "-S", "-c", _PRINT_MACHINE],
        capture_output=True, text=True, timeout=60, check=False,
    )
    assert bare.stdout.strip() == "x86_64"


_PRINT_MACHINE = "import platform; print(platform.machine())"


def _rosetta(monkeypatch: pytest.MonkeyPatch, verifier: Any, translated: bool) -> None:
    monkeypatch.setattr(platform, "system", lambda: "Darwin")
    monkeypatch.setattr(platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(verifier, "_rosetta_translated", lambda: translated)
    # a universal2 python (python.org's): an x86_64-only one is test_cr2_packaging's V3-n
    monkeypatch.setattr(verifier, "interpreter_machines", lambda: {"x86_64", "arm64"})


def test_m1_the_verifier_judges_the_architecture_by_the_hardware(monkeypatch: pytest.MonkeyPatch) -> None:
    verifier = _load_verifier()
    profiles = verifier.load_profiles_module()
    mac = profiles.PROFILES["macos-arm64-cp312"]
    _rosetta(monkeypatch, verifier, translated=True)
    assert verifier.host_machine() == "arm64"
    assert verifier.host_profile_mismatches(profiles, mac) == []
    # an Intel Mac is still an Intel Mac
    _rosetta(monkeypatch, verifier, translated=False)
    assert verifier.host_machine() == "x86_64"
    assert verifier.host_profile_mismatches(profiles, mac) == ["machine architecture x86_64 (target arm64)"]
    # and a translated process on an arm64 Mac is not a match for an x86_64 target
    _rosetta(monkeypatch, verifier, translated=True)
    linux = profiles.PROFILES["linux-x86_64-ubuntu24.04-cp312"]
    assert "machine architecture arm64 (target x86_64)" in verifier.host_profile_mismatches(profiles, linux)


def test_m1_a_macos_arm64_bundle_verifies_under_rosetta(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    key, _, pub = _keypair(tmp_path)
    bundle = _bundle(tmp_path / "bundle", key, profile="macos-arm64-cp312", release_seq=5)
    verifier = _load_verifier()
    monkeypatch.setattr(verifier, "platform_installed_manifest", lambda: tmp_path / "absent.json")
    monkeypatch.setattr(sys, "argv", ["verify_bundle.py", "--bundle", str(bundle), "--pubkey", str(pub)])
    _rosetta(monkeypatch, verifier, translated=True)
    assert verifier.main() == 0, capsys.readouterr().out
    assert "bundle verification PASSED" in capsys.readouterr().out
    verifier.failed = False
    _rosetta(monkeypatch, verifier, translated=False)
    assert verifier.main() == 1
    assert "machine architecture x86_64 (target arm64)" in capsys.readouterr().out


@pytest.mark.skipif(not ARM64_MAC, reason="needs Apple silicon with Rosetta 2")
def test_m1_live_rosetta_detection_in_the_verifier() -> None:
    probe = (
        "import importlib.util, platform\n"
        f"spec = importlib.util.spec_from_file_location('vb', {str(VERIFIER)!r})\n"
        "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)\n"
        "print(platform.machine(), m.host_machine())\n"
    )
    proc = subprocess.run(  # noqa: S603 - Apple's universal python, translated
        ["/usr/bin/arch", "-x86_64", "/usr/bin/python3", "-I", "-S", "-c", probe],
        capture_output=True, text=True, timeout=60, check=False,
    )
    if proc.returncode != 0:
        pytest.skip(f"no translated universal python here: {proc.stderr[-200:]}")
    assert proc.stdout.split() == ["x86_64", "arm64"]


# ---- I1: the release record is published in a run through sudo -------------------


# install(1) without -o/-g: no chown without root
_INSTALL_WITHOUT_CHOWN = (
    "#!/bin/bash\nargs=()\n"
    'while [ $# -gt 0 ]; do case "$1" in -o|-g) shift 2 ;; *) args+=("$1"); shift ;; esac; done\n'
    'exec /usr/bin/install "${args[@]}"\n'
)


def _root_only_staging(tmp_path: Path) -> tuple[Path, Path, dict[str, str]]:
    """A staging copy only 'root' can enter (mode 000 to this account; the sudo shim opens it for the
    one command it runs), and an install shim that drops -o/-g (no chown without root)."""
    staging = tmp_path / "staging" / "udbmcp-install.XXXX"
    bundle = staging / "bundle"
    bundle.mkdir(parents=True)
    (bundle / "manifest.json").write_text(json.dumps({"profile": "p", "release_seq": 9}), encoding="utf-8")
    shims = tmp_path / "root-shims"
    shims.mkdir()
    (shims / "sudo").write_text(
        f'#!/bin/bash\nchmod 700 "{staging}"\n"$@"; rc=$?\nchmod 000 "{staging}"\nexit $rc\n', encoding="utf-8"
    )
    (shims / "install").write_text(
        _INSTALL_WITHOUT_CHOWN,
        encoding="utf-8",
    )
    (shims / "systemctl").write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    for shim in shims.iterdir():
        shim.chmod(0o755)
    staging.chmod(0o000)
    env = {**os.environ, "PATH": f"{shims}:/usr/bin:/bin:/usr/sbin:/sbin"}
    return staging, bundle, env


@_NOT_ROOT
@pytest.mark.parametrize("script", [INSTALL, UPGRADE], ids=["install_offline", "upgrade_offline"])
def test_i1_a_run_through_sudo_publishes_the_release_record(tmp_path: Path, script: Path) -> None:
    text = script.read_text(encoding="utf-8")
    var = "BUNDLE" if script == INSTALL else "NEW_BUNDLE"
    start = text.index("# Publish the ")
    block = text[start : text.index("\nfi\n", text.index(f'$sudo_ok test -f "${var}/manifest.json"', start)) + 4]
    if script == UPGRADE:  # the record is checked after the service is started again
        block += text[text.index('if [ "$PUBLISHED" -eq 0 ]; then') :].split("\nfi\n", 1)[0] + "\nfi\n"
    staging, bundle, env = _root_only_staging(tmp_path)
    target = tmp_path / "target"
    target.mkdir()
    try:
        proc = _bash(f'set -euo pipefail\nsudo_ok=sudo\n{var}="{bundle}"\nTARGET="{target}"\n{block}', env=env)
    finally:
        staging.chmod(0o700)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert json.loads((target / "manifest.json").read_text(encoding="utf-8"))["release_seq"] == 9


def test_i1_nothing_tests_the_root_only_staging_copy_without_sudo() -> None:
    """The class: after the private copy is verified, every test of a path in it runs through $sudo_ok."""
    unprivileged = re.compile(r'(?<!\$sudo_ok )(?:\[\[? -[a-zA-Z] |\btest -[a-zA-Z] )"\$(?:NEW_)?(?:BUNDLE|STAGING)\b')
    for script, after in (
        (INSTALL, 'BUNDLE="$STAGING"'),
        (UPGRADE, 'NEW_BUNDLE="$STAGING"'),
        (LOADER, 'verify_with_proof "$STAGING"'),
    ):
        code = "\n".join(
            line for line in script.read_text(encoding="utf-8").splitlines() if not line.lstrip().startswith("#")
        )
        tail = code[code.index(after) :]
        assert not unprivileged.findall(tail), (script.name, unprivileged.findall(tail))


# ---- I2: the upgrade refuses a verifier in the bundle root ------------------------


@pytest.mark.parametrize("how", ["verifier", "trust-dir"])
def test_i2_upgrade_refuses_a_verifier_directly_in_the_bundle_root(tmp_path: Path, how: str) -> None:
    key, _, _ = _keypair(tmp_path)
    bundle = _bundle(tmp_path / "bundle", key, release_seq=5)
    ran = tmp_path / "bundle-verifier-ran"
    planted = bundle / "verify_bundle.py"
    planted.write_text(f"open({str(ran)!r}, 'w').write('ran')\nprint('bundle verification PASSED')\n", encoding="utf-8")
    extra = {"UDBMCP_TRUST_DIR": str(bundle)} if how == "trust-dir" else {}
    verifier = planted if how == "verifier" else VERIFIER
    args = [str(bundle), str(tmp_path / "target"), str(tmp_path / "backups")]
    if how == "trust-dir":
        env = {k: v for k, v in os.environ.items() if not k.startswith("UDBMCP_")}
        env.update(
            PATH=f"{_shims(tmp_path)}:{os.environ.get('PATH', '')}",  # sudo runs as this account
            UDBMCP_RELEASE_PUBKEY=str(tmp_path / "release.pub.pem"),
            UDBMCP_STAGING_DIR=str(tmp_path / "staging"), TMPDIR=str(tmp_path), **extra,
        )
        proc = subprocess.run(  # noqa: S603 - repo script under test
            ["/bin/bash", str(UPGRADE), *args], env=env, capture_output=True, text=True, timeout=120, check=False
        )
    else:
        proc = _run_installer(tmp_path, UPGRADE, args, verifier)
    assert proc.returncode != 0, proc.stdout + proc.stderr
    assert "UDBMCP_VERIFIER points inside the bundle" in proc.stderr, proc.stderr
    assert not ran.exists(), "the bundle's own verifier ran"


# ---- I3: release_seq cannot order two releases that share it ----------------------


def _installed(tmp_path: Path, **manifest: Any) -> Path:
    path = tmp_path / "installed-manifest.json"
    path.write_text(json.dumps({"profile": "test-profile", **manifest}), encoding="utf-8")
    return path


def test_i3_another_release_with_the_installed_release_seq_is_refused(tmp_path: Path) -> None:
    key, _, pub = _keypair(tmp_path)
    installed = _installed(tmp_path, release_seq=1727000000, source_rev="b" * 40)
    other = _bundle(tmp_path / "other", key, release_seq=1727000000, source_rev="a" * 40)
    proc = _verify("--bundle", other, "--pubkey", pub, "--installed-manifest", installed)
    assert proc.returncode == 1, proc.stdout
    assert "FAIL: rollback refused" in proc.stdout and "another release" in proc.stdout, proc.stdout
    assert f"source_rev {'a' * 40}" in proc.stdout and f"installed source_rev {'b' * 40}" in proc.stdout
    assert "bundle verification PASSED" not in proc.stdout
    allowed = _verify("--bundle", other, "--pubkey", pub, "--installed-manifest", installed, "--allow-downgrade")
    assert allowed.returncode == 0 and "WARNING: DOWNGRADE allowed" in allowed.stdout, allowed.stdout


@pytest.mark.parametrize(
    "fields",
    [
        {"source_rev": "b" * 40},  # a reinstall, or a rebuild of the same commit
        {"source_rev": "b" * 40, "created": "2026-10-01T00:00:00+00:00"},
        {},  # a bundle that names no revision: nothing tells them apart (an explicit --release-seq)
        {"source_rev": "unknown"},
    ],
    ids=["same-rev", "rebuilt", "no-rev", "unknown-rev"],
)
def test_i3_the_same_release_is_still_reinstallable(tmp_path: Path, fields: dict[str, Any]) -> None:
    key, _, pub = _keypair(tmp_path)
    installed = _installed(tmp_path, release_seq=1727000000, source_rev="b" * 40)
    bundle = _bundle(tmp_path / "again", key, release_seq=1727000000, **fields)
    proc = _verify("--bundle", bundle, "--pubkey", pub, "--installed-manifest", installed)
    assert proc.returncode == 0 and "(not a downgrade)" in proc.stdout, proc.stdout


# ---- K1/K2: the deb preinst refuses before dpkg unpacks anything ------------------


def _deb_preinst(tmp_path: Path, seq: str = "", rev: str = "", verifier: str = "# verifier\n") -> tuple[Path, Path]:
    """preinst sandboxed (trust paths and the installed manifest in tmp_path), with the payload's
    release_seq and source_rev written in as build_deb.sh does."""
    script, verifier_path, pubkey = _preinst_sandbox_script(tmp_path)
    verifier_path.parent.mkdir(parents=True, exist_ok=True)
    verifier_path.write_text(verifier, encoding="utf-8")
    pubkey.parent.mkdir(parents=True, exist_ok=True)
    pubkey.write_text("-----BEGIN PUBLIC KEY-----\nAA==\n-----END PUBLIC KEY-----\n", encoding="utf-8")
    shutil.copy2(INSTALL, verifier_path.parent / "install_offline.sh")
    installed = tmp_path / "opt" / "manifest.json"
    text = script.read_text(encoding="utf-8")
    for name, value in (("PAYLOAD_RELEASE_SEQ", seq), ("PAYLOAD_SOURCE_REV", rev),
                        ("INSTALLED_MANIFEST", str(installed))):
        text, count = re.subn(rf'^{name}="[^"\n]*"$', f'{name}="{value}"', text, flags=re.M)
        assert count == 1, name
    script.write_text(text, encoding="utf-8")
    return script, installed


def _run_preinst(tmp_path: Path, script: Path, **env: str) -> subprocess.CompletedProcess[str]:
    full = {k: v for k, v in os.environ.items() if not k.startswith("UDBMCP_")}
    full["PATH"] = f"{_py_shims(tmp_path)}:/usr/bin:/bin"
    full.update(env)
    return subprocess.run(  # noqa: S603 - sandboxed copy of a repo script
        ["/bin/bash", str(script), "upgrade", "0.1.0+202609010000.gabc1234"],
        env=full, capture_output=True, text=True, timeout=60, check=False,
    )


def test_k1_preinst_refuses_a_verifier_that_predates_the_rollback_check(tmp_path: Path) -> None:
    script, _ = _deb_preinst(tmp_path, verifier='ap.add_argument("--pubkey", default=None)\n')
    proc = _run_preinst(tmp_path, script)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "OUTDATED copy" in proc.stderr and "--installed-manifest" in proc.stderr and "ABORTED" in proc.stderr
    script, _ = _deb_preinst(tmp_path, verifier=VERIFIER.read_text(encoding="utf-8"))
    proc = _run_preinst(tmp_path, script)
    assert proc.returncode == 0, proc.stderr
    assert "trust prerequisites present" in proc.stdout


@pytest.mark.parametrize(
    ("installed", "env", "refused"),
    [
        ({"release_seq": 6, "source_rev": "bbb"}, {}, "OLDER than the installed release_seq 6"),
        ({"release_seq": 6, "source_rev": "bbb"}, {"UDBMCP_ALLOW_DOWNGRADE": "1"}, None),
        ({"release_seq": 5, "source_rev": "bbb"}, {}, "another release with the installed release's release_seq 5"),
        ({"release_seq": 5, "source_rev": "aaa"}, {}, None),  # a reinstall
        ({"release_seq": 5}, {}, None),  # the installed release names no revision: postinst's verifier decides
        ({"release_seq": 4, "source_rev": "bbb"}, {}, None),  # an upgrade
        ({}, {}, None),  # predates release_seq: postinst's verifier orders it
        (None, {}, None),  # a first install
    ],
    ids=["older", "older-allowed", "same-seq-other-rev", "reinstall", "installed-no-rev", "newer", "unsequenced",
         "first"],
)
def test_k2_preinst_refuses_an_older_release_before_it_is_unpacked(
    tmp_path: Path, installed: dict[str, Any] | None, env: dict[str, str], refused: str | None
) -> None:
    script, manifest = _deb_preinst(tmp_path, seq="5", rev="aaa")
    if installed is not None:
        manifest.parent.mkdir(parents=True)
        manifest.write_text(json.dumps({"profile": "p", **installed}), encoding="utf-8")
    proc = _run_preinst(tmp_path, script, **env)
    if refused is None:
        assert proc.returncode == 0, proc.stdout + proc.stderr
        return
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "rollback refused" in proc.stderr and refused in proc.stderr, proc.stderr
    assert "nothing was unpacked" in proc.stderr and "UDBMCP_ALLOW_DOWNGRADE=1 dpkg -i" in proc.stderr


def test_k2_the_repository_preinst_compares_nothing(tmp_path: Path) -> None:
    script, manifest = _deb_preinst(tmp_path)
    manifest.parent.mkdir(parents=True)
    manifest.write_text(json.dumps({"release_seq": 99, "source_rev": "zzz"}), encoding="utf-8")
    assert _run_preinst(tmp_path, script).returncode == 0


def test_k2_build_deb_writes_the_payload_release_into_the_preinst(tmp_path: Path) -> None:
    text = BUILD_DEB.read_text(encoding="utf-8")
    block = _between(text, 'case "$RELEASE_SEQ" in', 'chmod 0755 "$DEBROOT/DEBIAN/preinst"')
    (tmp_path / "DEBIAN").mkdir()
    for seq, expected_seq in (("1727000000", "1727000000"), ("", ""), ("12x", "")):
        shutil.copy2(PREINST, tmp_path / "DEBIAN" / "preinst")  # the copy loop before the block
        script = (
            f'die() {{ echo "DIE: $*" >&2; exit 9; }}\nMAINT_DIR="{PREINST.parent}"\nDEBROOT="{tmp_path}"\n'
            f'RELEASE_SEQ="{seq}"\nSOURCE_REV="0.1.0+202609270000.gabc1234"\n{block}'
        )
        proc = _bash(script)
        assert proc.returncode == 0, proc.stderr
        built = (tmp_path / "DEBIAN" / "preinst").read_text(encoding="utf-8")
        expected = PREINST.read_text(encoding="utf-8").replace(
            '\nPAYLOAD_RELEASE_SEQ=""\n', f'\nPAYLOAD_RELEASE_SEQ="{expected_seq}"\n'
        ).replace('\nPAYLOAD_SOURCE_REV=""\n', '\nPAYLOAD_SOURCE_REV="0.1.0+202609270000.gabc1234"\n')
        assert built == expected
        assert os.access(tmp_path / "DEBIAN" / "preinst", os.X_OK)


def test_k2_postinst_only_restarts_the_service_when_dpkg_undoes_an_upgrade(tmp_path: Path) -> None:
    """A preinst refusal makes dpkg run the installed release's postinst with abort-upgrade: the old
    payload is still in place and only the service the prerm stopped has to run again."""
    text = POSTINST.read_text(encoding="utf-8")
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    block = _between(text, 'case "${1:-}" in', "esac")
    # it runs before anything else does: the trust dir, the verifier, the installer
    assert code.index('case "${1:-}" in') < code.index("TRUST_DIR=") < code.index("verify_payload_with_proof")
    shims = tmp_path / "shims"
    shims.mkdir()
    (shims / "systemctl").write_text(f'#!/bin/sh\necho "$*" >> "{tmp_path}/systemctl.log"\nexit 0\n', encoding="utf-8")
    (shims / "systemctl").chmod(0o755)
    env = {**os.environ, "PATH": f"{shims}:/usr/bin:/bin"}
    venv_python = tmp_path / "opt" / "venv" / "bin" / "python"  # the installed release's venv is in place
    venv_python.parent.mkdir(parents=True)
    venv_python.write_text("#!/bin/sh\n", encoding="utf-8")
    venv_python.chmod(0o755)
    block = block.replace("/opt/universal-db-mcp/venv/bin/python", str(venv_python))
    block = block.replace("/var/log/universal-db-mcp-install.status", str(tmp_path / "status"))
    for action in ("abort-upgrade", "abort-remove", "abort-deconfigure", "configure"):
        script = block.replace("[ -d /run/systemd/system ]", "true") + 'echo "FELL THROUGH"\n'
        proc = subprocess.run(  # noqa: S603 - postinst's own block
            ["/bin/bash", "-c", script, "postinst", action, "0.1.0+1"],
            env=env, capture_output=True, text=True, timeout=60, check=False,
        )
        assert proc.returncode == 0, proc.stderr
        assert ("FELL THROUGH" in proc.stdout) is (action == "configure"), (action, proc.stdout)
    calls = (tmp_path / "systemctl.log").read_text(encoding="utf-8").splitlines()
    assert calls.count("start universal-db-mcp") == 3, calls


# ---- K4: the bootstrap's scratch-site hook never reaches root ---------------------


def test_k4_bootstrap_refuses_the_test_hook_when_run_as_root(tmp_path: Path) -> None:
    _key, _, pub = _keypair(tmp_path)
    stick = tmp_path / "stick"
    (stick / "trust-bootstrap-linux").mkdir(parents=True)
    shutil.copy2(BOOTSTRAP, stick / "trust-bootstrap-linux" / "bootstrap.sh")
    root = _site(tmp_path, pub)
    fake_root = tmp_path / "as-root"
    fake_root.mkdir()
    (fake_root / "id").write_text(
        '#!/bin/sh\n[ "$1" = -u ] && { echo 0; exit 0; }\nexec /usr/bin/id "$@"\n', encoding="utf-8"
    )
    (fake_root / "id").chmod(0o755)
    env = {k: v for k, v in os.environ.items() if not k.startswith("UDBMCP_")}
    env.update(PATH=f"{fake_root}:/usr/bin:/bin:/usr/sbin:/sbin", UDBMCP_BOOTSTRAP_ROOT=str(root))
    before = sorted(str(p.relative_to(root)) for p in root.rglob("*"))
    proc = subprocess.run(  # noqa: S603 - repo script under test, "root" by a shimmed id
        ["/bin/bash", str(stick / "trust-bootstrap-linux" / "bootstrap.sh")],
        env=env, capture_output=True, text=True, timeout=120, check=False,
    )
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "UDBMCP_BOOTSTRAP_ROOT is set" in proc.stderr and "refused as root" in proc.stderr, proc.stderr
    assert sorted(str(p.relative_to(root)) for p in root.rglob("*")) == before


def test_k4_the_hook_is_checked_before_anything_reads_it() -> None:
    text = BOOTSTRAP.read_text(encoding="utf-8")
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    guard = code.index('if [ -n "$ROOT" ] && [ "$(id -u)" -eq 0 ]; then')
    assert code.index('ROOT="${UDBMCP_BOOTSTRAP_ROOT:-}"') < guard < code.index('TRUST_DIR="$ROOT/')


# ---- Z1: a rollback never leaves the release record below the running release -----


def _rollback_target(tmp_path: Path, record: dict[str, Any] | None, previous: dict[str, Any] | None) -> Path:
    """$TARGET with a verifiable venv.previous, the installed-release record *record* and the record
    of the release in venv.previous that the installer kept beside it (*previous*)."""
    target = tmp_path / "target"
    venv_bin = target / "venv.previous" / "bin"
    venv_bin.mkdir(parents=True)
    (venv_bin / "python").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    (venv_bin / "python").chmod(0o755)
    (target / "venv.previous.sha256").write_text(f"{_sha256(venv_bin / 'python')}  ./bin/python\n", encoding="utf-8")
    (target / "venv" / "bin").mkdir(parents=True)
    if record is not None:
        (target / "manifest.json").write_text(json.dumps(record), encoding="utf-8")
    if previous is not None:
        (target / "venv.previous.manifest.json").write_text(json.dumps(previous), encoding="utf-8")
    return target


def _rollback(tmp_path: Path, target: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("UDBMCP_")}
    env.update(UDBMCP_CONFIG_DIR=str(tmp_path / "etc"), UDBMCP_STATE_DIR=str(tmp_path / "varlib"))
    env["PATH"] = f"{_py_shims(tmp_path)}:{env.get('PATH', '/usr/bin:/bin')}"
    return subprocess.run(  # noqa: S603 - repo script under test
        ["/bin/bash", str(ROLLBACK), str(target), str(tmp_path / "backups"), *args],
        env=env, capture_output=True, text=True, timeout=120, check=False,
    )


def test_z1_rollback_after_an_intended_downgrade_raises_the_record_to_the_running_release(tmp_path: Path) -> None:
    """200 ran; 100 was installed on purpose (record 100); rolling back brings 200 back, so the record
    must name 200 again or every bundle from 100 to 199 is accepted without --allow-downgrade."""
    running = {"profile": "p", "release_seq": 200, "source_rev": "new"}
    target = _rollback_target(tmp_path, {"profile": "p", "release_seq": 100}, running)
    proc = _rollback(tmp_path, target)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert json.loads((target / "manifest.json").read_text(encoding="utf-8")) == running
    assert "now names the running release" in proc.stdout, proc.stdout
    assert "re-installing the older bundle is a downgrade" not in proc.stdout, proc.stdout
    assert not (target / "venv.previous.manifest.json").exists()
    # and the verifier then refuses what lies between
    key, _, pub = _keypair(tmp_path)
    between = _bundle(tmp_path / "b150", key, release_seq=150)
    refused = _verify("--bundle", between, "--pubkey", pub, "--installed-manifest", target / "manifest.json")
    assert refused.returncode == 1 and "FAIL: rollback refused" in refused.stdout, refused.stdout


@pytest.mark.parametrize(
    ("record", "previous", "kept"),
    [
        ({"release_seq": 200}, {"release_seq": 100}, True),  # an ordinary rollback: the high-water mark stays
        ({"release_seq": 200}, None, True),  # demoted by an installer that kept no record
        ({"release_seq": 200}, {"release_seq": 200}, True),
        ({"release_seq": 200}, {"profile": "p"}, True),  # the restored release predates release_seq
    ],
    ids=["ordinary", "no-previous-record", "same", "previous-unsequenced"],
)
def test_z1_an_ordinary_rollback_keeps_the_later_release_in_the_record(
    tmp_path: Path, record: dict[str, Any], previous: dict[str, Any] | None, kept: bool
) -> None:
    target = _rollback_target(tmp_path, record, previous)
    proc = _rollback(tmp_path, target)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert json.loads((target / "manifest.json").read_text(encoding="utf-8")) == record
    if previous is None or previous.get("release_seq") != record["release_seq"]:
        assert "re-installing the older bundle is a downgrade" in proc.stdout, proc.stdout


def test_z1_a_missing_record_is_restored_from_the_running_release(tmp_path: Path) -> None:
    running = {"profile": "p", "release_seq": 200}
    target = _rollback_target(tmp_path, None, running)
    proc = _rollback(tmp_path, target)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert json.loads((target / "manifest.json").read_text(encoding="utf-8")) == running


@pytest.mark.parametrize("script", [INSTALL, UPGRADE], ids=["install_offline", "upgrade_offline"])
def test_z1_the_installers_keep_the_running_release_record_with_its_demoted_venv(script: Path) -> None:
    text = script.read_text(encoding="utf-8")
    switch = text[text.index('$sudo_ok rm -rf "$TARGET/venv.previous"') :]
    keep = switch.index('"$TARGET/manifest.json" "$TARGET/venv.previous.manifest.json"')
    assert switch.index('rm -f "$TARGET/venv.previous.manifest.json"') < keep
    assert keep < switch.index('mv "$TARGET/venv" "$TARGET/venv.previous"')


@_NOT_ROOT
def test_z1_the_installers_switch_block_keeps_the_record(tmp_path: Path) -> None:
    """Behaviour of the upgrade's switch: the running release's record lands beside venv.previous."""
    text = UPGRADE.read_text(encoding="utf-8")
    block = text[text.index('if [ -d "$TARGET/venv" ]; then\n  $sudo_ok rm -rf "$TARGET/venv.previous"') :]
    switched = '$sudo_ok mv "$NEWVENV" "$TARGET/venv"\n'
    block = block[: block.index(switched) + len(switched)]
    target = tmp_path / "target"
    (target / "venv" / "bin").mkdir(parents=True)
    (target / "venv" / "bin" / "python").write_text("old\n", encoding="utf-8")
    (target / "venv.new-1" / "bin").mkdir(parents=True)
    record = {"profile": "p", "release_seq": 200}
    (target / "manifest.json").write_text(json.dumps(record), encoding="utf-8")
    shims = tmp_path / "shims"
    shims.mkdir()
    (shims / "install").write_text(
        _INSTALL_WITHOUT_CHOWN,
        encoding="utf-8",
    )
    if shutil.which("sha256sum") is None:  # macOS has shasum only
        (shims / "sha256sum").write_text('#!/bin/sh\nexec shasum -a 256 "$@"\n', encoding="utf-8")
    for shim in shims.iterdir():
        shim.chmod(0o755)
    env = {**os.environ, "PATH": f"{shims}:/usr/bin:/bin:/usr/sbin:/sbin"}
    proc = _bash(f'set -euo pipefail\nsudo_ok=""\nTARGET="{target}"\nNEWVENV="{target}/venv.new-1"\n{block}', env=env)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert json.loads((target / "venv.previous.manifest.json").read_text(encoding="utf-8")) == record
    assert (target / "venv.previous" / "bin" / "python").read_text(encoding="utf-8") == "old\n"


# ---- Z2: the format marker moves with the installer's behaviour -------------------


def test_z2_preinst_postinst_and_the_installer_agree_on_a_bumped_format() -> None:
    marker = re.search(r"^# udbmcp-installer-format: (\d+)$", INSTALL.read_text(encoding="utf-8"), flags=re.M)
    assert marker is not None
    current = int(marker.group(1))
    assert current >= 4, "the 2026-09 hardening changed what the trusted installer does: the marker must move"
    for script in (PREINST, POSTINST):
        assert re.findall(r"^INSTALLER_FORMAT=(\d+)$", script.read_text(encoding="utf-8"), flags=re.M) == [str(current)]


def test_z2_an_installer_with_the_previous_marker_is_refused(tmp_path: Path) -> None:
    script, _ = _deb_preinst(tmp_path)
    installer = tmp_path / "udbmcp-trust" / "install_offline.sh"
    installer.write_text(
        INSTALL.read_text(encoding="utf-8").replace("# udbmcp-installer-format: 4\n", "# udbmcp-installer-format: 3\n"),
        encoding="utf-8",
    )
    proc = _run_preinst(tmp_path, script)
    assert proc.returncode == 1 and "udbmcp-installer-format: 4" in proc.stderr, proc.stderr


# ---- Z3: --restore-config never brings back retired trust material or tokens -------


def test_z3_restore_config_keeps_the_live_release_key_and_http_token(tmp_path: Path) -> None:
    target = _rollback_target(tmp_path, {"release_seq": 200}, {"release_seq": 100})
    etc = tmp_path / "etc"
    (etc / "keys").mkdir(parents=True)
    (etc / "config.yaml").write_text("live: config\n", encoding="utf-8")
    (etc / "keys" / "release.pub.pem").write_text("ROTATED KEY\n", encoding="utf-8")
    (etc / "http-token").write_text("rotated-token\n", encoding="utf-8")
    backup = tmp_path / "backups" / "pre-upgrade-20260901T000000Z" / "universal-db-mcp"
    (backup / "keys").mkdir(parents=True)
    (backup / "config.yaml").write_text("backup: config\n", encoding="utf-8")
    (backup / "keys" / "release.pub.pem").write_text("RETIRED KEY\n", encoding="utf-8")
    (backup / "keys" / "old-extra.pem").write_text("RETIRED EXTRA\n", encoding="utf-8")
    (backup / "http-token").write_text("leaked-token\n", encoding="utf-8")
    proc = _rollback(tmp_path, target, "--restore-config")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert (etc / "config.yaml").read_text(encoding="utf-8") == "backup: config\n"  # configuration IS restored
    assert (etc / "keys" / "release.pub.pem").read_text(encoding="utf-8") == "ROTATED KEY\n"
    assert not (etc / "keys" / "old-extra.pem").exists()
    assert (etc / "http-token").read_text(encoding="utf-8") == "rotated-token\n"


def test_z3_a_trust_item_absent_from_the_live_configuration_stays_absent(tmp_path: Path) -> None:
    target = _rollback_target(tmp_path, {"release_seq": 200}, {"release_seq": 100})
    etc = tmp_path / "etc"
    etc.mkdir()
    (etc / "config.yaml").write_text("live: config\n", encoding="utf-8")
    backup = tmp_path / "backups" / "pre-upgrade-20260901T000000Z" / "universal-db-mcp"
    backup.mkdir(parents=True)
    (backup / "config.yaml").write_text("backup: config\n", encoding="utf-8")
    (backup / "http-token").write_text("revoked-token\n", encoding="utf-8")
    proc = _rollback(tmp_path, target, "--restore-config")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert not (etc / "http-token").exists()


# ---- the pkg preinstall: same refusals as the deb's, before the payload lands --------


def _pkg_installed(seq: int, rev: str | None, payload_rev: str) -> Any:
    def arrange(tmp: Path) -> None:
        _payload_release_seq(tmp, PKG_PREINSTALL, "4")
        sandbox = tmp / f"{PKG_PREINSTALL.name}_sbx.sh"
        text, count = re.subn(r'^PAYLOAD_SOURCE_REV=""$', f'PAYLOAD_SOURCE_REV="{payload_rev}"',
                              sandbox.read_text(encoding="utf-8"), flags=re.M)
        assert count == 1
        sandbox.write_text(text, encoding="utf-8")
        manifest: dict[str, Any] = {"profile": "p", "release_seq": seq}
        if rev is not None:
            manifest["source_rev"] = rev
        (tmp / "prefix" / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    return arrange


@_NOT_ROOT
@pytest.mark.parametrize(
    ("seq", "rev", "refused"),
    [(4, "bbb", "another release with the installed release_seq 4"), (4, "aaa", None), (4, None, None),
     (5, "aaa", "OLDER than the installed release_seq 5"), (3, "bbb", None)],
    ids=["same-seq-other-rev", "reinstall", "installed-no-rev", "older", "newer"],
)
def test_i3_pkg_preinstall_refuses_another_release_with_the_same_seq(
    tmp_path: Path, seq: int, rev: str | None, refused: str | None
) -> None:
    proc, _, _ = _run_pkg(tmp_path, PKG_PREINSTALL, _python_org, _find_as_root(tmp_path),
                          tweak=_pkg_installed(seq, rev, "aaa"))
    if refused is None:
        assert proc.returncode == 0, proc.stdout + proc.stderr
        return
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert refused in proc.stderr and "nothing was installed" in proc.stderr, proc.stderr


@_NOT_ROOT
def test_k1_pkg_preinstall_refuses_a_verifier_that_predates_the_rollback_check(tmp_path: Path) -> None:
    def outdated(tmp: Path) -> None:
        (tmp / "trust" / "verify_bundle.py").write_text('ap.add_argument("--pubkey", default=None)\n', encoding="utf-8")
        _config_dir(tmp)

    proc, runs, _ = _run_pkg(tmp_path, PKG_PREINSTALL, _python_org, _find_as_root(tmp_path), tweak=outdated)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "OUTDATED copy" in proc.stderr and "Nothing was installed" in proc.stderr, proc.stderr
    assert runs == [], "refused before any interpreter ran"


def test_i3_build_pkg_writes_the_payload_source_rev_into_preinstall_only() -> None:
    text = BUILD_PKG.read_text(encoding="utf-8")
    loop = _between(text, "for f in preinstall postinstall; do", "done")
    assert 's/^PAYLOAD_SOURCE_REV=\\"\\"\\$/PAYLOAD_SOURCE_REV=\\"$SOURCE_REV\\"/' in loop
    assert PKG_PREINSTALL.read_text(encoding="utf-8").count('\nPAYLOAD_SOURCE_REV=""\n') == 1
    assert "PAYLOAD_SOURCE_REV" not in PKG_POSTINSTALL.read_text(encoding="utf-8")
