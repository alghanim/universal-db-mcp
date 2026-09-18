"""The package refuses an OUTDATED trusted installer.

A trusted-tools copy from before 2026-09-15 runs pip without
--force-reinstall; through it an upgrade keeps the previous release's code
in the venv while dpkg, the manifest and the status file report success
(seen live at a site). preinst refuses before the payload is unpacked,
postinst refuses at configure time; a fake installer that does not run pip
at all (the fixtures of the other packaging tests) is left alone, and the
real scripts/install_offline.sh passes.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

from test_deb_packaging import _POSIX, _postinst_step1_bootstrap_script, _preinst_sandbox_script

ROOT = Path(__file__).resolve().parents[2]
REAL_INSTALLER = (ROOT / "scripts" / "install_offline.sh").read_text(encoding="utf-8")
OUTDATED_INSTALLER = (
    "#!/usr/bin/env bash\n"
    'PIP_FIND_LINKS="$BUNDLE/wheelhouse" "$TARGET/venv/bin/python" -m pip install --no-index '
    '--require-hashes -r "$BUNDLE/requirements/runtime.lock"\n'
)


def _run(script: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["/bin/bash", str(script)], capture_output=True, text=True, timeout=60)  # noqa: S603


@_POSIX
def test_preinst_refuses_an_installer_that_runs_pip_without_force_reinstall(tmp_path: Path) -> None:
    script, verifier, pubkey = _preinst_sandbox_script(tmp_path)
    verifier.parent.mkdir(parents=True, exist_ok=True)
    verifier.write_text("# verifier\n", encoding="utf-8")
    pubkey.parent.mkdir(parents=True, exist_ok=True)
    pubkey.write_text("-----BEGIN PUBLIC KEY-----\nAA==\n-----END PUBLIC KEY-----\n", encoding="utf-8")
    installer = verifier.parent / "install_offline.sh"

    installer.write_text(OUTDATED_INSTALLER, encoding="utf-8")
    proc = _run(script)
    assert proc.returncode == 1
    assert "OUTDATED copy" in proc.stderr and "trust-bootstrap-linux/bootstrap.sh" in proc.stderr
    assert "ABORTED" in proc.stderr

    installer.write_text(REAL_INSTALLER, encoding="utf-8")
    proc = _run(script)
    assert proc.returncode == 0, proc.stderr
    assert "trust prerequisites present" in proc.stdout

    installer.unlink()  # absent: postinst's completeness check owns that case
    proc = _run(script)
    assert proc.returncode == 0, proc.stderr


@_POSIX
def test_postinst_refuses_an_outdated_installer_and_accepts_the_real_one(tmp_path: Path) -> None:
    trust = tmp_path / "trust_dir"
    (trust / "lib").mkdir(parents=True)
    (trust / "verify_bundle.py").write_text("# admin verifier\n", encoding="utf-8")
    (trust / "profiles.py").write_text("# admin registry\n", encoding="utf-8")
    (trust / "lib" / "os_packages.sh").write_text("# admin helper\n", encoding="utf-8")
    script = _postinst_step1_bootstrap_script(tmp_path, strip_root_owner=True)

    (trust / "install_offline.sh").write_text(OUTDATED_INSTALLER, encoding="utf-8")
    proc = _run(script)
    assert proc.returncode != 0
    assert "OUTDATED copy" in proc.stderr and "bootstrap.sh" in proc.stderr

    (trust / "install_offline.sh").write_text(REAL_INSTALLER, encoding="utf-8")
    proc = _run(script)
    assert proc.returncode == 0, proc.stderr
    assert "admin trust dir complete" in proc.stdout

    # a fixture installer that does not run pip is not "outdated", it is a stub
    (trust / "install_offline.sh").write_text("# admin installer\n", encoding="utf-8")
    proc = _run(script)
    assert proc.returncode == 0, proc.stderr
