"""install_offline.sh must replace the application code on UPGRADES.

The app wheel's version string does not change between code-only releases
(0.1.0 -> 0.1.0), and the .deb postinst re-runs install_offline.sh over the
EXISTING venv. Without --force-reinstall, pip reports "already satisfied" for
universal-db-mcp==0.1.0 and keeps the previous release's code: the package
upgrade reports success while the old connector keeps running. Seen live
2026-09-15 at an air-gapped Ubuntu site - the Db2 credential fix (854b50d)
was installed via dpkg -i yet the same SQL30082N errors persisted. The macOS
postinstall already carries this rule (test_service_http_mode.py pins it).
"""

from __future__ import annotations

from pathlib import Path

INSTALLER = Path(__file__).resolve().parents[2] / "scripts" / "install_offline.sh"


def _app_pip_block() -> str:
    text = INSTALLER.read_text(encoding="utf-8")
    start = text.index('echo "==> installing application from bundle wheelhouse')
    end = text.index('-r "$BUNDLE/requirements/runtime.lock"', start)
    return text[start:end]


def test_installer_force_reinstalls_the_hashed_lock_on_upgrade() -> None:
    block = _app_pip_block()
    assert "--force-reinstall" in block, (
        "install_offline.sh must --force-reinstall from the verified wheelhouse: "
        "a same-version upgrade otherwise keeps the previous release's code"
    )


def test_force_reinstall_keeps_the_offline_hashed_guarantees() -> None:
    block = _app_pip_block()
    for flag in ("--no-index", "--require-hashes", "--only-binary=:all:", "--no-cache-dir"):
        assert flag in block, f"{flag} must stay on the forced reinstall"
    assert "PIP_CONFIG_FILE=/dev/null" in block
