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


def test_installer_builds_beside_a_running_venv_and_switches_with_a_manifest() -> None:
    """Since 2026-09-18 an upgrade never modifies the live venv in place: the
    new venv is built as venv.new-<ts>, smoke-checked, then switched with two
    renames after the running venv's integrity manifest is recorded, so the
    layout rollback_offline.sh expects (venv.previous + venv.previous.sha256)
    exists on the .deb path too."""
    text = INSTALLER.read_text(encoding="utf-8")
    assert 'VENV_BUILD="$TARGET/venv.new-$(date -u +%Y%m%dT%H%M%SZ)"' in text
    switch = text[text.index('if [ "$VENV_BUILD" != "$TARGET/venv" ]; then'):]
    assert "venv.previous.sha256" in switch and "sha256sum" in switch
    assert switch.index("sha256sum") < switch.index('mv "$TARGET/venv" "$TARGET/venv.previous"'), (
        "the manifest must be recorded BEFORE the demote rename"
    )
    assert switch.index('mv "$TARGET/venv" "$TARGET/venv.previous"') < switch.index('mv "$VENV_BUILD" "$TARGET/venv"')
    # the smoke check and mode normalization run on the NEW tree before the switch
    smoke_at = text.index('"$VENV_BUILD/bin/python" -m universal_db_mcp version')
    assert smoke_at < text.index('if [ "$VENV_BUILD" != "$TARGET/venv" ]; then')
    assert "restore_previous_venv_on_interrupt" in text and "trap on_exit EXIT" in text
