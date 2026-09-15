"""Packaging paths that report success while leaving a broken deployment.

Audit 2026-09-15. Each of these is invisible to the four packaging gates,
because every gate installs onto a CLEAN machine and none starts the daemon in
its real transport:

* the macOS postinstall was the only verifier call site that trusted an exit
  code, so an empty or no-op verifier would "pass";
* the upgrade script never normalized venv modes, so an upgrade under umask
  077 reproduced the live 203/EXEC failure the install path already fixes;
* the shipped config template points at a demo database no installer created,
  so doctor was fatally unhealthy on every clean install - and that later
  aborts the next upgrade, blaming the new release;
* a .deb upgrade kept a pre-HTTP (stdio) unit forever on hosts installed
  before the shipped-unit hash record existed - stdio under a service manager
  reads EOF and exits 0, which looks like a clean start and logs nothing;
* two status-file ordering bugs let the deferred-install guard refuse the very
  install that had just succeeded.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PKG_POSTINSTALL = (ROOT / "packaging" / "pkg" / "postinstall").read_text(encoding="utf-8")
DEB_POSTINST = (ROOT / "packaging" / "deb" / "postinst").read_text(encoding="utf-8")
INSTALLER = (ROOT / "scripts" / "install_offline.sh").read_text(encoding="utf-8")
UPGRADER = (ROOT / "scripts" / "upgrade_offline.sh").read_text(encoding="utf-8")
TEMPLATE = (ROOT / "config.example.yaml").read_text(encoding="utf-8")


def test_macos_verifier_requires_proof_not_just_exit_zero() -> None:
    assert "bundle verification PASSED" in PKG_POSTINSTALL, (
        "python3 on an empty verifier exits 0 without verifying anything"
    )
    assert "grep -q '^FAIL:'" in PKG_POSTINSTALL


def test_upgrade_normalizes_venv_modes_like_install() -> None:
    for pattern in (
        'find "$NEWVENV" -type d -exec chmod 755',
        'find "$NEWVENV" -type f -exec chmod 644',
        'find "$NEWVENV/bin" -type f -exec chmod 755',
    ):
        assert pattern in UPGRADER, f"missing from the upgrade path: {pattern}"


def test_installers_create_the_demo_database_the_template_references() -> None:
    demo_path = "/var/lib/universal-db-mcp/demo/finlink_demo.db"
    assert demo_path in TEMPLATE, "the template is what makes this file load-bearing"
    assert demo_path in INSTALLER
    assert "demo/finlink_demo.db" in PKG_POSTINSTALL
    # never clobber a seeded database
    assert 'if [ ! -f "$DEMO_DB" ]' in INSTALLER
    assert 'if [ ! -f "$DEMO_DB" ]' in PKG_POSTINSTALL


def test_deb_replaces_a_unit_that_still_runs_stdio() -> None:
    assert DEB_POSTINST.count('! grep -q -- "--transport http" "$UNIT_DST"') == 2, (
        "both the deferred and the synchronous install path must replace a pre-HTTP unit"
    )


def test_deferred_path_records_success_before_restarting() -> None:
    success = DEB_POSTINST.index('echo success > "$STATUS"')
    restart = DEB_POSTINST.index("systemctl try-restart", success)
    assert success < restart, (
        "the guard refuses starts until the status says success, so restarting first "
        "stops a running service and leaves it failed"
    )


def test_sync_path_clears_stale_status_before_enabling() -> None:
    clear = DEB_POSTINST.rindex('rm -f -- "$STATUS"')
    enable = DEB_POSTINST.rindex("systemctl enable --now")
    assert clear < enable, (
        "a stale deferred-status file must be dropped before this install starts the service"
    )


# ------------------------------------------------- Windows installer (never run end to end)
MSI_SERVICE = (ROOT / "packaging" / "msi" / "custom" / "service.ps1").read_text(encoding="utf-8")
MSI_WXS = (ROOT / "packaging" / "msi" / "udbmcp.wxs").read_text(encoding="utf-8")


def test_service_environment_is_one_multi_sz_value_under_the_service_key() -> None:
    """Windows reads a REG_MULTI_SZ value named Environment directly under the
    service key. Per-variable values under an Environment SUBKEY are ignored,
    while reg.exe still exits 0 - success reported, no environment set."""
    assert "/v Environment /t REG_MULTI_SZ" in MSI_SERVICE
    assert "UDBMCP_CONFIG=" in MSI_SERVICE and "UDBMCP_HTTP_BEARER_TOKEN_FILE=" in MSI_SERVICE
    assert "/v UDBMCP_CONFIG /t REG_MULTI_SZ" not in MSI_SERVICE, "the ignored subkey form"


def test_same_version_rebuilds_are_treated_as_upgrades() -> None:
    assert 'AllowSameVersionUpgrades="yes"' in MSI_WXS, (
        "the product version does not change between code-only builds"
    )
