"""The deb gate carries an install-over-install case.

The 2026-09-15 incident (an upgrade that kept the previous release's code
while dpkg reported success) was invisible to a gate that only installed
fresh. This pins the shape of the upgrade case so it cannot be dropped
silently; its outcome is recorded in out/package-evidence/deb/results.json
when the gate runs.
"""
from __future__ import annotations

import re
from pathlib import Path

GATE = (Path(__file__).resolve().parents[2] / "scripts" / "package" / "test_package_deb.sh").read_text(encoding="utf-8")


def _upgrade_script() -> str:
    start = GATE.index("cat > \"$WORK/upgrade.sh\" <<'UPGRADE_EOF'")
    end = GATE.index("UPGRADE_EOF", start + 40)
    return GATE[start:end]


def test_upgrade_case_installs_twice_and_checks_the_marker_is_gone() -> None:
    body = _upgrade_script()
    assert body.count("install_pkg first") == 1 and body.count("install_pkg second") == 1
    assert "STALE-RELEASE-MARKER" in body
    assert 'grep -q "STALE-RELEASE-MARKER" "$PKG_INIT"' in body
    assert "rec upgrade_replaces_venv_code failed" in body and "rec upgrade_replaces_venv_code passed" in body
    # the marker goes into a wheel-tracked file so pip's reinstall must overwrite it
    assert "site-packages/universal_db_mcp/__init__.py" in body


def test_upgrade_case_keeps_the_admin_config_and_refuses_an_outdated_installer() -> None:
    body = _upgrade_script()
    assert "ADMIN-EDIT-MARKER" in body and "upgrade_keeps_admin_config" in body
    assert 'grep -v -- "--force-reinstall" /trust/install_offline.sh' in body
    assert 'grep -q "OUTDATED copy"' in body and "upgrade_refuses_outdated_installer" in body
    assert "install_pkg recovery" in body and "upgrade_after_refresh" in body
    assert 'dpkg --compare-versions "$NEWVER" gt "0.1.0~' in body and "upgrade_version_ordering" in body


def test_upgrade_case_runs_in_its_own_no_network_container_and_is_merged() -> None:
    block = GATE[GATE.index("# -------------------------------------------------------------- upgrade case"):]
    block = block[: block.index("# ------------------------------------------------------------- negative case")]
    assert re.search(r"docker run --rm --network none --platform linux/amd64", block)
    assert '-v "$WORK/upgrade.sh":/gate/upgrade.sh:ro' in block
    assert '-v "$PROJECT/scripts/install_offline.sh":/trust/install_offline.sh:ro' in block
    assert 'merge_container_checks "$EVIDENCE_DIR/upgrade-checks.tsv" "$UPG_RC" "upgrade"' in block
