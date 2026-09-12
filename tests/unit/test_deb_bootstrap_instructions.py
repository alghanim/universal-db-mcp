"""Regression tests: the deb preinst bootstrap instructions list ALL trusted-channel files.

Defect fixed 2026-09-12: bootstrap_verifier (packaging/deb/preinst) told the
admin to install only verify_bundle.py and install_offline.sh. But
verify_bundle.py hard-requires profiles.py next to itself
(scripts/verify_bundle.py: load_profiles_module, "profiles.py not found next
to this verifier or in its lib/ directory") and install_offline.sh
hard-requires lib/os_packages.sh next to itself
(scripts/install_offline.sh: "shared OS-package helper not found"). An admin
following the printed instructions verbatim passed preinst, then postinst
aborted inside install_offline.sh with a diagnostic about a different missing
file. These tests lock the complete file set into the preinst heredocs and
into both mirrored bootstrap blocks in docs/offline-deployment.md.

No trust invariants are exercised here beyond documentation accuracy: the
fail-closed behavior is covered by tests/unit/test_deb_packaging.py.
"""

from __future__ import annotations

import re
from pathlib import Path

_PROJECT = Path(__file__).resolve().parents[2]
_PREINST = _PROJECT / "packaging" / "deb" / "preinst"
_DEPLOY_DOC = _PROJECT / "docs" / "offline-deployment.md"

# The complete set of trusted-channel files an admin must install into
# /usr/local/lib/udbmcp-trust for postinst's verify+install to be able to run
# at all. This is a subset of scripts/prepare_offline_bundle.py's
# trusted-tools/ export, which additionally ships upgrade_offline.sh and
# rollback_offline.sh; the .deb bootstrap path never invokes those two, so
# they are not required here.
_REQUIRED_TRUST_FILES = (
    "verify_bundle.py",
    "profiles.py",
    "install_offline.sh",
    "lib/os_packages.sh",
)


def _bootstrap_blocks(text: str) -> list[str]:
    """Return the quoted-heredoc blocks (preinst prints these verbatim)."""
    return re.findall(r"<<'EOF'\n(.*?)\nEOF", text, flags=re.DOTALL)


def test_preinst_bootstrap_heredoc_lists_all_required_trust_files() -> None:
    text = _PREINST.read_text(encoding="utf-8")
    blocks = "\n".join(_bootstrap_blocks(text))
    for name in _REQUIRED_TRUST_FILES:
        assert f"/{name} " in blocks or blocks.rstrip().endswith(f"/{name}"), (
            f"preinst bootstrap heredocs do not install {name}; an admin "
            "following them verbatim fails later inside postinst"
        )


def test_preinst_bootstrap_heredoc_creates_lib_subdirectory() -> None:
    """install_offline.sh sources lib/os_packages.sh relative to itself, so the
    heredoc must create $TRUST_DIR/lib before installing the helper into it."""
    text = _PREINST.read_text(encoding="utf-8")
    blocks = "\n".join(_bootstrap_blocks(text))
    assert "install -d -m 755 /usr/local/lib/udbmcp-trust/lib" in blocks


def test_preinst_still_fails_closed_and_keeps_original_two_prerequisites() -> None:
    """Guard against the fix accidentally dropping the core preinst behavior."""
    text = _PREINST.read_text(encoding="utf-8")
    assert 'sudo install -m 644 <trusted-channel>/verify_bundle.py /usr/local/lib/udbmcp-trust/' in text
    assert 'sudo install -m 755 <trusted-channel>/install_offline.sh /usr/local/lib/udbmcp-trust/' in text
    assert "exit 1" in text


def _doc_bash_blocks(text: str) -> list[str]:
    return re.findall(r"```bash\n(.*?)```", text, flags=re.DOTALL)


def test_offline_deployment_doc_mirrors_complete_file_set() -> None:
    """The runbook's generic 'Trust bootstrap' block and the .deb Step 1 block
    must name every required trusted-channel file. (The .pkg section has its
    own bootstrap block, owned by the pkg artifact — not asserted here.)"""
    doc = _DEPLOY_DOC.read_text(encoding="utf-8")

    def _bootstrap_blocks_between(start: str, end: str) -> list[str]:
        # Only blocks that bootstrap the trust dir (create it) count; other
        # blocks merely invoke the installer/verifier from it.
        section = doc[doc.index(start):doc.index(end)]
        return [
            b for b in _doc_bash_blocks(section)
            if "install -d -m 755 /usr/local/lib/udbmcp-trust" in b
        ]

    # Bind each owned block by its enclosing section, not by a bare count over
    # the whole document: a regression in ONE block (e.g. dropping the
    # profiles.py line from the .deb Step 1 block) must fail this test even
    # though the other blocks are still complete.
    sections = (
        (
            "generic Trust bootstrap",
            _bootstrap_blocks_between(
                "## Trust bootstrap (before install)", "## Native mode install"
            ),
        ),
        (
            ".deb Step 1",
            _bootstrap_blocks_between(
                "## Install on Ubuntu via .deb", "## Install on macOS via .pkg"
            ),
        ),
    )
    for label, blocks in sections:
        assert len(blocks) == 1, (
            f"expected exactly one trust-bootstrap bash block in the {label} "
            f"section of docs/offline-deployment.md, found {len(blocks)}"
        )
        missing = [
            name for name in _REQUIRED_TRUST_FILES if f"/{name}" not in blocks[0]
        ]
        assert not missing, (
            f"the {label} bootstrap block in docs/offline-deployment.md does "
            f"not install {missing}; an admin following it verbatim fails "
            "later inside postinst"
        )
