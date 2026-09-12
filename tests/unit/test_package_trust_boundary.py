"""Trust-boundary regression tests for the native-package build scripts.

The commit security review (2026-09-12) flagged that build_deb.sh and
build_msi.sh accepted an IN-BUNDLE trusted-tools/ copy as the verification
verifier — a tampered bundle could ship a verifier that prints PASSED and
get itself verified (the same self-verification bypass class the installer's
trust boundary fixes). The builder must verify only with an OUT-of-bundle
verifier: the sibling trusted-tools/ directory or an explicit
UDBMCP_TRUST_DIR override.
"""

from __future__ import annotations

import pathlib

import pytest

BUILD_SCRIPTS = [
    "scripts/package/build_deb.sh",
    "scripts/package/build_msi.sh",
]


def _project_root() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("script", BUILD_SCRIPTS)
def test_build_script_never_uses_in_bundle_verifier(script: str) -> None:
    """The verifier candidate list must not contain an in-bundle path, and
    must reject a candidate that resolves inside the bundle."""
    text = (_project_root() / script).read_text(encoding="utf-8")
    assert '"$BUNDLE/trusted-tools"' not in text, (
        f"{script} must not offer $BUNDLE/trusted-tools as a verifier candidate: "
        "a tampered bundle could ship a verifier that prints PASSED"
    )
    # candidates: explicit UDBMCP_TRUST_DIR override + the sibling directory
    assert '"${UDBMCP_TRUST_DIR:-}"' in text, "override must be honored"
    assert '"$BUNDLE/../trusted-tools"' in text, "sibling trusted-tools is the documented channel"
    # a candidate resolving INSIDE the bundle is skipped, not used
    assert '"$bundle_real"/*) continue' in text.replace("\t", "    ") or '"$bundle_real"/*)' in text, (
        f"{script} must skip any verifier candidate that resolves inside the bundle"
    )


@pytest.mark.parametrize("script", BUILD_SCRIPTS)
def test_build_script_fails_closed_without_out_of_bundle_verifier(script: str) -> None:
    """With no out-of-bundle verifier the build must refuse (the error text
    must say an in-bundle verifier is never trusted, so the operator is not
    steered toward the unsafe fallback)."""
    text = (_project_root() / script).read_text(encoding="utf-8")
    assert "never trusted" in text, "fail message must name the invariant"
    assert "die " in text, "absence of the trusted verifier must abort the build"
