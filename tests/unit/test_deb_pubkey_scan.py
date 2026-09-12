"""Trust-invariant 2: the .deb builder's staged-root pubkey scan.

Completeness-gap fix (round 1): build_deb.sh's invariant-2 scan only matched
``*.pub`` / ``*.pub.pem`` / ``release.pub*``, so a stray key file named e.g.
``key.pem`` (or ANY ``*.pem``, including a PRIVATE key) or ``*pubkey*`` in the
bundle / trusted-tools payload was silently packaged into the .deb, while the
.pkg and .msi builders refuse to build. These tests pin the .deb scan to the
same name-based pattern set as build_msi.sh's ``find_pubkey_material`` (plus
``*.key``, which the deb gate's in-container payload scan also checks), and
prove the pattern functionally.

The builder script itself is parsed (not executed): these tests must run
docker-free and offline like the rest of the unit suite.
"""

import fnmatch
import re
import subprocess
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[2]
BUILD_DEB = PROJECT / "scripts" / "package" / "build_deb.sh"
BUILD_MSI = PROJECT / "scripts" / "package" / "build_msi.sh"
BUILD_PKG = PROJECT / "scripts" / "package" / "build_pkg.sh"
DEB_GATE = PROJECT / "scripts" / "package" / "test_package_deb.sh"

# The pattern set every builder's staged-root scan must cover at minimum.
REQUIRED_PATTERNS = {
    "*.pub",
    "*.pub.pem",
    "*.pem",
    "release.pub*",
    "*pubkey*",
}


def _find_pubkey_material_patterns(script: Path) -> set[str]:
    """Extract the ``-name`` patterns from a builder's key-material scan.

    Matches every ``-name '...'`` / ``-name "..."`` inside the file; for
    build_deb.sh and build_msi.sh the only such finds are inside (or invoked
    through) ``find_pubkey_material`` / the invariant-2 scan.
    """
    code = script.read_text(encoding="utf-8")
    return {m[0] or m[1] for m in re.findall(r"-name\s+'([^']+)'|-name\s+\"([^\"]+)\"", code)}


def _scan_matches(patterns: set[str], name: str) -> bool:
    # find -name matches the basename with glob semantics (fnmatch).
    return any(fnmatch.fnmatchcase(name, pat) for pat in patterns)


def test_deb_scan_covers_the_required_pattern_set() -> None:
    patterns = _find_pubkey_material_patterns(BUILD_DEB)
    missing = REQUIRED_PATTERNS - patterns
    assert not missing, (
        "build_deb.sh's staged-root scan is missing key-material name patterns "
        f"{sorted(missing)} — a stray {sorted(missing)[0]} file would be "
        "silently packaged into the .deb (the .pkg/.msi builders refuse it)"
    )


def test_deb_scan_covers_key_extension_too() -> None:
    # Strictly stronger than build_msi.sh: '*.key' is also matched (the deb
    # gate's own in-container no_keys_in_package scan checks it as well).
    patterns = _find_pubkey_material_patterns(BUILD_DEB)
    assert "*.key" in patterns, "build_deb.sh scan must also match '*.key'"


def test_deb_scan_is_never_weaker_than_pkg_and_msi_builders() -> None:
    deb = _find_pubkey_material_patterns(BUILD_DEB)
    for other in (BUILD_PKG, BUILD_MSI):
        other_patterns = _find_pubkey_material_patterns(other)
        weaker = other_patterns - deb
        assert not weaker, (
            f"build_deb.sh scan is missing patterns {sorted(weaker)} that "
            f"{other.name} matches — the .deb must be at least as strict"
        )


def test_deb_builder_uses_the_scan_on_the_staged_root_and_fails_closed() -> None:
    code = BUILD_DEB.read_text(encoding="utf-8")
    # The scan must gate the staged deb root itself...
    assert re.search(r'find_pubkey_material\s+"\$DEBROOT"', code), (
        "build_deb.sh must run find_pubkey_material against the staged $DEBROOT"
    )
    # ...and must abort the build with the canonical fail-closed diagnostic.
    assert "public key material found in staged deb root" in code, (
        "build_deb.sh must die with the canonical staged-root diagnostic"
    )


def test_deb_scan_patterns_functionally_match_stray_key_files(tmp_path: Path) -> None:
    """The extracted pattern set catches every stray key-material name the
    completeness critic demonstrated (previously x.pem slipped through)."""
    patterns = _find_pubkey_material_patterns(BUILD_DEB)
    must_match = [
        "x.pem",
        "key.pem",
        "private-key.pem",  # even a PRIVATE key must abort the build
        "release_pub.pem",
        "udbmcp.pub",
        "release.pub.pem",
        "release.pub.bak",
        "release.udbmcp.pubkey",
        "my-pubkey.txt",
        "pubkeys.md",  # '*pubkey*' substring-matches; over-matching fails closed
        "server.key",
    ]
    must_not_match = [
        "manifest.json",
        "config.yaml",
        "universal-db-mcp.service",
        "install_offline.sh",
        "publickey.md",  # contains 'publickey', not the 'pubkey' substring
    ]
    for name in must_match:
        assert _scan_matches(patterns, name), f"{name} must be caught by the deb scan"
    for name in must_not_match:
        assert not _scan_matches(patterns, name), f"{name} is not key material"


def _extract_shell_function(script: Path, name: str) -> str:
    """Pull a ``name() { ... }`` definition verbatim out of a bash script."""
    code = script.read_text(encoding="utf-8")
    match = re.search(rf"^{name}\(\) \{{\n.*?^\}}$", code, re.S | re.M)
    assert match, f"function {name}() not found in {script.name}"
    return match.group(0)


def test_deb_scan_function_does_not_match_the_root_directory(tmp_path: Path) -> None:
    """Regression: the invariant check once passed ``-print -quit`` through
    find_pubkey_material, which placed it BEFORE the -type f expression (the
    function prefixes its path arguments) — BSD/GNU find then matched the
    staged root DIRECTORY itself and every .deb build failed closed on a
    false positive. Run the real function via bash: an empty tree must match
    nothing, a nested x.pem must be the only match."""
    fn = _extract_shell_function(BUILD_DEB, "find_pubkey_material")

    def run_scan(root: Path) -> str:
        proc = subprocess.run(
            ["bash", "-c", f"{fn}\nfind_pubkey_material \"$1\"", "bash", str(root)],
            capture_output=True, text=True, timeout=60,
        )
        assert proc.returncode == 0, proc.stderr
        return proc.stdout

    assert run_scan(tmp_path) == "", "empty staged root must not match"
    poisoned = tmp_path / "usr" / "share" / "trusted-tools"
    poisoned.mkdir(parents=True)
    (poisoned / "x.pem").write_text("dummy\n", encoding="utf-8")
    out = run_scan(tmp_path)
    assert "x.pem" in out and out.strip().endswith("x.pem"), (
        f"scan must match only the nested x.pem, got: {out!r}"
    )


def test_deb_invariant_check_passes_no_find_predicates_through() -> None:
    """The scan call sites must not append find predicates (e.g. -print -quit):
    find_pubkey_material interpolates its arguments as PATHS before the
    -type f expression, so any predicate would be evaluated first and match
    the staged root directory itself."""
    code = BUILD_DEB.read_text(encoding="utf-8")
    for call in re.findall(r"find_pubkey_material\s+\"\$DEBROOT\"[^\n|]*", code):
        assert "-print" not in call and "-quit" not in call, (
            f"do not pass find predicates through find_pubkey_material: {call!r}"
        )


def test_deb_gate_asserts_the_builder_rejects_poisoned_staged_roots() -> None:
    """The deb gate must exercise the build-time negative case end to end."""
    code = DEB_GATE.read_text(encoding="utf-8")
    assert "build_rejects_key_material" in code, (
        "test_package_deb.sh must record a build_rejects_key_material check: "
        "a staged root containing a dummy x.pem must fail build_deb.sh"
    )
    assert "x.pem" in code and "public key material found in staged deb root" in code
