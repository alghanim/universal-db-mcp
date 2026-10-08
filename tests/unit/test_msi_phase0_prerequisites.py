"""Regression tests for the plan-Phase-0 prerequisite gate of
scripts/package/build_msi.sh (artifact: msi:build_script, Phase 0 gate).

Background (completeness-critic round 1): build_msi.sh was delivered but was
NEVER executed on this staging host because the Phase 0 prerequisites
(.NET 8 SDK + the global ``wix`` tool) were never installed here. Its
prerequisite gate — the very first fail-closed checkpoint of the MSI build —
was therefore never exercised end-to-end either. These tests pin that gate's
contract WITHOUT requiring dotnet/wix on the host (they run the script under
a scrubbed PATH and, where one side of the gate must pass, a stub binary):

  * with NEITHER dotnet NOR wix on PATH, the build must abort (fail closed)
    BEFORE touching the bundle: nonzero exit, a diagnostic naming each
    missing tool, the exact Phase 0 install commands (including
    ``dotnet tool install --global wix``), and NO artifact in the output dir;
  * with only ONE of the two present (stubbed), the gate must still abort,
    naming only the genuinely missing tool;
  * the gate must fire even when every later input would have been valid
    (a well-formed signed bundle + pubkey): prerequisites are checked before
    any staging, so no temp state or output is produced.

Trust invariants asserted here (NEVER break):
  * no artifact is produced when the staging host lacks the verified
    toolchain (fail closed on every missing prerequisite);
  * the bundle is not staged, modified, or executed by the prerequisite gate
    (the bundle directory is byte-identical after the failed run).

These tests are POSIX-only (build_msi.sh is the macOS/Linux staging-host
bash script) and are hermetic: they never require dotnet, wix, or network.

Ownership note: the happy-path/fail-closed-verification behavior of
build_msi.sh is pinned in tests/unit/test_msi_build_script.py; this file
owns ONLY the Phase 0 prerequisite gate. The producer file under test is
scripts/package/build_msi.sh.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="build_msi.sh is the macOS/Linux staging-host bash script (plan Phase 0)",
)

REPO_ROOT = Path(__file__).resolve().parents[2]
BUILD_MSI = REPO_ROOT / "scripts" / "package" / "build_msi.sh"
WXS = REPO_ROOT / "packaging" / "msi" / "udbmcp.wxs"
WIX_NS = "http://wixtoolset.org/schemas/v4/wxs"

# The tools a staging host's PATH gives the script, minus the two the gate
# looks for. /usr/bin:/bin alone is not enough: a host may install dotnet there
# (GitHub's ubuntu-24.04 runner links /usr/bin/dotnet), so the PATH is a
# directory of links to every other tool in them.
GATED_TOOLS = frozenset({"dotnet", "wix"})


def _scrubbed_path(root: Path) -> str:
    scrubbed = root / "scrubbed-bin"
    if not scrubbed.is_dir():
        scrubbed.mkdir()
        for directory in (Path("/usr/bin"), Path("/bin")):
            for tool in directory.iterdir():
                link = scrubbed / tool.name
                if tool.name not in GATED_TOOLS and not link.exists() and not link.is_symlink():
                    link.symlink_to(tool)
    return str(scrubbed)


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def _make_signed_bundle(root: Path) -> tuple[Path, Path]:
    """A minimal well-formed SIGNED windows-x86_64 bundle + its sibling
    trusted-tools/ copy (stub verifier + admin pubkey). Every LATER build
    step would succeed against this input — only the Phase 0 toolchain gate
    can stop the run, which is exactly what these tests pin."""
    bundle = root / "bundle"
    (bundle / "config-templates").mkdir(parents=True)
    (bundle / "manifest.json").write_text(
        '{"release": "0.1.0", "target": {"os": "windows", "arch": "x86_64", "python": "cp312"}}\n',
        encoding="utf-8",
    )
    (bundle / "SIGNATURE").write_text("signature\n", encoding="utf-8")
    (bundle / "SHA256SUMS").write_text("sums\n", encoding="utf-8")
    (bundle / "config-templates" / "config.template.yaml").write_text(
        "template: true\n", encoding="utf-8"
    )

    trusted = root / "trusted-tools"
    trusted.mkdir()
    (trusted / "verify_bundle.py").write_text(
        "import sys\n"
        "args = sys.argv[1:]\n"
        'assert "--bundle" in args and "--pubkey" in args, args\n'
        'print("bundle verification PASSED")\n',
        encoding="utf-8",
    )
    pubkey = trusted / "release.pub.pem"
    pubkey.write_text(
        "-----BEGIN PUBLIC KEY-----\nTESTONLY\n-----END PUBLIC KEY-----\n", encoding="utf-8"
    )
    return bundle, pubkey


def _write_stub(stub_dir: Path, name: str) -> None:
    """A no-op stub binary so exactly one side of the gate passes."""
    stub_dir.mkdir(parents=True, exist_ok=True)
    exe = stub_dir / name
    exe.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    exe.chmod(0o755)


def _run_build(bundle: Path, pubkey: Path, out_dir: Path, stub: str | None = None):
    scrubbed_path = _scrubbed_path(out_dir.parent)
    env = {**os.environ, "PATH": scrubbed_path}
    if stub is not None:
        # one dedicated stub dir per case: a shared dir would let one case's
        # stub satisfy the OTHER prerequisite of a later case
        stub_dir = out_dir.parent / f"stubbin-{stub}"
        _write_stub(stub_dir, stub)
        env["PATH"] = f"{stub_dir}{os.pathsep}{scrubbed_path}"
    return subprocess.run(  # noqa: S603 - fixed args, tmp_path sandbox
        ["/bin/bash", str(BUILD_MSI), str(bundle), "--pubkey", str(pubkey), "--out", str(out_dir)],
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
    )


# --------------------------------------------------------------------------
# the gate
# --------------------------------------------------------------------------


def test_phase0_gate_aborts_when_dotnet_and_wix_are_missing(tmp_path: Path) -> None:
    """With neither dotnet nor wix on PATH, build_msi.sh fails closed before
    producing anything, names BOTH missing tools, and prints the exact
    Phase 0 install commands (including the wix global-tool install)."""
    bundle, pubkey = _make_signed_bundle(tmp_path)
    out_dir = tmp_path / "dist"

    proc = _run_build(bundle, pubkey, out_dir)
    out = proc.stdout + proc.stderr

    assert proc.returncode != 0, (
        "build_msi.sh must abort on a staging host without the Phase 0 "
        f"prerequisites, but it exited 0:\n{proc.stdout}"
    )
    assert "dotnet not found" in out, f"the diagnostic must name the missing dotnet SDK:\n{out}"
    assert "wix not found" in out, f"the diagnostic must name the missing wix tool:\n{out}"
    assert "dotnet tool install --global wix" in out, (
        f"the diagnostic must carry the exact Phase 0 wix install command:\n{out}"
    )
    assert ".NET 8 SDK" in out, (
        f"the diagnostic must name the .NET 8 SDK (plan Phase 0 prerequisite):\n{out}"
    )
    assert "ABORTED" in out, f"the refusal must state the build was aborted (fail closed):\n{out}"
    assert list(out_dir.glob("*.msi")) == [], "no artifact may exist after a refused build"


def test_phase0_gate_names_only_the_genuinely_missing_tool(tmp_path: Path) -> None:
    """Each prerequisite is fail-closed on its own: with only a stub wix (no
    dotnet) the gate still aborts naming dotnet; with only a stub dotnet (no
    wix) it still aborts naming wix."""
    bundle, pubkey = _make_signed_bundle(tmp_path)

    dotnet_only = tmp_path / "dist-dotnet-only"
    proc = _run_build(bundle, pubkey, dotnet_only, stub="wix")
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0, "a stub wix must not satisfy the dotnet prerequisite"
    assert "dotnet not found" in out, f"must name the missing dotnet SDK:\n{out}"
    assert "wix not found" not in out, f"must not falsely claim wix is missing:\n{out}"
    assert list(dotnet_only.glob("*.msi")) == [], "no artifact after a refused build"

    wix_only = tmp_path / "dist-wix-only"
    proc = _run_build(bundle, pubkey, wix_only, stub="dotnet")
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0, "a stub dotnet must not satisfy the wix prerequisite"
    assert "wix not found" in out, f"must name the missing wix tool:\n{out}"
    assert "dotnet not found" not in out, f"must not falsely claim dotnet is missing:\n{out}"
    assert list(wix_only.glob("*.msi")) == [], "no artifact after a refused build"


def test_phase0_gate_fires_before_the_bundle_is_touched(tmp_path: Path) -> None:
    """The prerequisite gate runs BEFORE staging/verification: a refused run
    must leave the signed bundle byte-identical (nothing staged, modified, or
    executed) and must not even reach the manifest/trusted-channel steps."""
    bundle, pubkey = _make_signed_bundle(tmp_path)
    before = {
        p.relative_to(bundle): p.read_bytes()
        for p in sorted(bundle.rglob("*"))
        if p.is_file()
    }

    out_dir = tmp_path / "dist"
    proc = _run_build(bundle, pubkey, out_dir)
    out = proc.stdout + proc.stderr

    assert proc.returncode != 0, "the Phase 0 gate must abort the build"
    after = {
        p.relative_to(bundle): p.read_bytes()
        for p in sorted(bundle.rglob("*"))
        if p.is_file()
    }
    assert after == before, "the refused build must not modify the signed bundle"

    # the gate fires before the trusted-channel verification and the manifest
    # are even reached: no verification output, no target diagnostics
    assert "bundle verification" not in out, (
        f"the prerequisite gate must fire BEFORE bundle verification:\n{out}"
    )
    assert list(out_dir.glob("*.msi")) == [], "no artifact after a refused build"


# --------------------------------------------------------------------------
# wxs authoring defects found by the FIRST real `wix build` run (this host,
# Phase 0 toolchain actually installed): the v3-era constructs below are
# rejected by every WiX v4+ compiler and must never regress.
# --------------------------------------------------------------------------


def _wxs_root() -> ET.Element:
    # first-party static repo file with no DTD/entities (defusedxml is not a
    # project dependency — see the module note in test_msi_packaging.py)
    return ET.fromstring(WXS.read_text(encoding="utf-8"))  # noqa: S314


def _iter_local(root: ET.Element, name: str) -> list[ET.Element]:
    return [el for el in root.iter() if el.tag.rsplit("}", 1)[-1] == name]


def test_wxs_registrysearch_uses_wix4_bitness_not_win64() -> None:
    """WiX error WIX0004: RegistrySearch has no Win64 attribute in WiX v4+;
    the 64-bit registry view is selected with Bitness="always64"."""
    code = WXS.read_text(encoding="utf-8")
    for search in _iter_local(_wxs_root(), "RegistrySearch"):
        assert "Win64" not in search.attrib, (
            "RegistrySearch/@Win64 is a WiX v3 attribute (WIX0004); use Bitness=\"always64\""
        )
    assert re.search(r"<RegistrySearch[^>]*Bitness=\"always64\"", code, re.DOTALL), (
        "the per-machine CPython 3.12 registry probe must read the 64-bit view "
        "(RegistrySearch Bitness=\"always64\")"
    )


def test_wxs_uses_launch_not_launchcondition() -> None:
    """WiX error WIX0005: <Package> has no <LaunchCondition> child in WiX v4+;
    the rename is <Launch Condition=... Message=... /> (still a direct child
    of Package, so the prerequisite is still enforced at install time)."""
    root = _wxs_root()
    assert not _iter_local(root, "LaunchCondition"), (
        "LaunchCondition is a WiX v3 element (WIX0005); use <Launch>"
    )
    launches = [el for el in _iter_local(root, "Launch") if "CPYTHON312" in (el.get("Condition") or "")]
    assert len(launches) == 1, "exactly one Launch holds the CPython prerequisite"
    launch = launches[0]
    assert launch.get("Condition") == "Installed OR CPYTHON312", (
        "the Launch condition must keep the Installed-OR short circuit so "
        "uninstall/repair work even if Python was later removed"
    )
    # the others refuse a UDBMCP_ALLOW_DOWNGRADE value other than 1, either
    # property from anyone but an administrator, and an account value that
    # would break out of its quotes on the custom actions' command lines
    others = [el.get("Condition") for el in _iter_local(root, "Launch") if el is not launch]
    assert others == [
        'NOT UDBMCP_ALLOW_DOWNGRADE OR UDBMCP_ALLOW_DOWNGRADE="1"',
        "AdminUser OR NOT (UDBMCP_SERVICE_ACCOUNT OR UDBMCP_ALLOW_DOWNGRADE)",
        'NOT (UDBMCP_SERVICE_ACCOUNT >< UdbmcpQuoteChar OR UDBMCP_SERVICE_ACCOUNT >> "\\")',
        "NOT (INSTALLFOLDER >< \"'\")",
    ], others
    for el in _iter_local(root, "Launch"):
        assert el.get("Message"), "a Launch refusal must carry a remediation message"


def test_wxs_uses_common_app_data_standard_directory() -> None:
    """WiX error WIX0021: StandardDirectory/@Id only accepts MSI standard
    directory names — C:\\ProgramData is CommonAppDataFolder (there is no
    'ProgramDataFolder')."""
    code = WXS.read_text(encoding="utf-8")
    assert 'StandardDirectory Id="ProgramDataFolder"' not in code, (
        "StandardDirectory Id=ProgramDataFolder is not a legal MSI standard "
        "directory (WIX0021); use CommonAppDataFolder"
    )
    assert 'StandardDirectory Id="CommonAppDataFolder"' in code, (
        "the machine-wide config must be authored under CommonAppDataFolder "
        "(C:\\ProgramData)"
    )


def test_wxs_document_element_and_namespace_are_wix4() -> None:
    """The authoring compiles only as a WiX v4-namespace document; the
    harvest include contract is pinned in test_msi_build_script.py."""
    root = _wxs_root()
    assert root.tag == f"{{{WIX_NS}}}Wix", f"unexpected wxs document element: {root.tag}"
