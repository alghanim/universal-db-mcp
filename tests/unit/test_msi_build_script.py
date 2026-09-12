"""Regression tests for scripts/package/build_msi.sh (artifact: msi:build_script).

Two confirmed defects are pinned here:

1. BUILD MUST WORK WITH THE REAL WIX v4+ TOOLCHAIN: ``heat`` is NOT a command
   of the WiX v4+ ``wix`` CLI (that CLI implements only ``build`` and ``eula``,
   and no heat extension ships with it — heat was split into the separate,
   deprecated WixToolset.Heat package). The script therefore harvests the
   staged signed bundle with a BUILT-IN heat-equivalent fragment generator
   (ComponentGroup Id="HarvestedBundleComponents" under
   DirectoryRef Id="BundleDir", File/@Source via -define BundleSourceDir).
   The tests run the script END-TO-END against a stub toolchain (no dotnet or
   wix needed) and validate the generated fragment structurally.

2. THE MSI MUST ACTUALLY WIRE THE DEFERRED CUSTOM ACTIONS: udbmcp.wxs ships
   the packaging/msi/custom/*.ps1 scripts into INSTALLFOLDER\\scripts and
   schedules them as deferred, impersonate=no, Return="check" custom actions
   in the required trust order (trusted verify_bundle.py verification BEFORE
   the venv build BEFORE the doctor smoke BEFORE the service registration;
   uninstall mirror before RemoveFiles; a rollback twin for the non-
   transactional sc.exe state). build_msi.sh stages those scripts and passes
   -define CustomActionScriptsDir.

Trust invariants asserted here (NEVER break):
  * the build verifies the source bundle via the trusted-channel verifier
    BEFORE staging anything, and refuses unsigned bundles (fail closed);
  * the release public key is NEVER shipped inside the package: the payload
    and the staged custom action scripts are both scanned, and the wxs must
    not embed or reference any key path;
  * every verification/build failure exits nonzero and produces NO artifact;
  * nothing in the bundle is executed on the staging host.

Ownership note: these are the build-script artifact's own tests; the producer
files under test are scripts/package/build_msi.sh and packaging/msi/udbmcp.wxs
(the custom/*.ps1 implementations have their own gates in
tests/unit/test_msi_packaging.py and are only referenced structurally here).

The tests are POSIX-only (build_msi.sh is the staging-host bash script; the
staging host is macOS/Linux by plan Phase 0) and need nothing but /bin/bash,
python3 and the repo checkout.
"""

from __future__ import annotations

import os
import re
import shutil
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
CUSTOM_DIR = REPO_ROOT / "packaging" / "msi" / "custom"

WIX_NS = "http://wixtoolset.org/schemas/v4/wxs"
CUSTOM_ACTION_SCRIPTS = ("verify.ps1", "venv.ps1", "doctor.ps1", "service.ps1", "uninstall.ps1")
MSI_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"  # OLE2 compound document
_XML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def _require(path: Path) -> Path:
    assert path.exists(), f"expected producer file to exist: {path}"
    return path


def _script_code() -> str:
    """build_msi.sh with comments stripped, so prose cannot satisfy or defeat
    a gate."""
    return _XML_COMMENT.sub("", _require(BUILD_MSI).read_text(encoding="utf-8"))


def _wxs_code() -> str:
    """udbmcp.wxs with XML comments stripped."""
    return _XML_COMMENT.sub("", _require(WXS).read_text(encoding="utf-8"))


def _wxs_root() -> ET.Element:
    return ET.fromstring(_wxs_code())  # noqa: S314 - first-party repo file, no DTD/entities


def _localname(el: ET.Element) -> str:
    return el.tag.rsplit("}", 1)[-1]


def _iter_local(root: ET.Element, name: str) -> list[ET.Element]:
    return [el for el in root.iter() if _localname(el) == name]


def _write_stub_toolchain(stub_dir: Path, wix_fails: bool = False) -> None:
    """A fake dotnet + wix CLI: records the wix invocation, captures the
    staged build products (harvest.wxi, udbmcp.wxs, custom/), and emits a
    fake MSI with the OLE compound-document magic."""
    stub_dir.mkdir(parents=True, exist_ok=True)
    (stub_dir / "dotnet").write_text("#!/bin/bash\nexit 0\n", encoding="utf-8")
    if wix_fails:
        wix_body = '#!/bin/bash\necho "stub wix: compile error" >&2\nexit 1\n'
    else:
        wix_body = """#!/bin/bash
# Stub WiX v4+ CLI: parse -out / -define, capture staged products, fake MSI.
set -euo pipefail
cap="${UDBMCP_MSI_TEST_CAPTURE:-}"
if [ -n "$cap" ]; then printf '%s\\n' "$@" > "$cap/wix-args.txt"; fi
out=""; bundle_dir=""
prev=""
for a in "$@"; do
  case "$prev" in
    -out) out="$a" ;;
    -define) case "$a" in BundleSourceDir=*) bundle_dir="${a#BundleSourceDir=}" ;; esac ;;
  esac
  prev="$a"
done
[ -n "$out" ] || { echo "stub wix: no -out argument" >&2; exit 1; }
if [ -n "$cap" ] && [ -n "$bundle_dir" ]; then
  stage="$(dirname "$bundle_dir")"
  cp "$stage/harvest.wxi" "$cap/harvest.wxi"
  cp "$stage/udbmcp.wxs" "$cap/udbmcp.wxs"
  if [ -d "$stage/custom" ]; then cp -a "$stage/custom" "$cap/custom"; fi
fi
printf '\\320\\317\\021\\340\\241\\261\\032\\341' > "$out"
dd if=/dev/zero bs=1024 count=4 >> "$out" 2>/dev/null
exit 0
"""
    wix = stub_dir / "wix"
    wix.write_text(wix_body, encoding="utf-8")
    for exe in (stub_dir / "dotnet", wix):
        exe.chmod(0o755)


def _make_signed_bundle(root: Path) -> tuple[Path, Path]:
    """A minimal but well-formed SIGNED windows-x86_64 bundle (release
    1.2.3) plus its sibling trusted-tools/ copy (stub verifier + admin
    pubkey, distributed on the trusted channel OUTSIDE the bundle)."""
    bundle = root / "bundle"
    for sub in ("wheelhouse", "config-templates", "requirements", "installers"):
        (bundle / sub).mkdir(parents=True)
    (bundle / "manifest.json").write_text(
        '{"release": "1.2.3", "target": {"os": "windows", "arch": "x86_64", "python": "cp312"}}\n',
        encoding="utf-8",
    )
    (bundle / "SIGNATURE").write_text("signature\n", encoding="utf-8")
    (bundle / "SHA256SUMS").write_text("sums\n", encoding="utf-8")
    (bundle / "config-templates" / "config.template.yaml").write_text(
        "template: true\n", encoding="utf-8"
    )
    (bundle / "requirements" / "runtime.lock").write_text("lock\n", encoding="utf-8")
    (bundle / "wheelhouse" / "mcp-1.9.0-py3-none-any.whl").write_bytes(b"\x50\x4b\x03\x04" + b"w" * 64)
    (bundle / "wheelhouse" / "pyodbc-5.1.0-cp312-cp312-win_amd64.whl").write_bytes(b"\x50\x4b\x03\x04" + b"p" * 64)
    (bundle / "installers" / "verify_bundle.py").write_text("# reference copy\n", encoding="utf-8")

    trusted = root / "trusted-tools"
    trusted.mkdir()
    (trusted / "verify_bundle.py").write_text(
        "import sys\n"
        'args = sys.argv[1:]\n'
        'assert "--bundle" in args and "--pubkey" in args, args\n'
        'print("bundle verification PASSED")\n',
        encoding="utf-8",
    )
    pubkey = trusted / "release.pub.pem"
    pubkey.write_text("-----BEGIN PUBLIC KEY-----\nTESTONLY\n-----END PUBLIC KEY-----\n", encoding="utf-8")
    return bundle, pubkey


def _run_build(
    bundle: Path, pubkey: Path, out_dir: Path, capture: Path | None = None, wix_fails: bool = False
) -> subprocess.CompletedProcess[str]:
    stub_dir = out_dir.parent / ("stubbin-fail" if wix_fails else "stubbin")
    _write_stub_toolchain(stub_dir, wix_fails=wix_fails)
    env = {**os.environ, "PATH": f"{stub_dir}{os.pathsep}{os.environ.get('PATH', '')}"}
    if capture is not None:
        capture.mkdir(parents=True, exist_ok=True)
        env["UDBMCP_MSI_TEST_CAPTURE"] = str(capture)
    return subprocess.run(  # noqa: S603 - fixed args, tmp_path sandbox
        ["/bin/bash", str(BUILD_MSI), str(bundle), "--pubkey", str(pubkey), "--out", str(out_dir)],
        capture_output=True,
        text=True,
        timeout=300,
        env=env,
    )


def _payload_relpaths(bundle: Path) -> set[str]:
    return {
        p.relative_to(bundle).as_posix()
        for p in bundle.rglob("*")
        if p.is_file() and not p.is_symlink()
    }


@pytest.fixture()
def build_env(tmp_path: Path) -> dict[str, Path]:
    bundle, pubkey = _make_signed_bundle(tmp_path)
    return {
        "root": tmp_path,
        "bundle": bundle,
        "pubkey": pubkey,
        "capture": tmp_path / "capture",
        "dist": tmp_path / "dist",
    }


# --------------------------------------------------------------------------
# the toolchain defect: no `wix heat`, harvest is built in
# --------------------------------------------------------------------------


def test_build_msi_never_invokes_wix_heat() -> None:
    """`heat` is not a command of the WiX v4+ `wix` CLI (only `build` and
    `eula` are built in; heat lives in the separate, deprecated
    WixToolset.Heat package). The script must not call `wix heat` — the
    harvest is generated by the built-in fragment generator instead."""
    code = _script_code()
    assert "wix heat" not in code, (
        "build_msi.sh still invokes `wix heat`, which fails on every provisioned "
        "staging host (heat is not a WiX v4+ wix command); use the built-in harvester"
    )
    assert "heat dir" not in code, "no heat invocation may remain in build_msi.sh code"
    # and the built-in harvester is actually what produces the fragment
    assert "harvest.py" in code, "the built-in WiX v4-native harvest generator is missing"
    assert re.search(r'python3\s+"\$HARVESTER"', code), (
        "build_msi.sh must run the built-in harvest generator to produce harvest.wxi"
    )


def test_wxs_does_not_document_heat_as_the_harvest_tool() -> None:
    """The authoring must not tell a future maintainer to run `wix heat`."""
    raw = _require(WXS).read_text(encoding="utf-8")
    assert "wix heat" not in raw and "heat dir" not in raw, (
        "udbmcp.wxs still documents `heat` as the harvest mechanism"
    )
    assert "not part of the WiX v4+" in raw, (
        "the wxs must explain that heat is not a WiX v4+ wix CLI command"
    )


def test_build_msi_happy_path_produces_msi_and_heat_equivalent_fragment(
    build_env: dict[str, Path],
) -> None:
    """FUNCTIONAL (stub toolchain): the build succeeds, produces the MSI with
    the OLE compound-document magic, and the generated harvest.wxi is the
    exact heat-equivalent authoring the .wxs include expects: a Fragment with
    DirectoryRef Id="BundleDir" containing one component per payload file and
    ComponentGroup Id="HarvestedBundleComponents" referencing them all."""
    env = build_env
    proc = _run_build(env["bundle"], env["pubkey"], env["dist"], capture=env["capture"])
    assert proc.returncode == 0, f"build_msi.sh failed on a signed bundle:\n{proc.stdout}\n{proc.stderr}"

    msi = env["dist"] / "universal-db-mcp-1.2.3-win-x86_64.msi"
    assert msi.is_file() and msi.stat().st_size > 0, "no MSI artifact was produced"
    with msi.open("rb") as fh:
        assert fh.read(8) == MSI_MAGIC, "the artifact is not an OLE compound document"

    # the harvest fragment is the heat-equivalent authoring; a .wxi
    # preprocessor include MUST use <Include> as its document element
    # (WiX error WIX0048), carrying the WiX v4 namespace, with the
    # heat-equivalent Fragment spliced at the <?include?> site
    harvest = env["capture"] / "harvest.wxi"
    assert harvest.is_file(), "the build did not generate harvest.wxi (stub wix captured nothing)"
    root = ET.parse(harvest).getroot()  # noqa: S314 - generated build product
    assert root.tag == f"{{{WIX_NS}}}Include", (
        f"a .wxi include must use <Include> as its document element, got: {root.tag}"
    )
    fragments = [el for el in root if _localname(el) == "Fragment"]
    assert len(fragments) == 1, "the wxi must contain exactly one Fragment"
    dir_refs = [el for el in fragments[0] if _localname(el) == "DirectoryRef"]
    assert [el.get("Id") for el in dir_refs] == ["BundleDir"], (
        "payload components must land directly under DirectoryRef Id=BundleDir (heat -srd shape)"
    )

    # components live both directly under the root DirectoryRef and under the
    # nested per-subdirectory Directory elements (the heat dir shape)
    comps = {el.get("Id"): el for el in dir_refs[0].iter() if _localname(el) == "Component"}
    expected = _payload_relpaths(env["bundle"])
    assert len(comps) == len(expected), (
        f"expected one component per payload file ({len(expected)}), got {len(comps)}"
    )
    seen_files: set[str] = set()
    for comp in comps.values():
        assert comp.get("Guid") == "*", "heat-style components use auto-generated stable GUIDs"
        files = [el for el in comp if _localname(el) == "File"]
        assert len(files) == 1 and files[0].get("KeyPath") == "yes", (
            "each payload component is a single-file component with that file as KeyPath"
        )
        f = files[0]
        src = f.get("Source") or ""
        assert src.startswith("$(var.BundleSourceDir)/"), (
            f"File/@Source must resolve via the BundleSourceDir variable, got {src!r}"
        )
        seen_files.add(src.removeprefix("$(var.BundleSourceDir)/"))
    assert seen_files == expected, (
        f"harvest must package exactly the signed payload; missing={expected - seen_files}, "
        f"extra={seen_files - expected}"
    )

    group = _iter_local(root, "ComponentGroup")
    assert [el.get("Id") for el in group] == ["HarvestedBundleComponents"], (
        "the wxi must define ComponentGroup Id=HarvestedBundleComponents"
    )
    refs = [el.get("Id") for el in group[0] if _localname(el) == "ComponentRef"]
    assert sorted(refs) == sorted(comps), "every harvested component must be referenced by the group"

    # the staged custom action scripts reached the compile step unchanged
    args = (env["capture"] / "wix-args.txt").read_text(encoding="utf-8")
    assert "-define" in args and "CustomActionScriptsDir=" in args, (
        "wix build must receive -define CustomActionScriptsDir for the deferred actions"
    )
    # step 4 of the script: the SIGNED manifest release is substituted into
    # the .wxs preprocessor variables. If -define ProductVersion is dropped
    # or broken, udbmcp.wxs silently falls back to its <?ifndef> default
    # (0.1.0) and still compiles — corrupting MajorUpgrade/upgrade detection
    # while every other gate stays green.
    assert "ProductVersion=1.2.3" in args, (
        "wix build must receive -define ProductVersion=<signed manifest release> "
        "(1.2.3 here); the wxs <?ifndef ProductVersion> fallback would otherwise "
        "ship 0.1.0 and break MajorUpgrade"
    )
    staged = env["capture"] / "custom"
    assert staged.is_dir(), "the custom action scripts were not staged for the compile"
    for name in CUSTOM_ACTION_SCRIPTS:
        shipped = staged / name
        assert shipped.is_file(), f"custom action script {name} was not staged"
        assert shipped.read_bytes() == (CUSTOM_DIR / name).read_bytes(), (
            f"staged {name} differs from the reviewed packaging/msi/custom/{name}"
        )


def test_harvest_is_deterministic(build_env: dict[str, Path]) -> None:
    """Two builds of the same signed bundle must produce byte-identical
    harvest authoring (stable auto component GUIDs across rebuilds)."""
    env = build_env
    first, second = env["capture"] / "a", env["capture"] / "b"
    for cap in (first, second):
        proc = _run_build(env["bundle"], env["pubkey"], env["dist"], capture=cap)
        assert proc.returncode == 0, f"build failed:\n{proc.stderr}"
    assert (first / "harvest.wxi").read_bytes() == (second / "harvest.wxi").read_bytes(), (
        "the harvest fragment is not deterministic; component GUIDs would churn on every rebuild"
    )


# --------------------------------------------------------------------------
# fail-closed behavior
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "mutate, reason",
    [
        ("unsigned", "no SIGNATURE file: the bundle is unsigned"),
        ("wrong-target", "manifest target is not windows/x86_64"),
        ("pubkey-in-payload", "public key material in the staged payload"),
        ("symlink-in-payload", "non-regular file in the staged payload"),
    ],
)
def test_build_msi_fails_closed(
    build_env: dict[str, Path], mutate: str, reason: str, tmp_path_factory: pytest.TempPathFactory
) -> None:
    """Every verification/harvest failure aborts the build with a nonzero
    exit, a diagnostic, and NO MSI artifact."""
    env = build_env
    work = tmp_path_factory.mktemp("msi-neg")
    bundle = work / "bundle"
    shutil.copytree(env["bundle"], bundle, symlinks=True)
    # build_msi.sh resolves the trusted verifier OUTSIDE the bundle (sibling
    # trusted-tools/ or $UDBMCP_TRUST_DIR) and dies BEFORE staging when it is
    # absent. Copy the sibling so the payload mutations below actually reach
    # the gates they pin (the staged-payload pubkey scan and the harvester's
    # non-regular-file check) instead of failing earlier on the verifier
    # lookup — otherwise these two fail-closed gates would be untested.
    shutil.copytree(env["root"] / "trusted-tools", work / "trusted-tools")
    pubkey = work / "release.pub.pem"
    pubkey.write_bytes(env["pubkey"].read_bytes())

    if mutate == "unsigned":
        (bundle / "SIGNATURE").unlink()
    elif mutate == "wrong-target":
        (bundle / "manifest.json").write_text(
            '{"release": "1.2.3", "target": {"os": "macos", "arch": "arm64"}}\n', encoding="utf-8"
        )
    elif mutate == "pubkey-in-payload":
        (bundle / "evil.pem").write_text("-----BEGIN PUBLIC KEY-----\n", encoding="utf-8")
    elif mutate == "symlink-in-payload":
        (bundle / "link.sum").symlink_to("SHA256SUMS")

    out_dir = work / "dist"
    proc = _run_build(bundle, pubkey, out_dir)
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0, f"build_msi.sh must fail closed ({reason}); it exited 0:\n{proc.stdout}"
    assert "FAIL" in out, f"the refusal must carry a diagnostic ({reason}), got:\n{out}"
    assert list(out_dir.glob("*.msi")) == [], f"no MSI may be produced ({reason})"
    # pin the SPECIFIC gate each payload mutation must reach: with the trusted
    # verifier present, an earlier/other refusal would mean the gate under
    # test was bypassed or reordered and the test would pass for the wrong
    # reason (mutation-proven vacuous-pass failure mode).
    expected_gate = {
        "pubkey-in-payload": "public key material found in staged msi payload",
        "symlink-in-payload": "non-regular file in staged payload",
    }
    if mutate in expected_gate:
        assert expected_gate[mutate] in out, (
            f"the build must fail at the gate this mutation targets ({reason}), got:\n{out}"
        )


def test_build_msi_fails_closed_when_wix_build_fails(
    build_env: dict[str, Path], tmp_path: Path
) -> None:
    env = build_env
    proc = _run_build(env["bundle"], env["pubkey"], tmp_path / "dist", wix_fails=True)
    assert proc.returncode != 0, "a failed wix compile must abort the build"
    assert list((tmp_path / "dist").glob("*.msi")) == [], "no MSI may be left by a failed compile"


def test_build_msi_fails_closed_when_a_custom_action_script_is_missing(tmp_path: Path) -> None:
    """The deferred action wiring in udbmcp.wxs requires all five custom
    action scripts; a missing one is a packaging bug and must fail the build
    (never silently ship a half-wired installer)."""
    sandbox = tmp_path / "sandbox"
    (sandbox / "scripts" / "package").mkdir(parents=True)
    shutil.copytree(CUSTOM_DIR.parent, sandbox / "packaging" / "msi")
    (sandbox / "packaging" / "msi" / "custom" / "venv.ps1").unlink()
    shutil.copy2(BUILD_MSI, sandbox / "scripts" / "package" / "build_msi.sh")

    bundle, pubkey = _make_signed_bundle(tmp_path)
    stub_dir = tmp_path / "stubbin"
    _write_stub_toolchain(stub_dir)
    proc = subprocess.run(  # noqa: S603 - fixed args, tmp_path sandbox
        ["/bin/bash", str(sandbox / "scripts" / "package" / "build_msi.sh"),
         str(bundle), "--pubkey", str(pubkey), "--out", str(tmp_path / "dist")],
        capture_output=True, text=True, timeout=300,
        env={**os.environ, "PATH": f"{stub_dir}{os.pathsep}{os.environ.get('PATH', '')}"},
    )
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0, "a missing custom action script must fail the build"
    assert "venv.ps1" in out, f"the diagnostic must name the missing script, got:\n{out}"
    assert list((tmp_path / "dist").glob("*.msi")) == []


# --------------------------------------------------------------------------
# the wiring defect: the deferred custom actions are actually scheduled
# --------------------------------------------------------------------------


def test_build_msi_stages_and_scans_all_custom_action_scripts() -> None:
    """build_msi.sh stages every custom action script (they ship INSIDE the
    msi), passes the staged dir as -define CustomActionScriptsDir, and applies
    the same no-key-material scan to the staged scripts as to the payload."""
    code = _script_code()
    for name in CUSTOM_ACTION_SCRIPTS:
        assert f'"{name}"' in code or f"{name}" in code, (
            f"build_msi.sh must explicitly stage {name}"
        )
    assert re.search(r'-define\s+"CustomActionScriptsDir=\$CUSTOM_STAGE"', code), (
        "wix build must receive -define CustomActionScriptsDir"
    )
    # the pubkey scan covers BOTH the payload and the staged custom scripts
    scan_calls = re.findall(r"find_pubkey_material\s+\"\$\w+\"", code)
    assert len(scan_calls) >= 2, (
        "the no-key-material scan must run on the staged payload AND the staged custom action scripts"
    )
    # the scripts are staged BEFORE the compile, from the repo's reviewed copy
    assert re.search(r'cp\s+"\$CUSTOM_SRC/\$ps1"\s+"\$CUSTOM_STAGE/\$ps1"', code), (
        "staged scripts must be byte copies of packaging/msi/custom/*.ps1"
    )


def test_wxs_defines_the_five_deferred_actions() -> None:
    """All four install-time actions plus the uninstall and rollback twins are
    authored as deferred/rollback, impersonate=no (LocalSystem), Return=check
    exe custom actions running the installed PowerShell scripts."""
    root = _wxs_root()
    cas = {el.get("Id"): el for el in _iter_local(root, "CustomAction")}
    expected = {
        "VerifyBundleCA": ("deferred", "verify.ps1"),
        "BuildVenvCA": ("deferred", "venv.ps1"),
        "DoctorSmokeCA": ("deferred", "doctor.ps1"),
        "RegisterServiceCA": ("deferred", "service.ps1"),
        "RollbackRemoveServiceCA": ("rollback", "uninstall.ps1"),
        "RemoveServiceCA": ("deferred", "uninstall.ps1"),
    }
    for action_id, (mode, script) in expected.items():
        ca = cas.get(action_id)
        assert ca is not None, f"CustomAction Id={action_id} is missing from udbmcp.wxs"
        assert ca.get("Execute") == mode, f"{action_id} must be Execute={mode}"
        assert ca.get("Impersonate") == "no", (
            f"{action_id} must run as LocalSystem (Impersonate=no): per-machine writes and sc.exe"
        )
        assert ca.get("Return") == "check", (
            f"{action_id} must Return=check: any nonzero exit rolls the install back"
        )
        assert ca.get("Property") == "POWERSHELLEXE", (
            f"{action_id} must run the system powershell.exe via the POWERSHELLEXE property"
        )
        cmd = ca.get("ExeCommand") or ""
        assert f"[INSTALLFOLDER]scripts\\{script}" in cmd, (
            f"{action_id} must invoke the installed script {script}, got: {cmd}"
        )
        assert "-NoProfile" in cmd and "-NonInteractive" in cmd and "-ExecutionPolicy Bypass" in cmd, (
            f"{action_id} must run powershell with -NoProfile -NonInteractive -ExecutionPolicy Bypass"
        )
    # the property feeding the exe path is set unconditionally by a type-51
    setter = cas.get("SetPowerShellExe")
    assert setter is not None and setter.get("Property") == "POWERSHELLEXE" and setter.get("Value"), (
        "SetPowerShellExe (type 51) must set POWERSHELLEXE in the execute sequence"
    )
    assert "System64Folder" in (setter.get("Value") or ""), (
        "POWERSHELLEXE must resolve to the 64-bit system powershell.exe"
    )


def test_wxs_sequences_the_actions_in_trust_order() -> None:
    """InstallExecuteSequence: verify BEFORE venv BEFORE doctor BEFORE service
    registration, all after InstallFiles (only then does the bundle exist) and
    none on uninstall; the service removal runs on uninstall before RemoveFiles
    deletes the script it runs; the rollback twin follows the registration."""
    root = _wxs_root()
    seq = _iter_local(root, "InstallExecuteSequence")
    assert seq, "udbmcp.wxs must contain an InstallExecuteSequence"
    customs = {el.get("Action"): el for el in seq[0] if _localname(el) == "Custom"}

    def entry(action_id: str) -> ET.Element:
        el = customs.get(action_id)
        assert el is not None, f"{action_id} is not scheduled in InstallExecuteSequence"
        return el

    assert entry("VerifyBundleCA").get("After") == "InstallFiles", (
        "the trusted verify action must run AFTER InstallFiles (the installed bundle must exist)"
    )
    assert entry("BuildVenvCA").get("After") == "VerifyBundleCA", (
        "the venv build must be scheduled strictly AFTER the trusted verification (invariant 1)"
    )
    assert entry("DoctorSmokeCA").get("After") == "BuildVenvCA", (
        "the doctor smoke (first payload execution) must run only after the venv exists"
    )
    assert entry("RegisterServiceCA").get("After") == "DoctorSmokeCA", (
        "the service must be registered only after the doctor smoke passed"
    )
    assert entry("RollbackRemoveServiceCA").get("Before") == "RegisterServiceCA", (
        "a rollback twin must ALWAYS precede the deferred action it rolls back in the "
        "sequence, otherwise a failure/cancellation during the register action never "
        "enters the rollback script and the half-created service survives the rollback"
    )
    assert entry("RollbackRemoveServiceCA").get("Condition") == "NOT REMOVE", (
        "the rollback twin is install-time only"
    )
    remove = entry("RemoveServiceCA")
    assert remove.get("Before") == "RemoveFiles", (
        "the uninstall action must run BEFORE RemoveFiles deletes the uninstall.ps1 it executes"
    )
    assert remove.get("Condition") == 'REMOVE="ALL"', (
        "the uninstall action must run only on uninstall (REMOVE=ALL)"
    )
    for action_id in ("VerifyBundleCA", "BuildVenvCA", "DoctorSmokeCA", "RegisterServiceCA"):
        assert entry(action_id).get("Condition") == "NOT REMOVE", (
            f"{action_id} must be install-time only (NOT REMOVE), never re-run during uninstall"
        )


def test_wxs_passes_the_right_arguments_to_each_action() -> None:
    """The action command lines match the parameter contracts of the
    packaging/msi/custom/*.ps1 scripts (verified against those scripts'
    documented parameters)."""
    root = _wxs_root()
    cas = {el.get("Id"): el for el in _iter_local(root, "CustomAction")}
    cmd = cas["VerifyBundleCA"].get("ExeCommand") or ""
    assert "-CustomActionData" in cmd and "BUNDLE_DIR=[INSTALLFOLDER]bundle" in cmd, (
        "verify.ps1 requires BUNDLE_DIR in CustomActionData (its CustomActionData contract)"
    )
    assert "venv" not in cmd.replace("[INSTALLFOLDER]scripts\\verify.ps1", ""), (
        "the verify action must not build or reference the venv (nothing may run payload first)"
    )
    cmd = cas["BuildVenvCA"].get("ExeCommand") or ""
    assert "-BundleDir" in cmd and "[INSTALLFOLDER]bundle" in cmd, "venv.ps1 needs -BundleDir"
    assert "-VenvDir" in cmd and "[INSTALLFOLDER]venv" in cmd, "venv.ps1 needs -VenvDir"
    cmd = cas["DoctorSmokeCA"].get("ExeCommand") or ""
    assert "-VenvDir" in cmd and "-ConfigPath" in cmd and "[ProgramDataUdbmcpDir]config.yaml" in cmd, (
        "doctor.ps1 needs -VenvDir and the machine-wide config path"
    )
    assert "[INSTALLFOLDER]bundle\\manifest.json" in cmd, (
        "doctor.ps1 needs -BundleManifest so doctor reports the installed profile"
    )
    cmd = cas["RegisterServiceCA"].get("ExeCommand") or ""
    assert "-VenvDir" in cmd and "-ConfigPath" in cmd and "-ServiceAccount" in cmd, (
        "service.ps1 needs -VenvDir, -ConfigPath and -ServiceAccount"
    )
    cmd = cas["RemoveServiceCA"].get("ExeCommand") or ""
    assert "-ServiceName" in cmd and "udbmcp" in cmd, "uninstall.ps1 needs -ServiceName"


def test_wxs_ships_the_custom_action_scripts_outside_the_bundle() -> None:
    """The scripts are installed into INSTALLFOLDER\\scripts — a sibling of
    INSTALLFOLDER\\bundle, so verify.ps1's in-bundle containment guard holds —
    each as a single-file component referenced by the Main feature."""
    root = _wxs_root()
    dirs = {el.get("Id"): el for el in _iter_local(root, "Directory")}
    scripts_dir = dirs.get("ScriptsDir")
    assert scripts_dir is not None, "the ScriptsDir directory must be declared"
    bundle_dir = dirs.get("BundleDir")
    assert bundle_dir is not None and len(list(bundle_dir)) == 0, (
        "BundleDir must stay a bare directory (the payload is harvested into it)"
    )
    comps = _iter_local(scripts_dir, "Component")
    installed = {}
    for comp in comps:
        files = [el for el in comp if _localname(el) == "File"]
        assert len(files) == 1 and files[0].get("KeyPath") == "yes"
        installed[files[0].get("Name")] = comp
    for name in CUSTOM_ACTION_SCRIPTS:
        comp = installed.get(name)
        assert comp is not None, f"{name} is not installed into INSTALLFOLDER\\scripts"
        f = [el for el in comp if _localname(el) == "File"][0]
        assert f.get("Source") == f"$(var.CustomActionScriptsDir)/{name}", (
            f"{name} must be staged by build_msi.sh (-define CustomActionScriptsDir)"
        )
    feature = _iter_local(root, "Feature")
    assert feature, "the Main feature must reference the script components"
    refs = {el.get("Id") for el in feature[0] if _localname(el) == "ComponentRef"}
    for name, comp in installed.items():
        assert comp.get("Id") in refs, f"{name} is installed but not referenced by the feature"


def test_wxs_never_references_release_key_material() -> None:
    """Trust invariant 2: the release public key is distributed out-of-band;
    the package authoring must not embed or reference key paths — the verify
    action reads UDBMCP_RELEASE_PUBKEY from machine scope at runtime (inside
    verify.ps1, not in the package authoring)."""
    code = _wxs_code()
    assert "UDBMCP_RELEASE_PUBKEY" not in code, (
        "the wxs must not point the verify action at a bundled key; the admin distributes it"
    )
    assert "BEGIN PUBLIC KEY" not in code and "release.pub" not in code, (
        "no key material may be embedded in the package authoring"
    )
    verify_cmd = next(
        el.get("ExeCommand") for el in _iter_local(_wxs_root(), "CustomAction")
        if el.get("Id") == "VerifyBundleCA"
    )
    assert "pubkey" not in verify_cmd.lower(), (
        "the verify action's command line must not reference a public key; the "
        "release pubkey is resolved at runtime from machine scope "
        "(UDBMCP_RELEASE_PUBKEY), never from the package authoring"
    )
    # The trust DIRECTORY, by contrast, IS pinned in the command line —
    # deliberately (P1 fix): TRUST_DIR=[ProgramFiles64Folder]udbmcp-trust
    # forces the gate to run the trusted verifier from the admin-write-only
    # Program Files tree instead of verify.ps1's fallback default under
    # C:\ProgramData, whose default ACLs let a NON-ADMIN process pre-create
    # (and thereby own) the trust directory and swap the verifier that this
    # LocalSystem action then executes. This pins a location, not key
    # material — no key path or key bytes pass through the authoring.
    assert "TRUST_DIR=[ProgramFiles64Folder]udbmcp-trust" in verify_cmd, (
        "the verify action must pin TRUST_DIR to the ACL-protected Program "
        "Files trust location; leaving it to verify.ps1's C:\\ProgramData "
        "fallback reopens the non-admin trust-dir squatting bypass"
    )
