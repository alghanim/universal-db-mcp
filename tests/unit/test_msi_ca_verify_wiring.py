# Artifact-owner (msi:ca_verify) tests for the MSI verify-before-execute gate.
#
# Scope: packaging/msi/custom/verify.ps1 AND the wiring that makes it more
# than dead code -- the VerifyBundleCA custom action in packaging/msi/
# udbmcp.wxs. The verifier lens confirmed the P2 defect "the verify custom
# action is never scheduled, so verify.ps1 is dead code"; these tests pin the
# fix: the wxs must schedule VerifyBundleCA exactly as verify.ps1's own
# SCHEDULING CONTRACT header (lines 32-52) requires, and verify.ps1 must keep
# its fail-closed decision structure (exit 0 only on verifier exit 0 AND the
# explicit 'bundle verification PASSED' proof AND no FAIL line).
#
# Static tests only (no Windows host, no wix toolchain): full compile
# validation happens in the Phase 0 Windows staging environment. The wxs
# parsing approach mirrors tests/unit/test_msi_wxs_authoring.py (expat on a
# first-party repo file that declares no DTD/entities).

import re
import xml.etree.ElementTree as ET
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
WXS = REPO / "packaging" / "msi" / "udbmcp.wxs"
VERIFY_PS1 = REPO / "packaging" / "msi" / "custom" / "verify.ps1"
BUILD_MSI = REPO / "scripts" / "package" / "build_msi.sh"

WIX_NS = "http://wixtoolset.org/schemas/v4/wxs"


def local(tag: str) -> str:
    return tag.split("}", 1)[-1]


def find_all(root: ET.Element, name: str) -> list[ET.Element]:
    return [el for el in root.iter() if local(el.tag) == name]


def find_one(root: ET.Element, name: str, **attrs: str) -> ET.Element:
    matches = [
        el
        for el in find_all(root, name)
        if all(el.get(k) == v for k, v in attrs.items())
    ]
    assert len(matches) == 1, (
        f"expected exactly one <{name}> with {attrs}, found {len(matches)}"
    )
    return matches[0]


def wxs_root() -> ET.Element:
    # ElementTree drops comments: assertions see CODE ONLY (comments may
    # legitimately mention things the code must not contain).
    return ET.parse(WXS).getroot()  # noqa: S314 - first-party repo file, no DTD/entities


def wxs_text() -> str:
    return WXS.read_text(encoding="utf-8")


def verify_text() -> str:
    return VERIFY_PS1.read_text(encoding="utf-8")


def sequence_entry(root: ET.Element, action: str) -> ET.Element:
    return find_one(root, "Custom", Action=action)


# ---------------------------------------------------------------------------
# 1. VerifyBundleCA exists and is wired fail-closed (the P2 dead-code defect)
# ---------------------------------------------------------------------------


def test_verify_bundle_ca_is_declared_in_the_wxs():
    root = wxs_root()
    ca = find_one(root, "CustomAction", Id="VerifyBundleCA")
    # Scheduling contract (verify.ps1 lines 32-36): Deferred, impersonate=no
    # (LocalSystem), Return="check" so any nonzero exit aborts and rolls back.
    assert ca.get("Execute") == "deferred"
    assert ca.get("Impersonate") == "no"
    assert ca.get("Return") == "check"
    # The executable is the fixed 64-bit inbox PowerShell, never something the
    # bundle supplies (POWERSHELLEXE is assigned by SetPowerShellExe).
    assert ca.get("Property") == "POWERSHELLEXE"


def test_verify_bundle_ca_is_scheduled_after_installfiles():
    # The bundle must be on disk before it can be verified.
    root = wxs_root()
    entry = sequence_entry(root, "VerifyBundleCA")
    assert entry.get("After") == "InstallFiles"
    assert entry.get("Before") is None


def test_verify_bundle_ca_runs_on_install_but_not_uninstall():
    root = wxs_root()
    entry = sequence_entry(root, "VerifyBundleCA")
    assert entry.get("Condition") == "NOT REMOVE"


def test_verify_bundle_ca_runs_before_every_payload_consuming_action():
    # Contract: "scheduled AFTER the InstallFiles action ... and BEFORE the
    # venv/doctor/service custom actions (nothing may run payload first)."
    root = wxs_root()
    for action in ("BuildVenvCA", "DoctorSmokeCA", "RegisterServiceCA"):
        entry = sequence_entry(root, action)
        assert entry.get("After") == {
            "BuildVenvCA": "VerifyBundleCA",
            "DoctorSmokeCA": "BuildVenvCA",
            "RegisterServiceCA": "DoctorSmokeCA",
        }[action], f"{action} must run strictly after VerifyBundleCA"


def test_powershell_path_is_resolved_by_an_immediate_action_before_the_first_deferred_one():
    root = wxs_root()
    setter = find_one(root, "CustomAction", Id="SetPowerShellExe")
    assert setter.get("Property") == "POWERSHELLEXE"
    value = setter.get("Value") or ""
    assert "[System64Folder]" in value and "WindowsPowerShell\\v1.0\\powershell.exe" in value
    entry = sequence_entry(root, "SetPowerShellExe")
    # before InstallInitialize, so before every deferred action, the
    # uninstall's RemoveServiceCA (at RemoveFiles) included
    assert entry.get("Before") == "InstallInitialize"


def test_setpowershellexe_entry_is_unconditional():
    # An attacker-controllable condition on the assignment could leave
    # POWERSHELLEXE set from a caller-supplied public property and redirect
    # the deferred actions to a different executable.
    root = wxs_root()
    entry = sequence_entry(root, "SetPowerShellExe")
    assert entry.get("Condition") is None


# ---------------------------------------------------------------------------
# 2. The wxs invocation matches verify.ps1's parameter surface
# ---------------------------------------------------------------------------


def test_verify_action_invokes_the_shipped_verify_ps1_with_customactiondata():
    root = wxs_root()
    ca = find_one(root, "CustomAction", Id="VerifyBundleCA")
    cmd = ca.get("ExeCommand") or ""
    assert "-NoProfile" in cmd and "-NonInteractive" in cmd
    assert "-ExecutionPolicy Bypass" in cmd
    assert "-File" in cmd and "[INSTALLFOLDER]scripts\\verify.ps1" in cmd
    assert "-CustomActionData" in cmd
    # The installed bundle path (sibling of the installed scripts dir) is the
    # one required parameter; trust dir / pubkey / python fall back to the
    # machine-scope env vars verify.ps1 documents (UDBMCP_TRUST_DIR,
    # UDBMCP_RELEASE_PUBKEY, UDBMCP_PYTHON).
    assert "BUNDLE_DIR=[INSTALLFOLDER]bundle" in cmd


def test_verify_action_pins_trust_dir_to_an_acl_protected_location():
    # Trust invariant: the gate must not resolve the trusted verifier from a
    # location a NON-ADMIN local process can pre-create. C:\ProgramData's
    # default ACLs give Authenticated Users create-folder/append-data on the
    # root and CREATOR OWNER Full Control on directories they create, so a
    # squatted C:\ProgramData\udbmcp-trust would let an attacker delete and
    # replace the admin-copied verifier that this action (Impersonate="no":
    # LocalSystem) then executes — LocalSystem code execution and a forged
    # "bundle verification PASSED" proof. The wxs therefore passes TRUST_DIR
    # explicitly into the admin-write-only Program Files tree, the analogue
    # of the deb/pkg bootstrap's root-owned
    # `install -d -m 755 /usr/local/lib/udbmcp-trust`. CustomActionData takes
    # precedence over the machine-scope UDBMCP_TRUST_DIR override in
    # verify.ps1, so this pins the effective path, not just a fallback.
    root = wxs_root()
    ca = find_one(root, "CustomAction", Id="VerifyBundleCA")
    cmd = ca.get("ExeCommand") or ""
    assert "TRUST_DIR=[ProgramFiles64Folder]udbmcp-trust" in cmd, (
        "VerifyBundleCA must pass TRUST_DIR pointing into the admin-write-only "
        "Program Files tree; falling back to verify.ps1's machine-scope "
        "UDBMCP_TRUST_DIR lets a C:\\ProgramData path a non-admin squatted "
        "supply the verifier the gate executes as LocalSystem"
    )
    # The authored CustomActionData must never root the trust dir (or any
    # other trust input) in world-squattable ProgramData.
    custom_action_data = cmd.split("-CustomActionData", 1)[1]
    assert "ProgramData" not in custom_action_data, (
        f"CustomActionData must not place trust material under C:\\ProgramData: {custom_action_data!r}"
    )


def test_customactiondata_flag_matches_the_verify_ps1_param_name():
    # Cross-file consistency: the wxs passes "-CustomActionData ..." and
    # verify.ps1's param block binds exactly that name (a rename on either
    # side would silently drop the bundle path and fail closed mid-install).
    assert "-CustomActionData" in (find_one(wxs_root(), "CustomAction", Id="VerifyBundleCA").get("ExeCommand") or "")
    assert re.search(r"\[string\]\$CustomActionData", verify_text())


def test_verify_ps1_is_shipped_as_a_component_outside_the_bundle():
    # The verifier ships in the MSI but OUTSIDE the bundle directory (a
    # verifier shipped in the payload would be a tampered verifier), and the
    # component must actually be in the feature so the file lands on disk.
    root = wxs_root()
    comp = find_one(root, "Component", Id="VerifyPs1Component")
    file_el = find_one(comp, "File", Id="VerifyPs1File")
    assert file_el.get("Source", "").endswith("verify.ps1")
    assert file_el.get("KeyPath") == "yes"
    feature = find_one(root, "Feature", Id="Main")
    refs = [el.get("Id") for el in find_all(feature, "ComponentRef")]
    assert "VerifyPs1Component" in refs


def test_build_msi_defines_the_custom_action_scripts_dir():
    # The wxs resolves the shipped scripts through -define
    # CustomActionScriptsDir; if build_msi.sh stopped passing it, `wix build`
    # would fail closed -- and if it passed a wrong dir, this test still pins
    # the contract documented in the wxs header.
    script = BUILD_MSI.read_text(encoding="utf-8")
    assert "-define \"CustomActionScriptsDir=" in script or "-define CustomActionScriptsDir=" in script
    # And the scripts are staged, not referenced from the live checkout.
    assert "CUSTOM_STAGE" in script


# ---------------------------------------------------------------------------
# 3. verify.ps1 keeps its fail-closed decision structure
# ---------------------------------------------------------------------------


def test_verify_ps1_exit_zero_appears_only_after_the_proof_check():
    text = verify_text()
    exits = [m.start() for m in re.finditer(r"^\s*exit 0\s*$", text, re.M)]
    assert len(exits) == 1, "there must be exactly one exit-0 path"
    proof_pos = text.index("'bundle verification PASSED'")
    fail_on_missing_proof = text.index("did not print 'bundle verification PASSED'")
    # The Write-Log helper has its own try/catch; the catch-all that must
    # follow the exit-0 path is the LAST catch in the script.
    catch_all = text.rindex("} catch {")
    assert fail_on_missing_proof < exits[0] < catch_all, (
        "exit 0 must be reachable only after the explicit proof-of-verification check"
    )
    assert proof_pos < fail_on_missing_proof


def test_verify_ps1_fails_closed_via_fail_and_catch_all():
    text = verify_text()
    # Fail exits nonzero (msiexec rolls back via Return="check").
    assert re.search(r"function Fail \{[\s\S]*?exit 1", text)
    # The catch-all routes to Fail: no unhandled error can exit 0.
    assert re.search(r"\} catch \{\s*\n\s*Fail ", text)
    # $ErrorActionPreference = 'Stop' is set before any decision work.
    assert "$ErrorActionPreference = 'Stop'" in text


def test_verify_ps1_checks_verifier_exit_code_and_no_fail_line():
    text = verify_text()
    assert "$verifierExit -ne 0" in text
    assert re.search(r"-match '\(\?m\)\^FAIL:'", text)


def test_verify_ps1_runs_the_verifier_without_a_shell():
    # The verifier must be invoked through the argument array of the resolved
    # interpreter -- never via a shell string (cmd /c, Invoke-Expression, ...).
    text = verify_text()
    assert "& $pyExe @pyArgs $Verifier --bundle $BundleDir --pubkey $PubKey" in text
    for banned in ("Invoke-Expression", "cmd.exe", "/c ", "Start-Process"):
        assert banned not in text, f"shell-style invocation '{banned}' must not appear"


def test_verify_ps1_refuses_bundle_located_trust_inputs():
    # Defense in depth: verifier, profiles registry, pubkey and interpreter
    # inside the bundle are attacker-controlled positions -- each must be
    # rejected via the containment check.
    text = verify_text()
    assert "Test-InsideDir $PSCommandPath $BundleDir" in text
    assert "Test-InsideDir $TrustDir $BundleDir" in text
    assert "Test-InsideDir $PubKey $BundleDir" in text
    assert "Test-InsideDir $pyExe $BundleDir" in text


def test_verify_ps1_never_embeds_key_material():
    # Invariant 2: the release public key is NEVER shipped inside any package.
    text = verify_text()
    assert "BEGIN PUBLIC KEY" not in text and "BEGIN OPENSSH PUBLIC KEY" not in text
    root = wxs_root()
    for el in root.iter():
        for v in el.attrib.values():
            assert "BEGIN PUBLIC KEY" not in v
    assert "BEGIN PUBLIC KEY" not in wxs_text().split("<Wix", 1)[0]  # header comment too


def test_verify_ps1_reads_no_decision_from_the_log_file():
    # The install-verify.log is a post-mortem artifact only: no trust decision
    # may depend on it (its location is world-writable by default ACLs).
    text = verify_text()
    reads = re.findall(r"Get-Content[^\n]*LogPath", text)
    assert not reads, "the verify decision must not read back the log file"
