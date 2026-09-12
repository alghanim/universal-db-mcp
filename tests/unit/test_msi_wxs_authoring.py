# Static authoring gates for the WiX source packaging/msi/udbmcp.wxs.
#
# These tests are the artifact-owner (msi:wxs_core) checks for the deferred
# custom-action pipeline: they pin the trust-model invariants that the .wxs
# must keep, independently of the broader packaging tests in
# test_msi_packaging.py. They are intentionally static (no Windows host, no
# `wix` toolchain is required to run them): full compile validation happens
# in the Phase 0 Windows staging environment.

import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

# xml.etree (expat) is used on a FIRST-PARTY repo file (packaging/msi/udbmcp.wxs)
# that we author and review; it declares no DTD/entities, and CPython's expat
# ships the billion-laughs protections. defusedxml is not a project dependency
# and these tests must not add one — the trust boundary for packaging content
# is the signed-bundle verification pipeline, not this parser.

REPO = Path(__file__).resolve().parents[2]
WXS = REPO / "packaging" / "msi" / "udbmcp.wxs"
CUSTOM_DIR = REPO / "packaging" / "msi" / "custom"

WIX_NS = "http://wixtoolset.org/schemas/v4/wxs"

# The deferred trust pipeline, in the order the plan (Phase 5) mandates:
# verify -> venv -> doctor -> service, each a deferred, elevated, fail-closed
# exe custom action running the shipped PowerShell wrappers.
PIPELINE_ACTIONS = ("VerifyBundleCA", "BuildVenvCA", "DoctorSmokeCA", "RegisterServiceCA")

SCRIPT_COMPONENTS = {
    "verify.ps1": "VerifyPs1Component",
    "venv.ps1": "VenvPs1Component",
    "doctor.ps1": "DoctorPs1Component",
    "service.ps1": "ServicePs1Component",
    "uninstall.ps1": "UninstallPs1Component",
}


def wxs_text() -> str:
    return WXS.read_text(encoding="utf-8")


def wxs_root() -> ET.Element:
    # ElementTree drops XML comments by default, so assertions against the
    # parsed tree see CODE ONLY (comments may legitimately mention things the
    # code must not contain, e.g. "ServiceInstall").
    return ET.parse(WXS).getroot()  # noqa: S314 - first-party repo file, no DTD/entities (see module note)


def local(tag: str) -> str:
    return tag.split("}", 1)[-1]


def find_all(root: ET.Element, name: str) -> list[ET.Element]:
    return [el for el in root.iter() if local(el.tag) == name]


def find_one(root: ET.Element, name: str, **attrs: str) -> ET.Element:
    matches = [
        el
        for el in find_all(root, name)
        if all(el.get(key) == value for key, value in attrs.items())
    ]
    assert len(matches) == 1, f"expected exactly one <{name} {attrs}>, found {len(matches)}"
    return matches[0]


def sequence_rows(root: ET.Element) -> dict[str, ET.Element]:
    rows = find_all(root, "Custom")
    assert rows, "InstallExecuteSequence contains no <Custom> rows"
    return {row.get("Action"): row for row in rows}


def custom_actions(root: ET.Element) -> dict[str, ET.Element]:
    actions = find_all(root, "CustomAction")
    assert actions, "no <CustomAction> definitions found"
    return {action.get("Id"): action for action in actions}


@pytest.fixture(scope="module")
def root() -> ET.Element:
    return wxs_root()


# --------------------------------------------------------------------------
# Structure / syntax
# --------------------------------------------------------------------------


def test_wxs_is_well_formed_xml_in_wix_v4_namespace(root):
    assert local(root.tag) == "Wix"
    assert root.tag.startswith("{" + WIX_NS + "}")


def test_version_and_config_template_come_from_build_defines(root):
    package = find_one(root, "Package")
    assert package.get("Version") == "$(var.ProductVersion)"
    config_file = find_one(root, "File", Id="ConfigYamlFile")
    assert config_file.get("Source") == "$(var.ConfigTemplateSource)"


def test_in_file_defines_are_guardeed_so_build_flags_win():
    # WiX's preprocessor lets an in-file <?define> overwrite a -define passed
    # on the wix command line (with only a warning). build_msi.sh passes
    # -define ProductVersion / ConfigTemplateSource, so every default that
    # collides with a build flag MUST be guarded with <?ifndef> or the build
    # would silently stamp the in-file placeholder value into the MSI.
    text = wxs_text()
    for variable in ("ProductVersion", "ConfigTemplateSource", "ConfigTemplateGuid"):
        guard = f'<?ifndef {variable} ?>'
        assert guard in text, f"missing {guard} guard"
        assert text.index(guard) < text.index(f'<?define {variable} '), (
            f"{guard} must precede the in-file define for {variable}"
        )


# --------------------------------------------------------------------------
# Deferred custom actions: the trust pipeline
# --------------------------------------------------------------------------


def test_deferred_pipeline_actions_are_declared_and_fail_closed(root):
    actions = custom_actions(root)
    for action_id in PIPELINE_ACTIONS:
        action = actions[action_id]
        assert action.get("Execute") == "deferred", action_id
        # LocalSystem: per-machine writes and sc.exe need the elevation.
        assert action.get("Impersonate") == "no", action_id
        # Fail closed: any nonzero script exit aborts the install.
        assert action.get("Return") == "check", action_id


def test_pipeline_runs_the_absolute_system_powershell(root):
    # Bare "powershell.exe" would resolve through the process' CWD/PATH inside
    # a LocalSystem custom action — an executable-search hijack vector. The
    # interpreter must be pinned to the absolute inbox path instead.
    setter = find_one(root, "CustomAction", Id="SetPowerShellExe")
    assert setter.get("Property") == "POWERSHELLEXE"
    value = setter.get("Value", "")
    assert value == "[System64Folder]WindowsPowerShell\\v1.0\\powershell.exe"
    for action_id in PIPELINE_ACTIONS + ("RollbackRemoveServiceCA", "RemoveServiceCA"):
        assert custom_actions(root)[action_id].get("Property") == "POWERSHELLEXE", action_id


def test_sequence_orders_verify_before_venv_before_doctor_before_service(root):
    rows = sequence_rows(root)
    # Verify runs against the freshly installed files, before anything
    # executes payload; every later stage is chained strictly after it.
    assert rows["VerifyBundleCA"].get("After") == "InstallFiles"
    assert rows["BuildVenvCA"].get("After") == "VerifyBundleCA"
    assert rows["DoctorSmokeCA"].get("After") == "BuildVenvCA"
    assert rows["RegisterServiceCA"].get("After") == "DoctorSmokeCA"
    # Install/repair-only stages are skipped on uninstall.
    for action_id in ("VerifyBundleCA", "BuildVenvCA", "DoctorSmokeCA", "RegisterServiceCA"):
        assert rows[action_id].get("Condition") == "NOT REMOVE", action_id


def test_verify_action_verifies_the_installed_bundle(root):
    action = custom_actions(root)["VerifyBundleCA"]
    command = action.get("ExeCommand", "")
    assert "verify.ps1" in command
    assert "BUNDLE_DIR=" in command
    assert "[INSTALLFOLDER]bundle" in command


def test_doctor_and_service_actions_only_touch_verified_artifacts(root):
    actions = custom_actions(root)
    doctor = actions["DoctorSmokeCA"].get("ExeCommand", "")
    service = actions["RegisterServiceCA"].get("ExeCommand", "")
    assert "-VenvDir" in doctor and "[INSTALLFOLDER]venv" in doctor
    assert "doctor.ps1" in doctor
    assert "service.ps1" in service
    # The service registration passes the service account through the
    # documented (empty -> env -> LocalSystem) override, never a hardcoded
    # account value baked into the package.
    assert "-ServiceAccount" in service
    assert "[UDBMCP_SERVICE_ACCOUNT]" in service


def test_service_account_override_is_a_secure_public_property(root):
    prop = find_one(root, "Property", Id="UDBMCP_SERVICE_ACCOUNT")
    assert prop.get("Secure") == "yes"


def test_rollback_twin_precedes_the_action_it_rolls_back(root):
    # MSI rule: "A rollback custom action must always precede the deferred
    # custom action it rolls back in the action sequence" — otherwise a
    # failure/cancellation during the register action itself never enters the
    # rollback script and a half-created service survives the rollback.
    row = sequence_rows(root)["RollbackRemoveServiceCA"]
    assert row.get("Before") == "RegisterServiceCA"
    assert row.get("Condition") == "NOT REMOVE"
    action = custom_actions(root)["RollbackRemoveServiceCA"]
    assert action.get("Execute") == "rollback"
    assert action.get("Impersonate") == "no"
    assert "uninstall.ps1" in action.get("ExeCommand", "")


def test_uninstall_mirror_removes_service_before_its_script_is_deleted(root):
    row = sequence_rows(root)["RemoveServiceCA"]
    assert row.get("Before") == "RemoveFiles"
    assert row.get("Condition") == 'REMOVE="ALL"'
    action = custom_actions(root)["RemoveServiceCA"]
    assert action.get("Execute") == "deferred"
    assert action.get("Impersonate") == "no"
    assert action.get("Return") == "check"
    assert "uninstall.ps1" in action.get("ExeCommand", "")


def test_no_service_install_or_service_control_elements_in_code(root):
    # The service is registered by the deferred sc.exe custom actions because
    # the service binary (the venv interpreter) does not exist at authoring
    # time; ServiceInstall/ServiceControl elements must not appear.
    code = ET.tostring(root, encoding="unicode")
    assert "ServiceInstall" not in code
    assert "ServiceControl" not in code


# --------------------------------------------------------------------------
# Custom-action script payload
# --------------------------------------------------------------------------


@pytest.mark.parametrize("script,component_id", sorted(SCRIPT_COMPONENTS.items()))
def test_action_scripts_are_installed_into_scripts_dir(root, script, component_id):
    component = find_one(root, "Component", Id=component_id)
    file_el = component.find(f"{{{WIX_NS}}}File")
    assert file_el is not None, component_id
    assert file_el.get("KeyPath") == "yes", component_id
    assert file_el.get("Source") == f"$(var.CustomActionScriptsDir)/{script}", component_id
    # The scripts live outside the bundle directory (a sibling of bundle\):
    # verify.ps1 refuses to run from inside the payload it verifies.
    feature = find_one(root, "Feature", Id="Main")
    refs = {ref.get("Id") for ref in find_all(feature, "ComponentRef")}
    assert component_id in refs
    assert (CUSTOM_DIR / script).is_file(), f"{script} missing from {CUSTOM_DIR}"


# --------------------------------------------------------------------------
# Trust invariants
# --------------------------------------------------------------------------


def test_no_key_material_in_the_wxs():
    text = wxs_text().lower()
    for marker in ("private key", "begin openssh", "ssh-rsa", "sha256:"):
        assert marker not in text, marker
    key_files = [
        p
        for p in (REPO / "packaging" / "msi").rglob("*")
        if p.suffix.lower() in {".pem", ".key", ".pub", ".pfx", ".p12"}
    ]
    assert not key_files, key_files
