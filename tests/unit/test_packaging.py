"""Phase 1 regression tests for the target-profile registry.

The linux-x86_64-ubuntu24.04-cp312 profile must reproduce the parameters that
were previously hardcoded in scripts/prepare_offline_bundle.py byte-for-byte
(behavior-neutrality for the shipped profile), and the new fail-loud
wheelhouse rule must behave exactly as specified.
"""

from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parents[2]
if str(PROJECT) not in sys.path:
    sys.path.insert(0, str(PROJECT))

import scripts.profiles as prof_mod  # noqa: E402
from scripts import prepare_offline_bundle as pob  # noqa: E402
from scripts.profiles import PROFILES, get_profile, profile_host_mismatches  # noqa: E402

LINUX = "linux-x86_64-ubuntu24.04-cp312"
WINDOWS = "windows-x86_64-cp312"
MACOS = "macos-arm64-cp312"


# --- linux profile: golden parameters (byte-identical to the old hardcodes) ---


def test_linux_profile_matches_previous_hardcoded_params() -> None:
    prof = PROFILES[LINUX]
    assert prof.python_version == "3.12"
    assert prof.abi == "cp312"
    assert prof.pip_platforms == ("manylinux2014_x86_64",)
    assert prof.manifest_target == {
        "os": "ubuntu-24.04", "arch": "x86_64", "python": "3.12", "abi": "cp312",
    }
    assert prof.os_packages_staging == "out/os-packages-ubuntu24.04"
    assert prof.baseline_image == "udbmcp-baseline:ubuntu24.04-cp312"
    assert prof.odbc_driver_package == ".deb"


def test_windows_profile_values() -> None:
    prof = PROFILES[WINDOWS]
    assert prof.python_version == "3.12"
    assert prof.abi == "cp312"
    assert prof.pip_platforms == ("win_amd64",)
    assert prof.manifest_target == {
        "os": "windows", "arch": "x86_64", "python": "3.12", "abi": "cp312",
    }
    assert prof.os_packages_staging is None
    assert prof.baseline_image is None
    assert prof.odbc_driver_package == ".msi"


def test_macos_profile_values() -> None:
    prof = PROFILES[MACOS]
    assert prof.python_version == "3.12"
    assert prof.abi == "cp312"
    assert prof.pip_platforms == ("macosx_11_0_arm64", "macosx_14_0_arm64")
    assert prof.manifest_target == {
        "os": "macos", "arch": "arm64", "python": "3.12", "abi": "cp312",
    }
    assert prof.os_packages_staging is None
    assert prof.baseline_image is None
    assert prof.odbc_driver_package == ".pkg"


# --- unknown profiles are rejected, at both entry points ---


def test_unknown_profile_rejected_by_get_profile() -> None:
    with pytest.raises(SystemExit, match="unknown profile"):
        get_profile("linux-x86_64")  # legacy short name must NOT resolve


def test_unknown_profile_rejected_by_builder_argparse() -> None:
    parser = pob.build_arg_parser()
    assert set(parser._option_string_actions["--profile"].choices) == set(PROFILES)
    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["--out", "out/x", "--profile", "linux-x86_64"])
    assert exc.value.code == 2


# --- fail-loud wheelhouse rule and signing-key refusal ---


def test_missing_connector_wheels_fail_loud_naming_wheel_and_profile() -> None:
    with pytest.raises(SystemExit) as exc:
        pob.require_complete_wheelhouse(["ibm-db"], LINUX, allow_missing=False)
    msg = str(exc.value)
    assert "ibm-db" in msg
    assert LINUX in msg
    assert "--allow-missing-connectors" in msg


def test_missing_connector_wheels_allowed_with_explicit_flag() -> None:
    pob.require_complete_wheelhouse(["ibm-db"], LINUX, allow_missing=True)


def test_complete_wheelhouse_needs_no_flag() -> None:
    pob.require_complete_wheelhouse([], LINUX, allow_missing=False)


def test_allow_missing_connectors_refused_with_signing_key() -> None:
    with pytest.raises(SystemExit) as exc:
        pob.check_signing_conflict("udbmcp-release.pem", allow_missing=True)
    assert "signing" in str(exc.value)
    assert "incomplete wheelhouse" in str(exc.value)


def test_allow_missing_connectors_permitted_without_signing_key() -> None:
    pob.check_signing_conflict(None, allow_missing=True)
    pob.check_signing_conflict("udbmcp-release.pem", allow_missing=False)


# --- --connectors validation at the argparse boundary ---


def test_connectors_arg_rejects_unknown_connector_cleanly() -> None:
    parser = pob.build_arg_parser()
    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["--out", "out/x", "--connectors", "core,trino"])
    assert exc.value.code == 2  # clean argparse error, never a raw KeyError
    with pytest.raises(SystemExit) as exc2:
        parser.parse_args(["--out", "out/x", "--connectors", ""])
    assert exc2.value.code == 2


def test_connectors_arg_strips_whitespace_and_keeps_valid_names() -> None:
    parser = pob.build_arg_parser()
    # previously ' postgres' hit CONNECTOR_WHEELS[c] as ' postgres' -> KeyError
    ns = parser.parse_args(["--out", "out/x", "--connectors", " core , mssql "])
    assert ns.connectors == "core,mssql"
    ns = parser.parse_args(["--out", "out/x"])
    assert ns.connectors == "core,postgres,mysql,clickhouse,oracle,mssql,db2"


# --- OS-package closure: fail loud on incomplete staged .debs ---


def test_stage_os_packages_fails_when_sums_declares_absent_deb(tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    staging.mkdir()
    (staging / "msodbcsql18_18.4.1.1-1_amd64.deb").write_bytes(b"payload")
    digest = hashlib.sha256(b"payload").hexdigest()
    (staging / "SHA256SUMS").write_text(
        f"{digest}  msodbcsql18_18.4.1.1-1_amd64.deb\n"
        f"{hashlib.sha256(b'x').hexdigest()}  unixodbc_2.3.12-1_amd64.deb\n"
    )
    out = tmp_path / "bundle"
    out.mkdir()
    with pytest.raises(SystemExit, match="incomplete"):
        pob.stage_os_packages(out, staging)
    # nothing was copied: the bundle must not declare files it does not ship
    assert not (out / "os-packages" / "SHA256SUMS").exists()


def test_os_package_closure_refused_with_signing_key_when_incomplete() -> None:
    prof = PROFILES[LINUX]
    for closure in ([], [{"package": "unixodbc"}]):  # absent, and present-but-no-driver
        with pytest.raises(SystemExit) as exc:
            pob.check_os_package_closure(["core", "mssql"], closure, prof, "key.pem")
        assert "OS-package closure" in str(exc.value)
        assert "signed" in str(exc.value)


def test_os_package_closure_warns_loudly_without_signing_key(
    tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    prof = PROFILES[LINUX]
    for closure in ([], [{"package": "unixodbc"}]):
        assert pob.check_os_package_closure(["core", "mssql"], closure, prof, None) is False
        err = capsys.readouterr().err
        assert "WARNING" in err
        assert "administrator_supplied" in err


def test_os_package_closure_passes_when_msodbcsql18_is_vendored() -> None:
    prof = PROFILES[LINUX]
    assert pob.check_os_package_closure(
        ["core", "mssql"], [{"package": "unixodbc"}, {"package": "msodbcsql18"}], prof, "key.pem",
    ) is True
    # native profiles stage no OS packages: mssql stays administrator_supplied
    assert pob.check_os_package_closure(["core", "mssql"], [], PROFILES[MACOS], "key.pem") is False


def test_os_package_closure_refuses_msodbcsql18_without_unixodbc_for_signed_build() -> None:
    # Mirror of verify_bundle.py's second closure rule: any bundle declaring
    # msodbcsql18 without unixodbc is refused unconditionally, so a signed
    # build must fail here instead of producing an unverifiable release.
    prof = PROFILES[LINUX]
    for connectors in (["core", "mssql"], ["core"]):  # rule fires regardless of selection
        with pytest.raises(SystemExit) as exc:
            pob.check_os_package_closure(
                connectors, [{"package": "msodbcsql18", "file": "msodbcsql18.deb"}], prof, "key.pem",
            )
        assert "unixodbc" in str(exc.value)
        assert "signed" in str(exc.value)


def test_os_package_closure_warns_when_msodbcsql18_lacks_unixodbc_unsigned(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Unsigned builds keep building (no signed-release guarantee to protect),
    # but never silently: the bundle would fail verification on the target.
    prof = PROFILES[LINUX]
    assert pob.check_os_package_closure(
        ["core", "mssql"], [{"package": "msodbcsql18", "file": "msodbcsql18.deb"}], prof, None,
    ) is True
    err = capsys.readouterr().err
    assert "WARNING" in err
    assert "unixodbc" in err


def test_os_package_closure_unixodbc_without_driver_still_fine(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Rule 1 only fires when the driver is declared; a unixODBC-only staging
    # dir keeps the existing mssql-demotion semantics (admin-supplied driver),
    # so no rule-1 message and only the usual rule-2 unsigned warning.
    prof = PROFILES[LINUX]
    assert pob.check_os_package_closure(
        ["core", "mssql"], [{"package": "unixodbc", "file": "unixodbc.deb"}], prof, None,
    ) is False
    err = capsys.readouterr().err
    assert "WARNING" in err
    assert "declares msodbcsql18 without" not in err


# --- pip download command: repeated --platform flags ---


def _platform_flags(cmd: list[str]) -> list[str]:
    return [cmd[i + 1] for i, v in enumerate(cmd) if v == "--platform"]


def test_pip_command_linux_uses_single_manylinux_platform() -> None:
    cmd = pob.pip_download_command(PROFILES[LINUX], ["pyodbc"], Path("wh"), Path("c.txt"))
    assert _platform_flags(cmd) == ["manylinux2014_x86_64"]
    assert cmd[cmd.index("--python-version") + 1] == "3.12"
    assert cmd[cmd.index("--abi") + 1] == "cp312"


def test_pip_command_windows_uses_win_amd64() -> None:
    cmd = pob.pip_download_command(PROFILES[WINDOWS], ["pyodbc"], Path("wh"), Path("c.txt"))
    assert _platform_flags(cmd) == ["win_amd64"]


def test_pip_command_macos_passes_repeated_platform_flags() -> None:
    cmd = pob.pip_download_command(PROFILES[MACOS], ["ibm-db"], Path("wh"), Path("c.txt"))
    assert _platform_flags(cmd) == ["macosx_11_0_arm64", "macosx_14_0_arm64"]


# --- verifier-side host matching (registry-driven, platform-independent) ---


def test_profile_host_mismatches_report_os_arch_and_python(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(prof_mod.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(prof_mod.platform, "machine", lambda: "arm64")
    monkeypatch.setattr(prof_mod.platform, "python_version", lambda: "3.12.3")
    # macOS/arm64 host matches the macos profile exactly
    assert profile_host_mismatches(PROFILES[MACOS]) == []
    # ...but the linux profile mismatches on the operating system
    linux_mismatch = profile_host_mismatches(PROFILES[LINUX])
    assert any("operating system" in m for m in linux_mismatch)

    monkeypatch.setattr(prof_mod.platform, "machine", lambda: "x86_64")
    arch_mismatch = profile_host_mismatches(PROFILES[MACOS])
    assert any("machine architecture" in m for m in arch_mismatch)

    monkeypatch.setattr(prof_mod.platform, "python_version", lambda: "3.11.9")
    py_mismatch = profile_host_mismatches(PROFILES[MACOS])
    assert any("3.11" in m for m in py_mismatch)


def test_verify_bundle_loads_profile_registry_from_scripts_dir() -> None:
    spec = importlib.util.spec_from_file_location(
        "verify_bundle_under_test", PROJECT / "scripts" / "verify_bundle.py"
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    profiles = mod.load_profiles_module()
    assert set(profiles.PROFILES) == {LINUX, WINDOWS, MACOS}
