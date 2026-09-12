"""Target-profile registry for the offline bundle builder and verifier.

Single source of truth for every parameter that varies per install target:
the pip download tags, the manifest "target" block, the staged OS-package
closure and the baseline container image. scripts/prepare_offline_bundle.py
and scripts/verify_bundle.py both read from PROFILES.

The linux-x86_64-ubuntu24.04-cp312 entry is byte-identical to the parameters
that were previously hardcoded in the builder, so the shipped profile is
behavior-neutral. windows-x86_64-cp312 and macos-arm64-cp312 install natively
(they stage no OS packages and carry no baseline image); pip accepts repeated
--platform flags, which is how the two macOS tags are requested.

scripts/verify_bundle.py also runs from the trusted-tools channel outside
this repository, where it locates profiles.py next to itself (or in lib/).
"""

from __future__ import annotations

import platform
from dataclasses import dataclass


@dataclass(frozen=True)
class Profile:
    """One supported install target."""

    name: str
    # pip download parameters for the TARGET interpreter (not the staging host)
    python_version: str
    abi: str
    pip_platforms: tuple[str, ...]  # passed as repeated --platform flags
    # manifest.json "target" block
    manifest_target: dict[str, str]
    # which running systems/machines this target matches (used by the verifier)
    host_systems: tuple[str, ...]
    host_machines: tuple[str, ...]
    # repo-relative staging directory of the OS-package (.deb) closure; None
    # for profiles that install natively without a staged closure
    os_packages_staging: str | None
    # baseline container image (OS + CPython only); None for native installs
    baseline_image: str | None
    # administrator-supplied mssql ODBC driver artifact, for the manifest
    # administrator_supplied wording (".deb" | ".msi" | ".pkg")
    odbc_driver_package: str


LINUX_PROFILE_NAME = "linux-x86_64-ubuntu24.04-cp312"

_PROFILES = (
    Profile(
        name=LINUX_PROFILE_NAME,
        python_version="3.12",
        abi="cp312",
        pip_platforms=("manylinux2014_x86_64",),
        manifest_target={"os": "ubuntu-24.04", "arch": "x86_64", "python": "3.12", "abi": "cp312"},
        host_systems=("Linux",),
        host_machines=("x86_64", "AMD64"),
        os_packages_staging="out/os-packages-ubuntu24.04",
        baseline_image="udbmcp-baseline:ubuntu24.04-cp312",
        odbc_driver_package=".deb",
    ),
    Profile(
        name="windows-x86_64-cp312",
        python_version="3.12",
        abi="cp312",
        pip_platforms=("win_amd64",),
        manifest_target={"os": "windows", "arch": "x86_64", "python": "3.12", "abi": "cp312"},
        host_systems=("Windows",),
        host_machines=("AMD64", "x86_64"),
        os_packages_staging=None,
        baseline_image=None,
        odbc_driver_package=".msi",
    ),
    Profile(
        name="macos-arm64-cp312",
        python_version="3.12",
        abi="cp312",
        pip_platforms=("macosx_11_0_arm64", "macosx_14_0_arm64"),
        manifest_target={"os": "macos", "arch": "arm64", "python": "3.12", "abi": "cp312"},
        host_systems=("Darwin",),
        host_machines=("arm64",),
        os_packages_staging=None,
        baseline_image=None,
        odbc_driver_package=".pkg",
    ),
)

PROFILES: dict[str, Profile] = {p.name: p for p in _PROFILES}


def get_profile(name: str) -> Profile:
    try:
        return PROFILES[name]
    except KeyError:
        raise SystemExit(
            f"unknown profile '{name}'; available profiles: {', '.join(sorted(PROFILES))}"
        ) from None


def profile_host_mismatches(profile: Profile) -> list[str]:
    """Describe how the RUNNING interpreter differs from the profile target.

    Empty list = this machine matches the profile. Checks operating system,
    machine architecture and CPython minor version — exactly the checks the
    previously hardcoded 'linux-x86_64' branch of scripts/verify_bundle.py
    performed, now derived from the registry.
    """
    system, machine = platform.system(), platform.machine()
    mismatches: list[str] = []
    if system not in profile.host_systems:
        mismatches.append(f"operating system {system} (target {profile.manifest_target['os']})")
    if machine not in profile.host_machines:
        mismatches.append(f"machine architecture {machine} (target {profile.manifest_target['arch']})")
    want_py = profile.manifest_target["python"]
    if not platform.python_version().startswith(want_py):
        mismatches.append(f"CPython {platform.python_version()} (target {want_py})")
    return mismatches
