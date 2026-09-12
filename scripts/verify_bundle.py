#!/usr/bin/env python3
"""Stage B, step 1: validate the offline bundle before installation.

Runs on the air-gapped target with no network. Checks:
- manifest present and parses; profile matches this machine
- every file matches SHA256SUMS (integrity)
- SIGNATURE verifies against an independently distributed Ed25519 public key
  (authenticity; --pubkey is REQUIRED — without it the verdict is always
  FAILED, because integrity alone proves nothing against an attacker who can
  rewrite SHA256SUMS)
- wheelhouse satisfies runtime.lock: every pinned requirement has a wheel
  with the exact recorded hash
- declared os_packages (.deb closure) exist and match the manifest hashes,
  and no undeclared .deb is present
- declared administrator-supplied artifacts are listed, not silently absent

Fails before anything is installed; prints actionable failures.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import re
import subprocess
import sys
from pathlib import Path

WHEEL_RE = re.compile(r"^(?P<name>[^-]+)-(?P<ver>[^-]+)-[^-]+-[^-]+-[^-]+\.whl$")


def load_profiles_module():
    """Import scripts/profiles.py (the target-profile registry).

    The verifier travels on the trusted channel, outside this repository, so
    the registry is located next to this file (as shipped in trusted-tools/)
    or in its lib/ directory. Missing registry = fail closed.
    """
    here = Path(__file__).resolve().parent
    for base in (here, here / "lib"):
        if (base / "profiles.py").is_file():
            if str(base) not in sys.path:
                sys.path.insert(0, str(base))
            import profiles  # type: ignore[import-not-found]

            return profiles
    raise ImportError("profiles.py not found next to this verifier or in its lib/ directory")


def fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    global failed
    failed = True


failed = False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bundle", required=True)
    ap.add_argument("--pubkey", default=None, help="Ed25519 public key PEM; required to verify signatures")
    ap.add_argument("--allow-platform-mismatch", action="store_true",
                    help="staging-side verification on a machine whose platform differs from "
                         "the bundle profile; prints a loud warning and skips the local "
                         "python-version check. NEVER use this on the install target.")
    args = ap.parse_args()

    bundle = Path(args.bundle)
    manifest_p = bundle / "manifest.json"
    if not manifest_p.exists():
        fail(f"manifest.json missing in {bundle}")
        return 1
    try:
        manifest = json.loads(manifest_p.read_text())
        profile = manifest["profile"]
    except (ValueError, KeyError, TypeError) as exc:
        fail(f"manifest.json is unreadable or not a valid manifest ({exc}); "
             "re-copy the bundle from your trusted channel and re-run")
        return 1

    # profile compatibility: registry lookup (scripts/profiles.py) replaces the
    # previously hardcoded 'linux-x86_64' branch. Known profiles are checked
    # against their declared target; unknown profiles (not from this registry)
    # only draw a loud warning — integrity/authenticity above still cover them.
    try:
        profiles = load_profiles_module()
        prof = profiles.PROFILES.get(profile)
        if prof is None:
            print(f"WARNING: unknown bundle profile '{profile}' (this verifier knows: "
                  f"{', '.join(sorted(profiles.PROFILES))}); skipping platform compatibility check")
        else:
            mismatches = profiles.profile_host_mismatches(prof)
            if mismatches:
                if args.allow_platform_mismatch:
                    print(
                        f"WARNING: verifying a {profile} bundle on "
                        f"{platform.system()}/{platform.machine()}. This is a STAGING-side "
                        f"integrity/authenticity check only. The bundle must still be verified "
                        f"WITHOUT this flag on the actual install target."
                    )
                else:
                    fail(f"bundle profile '{profile}' does not match this machine "
                         f"({platform.system()}/{platform.machine()}/"
                         f"{platform.python_version()}): {'; '.join(mismatches)}; pass "
                         f"--allow-platform-mismatch only when verifying on a staging machine")
    except Exception as exc:  # pragma: no cover - fail closed on any registry problem
        fail(f"cannot load the target-profile registry: {exc}. Install profiles.py "
             f"next to this verifier (trusted-tools ships it) and re-run")

    # integrity
    sums = bundle / "SHA256SUMS"
    if not sums.exists():
        fail("SHA256SUMS missing")
    else:
        checked = 0
        listed: set[Path] = set()
        for line in sums.read_text().splitlines():
            if not line.strip():
                continue
            digest, _, rel = line.partition("  ")
            f = bundle / rel
            if f.resolve().parent != bundle.resolve() and not f.resolve().is_relative_to(bundle.resolve()):
                fail(f"SHA256SUMS path escapes the bundle directory: {rel}")
                continue
            listed.add(f.resolve())
            if not f.exists():
                fail(f"missing artifact: {rel}")
                continue
            actual = hashlib.sha256(f.read_bytes()).hexdigest()
            if actual != digest:
                fail(f"tampered artifact: {rel} (sha256 mismatch)")
            checked += 1
        # every file on disk must be accounted for: an unlisted file (planted
        # or left by a partial regeneration) is a failure. Exempt: checksum
        # listings named SHA256SUMS (the trusted build tool writes a per-image
        # images/SHA256SUMS next to the tars; these listings are inert — only
        # the root one is ever the verification basis) and the bundle-root
        # SIGNATURE. A file merely NAMED "SIGNATURE" in a subdirectory is NOT
        # exempt and must be covered like any other payload.
        root = bundle.resolve()
        for f in bundle.rglob("*"):
            if not f.is_file() or f.resolve() in listed:
                continue
            if f.name == "SHA256SUMS" or f.resolve() == root / "SIGNATURE":
                continue
            fail(f"file present in bundle but NOT covered by SHA256SUMS: {f.relative_to(bundle)}")
        print(f"integrity: {checked} artifacts checked, full coverage verified")

    # authenticity
    sig = bundle / "SIGNATURE"
    if args.pubkey:
        if not sig.exists():
            fail("SIGNATURE missing but a public key was provided for verification")
        elif not sums.exists():
            # already reported above ("SHA256SUMS missing"); there is no
            # signed data left to verify against
            pass
        else:
            data = (bundle / "SHA256SUMS").read_bytes()
            # OpenSSL 3.0's pkeyutl -rawin cannot read a non-seekable stdin
            # pipe ('unable to determine file size for oneshot operation'),
            # so the signed data goes through a temp file.
            import tempfile

            with tempfile.NamedTemporaryFile(delete=False) as tf:
                tf.write(data)
                tf_path = tf.name
            r = subprocess.run(
                ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", args.pubkey, "-rawin",
                 "-sigfile", str(sig), "-in", tf_path],
                capture_output=True,
            )
            Path(tf_path).unlink(missing_ok=True)
            if r.returncode != 0:
                # Some staging hosts ship LibreSSL, which rejects Ed25519
                # pkeyutl -rawin. Fall back to the python cryptography package
                # (same primitive, no network) before declaring failure.
                try:
                    from cryptography.exceptions import InvalidSignature
                    from cryptography.hazmat.primitives.serialization import load_pem_public_key

                    pub = load_pem_public_key(Path(args.pubkey).read_bytes())
                    pub.verify(sig.read_bytes(), data)
                    print("signature: verified against provided public key (python cryptography)")
                except ImportError:
                    # The canonical diagnostic must appear on EVERY rejection
                    # path (openssl-only hosts included): operators and the
                    # failure-mode gate match on it. The openssl detail is
                    # appended for diagnosis, never replaces it.
                    fail("signature verification FAILED (untrusted or corrupted "
                         "bundle); openssl rejected Ed25519 verification and no "
                         "cryptography fallback is installed: " + r.stderr.decode()[:200])
                except InvalidSignature:
                    fail("signature verification FAILED (untrusted or corrupted bundle)")
            else:
                print("signature: verified against provided public key")
    else:
        # Fail closed, unconditionally: integrity alone proves nothing, since
        # an attacker who can touch the bundle can also regenerate unsigned
        # SHA256SUMS (and delete SIGNATURE). Without --pubkey this verifier
        # must never certify the bundle — no PASSED verdict, exit nonzero.
        if sig.exists():
            # A signed bundle MUST be verifiable: refusing to proceed without
            # the key prevents 'verify without authenticity' becoming the norm.
            fail("bundle is signed but no --pubkey was provided; obtain the release "
                 "public key through your trusted channel and verify before installing")
        else:
            print("signature: NOT verified (no --pubkey given); authenticity unproven")
        fail("authenticity NOT verified: obtain the release public key through "
             "your trusted channel and re-run with --pubkey before installing")

    # wheelhouse satisfies runtime.lock
    lock = bundle / "requirements" / "runtime.lock"
    wh = bundle / "wheelhouse"
    if not lock.exists() or not wh.exists():
        fail("requirements/runtime.lock or wheelhouse missing")
    else:
        by_hash = {hashlib.sha256(w.read_bytes()).hexdigest(): w for w in wh.glob("*.whl")}
        n = 0
        for line in lock.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"^([A-Za-z0-9._-]+)==(\S+) --hash=sha256:([0-9a-f]{64})$", line)
            if not m:
                fail(f"runtime.lock line is not a pinned+hashed requirement: {line[:60]}")
                continue
            name, ver, digest = m.groups()
            w = by_hash.get(digest)
            if w is None:
                fail(f"wheel missing from wheelhouse: {name}=={ver}")
            else:
                wm = WHEEL_RE.match(w.name)
                if not wm or wm.group("name").replace("_", "-").lower() != name or wm.group("ver") != ver:
                    fail(f"wheelhouse artifact does not match lock: {line[:40]} vs {w.name}")
            n += 1
        print(f"runtime.lock: {n} pinned requirements checked against wheelhouse")
        app_wheel = [w for w in wh.glob("*.whl") if w.name.startswith("universal_db_mcp-")]
        if not app_wheel:
            fail("application wheel is not in the wheelhouse (source installs are not permitted)")

    # declared-but-missing artifacts
    missing = manifest.get("connector_wheel_status", {}).get("missing_from_closure", [])
    if missing:
        print("WARN: manifest declares missing driver artifacts (affected connectors "
              f"cannot pass readiness checks): {', '.join(missing)}")

    admin = manifest.get("administrator_supplied", {})
    if admin:
        print("NOTE: administrator-supplied prerequisites (not distributable):")
        for k, v in admin.items():
            print(f"  - {k}: {v}")

    # os-packages: every declared .deb must exist with the manifest hash, and
    # every .deb shipped on disk must be declared (nothing extra, nothing
    # swapped after signing). Enforced even when the manifest declares no
    # packages: os_packages.sh falls back to running every .deb found in
    # os-packages/, so an undeclared .deb must never slip through a manifest
    # with an empty os_packages section.
    os_packages = manifest.get("os_packages") or {}
    entries = os_packages.get("packages") if isinstance(os_packages, dict) else None
    entries = list(entries) if entries else []
    osp_dir = bundle / "os-packages"
    declared_files: set[Path] = set()
    declared_names: set[str] = set()
    ok_count = 0
    for entry in entries:
        fname = str(entry.get("file", ""))
        rel = str(entry.get("path") or f"os-packages/{fname}")
        f = bundle / rel
        declared_files.add(f.resolve())
        declared_names.add(str(entry.get("package", "")))
        if not fname or not f.exists():
            fail(f"os package declared in manifest but missing from bundle: {rel}")
            continue
        actual = hashlib.sha256(f.read_bytes()).hexdigest()
        if actual != entry.get("sha256"):
            fail(f"tampered os package: {rel} (manifest sha256 mismatch)")
            continue
        ok_count += 1
    if osp_dir.exists():
        for f in sorted(osp_dir.glob("*.deb")):
            if f.resolve() not in declared_files:
                fail(f".deb present in os-packages but not declared in manifest.json: {f.name}")
    print(f"os-packages: {ok_count}/{len(entries)} declared .deb artifacts hash-checked")
    if entries:
        # dependency closure sanity: msodbcsql18 cannot be configured without
        # the unixODBC stack, and a selected mssql connector without the driver
        # deb means the shipped closure is incomplete (not admin-supplied).
        # (Only meaningful when the manifest declares deb packages at all:
        # macOS/Windows bundles legitimately ship none.)
        if "msodbcsql18" in declared_names and "unixodbc" not in declared_names:
            fail("os_packages closure incomplete: msodbcsql18 requires unixodbc")
        if "mssql" in manifest.get("selected_connectors", []) and "msodbcsql18" not in declared_names:
            fail("os_packages closure incomplete: mssql connector is selected but "
                 "msodbcsql18 is not among the declared os_packages")

    if failed:
        print("\nbundle verification FAILED; do not install")
        return 1
    print("\nbundle verification PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
