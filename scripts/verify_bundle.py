#!/usr/bin/env python3
"""Stage B, step 1: validate the offline bundle before installation.

Runs on the air-gapped target with no network. Checks:
- manifest present and parses; profile matches this machine
- every file matches SHA256SUMS (integrity)
- SIGNATURE verifies against an independently distributed Ed25519 public key
  (authenticity; pass --pubkey to enforce)
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
    manifest = json.loads(manifest_p.read_text())
    profile = manifest["profile"]

    # profile compatibility
    if "linux-x86_64" in profile:
        if platform.system() != "Linux" or platform.machine() not in ("x86_64", "AMD64"):
            if args.allow_platform_mismatch:
                print(
                    f"WARNING: verifying a linux-x86_64 bundle on "
                    f"{platform.system()}/{platform.machine()}. This is a STAGING-side "
                    f"integrity/authenticity check only. The bundle must still be verified "
                    f"WITHOUT this flag on the actual install target."
                )
            else:
                fail(f"bundle profile '{profile}' does not match this platform "
                     f"({platform.system()}/{platform.machine()}); pass "
                     f"--allow-platform-mismatch only when verifying on a staging machine")
        if not sys.version.startswith("3.12") and not args.allow_platform_mismatch:
            fail(f"bundle profile requires CPython 3.12; running {platform.python_version()}")

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
        # or left by a partial regeneration) is a failure
        for f in bundle.rglob("*"):
            if f.is_file() and f.name not in ("SHA256SUMS", "SIGNATURE") and f.resolve() not in listed:
                fail(f"file present in bundle but NOT covered by SHA256SUMS: {f.relative_to(bundle)}")
        print(f"integrity: {checked} artifacts checked, full coverage verified")

    # authenticity
    sig = bundle / "SIGNATURE"
    if not args.pubkey and sig.exists():
        # A signed bundle MUST be verifiable: refusing to proceed without the
        # key prevents 'verify without authenticity' becoming the norm.
        fail("bundle is signed but no --pubkey was provided; obtain the release "
             "public key through your trusted channel and verify before installing")
    if args.pubkey:
        if not sig.exists():
            fail("SIGNATURE missing but a public key was provided for verification")
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
        print("signature: NOT verified (no --pubkey given); authenticity unproven")

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
    # swapped after signing).
    os_packages = manifest.get("os_packages") or {}
    entries = os_packages.get("packages") if isinstance(os_packages, dict) else None
    if entries:
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
        # dependency closure sanity: msodbcsql18 cannot be configured without
        # the unixODBC stack, and a selected mssql connector without the driver
        # deb means the shipped closure is incomplete (not admin-supplied).
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
