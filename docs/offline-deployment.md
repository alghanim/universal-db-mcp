# Offline deployment (Stage B — inside the air gap)

## Prerequisites (verified platform baseline)

- Ubuntu 24.04, linux x86_64 (this profile; others are separate profiles).
- CPython 3.12 + venv: included in the bundle's baseline image for container
  mode; for native mode install from your approved internal mirror BEFORE
  transferring the bundle (record the exact patch version in the release
  record).
- Container engine (container mode): use the version in your approved
  baseline; the bundle's images are loaded with `docker load`, never pulled.

## Trust bootstrap (before install)

The verifier and installer must NOT come from inside the bundle they verify: a
tampered bundle would simply ship a verifier that prints PASSED. Install both
from the same trusted channel as the release public key, at a root-owned path
outside the bundle. The copies in the bundle's `installers/` directory are
reference copies only and are never executed.

```bash
# verify_bundle.py imports profiles.py from its own directory, and
# the installer sources lib/os_packages.sh relative to its own
# location: ALL of these files are required, a trust dir missing either
# aborts later (inside verify/install) with a diagnostic about the
# missing file instead of this bootstrap block.
sudo install -d -m 755 /usr/local/lib/udbmcp-trust
sudo install -m 644 <trusted-channel>/verify_bundle.py /usr/local/lib/udbmcp-trust/
sudo install -m 644 <trusted-channel>/profiles.py /usr/local/lib/udbmcp-trust/
sudo install -m 755 <trusted-channel>/install_offline.sh /usr/local/lib/udbmcp-trust/
sudo install -d -m 755 /usr/local/lib/udbmcp-trust/lib
sudo install -m 644 <trusted-channel>/lib/os_packages.sh /usr/local/lib/udbmcp-trust/lib/
```

Install the release public key at the path used throughout this runbook:

```bash
sudo install -d -m 755 /etc/universal-db-mcp /etc/universal-db-mcp/keys
sudo install -m 644 <trusted-path>/udbmcp-release.pub.pem /etc/universal-db-mcp/keys/release.pub.pem
```

## Native mode install

```bash
# transfer bundle into the air gap (approved media)
# optional pre-check with the TRUSTED verifier from the trust bootstrap above
# (do NOT use the bundle's installers/ reference copy for this: it ships
# without profiles.py, which verify_bundle.py imports from its own directory,
# so that check would fail even on a pristine bundle — the installer itself
# re-verifies with the trusted copy regardless):
sudo python3 /usr/local/lib/udbmcp-trust/verify_bundle.py \
  --bundle <bundle-dir> --pubkey /etc/universal-db-mcp/keys/release.pub.pem

# The installer HARD-REQUIRES the release public key and exits 1 without it:
# an unsigned/unverified bundle must never be installed.
export UDBMCP_RELEASE_PUBKEY=/etc/universal-db-mcp/keys/release.pub.pem
# sudo strips the environment, so pass the variable through explicitly:
sudo UDBMCP_RELEASE_PUBKEY="$UDBMCP_RELEASE_PUBKEY" \
  bash /usr/local/lib/udbmcp-trust/install_offline.sh <bundle-dir> /opt/universal-db-mcp
```

The installer:
1. verifies integrity and the Ed25519 signature (the key is mandatory:
   `UDBMCP_RELEASE_PUBKEY` must point at the trusted public key PEM),
2. checks the platform baseline (fails fast on wrong Python/ABI),
3. creates a fresh venv and installs with
   `--no-index --no-cache-dir --find-links=<wheelhouse> --only-binary=:all:
   --require-hashes`, with hostile inherited pip config neutralized
   (`PIP_CONFIG_FILE=/dev/null`, index env vars overridden).

Missing wheel / OS package / licensed driver: the verifier and doctor fail
with the exact artifact named. Nothing downloads; nothing falls back.

## OS packages (Microsoft ODBC Driver 18 for SQL Server)

The bundle ships the SQL Server ODBC driver packages for the target profile
(ubuntu 24.04 amd64): `msodbcsql18` and its `unixodbc` dependencies are
staged in bundle `os-packages/` with sha256 hashes recorded in
`SHA256SUMS` (staged and wired into the builder/installer; included in the
next bundle build). The installer installs them automatically with `dpkg`
in dependency order (`odbcinst`/`libodbc2`/`libodbcinst2`/`unixodbc-common`
before `unixodbc`/`msodbcsql18`), offline — no repository access — and
idempotently: packages already installed at the required version are left
untouched, so re-running the installer is safe.

**EULA:** installing the `msodbcsql18` package constitutes accepting the
Microsoft ODBC driver EULA. The bundle merely carries the package; the
acceptance decision belongs to the administrator and is recorded at install
time.

After install, `doctor` reports driver presence explicitly: it checks for
the installed ODBC Driver 18 and names it in its output, so a missing or
mismatched driver is reported as the specific failing artifact rather than
surfacing later as an opaque connection error.

## Configure

```bash
# The installer creates the udbmcp service account and the state directories.
# The release public key was already installed under /etc/universal-db-mcp/keys
# during the trust bootstrap (it must exist BEFORE the installer runs).
sudo install -o udbmcp -g udbmcp -m 640 bundle/config-templates/config.yaml /etc/universal-db-mcp/config.yaml
sudo install -o udbmcp -g udbmcp -m 600 <secret> /run/secrets/<connection>_password
# edit /etc/universal-db-mcp/config.yaml for your connections
sudo -u udbmcp /opt/universal-db-mcp/venv/bin/python -m universal_db_mcp doctor
```

Doctor checks wheels, TLS material, secret-file permissions, writable paths,
and policy consistency — no database credentials required.

The installers also link a short CLI alias into `/usr/local/bin`: every
command can be run as `udbmcp doctor`, `udbmcp add-connection`,
`udbmcp configure-agents` — equivalent to the long
`<venv>/bin/python -m universal_db_mcp ...` form used in the examples.

## Service

```bash
sudo install -m 644 bundle/operations/universal-db-mcp.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now universal-db-mcp
```

The unit runs as the dedicated `udbmcp` account with a hardened sandbox
(read-only FS, explicit writable paths, no privileges).

The daemon runs in **HTTP mode** (`serve --transport http`): a service-manager
daemon has no client on stdin, so the config template's `stdio` default would
read EOF and exit 0 immediately. The listener's only authentication is a
bearer token; the unit points at `/etc/universal-db-mcp/http-token` via
`UDBMCP_HTTP_BEARER_TOKEN_FILE`, which the package postinst provisions (0600,
owned `udbmcp`) when absent. A manual unit-only install must create it the
same way:

```bash
sudo install -d -o root -g root -m 755 /etc/universal-db-mcp
if [ ! -s /etc/universal-db-mcp/http-token ]; then
  # only-if-absent/empty: never clobber an existing token
  sudo install -o udbmcp -g udbmcp -m 600 /dev/null /etc/universal-db-mcp/http-token
  python3 -c 'import secrets; print(secrets.token_hex(32))' \
    | sudo tee -a /etc/universal-db-mcp/http-token >/dev/null
fi
```

An explicit `application.http_bearer_token_file` in the config always wins
over the unit's env fallback. Per-harness agent spawns keep using stdio and
are unaffected (the override only supplies the token PATH; the token value is
never carried in an environment variable).

## Container mode

Before starting, two prerequisites the bundle does **not** satisfy on its own:

1. **The application image tar must have been exported on the staging
   machine.** `scripts/prepare_offline_bundle.py` only creates the (empty)
   `images/` directory; `images/universal-db-mcp.tar` exists only if
   `docs/offline-build.md` steps 4 **and** 4b (`docker build` + `docker
   save`, then the SHA256SUMS/SIGNATURE refresh) were run. Without them the
   `docker load` below fails on a missing tar and container mode is not
   deployable from this bundle — use native mode instead.
2. **HTTP transport requires a bearer token.** The compose file runs
   `serve --transport http`, and the server exits immediately with
   `CONFIG_ERROR: http transport requires application.http_bearer_token_file`
   unless the mounted config sets that key and the token file exists:

   ```bash
   openssl rand -hex 32 | sudo tee /run/secrets/udbmcp_http_token >/dev/null
   sudo chmod 600 /run/secrets/udbmcp_http_token
   # then in /etc/universal-db-mcp/config.yaml set:
   #   application:
   #     http_bearer_token_file: /run/secrets/udbmcp_http_token
   ```

```bash
docker load -i <bundle>/images/udbmcp-baseline-ubuntu24.04-cp312.tar
docker load -i <bundle>/images/universal-db-mcp.tar
docker image inspect udbmcp/universal-db-mcp:0.1.0-linux-x86_64-ubuntu24.04-cp312  # identity check
docker network create --internal udbmcp-internal   # admin-managed
# the bundle ships the compose file under operations/, not packaging/
# (there is no packaging/ directory on the target):
docker compose -f <bundle>/operations/compose.offline.yaml up -d
```

`pull_policy: never` — an absent image fails locally; no registry contact.

## Install on Windows via .msi

The MSI packages the **signed Windows bundle** (`windows-x86_64-cp312`
profile) exactly as produced by `scripts/prepare_offline_bundle.py`; the
artifacts are `dist/universal-db-mcp-<version>-win-x86_64.msi` plus the
bundle's `SIGNATURE`/`SHA256SUMS`. The trust rule is the same as on Linux —
**nothing in the installed payload may be executed before an admin-installed
trusted verifier has cleared it**, and the release public key is NEVER
shipped inside the package (you distribute it out-of-band, exactly like the
pubkey on the native-mode path above). The enforcement mechanism here is a
chain of **deferred, `Impersonate="no"`, `Return="check"` custom actions**
authored in `packaging/msi/udbmcp.wxs` and implemented by the
`packaging/msi/custom/*.ps1` scripts that `scripts/package/build_msi.sh`
stages into the package. After `InstallFiles`, and in this strict order,
`msiexec` runs: (1) `VerifyBundleCA` — verify the installed bundle with the
ADMIN-installed trusted verifier and public key, (2) `BuildVenvCA` — build
the venv from the verified wheelhouse with `pip --no-index
--require-hashes` and `PIP_CONFIG_FILE` neutralized, (3) `DoctorSmokeCA` —
a `doctor` smoke check, the FIRST execution of payload code, strictly after
verification passed, and (4) `RegisterServiceCA` — `sc.exe` service
registration. Any nonzero exit rolls the whole install back, so a failed
verification can never leave a half-trusted install behind. What the MSI
does NOT do is ship the verifier or the public key: both are provisioned by
you (below) before `msiexec` runs, and the custom actions fail closed
without them.

### Prerequisites

- Windows x86_64 with local administrator rights (the MSI is per-machine).
- **CPython 3.12 from python.org, installed "for all users"** (64-bit). The
  installer's launch condition checks the per-machine PEP 514 registry key
  (`HKLM\SOFTWARE\Python\PythonCore\3.12\InstallPath`); a per-user install
  writes only HKCU and is deliberately rejected. Install this BEFORE running
  the MSI, from your approved media.
- The **Microsoft ODBC Driver 18 for SQL Server** MSI (see the ODBC section
  below) if you use mssql connections: on the Windows profile the driver is
  admin-supplied, not shipped in the bundle.
- An Ed25519 verification path for the trusted verifier: `openssl.exe` on
  PATH (e.g. from Git for Windows) or the `cryptography` package importable
  by CPython 3.12. With neither, verification fails closed.

### Trust bootstrap (before running the MSI)

The verifier must NOT come from inside the bundle it verifies: a tampered
bundle would ship a verifier that prints PASSED. Install the trusted tools
and the release public key from the same trusted channel that delivered the
MSI, at paths OUTSIDE the bundle. The trust directory MUST be
`C:\Program Files\udbmcp-trust`: the MSI's deferred verify custom action
resolves exactly that path (WiX `ProgramFiles64Folder`) via CustomActionData
and does NOT read a `UDBMCP_TRUST_DIR` environment override. `C:\Program
Files` is admin-write-only, so a non-admin process cannot pre-create (and
thereby own) the verifier that LocalSystem executes — the analogue of the
root-owned `/usr/local/lib/udbmcp-trust` on Linux/macOS:

```powershell
# 1. trusted verifier + its profile registry (plain copies; run via python.exe)
New-Item -ItemType Directory -Force "C:\Program Files\udbmcp-trust\lib"
Copy-Item <trusted-channel>\verify_bundle.py "C:\Program Files\udbmcp-trust\"
Copy-Item <trusted-channel>\profiles.py      "C:\Program Files\udbmcp-trust\"

# 2. release public key (distributed out-of-band by the release administrator)
New-Item -ItemType Directory -Force "$env:ProgramData\universal-db-mcp\keys"
Copy-Item <trusted-path>\udbmcp-release.pub.pem `
    "$env:ProgramData\universal-db-mcp\keys\udbmcp-release.pub.pem"

# 3. point the installer at the key (machine scope)
setx /M UDBMCP_RELEASE_PUBKEY "C:\ProgramData\universal-db-mcp\keys\udbmcp-release.pub.pem"
```

Optional override (machine scope, `setx /M`): `UDBMCP_PYTHON` (explicit
interpreter for the verifier). The trust directory itself is NOT
env-overridable for the MSI: the installer pins it to
`C:\Program Files\udbmcp-trust` via CustomActionData, so the trusted tools
must be provisioned at that exact path before `msiexec` runs.

The verifier fails closed — exits nonzero with a diagnostic — if any of
these are missing, if the trust directory, the public key, or the Python
interpreter resolve INSIDE the installed bundle, or on any signature or
hash mismatch; on success it prints its explicit `bundle verification
PASSED` proof. This bootstrap MUST happen before `msiexec` runs: the MSI's
deferred `VerifyBundleCA` custom action executes during the install, runs
as LocalSystem (so it sees machine-scope environment only), and invokes
this same trusted verifier with the same public key. With the trust
directory or key absent, the action exits nonzero and `msiexec` rolls the
install back. The action's output is persisted to
`C:\ProgramData\universal-db-mcp\install-verify.log` for the post-mortem;
after the install, confirm it contains the exact `bundle verification
PASSED` line (below).

### Install

```bat
msiexec /i dist\universal-db-mcp-0.1.0-win-x86_64.msi /l*v udbmcp-install.log
```

Always pass `/l*v`: the MSI log is the install's post-mortem record.
Run from an elevated prompt. During the install the custom actions run in
their strict order (verify → venv → doctor → service); a failure at any
step aborts and rolls back the install. Layout after a successful install:

- `C:\Program Files\UniversalDB MCP\bundle\` — the signed bundle payload
  (harvested verbatim; only ever READ by the verifier first),
- `C:\Program Files\UniversalDB MCP\scripts\` — the custom action scripts
  (`verify.ps1`, `venv.ps1`, `doctor.ps1`, `service.ps1`, `uninstall.ps1`),
  installed as a SIBLING of `bundle\`, never inside it: `verify.ps1`
  refuses to run from inside the bundle (a verifier shipped in the payload
  would be a tampered verifier that prints PASSED),
- `C:\Program Files\UniversalDB MCP\venv\` — created by `BuildVenvCA` from
  the verified wheelhouse (`pip --no-index --require-hashes`,
  `PIP_CONFIG_FILE=NUL`, proxy/index env vars scrubbed, `--isolated`,
  `--only-binary=:all:`),
- `C:\ProgramData\UniversalDB MCP\config.yaml` — config template, installed
  once and never overwritten on upgrade/repair (edit for your connections),
- `C:\ProgramData\universal-db-mcp\install-verify.log` — the verifier
  output written by `VerifyBundleCA`.

The MSI performs the verify → venv → doctor → service sequence itself; you
do not repeat it manually. Your post-install duties:

1. **Read the post-mortem**: confirm `udbmcp-install.log` shows the custom
   actions ran, and `C:\ProgramData\universal-db-mcp\install-verify.log`
   contains the exact `bundle verification PASSED` line. (The install
   cannot complete without it — `Return="check"` rolls back on any nonzero
   exit — but a rollback you did not notice is still a failed install; make
   the log check explicit.) A missing PASSED line is a hard stop: do not
   start the service, do not execute payload.
2. **Check the service registration**: `sc.exe query udbmcp` should show
   the service created by `RegisterServiceCA` (auto start) — see
   [Service management](#service-management-scexe) below.
3. **Edit `config.yaml`** for your connections (the service reads it via
   its `Environment` registry value, written by `service.ps1`), then start
   the service when your configuration is ready.

### Microsoft ODBC Driver 18 for SQL Server (admin-supplied)

On Windows the bundle does NOT carry the driver: `msodbcsql18` is Microsoft-
licensed software, so the administrator obtains the driver MSI from the
approved media and installs it before or after the udbmcp install (no
specific order is required — `doctor` and the mssql connector both check for
the driver at use time and name it explicitly if missing). Installing the
driver MSI constitutes accepting the Microsoft EULA; that acceptance decision
belongs to the administrator.

Verify the driver registration with the 64-bit ODBC Administrator
(`C:\Windows\System32\odbcad32.exe`) → *Drivers* tab, expecting
`ODBC Driver 18 for SQL Server`. (The 32-bit `odbcad32.exe` under
`SysWOW64` will not show it and is not relevant here.)

### Service management (sc.exe)

The MSI registers the service itself: the deferred `RegisterServiceCA`
action runs `service.ps1`, which creates an auto-start service named
`udbmcp` running
`"<venv>\Scripts\python.exe" -m universal_db_mcp serve --transport http`
(account LocalSystem
by default; override with the public `UDBMCP_SERVICE_ACCOUNT` property on
the `msiexec` command line or the machine-scope `UDBMCP_SERVICE_ACCOUNT`
environment value — values containing quotes or line breaks are rejected,
fail closed) with failure recovery mirroring the systemd unit
(`Restart=on-failure`: restart after 60000 ms, counter reset after 86400 s)
and `UDBMCP_CONFIG` + `UDBMCP_HTTP_BEARER_TOKEN_FILE` injected via the
service's `Environment` registry value. A daemon under the SCM has no stdin
client, so HTTP transport is forced (the config's `stdio` default would exit
0 immediately); the HTTP listener's only authentication is a bearer token
that the action provisions at `<config dir>\http-token` (only if absent or
empty, never clobbered, value never printed). `start= auto` registers the
service for automatic start; the admin
(or the gate script) starts it once the configuration is in place. For
inspection and manual recovery, the equivalent commands:

```bat
sc.exe create udbmcp binPath= "\"C:\Program Files\UniversalDB MCP\venv\Scripts\python.exe\" -m universal_db_mcp serve --transport http" start= auto
sc.exe failure udbmcp reset= 86400 actions= restart/60000/restart/60000//0
REM sc.exe has no env= option. The service environment is a REG_MULTI_SZ
REM value named Environment directly under the service key:
reg add "HKLM\SYSTEM\CurrentControlSet\Services\udbmcp" /v Environment /t REG_MULTI_SZ /d "UDBMCP_CONFIG=C:\ProgramData\UniversalDB MCP\config.yaml" /f
sc.exe query udbmcp
sc.exe start udbmcp
sc.exe stop udbmcp
sc.exe delete udbmcp   &rem uninstall DOES this (RemoveServiceCA); manual removal only
```

### Upgrade and downgrade

The MSI has a fixed `UpgradeCode` and WiX `MajorUpgrade`:

- **Upgrade** (newer version over older): the old version is removed first
  (its `RemoveServiceCA` stops and deletes the `udbmcp` service) and the
  new payload installed; the full verify → venv → doctor → service sequence
  then re-runs automatically against the fresh payload — the venv is built
  from scratch from the newly verified wheelhouse (never a stale mix),
  `doctor` re-runs, and the service is re-registered. `config.yaml` is left
  untouched (`NeverOverwrite`).
- **Downgrade** (older over newer): refused with "A newer version of
  UniversalDB MCP is already installed." Downgrading intentionally requires
  uninstalling the newer version first — an explicit admin decision.
- **Uninstall** removes the install tree; the `RemoveServiceCA` action stops
  and deletes the `udbmcp` service first (before `RemoveFiles` deletes the
  script that performs the removal). `config.yaml` under
  `C:\ProgramData\UniversalDB MCP\` is
  NOT retained: the component's `NeverOverwrite` protects it at install/repair
  time only, not at uninstall (unlike the .deb conffile behavior) — back it up
  before uninstalling if you want to keep your edits.

### Status (honest)

**The custom actions ARE authored and wired.** `packaging/msi/udbmcp.wxs`
contains the `<CustomAction>` elements (`SetPowerShellExe`,
`VerifyBundleCA`, `BuildVenvCA`, `DoctorSmokeCA`, `RegisterServiceCA`,
`RollbackRemoveServiceCA`, `RemoveServiceCA`) and the
`<InstallExecuteSequence>` that schedules them (verify after `InstallFiles`,
then venv → doctor → service, the rollback twin before the register action,
and service removal before `RemoveFiles` on uninstall), and
`scripts/package/build_msi.sh` stages `packaging/msi/custom/*.ps1` and
passes their directory to `wix build` as
`-define CustomActionScriptsDir=...`, so the scripts ship inside the
compiled MSI. The manual verify/venv/service sequence described in earlier
revisions of this document is gone: the package enforces
verify-before-execute itself.

**The MSI has never been compiled — but not for lack of trying.** The
plan-Phase-0 prerequisites ARE installed on this staging host (user-local
.NET 8 SDK `8.0.425` + the `wix` global dotnet tool), and
`scripts/package/build_msi.sh` was executed end-to-end against a freshly
built, SIGNED `windows-x86_64-cp312` bundle (release `0.1.0`, 42 wheels, no
missing connectors). Every first-party build step ran and passed:
trusted-channel `verify_bundle.py --pubkey` verification of the source
bundle (79 artifacts, signature verified), payload staging with a
no-key-material scan, deterministic harvest, `xmllint` validation, and a
real `wix` invocation that reached full authoring validation. Evidence:
`out/package-evidence/msi/results.json` and
`out/package-evidence/msi/build-msi-build-only.log`.

The compile itself does NOT complete on this host, and cannot on ANY Unix
host: current WiX (v4.0.5, 5.0.2 and 6.0.2 all tested) rejects every
`Directory/@Name` with error **WIX0389** ("... is not a relative path") —
`BundleValidator.GetCanonicalRelativePath` does
`Path.GetFullPath("C:\" + name)` and requires the result to start with
`C:\`, which no Unix `GetFullPath` can ever produce (ShortName-only
directories are rejected too). The 15 WIX0389 errors are the ONLY remaining
failures — the same authoring compiles past all first-party errors — so
this is a WiX-on-Unix toolchain limitation, not an authoring defect. MSI
compilation therefore requires a **Windows** staging host with the same
Phase-0 prerequisites.

The signed `windows-x86_64-cp312` bundle this run targeted exists at
`out/bundle-windows/universal-db-mcp-0.1.0-windows-x86_64-cp312`
(`SIGNATURE` + `SHA256SUMS`; trusted verifier tooling one level up at
`out/bundle-windows/trusted-tools/`). No MSI artifact was produced here and
none may be claimed. The only `*.msi` file that ever appeared in `dist/`
(`universal-db-mcp-1.2.3-win-x86_64.msi`) was a 12-byte placeholder whose
content was the literal text `FAKE` after the OLE compound-document magic —
not an MSI, not produced by `build_msi.sh`, and its `1.2.3` version matched
nothing in the signed manifest release (0.1.0); it has been removed and no
`*.msi` exists in `dist/` now. If you ever find an `*.msi` in `dist/` on
this host, treat any such file as debris unless it is accompanied by a
`build_msi.sh` run log and its version matches the signed manifest
release.

Consequently every Windows row — the compile sanity checks themselves
(`file` showing a Composite Document File, payload inspection of the
compiled package) as well as the custom-action runtime behavior
(verification, venv build, doctor smoke, service registration and rollback,
uninstall service removal), the msodbcsql MSI interplay, and NTFS ACL
behavior — is `not_run`, and no "passed"/"verified" wording may be read
into this section for any Windows runtime step (the first-party build-side
passes recorded in `out/package-evidence/msi/results.json` cover bundle
verification, harvest, validation and the WiX invocation only — not
runtime behavior, and they produced no MSI). The release ledger records the
Windows `.msi` as **NOT built** with the install gate `not_run`.

Before a Windows deployment can be trusted: (1) on a **Windows** staging
host with the Phase-0 prerequisites (.NET 8 SDK + `dotnet tool install
--global wix`) — a Unix host cannot work, per the WIX0389 limitation above —
run `scripts/package/build_msi.sh` against a freshly built and signed
`windows-x86_64-cp312` bundle (the build-side authoring has already been
exercised as far as a Unix host allows, with all first-party steps passing;
only the final WiX compile step remains); (2) on a real Windows machine, run
`scripts/test_package_msi.ps1`: `msiexec /i /l*v`, `sc.exe query`, doctor,
stdio protocol probe, a tamper negative case, and evidence JSON — and
record its results in the release ledger. Until both have passed, this
section describes delivered authoring, not exercised behavior.

## Claude Code registration

See `docs/claude-code-integration.md` and `examples/claude-code/.mcp.json`.

## Install on Ubuntu via .deb

The `.deb` carries the **signed** offline bundle as its payload
(`/usr/share/universal-db-mcp/bundle/`) plus an INERT reference copy of the
trusted tools (`/usr/share/universal-db-mcp/trusted-tools/` — the package
never executes it and never bootstraps the trust dir from it; see the
postinst walk-through below). It follows the same
verify-before-execute model as everything else in this release: **no payload
byte is ever executed before a trusted `verify_bundle.py --pubkey` run has
passed.** Because dpkg unpacks the payload only *after* the `preinst` runs,
the package splits the work honestly:

- **`preinst`** checks the trust *prerequisites* only and **fails closed
  (exit 1, dpkg aborts)** with bootstrap instructions if either is missing;
- **`postinst`** runs the ONE trusted installer (`install_offline.sh`), which
  re-verifies the now-unpacked payload against the admin-held public key
  before anything in it executes — verify-then-use staging is inherited from
  that installer, not re-implemented.

### Step 1 — Trust bootstrap (BEFORE `dpkg -i`; the preinst refuses without it)

The package refuses to install on a host where the trusted verifier or the
release public key is absent. Bootstrap both first, exactly as in
[Trust bootstrap](#trust-bootstrap-before-install) above:

```bash
# trusted verifier + installer, at a root-owned path OUTSIDE the bundle they
# verify (a tampered bundle would ship a verifier that prints PASSED).
# ALL of the files below are required: verify_bundle.py imports profiles.py
# from its own directory, and the installer sources lib/os_packages.sh
# relative to its own location — missing either aborts inside postinst.
sudo install -d -m 755 /usr/local/lib/udbmcp-trust
sudo install -m 644 <trusted-channel>/verify_bundle.py /usr/local/lib/udbmcp-trust/
sudo install -m 644 <trusted-channel>/profiles.py /usr/local/lib/udbmcp-trust/
sudo install -m 755 <trusted-channel>/install_offline.sh /usr/local/lib/udbmcp-trust/
sudo install -d -m 755 /usr/local/lib/udbmcp-trust/lib
sudo install -m 644 <trusted-channel>/lib/os_packages.sh /usr/local/lib/udbmcp-trust/lib/

# release public key — distributed OUT-OF-BAND by the release administrator.
# It is deliberately NEVER shipped inside the .deb (or any other release
# artifact): verifying with a key that arrived on the same channel as the
# payload proves nothing.
sudo install -d -m 755 /etc/universal-db-mcp /etc/universal-db-mcp/keys
sudo install -m 644 <trusted-path>/udbmcp-release.pub.pem /etc/universal-db-mcp/keys/release.pub.pem
```

If either path is missing, `preinst` prints the matching bootstrap block and
`universal-db-mcp: package installation ABORTED (fail closed)`.

### Step 2 — Install the package

Transfer the `.deb` into the air gap on approved media, then:

```bash
sudo apt-get install ./universal-db-mcp_0.1.0+<build-stamp>.g<rev7>_amd64.deb
# or, equivalently:
sudo dpkg -i universal-db-mcp_0.1.0+<build-stamp>.g<rev7>_amd64.deb
```

(The exact version string is derived from the signed manifest — upstream
release plus a debian-style source revision — so it always matches what was
signed.)

What postinst does, in order:

1. **Trust dir**: verifies that the ADMIN-installed trust dir
   `/usr/local/lib/udbmcp-trust` is complete (verifier, `profiles.py`,
   installer, `lib/os_packages.sh`) and **fails closed (exit 1, dpkg aborts
   the configure step) with bootstrap instructions if it is absent or
   incomplete**. The package NEVER bootstraps the trust dir from its own
   payload, and never completes a partial admin install from it either: the
   deb-shipped `trusted-tools/` copy travels on the same channel as the
   payload it would verify, so a tampered package could ship a tampered
   verifier that prints PASSED (or a tampered installer that skips
   verification) and get it installed to the root-owned trust path. That
   copy is inert reference material — the package never reads or executes
   it. This re-check exists because `postinst` is reachable without a
   `preinst` run (e.g. `dpkg --configure universal-db-mcp` after the trust
   dir was removed).
2. **Verify + install**: runs
   `UDBMCP_RELEASE_PUBKEY=/etc/universal-db-mcp/keys/release.pub.pem bash
   /usr/local/lib/udbmcp-trust/install_offline.sh
   /usr/share/universal-db-mcp/bundle /opt/universal-db-mcp`. That single
   trusted implementation re-verifies the payload with
   `verify_bundle.py --pubkey`, stages a private root-owned copy,
   re-verifies the copy, creates the `udbmcp` service account and state/log
   directories, builds the venv strictly offline
   (`--no-index --require-hashes`, `PIP_CONFIG_FILE=/dev/null`, hostile
   inherited pip config neutralized), installs the bundle's OS packages with
   `dpkg` only (never apt, never network), and smoke-checks the result. Any
   failure exits nonzero and dpkg aborts the configure step — nothing
   half-trusted is ever left runnable.

   When the bundle ships OS packages (the linux-x86_64 profile does), the
   `dpkg -i` of that closure cannot run while THIS `dpkg -i` still holds its
   locks. In that case postinst verifies the payload synchronously (a
   tampered package still fails the configure step), hands the install to a
   detached root worker that waits for dpkg to release its locks, and
   `dpkg -i` returns while the install continues: track it with
   `cat /var/log/universal-db-mcp-install.status` and
   `tail -f /var/log/universal-db-mcp-install.log`. The worker records
   `success` only after the trusted installer finished; on any failure it
   records `failed` and the unit is never installed or enabled.
3. **Systemd unit** installed to `/etc/systemd/system/universal-db-mcp.service`
   only if absent or identical to the deb-shipped copy — an admin-modified
   unit is never overwritten (the unit is not a dpkg path; the deb-shipped
   canonical copy stays at `/usr/share/universal-db-mcp/systemd/`).
4. **Config**: `/etc/universal-db-mcp/config.yaml` ships as a **dpkg
   conffile** (registered in the package's `conffiles`, staged 0644
   root:root from the verified bundle's `config-templates/config.yaml`):
   dpkg places it at unpack time — BEFORE the service is enabled, so the
   first start already sees it. `postinst` keeps an only-if-absent seeding
   from that same verified bundle copy as a **fallback** that restores the
   config if an admin deleted it before an upgrade (that fallback copy is
   seeded `udbmcp:udbmcp` 0640 so the service account can read it); it never
   overwrites an existing file, so an admin-provisioned config is never
   clobbered. Because the config is a conffile, dpkg preserves admin edits
   on upgrade and prompts only when an admin-modified config conflicts with
   a changed shipped default.
5. **Enable**: `systemctl daemon-reload`, then `systemctl enable --now`. The
   enable call is guarded: in a container without systemd as PID 1 the package
   install still succeeds and prints
   `systemctl enable --now universal-db-mcp` for later.

### Step 3 — Configure

Edit `/etc/universal-db-mcp/config.yaml` for your connections, then run the
doctor exactly as in [Configure](#configure):

```bash
sudo -u udbmcp /opt/universal-db-mcp/venv/bin/python -m universal_db_mcp doctor
```

### msodbcsql18 note (.deb-shipped)

The SQL Server ODBC driver does not need a separate download: the signed
bundle ships `msodbcsql18` and its `unixodbc` dependency chain as `.deb`
files in `os-packages/`, and the trusted installer installs them
automatically with `dpkg` in dependency order, offline and idempotently
(packages already installed at the required version are left untouched).
During a `.deb` install these packages are installed by the deferred
postinst worker, right after the outer `dpkg -i` releases its locks (see
"Verify + install" above) — `dpkg -i` of the package returns before that
finishes, so check `/var/log/universal-db-mcp-install.status` before relying
on the driver. Installing `msodbcsql18` constitutes accepting the Microsoft
ODBC driver EULA — the bundle merely carries the package; the acceptance
decision belongs to the administrator. `doctor` names the installed ODBC
Driver 18 explicitly, so a missing or mismatched driver is reported as the
specific failing artifact rather than surfacing later as an opaque
connection error.

### Upgrade, remove, purge

Operators: `docs/site-upgrade-runbook.md` is the command-by-command version of this
section for a live site (upgrade in place, or erase and reinstall), including the
mandatory trust-tools refresh and the deferred-install status check.

| Action | Service | `/etc/universal-db-mcp/config.yaml` (dpkg conffile; postinst seeds only if absent) | venv `/opt/universal-db-mcp/venv` | Audit/state `/var/lib`, `/var/log/universal-db-mcp` |
|---|---|---|---|---|
| `dpkg -i` (upgrade) | stopped by `prerm`, then re-enabled and started by `postinst` (`enable --now`) | kept (conffile semantics: your edits survive; dpkg prompts only if your modified config conflicts with a changed shipped default) | rebuilt against the new bundle | kept |
| `dpkg -r` (remove) | stopped and disabled | **kept** | kept (fast reinstall / rollback) | kept |
| `dpkg -P` (purge) | stopped and disabled: dpkg runs the package's `prerm remove` before `postrm remove` and `postrm purge`, so the service is handled exactly as on `dpkg -r` (a manual stop first is harmless) | **deleted** (dpkg removes conffiles on purge; `postrm` also removes the postinst-seeded fallback copy — belt and braces; `/etc/universal-db-mcp/keys/` with the release public key is never touched) | deleted, plus installer staging leftovers under `/usr/share/universal-db-mcp/bundle` | **kept** — the audit trail must outlive the package; delete explicitly if you really want it gone |

Notes:

- On upgrade the `preinst`/`postinst` trust checks run again — a new package
  version cannot weaken them.
- `/etc/systemd/system/universal-db-mcp.service` is installed by `postinst`
  under admin control (not a dpkg path — the deb ships the canonical copy at
  `/usr/share/universal-db-mcp/systemd/`), so conffile merging does not apply
  to it and dpkg never overwrites it. On upgrade postinst refreshes it only
  when absent or identical to the shipped copy; an admin-modified unit is
  kept untouched and postinst prints a warning pointing at the canonical
  copy for a manual review.
- If the service does not come up after an upgrade, check
  `systemctl status universal-db-mcp` and `doctor` before rolling back; see
  `docs/offline-upgrade-rollback.md` for the bundle-level rollback path.

## Install on macOS via .pkg

The `.pkg` carries the **signed** offline bundle as its payload
(`/usr/local/universal-db-mcp/bundle/`, built from the `macos-arm64-cp312`
profile bundle — not the Linux one). It follows the same verify-before-execute
model as the `.deb`: **no payload byte is ever executed before a trusted
`verify_bundle.py --pubkey` run has passed.** Because the macOS Installer
unpacks the payload only *after* the `preinstall` script runs, the package
splits the work honestly:

- **`preinstall`** checks the trust *prerequisites* only (trusted verifier,
  release public key, CPython 3.12 per-machine install) and **fails closed
  (exit 1, the Installer aborts)** with bootstrap instructions if any is
  missing;
- **`postinstall`** re-verifies the unpacked payload with the trusted
  verifier against the admin-held public key, and only then builds the venv,
  creates the service account, and bootstraps the launchd daemon.

The package is **non-relocatable**: every path below is absolute and
load-bearing. The Installer-provided arguments (target volume, boot volume,
admin user) are deliberately ignored by the scripts.

### Prerequisites

- **macOS host with admin rights** (`sudo`). The package installs per-machine
  (`InstallScope` equivalent: fixed absolute paths under `/usr/local`,
  `/etc`, `/var`).
- **CPython 3.12 as a per-machine (all-users) install** — either the
  python.org macOS installer (lands in
  `/Library/Frameworks/Python.framework/Versions/3.12/` and symlinks
  `/usr/local/bin/python3`) or `brew install python@3.12` (machine-wide,
  world-executable Homebrew prefix: `/opt/homebrew/bin/python3.12` on Apple
  Silicon, `/usr/local/bin/python3.12` on Intel). Per-user installs
  (`~/Library/Python`) and version managers do **not** satisfy this
  requirement: the venv is built into `/usr/local/universal-db-mcp/venv` and
  the service runs as the `_udbmcp` account, which cannot see a per-user
  interpreter. `preinstall` checks the interpreter really is CPython 3.12
  (a stale `/usr/local/bin/python3` pointing at another version is rejected).
- **The signed `macos-arm64-cp312` bundle**, transferred on approved media.
  The wheelhouse for this profile includes the `ibm-db` `macosx_14_0_arm64`
  wheel (see `docs/driver-matrix.md`); the builder fails loud if a connector
  wheel is missing.

### Step 1 — Trust bootstrap (BEFORE the install; `preinstall` refuses without it)

Identical in shape to the Linux bootstrap: the verifier must NOT come from
inside the bundle it verifies, and the release public key is NEVER shipped
inside any package — the admin distributes it out-of-band on the same trusted
channel.

```bash
# ALL of the files below are required: verify_bundle.py imports profiles.py
# from its own directory, and the installer sources lib/os_packages.sh
# relative to its own location — a trust dir missing either aborts later
# (inside verify/install) with a diagnostic about the missing file.
sudo install -d -m 755 /usr/local/lib/udbmcp-trust
sudo install -m 644 <trusted-channel>/verify_bundle.py /usr/local/lib/udbmcp-trust/
sudo install -m 644 <trusted-channel>/profiles.py /usr/local/lib/udbmcp-trust/
sudo install -m 755 <trusted-channel>/install_offline.sh /usr/local/lib/udbmcp-trust/
sudo install -d -m 755 /usr/local/lib/udbmcp-trust/lib
sudo install -m 644 <trusted-channel>/lib/os_packages.sh /usr/local/lib/udbmcp-trust/lib/

sudo install -d -m 755 /etc/universal-db-mcp /etc/universal-db-mcp/keys
sudo install -m 644 <trusted-path>/udbmcp-release.pub.pem /etc/universal-db-mcp/keys/release.pub.pem
```

If `/usr/local/lib/udbmcp-trust/verify_bundle.py` or
`/etc/universal-db-mcp/keys/release.pub.pem` is missing (or the key is an
empty file), `preinstall` prints the matching bootstrap block and exits 1 —
the Installer aborts before a single payload byte lands on disk. The
`profiles.py` and `lib/os_packages.sh` copies above are equally required:
`verify_bundle.py` imports the former from its own directory (so
`postinstall`'s verification fails closed without it), and `install_offline.sh`
sources the latter relative to its own location.

### Step 2 — Install the package

```bash
sudo installer -pkg universal-db-mcp-<version>-macos.pkg -target /
```

What `postinstall` does, in order:

1. **Verify the unpacked payload** with
   `python3 /usr/local/lib/udbmcp-trust/verify_bundle.py --bundle
   /usr/local/universal-db-mcp/bundle --pubkey
   /etc/universal-db-mcp/keys/release.pub.pem`. It refuses to run a verifier
   or a pubkey that lives inside the bundle, and fails closed on any verifier
   complaint — nothing is installed or executed. (The verify-then-use staging
   dance of `install_offline.sh` is not needed here: `pkgbuild` unpacks as
   root into a root-owned path, so there is no operator-writable window
   between verification and use.)
2. **Create the `_udbmcp` service group and user** (idempotent, `dscl`, UID/GID
   from the 400–499 reserved service range, no login shell, home
   `/var/empty`, hidden). On upgrade the existing account is kept.
3. **Build the venv** at `/usr/local/universal-db-mcp/venv` from the bundle
   wheelhouse strictly offline: `--no-index --no-cache-dir --find-links=<wheelhouse>
   --only-binary=:all: --require-hashes` with the hostile inherited pip
   environment neutralized (`PIP_CONFIG_FILE=/dev/null`, proxy and index env
   vars unset, `--isolated`).
4. **Smoke check** — `universal_db_mcp version` — the FIRST execution of
   payload code, reached only because step 1 passed.
5. **Config**: `/etc/universal-db-mcp/config.yaml` is installed **only if
   absent** (seeded from the bundle's `config-templates/config.yaml`,
   root-owned, group `_udbmcp`, mode 640). An admin-provisioned config is
   never overwritten.
6. **HTTP bearer token**: `/etc/universal-db-mcp/http-token` is generated
   **only if absent** (mode 0600, owned `_udbmcp`) — the launchd daemon runs
   `serve --transport http` (a daemon has no stdin client; the config's
   `stdio` default would exit 0 immediately under launchd), and this token is
   the only authentication on the listener. The value is never printed or
   logged. An explicit `application.http_bearer_token_file` in the config
   would win over the unit's env fallback.
7. **State/log dirs**: `/var/lib/universal-db-mcp` and
   `/var/log/universal-db-mcp` created 0750, owned `_udbmcp:_udbmcp`.
8. **Manifest** published next to the venv
   (`/usr/local/universal-db-mcp/manifest.json`) so `doctor` reports the real
   installed profile instead of guessing from the platform.
9. **launchd**: if `launchctl print system/com.udbmcp.server` shows the
   daemon already bootstrapped (upgrade), `launchctl bootout
   system/com.udbmcp.server` unloads it — a bootout failure is fatal — then
   `launchctl bootstrap system
   /Library/LaunchDaemons/com.udbmcp.server.plist` (the job registers under
   the plist's `Label`, `com.udbmcp.server`, which matches the installed
   filename stem and `packaging/pkg/postinstall`'s `LABEL`). Bootstrap
   failures are fatal; there is no already-bootstrapped tolerance (a masked
   failed upgrade must never be reported as success).

Any failure exits nonzero and the Installer reports the package install as
failed — nothing half-trusted is ever left runnable or started.

### Step 3 — Configure and verify

```bash
# edit /etc/universal-db-mcp/config.yaml for your connections (secrets, TLS)
sudo /usr/local/universal-db-mcp/venv/bin/python -m universal_db_mcp doctor
launchctl print system/com.udbmcp.server   # service identity/health
```

`doctor` checks wheels, TLS material, secret-file permissions, writable
paths, and policy consistency — no database credentials required.

### msodbcsql18 note (admin-supplied, NOT package-shipped)

Unlike the Ubuntu path, the macOS bundle's `os-packages/` staging is
Linux-only, so the `.pkg` does **not** carry the SQL Server ODBC driver.
The administrator supplies **`msodbcsql18.pkg`** (Microsoft ODBC Driver 18
for SQL Server, macOS installer) out-of-band and installs it before or after
this package — installing it constitutes accepting the Microsoft ODBC driver
EULA, which belongs to the administrator. The driver's `unixodbc`
dependency is provided by Homebrew (`brew install unixodbc`) or an
equivalent admin-approved offline source; the air gap means neither download
can happen at install time. `doctor` names the installed ODBC Driver 18
explicitly, so a missing or mismatched driver is reported as the specific
failing artifact rather than surfacing later as an opaque connection error.
(`doctor`'s darwin remediation text points at exactly this path.)

### The launchd-vs-systemd hardening delta

The launchd plist (`packaging/launchd/com.udbmcp.server.plist`) mirrors the
systemd unit line for line: `UserName _udbmcp`, `Umask 63` (launchd takes
DECIMAL; 0077 octal == 63), `KeepAlive { SuccessfulExit = false; }` =
`Restart=on-failure`, `ThrottleInterval 5` = `RestartSec=5`, `RunAtLoad` =
`WantedBy=multi-user.target`, `UDBMCP_CONFIG` environment, logs to
`/var/log/universal-db-mcp/`.

**Honest delta:** launchd has NO equivalent of systemd's `ProtectSystem=strict`,
`ReadWritePaths`, `NoNewPrivileges`, `ProtectHome`, `PrivateTmp`,
`ProtectKernelTunables`, or `CapabilityBoundingSet`. Compensating controls,
documented rather than hidden:

- audit/metadata files are created 0600 by the **code** itself; `Umask 63`
  is defense-in-depth, not the sole control;
- state/log directories are 0750 and owned `_udbmcp` (provisioned by
  `postinstall`, an admin step launchd cannot express);
- the daemon runs as the dedicated non-privilege `_udbmcp` account, which
  bounds the blast radius of the missing filesystem sandbox.

Separately from the bundle signature: the `.pkg` **may** also carry its own
developer-ID code signature (`productbuild --sign`); if built unsigned, the
build script warns that Gatekeeper/installer will not attribute the package
to a developer identity — record this in the release ledger. The package's
code signature (if any) is in addition to, never a substitute for, the
Ed25519 bundle verification above.

### Status (honest)

The build-environment gate (`scripts/package/test_package_pkg.sh`) proved on
a real macOS host: payload = the signed bundle (trusted verifier run against
the expanded package payload), plist contents, prerequisite checks, and the
native unit suite — plus, in the latest recorded run
(`out/package-evidence/pkg/results.json`), an executed
tamper negative: a byte-flipped wheel inside a repacked COPY of the `.pkg` is
rejected by the trusted verifier with the canonical FAIL diagnostic
(`tamper_copy` / `wheel_tampered` / `tampered_payload_rejected` all passed).
That file records a complete green gate: status `passed`, all 23 checks
green, including the native unit suite and all three tamper checks. (The
file is overwritten by every gate run, so check it directly for the
`generated_at` timestamp of the run it currently describes.) History: an
earlier same-day run (2026-09-12T10:47:30Z) recorded all 20 checks green;
a later run (2026-09-12T11:17:20Z) recorded 22/23, failing only the
unit-suite check in a transient race with concurrent edits to the tree
(the two affected tests pass on re-run); the owed full re-run of the
23-check gate has since been recorded green, closing that gap. The **full `sudo installer` run
was NOT performed in the build environment** — `installer_run` is recorded
`not_run` in the evidence at `out/package-evidence/pkg/`. Run the optional
full install
(`UDBMCP_PKG_INSTALL=1 scripts/package/test_package_pkg.sh`) on a
sacrificial macOS host before fleet rollout.
