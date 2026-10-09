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
tampered bundle would simply ship a verifier that prints PASSED. They live at
a root-owned path outside the bundle, `/usr/local/lib/udbmcp-trust`,
installed from the same trusted channel as the release public key. The
copies in the bundle's `installers/` directory are reference copies only and
are never executed.

From a release stick (the normal case), `bootstrap.sh` installs them and
checks the stick first. The bundle signature covers only the payload inside
the package; the package's maintainer scripts, `bootstrap.sh` and the trust
tools are covered by the stick's `SHA256SUMS`, which the release key signs
(`SHA256SUMS.sig`). `bootstrap.sh` verifies that signature and refuses any
file on the stick that does not match the list or is not on it, and any
symlink, FIFO, device node or name with a line break, before it installs
anything. On a first install, compare the key's fingerprint with the value
your release administrator gave you out of band and run the stick's copy; on
every later upgrade run the copy an earlier bootstrap installed, which checks
the new stick with the INSTALLED key before anything from it runs
(`docs/site-upgrade-runbook.md`, steps 0 and 1):

```bash
sudo bash <stick>/trust-bootstrap-linux/bootstrap.sh                 # first install
sudo bash /usr/local/lib/udbmcp-trust/bootstrap.sh --stick <stick>   # every later upgrade
# [--rotate-key] after an out-of-band fingerprint check; [--allow-downgrade] for an older stick
```

A first install, and an upgrade from a release whose verifier cannot check a
detached signature (`--verify-file`, new in this release, which refuses a
symlinked or non-regular data or signature file), checks the
signature with `/usr/bin/openssl` (OpenSSL 3, as on Ubuntu 24.04); later runs
use the installed verifier, which needs no openssl. `bootstrap.sh` refuses to replace an installed key with a different
one unless you pass `--rotate-key` after comparing fingerprints out of band.
It reads a private copy of the stick's tools and signed list, made under
`/var/tmp` (it unsets `TMPDIR`, `TEMP` and `TMP` first), and refuses
anything in that copy that is not a regular file, or that the signed list
does not name (`FAIL: <path> is in the private copy of the stick but not on
its signed SHA256SUMS.`, `The stick changed while it was read`).

Release sticks are ordered: every stick carries
`trust-bootstrap-linux/RELEASE`, its Linux bundle's `release_seq`, on the
signed list. `bootstrap.sh` reads it from the checked private copy, prints a
`release order:` line, and refuses a stick whose `RELEASE` is lower than the
one it recorded at `/usr/local/lib/udbmcp-trust/RELEASE`, or a stick with
no `RELEASE` once one is recorded (`FAIL: this stick is release N, OLDER
than release M whose trust tools are installed.`), unless you pass
`--allow-downgrade`; a malformed `RELEASE` on the stick is refused always.
An equal `RELEASE` passes only when every trust tool on the stick is
byte-identical to the installed one (a re-run, or another stick of that
release); tools that differ under the same number are another release,
possibly the older one, and are refused the same way (`... its tools differ
from the installed ones ...`).
On success it records the stick's release
(removing the record when the stick names none) and prints it on its
`release  :` line. Until a release is recorded (`nothing recorded yet`),
any genuinely signed stick is accepted.

Before it installs any trust tool, it copies every `.deb` the signed list
names into a new root-only directory beside `/var/cache/udbmcp-trust/`
(`/var/cache/udbmcp-trust.new.XXXXXX`), checks those copies against the
signed list again, and only then puts that directory in place of
`/var/cache/udbmcp-trust/`; on any failure, a `cp` error included (`FAIL:
<deb> could not be copied from the stick ...`), an earlier release's checked
copies stay where they are and nothing is installed. It prints
`sudo dpkg -i /var/cache/udbmcp-trust/<package>` for the package: install
from that copy, never from the stick. `dpkg -i` reads the file again and the
package's `preinst` runs as root, so a stick that changed after the check
would otherwise hand it another package. The copies (about 65 MB) stay until
the next `bootstrap.sh` run replaces them.

Without a stick (a bundle delivered some other way), install the same files
by hand from the release's `trusted-tools/` directory:

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

`trusted-tools/` also holds `upgrade_offline.sh`, `rollback_offline.sh` and
the container-mode image loader `load_images_offline.sh` (all listed in
`trusted-tools/SHA256SUMS`); install the ones your install mode uses the same
way.

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
   `UDBMCP_RELEASE_PUBKEY` must point at the trusted public key PEM), then
   copies the verified bundle into a private directory, verifies that copy
   again and uses only the copy from then on (below),
2. checks the platform baseline (fails fast on wrong Python/ABI),
3. creates a fresh venv and installs with
   `--no-index --no-cache-dir --find-links=<wheelhouse> --only-binary=:all:
   --require-hashes`, with hostile inherited pip config neutralized
   (`PIP_CONFIG_FILE=/dev/null`, index env vars overridden).

Missing wheel / OS package / licensed driver: the verifier and doctor fail
with the exact artifact named. Nothing downloads; nothing falls back.

The verifier reads each file of the bundle once, never through a link at any
path component, and checks the signature over exactly the `SHA256SUMS` bytes
it parsed. It refuses a bundle holding a symlink (to a file or a directory,
dangling or not), FIFO, socket, device or Windows symlink or junction
anywhere (`FAIL: not a regular file or directory in the bundle: <rel> (a
link, a FIFO or a device) ...`), a bundle whose root `SHA256SUMS` or
`SIGNATURE` has more than one hard link (`... has N links ...`: a copy made
with `cp -al` or `rsync --link-dest`; copy the bundle plainly), a file that
reads differently the second time (`changed while the bundle was verified`),
and a bundle or directory it cannot list (`FAIL: the bundle cannot be
listed: <path>: <reason>; nothing in it was checked`, a missing bundle path
included).

**The private copy.** `install_offline.sh`, `upgrade_offline.sh` and
`load_images_offline.sh` share one block for what they make as root. The
staging base, `UDBMCP_STAGING_DIR` (default `/var/tmp`), is created with
umask 022 when missing and resolved to its real path, and it and every
directory above it must be a real directory owned by root, not writable by
group or others, or root-owned and sticky; otherwise the script stops before
it copies anything (`FAIL: the private copy of the bundle would be made in
<base>, and <dir> is not root's alone ...`, then `Installation ABORTED.`,
`Upgrade ABORTED.` or `No image was loaded.`). The copy is made at
`<base>/udbmcp-install.XXXXXX/bundle` (`udbmcp-upgrade`, `udbmcp-images`),
in a directory that stays 0700. It keeps none of the bundle's owners,
group or other permissions, timestamps or hard links: files and
directories are root-owned with no group or other bits, and only the owner
bits of the bundle's modes carry over (a 0644 file becomes 0600, a 0755
one 0700, a 0444 one 0400). A copy that fails, that holds anything but
regular files and directories, or that is not root's alone afterwards
stops the script
(`FAIL: the private copy of the bundle could not be made in <dir>. ...`,
`FAIL: the private copy holds what is not a regular file or directory ...`,
`FAIL: the private copy is not root's alone ...`). The same block checks
`TMPDIR`, `TEMP` and `TMP` before the first verification: one whose real
path, like every directory above it, is root's alone is exported as that
checked real path; any other is unset with `NOTE: <VAR> (<value>) is not
root's alone; root's temporary files are not made there` (an empty one
silently), so `sudo -E` cannot point root's temporary files into another
account's directory. The verifier's output is kept in the shell, never in a
temporary file. `rollback_offline.sh`, the `.deb`'s postinst and
`bootstrap.sh` unset all three at start.

Anti-rollback: every signed bundle carries an integer `release_seq`, and the
verifier refuses a bundle older than the installed release
(`/opt/universal-db-mcp/manifest.json`) with `FAIL: rollback refused: this
bundle is an OLDER release than the one installed ...`. An intended downgrade
passes `--allow-downgrade` to `install_offline.sh` or `upgrade_offline.sh`
(or sets `UDBMCP_ALLOW_DOWNGRADE=1`; for the `.deb`,
`sudo UDBMCP_ALLOW_DOWNGRADE=1 dpkg -i <older .deb>`). Run on the install
target without `--installed-manifest`, as in the pre-check above, the
verifier compares with this platform's installed release on its own
(`release order: no --installed-manifest given; checking this machine's
installed release ...`) and prints `release order: nothing installed yet`
on a first install. Only a verification on another machine skips it:
`--allow-platform-mismatch`, or `--no-installed-manifest` on a build machine
(`docs/offline-build.md`).

The installer, `upgrade_offline.sh`, `rollback_offline.sh` and the `.deb`'s
postinst unset every `PYTHON*` variable at start and work from `/`, and their
root-side interpreter and pip runs are isolated (`-I`; base interpreters
`-I -S`), so a root shell's environment or working directory cannot put code
into them. (`upgrade_offline.sh` still runs its two `doctor` checks without
`-I`; with the variables unset and `/` as the working directory, nothing from
the caller reaches them.) A re-run
of the installer also hands root-owned `audit.jsonl*` files in
`/var/log/universal-db-mcp` (left by an older release's root `site-check` or
`doctor`) back to `udbmcp`, mode 0600.

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

**Bundles without the driver (public releases).** The Linux bundle and
`.deb` published on GitHub are built with `--without-mssql-driver`
(`docs/offline-build.md`): Microsoft's driver is not redistributed, so they
carry no OS packages, and the manifest lists the driver as an
administrator-supplied prerequisite. On a host that will use SQL Server
connections, install `msodbcsql18` (it brings the unixODBC packages with it)
from Microsoft's package repository, or carry its `.deb` files in from a
machine that can reach it, accepting the EULA (`ACCEPT_EULA=Y`); Microsoft's
"Install the Microsoft ODBC driver for SQL Server (Linux)" page has the
commands. Install it on the host, never into the bundle: the bundle is
signed, and the verifier refuses any `.deb` its manifest does not declare.
`doctor` names the driver when it is missing.

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

Config rules that matter at a site (details in `docs/security.md`):

- When the config leaves `application.audit_path` unset, the service audits
  to `/var/log/universal-db-mcp/audit.jsonl` (any other config to
  `~/.universal-db-mcp/audit.jsonl`, and a home that is `/`, empty or
  relative derives no default, so the config does not load); auditing is
  never off. The audit
  path must be a plain file on a local filesystem with file locking (not NFS or
  SMB): the log shares a `<audit_path>.lock` sidecar with every other server
  process using it.
- Relative paths in the config resolve against the config file's directory.
- A connection-level `read_only: false`, a mapping key given twice, and
  connection ids outside `[A-Za-z0-9_-]` (1-64 characters, not starting with
  `-`) are refused at load.
- With `allowed_schemas` set, agents must schema-qualify every table in a
  statement.
- `sudo udbmcp add-connection --config /etc/universal-db-mcp/config.yaml`
  writes the connection's secret files for the service account (the
  config's owner, or its group when root owns it) and prints the restart
  command. A config owned `root:root`, as the `.deb`'s conffile arrives, is
  refused with the commands to fix it: give it to the service account first
  (`sudo chown root:udbmcp /etc/universal-db-mcp/config.yaml && sudo chmod 640
  /etc/universal-db-mcp/config.yaml`).

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
never carried in an environment variable). The token must hold at least 32
characters of UTF-8, or `serve` refuses to start with a `CONFIG_ERROR`.

Pre-auth limits of the listener: a connection must deliver a complete
request head within 10 s (`UDBMCP_HTTP_HEADER_TIMEOUT`, in the unit's
environment), a head of more than 100 header lines or 16 KiB is answered 431,
and a request without the token is answered 401 and closed before its body is
read. The unit sets `LimitNOFILE=65536` (the `.deb` refreshes the unit only
when it is absent or unmodified; add it to an edited unit by hand). An idle
connection still holds a descriptor until the header deadline, so a local
client that sustains about 6.5k new connections per second could exhaust
them; there is no connection cap by design. `UDBMCP_HTTP_LOG_FILE` sends the
listener's log to a size-bounded file (5 MiB x 3); ERROR records also go to
stderr, so `journalctl` still shows a port already in use.

### Reverse proxy and TLS in front of the HTTP listener

The listener binds loopback and validates the `Host` header against its own
address (DNS-rebinding protection; a client that connects by another name
is answered `421 Invalid Host header`). A TLS-terminating reverse proxy in
front of it must therefore forward the LISTENER's address as `Host`, not the
client's, and keep the bearer token header as it is:

```nginx
location / {
  proxy_pass http://127.0.0.1:8765;
  proxy_http_version 1.1;
  proxy_set_header Host 127.0.0.1:8765;   # the listener's own address, not $host
  proxy_set_header Connection "";
  proxy_buffering off;                     # the MCP stream is server-sent events
  proxy_read_timeout 300s;
}
```

Bound what an unauthenticated client can hold at the proxy too, for example
`client_header_timeout 10s;` and a `limit_conn` zone per client address in
the `server` block.

Evidence: `scripts/http_client_evidence.py` drives exactly this layout
(self-signed nginx in Docker, the MCP SDK's streamable HTTP client with a
bearer token) and records `test-evidence/http-transport/results.txt`:
initialize, 29 tools listed, a tool call, and HTTP 401 for a wrong or
missing token before any tool runs.

## Container mode

### The published image (connected hosts)

Each GitHub release also publishes this image to GitHub Packages as
`ghcr.io/alghanim/universal-db-mcp:<version>` (`latest` follows stable
releases only), for hosts that may reach a registry. `.github/workflows/container.yml`
builds it from that release's own signed Linux bundle, after checking the
bundle's signature against the key `SECURITY.md` publishes, and stores a
build-provenance attestation with it. Check it before running it:

```bash
gh attestation verify oci://ghcr.io/alghanim/universal-db-mcp:0.1.0 --repo alghanim/universal-db-mcp
docker run --rm ghcr.io/alghanim/universal-db-mcp:0.1.0 version
```

It is a `linux/amd64` image with no configuration inside: mount
`/etc/universal-db-mcp/config.yaml` and its secrets as the compose file
below does. It carries no ODBC stack, so SQL Server connections need an
image built on top of it with Microsoft's driver, whose EULA you accept:

```dockerfile
FROM ghcr.io/alghanim/universal-db-mcp:0.1.0
USER root
# Add Microsoft's package repository for Ubuntu 24.04 as Microsoft's
# "Install the Microsoft ODBC driver for SQL Server (Linux)" page describes, then:
RUN apt-get update && ACCEPT_EULA=Y apt-get install -y --no-install-recommends msodbcsql18 \
    && rm -rf /var/lib/apt/lists/*
USER udbmcp
```

An air-gapped host does not pull: it loads the image from the bundle as
the rest of this section describes.

### Loading the image from the bundle

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

Load the images with the TRUSTED loader, never with a plain `docker load`
of the bundle: `load_images_offline.sh` refuses to run from inside a bundle,
verifies the bundle with the trusted verifier, copies it to a private
root-owned staging directory (`/var/tmp`, or `UDBMCP_STAGING_DIR`), verifies
that copy again and loads the images from it, so the tars cannot change
between check and load (the same private copy as the native installer's,
at `<base>/udbmcp-images.XXXXXX/bundle`; see above). It needs root (or
sudo). Install it from the
release's `trusted-tools/` into the trust dir first; the bundle's
`operations/load_images_offline.sh` is a reference copy only.

```bash
sudo install -m 755 <trusted-channel>/load_images_offline.sh /usr/local/lib/udbmcp-trust/
sudo UDBMCP_RELEASE_PUBKEY=/etc/universal-db-mcp/keys/release.pub.pem \
  bash /usr/local/lib/udbmcp-trust/load_images_offline.sh <bundle-dir>   # [--allow-downgrade]
docker image inspect udbmcp/universal-db-mcp:0.1.0-linux-x86_64-ubuntu24.04-cp312  # identity check
docker network create --internal udbmcp-internal   # admin-managed
# the bundle ships the compose file under operations/, not packaging/
# (there is no packaging/ directory on the target):
docker compose -f <bundle>/operations/compose.offline.yaml up -d
```

The loader hands the images to the docker daemon the operator's own `docker`
command reaches when there is one (a rootless daemon, `DOCKER_HOST` or a
docker context: the one `docker compose up` uses afterwards), streaming the
root-only verified copy to it; otherwise it loads through root's daemon.
Under `sudo` (the invocation above) the operator is `SUDO_USER`: their
`docker` runs as them, with their home (so their current context applies),
with `DOCKER_HOST` when one is given on the `sudo` line (`sudo
DOCKER_HOST=... bash .../load_images_offline.sh ...`, since `sudo` drops it
from the environment), and otherwise with their rootless daemon's socket
`/run/user/<uid>/docker.sock` when it exists. The loader prints `==> loading
into <daemon>`.

`pull_policy: never` — an absent image fails locally; no registry contact.
The compose file sets `ulimits: nofile: 65536` and a bounded `json-file` log
(10 MB x 5).

Anti-rollback in container mode: the loader's usage is
`load_images_offline.sh <bundle-dir> [--allow-downgrade]`. A container host
installs nothing natively, so the loader keeps its own release record,
`/var/lib/universal-db-mcp/release.json` (`UDBMCP_RELEASE_RECORD` overrides it
and must be an absolute path). Both verifications, of the bundle and of the
private staging copy, pass it as `--installed-manifest`, so an older bundle,
or an unreadable record, is refused before anything is staged or loaded
(`FAIL: this bundle is an OLDER release than the one whose images this host
last loaded ...`). An intended downgrade passes `--allow-downgrade`, or
`UDBMCP_ALLOW_DOWNGRADE=1` (no other value counts). After every image has
loaded, the loader writes the verified copy's `manifest.json` as the record
(mode 0644, renamed into place) and prints `release record <path>:
release_seq <N> (an older bundle is refused from now on)`. It creates every
missing directory on the record's path (0755, as root) before the first
verification, even when the load is then refused, so no other account can
create one during the load, and it checks the whole chain again before it
writes the record: if the chain changed, it exits 1 with `The images are
loaded, but the record was not written.`. A record below a directory every
account can write (such as `/tmp` or `/var/tmp`, which boot or
systemd-tmpfiles may empty) gets a warning. A failed load leaves the record
as it was, and protection starts with the first load by this release's
loader.

The record counts only where root alone can change it. Before any
verification, the loader refuses (`FAIL: the release record <record> orders
the releases this host loads, and <path> is not root's alone ...`, nothing
loaded) unless the record is a root-owned regular file, its directory a
root-owned real directory, both unwritable by group and others and neither a
symlink, and every existing directory above it, up to `/`, a root-owned real
directory that group and others cannot write, or a root-owned sticky one such
as `/tmp`. On a host that also runs the native package,
`/var/lib/universal-db-mcp` belongs to `udbmcp`: leave it as it is and point
the loader at a root-only path instead, for example
`UDBMCP_RELEASE_RECORD=/var/lib/udbmcp-images/release.json`.

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
stages into the package. Before `CreateFolders`, on install and repair,
`CheckFoldersCA` checks the two folders the install writes into (its script,
`folders.ps1`, is embedded in the MSI, since nothing is installed yet; see
below). After `InstallFiles`, and in this strict order, `msiexec` runs: (1) `VerifyBundleCA` — verify the installed bundle with the
ADMIN-installed trusted verifier and public key, and refuse an older release
than the installed one, (2) `BuildVenvCA` — build the venv from the verified
wheelhouse with `pip --no-index --require-hashes` and `PIP_CONFIG_FILE`
neutralized (on a repair or upgrade it first stops the service and moves
the previous venv aside whole, see below), (3) `DoctorSmokeCA` — a `doctor` smoke check, the FIRST
execution of payload code, strictly after verification passed, and (4)
`RegisterServiceCA` — `sc.exe` service registration and the installed-release
record. Any nonzero exit rolls the whole install back, so a failed
verification can never leave a half-trusted install behind: the rollback twin
`RollbackRemoveServiceCA` removes the service a first install or an upgrade
registered (a failed repair keeps the service that was registered before it
began) and puts back the record this install replaced, and
`RollbackBuildVenvCA` puts back the venv `BuildVenvCA` moved aside. After a
successful install, repair or upgrade, the commit actions
`CommitReleaseRecordCA` and `CommitBuildVenvCA` remove the record's rollback
copy and the previous venv (they never touch the service).

**The previous venv.** A venv an earlier install built is never deleted in
place: Windows refuses to delete a file a process has open or mapped, so a
recursive delete failed part-way and left a gutted venv no rollback could
restore. `BuildVenvCA` stops the service (it runs from that venv), then
moves the venv whole to `venv.previous-<guid>` beside it. A move refuses a
folder a process still runs from (an MCP client a `configure-agents`
registration started, such as Claude Desktop, or a shell): the install then
fails with the venv untouched and the service stopped, naming the cause;
close it and rerun. The marker `venv.moved` names the folder moved aside and
whether the new venv is complete; a marker an interrupted install left is
settled first (an incomplete venv is replaced by the one moved aside, a
complete one keeps its place and the moved one is removed). Every Python run these actions make as LocalSystem is
isolated (`-I`), `venv.ps1`'s and the service included.

**Nothing about Windows has been run on Windows yet** (see Status below): this
section describes delivered authoring, exercised under PowerShell 7 on POSIX
with the Windows APIs stubbed.

### Prerequisites

- Windows x86_64 with local administrator rights (the MSI is per-machine);
  run `msiexec` from an elevated prompt.
- **CPython 3.12 from python.org, installed "for all users"** (64-bit), in a
  folder only SYSTEM, Administrators and TrustedInstaller can write: the
  default `C:\Program Files\Python312`. The installer's launch condition
  checks the per-machine PEP 514 registry key
  (`HKLM\SOFTWARE\Python\PythonCore\3.12\InstallPath`); a per-user install
  writes only HKCU and is rejected. `VerifyBundleCA` runs this interpreter as
  LocalSystem before the bundle is verified, so it also refuses an interpreter
  whose folder, the folder above it, the files beside it or anything under
  `Lib` or `DLLs` is a junction or symlink, is owned by a non-admin, or grants
  anyone else write access, and a virtual environment's interpreter (a
  `pyvenv.cfg` beside it or one folder up). An interpreter at `C:\Python312`
  (which inherits Authenticated Users Modify from `C:\`) is refused. This
  applies to `PYTHON`/`UDBMCP_PYTHON` overrides too. Walking the standard
  library adds a few seconds per install. An owner counts as an
  administrator only as SYSTEM, Administrators, TrustedInstaller or a direct
  member of the local Administrators group: files an administrator owns only
  through a domain group (for example after an elevated `pip install` into
  the base interpreter) are refused, and the fix is to add that account to
  the local Administrators group itself, or keep the base interpreter
  untouched. Never re-own files a non-admin could have written.
- The **Microsoft ODBC Driver 18 for SQL Server** MSI (see the ODBC section
  below) if you use mssql connections: on the Windows profile the driver is
  admin-supplied, not shipped in the bundle.
- No openssl: the trusted verifier checks the Ed25519 signature with its own
  code (standard library only).

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
root-owned `/usr/local/lib/udbmcp-trust` on Linux/macOS. The release key goes
there too, for the same reason:

```powershell
# 1. trusted verifier + its profile registry (plain copies; run via python.exe)
New-Item -ItemType Directory -Force "C:\Program Files\udbmcp-trust\lib"
Copy-Item <trusted-channel>\verify_bundle.py "C:\Program Files\udbmcp-trust\"
Copy-Item <trusted-channel>\profiles.py      "C:\Program Files\udbmcp-trust\"

# 2. release public key (distributed out-of-band by the release administrator)
New-Item -ItemType Directory -Force "C:\Program Files\udbmcp-trust\keys"
Copy-Item <trusted-path>\udbmcp-release.pub.pem "C:\Program Files\udbmcp-trust\keys\"

# 3. point the installer at the key (machine scope)
setx /M UDBMCP_RELEASE_PUBKEY "C:\Program Files\udbmcp-trust\keys\udbmcp-release.pub.pem"
```

- **Refresh the verifier on every upgrade.** A trust-dir `verify_bundle.py`
  from before this release (one without `--installed-manifest`) is refused as
  an `OUTDATED copy` before it runs: copy this release's `verify_bundle.py`
  and `profiles.py` into `C:\Program Files\udbmcp-trust` first.
- **Upgrading sites with the key under ProgramData.** Earlier releases
  documented `C:\ProgramData\universal-db-mcp\keys`. Such a key is still used,
  with a WARNING, only while it and every folder above it are owned by SYSTEM,
  Administrators, TrustedInstaller or an administrator, none is a junction or
  symlink, and nobody else can write, delete or re-permission it; otherwise
  `VerifyBundleCA` fails closed and names the entry. Move the key as above
  rather than re-owning the folder. A key read straight from the USB stick
  fails closed too: FAT and exFAT volumes carry no owner or ACL to check.

Optional override (machine scope, `setx /M`): `UDBMCP_PYTHON` (explicit
interpreter for the verifier, subject to the rules above). The trust
directory itself is NOT env-overridable for the MSI.

The verifier fails closed — exits nonzero with a diagnostic — if any of
these are missing, if the trust directory, the public key, or the Python
interpreter resolve INSIDE the installed bundle, or on any signature or
hash mismatch; on success it prints its explicit `bundle verification
PASSED` proof. The action's output is persisted to
`C:\ProgramData\universal-db-mcp\install-verify.log`, a folder created with a
SYSTEM + Administrators-only DACL: read it from an elevated prompt. The
install aborts if that folder or the log is a junction or symlink or owned by
a non-admin; inspect it, remove it, and rerun.

### Install

```bat
msiexec /i dist\universal-db-mcp-0.1.0-win-x86_64.msi /l*v udbmcp-install.log
```

Always pass `/l*v`: the MSI log is the install's post-mortem record.
`UDBMCP_SERVICE_ACCOUNT` and `UDBMCP_ALLOW_DOWNGRADE` are accepted only from
an elevated administrator (`MSIUSEREALADMINDETECTION` with an `AdminUser`
launch condition); a value of `UDBMCP_SERVICE_ACCOUNT` containing a double
quote or ending with a backslash, and any `UDBMCP_ALLOW_DOWNGRADE` other than
`1`, are refused before any custom action runs. Programs and Features shows
the publisher as `universal-db-mcp maintainers`; the MSI carries no e-mail
address or URL. Layout after a successful install:

- `C:\Program Files\UniversalDB MCP\bundle\` — the signed bundle payload
  (harvested verbatim; only ever READ by the verifier first),
- `C:\Program Files\UniversalDB MCP\scripts\` — the custom action scripts
  (`verify.ps1`, `venv.ps1`, `doctor.ps1`, `service.ps1`, `uninstall.ps1`),
  installed as a SIBLING of `bundle\`, never inside it,
- `C:\Program Files\UniversalDB MCP\venv\` — created by `BuildVenvCA` from
  the verified wheelhouse (`pip --no-index --require-hashes`,
  `PIP_CONFIG_FILE=NUL`, proxy/index env vars scrubbed, `--isolated`,
  `--only-binary=:all:`); the Windows bundle carries the `pywin32` and
  `tzdata` wheels its dependencies need on Windows. During a repair or
  upgrade the previous venv sits beside it as `venv.previous-<guid>` until
  the install commits,
- `C:\Program Files\UniversalDB MCP\manifest.json` — the installed-release
  record, at that fixed path whatever `INSTALLFOLDER` is. Only while an
  install runs, `manifest.json.previous` (the copy the rollback action
  restores) and `manifest.json.kept` (the marker meaning this install has not
  replaced the record yet) sit beside it; the commit action removes both, so
  after a successful install only `manifest.json` remains. One left behind
  because a process held it open is harmless: delete it once nothing holds
  it, and never copy it over `manifest.json`,
- `C:\ProgramData\UniversalDB MCP\` — `config.yaml` (installed once, never
  overwritten on upgrade or repair, and retained on uninstall: the component
  is `Permanent`, so neither `msiexec /x` nor the old product's removal a
  major upgrade runs deletes it), `http-token`, `smoke\` and `logs\`. The
  folder has a protected DACL: SYSTEM and Administrators only, plus read for a
  dedicated service account; reading it needs an elevated prompt,
- `C:\ProgramData\UniversalDB MCP\logs\` — the one place a dedicated service
  account can write (Modify): the default `audit_path`
  (`logs\audit.jsonl`) is there, and a dedicated account's
  `metadata_cache_path` belongs there too. `DoctorSmokeCA` and
  `RegisterServiceCA` create it with its protected DACL when it is missing,
- `C:\ProgramData\universal-db-mcp\install-verify.log` — the verifier
  output written by `VerifyBundleCA`.

Before anything is created or installed, `CheckFoldersCA` refuses (and rolls
the install back): an `INSTALLFOLDER` that anyone but SYSTEM,
Administrators, TrustedInstaller or an administrator may write (inherit-only
grants included; everything installed there runs as LocalSystem, and a
custom folder such as `D:\Apps\...` usually inherits Authenticated Users
Modify), a config folder that is a junction or symbolic link or is not owned
by SYSTEM, Administrators or an administrator, and any folder above either
one that is a junction or that a non-administrator could delete,
re-permission or empty (and so swap for a junction). A missing
`INSTALLFOLDER` or config folder is created with its protected DACL
(`INSTALLFOLDER`: SYSTEM and Administrators Full Control, Users read and
execute). A launch condition refuses an `INSTALLFOLDER` holding a single
quote. An install or repair also fails closed when anything under
`C:\ProgramData\UniversalDB MCP` is a junction or symlink, or is owned by
anyone but SYSTEM or an administrator (entries the configured service
account wrote below `logs\`, such as its audit log, are accepted). The
diagnostic names the entry: inspect it and remove it; for anything in
`logs\`, move it out and archive it, because `logs\` holds the audit trail.

Non-admin Windows users cannot read the machine-wide config, so `doctor`,
`site-check`, `add-connection` and `configure-agents` default to the per-user
`%USERPROFILE%\.universal-db-mcp\config.yaml` for them; nothing crashes.

Your post-install duties:

1. **Read the post-mortem** (elevated): confirm `udbmcp-install.log` shows the
   custom actions ran, and `install-verify.log` contains the exact `bundle
   verification PASSED` line. A missing PASSED line is a hard stop.
2. **Check the service registration**: `sc.exe query udbmcp` should show
   the service created by `RegisterServiceCA` (auto start).
3. **Edit `config.yaml`** for your connections, then start the service. The
   installed file is the demo template: replace its `PLACEHOLDER_DIR` and
   `PLACEHOLDER_DB` tokens. With a dedicated service account, point
   `metadata_cache_path` into `C:\ProgramData\UniversalDB MCP\logs\`, and
   either point `audit_path` there too or remove it to take the default
   `logs\audit.jsonl`; the account can write nowhere else.

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
`ODBC Driver 18 for SQL Server`.

### Service management (sc.exe)

`RegisterServiceCA` runs `service.ps1`, which creates (or, on a repair,
updates in place with `sc.exe config`, never deleting it) an auto-start
service named `udbmcp` running
`"<venv>\Scripts\python.exe" -I -m universal_db_mcp serve --transport http`,
with failure recovery mirroring the systemd unit (restart after 60000 ms,
counter reset after 86400 s) and `UDBMCP_CONFIG` +
`UDBMCP_HTTP_BEARER_TOKEN_FILE` in the service's `Environment` registry
value. A daemon under the SCM has no stdin client, so HTTP transport is
forced. Every install, a repair included, sets the service's DACL to the
Windows default for a new service (SYSTEM and Administrators control it,
interactive and service logons query it; anything granted since, such as
change-config to Users, is replaced) and its SID type to `unrestricted`. An
update in place re-applies what `sc.exe create` gives a new service (type
`own`, error control `normal`, no dependencies, the display name), then
switches the binPath and account. A service marked for deletion that
Windows removed once it stopped is created again; one still marked (a
handle to it is open) fails the install before anything is changed, naming
the remedy (close services.msc or the tool that holds it, or restart the
host).

**The account** is resolved in this order: the `UDBMCP_SERVICE_ACCOUNT`
property (elevated `msiexec` only), the machine-scope
`UDBMCP_SERVICE_ACCOUNT` variable, the account the service is already
registered under (read from
`HKLM\SYSTEM\CurrentControlSet\Services\udbmcp\ObjectName` before anything
runs), then LocalSystem. So a repair or upgrade keeps the registered account;
the log says `no service account given: keeping '<account>' ...`. It is
refused before anything changes when the registered account signs in with a
password (anything but LocalSystem, LocalService, NetworkService,
`NT SERVICE\<name>` or a gMSA) and `UDBMCP_SERVICE_PASSWORD` is not in the
installer's environment: pass `UDBMCP_SERVICE_ACCOUNT` from an elevated
`msiexec`, then set the password again (services.msc or `sc.exe config`). It
is also refused when no account is given or registered (after an uninstall)
but `logs\` still grants another account write access: name the account, or
pass `UDBMCP_SERVICE_ACCOUNT=LocalSystem` to switch. A virtual account,
`UDBMCP_SERVICE_ACCOUNT="NT SERVICE\udbmcp"`, works on a fresh install and
across upgrades: its SID is derived from the service name (as
`sc.exe showsid` does), not looked up, so the service need not exist yet.
Any `NT SERVICE\<name>` is taken as the virtual account of that service
name in the same way, without checking that the name is this service's:
`NT SERVICE\ALL SERVICES` is not the group of that name, and another
service's account (`NT SERVICE\MSSQLSERVER`) is accepted, so type this
service's account exactly (`NT SERVICE\udbmcp` under the default service
name). Any other name is looked up, and one that resolves to a SID no
service runs as is refused: a well-known group
or principal (`BUILTIN\Users`, `Authenticated Users`, `Everyone`, a
domain's built-in groups such as Domain Users) or the group `ALL SERVICES`
(`S-1-5-80-0`). A group an administrator created has the SID form of an
account and is not told apart, so name an account. To change the account,
first move the earlier account's files out of `logs\` (its `audit.jsonl` and
lock) and archive them. The change runs grant, switch, revoke: the new
account is granted its access first, while the account the service is
registered under keeps its read access and its Modify on `logs\`, and the
token it reads is kept aside for it while the new account gets a new one;
`sc.exe config` then switches the service; only then are the earlier
account's access and its kept token removed. A failure before the switch leaves the service as it was, able to
start, and takes back what the new account was granted. Switching from a
password account to a gMSA or virtual account (which take no password) also
clears the password the Service Control Manager stored for the earlier
account, by passing through `NT AUTHORITY\LocalService`.

**The bearer token** at `<config dir>\http-token` has its own protected DACL
(SYSTEM, Administrators, and read for the service account). An existing token
is kept only when SYSTEM or Administrators own it, its DACL is protected and
grants nobody else, and it is not empty. Otherwise `DoctorSmokeCA` deletes it
and `RegisterServiceCA` provisions a new one (the reason is logged, never the
value); an existing token is therefore rotated on the first upgrade from an
earlier MSI. Never re-own a token with `icacls /setowner`: that would make a
value someone planted trusted. Delete it and run a repair instead. The folder
DACL is reset on every install; grant extra access on a subfolder, not the
folder.

A manual `doctor.ps1` run must pass the account the service really runs as
(`-ServiceAccount`, or `UDBMCP_SERVICE_ACCOUNT`); otherwise a token that
grants that account is removed and `logs\`'s DACL is reset. For inspection
and manual recovery, the equivalent commands:

```bat
sc.exe create udbmcp binPath= "\"C:\Program Files\UniversalDB MCP\venv\Scripts\python.exe\" -I -m universal_db_mcp serve --transport http" start= auto
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

The MSI has a fixed `UpgradeCode` and WiX `MajorUpgrade`, and its
`ProductVersion` is derived from the signed manifest's `release_seq`
(`(1 + seq>>24).((seq>>16) & 255).(seq & 65535)`, shown in Programs and
Features; the release string stays in the file name):

- **Upgrade** (newer over older): the old version is removed first (its
  `RemoveServiceCA` stops and deletes the service) and the full verify →
  venv → doctor → service sequence re-runs against the fresh payload.
  `config.yaml` is left untouched (`NeverOverwrite` and `Permanent`: the old
  product's removal no longer deletes it, which before this release put the
  template in place of the admin's config). A rebuild of the same bundle may
  replace itself. A repair or upgrade run without `UDBMCP_SERVICE_ACCOUNT`
  keeps the account the service is registered under only when `logs\`
  grants it write access, as the install that registered it did (an
  account that is a member of Administrators, such as a gMSA an
  administrator put there, counts only through exactly the Modify grant
  the registration gives, never through access it holds as an
  administrator); otherwise (an account other than
  LocalSystem with no such grant, which could only come from the command
  line) it fails, naming the remedy.
- **Anti-rollback.** `VerifyBundleCA` refuses a bundle older than the
  installed-release record `C:\Program Files\UniversalDB MCP\manifest.json`
  (a fixed path whatever `INSTALLFOLDER` is). The MSI also refuses to install
  over a newer version ("A newer version of UniversalDB MCP is already
  installed."); since `ProductVersion` follows `release_seq`, that holds for
  any older MSI, one built before `release_seq` existed (`0.1.0`) included.
  The record outlives an uninstall. An older MSI's own `verify.ps1` names no
  record, but it runs the site's trusted verifier
  (`C:\Program Files\udbmcp-trust\verify_bundle.py`, which this release
  requires to be this release's copy), and that verifier compares the bundle
  with the kept record on its own, so an older release is refused after an
  uninstall too. An intended downgrade with one of this release's MSIs is:
  uninstall, then `msiexec /i <msi> UDBMCP_ALLOW_DOWNGRADE=1` from an
  elevated prompt; the override applies to that one run. An older MSI cannot
  pass the override: the administrator deletes the record deliberately
  first. None of this has been confirmed on a Windows host.
- **A failed install, repair or upgrade** leaves the record as it was: the
  rollback action restores the copy this install made, or removes a record
  this install created, and leaves a record the install had not replaced yet
  unchanged. A process that holds `manifest.json.previous` or
  `manifest.json.kept` open (anyone can read under `C:\Program Files`) makes
  the install fail with `The process cannot access the file ... because it is
  being used by another process`; find and close it (Sysinternals
  `handle.exe`) or reboot, then rerun.
- **Uninstall** removes the install tree but keeps the release record
  `C:\Program Files\UniversalDB MCP\manifest.json`; `RemoveServiceCA` stops
  and deletes the `udbmcp` service first. `config.yaml` under
  `C:\ProgramData\UniversalDB MCP\` is retained, as the .deb keeps its
  conffile; a later install finds it and keeps it.
- **A failed repair** keeps the service registered before it, stopped: on a
  repair `RegisterServiceCA` updates the existing service in place
  (`sc.exe config`) and never deletes it, and the rollback twin deletes only
  a service a first install or an upgrade registered (`sc.exe create`). The
  log says whether it keeps its binPath and account or already runs as the
  new account, and `RollbackBuildVenvCA` puts the previous venv back. Start
  it again once the cause is fixed, or run the repair again.

### Status (honest)

**No MSI has been built on Windows, and no Windows runtime step has run.** WiX
(v4.0.5, 5.0.2 and 6.0.2 all tested) rejects every `Directory/@Name` on a
Unix host with error **WIX0389** ("... is not a relative path"), a toolchain
limitation, not an authoring defect. With only the Unix-host artefacts
transformed (directory names, cabinets) and a stubbed `msi.dll`, WiX 4.0.6
on the macOS staging host compiles and links this release's `.wxs` and
writes its tables, apart from those artefacts (2026-10-02). The earlier
authoring did not: a private search property for the registered service
account failed with **WIX0012**, so no MSI could have been built from it,
and an uninstall's `RemoveServiceCA` ran before the interpreter property was
set, which would have failed (1721) and rolled back every uninstall and
upgrade. Both are fixed (`UDBMCPREGISTEREDACCOUNT`, public and `Secure`;
`SetPowerShellExe` before `InstallInitialize`). Every first-party build step
before the compile (trusted verification of the signed `windows-x86_64-cp312` bundle,
payload staging with a no-key-material scan, deterministic harvest,
`xmllint`, a real `wix` invocation) ran and passed on the macOS staging host
(`out/package-evidence/msi/`). MSI compilation requires a **Windows** staging
host (`docs/offline-build.md`). If you ever find an `*.msi` in `dist/` on this
host, treat it as debris unless a `build_msi.sh` run log accompanies it and its
version matches the signed manifest.

**Known blocker:** the service is registered as the bare interpreter
(`python.exe -I -m universal_db_mcp serve`), which does not answer the
Windows service control dispatcher, so starting it is expected to fail with
error 1053 until a service wrapper is bundled; none is yet
(`IMPLEMENTATION_STATUS.md`, §3c).

The custom actions are covered by unit tests that execute them under
PowerShell 7 on POSIX with the Windows APIs stubbed
(`tests/unit/test_hardening_2026_09_27_msi.py`,
`tests/unit/test_msi_ca_executed_failclosed.py`); real NTFS ACL semantics
(`MsiLockPermissionsEx`, `Set-Acl` propagation), Windows PowerShell 5.1,
service start, the msodbcsql MSI interplay and a real major upgrade are
`not_run`, and so are the behaviours this release added that only a
Windows host can show: moving the venv aside while a process holds a file
in it open or mapped, `sc.exe sdset`/`sidtype`/`depend=` on a service that
runs as a virtual account, and clearing the stored password (LSA secret)
when switching to a gMSA or virtual account. The delivered gate script `scripts/test_package_msi.ps1` exercises
them on a real Windows machine (`msiexec /l*v`, `sc.exe query`, doctor, stdio
protocol probe, tamper negative, and the checks `programdata_acl`,
`token_squat_doctor`, `token_squat_refused`, `folder_squat_refused`,
`folder_squat_cleanup_reinstalled`, `installed_manifest_recorded`, which also
fails when a rollback copy or marker is left beside the record,
`rollback_refused`, `launch_conditions` and `repair_keeps_account`); none has
been run. `folder_squat_refused` expects the squatted config folder to be
refused at `CheckFoldersCA` and a squatted `config.yaml` alone at
`DoctorSmokeCA`. A failing `service_running` check (error 1053 is the known
blocker) is recorded and the checks after it still run; so do the checks
after a failing `folder_squat_refused`, `launch_conditions` or
`repair_keeps_account`, each of which records its failure and goes on
(only the admin's config folder sitting aside stops the gate: one that
could not be restored, or a `.gate-backup` an interrupted run left, found
before anything is changed; restore it and rerun).
The gate then exits nonzero. In CI these unit tests run under the
ubuntu-24.04 runner's
PowerShell 7 and the suite fails, rather than skips them, when `pwsh` is
missing; on a host without `pwsh` they still skip. Until both the Windows
build and that gate have passed, no "passed" or "verified" wording may be
read into this section.

## Claude Code registration

Run `udbmcp configure-agents` as each user who runs an agent; see
`docs/claude-code-integration.md`. A stdio registration runs the server as that
user. It must use the per-user config `~/.universal-db-mcp/config.yaml`: the
system config audits to `/var/log/universal-db-mcp`, which only the service
account can write, so a server started from it as a user refuses every tool
call (`CONFIG_ERROR: audit log write ... failed`). `configure-agents`
registers the system config whenever the user can read it. The tarball
steps above and the `.pkg` (below) install it 0640 for the service account,
but the `.deb` ships it as a `root:root` 0644 conffile, readable by every
user; on a `.deb` host give it to the service account before anyone runs
`configure-agents`:

```bash
sudo chown root:udbmcp /etc/universal-db-mcp/config.yaml && sudo chmod 640 /etc/universal-db-mcp/config.yaml
```

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
release public key is absent. From a release stick, `bootstrap.sh` does this
after checking the stick's signed file list (see
[Trust bootstrap](#trust-bootstrap-before-install) and
`docs/site-upgrade-runbook.md`). Without a stick, bootstrap both by hand:

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

Transfer the `.deb` into the air gap on approved media. From a release
stick, install the checked copy `bootstrap.sh` made and printed, never the
stick's file:

```bash
sudo dpkg -i /var/cache/udbmcp-trust/universal-db-mcp_0.1.0+<build-stamp>.g<rev7>_amd64.deb
```

(The exact version string is derived from the signed manifest — upstream
release plus a debian-style source revision — so it always matches what was
signed. The file name `bootstrap.sh` printed is the one the signed list
names, never a glob. `dpkg -i` reads the package again, and its `preinst`
runs as root before the trusted verifier sees the payload, so it must read a
copy only root can change. Without a stick, copy the `.deb` into a
root-only directory yourself and install it from there;
`sudo apt-get install ./<file>.deb` in that directory works as well.)

The package refuses a payload whose signed `release_seq` is older than the
installed release, or another release with the installed release's
`release_seq` (a different `source_rev`: `release_seq` is a commit timestamp,
which a rebase can give two commits alike). `preinst` makes both checks from
the values `build_deb.sh` wrote into it, before dpkg unpacks anything
(`FAIL: rollback refused: ... nothing was unpacked`); `postinst`'s verifier
remains the authority for what that cannot order. An intended downgrade is
`sudo UDBMCP_ALLOW_DOWNGRADE=1 dpkg -i <older .deb>`. It also refuses trusted
tools that predate this release, in `preinst`, before the old service is
stopped and the payload unpacked: an installer without
`udbmcp-installer-format: 4` or `--force-reinstall`, or a verifier without
`--installed-manifest` (each an `OUTDATED copy`); refresh them from the stick.
The installer carries a marker line per format it serves, `4` first, then
`3`: the runbook's package rollback installs the previous release's package,
which tests for its own format, with the current trusted tools.
When dpkg undoes a failed upgrade (`abort-upgrade`, `abort-remove`,
`abort-deconfigure`), `postinst` starts the service the old `prerm` stopped
again (when it is enabled) and changes nothing else. While a deferred
install of the release dpkg records is still running (its worker named in
the owner file and holding the lock), it leaves that worker alone: the
status file stays `running`, the worker starts the service itself, and the
package stays `installed`. Otherwise, if the venv is gone (the runbook's
package rollback deletes it before installing the older package), nothing
can run: it writes `failed` to the status file and exits 1, which leaves
the package `unpacked`; `sudo dpkg --configure universal-db-mcp` then
installs its payload again.
When this release's upgrade fails, because its `preinst` refuses or because
the unpack fails after `preinst` passed (a file conflict, a full disk), dpkg
runs this package's `postrm` with `abort-upgrade` and then the installed
release's `postinst` with `abort-upgrade`; one from an earlier release
ignores that argument and configures again. So the new package's `postrm
abort-upgrade` (the one script dpkg runs on every path that undoes an
upgrade) leaves a short-lived process holding the deferred-install lock
until that dpkg run ends, then starts the service again when it is enabled:
the old `postinst` spawns no install worker. It may still re-run its
configure synchronously when the bundle carries no OS packages. `preinst` (before anything is unpacked) and
`postinst` (before anything is changed) refuse while a deferred install of
another payload runs (`a deferred install ... is still running`; wait for
`success` or `failed` in the status file, then install or configure again);
a worker of this same payload is left to finish. The worker itself stops,
starting nothing, when another dpkg run has changed the package version or
the unpacked payload since it was spawned.
On upgrade, root-owned `audit.jsonl*` files in `/var/log/universal-db-mcp`
(the log, its `.lock`, rotated backups; regular files with one link) are
handed back to `udbmcp` with mode 0600, and each is printed.

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
   canonical copy stays at `/usr/share/universal-db-mcp/systemd/`). To tell
   the two apart, postinst keeps the hash of the unit it deployed at
   `/var/lib/universal-db-mcp-package/shipped-unit.sha256` (the directory
   root-only, 0700), read and written without following a link. An older
   release's record, `/var/lib/universal-db-mcp/.shipped-unit.sha256` in the
   service account's directory, is taken over once, only when it is a
   root-owned regular file with one link holding one hash, and then removed,
   so a record the service account wrote, or a link, no longer decides
   whether an admin-modified unit is replaced. Failing to write the record
   only warns. Postinst unsets `TMPDIR`, `TEMP` and `TMP` at start, so its
   worker and the trusted installer it runs make root's temporary files in
   the system's `/tmp`.
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

The conffile arrives `root:root` 0644, readable by every user. Give it to
the service account first: `udbmcp add-connection` refuses a `root:root`
config, and `configure-agents` would register a config its users can read
(see [Claude Code registration](#claude-code-registration)). Then edit it for
your connections and run the doctor exactly as in [Configure](#configure):

```bash
sudo chown root:udbmcp /etc/universal-db-mcp/config.yaml && sudo chmod 640 /etc/universal-db-mcp/config.yaml
sudo -u udbmcp /opt/universal-db-mcp/venv/bin/python -m universal_db_mcp doctor --config /etc/universal-db-mcp/config.yaml
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
| `dpkg -P` (purge) | stopped and disabled: dpkg runs the package's `prerm remove` before `postrm remove` and `postrm purge`, so the service is handled exactly as on `dpkg -r` (a manual stop first is harmless) | **deleted** (dpkg removes conffiles on purge; `postrm` also removes the postinst-seeded fallback copy — belt and braces; `/etc/universal-db-mcp/keys/` with the release public key is never touched) | deleted, plus installer staging leftovers under `/usr/share/universal-db-mcp/bundle` and the unit-hash record `/var/lib/universal-db-mcp-package` | **kept** — the audit trail must outlive the package; delete explicitly if you really want it gone |

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
splits the work honestly. The package's Distribution declares the arm64 host
(`hostArchitectures="arm64"`), so the Installer refuses an Intel Mac and runs
the scripts natively; should it still run them under Rosetta 2, each script
starts over as a native arm64 process, and the verifier judges the hardware
architecture, not the translated process's (a universal2 python started
under Rosetta reported x86_64 and the arm64 bundle was refused). An
interpreter with no arm64 code (an x86_64-only CPython, which always runs
translated and would get x86_64 wheels) is refused for the arm64 profile:
use a universal2 or arm64 CPython 3.12. How the
real Installer treats the declaration is confirmed only by a real install:

- **`preinstall`** checks the trust *prerequisites* only (trusted verifier,
  release public key, CPython 3.12 per-machine install) and **fails closed
  (exit 1, the Installer aborts)** with bootstrap instructions if any is
  missing, if the verifier predates `--installed-manifest`, or if the
  payload is an older release than the installed one (or another release
  with its `release_seq`);
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
- **A root-owned CPython 3.12, installed for all users.** The installer runs
  this interpreter as root before the payload is verified, so its whole
  installation and every directory above it must be owned by root and
  writable by root only, with no ACL, and none of its symlinks may lead out
  of it. The supported interpreter is the python.org 3.12 installer (lands
  in `/Library/Frameworks/Python.framework/Versions/3.12/`), which leaves the
  framework writable by the admin group, so after installing it run:

  ```bash
  sudo chown -R root:wheel /Library/Frameworks/Python.framework; sudo chmod -R go-w /Library/Frameworks/Python.framework; sudo chmod -R -N /Library/Frameworks/Python.framework
  ```

  `preinstall` refuses any other interpreter tree with `FAIL: refusing to run
  <python> as root: <reason>` and prints the fix (`sudo chown -R root:wheel
  <tree>; sudo chmod -R go-w <tree>; sudo chmod -R -N <tree>`, or
  `sudo rm <link>` for a symlink that leads out of it); the resolved binary is
  what runs. A Homebrew `python@3.12` qualifies only when the whole Homebrew
  prefix is owned by root (which stops `brew` working for the admin user), and
  a prefix with cask links into `/Applications` is refused. A virtual
  environment is never accepted. Per-user installs (`~/Library/Python`) and
  version managers do **not** satisfy this requirement either: the service
  runs as the `_udbmcp` account, which cannot see them.
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

The trust dir (`/usr/local/lib/udbmcp-trust`), the key dir
(`/etc/universal-db-mcp/keys`) and their parents must be root-only with no
ACL, as `sudo install` leaves them. Copy this release's `verify_bundle.py`
and `profiles.py` on every upgrade: a verifier without `--installed-manifest`
is refused as an `OUTDATED copy`.

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

**Downgrades.** `preinstall` refuses a package whose `release_seq` is lower
than the installed release's (`/usr/local/universal-db-mcp/manifest.json`)
before any file of it is written, so a refused downgrade leaves the installed
release intact: `FAIL: this package is release_seq N, OLDER than the installed
release_seq M ...`. The Installer drops the caller's environment, so an
intended downgrade is authorised with a flag file that names the older
package's own `release_seq` (the refusal prints the exact command):

```bash
echo <release_seq> | sudo tee /etc/universal-db-mcp/allow-downgrade
```

The flag counts only when root alone wrote it (a regular file with one link,
owned by root, in a root-only directory with no ACL). It authorises that one
release for one attempt and is removed afterwards even when the attempt
fails, so write it again before a retry. `sudo touch` is enough only for a
package built without a `release_seq`. An unreadable installed manifest is
refused in `postinstall` with the same advice.

A `.pkg` built before this release has no such check in its `preinstall`,
and its `postinstall` names no installed manifest. Once the trust dir holds
this release's verifier, that verifier compares the bundle with
`/usr/local/universal-db-mcp/manifest.json` on its own and refuses an older
release, but only in `postinstall`, after the Installer has written the old
payload (`/usr/local/universal-db-mcp/bundle/`,
`/usr/local/universal-db-mcp/share/` and the LaunchDaemon plist), which it
does not put back. The venv is not touched, but the old plist lacks the
`NumberOfFiles` 65536 limits and `UDBMCP_HTTP_LOG_FILE`: re-install the
current release's `.pkg` to restore them (the refusal says so). Such a
package cannot use the flag file; to install one deliberately, move
`/usr/local/universal-db-mcp/manifest.json` aside first.

What `postinstall` does, in order (with a system-only `PATH`, and every root
Python run isolated):

1. **Verify the unpacked payload** with
   `python3 /usr/local/lib/udbmcp-trust/verify_bundle.py --bundle
   /usr/local/universal-db-mcp/bundle --pubkey
   /etc/universal-db-mcp/keys/release.pub.pem --installed-manifest
   /usr/local/universal-db-mcp/manifest.json`. It refuses to run a verifier
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
   Root-owned `audit.jsonl*` files there are handed back to `_udbmcp` (0600).
   **No root job rotates the logs**: the package ships no newsyslog(8) rule,
   and the postinstall removes an earlier release's
   `/etc/newsyslog.d/udbmcp.conf` and
   `/usr/local/universal-db-mcp/share/udbmcp.newsyslog.conf` (printing
   `==> postinstall: removed <path> ...`); if a removal fails, the install
   stops with `FAIL: could not remove <path>, ...` before the daemon starts.
   That rule had root rename, compress and re-own files in a directory
   `_udbmcp` owns, where a compromised service account could have planted
   links. Existing `*.log.N.bz2` archives are left in place.
   **launchd's output files**: launchd opens the daemon's stdout and stderr
   itself, as root, so they live in `/Library/Logs/universal-db-mcp`
   (`server.log`, `server.err.log`), a `root:wheel` 0755 directory, with the
   files `_udbmcp:_udbmcp` 0640. The install fails closed if that directory
   is a symlink, if it or any directory above it is not root's alone (owner,
   group or other write, or an ACL), or if either file is a symlink or not a
   regular file; existing files are kept and handed to `_udbmcp` (only a
   warning when that fails). The daemon keeps them under 5 MiB itself
   (`docs/security.md`, Transport). On upgrade the old `server.log` and
   `server.err.log` in `/var/log/universal-db-mcp` are left in place and no
   longer written.
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
10. **Configure app**: `Configure UniversalDB MCP.app` is assembled in
   `/var/tmp/udbmcp-app.XXXXXX` and renamed over any existing
   `/Applications` entry, which is removed first, so nothing an admin-group
   process put at that name beforehand receives root's writes. The closing
   message reads `4. Server logs: /var/log/universal-db-mcp/http.log;
   launchd's stdout and stderr: /Library/Logs/universal-db-mcp (launchd
   label: system/com.udbmcp.server)`, and the Installer's conclusion page
   lists both directories.

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
`WantedBy=multi-user.target`, `UDBMCP_CONFIG` environment, and
`NumberOfFiles 65536` for the listener's descriptors. The runtime log is
`/var/log/universal-db-mcp/http.log` (`UDBMCP_HTTP_LOG_FILE`, 5 MiB x 3);
launchd's stdout and stderr go to `/Library/Logs/universal-db-mcp/server.log`
and `server.err.log`, which carries startup output and ERROR records such as
a bind failure, which `http.log` also has. `serve` empties either file at
startup when it is over 5 MiB, and `server.err.log` before an ERROR record
once it is, but only a file `_udbmcp` owns with one link: if an
administrator deletes one, launchd recreates it as root and it is no longer
capped until the next `.pkg` install hands it back.

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
