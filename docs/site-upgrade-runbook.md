# Site runbook: upgrade in place, or erase and reinstall (Ubuntu, air-gapped)

For any release folder `usb-ubuntu-<sha7>/` (this copy ships on the stick as
`UPGRADE-README.md`). Every command runs on the air-gapped Ubuntu host,
offline, as an administrator who can `sudo`. Nothing here touches any
database server. The commands are written so that they can be pasted a
block at a time; each block is self-contained after step 0.

Read "Behaviour changes in this release" (near the end) before the first
query after the upgrade: some saved agent prompts and configs need a change.

The stick carries this file but not the documents it cites. A reference to
`docs/<name>.md` means `/usr/share/universal-db-mcp/bundle/docs/<name>.md`
once this release's package is installed (the same file is in the
repository's `docs/`).

What is on the stick:

| Path | Purpose |
|---|---|
| `SHA256SUMS` | SHA-256 of every other file on the stick |
| `SHA256SUMS.sig` | Ed25519 signature of `SHA256SUMS`, made with the release key; this is what makes the list trustworthy |
| `universal-db-mcp_0.1.0+<build stamp>.g<sha7>_amd64.deb` | the package (its payload is the signed offline bundle); the version rises with every build |
| `trust-bootstrap-linux/` | the trusted verifier, installer, `bootstrap.sh`, the release public key and `RELEASE`, this stick's release number (its bundle's `release_seq`) |
| `RELEASE-KEY-FINGERPRINT.txt` | SHA-256 fingerprint of the release public key on this stick, written by the release build. It is on the same stick, so it proves nothing on its own: compare fingerprints with the value your release administrator gave you out of band |
| `oracle-instantclient/` | Oracle Instant Client 19.28, `libaio` and `unzip`, only for thick-mode Oracle connections |
| `UPGRADE-README.md` | this file |

Which path to take:

- **Path A, upgrade in place**: keeps `/etc/universal-db-mcp/config.yaml`,
  the per-user config under `~/.universal-db-mcp/`, the audit log and the
  metadata cache. This is the normal path.
- **Path B, erase and reinstall**: for an install in an unknown state (a
  failed earlier upgrade, a venv that still runs old code, a status file
  stuck at `failed` or `running`, a package dpkg calls "half-installed").
  It deletes the venv, the system config and the systemd unit; the runbook
  backs them up first.

Both paths share steps 0 and 1 and end with the same verification.

## Step 0: mount the stick, check its signature, record what is installed

Ubuntu Server does not auto-mount removable media. Mount the stick read-only
with modes every user can traverse (a plain `sudo mount` under a hardened
umask gives a root-only mount point):

```bash
lsblk -o NAME,SIZE,FSTYPE,LABEL,MOUNTPOINT          # find the stick, for example sdb1
sudo mkdir -p /mnt/usb
sudo mount -o ro,uid=$(id -u),gid=$(id -g),umask=022 /dev/sdb1 /mnt/usb   # adjust sdb1
ls /mnt/usb
```

**Check the signature before anything from the stick runs.** Nothing below
executes a file from the stick: the host's own `/usr/bin/openssl` checks
`SHA256SUMS.sig` with a key the site already trusts. `sha256sum -c` alone
proves nothing, because whoever can change the stick can regenerate
`SHA256SUMS` too.

On a site that is already installed (an upgrade), use the installed key:

```bash
STICK=/mnt/usb/usb-ubuntu-<sha7>          # the folder name on the stick, typed exactly
KEY=/etc/universal-db-mcp/keys/release.pub.pem
/usr/bin/openssl pkeyutl -verify -pubin -inkey "$KEY" -rawin \
  -in "$STICK/SHA256SUMS" -sigfile "$STICK/SHA256SUMS.sig"   # must print: Signature Verified Successfully
```

On a first install (no key installed yet), first compare the fingerprint of
the key on the stick with the value your release administrator gave you out
of band (by phone, in person, on paper), then check the signature with it:

```bash
STICK=/mnt/usb/usb-ubuntu-<sha7>
KEY="$STICK/trust-bootstrap-linux/release.pub.pem"
/usr/bin/openssl pkey -pubin -in "$KEY" -outform DER | sha256sum   # must equal the out-of-band value
/usr/bin/openssl pkeyutl -verify -pubin -inkey "$KEY" -rawin \
  -in "$STICK/SHA256SUMS" -sigfile "$STICK/SHA256SUMS.sig"          # must print: Signature Verified Successfully
```

Stop if the fingerprint differs or the command does not print `Signature
Verified Successfully`: the stick was altered or is not a release stick. Use
another copy. A release signed with a new key fails this check on an upgrade;
that is expected only when your release administrator has told you the key
changed (see step 1, `--rotate-key`).

Then, in the shell you will use for the rest of the runbook, take the package
name from the signed list (never from a directory glob, which would also
match a file added to the stick later) and record what is installed now:

```bash
DEBNAME=$(awk '$2 ~ /^universal-db-mcp_[^\/]*_amd64\.deb$/ { print $2 }' "$STICK/SHA256SUMS")
[ "$(printf '%s\n' "$DEBNAME" | grep -c .)" -eq 1 ] || echo "STOP: the signed list does not name exactly one package"
DEB="/var/cache/udbmcp-trust/$DEBNAME"; echo "package (the copy step 1 checks and installs from): $DEB"
SHA=$(printf '%s' "$DEBNAME" | sed -E 's/^.*\.g([0-9a-f]+)_amd64\.deb$/\1/'); echo "release commit (short): $SHA"
(cd "$STICK" && sha256sum -c --strict SHA256SUMS)    # every line must end in ": OK"

# what is installed right now (keep this output; it is your rollback reference)
dpkg -s universal-db-mcp 2>/dev/null | grep -E '^(Status|Version)' || echo "package not installed"
sudo python3 -I -c 'import json; m = json.load(open("/opt/universal-db-mcp/manifest.json")); print("installed source_rev:", m.get("source_rev"), "release_seq:", m.get("release_seq"))' 2>/dev/null || echo "no installed manifest"
cat /var/log/universal-db-mcp-install.status 2>/dev/null || echo "no install status file"
systemctl is-active universal-db-mcp || true
```

`sha256sum -c` checks only the files the list names. A file added to the
stick (a second `.deb`, another `libaio` package) is on nobody's list, and it
is `bootstrap.sh` in step 1, not `sha256sum -c`, that refuses it. If
`dpkg -s` prints `Status: install reinstreq half-installed`, an earlier
`dpkg -i` was interrupted hard; see "dpkg says half-installed" under Path B
before doing anything else.

## Step 1 (always): refresh the trusted tools from THIS stick

The package never installs its own verifier or installer; it runs the copies
under `/usr/local/lib/udbmcp-trust/`, and it refuses copies that are too old
for it (see below). Refresh them on every upgrade, and never run an OLDER
stick's bootstrap afterwards (from this release on, the installed
`bootstrap.sh` refuses an older stick itself, see below).

On an upgrade, run the copy of `bootstrap.sh` that an earlier release
installed, against the new stick. It checks the stick's `SHA256SUMS.sig` with
the INSTALLED key before it reads anything else from the stick:

```bash
if [ -s /usr/local/lib/udbmcp-trust/bootstrap.sh ]; then
  sudo bash /usr/local/lib/udbmcp-trust/bootstrap.sh --stick "$STICK"
else
  # first install, or a site whose trust dir predates bootstrap.sh: only after step 0 passed
  sudo bash "$STICK/trust-bootstrap-linux/bootstrap.sh"
fi
grep -c -- --force-reinstall /usr/local/lib/udbmcp-trust/install_offline.sh    # must print 2
grep -c 'udbmcp-installer-format: 4' /usr/local/lib/udbmcp-trust/install_offline.sh   # must print 1
grep -c -- --installed-manifest /usr/local/lib/udbmcp-trust/verify_bundle.py   # must print more than 0
sudo ls -l "$DEB"                                                              # the checked copy step 0 named
cat "$STICK/trust-bootstrap-linux/RELEASE"                                     # this stick's release
sudo cat /usr/local/lib/udbmcp-trust/RELEASE                                   # must print the same number
```

If the last command prints nothing (`No such file or directory`), the
bootstrap that ran was an earlier release's, which does not record
releases. Run `sudo bash /usr/local/lib/udbmcp-trust/bootstrap.sh --stick
"$STICK"` once more: this release's copy, now installed, checks the stick
again and records its release (`release order: stick release N, nothing
recorded yet`). From then on an older stick is refused.

Always run `bootstrap.sh` by a path that names the stick: `cd
trust-bootstrap-linux; sudo bash bootstrap.sh` is refused (exit 2). What it
does, in order, and what it refuses:

- It prints the SHA-256 fingerprint of the key on the stick and of the
  installed key. The same key is left in place. A DIFFERENT key makes it stop:
  a stick that carried its own key, verifier and package would otherwise
  verify itself. Only when your release administrator has confirmed the new
  fingerprint out of band, re-run it with `--rotate-key` added.
- The stick must hold regular files only: a symlink, FIFO, device node, a
  symlinked `trust-bootstrap-linux`, or a file name with a line break is
  refused before anything is read (`FAIL: <path> is not a regular file; a
  release stick holds regular files only.`, `FAIL: the stick holds a file name
  with a line break ...`). Mac and Windows metadata (`._*` and `.DS_Store`
  files, `.Spotlight-V100`, `.fseventsd`, `.Trashes`, `.TemporaryItems`,
  `System Volume Information`) is skipped.
- It works on a private copy of `trust-bootstrap-linux/`, `SHA256SUMS` and
  `SHA256SUMS.sig`, made under `/var/tmp` (it unsets `TMPDIR`, `TEMP` and
  `TMP` first), and refuses anything in that copy that is not a regular file
  (`... The stick changed while it was read.`). A missing `SHA256SUMS` or
  `SHA256SUMS.sig`, or a directory by either name, is named (`FAIL: the
  stick has no ...`).
- `SHA256SUMS.sig` is checked with the installed key (with the stick's key
  only on a first install or after `--rotate-key`), using the installed
  verifier or `/usr/bin/openssl`. Then every file on the stick must match the
  signed list, and a file the list does not name is refused (`FAIL: <file> is
  on the stick but not on its signed SHA256SUMS.`). Its private copy of
  `trust-bootstrap-linux/` is compared with the signed list again, so a file
  that appeared while the stick was read is refused too (`FAIL: <path> is in
  the private copy of the stick but not on its signed SHA256SUMS.` / `The
  stick changed while it was read. ...`). An unreadable key is named in a
  `FAIL` line. On any failure the trust dir is left untouched and nothing is
  installed.
- It checks the release order. The stick's `trust-bootstrap-linux/RELEASE`
  (read from the checked copy, so only when the signed list names it) is
  compared with the release recorded at
  `/usr/local/lib/udbmcp-trust/RELEASE`, and a `release order:` line says
  which is which. A stick whose release is lower, or a stick with no
  `RELEASE` once one is recorded, is refused (`FAIL: this stick is release
  N, OLDER than release M whose trust tools are installed.`): its tools are
  genuinely signed, and they would put back what later releases fixed. An
  intended downgrade re-runs the printed command with `--allow-downgrade`.
  A malformed `RELEASE` on the stick is refused always. A stick of the same
  release passes only when its trust tools are byte-identical to the
  installed ones; tools that differ under the same number are refused as
  another, possibly older, release. With nothing recorded yet, any signed
  stick is accepted.
- It copies every `.deb` the signed list names (the package, and the
  `libaio` and `unzip` packages of the Oracle step) into a new root-only
  directory, `/var/cache/udbmcp-trust.new.XXXXXX`, checks those copies
  against the signed list again (`FAIL: a package copied from the stick does
  not match its signed SHA256SUMS ...`), and only then swaps it in as
  `/var/cache/udbmcp-trust/`. On any failure, a `cp` error included (`FAIL:
  <deb> could not be copied from the stick ... Nothing was installed.`),
  an earlier release's checked copies stay in place. `dpkg -i` reads a
  package again and runs its `preinst` as root, so it is always given these
  copies, never the stick's files. They stay until the next bootstrap run
  replaces them (about 65 MB).
- It installs `bootstrap.sh`, `verify_bundle.py`, `profiles.py`,
  `install_offline.sh` and `lib/os_packages.sh` to
  `/usr/local/lib/udbmcp-trust/` and the key to
  `/etc/universal-db-mcp/keys/release.pub.pem`, records the stick's release
  in `/usr/local/lib/udbmcp-trust/RELEASE` (and prints it on its `release  :`
  line), prints `sudo dpkg -i /var/cache/udbmcp-trust/<package>` for the
  package the signed list names (the `$DEB` set in step 0), and the command
  to use on the next upgrade.

The package refuses to install over a trusted installer that lacks the
`udbmcp-installer-format: 4` marker or `--force-reinstall`, and over a
verifier that cannot check the release order (`--installed-manifest`); each
diagnostic says `OUTDATED copy`, and this step is the fix.

## Path A: upgrade in place

Close every Claude Code (or other MCP client) session first. The systemd
service is gated until the install records success, but a stdio
registration spawns `/opt/universal-db-mcp/venv/bin/python` directly with
no such gate, and the venv is rebuilt in place during the upgrade.

```bash
sudo systemctl stop universal-db-mcp 2>/dev/null || true
sudo dpkg -i "$DEB"
```

Expect and accept during the install:

- No downgrade warning is expected: versions are
  `0.1.0+<build stamp>.g<commit>` and rise with every build. If you see
  `dpkg: warning: downgrading`, the stick is older than what is installed:
  stop and check the build stamps. The install then fails anyway: the
  verifier refuses a bundle whose signed `release_seq` is lower than the
  installed one (`FAIL: rollback refused: this bundle is an OLDER release than
  the one installed ...`), unless you asked for the downgrade (see Rollback).
- If dpkg asks what to do with `/etc/universal-db-mcp/config.yaml`
  ("configuration file … modified"), answer `N` (keep your current
  version). Your connections and security block are in that file; the
  shipped default is only a template.
- `dpkg -i` returns BEFORE the install is finished. The payload is verified
  synchronously; then a root worker waits for dpkg to release its locks and
  runs the trusted installer (venv rebuilt with `--force-reinstall`, ODBC
  driver packages, smoke check). The service refuses to start until the
  worker records `success`. The upgrade also hands root-owned
  `audit.jsonl*` files in `/var/log/universal-db-mcp` (left by an older
  release's root `site-check` or `doctor`) back to the service account and
  prints each one it repaired.

Wait for the worker (usually one to three minutes; the loop ends on
`success` or `failed`):

```bash
until grep -qxE 'success|failed' /var/log/universal-db-mcp-install.status 2>/dev/null; do sleep 5; done
cat /var/log/universal-db-mcp-install.status
sudo tail -n 40 /var/log/universal-db-mcp-install.log      # the log is root-only; on 'failed' the reason is here
```

On `success`, check the config against this release before starting the
service (see "Behaviour changes in this release": a config this release
refuses keeps the service from starting), then start it:

```bash
sudo -u udbmcp /opt/universal-db-mcp/venv/bin/python -m universal_db_mcp doctor --config /etc/universal-db-mcp/config.yaml
sudo systemctl restart universal-db-mcp
```

On `failed`: fix the cause the log names (a file missing from the trust dir,
a full disk, a dpkg lock held by something else), then install the package
AGAIN with `sudo dpkg -i "$DEB"` and repeat the wait. Do not use
`dpkg --configure`: after a deferred failure dpkg already considers the
package configured and answers "already installed and configured". If the
status stays `running` for more than 15 minutes, `sudo tail` the log; the
worker waits up to one hour for another dpkg to finish before giving up.
If a second `dpkg -i` fails the same way, take Path B.

## Path B: erase the current install and reinstall clean

**First make sure no deferred worker is still running.** A worker from an
earlier install holds `/run/udbmcp-deferred-install.lock`; purging under it
leaves the reinstall without a worker and without a status file.

```bash
sudo flock -w 900 /run/udbmcp-deferred-install.lock true && echo "no worker running"
```

If that prints nothing within 15 minutes the worker is stuck; the clean
offline remedy is a reboot of the host, then continue here.

**Back up what you may want back.** Purge deletes the system config, the
systemd unit and any `systemctl edit` override; the audit log under
`/var/log/universal-db-mcp/` and the keys are never deleted, but a copy
costs nothing:

```bash
B=/root/udbmcp-backup-$(date +%F-%H%M); echo "$B" | sudo tee /root/udbmcp-last-backup
sudo mkdir -p "$B"
sudo cp -a /etc/universal-db-mcp "$B/etc"
sudo cp -a /etc/systemd/system/universal-db-mcp.service "$B/" 2>/dev/null || true
sudo cp -a /etc/systemd/system/universal-db-mcp.service.d "$B/" 2>/dev/null || true
sudo cp -a /var/log/universal-db-mcp "$B/audit-log" 2>/dev/null || true       # audit trail
sudo cp -a /var/lib/universal-db-mcp "$B/state" 2>/dev/null || true           # metadata cache, demo db
cp -a ~/.universal-db-mcp ~/udbmcp-user-backup-$(date +%F-%H%M) 2>/dev/null || true   # your per-user config (purge never touches it)
sudo ls "$B"
```

**Purge and remove leftovers.** dpkg runs the package's `prerm remove`
first, which stops and disables the service itself; the explicit stop is a
harmless belt and braces:

```bash
sudo systemctl stop universal-db-mcp 2>/dev/null || true
sudo dpkg -P universal-db-mcp
sudo rm -rf /opt/universal-db-mcp /usr/share/universal-db-mcp
sudo rm -f /var/log/universal-db-mcp-install.status /var/log/universal-db-mcp-install.log
sudo rm -f /var/lib/universal-db-mcp/metadata.sqlite      # cache only; the audit log stays
```

Removing `/opt/universal-db-mcp` also removes the installed-release record
(`manifest.json`) that anti-rollback compares against, so the reinstall
accepts any signed release; install the stick you verified in step 0.

dpkg says half-installed: if `dpkg -P` (or the earlier `dpkg -s`) reports
`package is in a very bad inconsistent state` / `reinstreq`, an earlier
`dpkg -i` was killed mid-way. Either `sudo dpkg -i "$DEB"` once (repairs the
record, then purge as above) or `sudo dpkg -P --force-remove-reinstreq
universal-db-mcp`.

**Install and wait** (step 1 already refreshed the trusted tools from this
stick):

```bash
sudo dpkg -i "$DEB"
until grep -qxE 'success|failed' /var/log/universal-db-mcp-install.status 2>/dev/null; do sleep 5; done
cat /var/log/universal-db-mcp-install.status              # must say success; on failed: sudo tail -n 40 /var/log/universal-db-mcp-install.log
```

**Put your configuration back** (the fresh install seeded only the
template), check it against this release, and start:

```bash
B=$(sudo cat /root/udbmcp-last-backup)
sudo cp "$B/etc/config.yaml" /etc/universal-db-mcp/config.yaml
sudo chown root:udbmcp /etc/universal-db-mcp/config.yaml && sudo chmod 640 /etc/universal-db-mcp/config.yaml
sudo cp -a "$B/etc/http-token" /etc/universal-db-mcp/ 2>/dev/null || true
if [ -d "$B/universal-db-mcp.service.d" ]; then sudo cp -a "$B/universal-db-mcp.service.d" /etc/systemd/system/ && sudo systemctl daemon-reload; fi
sudo -u udbmcp /opt/universal-db-mcp/venv/bin/python -m universal_db_mcp doctor --config /etc/universal-db-mcp/config.yaml
sudo systemctl restart universal-db-mcp
```

Password files referenced by the config (`password_file:`) are wherever you
placed them; purge does not touch them. If you had edited the unit itself
(not a drop-in), diff `$B/universal-db-mcp.service` against the installed
`/etc/systemd/system/universal-db-mcp.service` and re-apply your change with
`sudo systemctl edit universal-db-mcp`.

## Oracle thick mode (only for the account with the legacy 10G verifier, or an 11g server)

Skip this if every Oracle connection already works. Ubuntu Server has no
`unzip`; the stick carries it. The block is a subshell with absolute paths,
so it can be repeated from any directory, and it sets modes explicitly
because the service account must be able to traverse `/opt/oracle`. The file
names are the ones on this release's signed `SHA256SUMS`; step 1 refused any
other file on the stick. The two packages are installed from the copies step 1
checked (`dpkg -i` runs their maintainer scripts as root). `bootstrap.sh` does
not copy the Instant Client zip, so the block copies it next to them, checks
the signature of a fresh copy of the signed list with the installed key, and
checks the zip against that list before unzipping it:

```bash
( set -e; C=/var/cache/udbmcp-trust/oracle-instantclient; Z=instantclient-basiclite-linux.x64-19.28.zip
  sudo dpkg -i "$C/libaio1t64_0.3.113-6build1.1_amd64.deb"
  command -v unzip >/dev/null || sudo dpkg -i "$C/unzip_6.0-28ubuntu4.1_amd64.deb"
  ls /usr/lib/x86_64-linux-gnu/libaio.so.1 >/dev/null 2>&1 || \
    sudo ln -s /usr/lib/x86_64-linux-gnu/libaio.so.1t64 /usr/lib/x86_64-linux-gnu/libaio.so.1
  sudo cp "$STICK/SHA256SUMS" "$STICK/SHA256SUMS.sig" "$STICK/oracle-instantclient/$Z" "$C/"
  sudo /usr/bin/openssl pkeyutl -verify -pubin -inkey /etc/universal-db-mcp/keys/release.pub.pem -rawin \
    -in "$C/SHA256SUMS" -sigfile "$C/SHA256SUMS.sig"                # must print: Signature Verified Successfully
  sudo awk -v c="$C" -v z="$Z" '$2 == "oracle-instantclient/" z { print $1 "  " c "/" z }' "$C/SHA256SUMS" \
    | sudo sha256sum -c --strict -                                   # must print: ...: OK
  sudo install -d -m 755 /opt/oracle
  sudo unzip -oq "$C/$Z" -d /opt/oracle
  sudo chmod -R a+rX /opt/oracle
  echo /opt/oracle/instantclient_19_28 | sudo tee /etc/ld.so.conf.d/oracle-instantclient.conf >/dev/null
  sudo ldconfig
  ldconfig -p | grep libclntsh                                   # must print a line
  sudo -u udbmcp ls /opt/oracle/instantclient_19_28/libclntsh.so.19.1   # the service account can reach it
)
```

If `dpkg -i` reports that a file does not exist, list the folder: the signed
`SHA256SUMS` names the package files this release carries.

Then set `options: {thick_mode: true}` on that connection (no `lib_dir` on
Linux) and restart the service. Every Oracle connection in one config must
use the same mode: thick mode is process-wide.

## Verify (both paths)

```bash
# the installed code is this stick's release
sudo python3 -I -c 'import json; print(json.load(open("/opt/universal-db-mcp/manifest.json"))["source_rev"])'; echo "expected to start with: $SHA"
grep -c server_read_only_session /opt/universal-db-mcp/venv/lib/python3.12/site-packages/universal_db_mcp/server.py
#   -> greater than 0: THIS release's code is in the installed venv, not only in the package
#   (server_read_only_session is new in this release)

# the service
systemctl status universal-db-mcp --no-pager | head -5
sudo -u udbmcp /opt/universal-db-mcp/venv/bin/python -m universal_db_mcp doctor --config /etc/universal-db-mcp/config.yaml

# the per-user config that Claude Code (stdio) uses, if you have one
/opt/universal-db-mcp/venv/bin/python -m universal_db_mcp doctor --config ~/.universal-db-mcp/config.yaml
```

Then run the site check: one read-only pass over every connection through
the same tools an agent uses (connection, listing, catalog, profile, plan,
review, search), which writes a JSON report made of counts, codes, names
and timings only, never a row value, so it can leave the site. Write it into
a private directory, never a fixed path under `/tmp`:

```bash
OUT=$(sudo -u udbmcp mktemp -d /tmp/udbmcp-site-check.XXXXXX)
sudo -u udbmcp /opt/universal-db-mcp/venv/bin/python -m universal_db_mcp site-check \
  --config /etc/universal-db-mcp/config.yaml --out "$OUT/report.json"
sudo cat "$OUT/report.json" > ~/udbmcp-site-check.json && sudo rm -rf "$OUT"
```

Run it as the service account (`sudo -u udbmcp`), not as root: a root run
creates audit files the service then cannot write. The report is written
private (mode 0600), never over an existing file and never through a symlink;
`--force` replaces only a regular file you own.

It prints one line per connection (`connection=ok list_tables=ok catalog=ok
profile=ok explain=ok review=ok search=ok`) and exits non-zero when a step
failed; `explain=SKIPPED` on Db2 means the DBA has not provisioned explain
tables, which is expected and harmless. Bring `~/udbmcp-site-check.json`
back for diagnosis; it is safe to share.

Then start a new Claude Code session. If it was registered with an earlier
release, re-run `udbmcp configure-agents` first (see below). Ask it to run
`db_list_connections`, then `db_test_connection` on each connection. The
reply carries a `session` block: Db2 shows `isolation: ur` and
`lock_timeout_seconds: 5`, PostgreSQL and MySQL show `read_only_verified:
true`, SQL Server shows `read_uncommitted`; `data.audit` shows the audit path
and `dropped_records: 0`. The tool list should hold 29 tools.

## Behaviour changes in this release

This release closes a security and production review (95 findings), the
review rounds that checked its fixes, and a convergence wave that fixed
whole classes of defects and attacked the result again. Most changes are
invisible; these are the ones an operator or an agent notices. `docs/security.md` and
`docs/tools.md` have the details.

**Before or during the upgrade**

- **Stick signature and trust tools.** The stick carries `SHA256SUMS.sig`;
  check it in step 0, and from now on run the installed
  `/usr/local/lib/udbmcp-trust/bootstrap.sh --stick <stick>`. `bootstrap.sh`
  refuses files not on the signed list, non-regular files and names with
  line breaks, and copies the packages into `/var/cache/udbmcp-trust/`,
  where it checks them again: `dpkg -i` those copies, never the stick's
  files. The package refuses trusted tools that predate this release
  (`OUTDATED copy`; the installer's marker is now
  `udbmcp-installer-format: 4`, and it keeps a `3` line so the previous
  release's package still installs with it on a rollback): step 1 is
  mandatory. The `.deb` makes that
  check, and the older-release check below, in `preinst`, before dpkg stops
  the service and unpacks anything; if dpkg undoes a failed upgrade,
  `postinst` starts the service again. A refused upgrade keeps the installed
  release's `postinst`, which dpkg runs to undo it, from starting a deferred
  install worker (it may still re-run its configure itself when the bundle
  has no OS packages), and `preinst` and `postinst` refuse while a deferred
  install of another payload is still running: wait until the status file
  says `success` or `failed`, then install again. Sticks are ordered: each
  carries `trust-bootstrap-linux/RELEASE` on its signed list, and the installed
  `bootstrap.sh` records it in `/usr/local/lib/udbmcp-trust/RELEASE` and
  refuses an older stick, or one of the same number whose trust tools
  differ from the installed ones (`--allow-downgrade` to mean it); on the
  first upgrade to this release run it twice, as step 1 says, so the release is
  recorded.
- **Installers work on a private copy.** `install_offline.sh`,
  `upgrade_offline.sh` and `load_images_offline.sh` verify the bundle, copy
  it to `/var/tmp/udbmcp-*.XXXXXX/bundle` (root-only: no owners, group or
  other bits, or links kept; only the owner bits of each mode carry over),
  verify the copy and use only the copy. They stop when
  `UDBMCP_STAGING_DIR` (or `/var/tmp`) or a directory above it is not root's
  alone, and unset a `TMPDIR`, `TEMP` or `TMP` that is not, with `NOTE:
  <VAR> (<value>) is not root's alone; root's temporary files are not made
  there` (a `sudo -E` from a user shell prints it; nothing to do). The
  verifier refuses a bundle holding a symlink, FIFO or device, or a
  hard-linked `SHA256SUMS` or `SIGNATURE`: copy bundles plainly, never with
  `cp -al` or `rsync --link-dest`. The `.deb` keeps its record of the
  deployed unit in `/var/lib/universal-db-mcp-package/` (root-only), which
  purge removes.
- **Anti-rollback.** Every bundle carries a signed `release_seq`. The
  installers refuse a bundle older than the installed release (`FAIL: rollback
  refused ...`), and another release with the installed release's
  `release_seq` (a different `source_rev`; `release_seq` is a commit
  timestamp). An intended downgrade is explicit: `sudo
  UDBMCP_ALLOW_DOWNGRADE=1 dpkg -i <older .deb>`, or `--allow-downgrade` for
  `install_offline.sh` / `upgrade_offline.sh`. On macOS it is a one-shot flag
  file, on Windows `UDBMCP_ALLOW_DOWNGRADE=1` for one `msiexec` run of one of
  this release's MSIs after uninstalling the newer one, since Windows
  Installer refuses any older MSI over a newer install (see
  `docs/offline-deployment.md`). Run on the install target without
  `--installed-manifest`, the trusted verifier compares with this machine's
  installed release on its own, so a `.pkg` or `.msi` built before this
  release is refused as a downgrade once the trust dir holds this release's
  verifier. Container hosts: `load_images_offline.sh` keeps a root-owned
  release record (`/var/lib/universal-db-mcp/release.json`) and refuses an
  older bundle (`docs/offline-deployment.md`, "Container mode"). An install
  or upgrade that cannot publish `/opt/universal-db-mcp/manifest.json` (the
  record those checks compare with) now fails instead of finishing without
  it (under `sudo` it was skipped silently). On macOS the `.pkg` declares an
  arm64 host (an Intel Mac is refused) and its scripts start over natively
  when the Installer runs them under Rosetta; the verifier judges the
  hardware architecture, and refuses an interpreter with no arm64 code (an
  x86_64-only CPython) for the arm64 profile: use a universal2 or arm64
  CPython 3.12.
- **Config that no longer loads.** These stop `serve` at start; run `doctor`
  before restarting:
  - a connection-level `read_only: false` (v1 is read-only);
  - a connection id that starts with `-` or holds non-ASCII characters (ids
    are 1-64 of `[A-Za-z0-9_-]`), or two ids that differ only in case;
  - a mapping key given twice (YAML used to keep the last one silently);
  - an inline `options.wallet_password` (use `wallet_password_file` or
    `wallet_password_env`);
  - `*_env` names that are not ASCII identifiers, and a
    `session.application_name` outside `[A-Za-z0-9_.:@-]{1,64}`;
  - an audit log or metadata cache that is one of the Oracle client's files
    (`tnsnames.ora`, `sqlnet.ora`, wallet files, ...) in `tns_admin`,
    `wallet_location` or, with `options.lib_dir`, `lib_dir/../network/admin`,
    or that sits directly in `lib_dir` or `lib_dir/network/admin`;
  - no `application.audit_path` in a config other than the service's, when
    the home directory is `/`, empty or relative (no per-user default can be
    derived; set `audit_path`).

  With `transport: http`, `serve` also stops on a bearer token shorter than
  32 characters (the package generates 64). `doctor` checks only that the
  token file exists with safe permissions, so check its length by hand
  (`/etc/universal-db-mcp/http-token` from the package, or the file
  `application.http_bearer_token_file` names); this must print 32 or more:
  `sudo cat /etc/universal-db-mcp/http-token | tr -d '[:space:]' | wc -c`.
- **Relative paths follow the config file.** A relative `audit_path`,
  `metadata_cache_path`, `http_bearer_token_file`, `username_file`,
  `password_file`, `tls` file, `options.wallet_password_file` or
  `options.passfile` now resolves against the config file's directory, not
  the directory the server was started in (`/` under the systemd unit). Write
  them absolute, or relative to `/etc/universal-db-mcp`, and check with
  `doctor`. A SQLite `database` and the Oracle `wallet_location`,
  `tns_admin` and `lib_dir` are used as written, so a relative one follows
  the working directory: write those absolute.
- **Audit is never off.** When `application.audit_path` is unset, the service
  config audits to `/var/log/universal-db-mcp/audit.jsonl` and a per-user
  config to `~/.universal-db-mcp/audit.jsonl`. The audit path must be on a
  local filesystem; a record waits at most 10 s for the audit lock, then the
  call is refused (fail-closed, the default), and after one such refusal the
  process's later records wait at most 1 s until the lock is free again
  (`... for more than 1 s, after an earlier record gave up waiting 10 s`).
- **Audit volume is bounded.** A call refused before anything reached a
  database writes one record (a refused `db_query` no longer writes a
  `db_query:statement` record), and repeats of one refusal kind past the
  first 10 in a 10 s window (64 full records per window in all) are counted
  into one `tool_call_summary` record per kind. With `audit_sql_text: true`,
  only a statement that was sent keeps its `sql_text`; one never sent
  (every `db_validate_query` included) keeps `sql_len` and `sql_sha256`.
  The text written per 10 s window past each record's first and last
  1024 bytes is capped at 1 MiB; past it a record carries `sql_text_tail`
  and `sql_text_omitted`. Log parsers that expect one record per call or a
  whole `sql_text` in every record need to handle both (`docs/security.md`,
  Audit).
- **Metadata cache.** The cache must be private to the service account (0600,
  no symlink, in a directory others cannot write), or caching is disabled
  with a stderr line (nothing fails). Existing entries are rebuilt once
  (the key now includes what the connection reaches: engine, host, port,
  database, login and options), and paging cursors issued before the
  upgrade are rejected as stale.

**What agents notice**

- **Schema-qualified tables under an allowlist.** On every connection with
  `allowed_schemas` (all engines but SQLite), statements must name each
  table's schema (its database on MySQL and ClickHouse): `SELECT * FROM
  ocean.buoys`, not `FROM buoys`. A bare name is refused with
  `AUTHORIZATION_DENIED: unqualified table ... write ocean.buoys`. Saved
  agent prompts and queries that use bare names need the schema added. Some
  refusals change category from `POLICY_VIOLATION` to `AUTHORIZATION_DENIED`.
  The metadata, sample and profile tools still accept a bare `object_name`.
- **Schema names that differ only in case.** Where the catalog holds one
  allowed name in several spellings (`TRAVEL` and `"travel"` on Oracle,
  `ocean` and `"Ocean"` on PostgreSQL), an `allowed_schemas` entry admits the
  spelling the engine folds it to; an entry mixing upper- and lower-case
  letters admits its exact spelling first. The other spellings are left out
  of `db_list_schemas`, `db_list_tables`, and `db_list_views`,
  `db_list_synonyms` and `db_list_routines` called without a schema, and
  refused (`... differ only in case ...`); a foreign key into one names its
  target `<not permitted>`. To admit a quoted
  namesake as well, list both spellings (`['TRAVEL', 'travel']`).
- **Masking follows the value, not the column name.** UNIONs, CTE column
  lists, aliases and whole-row references no longer unmask a sensitive
  column; a statement the analysis cannot trace has every unproven column
  masked, with a warning. Mask patterns also match a name's
  Unicode-normalised form (`ＭＲＮ`, `'MRN '`). A `WHERE`/`ORDER BY`/`GROUP BY`
  on a masked column is still not masked (a documented limitation): use
  column grants or views for secrets.
- **Bound parameters.** On MySQL, ClickHouse and PostgreSQL a placeholder
  inside a string literal or comment is text, not a parameter. In a string
  literal `%%` is still one `%` (`'50%%'`); in a quoted name or comment
  every `%` arrives as written. A placeholder count or name that does not
  match the values, a named value no placeholder uses, `%%` outside a
  string literal (write modulo as `%` or `MOD()`), and a placeholder glued
  to a name, digit or quote (`%ssn`) are `VALIDATION_ERROR`; queries that
  relied on a `%s` inside quotes being filled need the placeholder outside
  them. `db_federated_query` gives each statement only the named values it
  uses, and refuses a name no statement uses.
- **Errors.** A statement the engine rejects is now `QUERY_ERROR` (was often
  `CONNECTION_ERROR`); a statement stopped by the engine's time limit is
  `TIMEOUT`. Driver error text has values, quoted fragments and numbers
  replaced by `<redacted>`.
- **Response size.** Every listing, catalog and review page stops at
  `security.max_response_bytes` and resumes with its cursor; a single-object
  result far over the ceiling is `LIMIT_EXCEEDED`.
- **Guard refusals added.** MariaDB `/*M! ... */` comments and `SET
  STATEMENT`; on SQL Server an unquoted reserved keyword as an alias (quote it
  as `[x]`), money or binary literals written against more text, and any
  table, column or alias outside printable ASCII or a quoted name ending in a
  blank (an object whose catalog name is not ASCII cannot be named in a
  statement; `SELECT *` still returns such a column); a Db2 delimited name
  ending in blanks; an unquoted Oracle name with `ı` or `ſ`; a ClickHouse
  quoted identifier containing a backslash; line comments ended by a bare CR;
  a name after `IN` without parentheses (`x IN t`; a placeholder or constant
  there, such as ClickHouse `IN {ids:Array(UInt64)}`, is accepted);
  ClickHouse `{name:Identifier}` parameters; an `IN` with nothing after it
  or right after `IN`; ClickHouse `IN` over one name however wrapped (`x IN
  ((t AS z))`), the functions that read a table or dictionary (`joinGet`,
  `dict*`, `hasColumnInTable`, the `in` family), and an `a.b` ClickHouse
  would read as the table `a.b` (checked as that table; a tuple element is
  `a.1`); `@@` server variables on every engine and MySQL user variables;
  PostgreSQL and Db2 `U&"..."` identifiers and the prefix `@` operator
  (`abs(x)`); every Oracle database link (`@` outside literals, quoted names
  and hints); SQL Server lock hints in the legacy form without `WITH`
  (`FROM t b (TABLOCKX)`; `NOLOCK`, `READUNCOMMITTED`, `READPAST`, `NOWAIT`
  stay allowed); MySQL `MAX_EXECUTION_TIME`, `SET_VAR` and `RESOURCE_GROUP`
  optimizer hints, wherever the word appears in a `/*+ ... */` body (other
  hint comments, Oracle's `INDEX` or `LEADING`
  included, are accepted and not checked as functions); an empty quoted name
  (`"".ALL_USERS`, `[].syslogins`); a `WITH` after `UNION`,
  `INTERSECT` or `EXCEPT` with more branches after its query (write
  `(WITH ... SELECT ...)`); PostgreSQL `EXPLAIN (FORMAT JSON)` (use YAML or
  XML). On SQL Server and MySQL, a CTE referenced in a different letter case
  than declared is treated as a table. On ClickHouse a name counts as a CTE
  only where ClickHouse binds it to one (names are case-sensitive, and a CTE
  names itself only after the first branch of a `WITH RECURSIVE ... UNION
  ALL` body); anywhere else it gets the full table checks, and CTEs naming
  each other in a cycle, `WITH RECURSIVE` ahead of a set operation, a `WITH`
  on a parenthesised first operand, and a CTE body reading a name declared as
  a CTE elsewhere are refused with the rewrite to use.
- **Other sessions' SQL, column statistics, stored credentials.** Views
  that show other sessions' statements or the values they carry
  (`pg_stat_activity`, `pg_stat_statements`, MySQL `PROCESSLIST` and the
  `performance_schema` statement tables, Oracle `V$SQL`, `V$SESSION`, the
  audit trails, outlines and SQL tuning sets, SQL Server
  `sys.dm_exec_requests`, ClickHouse `system.query_log` and
  `system.processes`, Db2 `SYSIBMADM.MON_CURRENT_SQL`, ...), views of
  column statistics (MySQL `information_schema.COLUMN_STATISTICS`,
  `pg_stats`, Oracle `*_HISTOGRAMS`, Db2 `SYSCAT.COLDIST`, ...) and views of
  stored credentials (PostgreSQL's `information_schema.user_mapping_options`
  and `foreign_server_options` under the default `[information_schema]`,
  `mysql.user`, `sys.sql_logins`, Oracle's `*_DB_LINKS`, ...) are refused on
  every connection, whatever `allowed_system_schemas` says. Some were
  `AUTHORIZATION_DENIED` as a closed system schema and are now
  `POLICY_VIOLATION`. They are left out of `db_list_tables`, the catalog
  tools, and `db_list_views` and `db_list_synonyms` on PostgreSQL, Oracle
  and Db2 (a synonym or alias whose chain reaches one included). Oracle's
  `*_TAB_COLUMNS` and `COLS` and Db2's `SYSCAT.COLUMNS` may be read only
  without their `LOW_VALUE`/`HIGH_VALUE` or `HIGH2KEY`/`LOW2KEY` columns,
  without `*` and without a column list after the alias; a CTE named like
  one of them (`WITH cols AS (...) SELECT * FROM cols` on Oracle) is refused
  the same way. The `information_schema` views that carry other objects'
  definitions (`VIEWS`, `ROUTINES`, `COLUMNS`, `TRIGGERS`,
  `CHECK_CONSTRAINTS`, ...) are refused and unlisted too: describe objects
  with `db_list_columns` and `db_list_views`. MySQL's
  `information_schema.STATISTICS` stays readable without its `EXPRESSION`
  column (a functional index's SQL with its literals). The full lists are in
  `docs/security.md`.
- **No EXPLAIN ANALYZE, whatever the policy.** With `allow_explain_analyze:
  true`, `EXPLAIN ANALYZE ...` used to pass the guard; it is now
  `VALIDATION_ERROR: EXPLAIN option 'ANALYZE' is not supported by db_explain:
  plans are captured without executing the statement; use EXPLAIN
  <statement>`. `db_explain` with `analyze=true` is refused as well:
  `POLICY_VIOLATION: EXPLAIN ANALYZE is disabled by policy` by default, and
  `VALIDATION_ERROR: analyze=true is not supported by db_explain ...` with the
  setting on. `db_explain` never runs the statement. On MySQL, a TREE or JSON
  plan of a statement naming a masked column (or `*`, or a NATURAL join) is
  withheld, because MySQL prints the values it read while planning into
  those formats; `EXPLAIN FORMAT=TRADITIONAL` is returned for any statement.
- **System schemas and dummy tables.** The default
  `security.allowed_system_schemas: [information_schema]` now lists and opens
  `information_schema` on PostgreSQL, MySQL, SQL Server and ClickHouse (it
  appears after the database's own objects in `db_list_tables`). Under
  `allowed_schemas` its names-only views (`TABLES`, `SCHEMATA`, ...) still
  name the objects of every schema the login can see, which the metadata
  tools refuse (its definition views are refused, above); set
  `allowed_system_schemas: []` where object names outside the allowlist
  must stay hidden. Oracle
  `DUAL` (bare or `SYS.DUAL`) and Db2 `SYSIBM.SYSDUMMY1`..`4` are readable in
  statements on every connection without opening `SYS` or `SYSIBM`, which
  stay closed otherwise; a bare Db2 `SYSDUMMY1` under an allowlist is refused
  with the hint to write `SYSIBM.SYSDUMMY1`. `db_get_table`,
  `db_list_columns` and `db_sample_table` on them follow the listing, which
  holds them only where `SYS` or `SYSIBM` is opened. More Oracle owners count
  as system schemas (`WKSYS`, `DMSYS`, `ODM`, `APEX_nnnnnn`, `FLOWS_nnnnnn`,
  the 9i `AURORA$JIS$UTILITY$`, `AURORA$ORB$UNAUTHENTICATED`,
  `OSE$HTTP$ADMIN` and `TRACESVR`, ...): an application schema with one of
  those names must be listed in `allowed_schemas`.
- **Listings.** On Oracle and Db2, too, `db_list_tables` returns the
  database's own objects first and those of opened dictionary owners or
  system schemas after them. MySQL never lists `information_schema`
  `PROCESSLIST`, `INNODB_TRX`, `INNODB_LOCKS`, `QUERY_CACHE_INFO`,
  `INNODB_FT_INDEX_CACHE` or `INNODB_FT_INDEX_TABLE`, nor the `sys` lock-wait
  views, nor `performance_schema` `processlist`, `threads` and
  `events_statements_*` (listed before where `performance_schema` was
  opened), whatever is opened. PostgreSQL's `db_list_views` no longer names
  `pg_stat_activity` or `pg_stats*`, Oracle's `db_list_synonyms` no longer
  names the PUBLIC `V$SQL` or `ALL_TAB_HISTOGRAMS`, and Db2's
  `db_list_views` no longer names `MON_CURRENT_SQL` or `COLDIST`.
- **Names as the catalog spells them (default-deny, the default).** On
  PostgreSQL, Oracle, Db2 and ClickHouse a table name must be spelled as the
  catalog spells it (`POLICY_VIOLATION: table ... is not spelled as the
  catalog lists it ... write <spelling>`; on SQL Server only under a
  case-sensitive collation), and on PostgreSQL, Oracle, SQL Server and Db2 a
  bare name is accepted only when the listed table is in the first schema
  the session looks bare names up in (`... a bare name is looked up in
  <schema> first ...; write <schema>.<name>`). Saved queries that relied on
  a different case, or on a bare name the engine resolved elsewhere, need
  the spelling the message gives.
- **Without default-deny** (`default_deny_objects: false`), on Oracle, SQL
  Server and Db2 every name is also looked up as a synonym (Db2: an alias)
  and each object its chain names is checked as if written (`'<name>' is a
  synonym that reads '<target>', refused as that is: ...`); a bare Oracle
  `ALL_USERS` is then refused unless `SYS` is opened. SQL Server's
  compatibility views (`syslogins`, `sysobjects`, ...) under `dbo` or bare
  are authorized as `sys.<name>` in every mode.
- **SQLite.** `sqlite_*` catalog tables, SQLite's virtual tables and the
  internal tables of FTS and R*Tree indexes are never readable; statements read only the tables and views `db_list_tables` lists.
  A value longer than the handle's length limit (16 MiB by default) is
  `QUERY_ERROR: string or blob too big: the statement builds or reads a value
  longer than this server lets SQLite handle ...`, where it was a bare
  `DataError`. A cell cut to `max_cell_bytes` is reported by its warning
  only; `truncated` still means the row or byte limit cut the result, as
  before.
- **PostgreSQL arrays** arrive as PostgreSQL's own JSON text, numbers
  unquoted and without spaces: `numeric[]` `{1.10,2}` is `[1.10,2]` (was
  `["1.10", "2"]`), `int[]` is `[1,2]` (was `[1, 2]`).
- **`db_list_databases`** on MySQL and ClickHouse lists only the databases in
  the connection's `allowed_schemas`, like `db_list_schemas`.
- **New fields.** `db_list_connections` and `db_test_connection` report
  `data.audit` (path, fail_closed, dropped_records), and each connection's
  `server_read_only_session`; `db_test_connection`'s `server_reports` add
  `sql_mode` and `character_set_client` (MySQL) and
  `standard_conforming_strings` and `client_encoding` (PostgreSQL).
  `db_get_query_history` now describes itself as the redacted operational
  history of this server process, every client's calls under HTTP, not a
  substitute for the audit log.

**Engines**

- **How the server reads a statement.** Every connection now holds the
  settings that decide how its server reads statement text at the values
  the SQL guard parses under, and is refused when it cannot:
  `CONNECTION_ERROR: could not set <what> for the session on connection
  '<id>' (...); the server would read statements differently from the SQL
  guard that checked them, so the connection is refused`. MySQL/MariaDB:
  the session `sql_mode` is the site's own without `ANSI`, `ANSI_QUOTES`,
  `NO_BACKSLASH_ESCAPES`, `PIPES_AS_CONCAT`, `HIGH_NOT_PRECEDENCE` and the
  combination modes, then `SET NAMES utf8mb4`; a site whose global
  `sql_mode` sets them gets the default string, quote and `||` semantics on
  this server's sessions. PostgreSQL: `standard_conforming_strings = on`,
  `backslash_quote = safe_encoding`, `client_encoding = 'UTF8'`. SQL Server:
  `QUOTED_IDENTIFIER ON` (a DSN with `QuotedId=No` now reads `"x"` as an
  identifier). Db2: `SQL_COMPAT = 'DB2'` (before 11.1 listed under
  `skipped`). ClickHouse: `dialect`, `implicit_select`,
  `prefer_column_name_to_alias`, `enable_global_with_statement` and
  `analyzer_compatibility_join_using_top_level_identifier` are sent at their
  defaults where the account's profile changes them; a `readonly=1` profile
  that changes one, `compatibility` 21.x or older included, is refused
  (`docs/session-safety.md`).
- **Db2 over TLS.** The client now validates the server certificate's host
  name (`SSLClientHostnameValidation=Basic`): a certificate issued as
  `CN=<something else>` without a subjectAltName for the configured host
  fails with `SQL20576N`. Reissue it (`docs/db2-tls-setup.md`). Each TLS
  connect is preceded by a short TCP, TLS and DRDA probe (no credentials),
  which the server may log. A peer that answers the probe and then stalls
  the real connect still hangs it; the stuck-connect budget below contains
  it.
- **Oracle.** With `tls.enabled` and a `tns_alias`, every address of the
  alias must be TCPS; Thick mode with TLS needs an auto-login `cwallet.sso`
  (`docs/oracle-connect-modes.md`). A bare `DUAL` is refused
  (`AUTHORIZATION_DENIED`, write `SYS.DUAL`) where the login schema owns an
  object named `DUAL` or a logon trigger sets `CURRENT_SCHEMA` to another
  schema; elsewhere it costs one extra catalog round trip. A Thin connect to a
  listener that accepts and never answers is still not bounded by
  python-oracledb; such connects are parked in the stuck-connect budget.
- **SQL Server.** Every query is described first and rolled back explicitly;
  the login should be `db_datareader` plus `SHOWPLAN`, never `db_owner`.
- **ClickHouse.** Results stream under byte budgets and stop with `KILL
  QUERY`. The server's own memory is bounded only by the account's profile:
  set `max_memory_usage` for the MCP account. `db_explain` plans under a
  1000-row read ceiling, because ClickHouse evaluates subqueries while it
  plans; a plan that would read more is refused as `CAPABILITY_UNSUPPORTED`
  (use `db_query`). A `readonly=1` profile refuses that ceiling, so there
  every plan carries a warning that producing it may have read table data
  (`docs/driver-matrix.md` has the profile trade-off).
- **Concurrency.** One database server may hold at most
  `max_concurrent_queries - 1` calls (three at the default of 4); raise the
  limit by one per extra parallel call you need on one server. An Oracle
  `tns_alias` connection is keyed on the alias and its `tns_admin`, not the
  placeholder host, and a MySQL `unix_socket` connection on the socket. Up to
  10 connects to servers that never answer are parked; beyond that,
  connections to a database server are refused until one returns (SQLite
  connections keep running). A client cancel during a driver call is now
  handled as a deadline is: the engine's cancel hook fires (ClickHouse
  `KILL QUERY`, MySQL `KILL CONNECTION`, which ends the session rather
  than one statement, PostgreSQL `cancel_safe`, Oracle `cancel()`, SQL
  Server `Cursor.cancel()`, SQLite `interrupt()`; Db2 has none), which the
  database's logs may show, and requests already queued on that connection
  are refused with `connection is in an uncertain state after a previous
  cancelled query`. Earlier releases already discarded the connection after
  a client cancel, but only for later calls: the statement ran on, and the
  queued requests used the connection.

**Tools around the server**

- **Agent registrations** now start the server with `python -I`. Re-run
  `udbmcp configure-agents` as each user after the upgrade to rewrite old
  registrations; `chmod 600` old `~/.claude.json` backups. A harness config it
  may not replace (read-only, another owner, hard-linked, an access control
  list other than the one its directory gives new files, a group the user is
  not in that its mode gives access of its own) is refused, not overwritten;
  the refusal shows only this tool's own entry, never the other servers' in
  the file. A project `.mcp.json` is no longer given this machine's paths
  (only this tool's own pre-`-I` entry there is upgraded); the user-scope
  registration covers every project.
  On a `.deb` host, give the system config to the service account before
  anyone runs `configure-agents`: the conffile ships `root:root` 0644, and
  `configure-agents` registers a system config its user can read, whose
  audit log that user cannot write:

  ```bash
  sudo chown root:udbmcp /etc/universal-db-mcp/config.yaml && sudo chmod 640 /etc/universal-db-mcp/config.yaml
  ```

- **`add-connection`** updates an existing connection in place and keeps its
  `allowed_schemas`, `session` and `options`; `--read-write` is gone; flag
  and `--json` runs on a commented config need `--accept-comment-loss`. Its
  `<config>.bak.<stamp>` backup takes only the config's permission bits
  (never setuid, setgid or sticky; as root, no group or other write).
- **`site-check --out`** never follows a symlink; write the report into a
  `mktemp -d` directory, as above.
- **HTTP listener.** A request head must arrive within 10 s
  (`UDBMCP_HTTP_HEADER_TIMEOUT`), a head over 100 lines or 16 KiB is answered
  431, and a request without the token gets 401 before its body is read. The
  unit raises the descriptor limit to 65536.

Carried over from earlier releases, still worth knowing:

- **Every read-only connection gets a server session profile**: Db2 runs at
  `UR`, SQL Server at `READ UNCOMMITTED`, PostgreSQL and MySQL are put into
  read-only mode server-side, lock waits are capped at 5 s and statements at
  `security.hard_query_timeout_seconds`. Four of these fail closed; the
  per-connection `session:` block is the opt-out (`isolation: cs`,
  `enforce_read_only: false`). See `docs/offline-upgrade-rollback.md`.
- **Db2 statements may end in `WITH UR` or `WITH CS`; `WITH RS`/`WITH RR`
  are refused** because they hold locks.
- **`db_explain` works on every engine**, and refuses a non-empty
  `parameters` argument. It never runs the statement, but on Db2 `EXPLAIN
  PLAN` writes plan rows into DBA-provisioned explain tables and the
  connector reads them back and deletes them, so that login needs INSERT,
  SELECT and DELETE there (and only there); without the tables `site-check`
  reports `explain=SKIPPED`. Oracle writes its plan into the session-private
  `PLAN_TABLE`, which needs no grant. Neither touches your data.
- **Upgrades are reversible**: the trusted installer builds the new
  environment beside the running one and keeps
  `/opt/universal-db-mcp/venv.previous` with an integrity manifest.

## Rollback (to the previous stick's release)

An upgrade keeps the previous venv at `/opt/universal-db-mcp/venv.previous`
with an integrity manifest, so the quick rollback is the bundle's own script
(it verifies the manifest before it executes anything, then swaps the venvs
back):

```bash
# 1. put back the config the previous release understood (older releases reject keys they do not know)
sudo systemctl stop universal-db-mcp
sudo cp "$(sudo cat /root/udbmcp-last-backup 2>/dev/null)/etc/config.yaml" /etc/universal-db-mcp/config.yaml 2>/dev/null || true
# 2. swap the venvs back (verified against the manifest first)
sudo bash /usr/share/universal-db-mcp/bundle/operations/rollback_offline.sh /opt/universal-db-mcp
sudo systemctl restart universal-db-mcp
grep -c server_read_only_session /opt/universal-db-mcp/venv/lib/python3.12/site-packages/universal_db_mcp/server.py   # 0 on the previous release
```

That restores the venv installed BEFORE this upgrade (depth one). The
installed-release record (`/opt/universal-db-mcp/manifest.json`) still names
the newer release afterwards, so installing the older bundle again is a
downgrade and needs the explicit override below; the next upgrade to a newer
release needs nothing special. After an intended downgrade the record names
the older release; a rollback from there raises it to the release now
running, so bundles between the two are not accepted silently.
`rollback_offline.sh --restore-config` keeps the live `keys/` and
`http-token` (a rotated key or token is never put back).

To go back to an older package instead, or when the site was installed
before `venv.previous` existed, install the previous stick's package. Four
rules make that a real rollback instead of a masked or refused one:

1. **Keep the current trusted tools.** Do NOT run the older stick's
   `trust-bootstrap-linux/bootstrap.sh`: older copies lack
   `--force-reinstall` or the release-order check, so the "rollback" could
   keep the new code in the venv while dpkg and the manifest report the old
   release.
2. **Check the older stick first**: its `SHA256SUMS.sig` must verify with the
   installed key. Since its bootstrap may not run, the block below copies the
   signed list and the package into a root-only directory, checks the
   signature of that copy and the package against it, and installs the copy
   (`dpkg -i` reads the package again and runs its `preinst` as root). A
   stick made before this release carries no `SHA256SUMS.sig` and cannot be
   checked this way: use the `venv.previous` rollback above, or have the
   release administrator sign that stick folder
   (`release_usb.sh --sign-stick <dir>`, `docs/offline-build.md`).
3. **Restore the pre-upgrade config.** Older releases reject configuration
   keys they do not know: restore the config you backed up before upgrading,
   for the system and the per-user file.
4. **Delete the venv, then install with the downgrade override**, and verify.
   Installing the older package prints `dpkg: warning: downgrading`, which is
   expected here; without `UDBMCP_ALLOW_DOWNGRADE=1` the trusted installer
   refuses it as a rollback.

```bash
OLDSTICK=/mnt/usb/usb-ubuntu-<old sha7>                    # the OLD stick, mounted as in step 0
W=$(sudo mktemp -d /var/tmp/udbmcp-rollback.XXXXXX)       # root-only (0700)
sudo cp "$OLDSTICK/SHA256SUMS" "$OLDSTICK/SHA256SUMS.sig" "$W/"
sudo /usr/bin/openssl pkeyutl -verify -pubin -inkey /etc/universal-db-mcp/keys/release.pub.pem -rawin \
  -in "$W/SHA256SUMS" -sigfile "$W/SHA256SUMS.sig"         # must print: Signature Verified Successfully
OLDNAME=$(sudo awk '$2 ~ /^universal-db-mcp_[^\/]*_amd64\.deb$/ { print $2 }' "$W/SHA256SUMS")
sudo cp "$OLDSTICK/$OLDNAME" "$W/"
sudo awk -v w="$W" -v n="$OLDNAME" '$2 == n { print $1 "  " w "/" n }' "$W/SHA256SUMS" | sudo sha256sum -c --strict -   # must print: ...: OK
OLD="$W/$OLDNAME"; OLDSHA=$(printf '%s' "$OLDNAME" | sed -E 's/^.*\.g([0-9a-f]+)_amd64\.deb$/\1/')
sudo systemctl stop universal-db-mcp
sudo rm -rf /opt/universal-db-mcp/venv
sudo UDBMCP_ALLOW_DOWNGRADE=1 dpkg -i "$OLD"
until grep -qxE 'success|failed' /var/log/universal-db-mcp-install.status 2>/dev/null; do sleep 5; done
cat /var/log/universal-db-mcp-install.status
sudo python3 -I -c 'import json; print(json.load(open("/opt/universal-db-mcp/manifest.json"))["source_rev"])'; echo "expected to start with: $OLDSHA"
sudo systemctl restart universal-db-mcp
```

If the older package is refused (its `preinst` prints `FAIL`), dpkg undoes
the install, and with the venv deleted this release's `postinst` writes
`failed` to the status file and exits 1, which leaves the package
`unpacked`. Run `sudo dpkg --configure universal-db-mcp` to install this
release's payload again, resolve the refusal, then retry.

Keep the previous stick until the new release has run for a while.
