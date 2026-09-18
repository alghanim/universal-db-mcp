# Site runbook: upgrade in place, or erase and reinstall (Ubuntu, air-gapped)

For any release folder `usb-ubuntu-<sha7>/` (this copy ships on the stick as
`UPGRADE-README.md`). Every command runs on the air-gapped Ubuntu host,
offline, as an administrator who can `sudo`. Nothing here touches any
database server. The commands are written so that they can be pasted a
block at a time; each block is self-contained after step 0.

What is on the stick:

| Path | Purpose |
|---|---|
| `SHA256SUMS` | checksums of every other file on the stick |
| `universal-db-mcp_0.1.0+<build stamp>.g<sha7>_amd64.deb` | the package (its payload is the signed offline bundle); the version rises with every build |
| `trust-bootstrap-linux/` | the trusted verifier, installer and release public key; `bootstrap.sh` installs them |
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

## Step 0: mount and verify the stick, record what is installed

Ubuntu Server does not auto-mount removable media. Mount the stick read-only
with modes every user can traverse (a plain `sudo mount` under a hardened
umask gives a root-only mount point):

```bash
lsblk -o NAME,SIZE,FSTYPE,LABEL,MOUNTPOINT          # find the stick, for example sdb1
sudo mkdir -p /mnt/usb
sudo mount -o ro,uid=$(id -u),gid=$(id -g),umask=022 /dev/sdb1 /mnt/usb   # adjust sdb1
ls /mnt/usb
```

Then, in the shell you will use for the rest of the runbook:

```bash
STICK=$(ls -d /mnt/usb/usb-ubuntu-* | head -1); echo "release folder: $STICK"
DEB=$(ls "$STICK"/universal-db-mcp_*_amd64.deb); echo "package: $DEB"
SHA=$(basename "$DEB" | sed -E 's/^.*\.g([0-9a-f]+)_amd64\.deb$/\1/'); echo "release commit (short): $SHA"
(cd "$STICK" && sha256sum -c SHA256SUMS)             # every line must end in ": OK"

# what is installed right now (keep this output; it is your rollback reference)
dpkg -s universal-db-mcp 2>/dev/null | grep -E '^(Status|Version)' || echo "package not installed"
sudo python3 -c 'import json; print("installed source_rev:", json.load(open("/opt/universal-db-mcp/manifest.json")).get("source_rev"))' 2>/dev/null || echo "no installed manifest"
cat /var/log/universal-db-mcp-install.status 2>/dev/null || echo "no install status file"
systemctl is-active universal-db-mcp || true
```

Stop if any checksum line is not `OK`: the stick is damaged or altered, use
another copy. If `dpkg -s` prints `Status: install reinstreq half-installed`,
an earlier `dpkg -i` was interrupted hard; see "dpkg says half-installed"
under Path B before doing anything else.

## Step 1 (always): refresh the trusted tools from THIS stick

The package never installs its own verifier or installer; it runs the copies
under `/usr/local/lib/udbmcp-trust/`, and it only checks that they exist,
not which release they came from. The installer copy is what makes an
upgrade replace the code in the venv (older copies kept the previous code
while dpkg reported success), so run this on every upgrade, and never run an
OLDER stick's bootstrap afterwards:

```bash
sudo bash "$STICK/trust-bootstrap-linux/bootstrap.sh"
grep -c -- --force-reinstall /usr/local/lib/udbmcp-trust/install_offline.sh   # must print 2
```

It installs `verify_bundle.py`, `profiles.py`, `install_offline.sh`,
`lib/os_packages.sh` to `/usr/local/lib/udbmcp-trust/`, and prints the
SHA-256 fingerprint of the release public key on the stick. On a machine
that already has a key installed it compares the two: the same key is left
in place; a DIFFERENT key makes it stop, because a stick that carried its
own key, verifier and package would otherwise verify itself. Only when
your release administrator has confirmed the new fingerprint out-of-band
(by phone, in person, on paper) re-run it with `--rotate-key`. Safe to
repeat.

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

- No downgrade warning is expected any more: versions are
  `0.1.0+<build stamp>.g<commit>` and rise with every build, and a package
  of this scheme always counts as newer than an older `0.1.0~<hash>` install
  (dpkg sorts `~` first). If you ever see `dpkg: warning: downgrading`, the
  stick is older than what is installed: stop and check the build stamps.
- If dpkg asks what to do with `/etc/universal-db-mcp/config.yaml`
  ("configuration file … modified"), answer `N` (keep your current
  version). Your connections and security block are in that file; the
  shipped default is only a template.
- `dpkg -i` returns BEFORE the install is finished. The payload is verified
  synchronously; then a root worker waits for dpkg to release its locks and
  runs the trusted installer (venv rebuilt with `--force-reinstall`, ODBC
  driver packages, smoke check). The service refuses to start until the
  worker records `success`.

Wait for the worker (usually one to three minutes; the loop ends on
`success` or `failed`):

```bash
until grep -qxE 'success|failed' /var/log/universal-db-mcp-install.status 2>/dev/null; do sleep 5; done
cat /var/log/universal-db-mcp-install.status
sudo tail -n 40 /var/log/universal-db-mcp-install.log      # the log is root-only; on 'failed' the reason is here
```

On `success`:

```bash
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

dpkg says half-installed: if `dpkg -P` (or the earlier `dpkg -s`) reports
`package is in a very bad inconsistent state` / `reinstreq`, an earlier
`dpkg -i` was killed mid-way. Either `sudo dpkg -i "$DEB"` once (repairs the
record, then purge as above) or `sudo dpkg -P --force-remove-reinstreq
universal-db-mcp`.

**Install and wait:**

```bash
sudo bash "$STICK/trust-bootstrap-linux/bootstrap.sh"
sudo dpkg -i "$DEB"
until grep -qxE 'success|failed' /var/log/universal-db-mcp-install.status 2>/dev/null; do sleep 5; done
cat /var/log/universal-db-mcp-install.status              # must say success; on failed: sudo tail -n 40 /var/log/universal-db-mcp-install.log
```

**Put your configuration back** (the fresh install seeded only the
template) and start:

```bash
B=$(sudo cat /root/udbmcp-last-backup)
sudo cp "$B/etc/config.yaml" /etc/universal-db-mcp/config.yaml
sudo chown root:udbmcp /etc/universal-db-mcp/config.yaml && sudo chmod 640 /etc/universal-db-mcp/config.yaml
sudo cp -a "$B/etc/http-token" /etc/universal-db-mcp/ 2>/dev/null || true
if [ -d "$B/universal-db-mcp.service.d" ]; then sudo cp -a "$B/universal-db-mcp.service.d" /etc/systemd/system/ && sudo systemctl daemon-reload; fi
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
because the service account must be able to traverse `/opt/oracle`:

```bash
( set -e; cd "$STICK/oracle-instantclient"
  sudo dpkg -i libaio1t64_*.deb
  command -v unzip >/dev/null || sudo dpkg -i unzip_*.deb
  ls /usr/lib/x86_64-linux-gnu/libaio.so.1 >/dev/null 2>&1 || \
    sudo ln -s /usr/lib/x86_64-linux-gnu/libaio.so.1t64 /usr/lib/x86_64-linux-gnu/libaio.so.1
  sudo install -d -m 755 /opt/oracle
  sudo unzip -oq instantclient-basiclite-linux.x64-19.28.zip -d /opt/oracle
  sudo chmod -R a+rX /opt/oracle
  echo /opt/oracle/instantclient_19_28 | sudo tee /etc/ld.so.conf.d/oracle-instantclient.conf >/dev/null
  sudo ldconfig
  ldconfig -p | grep libclntsh                                   # must print a line
  sudo -u udbmcp ls /opt/oracle/instantclient_19_28/libclntsh.so.19.1   # the service account can reach it
)
```

Then set `options: {thick_mode: true}` on that connection (no `lib_dir` on
Linux) and restart the service. Every Oracle connection in one config must
use the same mode: thick mode is process-wide.

## Verify (both paths)

```bash
# the installed code is this stick's release
sudo python3 -c 'import json; print(json.load(open("/opt/universal-db-mcp/manifest.json"))["source_rev"])'; echo "expected to start with: $SHA"
grep -c db_review_schema /opt/universal-db-mcp/venv/lib/python3.12/site-packages/universal_db_mcp/server.py
#   -> greater than 0: the new code is in the installed venv, not only in the package

# the service
systemctl status universal-db-mcp --no-pager | head -5
sudo -u udbmcp /opt/universal-db-mcp/venv/bin/python -m universal_db_mcp doctor --config /etc/universal-db-mcp/config.yaml

# the per-user config that Claude Code (stdio) uses, if you have one
/opt/universal-db-mcp/venv/bin/python -m universal_db_mcp doctor --config ~/.universal-db-mcp/config.yaml
```

Then run the site check: one read-only pass over every connection through
the same tools an agent uses (connection, listing, catalog, profile, plan,
review, search), which writes a JSON report made of counts, codes, names
and timings only, never a row value, so it can leave the site:

```bash
sudo -u udbmcp /opt/universal-db-mcp/venv/bin/python -m universal_db_mcp site-check \
  --config /etc/universal-db-mcp/config.yaml --out /tmp/udbmcp-site-check.json
```

It prints one line per connection (`connection=ok list_tables=ok catalog=ok
profile=ok explain=ok review=ok search=ok`) and exits non-zero when a step
failed; `explain=SKIPPED` on Db2 means the DBA has not provisioned explain
tables, which is expected and harmless. Bring `/tmp/udbmcp-site-check.json`
back for diagnosis; it is safe to share.

Then start a new Claude Code session and ask it to run `db_test_connection`
on each connection. The reply carries a `session` block: Db2 shows
`isolation: ur` and `lock_timeout_seconds: 5`, PostgreSQL and MySQL show
`read_only_verified: true`, SQL Server shows `read_uncommitted`. Ask for
`db_review_schema` on one connection: it is one of the two new tools and
returns prioritized findings with evidence.

## What changed for an existing site (read before the first query)

Full list in `docs/offline-upgrade-rollback.md`; the ones that can surprise
you:

- **Every read-only connection now gets a server session profile**: Db2 runs
  at `UR`, SQL Server at `READ UNCOMMITTED`, PostgreSQL and MySQL are put
  into read-only mode server-side, lock waits are capped at 5 s and
  statements at `security.hard_query_timeout_seconds`. Four of these fail
  closed: the Db2 and SQL Server isolation and the PostgreSQL and MySQL
  read-only setting. A server or proxy that refuses one of them refuses the
  connection with `could not apply the session … refusing to run at the
  server's default level`; the per-connection `session:` block is the
  opt-out (`isolation: cs`, `enforce_read_only: false`).
- **Db2 statements may end in `WITH UR` or `WITH CS`; `WITH RS`/`WITH RR`
  are refused** because they hold locks.
- **`db_get_catalog` and `db_list_indexes` no longer list system catalogs**
  (Oracle dictionary views, Db2 SYSCAT) unless asked with `include_system`.
- **`schema.table` object names work everywhere** (they were denied before).
- **Two new tools**: `db_review_schema` and `db_document_schema`.

## Rollback (to the previous stick's release)

Since this release an upgrade keeps the previous venv at
`/opt/universal-db-mcp/venv.previous` with an integrity manifest, so the
quick rollback is the bundle's own script (it verifies the manifest before
it executes anything, then swaps the venvs back):

```bash
# 1. put back the config the previous release understood (older releases reject unknown keys such as session:)
sudo systemctl stop universal-db-mcp
sudo cp "$(sudo cat /root/udbmcp-last-backup 2>/dev/null)/etc/config.yaml" /etc/universal-db-mcp/config.yaml 2>/dev/null || true
# 2. swap the venvs back (verified against the manifest first)
sudo bash /usr/share/universal-db-mcp/bundle/operations/rollback_offline.sh /opt/universal-db-mcp
sudo systemctl restart universal-db-mcp
grep -c db_review_schema /opt/universal-db-mcp/venv/lib/python3.12/site-packages/universal_db_mcp/server.py   # 0 on a pre-27-tool release
```

That restores the venv installed BEFORE this upgrade (depth one). To go
back to an older package instead, or when the site was installed before
this release (no `venv.previous` yet), install the previous stick's package.
Three rules make that a real rollback instead of a masked one:

1. **Keep the current trusted tools.** Do NOT run the older stick's
   `trust-bootstrap-linux/bootstrap.sh`: copies built before 2026-09-15 lack
   `--force-reinstall`, so the "rollback" would keep the new code in the venv
   while dpkg and the manifest report the old release.
2. **Restore the pre-upgrade config.** Older releases reject configuration
   keys they do not know: a `session:` block added for this release makes
   the old service exit at start. Restore the config you backed up before
   upgrading (or remove every `session:` block), for the system and the
   per-user file.
3. **Delete the venv before installing the old package**, then verify.
   Installing the older package now prints `dpkg: warning: downgrading`,
   which is correct and expected here; `dpkg -i` proceeds.

```bash
OLD=$(ls /mnt/usb/usb-ubuntu-*/universal-db-mcp_*_amd64.deb | head -1)   # the OLD stick, mounted as in step 0
sudo systemctl stop universal-db-mcp
sudo rm -rf /opt/universal-db-mcp/venv
sudo dpkg -i "$OLD"
until grep -qxE 'success|failed' /var/log/universal-db-mcp-install.status 2>/dev/null; do sleep 5; done
cat /var/log/universal-db-mcp-install.status
grep -c db_review_schema /opt/universal-db-mcp/venv/lib/python3.12/site-packages/universal_db_mcp/server.py   # must print 0
sudo systemctl restart universal-db-mcp
```

Keep the previous stick until the new release has run for a while.
