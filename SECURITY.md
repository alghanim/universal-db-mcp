# Security policy

universal-db-mcp holds database credentials and stands between AI agents and
production data, so we treat a weakness in it as a weakness in every database
it can reach. Thank you for reporting one privately.

## Reporting a vulnerability

Report it through **GitHub private vulnerability reporting** on this
repository, at
<https://github.com/alghanim/universal-db-mcp/security/advisories/new> (or open
the **Security** tab and choose **Report a vulnerability**), and fill in the
form. That is the only reporting channel. Please do not open a
public issue, pull request or discussion for a suspected vulnerability, and do
not send it anywhere else. No e-mail address is published for reports: the
one in the `.deb`'s Maintainer field, which Debian requires, is a placeholder
under the reserved `.invalid` domain and reaches no one.

Useful things to include:

- the release you tested: `udbmcp version`, or the `source_rev` and
  `release_seq` in the installed `manifest.json`;
- the engine and server version, the transport (stdio or HTTP) and the
  install path (source, offline bundle, `.deb`, `.pkg`, `.msi`);
- the relevant part of the configuration (`security:` block, the connection's
  `allowed_schemas`, `session:` and `options:`), with every host name,
  credential and path you consider sensitive removed;
- the exact tool call or statement, what the server returned (the error
  category and message, or the result), and what you expected instead;
- for a guard, masking or authorization bypass: the smallest statement that
  shows it, and whether you confirmed it against a real server;
- the impact as you see it: what an agent, a local user or a network peer can
  read, change or disrupt that it should not.

A report is useful even when it is incomplete. Never include real
credentials, real data from a production database, or a key.

## What happens next

Every report is acknowledged within 7 days. We will confirm whether we can
reproduce the issue, keep you informed while a fix is prepared, and agree
with you when and how it is disclosed (coordinated disclosure: the advisory
is published once a fixed release is available). We credit reporters in the
advisory unless you ask us not to.

## Supported versions

Security fixes are made for the current release line (0.1.x) and ship as a
new signed build of the latest release. Older builds are not patched: install
the latest build. Every release build carries a signed `release_seq`, and
from this release on the installers refuse to replace a newer build with an
older one unless an administrator asks for the downgrade explicitly: the
offline-bundle scripts, the `.deb`, the `.pkg`, the `.msi`, and in container
mode the image loader, which keeps a root-owned release record
(`/var/lib/universal-db-mcp/release.json`). The check lives in the trusted
verifier a site installs, and on the install target that verifier compares
with the installed release even when an installer does not ask it to. So
while the site keeps this release's verifier, it also refuses an older
`.deb` or bundle, and a `.pkg` or `.msi` built before `release_seq` existed
(the `.msi` has not yet been run on a Windows host). Three limits
remain. Such an old `.pkg` is refused only in its postinstall, after the
macOS Installer has written its files, which it does not put back:
re-install the current `.pkg` to restore them. Container mode is protected
only from the first load by this release's loader, which writes the first
record. And a site whose trust directory still holds an older verifier gets
none of this for packages built before this release.

## How a fix reaches an air-gapped site

The server never downloads anything, so a fix arrives the same way as any
release: a new offline bundle, signed with the release key, carried in on a
USB stick or another approved channel.

1. The release administrator builds and signs the release on the staging
   machine (`scripts/package/release_usb.sh`). The stick lists every file in
   `SHA256SUMS` and carries `SHA256SUMS.sig`, an Ed25519 signature of that
   list made with the release key.
2. At the site, the new stick is checked with the release key the site
   already trusts, before anything from the stick runs. From this release
   on, the trust bootstrap an earlier release installed does it:
   `sudo bash /usr/local/lib/udbmcp-trust/bootstrap.sh --stick <stick>`.
   It refuses a stick whose list is not signed by that key, a file that does
   not match the list, and any file the list does not name. It also refuses
   a stick older than the release whose trust tools it installed: every
   stick names its release in `trust-bootstrap-linux/RELEASE`, on the signed
   list, and `bootstrap.sh` records it (an intended downgrade passes
   `--allow-downgrade`; until a release is recorded, any signed stick is
   accepted). On a first
   install, and on a site whose earlier release installed no bootstrap, the
   host's own `/usr/bin/openssl` checks `SHA256SUMS.sig` first, and only then
   does the stick's `bootstrap.sh` run. Either way, `bootstrap.sh` then
   copies the stick's `.deb` packages into the root-only
   `/var/cache/udbmcp-trust/`, checks the copies against the signed list
   again and prints the `dpkg -i` command for them: install from those
   copies, never from the stick.
3. The installers verify the bundle signature again before any of the payload
   runs, and refuse an older release.

Confirm the release key's fingerprint out of band (in person, by phone, on
paper) on a first install and whenever the key changes: `bootstrap.sh` prints
the SHA-256 fingerprint of the key on the stick, and a site replaces its
installed key only with `--rotate-key` after that comparison. A fingerprint
read from the stick itself (`RELEASE-KEY-FINGERPRINT.txt`) proves nothing on
its own, because whoever can change the stick can change that file too.
`docs/site-upgrade-runbook.md` has the full procedure.

## Release signing key

Releases from v0.1.0 on are signed with one Ed25519 release key. Its
fingerprint, the SHA-256 of the DER-encoded public key (what `bootstrap.sh`
and `release_usb.sh` print), is:

```
4d27906ec57c098f7c86942fb78803fdec9f753735afbc7c68a01c778ec62179
```

Each GitHub release carries the public key (`release.pub.pem`), `SHA256SUMS`
and `SHA256SUMS.sig`. This file is one channel for the fingerprint: before a
first install, confirm it through a second one as well. A key change is
announced here, in the release notes, and through that second channel, and
is installed at a site only with `bootstrap.sh --rotate-key`. Builds signed
with the demo key (`release_usb.sh --demo`) are for testing and are never
published.

## Scope

In scope: the server and its tools (`src/universal_db_mcp`), the SQL guard,
masking, authorization and session safety, the HTTP transport, the audit log,
the CLI (`udbmcp add-connection`, `configure-agents`, `doctor`, `site-check`),
the offline bundle builder and verifier, the trust bootstrap, the `.deb`,
`.pkg` and `.msi` installers, and the container image loader.

Documented limitations are not vulnerabilities in themselves, although a way
around the documented boundary of one is. The main ones are listed in
`docs/security.md`: stdio mode is not a security boundary between the agent
and the credentials, masking protects projected values only (a predicate on a
masked column can still infer values), and the database login's own grants
are the primary control. `IMPLEMENTATION_STATUS.md` lists what is verified
and what is not.
