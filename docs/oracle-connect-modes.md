# Oracle connect modes (udbmcp, air-gapped)

Covers the Oracle cases that a plain `host:port/service` connection cannot
reach: legacy password verifiers, pre-12c SIDs, `tnsnames.ora` aliases, and
TLS. Related: `docs/driver-matrix.md`, `docs/offline-deployment.md`.

## 1. `DPY-3015: password verifier type 0x939 is not supported`

The server is authenticating this session with the legacy 10G verifier, and
python-oracledb in Thin mode (our default) implements the 11G and 12C
verifiers only. It is not a wrong password and not a network problem.

**Two different server states produce it**, so check both before choosing a
remedy:

```sql
-- 1. what the account carries
SELECT username, password_versions FROM dba_users WHERE username = '<USER>';
--    '10G' alone        -> the account has no modern verifier
--    '10G 11G 12C'      -> the account is fine; the server is choosing 10G, see 2

-- 2. whether the server forces the old, case-insensitive logon path
SHOW PARAMETER sec_case_sensitive_logon
--    FALSE -> the server authenticates with the 10G verifier whatever the
--             account carries, and Thin mode is refused. Confirmed at a site
--             on Oracle 12c, 2026-09-20: password_versions = '10G 11G 12C'
--             and sec_case_sensitive_logon = FALSE gave DPY-3015.
```

A third possibility, when both look right: the server's `sqlnet.ora` pins
`SQLNET.ALLOWED_LOGON_VERSION_SERVER` low (8 or 10). That file is not
visible through `v$parameter`; it lives in `$ORACLE_HOME/network/admin/`
on the database host.

Thick mode (remedy B) fixes every one of these cases without a server
change, because Oracle's own client still speaks the old protocol.

Two remedies, either is sufficient.

**A. Server side (no client change, but it affects every application on
that database).** If `sec_case_sensitive_logon` is FALSE, the DBA sets it
back to TRUE (`ALTER SYSTEM SET sec_case_sensitive_logon = TRUE`), which
makes passwords case-sensitive again for every client and locks out any
account that still carries only a 10G verifier. If instead the account has
no modern verifier, the DBA regenerates the password hash:

```sql
SHOW PARAMETER sec_case_sensitive_logon    -- must NOT be FALSE
ALTER USER <USER> IDENTIFIED BY <new password>;
SELECT username, password_versions FROM dba_users WHERE username = '<USER>';
-- must now list 11G or 12C
```

If the account still comes back `10G` only, the server's
`SQLNET.ALLOWED_LOGON_VERSION_SERVER` is pinned low. That setting lives in
the server's `sqlnet.ora` file, not in `v$parameter`, and cannot be changed
with `ALTER SYSTEM`. Values of 11 or lower generate 10G, 11G and 12C
verifiers; 12 generates 11G and 12C. Raising it locks out any other account
that still has only a 10G verifier, so it is a DBA decision.

**B. Client side: Thick mode.** Thick mode uses Oracle's Instant Client,
which still accepts the 10G verifier. It is Oracle-licensed and
**administrator-supplied**: it is never shipped inside our bundles or
packages, and accepting Oracle's licence is an administrative decision.

Air-gapped delivery, mirroring the trust bootstrap:

1. On the staging machine (the only machine with network access), download the
   Instant Client for the target platform from Oracle and accept the licence
   there. The **19** line is the widest choice: it reaches servers from 11.2
   through current, and python-oracledb supports client libraries from 19.
2. Carry it on the same trusted channel (USB) as the release, together with
   `libaio` (the client links against it and a minimal Ubuntu does not have
   it). On Ubuntu 24.04 the package is `libaio1t64`, which ships
   `libaio.so.1t64`, so the client also needs a `libaio.so.1` symlink.
3. Install it so the LOADER can find it, which on Linux means `ldconfig`, not
   `options.lib_dir`. On a release stick, `bootstrap.sh` has checked every
   file against the signed `SHA256SUMS` and copied the `.deb` packages to
   `/var/cache/udbmcp-trust/` (root only): install them from those copies,
   never from the stick, because `dpkg -i` reads the file again and runs its
   scripts as root. It does not copy the Instant Client zip, so copy the zip
   with the signed list and check both before unzipping (`$STICK` is the
   stick folder, as in `docs/site-upgrade-runbook.md`):

```bash
C=/var/cache/udbmcp-trust/oracle-instantclient   # bootstrap.sh's checked copies
sudo dpkg -i "$C/libaio1t64_0.3.113-6build1.1_amd64.deb"   # the file names the stick's signed SHA256SUMS lists
command -v unzip >/dev/null || sudo dpkg -i "$C/unzip_6.0-28ubuntu4.1_amd64.deb"
ls /usr/lib/x86_64-linux-gnu/libaio.so.1 2>/dev/null || \
  sudo ln -s /usr/lib/x86_64-linux-gnu/libaio.so.1t64 /usr/lib/x86_64-linux-gnu/libaio.so.1
sudo cp "$STICK/SHA256SUMS" "$STICK/SHA256SUMS.sig" \
  "$STICK/oracle-instantclient/instantclient-basiclite-linux.x64-19.28.zip" "$C/"
sudo /usr/bin/openssl pkeyutl -verify -pubin -inkey /etc/universal-db-mcp/keys/release.pub.pem -rawin \
  -in "$C/SHA256SUMS" -sigfile "$C/SHA256SUMS.sig"      # must print: Signature Verified Successfully
sudo sh -c "cd $C && grep '  oracle-instantclient/instantclient-basiclite-linux.x64-19.28.zip\$' SHA256SUMS \
  | sed 's#oracle-instantclient/##' | sha256sum -c --strict -"   # must print: ...zip: OK
sudo mkdir -p /opt/oracle
sudo unzip "$C/instantclient-basiclite-linux.x64-19.28.zip" -d /opt/oracle
sudo chmod -R a+rX /opt/oracle   # the service account must reach it whatever root's umask is
echo /opt/oracle/instantclient_19_28 | sudo tee /etc/ld.so.conf.d/oracle-instantclient.conf
sudo ldconfig
ldconfig -p | grep libclntsh     # must print a match
```

   The copies stay in `/var/cache/udbmcp-trust/` until the next `bootstrap.sh`
   run replaces them. Keep the client under `/opt` or `/usr/local`: the
   loader refuses libraries in unsafe paths such as a user's home directory.
   Use `ldconfig` rather than `LD_LIBRARY_PATH`, which systemd clears for the
   service.

4. Point the connection at it:

```yaml
connections:
  legacy_ora:
    type: oracle
    host: 10.x.x.x
    port: 1521
    database: ORCLPDB1          # service name
    username_file: /home/<you>/.universal-db-mcp/secrets/legacy_ora.username
    password_file: /home/<you>/.universal-db-mcp/secrets/legacy_ora.password
    read_only: true
    options:
      thick_mode: true          # and NO lib_dir on Linux: see step 3
```

5. `udbmcp doctor` reports `connection-<name>-oracle-instant-client`. It checks
   the directory only: loading the client would switch the whole process to
   Thick mode, which a diagnostic must never do as a side effect.

**Thick mode is process-global.** `init_oracle_client()` switches the entire
server process, so the config refuses a mix: either every oracle connection
sets `thick_mode: true`, or none does. It also cannot be enabled after the
process has already made a Thin connection (`DPY-2019`), which is why the rule
is all-or-nothing rather than per connection. Restart the service after
switching a deployment to Thick mode.

## 2. Pre-12c databases that register a SID

Easy-connect (`host:port/service`) cannot express a SID. Use:

```yaml
    options:
      sid: ORCL
```

The connector then builds a full connect descriptor with `(SID=ORCL)`. The
`database:` field is unused in this form but still required by the schema.

## 3. `tnsnames.ora` aliases

```yaml
    options:
      tns_alias: PRODDB
      tns_admin: /etc/universal-db-mcp/tns     # directory holding tnsnames.ora
```

The alias carries its own descriptor, so `host`, `port` and `database` are not
used to reach the database. `tns_admin` is mandatory with an alias, and
`doctor` fails closed when `tnsnames.ora` is missing. This is also the way to
reach RAC services and LDAP-resolved descriptors that a DBA hands over as an
alias. In Thin mode the directory is passed per connection; in Thick mode it
is given to the Instant Client at initialization. For the per-server share,
the hung-connect breaker and the stuck-connect budget, such a connection's
database server is the alias (ignoring case) with its `tns_admin`
directory, normalized, never the placeholder `host` and `port`; in Thick
mode without `tls.enabled` the alias alone (with TLS the connector builds
the TCPS descriptor from the connection's own `tns_admin` in either mode,
so the directory counts again). Two aliases, or one alias under two `tns_admin`
directories, are two servers; one alias under several connection ids is
one; an alias and a host/port connection to the same database are two
(`docs/architecture.md`).

**An alias with `tls.enabled`.** The connector resolves the alias with
python-oracledb's own `tnsnames.ora` reader, the way the driver will (`IFILE`
includes, the last definition winning, multi-name entries, continuation
lines), checks the result and dials the checked descriptor, never the alias.
It refuses the connection when any address is not TCPS, when the entry turns
`SSL_SERVER_DN_MATCH` off, or when the alias cannot be found (an alias only a
directory server (LDAP) resolves cannot be checked: use the host/port/database
form). python-oracledb's reader does not take some spellings the Oracle
Client accepts: write `SSL_VERSION=TLSv1.2` (or `TLSv1.3`), not `1.2`, and
`SSL_CIPHER_SUITES` without parentheses; the refusal names the `DPY` code. A
wallet password (`options.wallet_password_file` or `wallet_password_env`) is
honoured on the alias path.

## 4. TLS (TCPS)

```yaml
    tls:
      enabled: true
    options:
      wallet_location: /etc/universal-db-mcp/oracle-wallet
```

`tls.enabled` alone is refused without a wallet: setting wallet parameters
without selecting TCPS would leave the wire in plaintext, so the connector
builds a TCPS descriptor and requires the administrator-supplied wallet. A
`sid` may be combined with TLS; the descriptor then carries `(SID=...)`.

The descriptor carries `(SECURITY=(SSL_SERVER_DN_MATCH=ON)(MY_WALLET_DIRECTORY=...))`,
so host-name (DN) matching is enforced in both modes: the server certificate
must match the host the client dials. The wallet path is written into the
descriptor double-quoted, so `options.wallet_location` may not contain `"`,
`)(` or a control character (the connector refuses, and doctor reports
`connection-<id>-oracle-wallet` as fatal; rename the directory).

- **Thin mode** reads a PEM wallet (`ewallet.pem`); doctor fails closed when
  the directory has none. A password-protected wallet takes its password from
  `options.wallet_password_file` (a 0600 file) or `options.wallet_password_env`.
  An inline `options.wallet_password` is a `CONFIG_ERROR`.
- **Thick mode** hands the descriptor to the Oracle Client unchanged, so
  wallet keywords given to `connect()` never reach it: it needs an
  auto-login wallet, `cwallet.sso`, at `options.wallet_location`
  (`orapki wallet create -wallet <dir> -auto_login`); the wallet password
  applies to Thin mode only. Doctor checks for `cwallet.sso`.

## 5. Other behaviour worth knowing

- **Thin mode is fixed before the first connect.** Every Thin connect first
  calls `oracledb.enable_thin_mode()`, so a listener that never answers no
  longer blocks other Oracle connections. In a process where something
  already enabled Thick mode, a Thin-configured connection fails with
  python-oracledb's own error (the all-or-nothing config rule prevents that in
  a real deployment).
- **Residual: a listener that accepts TCP and never answers.**
  python-oracledb 4.0.2 bounds only the TCP connect (`tcp_connect_timeout`,
  from `connect_timeout_seconds`); `CONNECT_TIMEOUT`,
  `TRANSPORT_CONNECT_TIMEOUT`, `RETRY_COUNT=0` and `expire_time` in a
  descriptor or easy-connect string were measured without effect on the rest
  of the handshake. Such a connect blocks its worker thread until the peer
  closes the socket. The executor fails the request at its deadline and,
  after `max(connect_timeout_seconds, 5 s)`, parks the connect in its
  stuck-connect budget (10 slots, at most 9 per database server) and refuses
  the other connections to that server while it hangs
  (`docs/driver-matrix.md`, `docs/architecture.md`).
- **Large values.** LOBs are read partially and cut to the cell limit; BLOBs
  come back as `{"$binary_b64", "$truncated"}`, an unreadable BFILE as null
  with a warning. Native JSON, LONG, LONG RAW, object and collection columns
  (XMLType in Thick mode) are decoded whole by the driver, so they are fetched
  1, 2, 4, 4, ... rows per round trip (at most 4), and back to 1 after a cut
  value; one large JSON document still costs about 8x its text size to decode.
- **System schemas.** Oracle-maintained owners (`SYS`, `SYSTEM`, `CTXSYS`,
  ..., the 9i-11g owners such as `WKSYS`, `DMSYS`, `ODM`, the 9i JServer and
  trace owners `AURORA$JIS$UTILITY$`, `AURORA$ORB$UNAUTHENTICATED`,
  `OSE$HTTP$ADMIN` and `TRACESVR`, and every `APEX_nnnnnn` / `FLOWS_nnnnnn`)
  are readable only when `security.allowed_system_schemas` or the
  connection's `allowed_schemas` names them, and discovery skips them.
  `PDBADMIN` counts as user data. `db_list_tables` lists the database's own
  owners first, then the opened dictionary owners. Views of other sessions'
  SQL (`V$SQL`, `V$SESSION`, the AWR, audit and SQL-tuning views and their
  base tables, in any schema or bare) and of column statistics
  (`*_HISTOGRAMS`, `*_COL_STATISTICS`, `HISTGRM$`, ...) are refused whatever
  is opened, and `*_TAB_COLUMNS` and `COLS` are readable only without
  `LOW_VALUE` and `HIGH_VALUE` (`docs/security.md`).
- **`DUAL`.** `DUAL` and `SYS.DUAL` are readable in statements on every
  connection without opening `SYS` (owner decision 2026-09-28). A bare
  `DUAL` is checked first, in the session that runs it: `db_query` (and
  every other tool that runs a statement) and `db_explain` refuse it
  (`AUTHORIZATION_DENIED`, with `write SYS.DUAL`) when the session's current
  schema owns an object named `DUAL`, or when a logon set the current schema
  to another schema than the login user's. `db_validate_query` does not
  reach the database and reports such a statement valid. `SYS.DUAL` always
  works, and the connector's own probes read it. The metadata tools describe
  `SYS.DUAL` only where `SYS` is opened or `default_deny_objects` is false
  (`docs/driver-matrix.md`).
- **Unquoted names with `ı` or `ſ`** are refused: Oracle upper-cases them to
  `I` or `S` and would read another name. Write the ASCII letter, or quote the
  name to mean it exactly.
- **Database links** are refused: the guard refuses any `@` outside a string
  literal, a hint or a double-quoted name, and `db_query` and `db_explain`
  check the text again in the connector before any session is opened (a
  statement with a `q'...'` or `nq'...'` literal and an `@` anywhere is
  refused there too). A `DUAL` named with a link is never taken for the
  local one. `V$DATABASE_LINK`, `GV$DATABASE_LINK` and the `*_DB_LINKS`
  views hold stored credentials and are refused whatever is opened.
- **Alternative-quoted literals:** the guard cannot parse an
  alternative-quoted `q'...'` or `nq'...'` literal, so a statement holding
  one is refused in every tool, `db_validate_query` included, with or
  without an `@` (`POLICY_VIOLATION: statement could not be parsed under the
  'oracle' dialect ...`). Write the string in ordinary quotes, doubling a
  quote inside it (`'it''s'`).
- **Catalog SQL names `SYS`.** The connector reads `SYS.ALL_*` views, its
  health probe `SYS.V_$VERSION`, and its plans through `SYS.DBMS_XPLAN`, so
  an object of the same name in the login's schema cannot stand in for the
  dictionary. With `default_deny_objects: false`, every name a statement or
  tool reads is also looked up in `SYS.ALL_SYNONYMS` and its chain checked
  (`docs/security.md`, Object authorization).
- **State files.** The audit log and the metadata cache may not be one of the
  client's files (`tnsnames.ora`, `sqlnet.ora`, `ldap.ora`, `oraaccess.xml`,
  `ewallet.pem`, `cwallet.sso`, `ewallet.p12`) under `tns_admin`,
  `wallet_location` or `lib_dir/../network/admin` (a full Oracle Client's
  `ORACLE_HOME/network/admin` when `lib_dir` is `ORACLE_HOME/lib`, or
  `ORACLE_HOME\bin` on Windows). A symlink or hard link to one of those files
  counts as the file. Nor may a state file sit directly in `lib_dir` or in
  `lib_dir/network/admin`, whatever its name (a rule by directory: a hard
  link elsewhere to a file there is not refused at load; on POSIX the audit
  log and the cache refuse to use a file with a second hard link). Other
  files, and deeper directories, are fine, so `TNS_ADMIN=$HOME` or
  `lib_dir=$HOME` works with the per-user audit default.

## Evidence status

| Item | Status | Evidence |
|---|---|---|
| Service-name, legacy SID and `tnsnames.ora` alias connects | passed (live) | `test-evidence/oracle-connect-modes/` against Oracle 23ai Free on this host |
| `DPY-3015` mapped to an error naming both remedies | passed (unit) | `tests/unit/test_oracle_connect_modes.py` with a driver fake |
| Thick mode initialization, single init, fail-closed diagnostics | passed (unit) | same file |
| Thick mode against an account carrying ONLY the 10G verifier (Oracle 18c XE, `password_versions = '10G'`) | **passed (live)** | `test-evidence/oracle-thick-mode/`: through `OracleConnector`, Thin fails with exactly `DPY-3015 ... 0x939` and Thick connects and returns query rows. Nothing changed on the server between the two runs. |
| Thick mode against an Oracle 11.2 server | passed (live) | same evidence file: Thin cannot reach 11.x at all (`DPY-3010`, below the Thin floor); Thick connects with Instant Client 19.28 loaded via `ldconfig` in a no-network container |
| Thick mode enabled after a Thin connection in the same process | refused with the ordering explained (`DPY-2019`) | unit-tested; the config's all-or-nothing rule prevents it in a real deployment |
| TLS/TCPS with a wallet, alias resolution under TLS, Thick-mode `cwallet.sso` | `not_run` live (unit-tested with driver fakes) | no wallet-enabled Oracle fixture |
