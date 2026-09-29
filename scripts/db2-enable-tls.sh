#!/usr/bin/env bash
# db2-enable-tls.sh — enable SSL on a Db2 LUW instance so the pinned ibm_db
# 3.2.9 client (bundled clidriver) can authenticate with REMOTE passwords.
#
# Background: the pinned ibm_db 3.2.9 client fails plaintext REMOTE password
# auth against Db2 LUW with SQL30082N reason 17 (observed on Db2 12.1 and
# 11.5.9). The proven remediation is server-side TLS: SECURITY=SSL +
# SSLServerCertificate. See docs/db2-tls-setup.md for the full runbook.
#
# Scope:
#   * --container mode (default): automates the recipe inside a running Db2
#     container (GSKit probe + optional ICU shim, keydb + self-signed cert,
#     DBM cfg, instance restart, certificate extraction, YAML block).
#   * --host mode: for a native LUW instance the script only PRINTS the exact
#     commands for the administrator to run on that host; it never opens a
#     network connection (air-gapped discipline).
#   * --verify-only: read-only check of the current SSL DBM configuration.
#
# Idempotent: re-running on an already-configured instance is safe (existing
# keydb/cert are reused, the DBM update is skipped when values already match,
# the instance is only restarted when the configuration actually changed).
#
# Usage (container mode):
#   scripts/db2-enable-tls.sh \
#     --container db2fixture \
#     --password '<keydb-password>' \
#     --ssl-port 50001 \
#     --cert-out /etc/universal-db-mcp/certs/db2-server.crt \
#     [--icu-source-dir /path/to/icu70-libs]        # only if the GSKit probe
#                                                   #   fails on an ICU library
#     [--client-host 127.0.0.1] [--database SAMPLE] \
#     [--instance-user db2inst1] [--label udbmcp_self]
#
# Usage (native host — prints commands only):
#   scripts/db2-enable-tls.sh --host db2.internal.example \
#     --ssl-port 50001 --database SAMPLE
#
# Usage (verify only, container):
#   scripts/db2-enable-tls.sh --container db2fixture --verify-only

set -euo pipefail

PROG="$(basename "$0")"
usage() {
  sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo "==> $*"; }

# ------------------------------------------------------------------ arguments
CONTAINER=""
HOST=""
PASSWORD=""
SSL_PORT="50001"
ICU_SOURCE_DIR=""
CERT_OUT="./server.crt"
CLIENT_HOST=""
DATABASE="SAMPLE"
INSTANCE_USER="db2inst1"
KEYDB_NAME="server.kdb"
STASH_NAME="server.sth"
CRT_NAME="server.crt"
LABEL="udbmcp_self"
VERIFY_ONLY=0

while [ $# -gt 0 ]; do
  case "$1" in
    --container)      CONTAINER="${2:?--container requires a value}"; shift 2 ;;
    --host)           HOST="${2:?--host requires a value}"; shift 2 ;;
    --password)       PASSWORD="${2:?--password requires a value}"; shift 2 ;;
    --ssl-port)       SSL_PORT="${2:?--ssl-port requires a value}"; shift 2 ;;
    --icu-source-dir) ICU_SOURCE_DIR="${2:?--icu-source-dir requires a value}"; shift 2 ;;
    --cert-out)       CERT_OUT="${2:?--cert-out requires a value}"; shift 2 ;;
    --client-host)    CLIENT_HOST="${2:?--client-host requires a value}"; shift 2 ;;
    --database)       DATABASE="${2:?--database requires a value}"; shift 2 ;;
    --instance-user)  INSTANCE_USER="${2:?--instance-user requires a value}"; shift 2 ;;
    --label)          LABEL="${2:?--label requires a value}"; shift 2 ;;
    --verify-only)    VERIFY_ONLY=1; shift ;;
    --help|-h)        usage 0 ;;
    *)                echo "Unknown argument: $1" >&2; usage 2 ;;
  esac
done

if [ -z "$CONTAINER" ] && [ -z "$HOST" ]; then
  echo "ERROR: one of --container <name> or --host <addr> is required" >&2
  usage 2
fi
if [ -n "$CONTAINER" ] && [ -n "$HOST" ]; then
  die "--container and --host are mutually exclusive"
fi

case "$SSL_PORT" in
  ''|*[!0-9]*) die "--ssl-port must be a positive integer (got '$SSL_PORT')" ;;
esac
[ "$SSL_PORT" -ge 1 ] && [ "$SSL_PORT" -le 65535 ] \
  || die "--ssl-port must be in 1..65535 (got '$SSL_PORT')"

# Lowercase form used in generated YAML keys/secrets (portable: bash 3.2 has
# no ${var,,} expansion, and /usr/bin/env bash is 3.2 on macOS admins' boxes).
DATABASE_LC="$(printf '%s' "$DATABASE" | tr '[:upper:]' '[:lower:]')"

# The certificate must name the host the CLIENT dials: the connector always
# sets SSLClientHostnameValidation=Basic, which matches HOSTNAME against the
# certificate's subjectAltName (an IP address needs an IP SAN).
CERT_HOST="${HOST:-${CLIENT_HOST:-127.0.0.1}}"
case "$CERT_HOST" in
  ''|*[!A-Za-z0-9.:-]*) die "host '$CERT_HOST' is not a DNS name or an IP address" ;;
esac
case "$CERT_HOST" in
  *:*)       CERT_SAN_KIND="ipaddr" ;;
  *[!0-9.]*) CERT_SAN_KIND="dnsname" ;;
  *)         CERT_SAN_KIND="ipaddr" ;;
esac

# ----------------------------------------------------------------- host mode
# A native LUW instance is configured ON that host by the administrator with
# the same recipe. This script deliberately does not SSH anywhere (the
# air-gapped target allows no egress); it prints the commands instead.
if [ -n "$HOST" ]; then
  echo "HOST MODE: no changes are made from this machine."
  echo
  echo "Run the following ON ${HOST}, as the instance owner (${INSTANCE_USER})"
  echo "(see docs/db2-tls-setup.md, section 'Native LUW instance'):"
  echo
  echo "  # 1. Probe GSKit with only \$HOME/sqllib/lib64/gskit on LD_LIBRARY_PATH."
  echo "  #    On Db2 11.5.x (GSKit 8) that alone is sufficient — NO ICU shim."
  echo "  #    Only if the probe fails on an ICU library (observed on the Db2"
  echo "  #    12.1 image), stage unsuffixed ICU 70 libraries — copied by the"
  echo "  #    administrator from any Ubuntu 22.04-based image's"
  echo "  #    /usr/lib/x86_64-linux-gnu/ (e.g."
  echo "  #    mcr.microsoft.com/mssql/server:2022-latest); the air-gapped target"
  echo "  #    NEVER downloads anything:"
  echo "  export LD_LIBRARY_PATH=\"\$HOME/sqllib/lib64/gskit:\${LD_LIBRARY_PATH:-}\""
  echo "  \$HOME/sqllib/gskit/bin/gsk8capicmd_64 -keydb -create -db \$HOME/.udbmcp-gskit-probe.kdb -pw '<keydb-password>' -stash \\"
  echo "    && rm -f \$HOME/.udbmcp-gskit-probe.kdb \$HOME/.udbmcp-gskit-probe.sth \\"
  echo "    || echo \"probe failed: if the error names libicu*.so.70, stage \$HOME/udbmcp-icu70 (libicu{data,i18n,io,uc}.so.70.1 + .so.70 symlinks) and put it FIRST on LD_LIBRARY_PATH — see docs/db2-tls-setup.md\""
  echo
  echo "  # 2. Key database + self-signed cert. Try '-cert -create' first; older"
  echo "  #    GSKit 8 builds that reject it use the legacy '-cert -selfsign' verb"
  echo "  #    instead (with GSKit 9 the binary is gsk9certutil_64). The certificate"
  echo "  #    names ${CERT_HOST} (CN and subjectAltName): the client validates the"
  echo "  #    host name it dials against it (SSLClientHostnameValidation=Basic):"
  echo "  export LD_LIBRARY_PATH=\"\$HOME/udbmcp-icu70:\$HOME/sqllib/lib64/gskit:\${LD_LIBRARY_PATH:-}\""
  echo "  \$HOME/sqllib/gskit/bin/gsk8capicmd_64 -keydb -create -db \$HOME/${KEYDB_NAME} -pw '<keydb-password>' -stash"
  echo "  \$HOME/sqllib/gskit/bin/gsk8capicmd_64 -cert -create -db \$HOME/${KEYDB_NAME} -pw '<keydb-password>' -label ${LABEL} -size 2048 -expire 3650 -dn CN=${CERT_HOST} -san_${CERT_SAN_KIND} ${CERT_HOST} \\"
  echo "    || \$HOME/sqllib/gskit/bin/gsk8capicmd_64 -cert -selfsign -db \$HOME/${KEYDB_NAME} -pw '<keydb-password>' -label ${LABEL} -size 2048 -expire 3650 -dn CN=${CERT_HOST} -san_${CERT_SAN_KIND} ${CERT_HOST}"
  echo
  echo "  # 3. DBM configuration + instance restart:"
  echo "  source \$HOME/sqllib/db2profile"
  echo "  db2 update dbm cfg using SSL_SVR_KEYDB \$HOME/${KEYDB_NAME} SSL_SVR_STASH \$HOME/${STASH_NAME} SSL_SVR_LABEL ${LABEL} SSL_SVCENAME ${SSL_PORT}"
  echo "  db2stop force && db2start"
  echo
  echo "  # 4. Extract the certificate and copy it OFF the host to the MCP target:"
  echo "  \$HOME/sqllib/gskit/bin/gsk8capicmd_64 -cert -extract -db \$HOME/${KEYDB_NAME} -pw '<keydb-password>' -label ${LABEL} -target \$HOME/${CRT_NAME} -format ascii"
  echo
  echo "  # 5. Verify on the host:"
  echo "  db2 get dbm cfg | grep -E 'SSL_SVCENAME|SSL_SVR_KEYDB|SSL_SVR_LABEL'"
  echo
  echo "Client YAML block to paste into the udbmcp config (adjust names/secrets):"
  cat <<EOF

connections:
  ${DATABASE_LC}_db2:
    type: db2
    family: luw
    host: ${HOST}
    port: ${SSL_PORT}
    database: ${DATABASE}
    username_env: DB2_USER                     # or an explicit username per policy
    password_file: /run/secrets/${DATABASE_LC}_db2_password
    tls:
      enabled: true
      verify_server: true
      ca_file: /etc/universal-db-mcp/certs/db2-server.crt   # = extracted ${CRT_NAME}
    allowed_schemas: [UDBMCP_RO]               # read-only account's schema — empty list = NO schema restriction
    read_only: true
EOF
  exit 0
fi

# ---------------------------------------------------- container mode: checks
command -v docker >/dev/null 2>&1 || die "docker CLI not found on PATH"

docker inspect -f '{{.State.Running}}' "$CONTAINER" >/dev/null 2>&1 \
  || die "container '$CONTAINER' not found or not running"

if [ "$VERIFY_ONLY" -eq 0 ]; then
  [ -n "$PASSWORD" ] || die "--password (key database password) is required outside --verify-only"
  # --icu-source-dir is OPTIONAL: it is only required when the GSKit probe
  # below fails on an ICU library (observed on the Db2 12.1 image; the Db2
  # 11.5.9 fixture's GSKit 8 works without any shim). If the administrator
  # supplies it explicitly, validate it up front.
  if [ -n "$ICU_SOURCE_DIR" ]; then
    [ -d "$ICU_SOURCE_DIR" ] || die "--icu-source-dir '$ICU_SOURCE_DIR' is not a directory"
    for lib in libicudata.so.70.1 libicui18n.so.70.1 libicuio.so.70.1 libicuuc.so.70.1; do
      [ -f "$ICU_SOURCE_DIR/$lib" ] \
        || die "missing $lib in --icu-source-dir (stage unsuffixed ICU 70 libs from any Ubuntu 22.04-based image first — the target never downloads anything)"
    done
  fi
  CERT_OUT_DIR="$(dirname "$CERT_OUT")"
  [ -w "$CERT_OUT_DIR" ] || [ -d "$CERT_OUT_DIR" ] || die "--cert-out directory '$CERT_OUT_DIR' does not exist"
fi

INSTANCE_HOME="$(docker exec -u "$INSTANCE_USER" "$CONTAINER" bash -lc 'printf %s "$HOME"')"
[ -n "$INSTANCE_HOME" ] || die "could not determine HOME for instance user '$INSTANCE_USER' in container"

# Detect GSKit version inside the container.
GSKCMD=""
GSK_MODE=""
if docker exec -u "$INSTANCE_USER" "$CONTAINER" bash -lc "test -x \$HOME/sqllib/gskit/bin/gsk8capicmd_64" 2>/dev/null; then
  GSKCMD="$INSTANCE_HOME/sqllib/gskit/bin/gsk8capicmd_64"
  GSK_MODE="gsk8"     # cert creation: -cert -create, falling back to -cert -selfsign
elif docker exec -u "$INSTANCE_USER" "$CONTAINER" bash -lc "test -x \$HOME/sqllib/gskit/bin/gsk9certutil_64" 2>/dev/null; then
  GSKCMD="$INSTANCE_HOME/sqllib/gskit/bin/gsk9certutil_64"
  GSK_MODE="gsk9"     # cert creation: -cert -create, falling back to -cert -selfsign
else
  die "neither gsk8capicmd_64 nor gsk9certutil_64 found under \$HOME/sqllib/gskit/bin in container '$CONTAINER'"
fi
info "GSKit detected: ${GSK_MODE} (${GSKCMD})"

# --------------------------------------------------------------- verify-only
if [ "$VERIFY_ONLY" -eq 1 ]; then
  echo "==> SSL-related DBM configuration in container '$CONTAINER' (user ${INSTANCE_USER}):"
  docker exec -u "$INSTANCE_USER" "$CONTAINER" bash -lc \
    'source "$HOME/sqllib/db2profile" >/dev/null 2>&1 || true; db2 get dbm cfg | grep -E "SSL_SVCENAME|SSL_SVR_KEYDB|SSL_SVR_STASH|SSL_SVR_LABEL" || echo "(no SSL_* entries — TLS is NOT enabled on this instance)"'
  echo
  echo "If SSL_SVCENAME is empty, run this script without --verify-only (or see"
  echo "docs/db2-tls-setup.md). Remember: the plaintext SVCENAME and SSL_SVCENAME"
  echo "are separate settings — the client must point at the SSL port."
  exit 0
fi

# ------------------------------------------- 1. GSKit probe / optional ICU shim
# GSKit normally runs with only $HOME/sqllib/lib64/gskit on LD_LIBRARY_PATH
# (verified on the Db2 11.5.9 fixture: `keydb -create -stash` and
# `-cert -create` both succeed without any ICU shim). Some builds — observed
# on the Db2 12.1 image — additionally probe for UNSUFFIXED ICU 70 .so names
# and need a shim dir FIRST on LD_LIBRARY_PATH. Probe GSKit as-is first and
# only require/stage the shim when that probe fails on an ICU library.
ICU_SHIM="udbmcp-icu70"
if [ -n "$ICU_SOURCE_DIR" ]; then
  # Explicit administrator override: this GSKit build is known to need the
  # shim (e.g. the Db2 12.1 image), so stage it unconditionally.
  info "ICU shim requested via --icu-source-dir — staging in container at \$HOME/${ICU_SHIM}"
  # docker cp does NOT create missing destination directories, so the shim dir
  # must exist (and belong to the instance owner) before the first copy — on a
  # fresh container $HOME/udbmcp-icu70 is absent and the cp would fail.
  docker exec -u root "$CONTAINER" bash -c "
    set -e
    mkdir -p '$INSTANCE_HOME/$ICU_SHIM'
    chown -R '$INSTANCE_USER' '$INSTANCE_HOME/$ICU_SHIM'
  "
  for lib in libicudata.so.70.1 libicui18n.so.70.1 libicuio.so.70.1 libicuuc.so.70.1; do
    docker cp "$ICU_SOURCE_DIR/$lib" "$CONTAINER:$INSTANCE_HOME/$ICU_SHIM/$lib.tmp.$$" >/dev/null \
      || die "docker cp of $lib failed"
  done
  docker exec -u root "$CONTAINER" bash -c "
    set -e
    chown -R '$INSTANCE_USER' '$INSTANCE_HOME/$ICU_SHIM'
  "
  docker exec -u "$INSTANCE_USER" "$CONTAINER" bash -lc "
    set -e
    cd \$HOME/$ICU_SHIM
    for lib in libicudata libicui18n libicuio libicuuc; do
      mv -f \$HOME/$ICU_SHIM/\${lib}.so.70.1.tmp.$$ \${lib}.so.70.1
      ln -sf \${lib}.so.70.1 \${lib}.so.70
    done
  "
  info "ICU shim staged (libicu{data,i18n,io,uc}.so.70 -> .so.70.1)"
  # Helper fragment prepended to every GSKit invocation's environment.
  GSK_ENV="export LD_LIBRARY_PATH=\"\$HOME/${ICU_SHIM}:\$HOME/sqllib/lib64/gskit:\${LD_LIBRARY_PATH:-}\""
else
  info "Probing GSKit without an ICU shim (only \$HOME/sqllib/lib64/gskit on LD_LIBRARY_PATH)"
  # Throwaway keydb -create probe: the same operation the run below needs, so
  # it proves the real invocations will work. The probe files are removed
  # again regardless of the outcome.
  PROBE_OUT="$(docker exec -u "$INSTANCE_USER" \
    -e GSKCMD="$GSKCMD" \
    "$CONTAINER" bash -c '
      export LD_LIBRARY_PATH="$HOME/sqllib/lib64/gskit:${LD_LIBRARY_PATH:-}"
      PROBE_DB="$HOME/.udbmcp-gskit-probe"
      rm -f "$PROBE_DB.kdb" "$PROBE_DB.sth" "$PROBE_DB.rdb" "$PROBE_DB.crl"
      "$GSKCMD" -keydb -create -db "$PROBE_DB.kdb" -pw udbmcp-gskit-probe -stash 2>&1
      rc=$?
      rm -f "$PROBE_DB.kdb" "$PROBE_DB.sth" "$PROBE_DB.rdb" "$PROBE_DB.crl"
      exit $rc
    ')" && PROBE_RC=0 || PROBE_RC=$?
  if [ "$PROBE_RC" -eq 0 ]; then
    info "GSKit probe succeeded — no ICU shim needed (staging skipped)"
    GSK_ENV='export LD_LIBRARY_PATH="$HOME/sqllib/lib64/gskit:${LD_LIBRARY_PATH:-}"'
  else
    case "$PROBE_OUT" in
      *libicu*)
        die "GSKit probe failed on an ICU library (exit ${PROBE_RC}):
$PROBE_OUT
This GSKit build probes for unsuffixed ICU 70 libraries (observed on the Db2
12.1 image). Re-run with --icu-source-dir pointing at a staged directory
containing libicu{data,i18n,io,uc}.so.70.1 (with .so.70 symlinks) — the target
never downloads anything (see docs/db2-tls-setup.md, 'Prerequisites')."
        ;;
      '')
        die "GSKit probe failed (exit ${PROBE_RC}) with no output — refusing to configure TLS on a broken GSKit (see docs/db2-tls-setup.md, 'Troubleshooting')"
        ;;
      *)
        die "GSKit probe failed (exit ${PROBE_RC}); this is NOT an ICU problem:
$PROBE_OUT
Check that \$HOME/sqllib/lib64/gskit exists and see the 'Troubleshooting'
table in docs/db2-tls-setup.md."
        ;;
    esac
  fi
fi

# ------------------------------------------------- 2. keydb + self-signed cert
info "Ensuring key database \$HOME/${KEYDB_NAME} and label '${LABEL}' exist"
docker exec -u "$INSTANCE_USER" \
  -e GSK_ENV="$GSK_ENV" -e GSKCMD="$GSKCMD" -e GSK_MODE="$GSK_MODE" \
  -e KDB="$KEYDB_NAME" -e STASH="$STASH_NAME" -e LABEL="$LABEL" -e KDB_PW="$PASSWORD" \
  -e CERT_HOST="$CERT_HOST" -e CERT_SAN_KIND="$CERT_SAN_KIND" \
  "$CONTAINER" bash -c '
    eval "$GSK_ENV"
    if [ ! -f "$HOME/$KDB" ]; then
      echo "    creating keydb $HOME/$KDB"
      "$GSKCMD" -keydb -create -db "$HOME/$KDB" -pw "$KDB_PW" -stash
    else
      echo "    keydb already exists — reusing"
    fi
    if "$GSKCMD" -cert -list -db "$HOME/$KDB" -pw "$KDB_PW" 2>/dev/null | grep -q "$LABEL"; then
      echo "    certificate label \"$LABEL\" already present — reusing"
      echo "    (a certificate that does not name $CERT_HOST in its subjectAltName is refused by"
      echo "     host-name validation: delete the label with -cert -delete and re-run to reissue it)"
    else
      # GSKit 8 vs 9 verb differences: gsk9certutil and current GSKit 8 builds
      # accept "-cert -create", but the GSKit 8 shipped in some Db2 images
      # rejects it and only accepts the legacy "-cert -selfsign". Probe with
      # -create first and fall back so either binary succeeds. Fail-closed:
      # if both verbs fail the run aborts (docker exec exits non-zero).
      if "$GSKCMD" -cert -create -db "$HOME/$KDB" -pw "$KDB_PW" -label "$LABEL" -size 2048 -expire 3650 -dn "CN=$CERT_HOST" "-san_$CERT_SAN_KIND" "$CERT_HOST"; then
        echo "    creating self-signed certificate (-cert -create)"
      elif "$GSKCMD" -cert -selfsign -db "$HOME/$KDB" -pw "$KDB_PW" -label "$LABEL" -size 2048 -expire 3650 -dn "CN=$CERT_HOST" "-san_$CERT_SAN_KIND" "$CERT_HOST"; then
        echo "    creating self-signed certificate (-cert -selfsign fallback)"
      else
        echo "    ERROR: both -cert -create and -cert -selfsign failed" >&2
        exit 1
      fi
    fi
  '
# -stash writes <dbname>.sth next to the .kdb; normalize the expected name.
docker exec -u "$INSTANCE_USER" "$CONTAINER" bash -lc "
  set -e
  if [ -f \$HOME/server.sth ] && [ \"\$HOME/$STASH_NAME\" != \"\$HOME/server.sth\" ]; then :; fi
  true
"

# ------------------------------------------------------- 3. DBM cfg + restart
info "Checking current SSL DBM configuration"
CURRENT_SSL_SVCENAME="$(docker exec -u "$INSTANCE_USER" \
  -e SSL_PORT="$SSL_PORT" -e KDB="$KEYDB_NAME" -e STASH="$STASH_NAME" -e LABEL="$LABEL" \
  "$CONTAINER" bash -c '
    source "$HOME/sqllib/db2profile" >/dev/null 2>&1
    # Db2 prints the parameter as
    # " SSL service name                         (SSL_SVCENAME) = 50001"
    # — the literal substring "SSL SVCENAME" never occurs, so the previous
    # awk pattern never matched and every re-run force-restarted the
    # instance. Match the parenthesised parameter name instead.
    db2 get dbm cfg 2>/dev/null | awk -F"= *" "/\\(SSL_SVCENAME\\)/ {print \$2}" | tr -d "\""
  ')" || CURRENT_SSL_SVCENAME=""

CFG_CHANGED=0
if [ "$CURRENT_SSL_SVCENAME" = "$SSL_PORT" ]; then
  info "SSL_SVCENAME already set to ${SSL_PORT} — DBM update and restart skipped"
else
  if [ -n "$CURRENT_SSL_SVCENAME" ] && [ "$CURRENT_SSL_SVCENAME" != 'NONE' ] && [ "$CURRENT_SSL_SVCENAME" != '""' ]; then
    info "SSL_SVCENAME currently '${CURRENT_SSL_SVCENAME}' — will change to ${SSL_PORT}"
  else
    info "SSL_SVCENAME not set — will configure SSL on port ${SSL_PORT}"
  fi
  CFG_CHANGED=1
fi

if [ "$CFG_CHANGED" -eq 1 ]; then
  info "Updating DBM configuration (SSL_SVR_KEYDB / SSL_SVR_STASH / SSL_SVR_LABEL / SSL_SVCENAME=${SSL_PORT})"
  docker exec -u "$INSTANCE_USER" \
    -e SSL_PORT="$SSL_PORT" -e KDB="$KEYDB_NAME" -e STASH="$STASH_NAME" -e LABEL="$LABEL" \
    "$CONTAINER" bash -c '
      set -e
      source "$HOME/sqllib/db2profile" >/dev/null 2>&1
      # KDB / STASH / LABEL / SSL_PORT arrive via docker exec -e; expanding
      # them container-side (never host-side: $KDB etc. are not host vars).
      db2 update dbm cfg using SSL_SVR_KEYDB "$HOME/$KDB" SSL_SVR_STASH "$HOME/$STASH" SSL_SVR_LABEL "$LABEL" SSL_SVCENAME "$SSL_PORT"
      echo "    restarting the instance (db2stop force; db2start)"
      db2stop force >/dev/null
      db2start >/dev/null
    '
else
  info "Restart skipped (configuration unchanged; instance already serving SSL)"
fi

# ------------------------------------------------------ 4. extract cert (out)
info "Extracting certificate to container:\$HOME/${CRT_NAME}, then copying to ${CERT_OUT}"
docker exec -u "$INSTANCE_USER" \
  -e GSK_ENV="$GSK_ENV" -e GSKCMD="$GSKCMD" \
  -e KDB="$KEYDB_NAME" -e LABEL="$LABEL" -e CRT_NAME="$CRT_NAME" -e KDB_PW="$PASSWORD" \
  "$CONTAINER" bash -c '
    eval "$GSK_ENV"
    $GSKCMD -cert -extract -db "$HOME/$KDB" -pw "$KDB_PW" -label "$LABEL" -target "$HOME/$CRT_NAME" -format ascii
  '
docker cp "$CONTAINER:$INSTANCE_HOME/$CRT_NAME" "$CERT_OUT" >/dev/null \
  || die "docker cp of $CRT_NAME to $CERT_OUT failed"
info "Certificate written to ${CERT_OUT}"

# ------------------------------------------------------------- 5. YAML block
if [ -z "$CLIENT_HOST" ]; then
  CLIENT_HOST="127.0.0.1"
  echo
  echo "NOTE: --client-host not given; defaulting the YAML below to ${CLIENT_HOST}."
  echo "      If the MCP server reaches Db2 through a published container port,"
  echo "      point 'host'/'port' at that published endpoint instead."
fi
echo
echo "----------------------------------------------------------------"
echo "Paste the following block into the udbmcp config (adjust names,)"
echo "schemas, and secret references to your deployment's policy:      "
echo "----------------------------------------------------------------"
cat <<EOF

connections:
  ${DATABASE_LC}_db2:
    type: db2
    family: luw
    host: ${CLIENT_HOST}
    port: ${SSL_PORT}                 # must be the SSL_SVCENAME port, not SVCENAME
    database: ${DATABASE}
    username_env: DB2_USER            # or an explicit username per policy
    password_file: /run/secrets/${DATABASE_LC}_db2_password
    tls:
      enabled: true
      verify_server: true
      ca_file: ${CERT_OUT}
    allowed_schemas: [UDBMCP_RO]      # read-only account's schema — empty list = NO schema restriction
    read_only: true
EOF

echo
echo "Done. Verify with the ibm_db one-liner from docs/db2-tls-setup.md:"
echo "  python3 -c \"import ibm_db; print(ibm_db.connect('DATABASE=${DATABASE};HOSTNAME=${CERT_HOST};PORT=${SSL_PORT};PROTOCOL=TCPIP;UID=<user>;PWD=<pw>;SECURITY=SSL;SSLServerCertificate=${CERT_OUT};SSLClientHostnameValidation=Basic;','',''))\""
