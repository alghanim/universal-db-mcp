set -u
export DEBIAN_FRONTEND=noninteractive
OLD=/dist/universal-db-mcp_0.1.0~ac75f19d68656561233eb619d87c6e768cb1b909_amd64.deb
NEW=/dist/universal-db-mcp_0.1.0~854b50da44d0995c05da86944f8bc2566622ee83_amd64.deb
DB2PY=/opt/universal-db-mcp/venv/lib/python3.12/site-packages/universal_db_mcp/connectors/db2.py
STATUS=/var/log/universal-db-mcp-install.status
n=0
install_deb() { # $1 label, $2 deb
  n=$((n+1)); m=/tmp/marker$n; touch "$m"; sleep 1
  dpkg -i --force-depends "$2" >/tmp/dpkg$n.log 2>&1; echo "  dpkg -i $1 rc=$?"
  for _ in $(seq 1 1200); do
    if [ -f "$STATUS" ] && [ "$STATUS" -nt "$m" ] && grep -qxE 'success|failed' "$STATUS"; then
      echo "  worker status: $(cat "$STATUS")"; return; fi
    sleep 2
  done
  echo "  worker status: TIMEOUT"; tail -5 /tmp/dpkg$n.log
}
fixcheck() {
  if grep -q 'fields.append(("PWD"' "$DB2PY" 2>/dev/null; then echo "  => $1: installed connector HAS the fix"
  else echo "  => $1: installed connector is OLD (no fix)"; fi
}
echo "== PHASE A: current (unfixed) trusted installer, old deb then upgrade"
bash /bootstrap-unfixed/bootstrap.sh >/tmp/boot.log 2>&1 && echo "  trust bootstrap ok (unfixed installer)"
install_deb OLD "$OLD"; fixcheck "after OLD install"
install_deb NEW "$NEW"; fixcheck "after upgrade to NEW"
echo "  pip on the upgrade: $(grep -iE 'universal.db.mcp' /var/log/universal-db-mcp-install.log | grep -iE 'already satisfied' | tail -1 | cut -c1-140)"
echo "== PHASE B: immediate recovery with the SAME unfixed trusted installer"
rm -rf /opt/universal-db-mcp/venv
UDBMCP_RELEASE_PUBKEY=/etc/universal-db-mcp/keys/release.pub.pem bash /usr/local/lib/udbmcp-trust/install_offline.sh /usr/share/universal-db-mcp/bundle >/tmp/recovery.log 2>&1
echo "  recovery installer rc=$?; $(grep -m1 'bundle verification PASSED' /tmp/recovery.log)"
fixcheck "after recovery"
echo "  udbmcp version: $(/usr/local/bin/udbmcp version 2>&1 | tail -1); venv: $(stat -c '%a %U:%G' /opt/universal-db-mcp/venv)"
echo "== PHASE C: FIXED trusted installer, old over new then new again"
install -m 755 /install_offline.fixed.sh /usr/local/lib/udbmcp-trust/install_offline.sh && echo "  fixed installer placed in trust dir"
install_deb OLD "$OLD"; fixcheck "after OLD over NEW"
install_deb NEW "$NEW"; fixcheck "after NEW again"
echo "  udbmcp version: $(/usr/local/bin/udbmcp version 2>&1 | tail -1)"
