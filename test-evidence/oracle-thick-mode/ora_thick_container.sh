set -e
echo "== installing libaio and the Oracle Instant Client (offline, from /stage)"
dpkg -i /stage/libaio1t64_*.deb >/dev/null 2>&1 || true
if ! ldconfig -p | grep -q "libaio.so.1 "; then
  target=$(ldconfig -p | sed -n 's/.*libaio.so.1t64 (libc6,x86-64) => //p' | head -1)
  if [ -n "$target" ]; then ln -sf "$target" "$(dirname "$target")/libaio.so.1"; ldconfig; fi
fi
mkdir -p /opt/oracle
cd /opt/oracle
if command -v unzip >/dev/null 2>&1; then
  unzip -q /stage/instantclient-basiclite-linux.x64-19.28.zip
else
  python3.12 -m zipfile -e /stage/instantclient-basiclite-linux.x64-19.28.zip /opt/oracle/
fi
ICDIR=$(ls -d /opt/oracle/instantclient_* | head -1)
chmod -R a+rX "$ICDIR"
echo "$ICDIR" > /etc/ld.so.conf.d/oracle-instantclient.conf
ldconfig
ldconfig -p | grep -c libclntsh | sed 's/^/libclntsh visible to the loader: /'
echo "== building a venv from the bundle wheelhouse (no index, no network)"
python3.12 -m venv /tmp/v >/dev/null
/tmp/v/bin/pip install --quiet --no-index --find-links /wh --only-binary=:all: \
  oracledb PyYAML pydantic sqlglot mcp >/dev/null
echo "== probing through the udbmcp Oracle connector"
/tmp/v/bin/python /stage/ora_thick_probe.py thin
echo
/tmp/v/bin/python /stage/ora_thick_probe.py thick
